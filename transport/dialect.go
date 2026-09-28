// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Protocol versions this transport can speak, newest first.
const (
	// V20260728 is the stateless revision: no initialize handshake, no
	// session header, per-request metadata in _meta, and body fields
	// mirrored into routing headers.
	V20260728 = "2026-07-28"
	// V20251125, V20250618 and V20250326 are the session-based revisions.
	V20251125 = "2025-11-25"
	V20250618 = "2025-06-18"
	V20250326 = "2025-03-26"
)

// Reserved _meta keys defined by the 2026-07-28 specification.
const (
	MetaProtocolVersion    = "io.modelcontextprotocol/protocolVersion"
	MetaClientInfo         = "io.modelcontextprotocol/clientInfo"
	MetaClientCapabilities = "io.modelcontextprotocol/clientCapabilities"
	MetaServerInfo         = "io.modelcontextprotocol/serverInfo"
	MetaSubscriptionID     = "io.modelcontextprotocol/subscriptionId"
)

// Routing headers the 2026-07-28 Streamable HTTP binding mirrors body
// fields into, so a gateway can route and meter without parsing JSON.
const (
	HeaderMethod = "Mcp-Method"
	HeaderName   = "Mcp-Name"
	// HeaderParamPrefix is the prefix for a tool parameter mirrored into a
	// header by an x-mcp-header annotation.
	HeaderParamPrefix = "Mcp-Param-"
)

// JSON-RPC error codes the 2026-07-28 specification reserves.
const (
	// CodeHeaderMismatch means a mirrored header disagreed with the body,
	// or a required one was missing.
	CodeHeaderMismatch = -32020
	// CodeMissingClientCapability means the request needed a capability the
	// client did not declare in _meta.
	CodeMissingClientCapability = -32021
	// CodeUnsupportedProtocolVersion means the server does not implement the
	// version the request asked for; the error data lists what it supports.
	CodeUnsupportedProtocolVersion = -32022
	// CodeMethodNotFound is the standard JSON-RPC code, which the 2026
	// binding pairs with HTTP 404 to distinguish an unknown method from a
	// legacy server that does not host an MCP endpoint at all.
	CodeMethodNotFound = -32601
)

// Implementation identifies a client or server by name and version.
type Implementation struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// Dialect is the version-specific half of the Streamable HTTP binding: what
// a request carries beyond its method and params.
//
// The protocol semantics are the same across versions; what changed in
// 2026-07-28 is where the metadata lives. Up to 2025-11-25 it was
// connection state established by an initialize handshake and carried by a
// session header. From 2026-07-28 it travels in every request's _meta, with
// selected fields mirrored into headers. Putting that difference behind an
// interface keeps one transport rather than two.
type Dialect interface {
	// Version is the protocol version this dialect speaks.
	Version() string
	// Stateful reports whether the server assigns a session that the client
	// must echo. False from 2026-07-28 on.
	Stateful() bool
	// PrepareBody injects per-request protocol metadata into the params.
	PrepareBody(rpc *Request) error
	// PrepareHeaders sets the headers the binding requires for rpc.
	PrepareHeaders(h http.Header, rpc *Request) error
}

// DialectFor returns the dialect for a protocol version, or an error when
// the version is not one this transport speaks.
func DialectFor(version string, client Implementation, caps json.RawMessage) (Dialect, error) {
	switch version {
	case V20260728:
		return &Stateless{ProtocolVersion: version, ClientInfo: client, Capabilities: caps}, nil
	case V20251125, V20250618, V20250326:
		return &Sessioned{ProtocolVersion: version}, nil
	case "":
		return &Sessioned{}, nil
	}
	return nil, fmt.Errorf("transport: unknown protocol version %q", version)
}

// --- the session-based dialects (2025-03-26 … 2025-11-25) ----------------

// SessionState is the live connection state a session-based dialect reads
// at send time. *Streamable implements it.
//
// The dialect reads rather than caches so that a version negotiated by one
// goroutine is visible to a request in flight on another without the
// dialect itself becoming shared mutable state.
type SessionState interface {
	ProtocolVersion() string
	SessionID() string
}

// Sessioned implements the revisions that establish connection state with
// an initialize handshake and carry it in the Mcp-Session-Id header.
type Sessioned struct {
	// Live, when set, supplies the negotiated version and session id from
	// the transport that owns them. It is set automatically by SetDialect.
	Live SessionState
	// ProtocolVersion is used when Live is nil.
	ProtocolVersion string
}

// Version implements Dialect.
func (d *Sessioned) Version() string {
	if d.Live != nil {
		if v := d.Live.ProtocolVersion(); v != "" {
			return v
		}
	}
	return d.ProtocolVersion
}

// Stateful implements Dialect.
func (d *Sessioned) Stateful() bool { return true }

// PrepareBody implements Dialect. These revisions carry no per-request
// metadata: the handshake established it for the connection.
func (d *Sessioned) PrepareBody(*Request) error { return nil }

// PrepareHeaders implements Dialect.
func (d *Sessioned) PrepareHeaders(h http.Header, _ *Request) error {
	if v := d.Version(); v != "" {
		h.Set(HeaderProtocolVersion, v)
	}
	if d.Live != nil {
		if sid := d.Live.SessionID(); sid != "" {
			h.Set(HeaderSessionID, sid)
		}
	}
	return nil
}

// --- the stateless dialect (2026-07-28) ----------------------------------

// Stateless implements the 2026-07-28 revision: every request carries its
// own protocol version, client identity and capabilities, and no state is
// inferred from the connection.
type Stateless struct {
	ProtocolVersion string
	ClientInfo      Implementation
	// Capabilities is the ClientCapabilities object sent on every request.
	// It is required, so a nil value is sent as {}.
	Capabilities json.RawMessage
	// LogLevel, when set, asks the server for a minimum log level.
	LogLevel string
}

// Version implements Dialect.
func (d *Stateless) Version() string {
	if d.ProtocolVersion == "" {
		return V20260728
	}
	return d.ProtocolVersion
}

// Stateful implements Dialect. The 2026-07-28 revision removed sessions.
func (d *Stateless) Stateful() bool { return false }

// PrepareBody injects the reserved io.modelcontextprotocol/* fields into
// params._meta. protocolVersion and clientCapabilities are required on
// every request; a request missing either is malformed and the server must
// answer -32602.
func (d *Stateless) PrepareBody(rpc *Request) error {
	if rpc == nil {
		return nil
	}
	params := map[string]any{}
	if len(rpc.Params) > 0 && string(rpc.Params) != "null" {
		if err := json.Unmarshal(rpc.Params, &params); err != nil {
			// Params that are not an object cannot carry _meta. The spec
			// models every request's params as an object, so this is a
			// caller error rather than something to paper over.
			return fmt.Errorf("transport: %s params must be a JSON object to carry _meta: %w", rpc.Method, err)
		}
	}
	meta := map[string]any{}
	if raw, ok := params["_meta"]; ok {
		if m, ok := raw.(map[string]any); ok {
			meta = m
		}
	}
	meta[MetaProtocolVersion] = d.Version()
	// Capabilities are per request on this revision, so a caller may
	// declare different ones for one call — an extension exercised on a
	// single request — and what it wrote is kept. Otherwise the dialect's
	// own declaration applies.
	if _, ok := meta[MetaClientCapabilities]; !ok {
		caps := d.Capabilities
		if len(caps) == 0 {
			caps = json.RawMessage("{}")
		}
		meta[MetaClientCapabilities] = caps
	}
	if d.ClientInfo.Name != "" {
		meta[MetaClientInfo] = d.ClientInfo
	}
	if d.LogLevel != "" {
		meta["io.modelcontextprotocol/logLevel"] = d.LogLevel
	}
	params["_meta"] = meta
	b, err := json.Marshal(params)
	if err != nil {
		return fmt.Errorf("transport: encode _meta for %s: %w", rpc.Method, err)
	}
	rpc.Params = b
	return nil
}

// PrepareHeaders mirrors the method and the target name into headers. The
// body stays the source of truth; a server that sees a header disagreeing
// with it must answer -32020, so these are derived from the body rather
// than tracked alongside it.
func (d *Stateless) PrepareHeaders(h http.Header, rpc *Request) error {
	h.Set(HeaderProtocolVersion, d.Version())
	if rpc == nil {
		return nil
	}
	h.Set(HeaderMethod, rpc.Method)
	name, ok, err := targetName(rpc)
	if err != nil {
		return err
	}
	if ok {
		h.Set(HeaderName, EncodeHeaderValue(name))
	}
	return nil
}

// methodsWithName are the methods whose params carry a name or URI that the
// binding requires to be mirrored into Mcp-Name.
var methodsWithName = map[string]string{
	"tools/call":     "name",
	"prompts/get":    "name",
	"resources/read": "uri",
	// The Tasks extension requires the task id in Mcp-Name, so an
	// intermediary can route every request about a task to the instance
	// holding its state.
	"tasks/get":    "taskId",
	"tasks/update": "taskId",
	"tasks/cancel": "taskId",
}

// targetName extracts the value Mcp-Name must carry for rpc, if any.
func targetName(rpc *Request) (string, bool, error) {
	field, ok := methodsWithName[rpc.Method]
	if !ok || len(rpc.Params) == 0 {
		return "", false, nil
	}
	var params map[string]json.RawMessage
	if err := json.Unmarshal(rpc.Params, &params); err != nil {
		// Params this dialect cannot read carry no name to mirror. The body
		// is still the source of truth, and the server will reject it.
		return "", false, nil //nolint:nilerr // an unreadable body yields no header, not an error here
	}
	raw, ok := params[field]
	if !ok {
		return "", false, nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", false, fmt.Errorf("transport: %s params.%s must be a string", rpc.Method, field)
	}
	return s, s != "", nil
}
