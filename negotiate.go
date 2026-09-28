// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"sort"

	"satellion.com/passmcp/trace"
	"satellion.com/passmcp/transport"
)

// Era is which generation of the protocol a server speaks.
type Era string

const (
	// EraStateless is 2026-07-28 and later: no handshake, no session, every
	// request carrying its own protocol metadata.
	EraStateless Era = "stateless"
	// EraSession is 2025-03-26 through 2025-11-25: an initialize handshake
	// establishes connection state carried by a session header.
	EraSession Era = "session"
	// EraUnknown means detection has not run or could not decide.
	EraUnknown Era = "unknown"
)

// Negotiation records how the era was decided, so a report can say what was
// tried rather than only what was concluded.
type Negotiation struct {
	Era Era `json:"era"`
	// Version is the protocol version in use.
	Version string `json:"version"`
	// Attempted lists the versions offered, newest first.
	Attempted []string `json:"attempted,omitempty"`
	// ServerSupported is what the server said it supports, when it told us.
	ServerSupported []string `json:"server_supported,omitempty"`
	// Reason is the plain-language account of how the era was decided.
	Reason string `json:"reason,omitempty"`
	// Discovered is the server/discover result, when the server answered it.
	Discovered *DiscoverResult `json:"discovered,omitempty"`
}

// DiscoverResult is what server/discover returned. The RPC is optional in
// the 2026-07-28 revision, so its absence is not a failure.
type DiscoverResult struct {
	ResultType string `json:"resultType,omitempty"`
	// ServerInfo is the server's identity. The 2026-07-28 revision carries
	// it in the result's _meta under the reserved
	// io.modelcontextprotocol/serverInfo key, which is where the reference
	// SDKs write it; UnmarshalJSON lifts it from there when the top-level
	// field is absent, so callers read one place.
	ServerInfo   Implementation     `json:"serverInfo,omitempty"`
	Capabilities ServerCapabilities `json:"capabilities"`
	Instructions string             `json:"instructions,omitempty"`
	// SupportedVersions lists the protocol revisions the server speaks.
	SupportedVersions []string `json:"supportedVersions,omitempty"`
	// Extensions is a top-level list of identifiers some servers send. It is
	// not where the specification puts extensions — that is
	// Capabilities.Extensions, which ExtensionIDs reads — and no client
	// following the specification looks here. It is kept so a report can
	// say a server advertised its extensions somewhere nobody will see them.
	Extensions []string `json:"extensions,omitempty"`
	// ExtensionSettings are the extensions the server advertises in
	// capabilities.extensions — where the 2026-07-28 revision puts them —
	// keyed by reverse-DNS identifier, with each one's settings as the
	// value; an empty object means supported with no settings. It lives
	// here rather than on ServerCapabilities, which is shared with the
	// handshake revisions and must stay comparable.
	ExtensionSettings map[string]json.RawMessage `json:"-"`
	// ExtensionsMalformed is true when capabilities.extensions was present
	// but not an object. The rest of the result is still read: one bad
	// field is a finding about that field, not a reason to lose the
	// server's identity and version list.
	ExtensionsMalformed bool `json:"-"`
	// Meta is the result's _meta, kept raw so reserved keys passmcp does not
	// model are still visible in the report.
	Meta map[string]json.RawMessage `json:"_meta,omitempty"`
}

// ExtensionIDs returns the extensions the server advertises where the
// specification puts them, in capabilities.extensions, sorted.
func (d *DiscoverResult) ExtensionIDs() []string {
	if d == nil || len(d.ExtensionSettings) == 0 {
		return nil
	}
	ids := make([]string, 0, len(d.ExtensionSettings))
	for id := range d.ExtensionSettings {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// UnmarshalJSON decodes a server/discover result and settles where the
// identity came from. A top-level serverInfo wins when present; otherwise
// the reserved _meta key supplies it. A malformed _meta entry is an error,
// not a silent blank: a server that put something there meant it.
func (d *DiscoverResult) UnmarshalJSON(b []byte) error {
	type plain DiscoverResult
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	if p.ServerInfo.Name == "" {
		if raw, ok := p.Meta[transport.MetaServerInfo]; ok {
			if err := json.Unmarshal(raw, &p.ServerInfo); err != nil {
				return fmt.Errorf("decoding _meta %s: %w", transport.MetaServerInfo, err)
			}
		}
	}
	var caps struct {
		Capabilities struct {
			Extensions json.RawMessage `json:"extensions"`
		} `json:"capabilities"`
	}
	if json.Unmarshal(b, &caps) == nil && len(caps.Capabilities.Extensions) > 0 &&
		string(caps.Capabilities.Extensions) != "null" {
		if json.Unmarshal(caps.Capabilities.Extensions, &p.ExtensionSettings) != nil {
			p.ExtensionSettings, p.ExtensionsMalformed = nil, true
		}
	}
	*d = DiscoverResult(p)
	return nil
}

// StatelessVersions are the stateless revisions passmcp offers, newest first.
var StatelessVersions = []string{transport.V20260728}

// SessionVersions are the handshake revisions passmcp offers, newest first.
var SessionVersions = []string{transport.V20251125, transport.V20250618, transport.V20250326}

// Negotiate decides which era the server speaks and configures the
// transport for it.
//
// The order follows the specification's backward-compatibility rule: try a
// stateless request first, and on 400 read the body before concluding
// anything. A modern server explains itself with a JSON-RPC error — an
// unsupported version, a missing capability, a header mismatch — and should
// be retried or corrected, not abandoned. Only an empty or unrecognised
// body means the server predates the revision and wants an initialize
// handshake.
func (c *Client) Negotiate(ctx context.Context) (*Negotiation, error) {
	ctx = trace.Ensure(ctx)
	n := &Negotiation{Era: EraUnknown, Attempted: slices.Clone(StatelessVersions)}

	for _, v := range StatelessVersions {
		res, err := c.tryStateless(ctx, v)
		switch {
		case err == nil:
			n.Era, n.Version, n.Discovered = EraStateless, v, res
			n.Reason = fmt.Sprintf("the server answered a stateless %s request", v)
			c.setNegotiation(n)
			return n, nil

		case isMethodNotFound(err):
			// The version is fine; this server simply does not implement
			// the optional discovery RPC. That is still a stateless server.
			n.Era, n.Version = EraStateless, v
			n.Reason = fmt.Sprintf("the server accepted a stateless %s request but does not implement server/discover", v)
			c.setNegotiation(n)
			return n, nil

		default:
			if stop, out, err := c.statelessRefused(ctx, n, v, err); stop {
				return out, err
			}
		}
	}

	// Session era: the initialize handshake settles the version.
	init, err := c.Initialize(ctx)
	if err != nil {
		return nil, fmt.Errorf("passmcp: no stateless version was accepted and the initialize handshake failed: %w", err)
	}
	n.Era, n.Version = EraSession, init.ProtocolVersion
	n.Attempted = append(n.Attempted, SessionVersions...)
	if n.Reason == "" {
		n.Reason = "the server completed an initialize handshake"
	}
	n.Reason += fmt.Sprintf("; it negotiated %s", init.ProtocolVersion)
	c.setNegotiation(n)
	return n, nil
}

// statelessRefused reads why a stateless request for v failed. stop reports
// that negotiation ends here with (out, err); otherwise the next stateless
// version, then the handshake, is tried, with n.Reason saying why.
func (c *Client) statelessRefused(ctx context.Context, n *Negotiation, v string, err error) (stop bool, out *Negotiation, _ error) {
	var uv *transport.UnsupportedVersionError
	if errors.As(err, &uv) {
		if c.tryNamedVersion(ctx, n, v, uv) {
			return true, n, nil
		}
		return false, nil, nil
	}
	if modern, ok := asModernRejection(err); ok {
		// It speaks the revision but refused this particular
		// request. Falling back would hide a real problem.
		n.Era, n.Version = EraStateless, v
		n.Reason = "the server answered with a " + modern
		c.setNegotiation(n)
		return true, n, fmt.Errorf("passmcp: the server speaks %s but rejected the request: %w", v, err)
	}
	if isLegacyMethodNotFound(err) {
		n.Reason = "the server answered server/discover with a plain JSON-RPC -32601 at HTTP 200, which is how a handshake-era server reports a method it does not know"
		return false, nil, nil
	}
	if !looksLegacy(err) {
		return true, nil, fmt.Errorf("passmcp: negotiating protocol version: %w", err)
	}
	n.Reason = "the server did not answer a stateless request with a recognised error, so it predates " + v
	return false, nil, nil
}

// tryNamedVersion handles an unsupported-version answer to v: it retries
// with a stateless version the server named, if there is one, and reports
// whether that settled the negotiation.
func (c *Client) tryNamedVersion(ctx context.Context, n *Negotiation, v string, uv *transport.UnsupportedVersionError) bool {
	n.ServerSupported = uv.Supported
	// The server named what it speaks. If that includes a
	// stateless version we do too, take it; otherwise this is a
	// session-era server that is merely polite about it.
	if pick := firstCommon(uv.Supported, StatelessVersions); pick != "" && pick != v {
		n.Attempted = append(n.Attempted, pick)
		if res, err := c.tryStateless(ctx, pick); err == nil || isMethodNotFound(err) {
			n.Era, n.Version, n.Discovered = EraStateless, pick, res
			n.Reason = "the server named " + pick + " among its supported versions"
			c.setNegotiation(n)
			return true
		}
	}
	n.Reason = fmt.Sprintf("the server does not support %s; it offers %v", v, uv.Supported)
	return false
}

// tryStateless configures the transport for a stateless version and probes
// it with server/discover.
func (c *Client) tryStateless(ctx context.Context, version string) (*DiscoverResult, error) {
	caps, err := json.Marshal(ClientCapabilities{})
	if err != nil {
		return nil, err
	}
	c.tr.SetDialect(&transport.Stateless{
		ProtocolVersion: version,
		ClientInfo:      transport.Implementation{Name: c.cfg.ClientInfo.Name, Title: c.cfg.ClientInfo.Title, Version: c.cfg.ClientInfo.Version},
		Capabilities:    caps,
	})
	var out DiscoverResult
	if err := c.tr.Call(ctx, "server/discover", map[string]any{}, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Negotiation returns the result of the last Negotiate call, or nil.
func (c *Client) Negotiation() *Negotiation {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.negotiated
}

func (c *Client) setNegotiation(n *Negotiation) {
	c.mu.Lock()
	c.negotiated = n
	c.mu.Unlock()
	if n.Era == EraSession {
		// Restore the handshake binding for everything that follows.
		c.tr.SetDialect(&transport.Sessioned{})
	}
}

// isMethodNotFound reports whether the server answered "no such method" in
// the shape a 2026-07-28 server must use: HTTP 404 with a JSON-RPC -32601
// body. For server/discover that means a stateless server that simply does
// not implement the optional RPC.
//
// The HTTP status is the whole signal. A handshake-era server handed
// server/discover also answers -32601, but as an ordinary JSON-RPC error
// with HTTP 200 — it does not know the method either. Treating a plain
// -32601 as proof of a stateless server would label every legacy server as
// current, which is the one thing this check exists to avoid.
func isMethodNotFound(err error) bool {
	var he *transport.HTTPStatusError
	return errors.As(err, &he) &&
		he.StatusCode == http.StatusNotFound &&
		he.RPCError != nil &&
		he.RPCError.Code == transport.CodeMethodNotFound
}

// isLegacyMethodNotFound reports the handshake-era shape of "no such
// method": a JSON-RPC error delivered with a 2xx status.
func isLegacyMethodNotFound(err error) bool {
	var he *transport.HTTPStatusError
	if errors.As(err, &he) {
		return false // carried by an HTTP status, so not the 200 form
	}
	var rpc *transport.RPCError
	return errors.As(err, &rpc) && rpc.Code == transport.CodeMethodNotFound
}

// asModernRejection names the modern error the server answered with, if it
// answered with one.
func asModernRejection(err error) (string, bool) {
	var mc *transport.MissingCapabilityError
	if errors.As(err, &mc) {
		return "missing-capability error, which only a 2026-07-28 server sends", true
	}
	var hm *transport.HeaderMismatchError
	if errors.As(err, &hm) {
		return "header-mismatch error, which only a 2026-07-28 server sends", true
	}
	return "", false
}

// looksLegacy reports whether a failed stateless attempt is consistent with
// a server that predates the revision, rather than one that is simply
// broken or unreachable.
func looksLegacy(err error) bool {
	var he *transport.HTTPStatusError
	if !errors.As(err, &he) {
		// A malformed body or an unparsable response is also what a legacy
		// server looks like when handed a request it does not understand.
		return !errors.Is(err, transport.ErrNoResponse)
	}
	if he.Modern() {
		return false
	}
	switch he.StatusCode {
	case http.StatusBadRequest, http.StatusNotFound, http.StatusMethodNotAllowed,
		http.StatusNotImplemented, http.StatusUnprocessableEntity:
		return true
	}
	return false
}

func firstCommon(theirs, ours []string) string {
	for _, o := range ours {
		if slices.Contains(theirs, o) {
			return o
		}
	}
	return ""
}
