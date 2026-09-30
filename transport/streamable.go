// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package transport implements the MCP Streamable HTTP transport: JSON-RPC
// over a single HTTP endpoint, with responses delivered either as a JSON body
// or as a Server-Sent Events stream, plus session and protocol-version
// header handling.
package transport

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync/atomic"
)

const (
	// HeaderProtocolVersion is sent on every request after initialize.
	HeaderProtocolVersion = "MCP-Protocol-Version"
	// HeaderSessionID is returned by the server on initialize and echoed
	// back on every subsequent request.
	HeaderSessionID = "Mcp-Session-Id"
)

// ErrSessionExpired is returned when the server answers 404 to a request
// carrying a session ID, which the spec defines as "session no longer
// valid, re-initialize".
var ErrSessionExpired = errors.New("transport: session expired (404), re-initialize")

// ErrNoResponse is returned when a server acknowledges a JSON-RPC request
// that carries an id without ever sending the matching response. The spec
// reserves 202 Accepted for notifications; answering a request with it
// leaves the client waiting for a reply that will never arrive.
var ErrNoResponse = errors.New("transport: server acknowledged a request with no response body")

// MaxResponseBytes caps a single JSON response body. A diagnostic client
// points at servers it does not trust, so an unbounded decode is a way for
// one of them to exhaust the client's memory.
const MaxResponseBytes = 32 << 20

// MaxStreamBytes caps the total size of one SSE stream, and MaxStreamEvents
// the number of events read from it while looking for a response.
const (
	MaxStreamBytes  = 32 << 20
	MaxStreamEvents = 10000
)

// ErrStreamTooLarge is returned when an SSE stream exceeds MaxStreamBytes
// or MaxStreamEvents without producing the response.
var ErrStreamTooLarge = errors.New("transport: event stream exceeded its limit without answering")

// HTTPStatusError is returned for non-2xx responses that are not JSON-RPC
// errors. The response headers are retained so callers can inspect
// WWW-Authenticate.
type HTTPStatusError struct {
	StatusCode int
	Header     http.Header
	Body       []byte
	// RPCError is set when the body carried a JSON-RPC error a 2026-07-28
	// server would send. Its presence is what distinguishes a modern
	// server's 400 from a legacy server's.
	RPCError *RPCError
	// Protocol is RPCError converted to its typed form, so errors.As finds
	// an UnsupportedVersionError on a 400 exactly as it would on a 200.
	Protocol error
}

func (e *HTTPStatusError) Error() string {
	if e.RPCError != nil {
		return fmt.Sprintf("transport: HTTP %d: %s", e.StatusCode, e.RPCError.Error())
	}
	return fmt.Sprintf("transport: unexpected HTTP status %d", e.StatusCode)
}

// Modern reports whether the server explained this status with a JSON-RPC
// error defined by the 2026-07-28 revision, which means it speaks that
// revision and the client should correct its request rather than fall back
// to an initialize handshake.
func (e *HTTPStatusError) Modern() bool { return e.RPCError != nil }

// Unwrap exposes the typed protocol error, when the body carried one.
func (e *HTTPStatusError) Unwrap() error { return e.Protocol }

// Streamable is a client for one MCP endpoint.
type Streamable struct {
	Endpoint string
	Client   *http.Client
	// ProtocolVersion is the negotiated version sent as MCP-Protocol-Version.
	// It is set by SetProtocolVersion once initialize succeeds.
	protocolVersion atomic.Value // string
	sessionID       atomic.Value // string
	nextID          atomic.Int64
	// dialect is boxed because atomic.Value refuses a second Store of a
	// different concrete type, and the two dialects are different types.
	dialect atomic.Pointer[dialectBox]
}

type dialectBox struct{ d Dialect }

// New returns a transport for endpoint using client (or http.DefaultClient).
// It speaks the session-based binding until SetDialect says otherwise.
func New(endpoint string, client *http.Client) *Streamable {
	if client == nil {
		client = http.DefaultClient
	}
	s := &Streamable{Endpoint: endpoint, Client: client}
	s.protocolVersion.Store("")
	s.sessionID.Store("")
	s.dialect.Store(&dialectBox{d: &Sessioned{Live: s}})
	return s
}

// Dialect returns the binding in use.
func (s *Streamable) Dialect() Dialect { return s.dialect.Load().d }

// SetDialect replaces the binding. A stateless dialect clears any session
// state, which can no longer mean anything to it.
func (s *Streamable) SetDialect(d Dialect) {
	if d == nil {
		d = &Sessioned{Live: s}
	}
	if sd, ok := d.(*Sessioned); ok && sd.Live == nil {
		sd.Live = s
	}
	if !d.Stateful() {
		s.sessionID.Store("")
	}
	s.protocolVersion.Store(d.Version())
	s.dialect.Store(&dialectBox{d: d})
}

// SessionID returns the current Mcp-Session-Id, or "".
func (s *Streamable) SessionID() string { return s.sessionID.Load().(string) }

// SetSessionID overrides the session, mainly for tests and resumption.
func (s *Streamable) SetSessionID(id string) { s.sessionID.Store(id) }

// ProtocolVersion returns the negotiated protocol version, or "".
func (s *Streamable) ProtocolVersion() string { return s.protocolVersion.Load().(string) }

// SetProtocolVersion records the version negotiated during initialize. For
// a session-based dialect it is also the value sent on every later request.
func (s *Streamable) SetProtocolVersion(v string) { s.protocolVersion.Store(v) }

// Reset clears session state so the next Call may be an initialize.
func (s *Streamable) Reset() {
	s.sessionID.Store("")
	s.protocolVersion.Store("")
}

// Call sends a JSON-RPC request and waits for the matching response.
func (s *Streamable) Call(ctx context.Context, method string, params any, result any) error {
	id := s.nextID.Add(1)
	req, err := s.buildRequest(&id, method, params)
	if err != nil {
		return err
	}
	resp, err := s.send(ctx, req)
	if err != nil {
		return err
	}
	if resp == nil {
		return fmt.Errorf("%w: %s (id %d)", ErrNoResponse, method, id)
	}
	if resp.Error != nil {
		return AsProtocolError(s.Dialect().Version(), resp.Error)
	}
	// A result whose resultType is input_required is not the answer: the
	// server is asking for something before it can finish.
	if ir, ok := AsInputRequired(method, resp.Result); ok {
		return ir
	}
	if result != nil && len(resp.Result) > 0 {
		if err := json.Unmarshal(resp.Result, result); err != nil {
			return fmt.Errorf("transport: decode %s result: %w", method, err)
		}
	}
	return nil
}

// Notify sends a JSON-RPC notification. The server answers 202 Accepted.
func (s *Streamable) Notify(ctx context.Context, method string, params any) error {
	req, err := s.buildRequest(nil, method, params)
	if err != nil {
		return err
	}
	_, err = s.send(ctx, req)
	return err
}

func (s *Streamable) buildRequest(id *int64, method string, params any) (*Request, error) {
	r := &Request{JSONRPC: "2.0", ID: id, Method: method}
	if params != nil {
		b, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("transport: encode params: %w", err)
		}
		r.Params = b
	}
	return r, nil
}

func (s *Streamable) send(ctx context.Context, rpc *Request) (*Response, error) {
	d := s.Dialect()
	if err := d.PrepareBody(rpc); err != nil {
		return nil, err
	}
	body, err := json.Marshal(rpc)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.Endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("transport: build request: %w", err)
	}
	req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if err := d.PrepareHeaders(req.Header, rpc); err != nil {
		return nil, err
	}

	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	if sid := resp.Header.Get(HeaderSessionID); sid != "" {
		s.sessionID.Store(sid)
	}

	if done, err := s.statusOutcome(resp, d); done {
		return nil, err
	}

	if rpc.ID == nil {
		// A notification sent with 200 OK: drain and ignore.
		_, _ = io.Copy(io.Discard, resp.Body)
		return nil, nil
	}
	return decodeResponse(resp, *rpc.ID)
}

// statusOutcome settles an exchange whose status leaves no response to
// read: an expired session, an acknowledgement with no body, or an HTTP
// error. done is false for a 2xx that carries a response.
func (s *Streamable) statusOutcome(resp *http.Response, d Dialect) (done bool, _ error) {
	switch {
	case resp.StatusCode == http.StatusNotFound && d.Stateful() && s.SessionID() != "":
		s.Reset()
		return true, ErrSessionExpired
	case resp.StatusCode == http.StatusAccepted, resp.StatusCode == http.StatusNoContent:
		// Notifications and responses are acknowledged with no body.
		return true, nil
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
		he := &HTTPStatusError{StatusCode: resp.StatusCode, Header: resp.Header.Clone(), Body: b}
		// A modern server explains a 4xx in the body; a legacy one does
		// not. Carrying the decoded error lets the caller tell them apart
		// without re-parsing.
		if rpcErr, ok := IsModernError(b); ok {
			he.RPCError = rpcErr
			he.Protocol = AsProtocolError(d.Version(), rpcErr)
		}
		return true, he
	}
	return false, nil
}

// ContentTypeError is returned when the reply to a request is neither
// application/json nor text/event-stream and its body is not a JSON-RPC
// response either. It names what arrived instead, because the decoder's
// own complaint ("invalid character '<'") says nothing about the usual
// cause: a sign-in page, an SSO or firewall interstitial, or a path that
// is not the MCP endpoint.
//
// A body that does decode is read whatever its label, so a server that
// mislabels valid JSON still works through this client.
type ContentTypeError struct {
	// ContentType is the reply's media type, lowercased and without
	// parameters, or the raw header when it does not parse. Empty when
	// the reply carried none.
	ContentType string
	// Err is the decode error the body produced.
	Err error
}

func (e *ContentTypeError) Error() string {
	return "transport: reply is not JSON-RPC: expected application/json or text/event-stream, " + e.Got()
}

// Got names what arrived instead of JSON-RPC and, where the media type
// says, what it most likely is.
func (e *ContentTypeError) Got() string {
	switch e.ContentType {
	case "":
		return "got no Content-Type"
	case "text/html", "application/xhtml+xml":
		return "got " + e.ContentType + "; likely a login, SSO or firewall page, or the wrong path"
	default:
		return "got " + e.ContentType
	}
}

// Unwrap exposes the decode error.
func (e *ContentTypeError) Unwrap() error { return e.Err }

// mediaType is a Content-Type header's media type, or the header itself
// when it does not parse, so a malformed label is still named.
func mediaType(header string) string {
	ct, _, err := mime.ParseMediaType(header)
	if err != nil {
		return strings.TrimSpace(header)
	}
	return ct
}

// decodeResponse reads the response to request id from an SSE stream or a
// JSON body, as the content type says.
func decodeResponse(resp *http.Response, id int64) (*Response, error) {
	ct := mediaType(resp.Header.Get("Content-Type"))
	switch ct {
	case "text/event-stream":
		return readSSEResponse(resp.Body, id)
	default:
		var out Response
		dec := json.NewDecoder(io.LimitReader(resp.Body, MaxResponseBytes))
		if err := dec.Decode(&out); err != nil {
			if ct != "application/json" {
				return nil, &ContentTypeError{ContentType: ct, Err: err}
			}
			return nil, fmt.Errorf("transport: decode response: %w", err)
		}
		return &out, nil
	}
}

// readSSEResponse consumes an SSE stream until it finds the JSON-RPC
// response whose id matches want. Other messages on the stream (server
// requests, notifications) are skipped.
func readSSEResponse(r io.Reader, want int64) (*Response, error) {
	sc := bufio.NewScanner(io.LimitReader(r, MaxStreamBytes))
	sc.Buffer(make([]byte, 0, 64<<10), 16<<20)
	events := 0
	var data strings.Builder
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			if out, ok, err := flushSSEEvent(&data, want); err != nil || ok {
				return out, err
			}
			if events++; events > MaxStreamEvents {
				return nil, ErrStreamTooLarge
			}
		case strings.HasPrefix(line, ":"):
			// comment / keep-alive
		case strings.HasPrefix(line, "data:"):
			if data.Len() > 0 {
				data.WriteByte('\n')
			}
			data.WriteString(strings.TrimPrefix(strings.TrimPrefix(line, "data:"), " "))
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("transport: read sse: %w", err)
	}
	if out, ok, err := flushSSEEvent(&data, want); err != nil || ok {
		return out, err
	}
	return nil, fmt.Errorf("transport: stream ended without response for id %d", want)
}

// flushSSEEvent decodes the event accumulated in data, empties data, and
// reports whether it was the response to want.
func flushSSEEvent(data *strings.Builder, want int64) (*Response, bool, error) {
	if data.Len() == 0 {
		return nil, false, nil
	}
	payload := data.String()
	data.Reset()
	var out Response
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		// Not a response we understand (could be a batch or a server
		// request); skip it and keep reading the stream.
		return nil, false, nil //nolint:nilerr // deliberate: an unparsable event is skipped, not fatal
	}
	// out.Error is the JSON-RPC error member, not a Go error: a
	// response carrying one is still the response we were waiting for.
	if out.ID != nil && *out.ID == want && (out.Result != nil || out.Error != nil) {
		return &out, true, nil //nolint:nilerr // out.Error is a protocol field, not a failure of this function
	}
	return nil, false, nil
}
