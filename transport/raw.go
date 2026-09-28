// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"mime"
	"net/http"
	"time"
)

// RawResult is the HTTP-level view of one exchange, for conformance probes
// that need to see status codes and headers rather than only the JSON-RPC
// result.
type RawResult struct {
	Status      int
	Header      http.Header
	ContentType string
	Body        []byte // capped at 1 MiB
	Duration    time.Duration
	// Response is set when the body parsed as a single JSON-RPC response
	// (from JSON or from the first matching SSE event).
	Response *Response
}

// RawOptions tweaks a Do call away from the well-formed default.
type RawOptions struct {
	// HTTPMethod defaults to POST.
	HTTPMethod string
	// Body is sent verbatim; when nil and Request is set, Request is
	// marshalled.
	Body []byte
	// Request, when set and Body is nil, is marshalled as the body.
	Request *Request
	// Headers override the defaults (set a key to "" to delete it).
	Headers map[string]string
	// OmitSession suppresses the Mcp-Session-Id header.
	OmitSession bool
	// OmitProtocolVersion suppresses the MCP-Protocol-Version header.
	OmitProtocolVersion bool
	// SkipDialect sends Request exactly as given, without the protocol
	// metadata the active dialect would add. Use it for a probe whose whole
	// point is to send something malformed.
	SkipDialect bool
	// HeadersOnly returns once the status line and headers arrive, without
	// reading the body. A GET that opens an event stream is answered with
	// a stream a conforming server may hold open and idle indefinitely;
	// reading it would wait out the whole call timeout for nothing the
	// caller looks at.
	HeadersOnly bool
}

// NextID reserves a fresh JSON-RPC id.
func (s *Streamable) NextID() int64 { return s.nextID.Add(1) }

// Do performs one arbitrary HTTP exchange against the endpoint and reports
// what came back. It never mutates session state except to record a new
// Mcp-Session-Id the server hands out.
func (s *Streamable) Do(ctx context.Context, opts RawOptions) (*RawResult, error) {
	method := opts.HTTPMethod
	if method == "" {
		method = http.MethodPost
	}
	d := s.Dialect()
	body, err := rawBody(d, opts)
	if err != nil {
		return nil, err
	}
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, s.Endpoint, rdr)
	if err != nil {
		return nil, err
	}
	if body != nil {
		req.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
		req.Header.Set("Content-Type", "application/json")
	}
	if err := s.setRawHeaders(req.Header, d, opts); err != nil {
		return nil, err
	}
	start := time.Now()
	resp, err := s.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	out := &RawResult{Status: resp.StatusCode, Header: resp.Header.Clone()}
	out.ContentType, _, _ = mime.ParseMediaType(resp.Header.Get("Content-Type"))
	if sid := resp.Header.Get(HeaderSessionID); sid != "" {
		s.sessionID.Store(sid)
	}
	if opts.HeadersOnly {
		out.Duration = time.Since(start)
		return out, nil
	}
	// Bound how much we read of a stream that never ends.
	out.Body, _ = io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	out.Duration = time.Since(start)
	out.Response = parseRawResponse(out, opts.Request)
	return out, nil
}

// rawBody is the body Do sends: the caller's bytes as given, or the
// request marshalled, prepared for the dialect unless the probe skips it.
func rawBody(d Dialect, opts RawOptions) ([]byte, error) {
	body := opts.Body
	if body == nil && opts.Request != nil {
		// A conformance probe must still be a well-formed request of the
		// generation the server speaks, or what it answers says more about
		// the probe than the server. The stateless revision rejects a
		// request without its _meta fields before it ever looks at the
		// method being tested.
		if !opts.SkipDialect {
			if err := d.PrepareBody(opts.Request); err != nil {
				return nil, err
			}
		}
		b, err := json.Marshal(opts.Request)
		if err != nil {
			return nil, err
		}
		body = b
	}
	return body, nil
}

// setRawHeaders sets Accept, the dialect's routing headers, the protocol
// version and session id unless omitted, then the caller's headers, where
// an empty value deletes.
func (s *Streamable) setRawHeaders(h http.Header, d Dialect, opts RawOptions) error {
	h.Set("Accept", "application/json, text/event-stream")
	if !opts.SkipDialect {
		// The dialect owns the routing headers; anything the caller sets
		// below still wins, which is how a mismatch probe is written.
		if err := d.PrepareHeaders(h, opts.Request); err != nil {
			return err
		}
	}
	if opts.OmitProtocolVersion {
		h.Del(HeaderProtocolVersion)
	} else if h.Get(HeaderProtocolVersion) == "" {
		if v := s.ProtocolVersion(); v != "" {
			h.Set(HeaderProtocolVersion, v)
		}
	}
	if opts.OmitSession {
		h.Del(HeaderSessionID)
	} else if d.Stateful() {
		if sid := s.SessionID(); sid != "" {
			h.Set(HeaderSessionID, sid)
		}
	}
	for k, v := range opts.Headers {
		if v == "" {
			h.Del(k)
		} else {
			h.Set(k, v)
		}
	}
	return nil
}

// parseRawResponse decodes the JSON-RPC response in a raw exchange's body,
// from an SSE stream (matched to the request's id) or a JSON body, or nil
// when there is none.
func parseRawResponse(out *RawResult, req *Request) *Response {
	if out.ContentType == "text/event-stream" {
		if req != nil && req.ID != nil {
			if r, err := readSSEResponse(bytes.NewReader(out.Body), *req.ID); err == nil {
				return r
			}
		}
		return nil
	}
	if len(out.Body) > 0 {
		var r Response
		if json.Unmarshal(out.Body, &r) == nil && (r.ID != nil || r.Error != nil) {
			return &r
		}
	}
	return nil
}
