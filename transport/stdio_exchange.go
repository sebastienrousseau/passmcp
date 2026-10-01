// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

// StdioExchange describes one raw message to send, for a conformance probe
// that needs to send something the normal path would never produce.
type StdioExchange struct {
	// Body is sent verbatim, newline appended. It does not have to be
	// JSON: that is the point of the malformed-input probes.
	Body []byte
	// Request, when Body is nil, is marshalled instead.
	Request *Request
	// SkipDialect sends Request exactly as given, without the protocol
	// metadata the active dialect would otherwise add.
	SkipDialect bool
	// AnyMessage waits for the next message the server writes rather than
	// one matching an id.
	//
	// It is how the malformed-input probes read their answer: JSON-RPC
	// says a parse error is reported with a null id, so there is nothing
	// to match on. The cost is that a notification the server happened to
	// emit at that moment is taken for the answer — unavoidable with this
	// framing, and the reason this is opt-in rather than a fallback.
	AnyMessage bool
}

// StdioResult is what one raw exchange produced.
//
// There is no status code and no header: a pipe has neither, which is why
// this is a separate type from the HTTP transport's RawResult rather than
// that one with two fields left at zero for a caller to misread.
type StdioResult struct {
	// Line is the message the server wrote, verbatim.
	Line []byte
	// Response is set when Line parsed as a JSON-RPC response.
	Response *Response
	Duration time.Duration
}

// exchangeBody is the line Exchange writes: the caller's bytes as given, or
// the request marshalled, prepared for the dialect unless the probe skips it.
func (s *Stdio) exchangeBody(opts StdioExchange) ([]byte, error) {
	if opts.Body != nil {
		return opts.Body, nil
	}
	if opts.Request == nil {
		return nil, errors.New("transport: exchange needs a Body or a Request")
	}
	if !opts.SkipDialect {
		if err := s.Dialect().PrepareBody(opts.Request); err != nil {
			return nil, err
		}
	}
	return json.Marshal(opts.Request)
}

// Exchange sends one raw message and returns what the server answered.
//
// It is the pipe's counterpart to Streamable.Do, and it exists for the same
// reason: a conformance probe has to be able to send what a client library
// would refuse to. Unlike Do it cannot lie about transport framing, so the
// probes that are about HTTP — a missing Accept header, a session id the
// server never issued — have no form here and are reported as skipped
// rather than approximated.
func (s *Stdio) Exchange(ctx context.Context, opts StdioExchange) (*StdioResult, error) {
	body, err := s.exchangeBody(opts)
	if err != nil {
		return nil, err
	}
	// A newline inside the body would frame two messages, and the probe
	// would be measuring something other than what it wrote.
	if bytes.ContainsAny(body, "\n\r") {
		return nil, errors.New("transport: a raw stdio message cannot contain a newline")
	}

	var ch chan reply
	switch {
	case opts.AnyMessage || opts.Request == nil || opts.Request.ID == nil:
		ch, err = s.expectAny()
		defer s.forgetAny(ch)
	default:
		ch, err = s.expect(*opts.Request.ID)
		defer s.forget(*opts.Request.ID, ch)
	}
	if err != nil {
		return nil, err
	}

	start := time.Now()
	if err := s.writeLine(ctx, body); err != nil {
		s.observe(ctx, body, nil, time.Since(start), err)
		return nil, err
	}
	r, err := s.await(ctx, ch)
	if err != nil {
		s.observe(ctx, body, nil, time.Since(start), err)
		return nil, err
	}
	s.observe(ctx, body, r.line, time.Since(start), nil)
	return &StdioResult{Line: r.line, Response: r.resp, Duration: time.Since(start)}, nil
}

// Noise reports how many lines the server wrote to stdout that were not
// JSON-RPC messages, and the first of them.
//
// The stream is the wire: the specification says a stdio server must write
// nothing else there. A stray print statement is the most common way a
// stdio server is broken, and the symptom — a client that hangs or reports
// a parse error — never names the cause.
func (s *Stdio) Noise() (int, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.noise, s.noiseSample
}

// observe reports one exchange, if anybody asked.
func (s *Stdio) observe(ctx context.Context, sent, recv []byte, d time.Duration, err error) {
	if s.cfg.Observe == nil {
		return
	}
	s.cfg.Observe(ctx, StdioMessage{Sent: sent, Received: recv, Duration: d, Err: err})
}

// buildRPC assembles a request. Shared with the HTTP transport's own
// builder in everything but the receiver.
func buildRPC(id *int64, method string, params any) (*Request, error) {
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
