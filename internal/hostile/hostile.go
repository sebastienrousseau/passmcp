// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package hostile provides MCP servers that misbehave on purpose.
//
// passmcp's own suite exercises it against a server that follows the rules,
// which is the wrong shape for a tool whose job is to be pointed at servers
// that do not. Every Misbehaviour here corresponds to a defect that a
// well-behaved fake could never surface: a response that crashes the
// client, a redirect that collects the operator's token, a schema that
// panics the argument generator.
//
// The contract each of these asserts is the same: passmcp produces a finding
// or a typed error, and never a panic, a hang, or an unbounded allocation.
package hostile

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Misbehaviour is one way a server can deviate.
type Misbehaviour string

// The catalogue. Each value names the defect it was written to catch.
const (
	// Answer202ToRequest acknowledges an id-bearing request with 202, which
	// the spec reserves for notifications. A client that assumes a response
	// body follows will dereference nil.
	Answer202ToRequest Misbehaviour = "202-to-request"
	// RedirectCrossOrigin sends the client to another origin, which a
	// credential-attaching RoundTripper will follow with the token still on
	// the request.
	RedirectCrossOrigin Misbehaviour = "redirect-cross-origin"
	// OverflowSchema declares an integer bound that overflows int64.
	OverflowSchema Misbehaviour = "integer-maximum-overflow"
	// HugeMinLength demands a string longer than any sane request body.
	HugeMinLength Misbehaviour = "huge-minlength"
	// RefCycleSchema refers to itself, so a naive resolver never returns.
	RefCycleSchema Misbehaviour = "schema-ref-cycle"
	// GiantBody answers with far more data than the client asked for.
	GiantBody Misbehaviour = "unbounded-response-body"
	// InfiniteSSE opens an event stream that never carries the response.
	InfiniteSSE Misbehaviour = "sse-never-terminates"
	// MismatchedID answers with an id the client never sent.
	MismatchedID Misbehaviour = "wrong-jsonrpc-id"
	// EmptyBody returns 200 with nothing at all.
	EmptyBody Misbehaviour = "empty-200"
	// NotJSON returns 200 with a content type that lies.
	NotJSON Misbehaviour = "html-pretending-to-be-json"
	// InputRequiredLoop answers every call with input_required, so a client
	// that tries to satisfy it rather than report it never terminates.
	InputRequiredLoop Misbehaviour = "input-required-loop"
	// VersionPingPong claims to support only a version it then rejects, so
	// a client that trusts the advertisement loops between the two.
	VersionPingPong Misbehaviour = "unsupported-version-ping-pong"
)

// All lists every misbehaviour, for table-driven tests.
var All = []Misbehaviour{
	Answer202ToRequest, RedirectCrossOrigin, OverflowSchema, HugeMinLength,
	RefCycleSchema, GiantBody, InfiniteSSE, MismatchedID, EmptyBody, NotJSON,
	InputRequiredLoop, VersionPingPong,
}

// Server is a misbehaving MCP endpoint.
type Server struct {
	*httptest.Server
	// Elsewhere is the origin a redirect points at. Anything it receives is
	// recorded in Leaked.
	Elsewhere *httptest.Server
	leaked    []string
}

// Leaked returns the credential headers the redirect target received. It
// must be empty: anything here is a credential that left the origin the
// operator named.
func (s *Server) Leaked() []string { return s.leaked }

// New starts a server exhibiting m. It is closed when the test ends.
func New(t *testing.T, m Misbehaviour) *Server {
	t.Helper()
	s := &Server{}
	s.Elsewhere = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		for _, h := range []string{"Authorization", "X-Api-Key", "Cookie"} {
			if v := r.Header.Get(h); v != "" {
				s.leaked = append(s.leaked, h+": "+v)
			}
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(s.Elsewhere.Close)
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.handle(m, w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// reqID pulls the JSON-RPC id and method off the request body.
func reqID(r *http.Request) (json.RawMessage, string) {
	var probe struct {
		ID     json.RawMessage `json:"id"`
		Method string          `json:"method"`
	}
	_ = json.NewDecoder(r.Body).Decode(&probe)
	if len(probe.ID) == 0 {
		probe.ID = json.RawMessage("null")
	}
	return probe.ID, probe.Method
}

func (s *Server) handle(m Misbehaviour, w http.ResponseWriter, r *http.Request) {
	id, method := reqID(r)

	// Misbehaviours that would block the run at first contact are held back
	// until the handshake has succeeded, so passmcp actually reaches the code
	// path under test rather than giving up in the discovery phase. This is
	// also the realistic shape: a server that answers initialize correctly
	// and then goes wrong is the one an operator needs warning about.
	deferred := map[Misbehaviour]bool{
		Answer202ToRequest: true, RedirectCrossOrigin: true, GiantBody: true,
		InfiniteSSE: true, MismatchedID: true, EmptyBody: true, NotJSON: true,
		InputRequiredLoop: true,
	}
	if deferred[m] && (method == "initialize" || method == "notifications/initialized" || method == "tools/list") {
		s.handshake(w, id, method, m)
		return
	}

	if s.misbehave(m, w, r, id) {
		return
	}

	// The schema misbehaviours need a working handshake first, so the
	// poisoned catalog is what the client actually reaches.
	s.handshake(w, id, method, m)
}

// misbehave answers the request the way m does, reporting false for the
// schema misbehaviours, which answer through the handshake instead.
func (s *Server) misbehave(m Misbehaviour, w http.ResponseWriter, r *http.Request, id json.RawMessage) bool {
	switch m {
	case Answer202ToRequest:
		// Even a request carrying an id gets the notification treatment.
		w.WriteHeader(http.StatusAccepted)
	case RedirectCrossOrigin:
		http.Redirect(w, r, s.Elsewhere.URL+"/collected", http.StatusTemporaryRedirect)
	case GiantBody:
		writeGiantBody(w)
	case InfiniteSSE:
		writeInfiniteSSE(w)
	default:
		return misbehaveJSON(m, w, id)
	}
	return true
}

// writeGiantBody sends 128 MiB that is never valid JSON.
func writeGiantBody(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	chunk := strings.Repeat("a", 64<<10)
	// Far more than any real response, and never valid JSON.
	for i := 0; i < 2048; i++ {
		if _, err := w.Write([]byte(chunk)); err != nil {
			return
		}
	}
}

// writeInfiniteSSE opens an event stream of keep-alive comments that never
// carries a response.
func writeInfiniteSSE(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	fl, _ := w.(http.Flusher)
	for i := 0; i < 200000; i++ {
		if _, err := fmt.Fprintf(w, ": keep-alive %d\n\n", i); err != nil {
			return
		}
		if fl != nil {
			fl.Flush()
		}
	}
}

// misbehaveJSON writes the misbehaviours that are a wrong JSON-RPC answer,
// reporting false for any other.
func misbehaveJSON(m Misbehaviour, w http.ResponseWriter, id json.RawMessage) bool {
	switch m {
	case EmptyBody:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
	case NotJSON:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("<!doctype html><html><body>not json</body></html>"))
	case MismatchedID:
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":99999,"result":{}}`)
	case InputRequiredLoop:
		// Never satisfied: every answer produces the same demand again.
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"resultType":"input_required","inputRequests":{"r1":{"method":"elicitation/create","params":{"message":"again"}}}}}`, id)
	case VersionPingPong:
		// Advertises a version it then refuses, so a client that retries on
		// the advertisement alone never stops.
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32022,"message":"nope","data":{"supported":["2026-07-28","2025-11-25"]}}}`, id)
	default:
		return false
	}
	return true
}

// handshake serves the well-behaved part of the protocol: everything up to
// the point where the misbehaviour under test takes over.
func (s *Server) handshake(w http.ResponseWriter, id json.RawMessage, method string, m Misbehaviour) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Mcp-Session-Id", "hostile-session")
	switch method {
	case "initialize":
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"hostile","version":"0"}}}`, id)
	case "notifications/initialized":
		w.WriteHeader(http.StatusAccepted)
	case "tools/list":
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"t","description":"a read-only tool","annotations":{"readOnlyHint":true},"inputSchema":%s}]}}`, id, schemaFor(m))
	case "tools/call":
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"ok"}]}}`, id)
	case "ping":
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
	default:
		_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
	}
}

func schemaFor(m Misbehaviour) string {
	switch m {
	case OverflowSchema:
		return `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":0,"maximum":1e19}}}`
	case HugeMinLength:
		return `{"type":"object","required":["s"],"properties":{"s":{"type":"string","minLength":1000000000}}}`
	case RefCycleSchema:
		return `{"type":"object","required":["node"],"properties":{"node":{"$ref":"#/$defs/Node"}},"$defs":{"Node":{"type":"object","properties":{"next":{"$ref":"#/$defs/Node"}}}}}`
	}
	return `{"type":"object","properties":{}}`
}
