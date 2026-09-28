// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestDoBranches(t *testing.T) {
	var seen http.Header
	var seenMethod, seenBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		seenMethod = r.Method
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		seenBody = string(b[:n])
		switch r.URL.Query().Get("mode") {
		case "sse":
			w.Header().Set("Content-Type", "text/event-stream")
			var req Request
			_ = json.Unmarshal(b[:n], &req)
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"ok\":true}}\n\n", *req.ID)
		case "sse-nomatch":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: {\"jsonrpc\":\"2.0\",\"method\":\"n\"}\n\n")
		case "session":
			w.Header().Set(HeaderSessionID, "fresh-session")
			w.WriteHeader(204)
		case "notjson":
			w.Header().Set("Content-Type", "text/plain")
			fmt.Fprint(w, "hello")
		case "errobj":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, `{"jsonrpc":"2.0","id":null,"error":{"code":-32700,"message":"parse"}}`)
		default:
			w.WriteHeader(202)
		}
	}))
	defer srv.Close()

	s := New(srv.URL+"?mode=sse", srv.Client())
	s.SetProtocolVersion("2025-11-25")
	s.SetSessionID("sess")
	id := s.NextID()
	res, err := s.Do(context.Background(), RawOptions{Request: &Request{JSONRPC: "2.0", ID: &id, Method: "ping"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 200 || res.ContentType != "text/event-stream" || res.Response == nil || res.Response.ID == nil || *res.Response.ID != id {
		t.Errorf("sse result = %+v", res)
	}
	if seen.Get(HeaderProtocolVersion) != "2025-11-25" || seen.Get(HeaderSessionID) != "sess" || seen.Get("Content-Type") != "application/json" || seenMethod != "POST" {
		t.Errorf("default headers: %v", seen)
	}

	// SSE stream with no matching response leaves Response nil.
	s2 := New(srv.URL+"?mode=sse-nomatch", srv.Client())
	id2 := s2.NextID()
	res, err = s2.Do(context.Background(), RawOptions{Request: &Request{JSONRPC: "2.0", ID: &id2, Method: "ping"}})
	if err != nil || res.Response != nil {
		t.Errorf("nomatch: %v %+v", err, res)
	}

	// Omit headers, override and delete headers, raw body, GET.
	s3 := New(srv.URL+"?mode=session", srv.Client())
	s3.SetProtocolVersion("v")
	s3.SetSessionID("old")
	res, err = s3.Do(context.Background(), RawOptions{HTTPMethod: http.MethodGet, OmitSession: true, OmitProtocolVersion: true, Headers: map[string]string{"Accept": "", "X-Custom": "1"}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != 204 || seenMethod != "GET" || seen.Get(HeaderSessionID) != "" || seen.Get(HeaderProtocolVersion) != "" || seen.Get("Accept") != "" || seen.Get("X-Custom") != "1" {
		t.Errorf("GET headers: status=%d %v", res.Status, seen)
	}
	if s3.SessionID() != "fresh-session" {
		t.Errorf("session id not captured: %q", s3.SessionID())
	}

	// Raw body wins over Request.
	s4 := New(srv.URL+"?mode=notjson", srv.Client())
	id4 := s4.NextID()
	res, err = s4.Do(context.Background(), RawOptions{Body: []byte("{raw}"), Request: &Request{ID: &id4}})
	if err != nil || seenBody != "{raw}" || res.Response != nil || string(res.Body) != "hello" {
		t.Errorf("raw body: %v %q %+v", err, seenBody, res)
	}

	// JSON body with an error object and no id is still a Response.
	s5 := New(srv.URL+"?mode=errobj", srv.Client())
	res, err = s5.Do(context.Background(), RawOptions{Body: []byte("x")})
	if err != nil || res.Response == nil || res.Response.Error == nil || res.Response.Error.Code != -32700 {
		t.Errorf("errobj: %v %+v", err, res)
	}

	// Transport error surfaces.
	s6 := New("http://127.0.0.1:1/x", srv.Client())
	if _, err := s6.Do(context.Background(), RawOptions{}); err == nil {
		t.Error("expected connection error")
	}
	// Bad method is rejected when building the request.
	if _, err := s.Do(context.Background(), RawOptions{HTTPMethod: "BAD METHOD"}); err == nil {
		t.Error("expected invalid method error")
	}
}

func TestSendBranches(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req Request
		_ = json.NewDecoder(r.Body).Decode(&req)
		switch req.Method {
		case "notify200":
			w.WriteHeader(200)
			fmt.Fprint(w, "ignored")
		case "sse-error":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprintf(w, "data: {\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-1,\"message\":\"boom\"}}\n\n", *req.ID)
		case "badjson":
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprint(w, "{not json")
		case "badresult":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":"string"}`, *req.ID)
		case "server-error":
			w.WriteHeader(500)
			fmt.Fprint(w, "oops")
		case "stream-end":
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, ": only comments\n\n")
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%d,"result":{}}`, *req.ID)
		}
	}))
	defer srv.Close()
	s := New(srv.URL, nil)
	s.Client = srv.Client()
	ctx := context.Background()
	if err := s.Notify(ctx, "notify200", map[string]int{"a": 1}); err != nil {
		t.Errorf("notify 200: %v", err)
	}
	err := s.Call(ctx, "sse-error", nil, nil)
	var rpc *RPCError
	if !errors.As(err, &rpc) || rpc.Code != -1 || !strings.Contains(rpc.Error(), "-1") {
		t.Errorf("sse error: %v", err)
	}
	if err := s.Call(ctx, "badjson", nil, nil); err == nil || !strings.Contains(err.Error(), "decode response") {
		t.Errorf("badjson: %v", err)
	}
	var out struct{ X int }
	if err := s.Call(ctx, "badresult", nil, &out); err == nil || !strings.Contains(err.Error(), "decode badresult result") {
		t.Errorf("badresult: %v", err)
	}
	err = s.Call(ctx, "server-error", nil, nil)
	var he *HTTPStatusError
	if !errors.As(err, &he) || he.StatusCode != 500 || string(he.Body) != "oops" || !strings.Contains(he.Error(), "500") {
		t.Errorf("server error: %v", err)
	}
	if err := s.Call(ctx, "stream-end", nil, nil); err == nil || !strings.Contains(err.Error(), "stream ended") {
		t.Errorf("stream end: %v", err)
	}
	// Params that cannot be encoded.
	if err := s.Call(ctx, "x", func() {}, nil); err == nil || !strings.Contains(err.Error(), "encode params") {
		t.Errorf("encode params: %v", err)
	}
	if err := s.Notify(ctx, "x", func() {}); err == nil {
		t.Error("notify encode params should fail")
	}
	if New("x", nil).Client != http.DefaultClient {
		t.Error("nil client defaults")
	}
}

func TestReadSSEEdgeCases(t *testing.T) {
	// Response found in the final unterminated event.
	r, err := readSSEResponse(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":5,\"result\":{}}"), 5)
	if err != nil || r == nil || *r.ID != 5 {
		t.Errorf("unterminated: %v %+v", err, r)
	}
	// Non-JSON data lines are skipped.
	if _, err := readSSEResponse(strings.NewReader("data: junk\n\ndata: {\"jsonrpc\":\"2.0\",\"id\":9,\"result\":{}}\n\n"), 9); err != nil {
		t.Errorf("skip junk: %v", err)
	}
	// Response for another id is skipped, then stream ends.
	if _, err := readSSEResponse(strings.NewReader("data: {\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\n\n"), 2); err == nil {
		t.Error("expected stream ended error")
	}
	// Reader error.
	if _, err := readSSEResponse(errReader{}, 1); err == nil || !strings.Contains(err.Error(), "read sse") {
		t.Errorf("reader error: %v", err)
	}
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, errors.New("broken pipe") }

// TestDoHeadersOnly holds an event stream open after its headers: with
// HeadersOnly, Do returns the status and content type without waiting for
// a body that never ends, and closing it lets the handler go.
func TestDoHeadersOnly(t *testing.T) {
	released := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream; charset=utf-8")
		w.Header().Set(HeaderSessionID, "sid-stream")
		_, _ = w.Write([]byte(": open\n\n"))
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(released)
	}))
	defer srv.Close()
	s := New(srv.URL, &http.Client{Timeout: 10 * time.Second})
	res, err := s.Do(context.Background(), RawOptions{HTTPMethod: http.MethodGet, HeadersOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != http.StatusOK || res.ContentType != "text/event-stream" || len(res.Body) != 0 {
		t.Errorf("got %d %q body %q", res.Status, res.ContentType, res.Body)
	}
	if res.Duration >= 5*time.Second {
		t.Errorf("Do took %s on a held-open stream", res.Duration)
	}
	if s.SessionID() != "sid-stream" {
		t.Errorf("session id %q not recorded", s.SessionID())
	}
	select {
	case <-released:
	case <-time.After(5 * time.Second):
		t.Error("the stream was not closed after Do returned")
	}
}
