// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/engine"
)

// streamRun serves a subscriber one of two ways: it replays a finished run
// and returns, or it follows a running one through a select loop. Which one
// a test takes was decided by a race between the run and the subscriber,
// so each was covered only by luck — and on a slower machine the luck ran
// the other way. That is not a flaky test so much as a flaky *gap*: CI
// reported this package eight points lower than a laptop did, because a
// different half of the function went unexercised.
//
// These tests pin the timing instead of hoping for it. A gated MCP server
// holds the run open until the test says otherwise, so "still running" and
// "already finished" are facts the test establishes rather than outcomes it
// races for.

// gatedMCP is mcpServer with a latch: tools/list blocks until release is
// closed, which keeps a run demonstrably in flight.
func gatedMCP(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	release := make(chan struct{})
	var once bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		id := req.ID
		if len(id) == 0 {
			id = json.RawMessage("null")
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Mcp-Session-Id", "s1")
		switch req.Method {
		case "initialize":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-11-25","capabilities":{"tools":{}},"serverInfo":{"name":"demo","version":"1.0"}}}`, id)
		case "notifications/initialized":
			w.WriteHeader(http.StatusAccepted)
		case "tools/list":
			// Hold the first catalogue call until the test releases it.
			// Later calls pass straight through so the run can finish.
			if !once {
				once = true
				select {
				case <-release:
				case <-r.Context().Done():
					return
				case <-time.After(30 * time.Second):
				}
			}
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"t","description":"A tool that looks things up.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}}]}}`, id)
		case "ping", "tools/call":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	var closed bool
	return srv, func() {
		if !closed {
			closed = true
			close(release)
		}
	}
}

// start posts a spec and returns the run id.
func start(t *testing.T, ts *httptest.Server, tok, endpoint string) string {
	t.Helper()
	spec := fmt.Sprintf(`{"target":{"endpoint":%q},"pacing":{"rps":0,"samples":1},"phases":{"only":["net","handshake","catalog"]}}`, endpoint+"/mcp")
	resp := do(t, ts, http.MethodPost, "/api/runs?t="+tok, spec, map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	var started map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	if started["id"] == "" {
		t.Fatal("no run id")
	}
	return started["id"]
}

// openStream subscribes and returns a scanner over the SSE body.
func openStream(t *testing.T, ts *httptest.Server, ctx context.Context, path string) (*bufio.Scanner, func()) {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+path, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("stream: %d", resp.StatusCode)
	}
	return bufio.NewScanner(resp.Body), func() { _ = resp.Body.Close() }
}

// nextEvent reads until the next data record, or fails.
func nextEvent(t *testing.T, sc *bufio.Scanner) map[string]any {
	t.Helper()
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var e map[string]any
		if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e) != nil {
			continue
		}
		return e
	}
	t.Fatal("the stream ended before the next event")
	return nil
}

// attachedLive asserts the subscriber is on the live path rather than the
// replay one. Reading an event is not enough to tell them apart — a
// finished run replays the same phase_start first — but only the live path
// registers a subscription, so that is what the test checks.
func attachedLive(t *testing.T, s *Server, id string) *run {
	t.Helper()
	s.mu.Lock()
	rn := s.runs[id]
	s.mu.Unlock()
	if rn == nil {
		t.Fatal("no such run")
	}
	rn.mu.Lock()
	done, subs := rn.done, len(rn.subs)
	rn.mu.Unlock()
	if done {
		t.Fatal("the run finished before the stream attached; the latch did not hold")
	}
	if subs != 1 {
		t.Fatalf("expected one live subscription, got %d; the stream took the replay path", subs)
	}
	return rn
}

// TestStreamFollowsRunInFlight covers the live path: the subscriber is
// attached while the run is provably still going, so events arrive over the
// channel and the stream closes when the run does.
func TestStreamFollowsRunInFlight(t *testing.T) {
	mcp, release := gatedMCP(t)
	s, ts := newTestServer(t)
	tok := s.Token()
	id := start(t, ts, tok, mcp.URL)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sc, closeBody := openStream(t, ts, ctx, "/api/runs/"+id+"/events?t="+tok)
	defer closeBody()

	// The run is latched inside tools/list, so this event came over the
	// live channel rather than out of a replayed backlog.
	nextEvent(t, sc)
	attachedLive(t, s, id)

	release()

	var done map[string]any
	for i := 0; i < 500 && done == nil; i++ {
		e := nextEvent(t, sc)
		if e["type"] == "done" {
			done = e
		}
	}
	if done == nil {
		t.Fatal("the stream never closed with a done record")
	}
	if _, ok := done["report"]; !ok {
		t.Error("the done record should carry the report")
	}
}

// TestStreamReplaysFinishedRun covers the other path: subscribing to a run
// that has already ended replays the backlog and closes, without entering
// the select loop at all.
func TestStreamReplaysFinishedRun(t *testing.T) {
	mcp := mcpServer(t)
	s, ts := newTestServer(t)
	tok := s.Token()
	id := start(t, ts, tok, mcp.URL)

	// Drain the first stream to completion. When this returns the run is
	// finished, so the second subscriber cannot take the live path.
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	sc, closeBody := openStream(t, ts, ctx, "/api/runs/"+id+"/events?t="+tok)
	for i := 0; i < 500; i++ {
		if nextEvent(t, sc)["type"] == "done" {
			break
		}
	}
	closeBody()

	// Wait for the report to be readable: the done record is written before
	// finish() stores the result, so a replay must not assume otherwise.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if do(t, ts, http.MethodGet, "/api/runs/"+id+"/report.json?t="+tok, "", nil).StatusCode == http.StatusOK {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	sc2, closeBody2 := openStream(t, ts, ctx, "/api/runs/"+id+"/events?t="+tok)
	defer closeBody2()
	var kinds int
	var done map[string]any
	for i := 0; i < 500 && done == nil; i++ {
		e := nextEvent(t, sc2)
		kinds++
		if e["type"] == "done" {
			done = e
		}
	}
	if done == nil {
		t.Fatal("a replayed run should still end in a done record")
	}
	if kinds < 2 {
		t.Errorf("the replay carried %d events; the backlog should come with it", kinds)
	}
}

// TestStreamStopsWhenClientDisconnects covers the context branch of the
// select loop: a browser that closes the tab ends the handler.
func TestStreamStopsWhenClientDisconnects(t *testing.T) {
	mcp, release := gatedMCP(t)
	defer release()
	s, ts := newTestServer(t)
	tok := s.Token()
	id := start(t, ts, tok, mcp.URL)

	ctx, cancel := context.WithCancel(context.Background())
	sc, closeBody := openStream(t, ts, ctx, "/api/runs/"+id+"/events?t="+tok)
	nextEvent(t, sc)
	rn := attachedLive(t, s, id)
	cancel()
	closeBody()

	// The handler must let go of the subscription rather than leaking it.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		rn.mu.Lock()
		n := len(rn.subs)
		rn.mu.Unlock()
		if n == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Error("the subscription outlived the client")
}

// TestStreamNeedsAFlusher covers the guard for a ResponseWriter that cannot
// flush, which would otherwise buffer an event stream into uselessness.
func TestStreamNeedsAFlusher(t *testing.T) {
	s, _ := newTestServer(t)
	s.mu.Lock()
	s.runs["x"] = &run{id: "x", subs: map[chan engine.Event]struct{}{}}
	s.mu.Unlock()

	req := httptest.NewRequest(http.MethodGet, "/api/runs/x/events", nil)
	req.SetPathValue("id", "x")
	rec := &unflushable{ResponseWriter: httptest.NewRecorder()}
	s.streamRun(rec, req)
	if rec.code != http.StatusInternalServerError {
		t.Errorf("a writer that cannot flush should be refused, got %d", rec.code)
	}
}

// unflushable deliberately does not implement http.Flusher.
type unflushable struct {
	http.ResponseWriter
	code int
}

func (u *unflushable) WriteHeader(c int) { u.code = c; u.ResponseWriter.WriteHeader(c) }

// TestIsLoopback covers the host forms New accepts without --allow-remote.
func TestIsLoopback(t *testing.T) {
	for _, tc := range []struct {
		host string
		want bool
	}{
		{"localhost", true},
		{"", true},
		{"127.0.0.1", true},
		{"::1", true},
		{"0.0.0.0", false},
		{"example.com", false},
		{"8.8.8.8", false},
	} {
		if got := isLoopback(tc.host); got != tc.want {
			t.Errorf("isLoopback(%q) = %v, want %v", tc.host, got, tc.want)
		}
	}
}

// TestCookieCarriesTheToken covers the third place authorized looks: the
// report page is opened by the browser itself, which sends no header.
func TestCookieCarriesTheToken(t *testing.T) {
	s, ts := newTestServer(t)

	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/runs/none/report.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(&http.Cookie{Name: "passmcp_token", Value: s.Token()})
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Authorized, so the run is merely absent rather than the request refused.
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("a cookie should authorize the request, got %d", resp.StatusCode)
	}

	req2, err := http.NewRequest(http.MethodGet, ts.URL+"/api/runs/none/report.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req2.AddCookie(&http.Cookie{Name: "passmcp_token", Value: "not-the-token"})
	resp2, err := ts.Client().Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Errorf("a wrong cookie is not authorization, got %d", resp2.StatusCode)
	}
}

// TestReportIsAbsentUntilTheRunEnds covers report()'s nil result: asking for
// a report mid-run is a 404, not a half-written document.
func TestReportIsAbsentUntilTheRunEnds(t *testing.T) {
	mcp, release := gatedMCP(t)
	defer release()
	s, ts := newTestServer(t)
	tok := s.Token()
	id := start(t, ts, tok, mcp.URL)

	// Latched inside tools/list, so there is provably no result yet.
	if got := do(t, ts, http.MethodGet, "/api/runs/"+id+"/report.json?t="+tok, "", nil).StatusCode; got != http.StatusNotFound {
		t.Errorf("report.json during a run should be 404, got %d", got)
	}
	if got := do(t, ts, http.MethodGet, "/runs/"+id+"/report.html?t="+tok, "", nil).StatusCode; got != http.StatusNotFound {
		t.Errorf("report.html during a run should be 404, got %d", got)
	}
}

// TestDoneEventNamesTheFailure covers the error branch of doneEvent.
func TestDoneEventNamesTheFailure(t *testing.T) {
	rn := &run{id: "x", failure: "the endpoint refused the connection"}
	e := rn.doneEvent()
	if e["error"] != "the endpoint refused the connection" {
		t.Errorf("a failed run should say why: %v", e)
	}
	if _, ok := e["report"]; ok {
		t.Error("a run with no result should carry no report")
	}
}

// TestTokenInURLSetsTheCookie is the half that was missing.
//
// authorized() read a passmcp_token cookie from the day it was written, and
// nothing ever set one. The printed URL therefore authorised exactly one
// request — the HTML — because a browser does not append a query string to
// a stylesheet or a script. Every asset came back 401, and since a 401 body
// is text/plain the console blamed the MIME type, which is a long way from
// the cause.
func TestTokenInURLSetsTheCookie(t *testing.T) {
	s, ts := newTestServer(t)

	resp, err := ts.Client().Get(ts.URL + "/?t=" + s.Token())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("the token-bearing page returned %d", resp.StatusCode)
	}

	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "passmcp_token" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no passmcp_token cookie was set; every asset the page loads will be refused")
	}
	if cookie.Value != s.Token() {
		t.Errorf("cookie carries %q, want the server token", cookie.Value)
	}
	if !cookie.HttpOnly {
		t.Error("the cookie is readable from script")
	}
	if cookie.SameSite != http.SameSiteStrictMode {
		t.Errorf("SameSite = %v, want Strict", cookie.SameSite)
	}
	// Secure would stop a browser storing it over loopback http, which is
	// the default listener — so it must be off unless the request was TLS.
	if cookie.Secure {
		t.Error("Secure is set on a plaintext listener; the browser would drop the cookie")
	}

	// The point of all of it: a second request carrying only the cookie,
	// with no token in the URL, is authorised.
	req, err := http.NewRequest(http.MethodGet, ts.URL+"/api/runs/none/report.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp2, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode == http.StatusUnauthorized {
		t.Error("the cookie the server itself set did not authorise the next request")
	}
}

// TestAssetsStayRefusedWithoutAuthorization: the cookie is a convenience for
// a page that already proved it had the token, not a way in.
func TestAssetsStayRefusedWithoutAuthorization(t *testing.T) {
	_, ts := newTestServer(t)
	resp, err := ts.Client().Get(ts.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("an unauthenticated request returned %d, want 401", resp.StatusCode)
	}
	if len(resp.Cookies()) != 0 {
		t.Error("a refused request handed out a cookie")
	}
}
