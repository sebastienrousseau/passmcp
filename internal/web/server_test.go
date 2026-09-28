// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// mcpServer is a small, well-behaved MCP server to point runs at.
func mcpServer(t *testing.T) *httptest.Server {
	t.Helper()
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
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"tools":[{"name":"t","description":"A tool that looks things up.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object"}}]}}`, id)
		case "ping", "tools/call":
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
		default:
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"error":{"code":-32601,"message":"no such method"}}`, id)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	s, err := New(Options{Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return s, ts
}

func do(t *testing.T, ts *httptest.Server, method, path string, body string, hdr map[string]string) *http.Response {
	t.Helper()
	var rdr *strings.Reader
	if body != "" {
		rdr = strings.NewReader(body)
	}
	var req *http.Request
	var err error
	if rdr != nil {
		req, err = http.NewRequest(method, ts.URL+path, rdr)
	} else {
		req, err = http.NewRequest(method, ts.URL+path, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = resp.Body.Close() })
	return resp
}

// passmcp tells every MCP server to bind loopback and validate Origin. A
// diagnostic that does not follow its own advice has no standing to give
// it, so these three are the ones that must never regress.
func TestGuards(t *testing.T) {
	s, ts := newTestServer(t)
	tok := s.Token()

	cases := []struct {
		name, path string
		hdr        map[string]string
		want       int
	}{
		{"with token", "/?t=" + tok, nil, http.StatusOK},
		{"no token", "/", nil, http.StatusUnauthorized},
		{"wrong token", "/?t=nope", nil, http.StatusUnauthorized},
		{"token in header", "/", map[string]string{"X-Passmcp-Token": tok}, http.StatusOK},
		{"cross origin", "/?t=" + tok, map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := do(t, ts, http.MethodGet, c.path, "", c.hdr).StatusCode; got != c.want {
				t.Errorf("status %d, want %d", got, c.want)
			}
		})
	}
	// Same-origin is allowed: the page's own fetches carry an Origin.
	host := strings.TrimPrefix(ts.URL, "http://")
	if got := do(t, ts, http.MethodGet, "/?t="+tok, "", map[string]string{"Origin": "http://" + host}).StatusCode; got != http.StatusOK {
		t.Errorf("same-origin refused: %d", got)
	}
}

// Binding anywhere but loopback is refused, because this listener starts
// authenticated runs and holds their reports.
func TestRemoteBindRefused(t *testing.T) {
	if _, err := New(Options{Addr: "0.0.0.0:0"}); err == nil {
		t.Fatal("a non-loopback bind must be refused by default")
	} else if !strings.Contains(err.Error(), "--allow-remote") {
		t.Errorf("the error should name the override: %v", err)
	}
	if _, err := New(Options{Addr: "0.0.0.0:0", AllowRemote: true}); err != nil {
		t.Errorf("--allow-remote must permit it: %v", err)
	}
	if _, err := New(Options{Addr: "nonsense"}); err == nil {
		t.Error("an unparsable address must be an error")
	}
	if s, err := New(Options{}); err != nil || s.Token() == "" {
		t.Errorf("the default must be a loopback server with a token: %v", err)
	}
}

// One validator for every surface: a browser gets the CLI's error, not a
// different one.
func TestStartRunValidation(t *testing.T) {
	s, ts := newTestServer(t)
	q := "?t=" + s.Token()
	cases := map[string]string{
		"not json":      `{`,
		"no endpoint":   `{}`,
		"relative":      `{"target":{"endpoint":"/mcp"}}`,
		"bad format":    `{"target":{"endpoint":"https://x/mcp"},"output":{"format":"pdf"}}`,
		"unknown phase": `{"target":{"endpoint":"https://x/mcp"},"phases":{"only":["nonsense"]}}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := do(t, ts, http.MethodPost, "/api/runs"+q, body, map[string]string{"Content-Type": "application/json"})
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("status %d, want 400", resp.StatusCode)
			}
			var out map[string]string
			_ = json.NewDecoder(resp.Body).Decode(&out)
			if out["error"] == "" {
				t.Error("a rejection must say why")
			}
		})
	}
}

// The whole point of the surface: a run started from a browser is the run
// the CLI would have started.
func TestRunEndToEnd(t *testing.T) {
	mcp := mcpServer(t)
	s, ts := newTestServer(t)
	q := "?t=" + s.Token()

	spec := fmt.Sprintf(`{"target":{"endpoint":%q},"pacing":{"rps":0,"samples":1},"phases":{"only":["net","handshake","catalog"]}}`, mcp.URL+"/mcp")
	resp := do(t, ts, http.MethodPost, "/api/runs"+q, spec, map[string]string{"Content-Type": "application/json"})
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("start: %d", resp.StatusCode)
	}
	var started map[string]string
	if err := json.NewDecoder(resp.Body).Decode(&started); err != nil {
		t.Fatal(err)
	}
	id := started["id"]
	if id == "" {
		t.Fatal("no run id")
	}

	// The event stream carries the run and closes with a done record.
	kinds := map[string]int{}
	var doneEvent map[string]any
	func() {
		req, _ := http.NewRequest(http.MethodGet, ts.URL+"/api/runs/"+id+"/events"+q, nil)
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		r, err := ts.Client().Do(req.WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = r.Body.Close() }()
		if ct := r.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
			t.Fatalf("content type %q", ct)
		}
		sc := bufio.NewScanner(r.Body)
		for sc.Scan() {
			line := sc.Text()
			if !strings.HasPrefix(line, "data: ") {
				continue
			}
			var e map[string]any
			if json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &e) != nil {
				continue
			}
			kind, _ := e["type"].(string)
			kinds[kind]++
			if kind == "done" {
				doneEvent = e
				return
			}
		}
	}()

	for _, k := range []string{"phase_start", "phase_done", "done"} {
		if kinds[k] == 0 {
			t.Errorf("no %s event", k)
		}
	}
	if doneEvent == nil {
		t.Fatal("the stream never closed with a done record")
	}
	if _, ok := doneEvent["report"]; !ok {
		t.Error("the done record should carry the report")
	}

	// And the report is retrievable in both renderings.
	jsonResp := do(t, ts, http.MethodGet, "/api/runs/"+id+"/report.json"+q, "", nil)
	if jsonResp.StatusCode != http.StatusOK {
		t.Fatalf("report.json: %d", jsonResp.StatusCode)
	}
	var rep map[string]any
	if err := json.NewDecoder(jsonResp.Body).Decode(&rep); err != nil {
		t.Fatal(err)
	}
	if phases, _ := rep["phases"].([]any); len(phases) != 3 {
		t.Errorf("the spec asked for three phases, got %d", len(phases))
	}

	htmlResp := do(t, ts, http.MethodGet, "/runs/"+id+"/report.html"+q, "", nil)
	if htmlResp.StatusCode != http.StatusOK {
		t.Fatalf("report.html: %d", htmlResp.StatusCode)
	}
	if ct := htmlResp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content type %q", ct)
	}
	htmlBody, err := io.ReadAll(htmlResp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(htmlBody), "<!doctype html>") {
		t.Error("report.html is not a document")
	}

	// A reconnecting browser gets the whole run replayed, not just what
	// happens next.
	replay := do(t, ts, http.MethodGet, "/api/runs/"+id+"/events"+q, "", nil)
	if replay.StatusCode != http.StatusOK {
		t.Fatalf("replay: %d", replay.StatusCode)
	}
}

func TestUnknownRun(t *testing.T) {
	s, ts := newTestServer(t)
	q := "?t=" + s.Token()
	for _, p := range []string{"/api/runs/nope/report.json", "/runs/nope/report.html", "/api/runs/nope/events"} {
		if got := do(t, ts, http.MethodGet, p+q, "", nil).StatusCode; got != http.StatusNotFound {
			t.Errorf("%s -> %d, want 404", p, got)
		}
	}
	if got := do(t, ts, http.MethodDelete, "/api/runs/nope"+q, "", nil).StatusCode; got != http.StatusNotFound {
		t.Errorf("cancel unknown -> %d", got)
	}
}

func TestCancelRun(t *testing.T) {
	mcp := mcpServer(t)
	s, ts := newTestServer(t)
	q := "?t=" + s.Token()
	spec := fmt.Sprintf(`{"target":{"endpoint":%q},"pacing":{"rps":0,"samples":1}}`, mcp.URL+"/mcp")
	resp := do(t, ts, http.MethodPost, "/api/runs"+q, spec, map[string]string{"Content-Type": "application/json"})
	var started map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&started)

	if got := do(t, ts, http.MethodDelete, "/api/runs/"+started["id"]+q, "", nil).StatusCode; got != http.StatusAccepted {
		t.Errorf("cancel -> %d", got)
	}
}

// Reports are held in memory, so the number held has to be bounded.
func TestRunsAreBounded(t *testing.T) {
	mcp := mcpServer(t)
	s, err := New(Options{Version: "test", MaxRuns: 3})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	defer ts.Close()
	q := "?t=" + s.Token()
	spec := fmt.Sprintf(`{"target":{"endpoint":%q},"pacing":{"rps":0,"samples":1},"phases":{"only":["net"]}}`, mcp.URL+"/mcp")
	for i := 0; i < 6; i++ {
		do(t, ts, http.MethodPost, "/api/runs"+q, spec, map[string]string{"Content-Type": "application/json"})
	}
	s.mu.Lock()
	held := len(s.runs)
	s.mu.Unlock()
	if held > 3 {
		t.Errorf("holding %d runs, cap is 3", held)
	}
}

// The shell has to be in the binary: a tool that needs assets beside it is
// a tool that breaks when somebody moves it.
func TestShellIsEmbedded(t *testing.T) {
	s, ts := newTestServer(t)
	resp := do(t, ts, http.MethodGet, "/?t="+s.Token(), "", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	body := string(raw)
	for _, want := range []string{"<!DOCTYPE html>", "run-form", "endpoint"} {
		if !strings.Contains(body, want) {
			t.Errorf("the shell is missing %q", want)
		}
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" {
		t.Error("nosniff is missing")
	}
}

func TestServeStartsAndStops(t *testing.T) {
	s, err := New(Options{Version: "test", Addr: "127.0.0.1:0"})
	if err != nil {
		t.Fatal(err)
	}
	// The URL arrives on a channel rather than a variable: Serve calls Open
	// from its own goroutine, and polling a shared string from the test is
	// a race the detector rightly objects to.
	urls := make(chan string, 1)
	s.opts.Open = func(u string) { urls <- u }
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx) }()

	var url string
	select {
	case url = <-urls:
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("the server never reported a URL")
	}
	if !strings.Contains(url, "?t=") {
		t.Errorf("the URL must carry the token: %s", url)
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Serve: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("the server did not shut down")
	}
}

// TestBrowserCannotStartAProgram is the guard that matters most in this
// file.
//
// The engine can diagnose a stdio server, and RunSpec carries the command
// because the parity contract says a capability lives on the spec or no
// surface can have it. That is the right place for it and the wrong thing
// to expose over HTTP: a POST that names a program is a remote shell, and
// the token in the page URL is not a credential anyone should be able to
// trade for one. It is refused unless the operator started the process
// saying otherwise.
func TestBrowserCannotStartAProgram(t *testing.T) {
	s, ts := newTestServer(t)
	// No filesystem path in the body: an earlier version put a t.TempDir()
	// path in there, and on Windows its backslashes are invalid JSON string
	// escapes — so the body failed to decode and the server answered 400.
	// The test passed everywhere else and asserted nothing on Windows except
	// that malformed JSON is rejected.
	body := `{"target":{"command":"/bin/sh","args":["-c","echo pwned"]},"phases":{"only":["net"]}}`
	resp := do(t, ts, http.MethodPost, "/api/runs?t="+s.Token(), body, map[string]string{"Content-Type": "application/json"})
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("posting a command returned %d, want 403", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !strings.Contains(out["error"], "--allow-stdio") {
		t.Errorf("the refusal should say how to permit it deliberately: %q", out["error"])
	}
}

// TestAllowStdioIsWhatPermitsIt: the flag has to actually be the thing that
// changes the answer, or the test above is asserting a constant.
func TestAllowStdioIsWhatPermitsIt(t *testing.T) {
	s, err := New(Options{Version: "test", AllowStdio: true})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	// A command that is a server for exactly one message, so the run gets
	// past the process check and stops on its own.
	body := `{"target":{"command":"/bin/sh","args":["-c","read -r l; printf '{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":{}}\\n'"]},"phases":{"only":["net"]},"pacing":{"rps":0}}`
	resp := do(t, ts, http.MethodPost, "/api/runs?t="+s.Token(), body, map[string]string{"Content-Type": "application/json"})
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted && resp.StatusCode != http.StatusOK {
		var out map[string]string
		_ = json.NewDecoder(resp.Body).Decode(&out)
		t.Fatalf("--allow-stdio did not permit a stdio run: %d %q", resp.StatusCode, out["error"])
	}
}

// TestPublicModeNeverRunsAProgram: --public and --allow-stdio together must
// not add up to an open shell. Public mode is reached from the internet by
// definition, and the two flags being independent is exactly how a
// misconfiguration like that gets written.
func TestPublicModeNeverRunsAProgram(t *testing.T) {
	spy := newSpyServer(t)
	list := &Allowlist{origins: map[string]string{}}
	o, err := originKey(spy.URL)
	if err != nil {
		t.Fatal(err)
	}
	list.origins[o] = "fixture"
	s, err := New(Options{Version: "test", Public: true, Allowed: list, AllowStdio: true, RatePerMinute: 600, RateBurst: 100})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	resp := postRun(t, ts, `{"target":{"command":"/bin/sh","args":["-c","exit 0"]},"phases":{"only":["net"]}}`)
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("a public server with --allow-stdio ran a program: %d", resp.StatusCode)
	}
}
