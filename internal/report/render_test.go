// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

func fullReport() *Report {
	r := &Report{Passmcp: Meta{Version: "t"}, Target: Target{Endpoint: "https://x/mcp"}, Started: time.Now(), Duration: probe.Millis(1500 * time.Millisecond), TraceID: "abc",
		Auth:   AuthSummary{Mode: "client-credentials", Required: true, Issuer: "https://as", Registration: "dcr"},
		Server: &ServerInfo{Name: "s", Version: "1", Protocol: "2025-11-25", Capabilities: []string{"tools"}},
		Files:  []string{"/tmp/report.json"},
	}
	r.Phases = []probe.PhaseResult{
		{Name: "net", Title: "Network", Status: probe.Pass, Findings: []probe.Finding{
			{Phase: "net", ID: "net.a", Title: "A", Status: probe.Pass, Detail: "fine", Evidence: []string{"req#1"}},
			{Phase: "net", ID: "net.i", Title: "I", Status: probe.Info, Detail: "note"},
		}},
		{Name: "auth", Title: "Auth", Status: probe.Skip, Skipped: "no creds"},
		{Name: "protocol", Title: "Protocol", Status: probe.Fail, Findings: []probe.Finding{
			{Phase: "protocol", ID: "p.minor", Title: "Minor", Status: probe.Fail, Severity: probe.Minor, Detail: "m", Advice: "fix m"},
			{Phase: "protocol", ID: "p.crit", Title: "Crit", Status: probe.Fail, Severity: probe.Critical, Detail: "c", Advice: "fix c"},
			{Phase: "protocol", ID: "p.warn", Title: "Warn", Status: probe.Warn, Detail: "w | with pipe", Advice: "fix w"},
			{Phase: "protocol", ID: "p.skip", Title: "Skip", Status: probe.Skip, Detail: "s"},
		}},
	}
	r.Catalog = Catalog{Tools: []ToolSummary{{Name: strings.Repeat("longtoolname", 4), Description: strings.Repeat("d", 200), ReadOnly: true, Required: []string{"q"}}}}
	r.Execution = Execution{
		Tools: []probe.ToolResult{
			{Name: "skipped", SkipReason: "policy"},
			{Name: "proto", Executed: true, ProtoError: "timeout", Duration: probe.Millis(time.Second)},
			{Name: "toolerr", Executed: true, ToolError: "bad\nsecond line", Duration: probe.Millis(time.Millisecond), NegativeTest: "rejected (isError)"},
			{Name: "good", Executed: true, OK: true, Duration: probe.Millis(2 * time.Second), ContentTypes: []string{"text"}, Structured: true, SchemaIssues: []string{"$.x: bad"}, NegativeTest: "ACCEPTED without required q"},
		},
		Resources: []probe.ResourceResult{{URI: "fake://a", OK: true, Bytes: 5}, {URI: "fake://b", Error: "boom"}},
		Prompts:   []probe.PromptResult{{Name: "p1", OK: true, Messages: 1}, {Name: "p2", Error: "nope"}},
	}
	r.Perf = &probe.PerfResult{Ping: &probe.ToolPerf{Name: "ping", Samples: 3, P50: probe.Millis(time.Millisecond)}, Tools: []probe.ToolPerf{{Name: "good", Samples: 3, Errors: 1, P50: probe.Millis(time.Millisecond)}},
		Concurrency: &probe.ConcurrencyResult{Tool: "good", Workers: 2, Calls: 4, OK: 3, Errors: 1, RateLimited: 0, Throughput: 12.5}}
	r.Score = ComputeScore(r.Phases)
	r.Counts = Counts{Pass: 1, Warn: 1, Fail: 2, Info: 1, Skip: 1}
	r.Telemetry = telemetry.Summary{Requests: 3, Errors: 1, BytesSent: 2048, BytesReceived: 3 << 20, ByStatus: map[string]int{"2xx": 2, "error": 1}, NewConns: 1}
	return r
}

func TestTextAllBranches(t *testing.T) {
	r := fullReport()
	for _, o := range []TextOptions{{}, {Color: true, Verbose: true}} {
		var buf bytes.Buffer
		Text(&buf, r, o)
		out := buf.String()
		base := []string{"Not ready for agents", "What to improve", "fix c", "How it scores", "not tested", "saved /tmp/report.json", "MB", "KB", "1.50s"}
		for _, want := range base {
			if !strings.Contains(out, want) {
				t.Errorf("text (color=%v) lacks %q\n%s", o.Color, want, out)
			}
		}
		if o.Verbose {
			for _, want := range []string{"Checks in detail", "not run: no creds", "timeout", "$.x: bad", "fake://b", "policy", "evidence: req#1"} {
				if !strings.Contains(out, want) {
					t.Errorf("verbose text lacks %q\n%s", want, out)
				}
			}
		}
		if o.Color && !strings.Contains(out, "\x1b[") {
			t.Error("colour markers missing")
		}
	}
	if humanBytes(10) != "10 B" || trunc("abc", 10) != "abc" || firstLine("one") != "one" || fmtMS(time.Duration(0)) != "-" {
		t.Error("helpers")
	}
	if mark(probe.Status("weird"), false) != "" {
		t.Error("unknown status mark")
	}
}

func TestMarkdownAllBranches(t *testing.T) {
	r := fullReport()
	var buf bytes.Buffer
	Markdown(&buf, r)
	out := buf.String()
	for _, want := range []string{"| Issuer | https://as |", "## Failures", "## Warnings", "Not run (no creds): auth", "not assessed", "protocol error: timeout", "isError: bad", "schema: $.x: bad", "Burst of 2 workers", "Files: /tmp/report.json", "→ fix c", "\\|"} {
		if !strings.Contains(out, want) {
			t.Errorf("markdown lacks %q\n%s", want, out)
		}
	}
	// critical must be listed before minor
	if strings.Index(out, "**Crit**") > strings.Index(out, "**Minor**") {
		t.Error("failures not ordered by severity")
	}
	if len(r.Warnings()) != 1 || r.Warnings()[0].ID != "p.warn" {
		t.Errorf("warnings = %+v", r.Warnings())
	}
	if f := adviceMD(probe.Finding{Status: probe.Pass, Advice: "x"}); f != "" {
		t.Error("advice only on fail/warn")
	}
	if esc("a|b\nc") != "a\\|b c" {
		t.Error("esc")
	}
}

// fakeMCP is a minimal open server so Build can run on a real session.
func fakeMCP(t *testing.T) *httptest.Server {
	t.Helper()
	yes := true
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || (req.ID == nil && req.Method != "notifications/initialized") {
			w.WriteHeader(400)
			return
		}
		reply := func(v any) {
			b, _ := json.Marshal(v)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(*req.ID) + `,"result":` + string(b) + `}`))
		}
		switch req.Method {
		case "initialize":
			w.Header().Set("Mcp-Session-Id", "s1")
			reply(map[string]any{"protocolVersion": "2025-11-25", "capabilities": map[string]any{"tools": map[string]any{}, "resources": map[string]any{}, "prompts": map[string]any{}, "logging": map[string]any{}}, "serverInfo": map[string]any{"name": "fake", "version": "1"}})
		case "notifications/initialized":
			w.WriteHeader(202)
		case "ping":
			reply(map[string]any{})
		case "tools/list":
			reply(map[string]any{"tools": []passmcp.Tool{{Name: "t", Description: "a fine tool description", InputSchema: json.RawMessage(`{"type":"object","required":["b","a"]}`), Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &yes}}}})
		case "tools/call":
			reply(map[string]any{"content": []map[string]any{{"type": "text", "text": "ok"}}})
		case "resources/list":
			reply(map[string]any{"resources": []any{}})
		case "resources/templates/list":
			reply(map[string]any{"resourceTemplates": []any{}})
		case "prompts/list":
			reply(map[string]any{"prompts": []any{}})
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + itoa(*req.ID) + `,"error":{"code":-32601,"message":"nope"}}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func itoa(i int64) string {
	return strings.TrimSpace(string(json.RawMessage(json.Number(int64String(i)))))
}

func int64String(i int64) string {
	b, _ := json.Marshal(i)
	return string(b)
}

func TestBuildFromRealSession(t *testing.T) {
	srv := fakeMCP(t)
	rec := telemetry.New()
	s, err := probe.Run(context.Background(), probe.Options{Endpoint: srv.URL + "/mcp", Recorder: rec, HTTPClient: srv.Client(), Version: "t", RPS: -1, Samples: 1, Concurrency: 2, Creds: &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234", Sources: map[string]string{"token": "flag"}}})
	if err != nil {
		t.Fatal(err)
	}
	r := Build(s, "t", true)
	if r.Server == nil || len(r.Server.Capabilities) != 4 || !r.Server.Session {
		t.Errorf("server = %+v", r.Server)
	}
	if len(r.Catalog.Tools) != 1 || strings.Join(r.Catalog.Tools[0].Required, ",") != "a,b" {
		t.Errorf("catalog = %+v", r.Catalog.Tools)
	}
	if len(r.Events) == 0 || r.Telemetry.Requests == 0 || r.Counts.Pass == 0 || r.Score.Assessed == 0 {
		t.Errorf("report = counts %+v score %+v events %d", r.Counts, r.Score, len(r.Events))
	}
	if r.Auth.Mode != "bearer" || r.Auth.Sources["token"] != "flag" {
		t.Errorf("auth = %+v", r.Auth)
	}
	r2 := Build(s, "t", false)
	if r2.Events != nil {
		t.Error("events must be omitted")
	}
	var buf bytes.Buffer
	Text(&buf, r, TextOptions{Verbose: true})
	Markdown(&buf, r)
	if b, err := json.Marshal(r); err != nil || len(b) == 0 {
		t.Error("json")
	}
}

func TestBuildWithDiscovery(t *testing.T) {
	// A protected server: discovery, registration and token info populate Auth.
	yes := true
	_ = yes
	rec := telemetry.New()
	f := newProtected(t)
	s, err := probe.Run(context.Background(), probe.Options{Endpoint: f.URL + "/mcp", Recorder: rec, HTTPClient: f.Client(), RPS: -1, Samples: 1, Concurrency: 0,
		Only:  []string{"net", "discovery", "auth", "handshake"},
		Creds: &creds.Credentials{Mode: creds.ModeClientCredentials, ClientID: "cid", ClientSecret: "sec"}})
	if err != nil {
		t.Fatal(err)
	}
	r := Build(s, "t", false)
	if r.Auth.Issuer == "" || r.Auth.Registration != "static" || r.Auth.ClientID != "cid" || r.Auth.Resource == "" || r.Auth.PRMSource == "" || r.Auth.Token == nil {
		t.Errorf("auth summary = %+v", r.Auth)
	}
	var buf bytes.Buffer
	Text(&buf, r, TextOptions{Verbose: true})
	if !strings.Contains(buf.String(), "issuer") {
		t.Error("verbose text lacks the sign-in issuer")
	}
}

func newProtected(t *testing.T) *httptest.Server {
	t.Helper()
	var srv *httptest.Server
	mux := http.NewServeMux()
	srv = httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	mux.HandleFunc("/.well-known/oauth-protected-resource/mcp", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"resource": srv.URL + "/mcp", "authorization_servers": []string{srv.URL + "/as"}})
	})
	mux.HandleFunc("/.well-known/oauth-authorization-server/as", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"issuer": srv.URL + "/as", "token_endpoint": srv.URL + "/as/token", "authorization_endpoint": srv.URL + "/as/authorize", "code_challenge_methods_supported": []string{"S256"}})
	})
	mux.HandleFunc("/as/token", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-abcdef", "token_type": "Bearer", "expires_in": 60})
	})
	mux.HandleFunc("/mcp", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok-abcdef" {
			w.Header().Set("WWW-Authenticate", `Bearer resource_metadata="`+srv.URL+`/.well-known/oauth-protected-resource/mcp"`)
			w.WriteHeader(401)
			return
		}
		var req struct {
			ID     *int64 `json:"id"`
			Method string `json:"method"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || (req.ID == nil && req.Method != "notifications/initialized") {
			w.WriteHeader(400)
			return
		}
		switch req.Method {
		case "initialize":
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + int64String(*req.ID) + `,"result":{"protocolVersion":"2025-11-25","capabilities":{},"serverInfo":{"name":"p","version":"1"}}}`))
		case "notifications/initialized":
			w.WriteHeader(202)
		default:
			_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":` + int64String(*req.ID) + `,"result":{}}`))
		}
	})
	return srv
}
