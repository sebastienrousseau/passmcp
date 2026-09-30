// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"satellion.com/passmcp/diagnostics"
	"satellion.com/passmcp/internal/creds"
)

// A server that negotiates 2024-11-05 is graded, not refused. The run
// reaches every phase; the revision itself is the warning; and every check
// about a field the revision does not have is skipped with the revision
// named, rather than passed on an absence or failed for one.
func TestLegacy2024OverStreamableHTTP(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.legacy2024 = true
	s, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, nil)

	if s.Blocked() != "" {
		t.Fatalf("a 2024-11-05 server blocked the run: %s", s.Blocked())
	}
	expect(t, fs, "handshake.initialize", Pass, "fake 1.0")
	expect(t, fs, "handshake.protocol_version", Warn, "2024-11-05")
	for _, want := range []string{"annotations", "outputSchema", "structuredContent", "elicitation"} {
		if !strings.Contains(fs["handshake.protocol_version"].Detail, want) {
			t.Errorf("handshake.protocol_version does not name what is lost (%s): %q", want, fs["handshake.protocol_version"].Detail)
		}
	}
	if fs["handshake.protocol_version"].Severity != Minor {
		t.Errorf("severity = %q, want minor", fs["handshake.protocol_version"].Severity)
	}
	expect(t, fs, "catalog.tools.list", Pass, "4 tools")
	expect(t, fs, "catalog.tools.annotations", Skip, "2025-03-26")
	expect(t, fs, "catalog.tools.annotation_honesty", Skip, "2025-03-26")
	expect(t, fs, "catalog.tools.idempotency", Skip, "2025-03-26")
	expect(t, fs, "catalog.tools.output_schema", Skip, "2025-06-18")
	// ADR-0004: with no annotations every tool is destructive by the
	// specification's default, so the read-only policy invokes nothing —
	// and the finding says which flag changes that, rather than warning
	// the server to add a field its revision does not have.
	expect(t, fs, "execution.tools", Skip, "--allow-destructive")
	expect(t, fs, "execution.tools", Skip, "2024-11-05")
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, name := range []string{"get_time", "search", "lax", "delete_all"} {
		if f.calls[name] != 0 {
			t.Errorf("%s was invoked %d times under the read-only policy", name, f.calls[name])
		}
	}
}

// When the operator does opt in, the tools run and are graded as usual,
// but a result is not judged against an outputSchema its revision has no
// field for.
func TestLegacy2024ToolsRunWhenAllowed(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.legacy2024 = true
	f.q.readOnlyOnly = true
	_, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) {
		o.Policy = diagnostics.Policy{AllowDestructive: true}
	})
	if st := fs["execution.tools"].Status; st == Skip {
		t.Errorf("execution.tools skipped with the tools allowed: %q", fs["execution.tools"].Detail)
	}
	expect(t, fs, "execution.content", Skip, "2025-06-18")
}

// The gate is the revision that introduced the field, so a 2025-03-26
// server is graded on annotations, which it has, and not on outputSchema,
// which arrived in 2025-06-18.
func TestRevisionGateFollowsTheIntroducingRevision(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	f.q.protocolVersion = "2025-03-26"
	_, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, nil)
	expect(t, fs, "handshake.protocol_version", Info, "2025-03-26")
	expect(t, fs, "catalog.tools.annotations", Warn, "without annotations")
	expect(t, fs, "catalog.tools.output_schema", Skip, "2025-06-18")
	expect(t, fs, "execution.content", Skip, "2025-06-18")
}

// A server on the HTTP+SSE transport refuses the POST that opens every
// Streamable HTTP exchange. passmcp does not implement the old transport,
// so the run stops — but with a finding that says what the server speaks,
// not an unexplained 405.
func TestHTTPSSETransportIsNamed(t *testing.T) {
	f := newFakeServer(t)
	f.q.sseTransport = "endpoint"
	s, fs := run(t, f, nil, nil)
	expect(t, fs, "discovery.first_contact", Fail, "HTTP+SSE")
	expect(t, fs, "discovery.first_contact", Fail, "/messages?session_id=legacy-1")
	if fs["discovery.first_contact"].Severity != Critical {
		t.Errorf("severity = %q", fs["discovery.first_contact"].Severity)
	}
	if !strings.Contains(fs["discovery.first_contact"].Advice, "stdio") {
		t.Errorf("advice does not offer the pipe: %q", fs["discovery.first_contact"].Advice)
	}
	if !strings.Contains(s.Blocked(), "HTTP+SSE") {
		t.Errorf("blocked = %q", s.Blocked())
	}
	for _, pr := range s.Results {
		if pr.Name == "handshake" && pr.Status != Skip {
			t.Errorf("handshake ran against a transport passmcp does not speak: %s", pr.Status)
		}
	}
}

// An event stream whose first event is not endpoint is not the old
// transport, and is not reported as one.
func TestEventStreamWithoutEndpointIsNotHTTPSSE(t *testing.T) {
	f := newFakeServer(t)
	f.q.sseTransport = "message"
	_, fs := run(t, f, nil, nil)
	expect(t, fs, "discovery.first_contact", Fail, "unexpected HTTP 405")
}

// Over a pipe there is no transport question: a 2024-11-05 server runs
// every phase that applies to it.
func TestStdioLegacy2024(t *testing.T) {
	s, fs := runStdioFixture(t, "legacy-2024")
	if s.Blocked() != "" {
		t.Fatalf("blocked: %s", s.Blocked())
	}
	expect(t, fs, "handshake.initialize", Pass, "fixture 1.0.0")
	expect(t, fs, "handshake.protocol_version", Warn, "2024-11-05")
	expect(t, fs, "catalog.tools.annotations", Skip, "2025-03-26")
	expect(t, fs, "execution.tools", Skip, "--allow-destructive")
	expect(t, fs, "stdio.alive", Pass, "still running")
}

// route picks the transport the fake speaks at /mcp.
func (f *fakeServer) route(w http.ResponseWriter, r *http.Request) {
	if f.q.sseTransport != "" {
		f.serveSSETransport(w, r)
		return
	}
	f.handle(w, r)
}

// version is the protocol revision the fake negotiates.
func (f *fakeServer) version() string {
	switch {
	case f.q.legacy2024:
		return "2024-11-05"
	case f.q.protocolVersion != "":
		return f.q.protocolVersion
	}
	return "2025-11-25"
}

// revisionResult is a tools/call result as the negotiated revision can
// carry it: 2024-11-05 has no structuredContent.
func (f *fakeServer) revisionResult(res map[string]any) map[string]any {
	if f.q.legacy2024 {
		delete(res, "structuredContent")
	}
	return res
}

// revisionTools is the catalogue as the negotiated revision can carry it.
// 2024-11-05 has no field for annotations (2025-03-26), or for
// outputSchema and title (2025-06-18).
func (f *fakeServer) revisionTools(tools []map[string]any) []map[string]any {
	if !f.q.legacy2024 {
		return tools
	}
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		c := map[string]any{}
		for k, v := range t {
			switch k {
			case "annotations", "outputSchema", "title":
			default:
				c[k] = v
			}
		}
		out = append(out, c)
	}
	return out
}

// serveSSETransport is the 2024-11-05 HTTP+SSE transport as far as a
// client probing it can see: POST to the URL it was given is not allowed,
// and GET opens an event stream whose first event names the endpoint to
// POST to. The stream is then held open, as the real transport does.
func (f *fakeServer) serveSSETransport(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.WriteHeader(http.StatusOK)
	_, _ = fmt.Fprintf(w, "event: %s\ndata: /messages?session_id=legacy-1\n\n", f.q.sseTransport)
	if fl, ok := w.(http.Flusher); ok {
		fl.Flush()
	}
	<-r.Context().Done()
}

// stdioInitResult is the fixture's initialize result. legacy-2024 is a
// server on the first published revision, which is still what many stdio
// servers speak.
func stdioInitResult(mode string) string {
	if mode == "legacy-2024" {
		return `{"protocolVersion":"2024-11-05","serverInfo":{"name":"fixture","version":"1.0.0"},"capabilities":{"tools":{}}}`
	}
	return `{"protocolVersion":"2025-11-25","serverInfo":{"name":"fixture","version":"1.0.0"},"capabilities":{"tools":{}},"instructions":"A fixture."}`
}

// stdioToolsResult is the fixture's tools/list result. 2024-11-05 has no
// annotations to declare.
func stdioToolsResult(mode string) string {
	if mode == "legacy-2024" {
		return `{"tools":[{"name":"look","description":"Look something up by its identifier and return what is stored.","inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}]}`
	}
	return `{"tools":[{"name":"look","description":"Look something up by its identifier and return what is stored.","annotations":{"readOnlyHint":true},"inputSchema":{"type":"object","properties":{"id":{"type":"string"}},"required":["id"]}}]}`
}
