// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/telemetry"
)

func findingsByID(s *Session) map[string]Finding {
	out := map[string]Finding{}
	for _, p := range s.Results {
		for _, f := range p.Findings {
			out[f.ID] = f
		}
	}
	return out
}

func phaseStatus(s *Session, name string) Status {
	for _, p := range s.Results {
		if p.Name == name {
			return p.Status
		}
	}
	return ""
}

func TestFullRunClientCredentials(t *testing.T) {
	f := newFakeServer(t)
	rec := telemetry.New()
	rec.CaptureBodies = true
	cr := &creds.Credentials{Mode: creds.ModeClientCredentials, ClientID: "static-id", ClientSecret: "static-secret-value", Sources: map[string]string{"client-id": "flag"}}
	s, err := Run(context.Background(), Options{Endpoint: f.srv.URL + "/mcp", Creds: cr, Recorder: rec, HTTPClient: f.srv.Client(), Version: "test", RPS: -1, Samples: 2, Concurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByID(s)
	expectPass := []string{"discovery.first_contact", "discovery.challenge", "discovery.prm", "discovery.prm.resource", "discovery.as", "discovery.as.pkce", "auth.registration", "auth.token", "auth.rejects_garbage",
		"handshake.initialize", "handshake.session", "protocol.ping", "protocol.unknown_method", "protocol.id_echo", "protocol.malformed_json", "protocol.invalid_params", "protocol.unknown_tool", "protocol.bogus_session", "protocol.version_header", "protocol.origin",
		"catalog.tools.list", "catalog.tools.unique", "catalog.tools.descriptions", "catalog.resources.list", "catalog.prompts.list", "execution.resources", "execution.prompts", "resilience.session_reinit", "resilience.token_refresh", "performance.ping"}
	for _, id := range expectPass {
		if f, ok := fs[id]; !ok || f.Status != Pass {
			t.Errorf("%s: want pass, got %+v", id, f)
		}
	}
	if f := fs["auth.registration"]; !strings.Contains(f.Detail, "static") {
		t.Errorf("registration should be static: %+v", f)
	}
	if f := fs["execution.content"]; f.Status != Fail {
		t.Errorf("search violates outputSchema; want fail: %+v", f)
	}
	if f := fs["execution.validation"]; f.Status != Fail || !strings.Contains(f.Detail, "1 tool") {
		t.Errorf("lax accepts missing arg; want fail: %+v", f)
	}
	if f := fs["catalog.tools.annotations"]; f.Status != Warn {
		t.Errorf("delete_all unannotated; want warn: %+v", f)
	}
	if f.calls["delete_all"] != 0 {
		t.Fatal("destructive tool invoked under default policy")
	}
	if s.Token == nil || s.Token.Scope != "mcp:read" || !s.RequiresAuth {
		t.Errorf("token info = %+v required=%v", s.Token, s.RequiresAuth)
	}
	// the challenge scope was requested and resource was sent
	if len(f.tokenReqs) == 0 || f.tokenReqs[0]["resource"] != f.srv.URL+"/mcp" || f.tokenReqs[0]["scope"] != "mcp:read" {
		t.Errorf("token request = %v", f.tokenReqs)
	}
	// resilience invalidated the token, so a second token request happened
	if len(f.tokenReqs) < 2 {
		t.Errorf("expected re-issue after invalidation, got %d token requests", len(f.tokenReqs))
	}
	// secrets never appear in telemetry
	b, _ := json.Marshal(rec.Events())
	for _, secret := range []string{"static-secret-value", "issued-token-", "dyn-secret-value"} {
		if strings.Contains(string(b), secret) {
			t.Errorf("secret %q leaked into telemetry", secret)
		}
	}
	if !strings.Contains(string(b), "Bearer ***") {
		t.Error("expected redacted Authorization header in telemetry")
	}
	for _, name := range PhaseNames() {
		if st := phaseStatus(s, name); st == "" || st == Skip {
			t.Errorf("phase %s status %q", name, st)
		}
	}
	if s.Perf == nil || s.Perf.Concurrency == nil || s.Perf.Concurrency.OK == 0 {
		t.Errorf("perf = %+v", s.Perf)
	}
}

func TestOpenServerNoCreds(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	// make it open: accept requests without a token too
	f.noChallenge = true
	orig := f.srv.Config.Handler
	f.srv.Config.Handler = httpHandlerFunc(func(w httpResponseWriter, r httpRequest) {
		r.Header.Set("Authorization", "Bearer anything")
		orig.ServeHTTP(w, r)
	})
	s, err := Run(context.Background(), Options{Endpoint: f.srv.URL + "/mcp", Recorder: telemetry.New(), HTTPClient: f.srv.Client(), RPS: -1, Samples: 1, Concurrency: 0, Only: []string{"net", "discovery", "auth", "handshake"}})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByID(s)
	if f := fs["discovery.first_contact"]; f.Status != Info || s.RequiresAuth {
		t.Errorf("open server: %+v", f)
	}
	// The auth phase used to be skipped entirely on an open server, on the
	// grounds that there were no credentials to check. That reported
	// "auth: not needed" for a server exposing a destructive tool to
	// anyone who could reach it, which is the wrong sentence.
	//
	// It now carries exactly one finding — what the server serves without
	// credentials — and nothing else, so an open server is described rather
	// than passed over.
	if st := phaseStatus(s, "auth"); st == Skip {
		t.Error("the auth phase says nothing at all about an open server")
	}
	// Two findings, by id rather than by count: what the server serves
	// without credentials, and that none were supplied because none were
	// demanded. A count would churn every time the phase gains anything.
	for _, id := range []string{"auth.unauthenticated_tools", "auth.mode"} {
		if _, ok := fs[id]; !ok {
			t.Errorf("the auth phase is missing %s for an open server", id)
		}
	}
	if len(s.Results) != 4 {
		t.Errorf("Only did not restrict phases: %d", len(s.Results))
	}
}

func TestProtectedServerWithoutCredsBlocks(t *testing.T) {
	f := newFakeServer(t)
	s, err := Run(context.Background(), Options{Endpoint: f.srv.URL + "/mcp", Recorder: telemetry.New(), HTTPClient: f.srv.Client(), RPS: -1})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByID(s)
	if f := fs["auth.token"]; f.Status != Fail || f.Severity != Critical {
		t.Errorf("want critical fail: %+v", f)
	}
	if st := phaseStatus(s, "handshake"); st != Skip {
		t.Errorf("later phases must be skipped: %s", st)
	}
	for _, p := range s.Results {
		if p.Name == "handshake" && !strings.Contains(p.Skipped, "no credentials") {
			t.Errorf("skip reason = %q", p.Skipped)
		}
	}
}

func TestServerAcceptingGarbageTokenIsCritical(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	cr := &creds.Credentials{Mode: creds.ModeBearer, Token: "operator-supplied-token"}
	s, err := Run(context.Background(), Options{Endpoint: f.srv.URL + "/mcp", Creds: cr, Recorder: telemetry.New(), HTTPClient: f.srv.Client(), RPS: -1, Only: []string{"net", "discovery", "auth", "handshake"}})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByID(s)
	if f := fs["auth.rejects_garbage"]; f.Status != Fail || f.Severity != Critical {
		t.Errorf("want critical: %+v", f)
	}
	if f := fs["handshake.initialize"]; f.Status != Pass {
		t.Errorf("bearer token should connect: %+v", f)
	}
}

func TestWrongClientCredentialsFailsClearly(t *testing.T) {
	f := newFakeServer(t)
	cr := &creds.Credentials{Mode: creds.ModeClientCredentials, ClientID: "wrong", ClientSecret: "x"}
	s, err := Run(context.Background(), Options{Endpoint: f.srv.URL + "/mcp", Creds: cr, Recorder: telemetry.New(), HTTPClient: f.srv.Client(), RPS: -1})
	if err != nil {
		t.Fatal(err)
	}
	fs := findingsByID(s)
	if f := fs["auth.token"]; f.Status != Fail || !strings.Contains(f.Detail, "invalid_client") {
		t.Errorf("want invalid_client failure: %+v", f)
	}
}

func TestToolArgOverridesAndOnlyPolicy(t *testing.T) {
	f := newFakeServer(t)
	f.acceptAnyToken = true
	cr := &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}
	s, err := Run(context.Background(), Options{Endpoint: f.srv.URL + "/mcp", Creds: cr, Recorder: telemetry.New(), HTTPClient: f.srv.Client(), RPS: -1, Samples: 1, Concurrency: 0,
		ToolArgs: map[string]map[string]any{"search": {"q": "custom"}}, Only: []string{"net", "discovery", "auth", "handshake", "catalog", "execution"}})
	if err != nil {
		t.Fatal(err)
	}
	var search *ToolResult
	for i := range s.ToolResults {
		if s.ToolResults[i].Name == "search" {
			search = &s.ToolResults[i]
		}
	}
	if search == nil || search.ArgsSource != "override" || search.Arguments["q"] != "custom" || search.NegativeTest != "" {
		t.Errorf("override not applied: %+v", search)
	}
}
