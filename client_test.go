// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/transport"
)

func TestConnectWithoutAuth(t *testing.T) {
	f := newFakeStack(t)
	c, err := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusConnected || res.Initialize.ServerInfo.Name != "fake" {
		t.Fatalf("res = %+v", res)
	}
	if c.Transport().SessionID() != "s1" || c.Transport().ProtocolVersion() != "2025-11-25" {
		t.Errorf("session/protocol not recorded")
	}
	tools, err := c.ListTools(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(tools) != 4 {
		t.Errorf("pagination: got %d tools", len(tools))
	}
}

func TestConnectRefusesAuthWhenModeNone(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	if _, err := c.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "Auth.Mode is none") {
		t.Fatalf("err = %v", err)
	}
}

func TestConnectClientCredentialsFullHandshake(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	c, err := New(Config{
		Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(),
		Auth: AuthConfig{Mode: AuthClientCredentials, Extra: url.Values{"profile_id": {"tenant-7"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusConnected {
		t.Fatalf("status = %s", res.Status)
	}
	if res.Discovery.Registration.Method != "dcr" || res.Discovery.Registration.ClientID != "dyn-client" {
		t.Errorf("registration = %+v", res.Discovery.Registration)
	}
	if res.Discovery.Resource != f.srv.URL+"/mcp" {
		t.Errorf("resource = %s", res.Discovery.Resource)
	}
	if got := f.lastTokenForm["profile_id"]; len(got) != 1 || got[0] != "tenant-7" {
		t.Errorf("profile_id not forwarded: %v", f.lastTokenForm)
	}
	if got := f.lastTokenForm.Get("scope"); got != "mcp:read" {
		t.Errorf("scope from challenge not used: %q", got)
	}
	r, err := c.CallTool(context.Background(), "get_time", nil)
	if err != nil || r.IsError {
		t.Fatalf("call: %v %+v", err, r)
	}
}

func TestStepUpOnInsufficientScope(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	f.strictScope = "mcp:write"
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials}})
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := f.tokenRequests.Load()
	r, err := c.CallTool(context.Background(), "rename", map[string]any{"name": "x"})
	if err != nil || r.IsError {
		t.Fatalf("call after step-up: %v %+v", err, r)
	}
	if f.tokenRequests.Load() != before+1 || f.lastTokenForm.Get("scope") != "mcp:write" {
		t.Errorf("expected one step-up token request with scope mcp:write, form = %v", f.lastTokenForm)
	}
}

func TestConnectAuthorizationCodeTwoPhase(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	c, err := New(Config{
		Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(),
		Auth: AuthConfig{Mode: AuthAuthorizationCode, RedirectURI: "http://127.0.0.1:9/cb", Scope: "mcp:read mcp:write"},
	})
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != StatusAuthorizationRequired || res.AuthorizationURL == "" {
		t.Fatalf("res = %+v", res)
	}
	u, _ := url.Parse(res.AuthorizationURL)
	if u.Query().Get("resource") != f.srv.URL+"/mcp" || u.Query().Get("code_challenge") == "" {
		t.Errorf("authorize url = %s", res.AuthorizationURL)
	}
	if _, err := c.CallTool(context.Background(), "get_time", nil); err == nil {
		t.Error("call before authorization should fail")
	}
	done, err := c.CompleteAuthorization(context.Background(), "the-code", res.State)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != StatusConnected || done.Discovery == nil {
		t.Fatalf("done = %+v", done)
	}
	if f.lastTokenForm.Get("grant_type") != "authorization_code" || f.lastTokenForm.Get("code_verifier") == "" {
		t.Errorf("token form = %v", f.lastTokenForm)
	}
	if _, err := c.CallTool(context.Background(), "get_time", nil); err != nil {
		t.Fatal(err)
	}
	// Resume from the stored token without discovery.
	src := c.TokenSource()
	c2, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthAuthorizationCode, RedirectURI: "http://127.0.0.1:9/cb"}})
	regs := f.registrations.Load()
	if r, err := c2.Resume(context.Background(), src); err != nil || r.Status != StatusConnected {
		t.Fatalf("resume: %v %+v", err, r)
	}
	if f.registrations.Load() != regs {
		t.Error("resume must not re-register")
	}
}

func TestCIMDPreferredOverDCR(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	f.cimd = true
	c, _ := New(Config{
		Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(),
		Auth: AuthConfig{Mode: AuthClientCredentials, Registration: auth.RegistrationOptions{ClientMetadataURL: "https://client.example/metadata.json"}},
	})
	res, err := c.Connect(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if res.Discovery.Registration.Method != "cimd" || res.Discovery.Registration.ClientID != "https://client.example/metadata.json" || f.registrations.Load() != 0 {
		t.Errorf("registration = %+v, dcr calls = %d", res.Discovery.Registration, f.registrations.Load())
	}
}

func TestSessionExpiryReinitializes(t *testing.T) {
	f := newFakeStack(t)
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	if _, err := c.Connect(context.Background()); err != nil {
		t.Fatal(err)
	}
	c.Transport().SetSessionID("gone")
	f.srv.Config.Handler = wrap404OnSession(f, "gone")
	if _, err := c.ListTools(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.Transport().SessionID() != "s2" {
		t.Errorf("session = %q, want fresh s2", c.Transport().SessionID())
	}
}

func TestToolHintDefaults(t *testing.T) {
	yes, no := true, false
	if !(Tool{}).IsDestructive() || (Tool{}).IsReadOnly() {
		t.Error("unannotated tool must be destructive and not read-only")
	}
	if (Tool{Annotations: &ToolAnnotations{ReadOnlyHint: &yes, DestructiveHint: &yes}}).IsDestructive() {
		t.Error("read-only overrides destructive")
	}
	if (Tool{Annotations: &ToolAnnotations{DestructiveHint: &no}}).IsDestructive() {
		t.Error("explicit destructiveHint=false honoured")
	}
}

// TestHTTPReportsTheTransport covers the seam the protocol phase depends on.
//
// A client built for an endpoint is speaking HTTP, and the conformance
// probes that send a malformed body need the concrete transport to do it.
// When that stops being true — a client over a pipe — they have to skip
// rather than crash, and the only thing standing between those two
// outcomes is this returning false.
func TestHTTPReportsTheTransport(t *testing.T) {
	f := newFakeStack(t)
	c, err := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	tr, ok := c.HTTP()
	if !ok {
		t.Fatal("a client built for an endpoint does not report an HTTP transport")
	}
	if tr == nil {
		t.Fatal("HTTP reported true and returned nil")
	}
	// The three accessors are one connection seen three ways.
	if c.Transport() != tr {
		t.Error("Transport() and HTTP() disagree about the connection")
	}
	if c.Conn() != transport.Conn(tr) {
		t.Error("Conn() and HTTP() disagree about the connection")
	}
}
