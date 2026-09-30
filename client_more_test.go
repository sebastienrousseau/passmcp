// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/transport"
)

func TestNewValidation(t *testing.T) {
	cases := []Config{
		{},
		{Endpoint: "/relative"},
		{Endpoint: "https://x", Auth: AuthConfig{Mode: "weird"}},
		{Endpoint: "https://x", Auth: AuthConfig{Mode: AuthAuthorizationCode}},
		{Endpoint: "https://x", Auth: AuthConfig{Mode: AuthBearer}},
	}
	for i, c := range cases {
		if _, err := New(c); err == nil {
			t.Errorf("case %d should fail: %+v", i, c)
		}
	}
	c, err := New(Config{Endpoint: "https://x/mcp", Headers: map[string]string{"X": "1"}, ClientInfo: Implementation{Name: "me", Version: "2"}})
	if err != nil || c.Config().ClientInfo.Name != "me" || c.HTTPClient() == nil || c.Discoverer() == nil || c.ServerInfo() != nil || c.LastConnect() != nil {
		t.Errorf("accessors: %v %+v", err, c)
	}
}

func TestCatalogMethods(t *testing.T) {
	f := newFakeStack(t)
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	ctx := context.Background()
	if _, err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Ping(ctx); err != nil {
		t.Error(err)
	}
	res, err := c.ListResources(ctx)
	if err != nil || len(res) != 2 || res[1].URI != "fake://b" {
		t.Errorf("resources: %v %+v", err, res)
	}
	tpl, err := c.ListResourceTemplates(ctx)
	if err != nil || len(tpl) != 1 {
		t.Errorf("templates: %v %+v", err, tpl)
	}
	rd, err := c.ReadResource(ctx, "fake://a")
	if err != nil || len(rd.Contents) != 1 || rd.Contents[0].Text != "hello" {
		t.Errorf("read: %v %+v", err, rd)
	}
	ps, err := c.ListPrompts(ctx)
	if err != nil || len(ps) != 1 || !ps[0].Arguments[0].Required {
		t.Errorf("prompts: %v %+v", err, ps)
	}
	gp, err := c.GetPrompt(ctx, "p", map[string]string{"x": "hi"})
	if err != nil || gp.Description != "p" || gp.Messages[0].Content.Text != "hi" {
		t.Errorf("get prompt: %v %+v", err, gp)
	}
	if _, err := c.GetPrompt(ctx, "p", nil); err != nil {
		t.Error(err)
	}
	var out map[string]any
	if err := c.Call(ctx, "ping", nil, &out); err != nil {
		t.Error(err)
	}
	if err := c.Call(ctx, "nope", nil, nil); err == nil {
		t.Error("unknown method should error")
	}
	if c.ServerInfo() == nil || c.LastConnect() == nil || c.LastConnect().Status != StatusConnected {
		t.Error("state after connect")
	}
	r := &CallToolResult{Content: []Content{{Type: "text", Text: "a"}, {Type: "image", Data: "x"}, {Type: "text", Text: "b"}}}
	if r.Text() != "a\nb" {
		t.Errorf("Text = %q", r.Text())
	}
}

func TestBearerModeAndRejection(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthBearer, Token: "at|mcp:read"}})
	res, err := c.Connect(context.Background())
	if err != nil || res.Status != StatusConnected {
		t.Fatalf("bearer connect: %v %+v", err, res)
	}
	if c.TokenSource() == nil {
		t.Error("static source expected")
	}
	c2, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthBearer, Token: "bad-bearer"}})
	if _, err := c2.Connect(context.Background()); err == nil || !strings.Contains(err.Error(), "rejected the supplied bearer") {
		t.Errorf("rejected bearer: %v", err)
	}
	// SetTokenSource lets a caller install its own.
	c3, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	c3.SetTokenSource(auth.StaticSource{AccessToken: "at|x"})
	if _, err := c3.Initialize(context.Background()); err != nil {
		t.Errorf("initialize with installed source: %v", err)
	}
}

func TestDiscoverOverridesAndStepPreconditions(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{
		Mode: AuthClientCredentials, Scope: "custom",
		Overrides:    Overrides{TokenURL: f.srv.URL + "/as/token", AuthorizationURL: f.srv.URL + "/as/authorize", Resource: f.srv.URL + "/mcp"},
		Registration: auth.RegistrationOptions{StaticClientID: "sid", StaticClientSecret: "sec"},
	}})
	ctx := context.Background()
	d, err := c.Discover(ctx, auth.Challenge{Scheme: "Bearer", Params: map[string]string{}})
	if err != nil || !d.Overridden || d.PRM != nil || d.Server.TokenEndpoint != f.srv.URL+"/as/token" || d.Scope != "custom" || d.Resource != f.srv.URL+"/mcp" {
		t.Fatalf("override discovery: %v %+v", err, d)
	}
	if _, err := c.ClientCredentialsSource(d); err == nil {
		t.Error("source before Register must fail")
	}
	if _, _, err := c.StartAuthorization(d); err == nil {
		t.Error("start before Register must fail")
	}
	if _, err := c.CompleteAuthorization(ctx, "c", "s"); err == nil {
		t.Error("complete without start must fail")
	}
	if _, err := c.Register(ctx, d); err != nil {
		t.Fatal(err)
	}
	src, err := c.ClientCredentialsSource(d)
	if err != nil {
		t.Fatal(err)
	}
	c.SetTokenSource(src)
	res, err := c.Connect(ctx)
	if err != nil || res.Status != StatusConnected {
		t.Errorf("connect with override + preset source: %v %+v", err, res)
	}

	// Override resource defaults to the canonical endpoint; scope falls back to the challenge.
	c2, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials, Overrides: Overrides{TokenURL: f.srv.URL + "/as/token"}}})
	d2, err := c2.Discover(ctx, auth.Challenge{Scheme: "Bearer", Params: map[string]string{"scope": "from-challenge"}})
	if err != nil || d2.Resource != f.srv.URL+"/mcp" || d2.Scope != "from-challenge" {
		t.Errorf("override defaults: %v %+v", err, d2)
	}
	// Full discovery honours an AuthorizationURL override and a Resource override.
	c3, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials, Overrides: Overrides{AuthorizationURL: "https://custom/authorize", Resource: "https://res"}}})
	d3, err := c3.Discover(ctx, auth.Challenge{Scheme: "Bearer", Params: map[string]string{}})
	if err != nil || d3.Server.AuthorizationEndpoint != "https://custom/authorize" || d3.Resource != "https://res" || d3.Scope != "mcp:read mcp:write" {
		t.Errorf("full discovery overrides: %v %+v", err, d3)
	}

	// Grant / PKCE mismatch.
	d4 := &Discovery{Server: &auth.ServerMetadata{Issuer: "i", GrantTypesSupported: []string{"authorization_code"}, CodeChallengeMethodsSupported: []string{"plain"}}, Registration: &auth.Registration{ClientID: "x"}}
	if _, err := c.ClientCredentialsSource(d4); err == nil || !strings.Contains(err.Error(), "client_credentials") {
		t.Errorf("grant mismatch: %v", err)
	}
	c5, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthAuthorizationCode, RedirectURI: "http://127.0.0.1:1/cb"}})
	if _, _, err := c5.StartAuthorization(d4); err == nil || !strings.Contains(err.Error(), "S256") {
		t.Errorf("pkce mismatch: %v", err)
	}
	d5 := &Discovery{Server: &auth.ServerMetadata{}, Registration: &auth.Registration{ClientID: "x"}}
	if _, _, err := c5.StartAuthorization(d5); err == nil {
		t.Error("missing authorization endpoint must fail Start")
	}
}

// TestConnectAcceptsTheOldestRevision is version negotiation as the
// specification defines it: passmcp offers its newest revision and a server
// that only speaks 2024-11-05 answers with that. passmcp can speak it, so
// the handshake completes and the version is recorded rather than the
// connection refused.
func TestConnectAcceptsTheOldestRevision(t *testing.T) {
	f := newFakeStack(t)
	f.protocolVer = "2024-11-05"
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	res, err := c.Connect(context.Background())
	if err != nil {
		t.Fatalf("a server on 2024-11-05 was refused: %v", err)
	}
	if res.Initialize.ProtocolVersion != "2024-11-05" || c.Transport().ProtocolVersion() != "2024-11-05" {
		t.Errorf("negotiated %q, transport recorded %q", res.Initialize.ProtocolVersion, c.Transport().ProtocolVersion())
	}
}

func TestConnectErrorPaths(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	f.noRegistration = true
	ctx := context.Background()
	// Client credentials with no way to register.
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials}})
	if _, err := c.Connect(ctx); !errors.Is(err, auth.ErrRegistrationUnsupported) {
		t.Errorf("registration unsupported: %v", err)
	}
	// Wrong token endpoint makes the exchange fail after discovery.
	c2, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials, Registration: auth.RegistrationOptions{StaticClientID: "s"}, Overrides: Overrides{TokenURL: "http://127.0.0.1:1/t"}}})
	if _, err := c2.Connect(ctx); err == nil || !strings.Contains(err.Error(), "initialize after token exchange") {
		t.Errorf("token exchange failure: %v", err)
	}
	// Unsupported protocol version negotiated.
	f2 := newFakeStack(t)
	f2.protocolVer = "1999-01-01"
	c3, _ := New(Config{Endpoint: f2.srv.URL + "/mcp", HTTPClient: f2.srv.Client()})
	if _, err := c3.Connect(ctx); err == nil || !strings.Contains(err.Error(), "unsupported protocol version") {
		t.Errorf("protocol version: %v", err)
	}
	// Non-401 failure propagates unchanged.
	c4, _ := New(Config{Endpoint: "http://127.0.0.1:1/mcp"})
	if _, err := c4.Connect(ctx); err == nil {
		t.Error("connection error expected")
	}
	// 401 without a Bearer challenge still counts as unauthorized.
	f3 := newFakeStack(t)
	f3.requireAuth = true
	f3.noChallenge = true
	c5, _ := New(Config{Endpoint: f3.srv.URL + "/mcp", HTTPClient: f3.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials, Registration: auth.RegistrationOptions{StaticClientID: "s", StaticClientSecret: "p"}}})
	res, err := c5.Connect(ctx)
	if err != nil || res.Status != StatusConnected || res.Discovery.Challenge.Scheme != "Bearer" {
		t.Errorf("no challenge: %v %+v", err, res)
	}
	if _, ok := Unauthorized(errors.New("plain")); ok {
		t.Error("plain error is not unauthorized")
	}
	if _, ok := Unauthorized(&transport.HTTPStatusError{StatusCode: 500}); ok {
		t.Error("500 is not unauthorized")
	}
	ch, ok := Unauthorized(&transport.HTTPStatusError{StatusCode: 401, Header: http.Header{"Www-Authenticate": {"Basic realm=x"}}})
	if !ok || ch.Scheme != "Bearer" {
		t.Errorf("non-bearer 401: %v %+v", ok, ch)
	}
	// Discovery failures.
	c6, _ := New(Config{Endpoint: "http://127.0.0.1:1/mcp", Auth: AuthConfig{Mode: AuthClientCredentials}})
	if _, err := c6.Discover(ctx, auth.Challenge{Params: map[string]string{}}); err == nil {
		t.Error("prm discovery must fail on an unreachable host")
	}
	var badURL string
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
			// The resource must bind to the endpoint, otherwise the
			// mix-up check fires before the authorization server is tried.
			fmt.Fprintf(w, `{"resource":%q,"authorization_servers":["http://127.0.0.1:1/as"]}`, badURL+"/mcp")
			return
		}
		http.NotFound(w, r)
	}))
	defer bad.Close()
	badURL = bad.URL
	c7, _ := New(Config{Endpoint: bad.URL + "/mcp", HTTPClient: bad.Client(), Auth: AuthConfig{Mode: AuthClientCredentials}})
	if _, err := c7.Discover(ctx, auth.Challenge{Params: map[string]string{}}); err == nil || !strings.Contains(err.Error(), "no usable authorization server") {
		t.Errorf("as discovery: %v", err)
	}

	// A resource that names somebody else must be refused outright: that
	// binding is what stops a token minted for this endpoint being
	// requested on another server's behalf.
	mismatch := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/.well-known/oauth-protected-resource") {
			_, _ = w.Write([]byte(`{"resource":"https://elsewhere.example/mcp","authorization_servers":["https://as.example"]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer mismatch.Close()
	c7b, _ := New(Config{Endpoint: mismatch.URL + "/mcp", HTTPClient: mismatch.Client(), Auth: AuthConfig{Mode: AuthClientCredentials}})
	if _, err := c7b.Discover(ctx, auth.Challenge{Params: map[string]string{}}); !errors.Is(err, ErrResourceMismatch) {
		t.Errorf("resource mismatch must be refused, got %v", err)
	}
	c7c, _ := New(Config{Endpoint: mismatch.URL + "/mcp", HTTPClient: mismatch.Client(), AllowResourceMismatch: true, Auth: AuthConfig{Mode: AuthClientCredentials}})
	if _, err := c7c.Discover(ctx, auth.Challenge{Params: map[string]string{}}); errors.Is(err, ErrResourceMismatch) {
		t.Error("AllowResourceMismatch must bypass the binding check")
	}
	c8, _ := New(Config{Endpoint: bad.URL + "/mcp", HTTPClient: bad.Client(), Auth: AuthConfig{Mode: AuthClientCredentials, Registration: auth.RegistrationOptions{ClientMetadataURL: "http://not-https"}}})
	d8 := &Discovery{Server: &auth.ServerMetadata{ClientIDMetadataDocumentSupported: true}}
	if _, err := c8.Register(ctx, d8); err == nil {
		t.Error("register error must propagate")
	}
}

func TestCustomStepUpAndResume(t *testing.T) {
	f := newFakeStack(t)
	f.requireAuth = true
	f.strictScope = "mcp:write"
	called := ""
	c, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthClientCredentials,
		StepUp: func(ctx context.Context, required string) (auth.TokenSource, error) {
			called = required
			return auth.StaticSource{AccessToken: "at|mcp:write"}, nil
		}}})
	ctx := context.Background()
	if _, err := c.Connect(ctx); err != nil {
		t.Fatal(err)
	}
	if r, err := c.CallTool(ctx, "rename", map[string]any{"name": "x"}); err != nil || r.IsError || called != "mcp:write" {
		t.Errorf("custom step-up: %v %+v called=%q", err, r, called)
	}
	// Step-up with no source is an error surfaced through the call.
	c2, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client()})
	if _, err := c2.stepUp(ctx, "x"); err == nil {
		t.Error("stepUp without a source must fail")
	}
	// Resume with a stale bearer surfaces the 401.
	c3, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthNone}})
	if _, err := c3.Resume(ctx, auth.StaticSource{AccessToken: "bad-bearer"}); err == nil {
		t.Error("resume with a rejected token must fail")
	}
	// Auth code registration defaults.
	c4, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthAuthorizationCode, RedirectURI: "http://127.0.0.1:9/cb"}})
	o := c4.registrationOptions()
	if o.Metadata.TokenEndpointAuthMethod != "none" || len(o.Metadata.RedirectURIs) != 1 || o.Metadata.ResponseTypes[0] != "code" {
		t.Errorf("auth code registration options: %+v", o.Metadata)
	}
	// Complete with wrong state.
	res, err := c4.Connect(ctx)
	if err != nil || res.Status != StatusAuthorizationRequired {
		t.Fatalf("%v %+v", err, res)
	}
	if _, err := c4.CompleteAuthorization(ctx, "code", "wrong"); err == nil {
		t.Error("state mismatch must fail")
	}
	// Complete against a token endpoint that is down.
	c5, _ := New(Config{Endpoint: f.srv.URL + "/mcp", HTTPClient: f.srv.Client(), Auth: AuthConfig{Mode: AuthAuthorizationCode, RedirectURI: "http://127.0.0.1:9/cb", Registration: auth.RegistrationOptions{StaticClientID: "s"}, Overrides: Overrides{TokenURL: "http://127.0.0.1:1/t", AuthorizationURL: "https://as/authorize"}}})
	res5, err := c5.Connect(ctx)
	if err != nil || res5.Status != StatusAuthorizationRequired {
		t.Fatalf("%v %+v", err, res5)
	}
	if _, err := c5.CompleteAuthorization(ctx, "code", res5.State); err == nil {
		t.Error("token endpoint down must fail")
	}
}
