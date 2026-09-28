// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestRegistrarPaths(t *testing.T) {
	var status int
	var body string
	var gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	r := &Registrar{Client: srv.Client()}
	ctx := context.Background()

	if _, err := r.Register(ctx, &ServerMetadata{ClientIDMetadataDocumentSupported: true}, RegistrationOptions{ClientMetadataURL: "http://insecure/md"}); err == nil {
		t.Error("non-https CIMD must fail")
	}
	reg, err := r.Register(ctx, &ServerMetadata{ClientIDMetadataDocumentSupported: true}, RegistrationOptions{ClientMetadataURL: "https://c/md"})
	if err != nil || reg.Method != "cimd" {
		t.Errorf("cimd: %v %+v", err, reg)
	}
	reg, err = r.Register(ctx, &ServerMetadata{RegistrationEndpoint: srv.URL}, RegistrationOptions{StaticClientID: "s", StaticClientSecret: "p"})
	if err != nil || reg.Method != "static" || reg.ClientSecret != "p" {
		t.Errorf("static: %v %+v", err, reg)
	}
	if _, err := r.Register(ctx, &ServerMetadata{}, RegistrationOptions{}); !errors.Is(err, ErrRegistrationUnsupported) {
		t.Errorf("unsupported: %v", err)
	}
	status, body = 400, strings.Repeat("e", 600)
	if _, err := r.Register(ctx, &ServerMetadata{RegistrationEndpoint: srv.URL}, RegistrationOptions{InitialAccessToken: "iat"}); err == nil || !strings.Contains(err.Error(), "...") || gotAuth != "Bearer iat" {
		t.Errorf("400 dcr: %v auth=%q", err, gotAuth)
	}
	status, body = 201, "{bad"
	if _, err := r.Register(ctx, &ServerMetadata{RegistrationEndpoint: srv.URL}, RegistrationOptions{}); err == nil || !strings.Contains(err.Error(), "decode registration") {
		t.Errorf("bad json: %v", err)
	}
	status, body = 200, `{"client_name":"x"}`
	if _, err := r.Register(ctx, &ServerMetadata{RegistrationEndpoint: srv.URL}, RegistrationOptions{}); err == nil || !strings.Contains(err.Error(), "missing client_id") {
		t.Errorf("missing id: %v", err)
	}
	status, body = 200, `{"client_id":"ok"}`
	reg, err = r.Register(ctx, &ServerMetadata{RegistrationEndpoint: srv.URL}, RegistrationOptions{})
	if err != nil || reg.Method != "dcr" || reg.ClientID != "ok" || len(reg.Raw) == 0 {
		t.Errorf("200 dcr: %v %+v", err, reg)
	}
	if _, err := r.Register(ctx, &ServerMetadata{RegistrationEndpoint: "http://127.0.0.1:1/reg"}, RegistrationOptions{}); err == nil {
		t.Error("connection failure must error")
	}
	if _, err := r.Register(ctx, &ServerMetadata{RegistrationEndpoint: "::bad"}, RegistrationOptions{}); err == nil {
		t.Error("bad endpoint url must error")
	}
	if (&Registrar{}).httpClient() != http.DefaultClient {
		t.Error("nil client defaults")
	}
	if truncate([]byte("abc"), 5) != "abc" {
		t.Error("truncate short")
	}
}

func TestTokenRequestMethodsAndErrors(t *testing.T) {
	var form url.Values
	var basicUser string
	var status int
	var body string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		basicUser, _, _ = r.BasicAuth()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	ctx := context.Background()
	ep := Endpoint{TokenURL: srv.URL}

	status, body = 200, `{"access_token":"t","token_type":"Bearer"}`
	src := &ClientCredentialsSource{HTTP: srv.Client(), Endpoint: Endpoint{TokenURL: srv.URL, AuthMethod: "client_secret_post"}, Creds: Credentials{ClientID: "c", ClientSecret: "s"}}
	tok, err := src.Token(ctx)
	if err != nil || form.Get("client_id") != "c" || form.Get("client_secret") != "s" || basicUser != "" || !tok.Valid(0) || !tok.Expiry.IsZero() {
		t.Errorf("post: %v %v %+v", err, form, tok)
	}
	scoped := src.WithScope("w").(*ClientCredentialsSource)
	if scoped.Scope != "w" || scoped.Creds.ClientID != "c" {
		t.Errorf("WithScope: %+v", scoped)
	}
	src2 := &ClientCredentialsSource{HTTP: srv.Client(), Endpoint: Endpoint{TokenURL: srv.URL, AuthMethod: "none"}, Creds: Credentials{ClientID: "pub"}}
	if _, err := src2.Token(ctx); err != nil || form.Get("client_id") != "pub" || form.Get("client_secret") != "" {
		t.Errorf("none: %v %v", err, form)
	}

	status, body = 503, "gateway down"
	src3 := &ClientCredentialsSource{HTTP: srv.Client(), Endpoint: ep, Creds: Credentials{ClientID: "c"}}
	_, err = src3.Token(ctx)
	var te *TokenError
	if !errors.As(err, &te) || te.Code != "http_503" || te.Description != "gateway down" || !strings.Contains(te.Error(), "gateway down") {
		t.Errorf("non-json error: %v", err)
	}
	if (&TokenError{Code: "x", StatusCode: 400}).Error() == "" {
		t.Error("error string")
	}
	status, body = 200, "{bad"
	if _, err := src3.Token(ctx); err == nil || !strings.Contains(err.Error(), "decode token response") {
		t.Errorf("bad json: %v", err)
	}
	status, body = 200, `{"token_type":"Bearer"}`
	if _, err := src3.Token(ctx); err == nil || !strings.Contains(err.Error(), "missing access_token") {
		t.Errorf("missing token: %v", err)
	}
	src4 := &ClientCredentialsSource{HTTP: srv.Client(), Endpoint: Endpoint{TokenURL: "http://127.0.0.1:1/t"}, Creds: Credentials{ClientID: "c"}}
	if _, err := src4.Token(ctx); err == nil {
		t.Error("connection error expected")
	}
	src5 := &ClientCredentialsSource{Endpoint: Endpoint{TokenURL: "::bad"}, Creds: Credentials{ClientID: "c"}}
	if _, err := src5.Token(ctx); err == nil {
		t.Error("bad url expected")
	}
}

func TestRefreshingSourceBranches(t *testing.T) {
	var status int
	var body string
	var form url.Values
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form = r.PostForm
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()
	ctx := context.Background()
	ep := Endpoint{TokenURL: srv.URL}
	expired := &Token{AccessToken: "old", RefreshToken: "rt", Expiry: time.Now().Add(-time.Minute)}

	status, body = 400, `{"error":"invalid_grant"}`
	s := NewRefreshingSource(srv.Client(), ep, Credentials{ClientID: "c"}, "https://r", expired)
	if _, err := s.Token(ctx); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("invalid_grant: %v", err)
	}
	status, body = 500, "x"
	if _, err := s.Token(ctx); errors.Is(err, ErrReauthRequired) || err == nil {
		t.Errorf("other error must not be reauth: %v", err)
	}
	status, body = 200, `{"access_token":"new","expires_in":60}`
	s2 := NewRefreshingSource(srv.Client(), ep, Credentials{ClientID: "c"}, "https://r", &Token{AccessToken: "old", RefreshToken: "rt", Expiry: time.Now().Add(-time.Minute)})
	s2.Scope = "sc"
	tok, err := s2.Token(ctx)
	if err != nil || tok.RefreshToken != "rt" || form.Get("resource") != "https://r" || form.Get("scope") != "sc" {
		t.Errorf("refresh keeps rt: %v %+v %v", err, tok, form)
	}
	if cur := s2.Current(); cur == nil || cur.AccessToken != "new" {
		t.Errorf("Current = %+v", cur)
	}
	s2.Invalidate()
	if s2.Current().AccessToken != "" {
		t.Error("Invalidate should clear access token")
	}
	ws := s2.WithScope("other").(*RefreshingSource)
	if ws.Scope != "other" || ws.tok == nil || ws.tok.AccessToken != "" || ws.tok.RefreshToken != "rt" {
		t.Errorf("WithScope: %+v", ws)
	}
	empty := &RefreshingSource{}
	if empty.Current() != nil {
		t.Error("nil token Current")
	}
	empty.Invalidate()
	if ws2 := empty.WithScope("x").(*RefreshingSource); ws2.tok != nil {
		t.Error("WithScope on empty")
	}
	if _, err := empty.Token(ctx); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("empty token: %v", err)
	}
}

func TestStaticSourceAndHeaderTransport(t *testing.T) {
	s := StaticSource{AccessToken: "abc"}
	tok, err := s.Token(context.Background())
	if err != nil || tok.AccessToken != "abc" || tok.TokenType != "Bearer" {
		t.Errorf("static: %v %+v", err, tok)
	}
	s.Invalidate()
	if s.WithScope("x") != s {
		t.Error("WithScope returns self")
	}
	var got http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { got = r.Header.Clone() }))
	defer srv.Close()
	hc := &http.Client{Transport: &HeaderTransport{Base: srv.Client().Transport, Headers: map[string]string{"X-Api-Key": "k"}}}
	if _, err := hc.Get(srv.URL); err != nil || got.Get("X-Api-Key") != "k" {
		t.Errorf("header transport: %v %v", err, got)
	}
	hc2 := &http.Client{Transport: &HeaderTransport{Base: srv.Client().Transport}}
	if _, err := hc2.Get(srv.URL); err != nil || got.Get("X-Api-Key") != "" {
		t.Errorf("empty headers passthrough: %v", err)
	}
	hc3 := &http.Client{Transport: &HeaderTransport{Headers: map[string]string{"A": "b"}}}
	if _, err := hc3.Get(srv.URL); err != nil || got.Get("A") != "b" {
		t.Errorf("nil base defaults: %v", err)
	}
}

func TestTransportErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/scope" {
			w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="s"`)
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/forbidden" {
			w.WriteHeader(403)
			return
		}
		if r.URL.Path == "/unauth" {
			w.WriteHeader(401)
			return
		}
		w.WriteHeader(200)
	}))
	defer srv.Close()
	tr := NewTransport(nil, &fakeSource{tok: "t"})
	if tr.Base != http.DefaultTransport {
		t.Error("nil base defaults")
	}
	tr = NewTransport(srv.Client().Transport, &fakeSource{tok: "t"})
	// Non-replayable body.
	req, _ := http.NewRequest("POST", srv.URL, io.NopCloser(strings.NewReader("x")))
	req.GetBody = nil
	if _, err := tr.RoundTrip(req); err == nil || !strings.Contains(err.Error(), "not replayable") {
		t.Errorf("non-replayable: %v", err)
	}
	// Step-up failure.
	tr.StepUp = func(context.Context, string) (TokenSource, error) { return nil, errors.New("nope") }
	if _, err := (&http.Client{Transport: tr}).Get(srv.URL + "/scope"); err == nil || !strings.Contains(err.Error(), "step-up failed") {
		t.Errorf("step-up failure: %v", err)
	}
	// 403 without insufficient_scope passes through.
	resp, err := (&http.Client{Transport: tr}).Get(srv.URL + "/forbidden")
	if err != nil || resp.StatusCode != 403 {
		t.Errorf("plain 403: %v", err)
	}
	// No source: 401 returned as-is, request untouched.
	tr2 := NewTransport(srv.Client().Transport, nil)
	resp, err = (&http.Client{Transport: tr2}).Get(srv.URL + "/unauth")
	if err != nil || resp.StatusCode != 401 {
		t.Errorf("no source 401: %v", err)
	}
	// Token source failure.
	tr3 := NewTransport(srv.Client().Transport, errSource{})
	if _, err := (&http.Client{Transport: tr3}).Get(srv.URL); err == nil {
		t.Error("token error expected")
	}
	// Body replay via GetBody error.
	tr4 := NewTransport(srv.Client().Transport, &fakeSource{tok: "t"})
	req4, _ := http.NewRequest("POST", srv.URL, strings.NewReader("x"))
	req4.GetBody = func() (io.ReadCloser, error) { return nil, errors.New("gone") }
	if _, err := tr4.RoundTrip(req4); err == nil {
		t.Error("GetBody error expected")
	}
	if (&InsufficientScopeError{Scope: "s"}).Error() == "" {
		t.Error("error string")
	}
}

type errSource struct{}

func (errSource) Token(context.Context) (*Token, error) { return nil, errors.New("no token") }
func (errSource) Invalidate()                           {}
func (e errSource) WithScope(string) TokenSource        { return e }

func TestDiscoveryEdges(t *testing.T) {
	if _, err := PRMCandidates("::bad"); err == nil {
		t.Error("bad url")
	}
	if _, err := ASMetadataCandidates("::bad"); err == nil {
		t.Error("bad issuer")
	}
	c, _ := ASMetadataCandidates("https://as.example")
	if len(c) != 2 {
		t.Errorf("root issuer candidates = %v", c)
	}
	d := &Discoverer{}
	if d.httpClient() != http.DefaultClient {
		t.Error("nil client defaults")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server/notoken":
			_, _ = io.WriteString(w, `{"issuer":"x"}`)
		case "/.well-known/oauth-authorization-server/badjson":
			_, _ = io.WriteString(w, "{bad")
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	d = &Discoverer{Client: srv.Client()}
	if _, err := d.DiscoverServer(context.Background(), srv.URL+"/notoken"); err == nil || !strings.Contains(err.Error(), "missing token_endpoint") {
		t.Errorf("no token endpoint: %v", err)
	}
	if _, err := d.DiscoverServer(context.Background(), srv.URL+"/badjson"); err == nil {
		t.Error("bad json")
	}
	if _, _, err := d.DiscoverPRM(context.Background(), "::bad", ""); err == nil {
		t.Error("bad resource url")
	}
	if _, err := d.DiscoverServer(context.Background(), "::bad"); err == nil {
		t.Error("bad issuer")
	}
	if err := d.getJSON(context.Background(), "::bad", nil); err == nil {
		t.Error("bad get url")
	}
	if _, err := CanonicalResource("::bad"); err == nil {
		t.Error("bad canonical")
	}
	if _, ok := FindBearer(nil); ok {
		t.Error("no bearer in empty")
	}
	if (&Token{}).Valid(0) || (*Token)(nil).Valid(0) {
		t.Error("empty tokens are invalid")
	}
	f := &AuthorizationCodeFlow{}
	if _, err := f.Start(); err == nil {
		t.Error("missing auth url")
	}
	f = &AuthorizationCodeFlow{Endpoint: Endpoint{AuthorizationURL: "::bad"}}
	if _, err := f.Start(); err == nil {
		t.Error("bad auth url")
	}
	if _, err := f.Complete(context.Background(), "c", "s"); err == nil {
		t.Error("complete before start")
	}
	f = &AuthorizationCodeFlow{Endpoint: Endpoint{AuthorizationURL: "https://as/authorize", TokenURL: "http://127.0.0.1:1/t"}, Extra: url.Values{"aud": {"x"}}}
	u, err := f.Start()
	if err != nil || !strings.Contains(u, "aud=x") {
		t.Errorf("extra params: %v %s", err, u)
	}
	if _, err := f.Complete(context.Background(), "c", f.State()); err == nil {
		t.Error("token endpoint unreachable")
	}
}

func TestParseTokenLoop(t *testing.T) {
	// A challenge whose value is followed by whitespace and then junk.
	ch := ParseWWWAuthenticate(`Bearer a=b c`)
	if len(ch) == 0 || ch[0].Params["a"] != "b" {
		t.Errorf("got %+v", ch)
	}
	// Unparsable prefix is skipped to the next comma.
	ch = ParseWWWAuthenticate(`"junk", Bearer realm=r`)
	if _, ok := FindBearer(ch); !ok {
		t.Errorf("junk skip: %+v", ch)
	}
	ch = ParseWWWAuthenticate(`"junk"`)
	if len(ch) != 0 {
		t.Errorf("only junk: %+v", ch)
	}
	// Quoted value with escaped backslash at the end.
	ch = ParseWWWAuthenticate("Bearer realm=\"a\\")
	if len(ch) != 1 {
		t.Errorf("trailing backslash: %+v", ch)
	}
	// token68 followed by a comma.
	ch = ParseWWWAuthenticate(`Negotiate abc=, Bearer`)
	if len(ch) != 2 || ch[0].Params["token68"] != "abc=" {
		t.Errorf("token68 comma: %+v", ch)
	}
	ch = ParseWWWAuthenticate(`Negotiate abc=`)
	if len(ch) != 1 || ch[0].Params["token68"] != "abc=" {
		t.Errorf("token68 end: %+v", ch)
	}
}
