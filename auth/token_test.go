// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
	"time"
)

func tokenServer(t *testing.T, check func(r *http.Request, form url.Values)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		check(r, r.PostForm)
		json.NewEncoder(w).Encode(map[string]any{"access_token": "tok-" + r.PostForm.Get("grant_type"), "token_type": "Bearer", "expires_in": 3600, "refresh_token": "rt2"})
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestClientCredentialsSendsResourceAndExtra(t *testing.T) {
	srv, calls := tokenServer(t, func(r *http.Request, form url.Values) {
		if form.Get("grant_type") != "client_credentials" {
			t.Errorf("grant_type = %s", form.Get("grant_type"))
		}
		if form.Get("resource") != "https://mcp.example/mcp" {
			t.Errorf("resource = %q", form.Get("resource"))
		}
		if form.Get("profile_id") != "tenant-42" {
			t.Errorf("profile_id = %q", form.Get("profile_id"))
		}
		u, p, ok := r.BasicAuth()
		if !ok || u != "cid" || p != "sec" {
			t.Errorf("basic auth = %q %q %v", u, p, ok)
		}
	})
	src := &ClientCredentialsSource{
		HTTP: srv.Client(), Endpoint: Endpoint{TokenURL: srv.URL}, Creds: Credentials{ClientID: "cid", ClientSecret: "sec"},
		Resource: "https://mcp.example/mcp", Extra: url.Values{"profile_id": {"tenant-42"}},
	}
	ctx := context.Background()
	tok, err := src.Token(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "tok-client_credentials" {
		t.Errorf("tok = %+v", tok)
	}
	if _, err := src.Token(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Errorf("expected cached token, got %d calls", calls.Load())
	}
	src.Invalidate()
	if _, err := src.Token(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Errorf("expected re-acquire after Invalidate, got %d calls", calls.Load())
	}
}

func TestAuthorizationCodeFlow(t *testing.T) {
	srv, _ := tokenServer(t, func(r *http.Request, form url.Values) {
		if form.Get("grant_type") != "authorization_code" {
			t.Errorf("grant_type = %s", form.Get("grant_type"))
		}
		if form.Get("code_verifier") == "" || form.Get("code") != "abc" || form.Get("resource") != "https://r" {
			t.Errorf("form = %v", form)
		}
		if form.Get("client_id") != "pub" {
			t.Errorf("public client must send client_id in body: %v", form)
		}
	})
	f := &AuthorizationCodeFlow{HTTP: srv.Client(), Endpoint: Endpoint{AuthorizationURL: "https://as.example/authorize", TokenURL: srv.URL}, Creds: Credentials{ClientID: "pub"}, Resource: "https://r", RedirectURI: "http://127.0.0.1:1/cb", Scope: "read"}
	u, err := f.Start()
	if err != nil {
		t.Fatal(err)
	}
	pu, _ := url.Parse(u)
	q := pu.Query()
	for _, k := range []string{"code_challenge", "state", "resource", "client_id", "redirect_uri"} {
		if q.Get(k) == "" {
			t.Errorf("authorize url missing %s: %s", k, u)
		}
	}
	if q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
		t.Errorf("url = %s", u)
	}
	if _, err := f.Complete(context.Background(), "abc", "wrong"); err == nil {
		t.Fatal("expected state mismatch")
	}
	src, err := f.Complete(context.Background(), "abc", f.State())
	if err != nil {
		t.Fatal(err)
	}
	tok, _ := src.Token(context.Background())
	if tok.AccessToken != "tok-authorization_code" || tok.RefreshToken != "rt2" {
		t.Errorf("tok = %+v", tok)
	}
}

func TestRefreshingSourceRefreshes(t *testing.T) {
	srv, calls := tokenServer(t, func(r *http.Request, form url.Values) {
		if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "rt1" {
			t.Errorf("form = %v", form)
		}
	})
	src := NewRefreshingSource(srv.Client(), Endpoint{TokenURL: srv.URL}, Credentials{ClientID: "c"}, "", &Token{AccessToken: "old", RefreshToken: "rt1", Expiry: time.Now().Add(-time.Minute)})
	tok, err := src.Token(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if tok.AccessToken != "tok-refresh_token" || calls.Load() != 1 {
		t.Errorf("tok = %+v calls = %d", tok, calls.Load())
	}
	none := NewRefreshingSource(srv.Client(), Endpoint{TokenURL: srv.URL}, Credentials{}, "", &Token{AccessToken: "old", Expiry: time.Now().Add(-time.Minute)})
	if _, err := none.Token(context.Background()); !errors.Is(err, ErrReauthRequired) {
		t.Errorf("err = %v", err)
	}
}

func TestTokenErrorDecoded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		w.Write([]byte(`{"error":"invalid_client","error_description":"nope"}`))
	}))
	defer srv.Close()
	src := &ClientCredentialsSource{HTTP: srv.Client(), Endpoint: Endpoint{TokenURL: srv.URL}, Creds: Credentials{ClientID: "c"}}
	_, err := src.Token(context.Background())
	var te *TokenError
	ok := errors.As(err, &te)
	if !ok || te.Code != "invalid_client" || te.Description != "nope" {
		t.Fatalf("err = %v", err)
	}
}
