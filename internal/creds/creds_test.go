// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package creds

import (
	"net/url"
	"path/filepath"
	"testing"
	"time"

	"satellion.com/passmcp"
)

func TestEffectiveModeAndValidate(t *testing.T) {
	c := &Credentials{Mode: ModeAuto}
	if c.Effective() != ModeNone {
		t.Error("empty auto should be none")
	}
	c.SetFromFlag("token", "tok")
	if c.Effective() != ModeBearer || c.Sources["token"] != "flag --token" {
		t.Errorf("bearer: %s %v", c.Effective(), c.Sources)
	}
	c = &Credentials{Mode: ModeAuto, ClientID: "id"}
	if c.Effective() != ModeClientCredentials {
		t.Error("client id should imply client-credentials")
	}
	c = &Credentials{Mode: ModeBearer}
	if err := c.Validate(); err == nil {
		t.Error("bearer without token must fail validation")
	}
	c = &Credentials{Mode: "weird"}
	if err := c.Validate(); err == nil {
		t.Error("unknown mode must fail")
	}
	c = &Credentials{Mode: ModeNone, AuthURL: "https://a"}
	if err := c.Validate(); err == nil {
		t.Error("auth-url without token-url must fail")
	}
}

func TestEnvResolution(t *testing.T) {
	t.Setenv(EnvToken, "envtok")
	t.Setenv("MY_SECRET", "s3")
	c := &Credentials{Mode: ModeAuto}
	c.FromEnv()
	if c.Token != "envtok" || c.Sources["token"] != "env "+EnvToken {
		t.Errorf("env token: %+v", c)
	}
	if err := c.SetFromEnvName("client-secret", "MY_SECRET"); err != nil || c.ClientSecret != "s3" {
		t.Errorf("env name: %v %+v", err, c)
	}
	if err := c.SetFromEnvName("client-secret", "MISSING_VAR_X"); err == nil {
		t.Error("missing env var must error")
	}
}

func TestApplyAndSecretsAndDescribe(t *testing.T) {
	c := &Credentials{Mode: ModeClientCredentials, ClientID: "id", ClientSecret: "sec", Scope: "a b", Params: url.Values{"profile_id": {"t1"}},
		Headers: map[string]string{"X-Api-Key": "key123", "X-Tenant": "acme"}, BasicUser: "u", BasicPassword: "p", TokenURL: "https://as/token"}
	var cfg passmcp.Config
	c.Apply(&cfg)
	if cfg.Auth.Mode != passmcp.AuthClientCredentials || cfg.Auth.Overrides.TokenURL != "https://as/token" || cfg.Auth.Registration.StaticClientID != "id" {
		t.Errorf("cfg = %+v", cfg.Auth)
	}
	if cfg.Headers["X-Api-Key"] != "key123" || cfg.Headers["Authorization"] != "Basic dTpw" {
		t.Errorf("headers = %v", cfg.Headers)
	}
	secrets := c.Secrets()
	want := map[string]bool{"sec": true, "p": true, "key123": true}
	for _, s := range secrets {
		delete(want, s)
	}
	if len(want) != 0 {
		t.Errorf("secrets missing: %v (got %v)", want, secrets)
	}
	for _, s := range secrets {
		if s == "acme" {
			t.Error("non-secret header treated as secret")
		}
	}
	d := c.Describe()
	for _, bad := range []string{"sec", "key123", "p\""} {
		if containsWord(d, bad) {
			t.Errorf("Describe leaks %q: %s", bad, d)
		}
	}
	for _, good := range []string{"client-credentials", "client_id=id", "headers=X-Api-Key,X-Tenant", "basic=u"} {
		if !containsWord(d, good) {
			t.Errorf("Describe lacks %q: %s", good, d)
		}
	}
	a := &Credentials{Mode: ModeAuthorizationCode}
	a.Apply(&cfg)
	if cfg.Auth.RedirectURI != "http://127.0.0.1:8976/callback" {
		t.Errorf("redirect = %s", cfg.Auth.RedirectURI)
	}
}

func containsWord(s, w string) bool {
	return len(w) > 0 && len(s) >= len(w) && (indexOf(s, w) >= 0)
}

func indexOf(s, w string) int {
	for i := 0; i+len(w) <= len(s); i++ {
		if s[i:i+len(w)] == w {
			return i
		}
	}
	return -1
}

func TestParseHelpers(t *testing.T) {
	if k, v, err := ParseHeader("X-Api-Key: abc"); err != nil || k != "X-Api-Key" || v != "abc" {
		t.Errorf("%s %s %v", k, v, err)
	}
	if k, v, err := ParseHeader("X=1"); err != nil || k != "X" || v != "1" {
		t.Errorf("%s %s %v", k, v, err)
	}
	if _, _, err := ParseHeader("nonsense"); err == nil {
		t.Error("expected error")
	}
	if _, _, err := ParseParam("=v"); err == nil {
		t.Error("expected error")
	}
}

func TestStoreRoundTrip(t *testing.T) {
	st := &Store{Path: filepath.Join(t.TempDir(), "tokens.json")}
	if got, err := st.Get("https://x"); err != nil || got != nil {
		t.Fatalf("empty store: %v %v", got, err)
	}
	tok := StoredToken{Endpoint: "https://x", AccessToken: "at", RefreshToken: "rt", TokenURL: "https://as/token", ClientID: "c", Expiry: time.Now().Add(time.Hour)}
	if err := st.Put(tok); err != nil {
		t.Fatal(err)
	}
	got, err := st.Get("https://x")
	if err != nil || got == nil || got.AccessToken != "at" || got.SavedAt.IsZero() {
		t.Fatalf("get: %+v %v", got, err)
	}
	src := got.Source(HTTP{})
	if src == nil {
		t.Fatal("source nil")
	}
	if err := st.Delete("https://x"); err != nil {
		t.Fatal(err)
	}
	if got, _ := st.Get("https://x"); got != nil {
		t.Error("delete failed")
	}
}
