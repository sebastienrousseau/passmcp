// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestOriginNormalisation(t *testing.T) {
	cases := map[string]string{
		"https://Example.com/mcp":      "https://example.com",
		"https://example.com:443/mcp":  "https://example.com",
		"http://example.com:80/x":      "http://example.com",
		"https://example.com:8443/mcp": "https://example.com:8443",
		"HTTPS://EXAMPLE.COM:8443/a/b": "https://example.com:8443",
		"http://[::1]:3000/mcp":        "http://[::1]:3000",
	}
	for in, want := range cases {
		got, err := Origin(in)
		if err != nil {
			t.Fatalf("Origin(%q): %v", in, err)
		}
		if got != want {
			t.Errorf("Origin(%q) = %q, want %q", in, got, want)
		}
	}
	if _, err := Origin("/relative"); err == nil {
		t.Error("a relative URL has no origin")
	}
	if _, err := Origin("://bad"); err == nil {
		t.Error("an unparsable URL has no origin")
	}
}

func TestOriginSet(t *testing.T) {
	var nilSet *OriginSet
	u, _ := url.Parse("https://example.com/mcp")
	if nilSet.Allows(u) {
		t.Error("a nil set must allow nothing, so a missing allow-list fails closed")
	}
	if nilSet.Origins() != nil {
		t.Error("nil set has no origins")
	}

	s, err := NewOriginSet("https://a.example/mcp")
	if err != nil {
		t.Fatal(err)
	}
	if !s.Allows(u2(t, "https://a.example/other")) {
		t.Error("same origin, different path must be allowed")
	}
	if s.Allows(u2(t, "https://b.example/mcp")) {
		t.Error("another host must not be allowed")
	}
	if s.Allows(u2(t, "http://a.example/mcp")) {
		t.Error("a scheme downgrade is a different origin")
	}
	if _, err := NewOriginSet("nonsense"); err == nil {
		t.Error("NewOriginSet must reject an unparsable URL")
	}
	if len(s.Origins()) != 1 {
		t.Errorf("Origins = %v", s.Origins())
	}
}

func TestOriginSetPinsFirstUse(t *testing.T) {
	s := &OriginSet{}
	if !s.pin(u2(t, "https://first.example/mcp")) {
		t.Fatal("an empty set must admit the first origin")
	}
	if s.pin(u2(t, "https://second.example/mcp")) {
		t.Error("a pinned set must refuse a second origin")
	}
	if !s.pin(u2(t, "https://first.example/again")) {
		t.Error("the pinned origin stays allowed")
	}
}

func u2(t *testing.T, raw string) *url.URL {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u
}

// leakRig builds a victim server that redirects to an attacker server, and
// reports what the attacker received.
func leakRig(t *testing.T, header string) (victimURL string, received func() string) {
	t.Helper()
	var got string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = r.Header.Get(header)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(attacker.Close)
	victim := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/collect", http.StatusTemporaryRedirect)
	}))
	t.Cleanup(victim.Close)
	return victim.URL, func() string { return got }
}

// TestBearerDoesNotFollowRedirectOffOrigin is the regression for the
// highest-severity defect passmcp has had: an http.RoundTripper attaches its
// header below http.Client's redirect handling, so a transport that adds a
// token unconditionally re-adds it on every hop. One 307 from a server
// passmcp was pointed at was enough to collect the operator's token.
func TestBearerDoesNotFollowRedirectOffOrigin(t *testing.T) {
	victimURL, received := leakRig(t, "Authorization")
	tr := NewTransport(nil, StaticSource{AccessToken: "super-secret-token"})
	resp, err := (&http.Client{Transport: tr}).Get(victimURL)
	if err == nil {
		_ = resp.Body.Close()
	}
	if got := received(); got != "" {
		t.Fatalf("token leaked across origins: %q", got)
	}
}

func TestAPIKeyDoesNotFollowRedirectOffOrigin(t *testing.T) {
	victimURL, received := leakRig(t, "X-Api-Key")
	// A distinctive value rather than a realistic-looking vendor key: the
	// assertion is that it never reaches the other origin, and a fixture
	// shaped like a real credential only trips secret scanners.
	tr := NewHeaderTransport(nil, map[string]string{"X-Api-Key": "api-key-that-must-not-travel"}, nil)
	resp, err := (&http.Client{Transport: tr}).Get(victimURL)
	if err == nil {
		_ = resp.Body.Close()
	}
	if got := received(); got != "" {
		t.Fatalf("API key leaked across origins: %q", got)
	}
}

// Credentials must still reach the origin the operator named, on every hop
// within it: the fix must not have turned into a silent credential drop.
func TestCredentialsStillReachTheirOwnOrigin(t *testing.T) {
	var sawAuth, sawKey string
	var hops int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/start" {
			hops++
			http.Redirect(w, r, "/end", http.StatusTemporaryRedirect)
			return
		}
		sawAuth, sawKey = r.Header.Get("Authorization"), r.Header.Get("X-Api-Key")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	set, err := NewOriginSet(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	hdr := NewHeaderTransport(srv.Client().Transport, map[string]string{"X-Api-Key": "k"}, set)
	tr := NewTransport(hdr, StaticSource{AccessToken: "tok"})
	tr.Allowed = set
	c := &http.Client{Transport: tr, CheckRedirect: CheckRedirect(set, nil)}
	resp, err := c.Get(srv.URL + "/start")
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if hops != 1 {
		t.Fatalf("same-origin redirect was not followed (hops=%d)", hops)
	}
	if sawAuth != "Bearer tok" {
		t.Errorf("Authorization = %q after a same-origin redirect", sawAuth)
	}
	if sawKey != "k" {
		t.Errorf("X-Api-Key = %q after a same-origin redirect", sawKey)
	}
}

func TestCheckRedirect(t *testing.T) {
	set, _ := NewOriginSet("https://ok.example")
	fn := CheckRedirect(set, nil)

	if err := fn(&http.Request{URL: u2(t, "https://ok.example/next")}, nil); err != nil {
		t.Errorf("same origin must be allowed: %v", err)
	}
	var xo *ErrCrossOriginRedirect
	err := fn(&http.Request{URL: u2(t, "https://evil.example/")}, []*http.Request{{URL: u2(t, "https://ok.example/")}})
	if !errors.As(err, &xo) {
		t.Fatalf("cross origin must be refused, got %v", err)
	}
	if xo.To != "https://evil.example" || xo.From != "https://ok.example" {
		t.Errorf("error names the wrong hosts: %+v", xo)
	}
	if xo.Error() == "" {
		t.Error("error message is empty")
	}

	via := make([]*http.Request, MaxRedirects)
	for i := range via {
		via[i] = &http.Request{URL: u2(t, "https://ok.example/")}
	}
	if err := fn(&http.Request{URL: u2(t, "https://ok.example/loop")}, via); err == nil {
		t.Error("a redirect chain must be bounded even within one origin")
	}

	// A caller's own policy still runs after the origin check.
	sentinel := errors.New("caller policy")
	fn2 := CheckRedirect(set, func(*http.Request, []*http.Request) error { return sentinel })
	if err := fn2(&http.Request{URL: u2(t, "https://ok.example/x")}, nil); !errors.Is(err, sentinel) {
		t.Errorf("caller policy must still apply, got %v", err)
	}
}
