// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"satellion.com/passmcp/internal/engine"
)

// The finding this file exists for.
//
// CredSpec.Token carries json:"-", so a request cannot hand passmcp a token.
// CredSpec.TokenEnv is ordinary JSON, and it is resolved with os.LookupEnv
// against the serving process. On a laptop that is harmless: passmcp serve
// binds loopback behind a token, so the only caller already owns the
// environment. Answering the open internet turns the same field into an
// arbitrary read of the host's secrets, delivered as a bearer token to
// whichever endpoint the same request named.
//
// TestPublicModeRefusesEnvironmentExfiltration is the regression test for
// that. It asserts the target saw no Authorization header at all, rather
// than asserting the run failed: a run can fail for a dozen reasons, and
// only one of them means the secret stayed at home.

// spyServer records whether it was ever sent credentials.
type spyServer struct {
	*httptest.Server
	mu   sync.Mutex
	auth []string
}

func newSpyServer(t *testing.T) *spyServer {
	t.Helper()
	sp := &spyServer{}
	sp.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sp.mu.Lock()
		if a := r.Header.Get("Authorization"); a != "" {
			sp.auth = append(sp.auth, a)
		}
		sp.mu.Unlock()
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
		fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{}}`, id)
	}))
	t.Cleanup(sp.Close)
	return sp
}

func (sp *spyServer) sawCredentials() []string {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	out := make([]string, len(sp.auth))
	copy(out, sp.auth)
	return out
}

// newPublicServer starts a public server that permits exactly one endpoint.
func newPublicServer(t *testing.T, allowed string) *httptest.Server {
	t.Helper()
	list := &Allowlist{origins: map[string]string{}}
	o, err := originKey(allowed)
	if err != nil {
		t.Fatal(err)
	}
	list.origins[o] = "fixture"

	s, err := New(Options{Version: "test", Public: true, Allowed: list, RatePerMinute: 600, RateBurst: 100})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)
	return ts
}

func postRun(t *testing.T, ts *httptest.Server, body string) *http.Response {
	t.Helper()
	return do(t, ts, http.MethodPost, "/api/runs", body, map[string]string{"Content-Type": "application/json"})
}

// TestPublicModeRefusesEnvironmentExfiltration is the one that matters.
func TestPublicModeRefusesEnvironmentExfiltration(t *testing.T) {
	const secret = "s3cr3t-value-the-host-holds"
	t.Setenv("PASSMCP_TEST_HOST_SECRET", secret)

	spy := newSpyServer(t)
	ts := newPublicServer(t, spy.URL)

	// Exactly the request an attacker would send: a variable that IS set in
	// this process, and an endpoint they chose.
	body := fmt.Sprintf(`{"target":{"endpoint":%q},"credentials":{"token_env":"PASSMCP_TEST_HOST_SECRET"},"pacing":{"rps":0,"samples":1},"phases":{"only":["net"]}}`,
		spy.URL+"/mcp")
	resp := postRun(t, ts, body)

	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("naming a host environment variable must be refused, got %d", resp.StatusCode)
	}
	var out map[string]string
	_ = json.NewDecoder(resp.Body).Decode(&out)
	if !strings.Contains(out["error"], "token_env") {
		t.Errorf("the refusal should name the field: %q", out["error"])
	}

	// And nothing reached the wire regardless of what the response said.
	if got := spy.sawCredentials(); len(got) != 0 {
		t.Fatalf("the host's environment reached the target: %q", got)
	}
}

// TestPublicModeRefusesEveryCredentialField walks the same struct the guard
// walks, so a field added later is covered without anyone editing a list.
func TestPublicModeRefusesEveryCredentialField(t *testing.T) {
	spy := newSpyServer(t)
	ts := newPublicServer(t, spy.URL)

	// Every field a request can actually carry. json:"-" fields are absent
	// on purpose: they cannot be expressed in a request body at all.
	for _, tc := range []struct{ field, json string }{
		{"TokenEnv", `"token_env":"HOME"`},
		{"ClientSecretEnv", `"client_secret_env":"HOME"`},
		{"Mode", `"mode":"authorization-code"`},
		{"ClientID", `"client_id":"abc"`},
		{"ClientMetadataURL", `"client_metadata_url":"https://evil.example/cimd"`},
		{"TokenURL", `"token_url":"https://evil.example/token"`},
		{"AuthURL", `"auth_url":"https://evil.example/auth"`},
		{"Resource", `"resource":"https://evil.example/"`},
		{"Scope", `"scope":"openid"`},
		{"RedirectPort", `"redirect_port":9999`},
		{"TokenAuthMethod", `"token_auth_method":"client_secret_post"`},
		{"Params", `"params":{"audience":["x"]}`},
	} {
		t.Run(tc.field, func(t *testing.T) {
			body := fmt.Sprintf(`{"target":{"endpoint":%q},"credentials":{%s},"phases":{"only":["net"]}}`,
				spy.URL+"/mcp", tc.json)
			resp := postRun(t, ts, body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Errorf("%s must be refused in public mode, got %d", tc.field, resp.StatusCode)
			}
		})
	}
}

// TestCredentialGuardCoversTheWholeStruct fails when a credential field is
// added and the guard has not been thought about. It is deliberately
// annoying: the cost of missing one is a hosted credential leak.
func TestCredentialGuardCoversTheWholeStruct(t *testing.T) {
	// Mode is the only field with a value public mode tolerates.
	if got := credentialFieldsSet(engine.CredSpec{Mode: "none"}); len(got) != 0 {
		t.Errorf(`Mode "none" is the absence of credentials, got %v`, got)
	}
	if got := credentialFieldsSet(engine.CredSpec{}); len(got) != 0 {
		t.Errorf("an empty CredSpec sets nothing, got %v", got)
	}
	if got := credentialFieldsSet(engine.CredSpec{Mode: "bearer"}); len(got) != 1 {
		t.Errorf("a real mode is a credential, got %v", got)
	}
	// Every other field, whatever it is called, must be reported.
	full := engine.CredSpec{
		Token: "t", TokenEnv: "E", Basic: "u:p", ClientID: "c",
		ClientSecret: "s", ClientSecretEnv: "E2", ClientMetadataURL: "u",
		Scope: "s", TokenURL: "t", AuthURL: "a", Resource: "r",
		RedirectPort: 1, TokenAuthMethod: "m",
		Headers: map[string]string{"X": "Y"},
	}
	got := credentialFieldsSet(full)
	if len(got) < 14 {
		t.Errorf("the guard reported %d of the fields set (%v); it must report all of them", len(got), got)
	}
}

// TestPublicModeOnlyScansItsAllowlist covers the SSRF half.
func TestPublicModeOnlyScansItsAllowlist(t *testing.T) {
	spy := newSpyServer(t)
	other := newSpyServer(t)
	ts := newPublicServer(t, spy.URL)

	for _, endpoint := range []string{
		other.URL + "/mcp",
		"http://169.254.169.254/latest/meta-data/",
		"https://metadata.google.internal/computeMetadata/v1/",
		"http://127.0.0.1:22/",
		"http://[::1]:8080/mcp",
	} {
		body := fmt.Sprintf(`{"target":{"endpoint":%q},"phases":{"only":["net"]}}`, endpoint)
		resp := postRun(t, ts, body)
		if resp.StatusCode != http.StatusForbidden && resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s must not be scannable, got %d", endpoint, resp.StatusCode)
		}
	}
	if got := other.sawCredentials(); len(got) != 0 {
		t.Errorf("an off-list server was contacted: %v", got)
	}
}

// TestPublicModeNeedsAnAllowlist covers the startup refusal. An empty list
// must not read as "allow everything".
func TestPublicModeNeedsAnAllowlist(t *testing.T) {
	if _, err := New(Options{Public: true}); err == nil {
		t.Fatal("public mode without an allowlist must be refused")
	}
	empty := &Allowlist{origins: map[string]string{}}
	if _, err := New(Options{Public: true, Allowed: empty}); err == nil {
		t.Fatal("public mode with an empty allowlist must be refused")
	}
}

// TestAllowlistRefusesUnsafeEntries keeps the list itself from being the way
// in. An operator pasting a registry export should not be able to point the
// host at its own metadata service by accident.
func TestAllowlistRefusesUnsafeEntries(t *testing.T) {
	for _, bad := range []string{
		"http://example.com/mcp",
		"https://127.0.0.1/mcp",
		"https://localhost/mcp",
		"https://169.254.169.254/",
		"https://10.0.0.5/mcp",
		"https://[::1]/mcp",
		"not a url",
		"https:///mcp",
	} {
		if _, err := NewAllowlist(bad); err == nil {
			t.Errorf("%q should not be allowlistable", bad)
		}
	}
	if _, err := NewAllowlist("https://mcp.example.com/mcp"); err != nil {
		t.Errorf("a public https endpoint should be allowlistable: %v", err)
	}
}

// TestPublicModeNeedsNoToken: the page is for people who were never given
// one. Origin validation still applies.
func TestPublicModeNeedsNoToken(t *testing.T) {
	spy := newSpyServer(t)
	ts := newPublicServer(t, spy.URL)

	body := fmt.Sprintf(`{"target":{"endpoint":%q},"pacing":{"rps":0,"samples":1},"phases":{"only":["net"]}}`, spy.URL+"/mcp")
	if resp := postRun(t, ts, body); resp.StatusCode != http.StatusAccepted {
		t.Errorf("a public server should accept a run with no token, got %d", resp.StatusCode)
	}
	resp := do(t, ts, http.MethodGet, "/api/runs/none/report.json", "", map[string]string{"Origin": "https://evil.example"})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin must still be refused in public mode, got %d", resp.StatusCode)
	}
}

// TestRateLimit covers the bucket, including that it refills.
func TestRateLimit(t *testing.T) {
	now := time.Now()
	l := newLimiter(60, 2) // one per second, burst of two
	l.nowFunc = func() time.Time { return now }

	// Each call consumes a token, so these are two distinct events even
	// though they read alike.
	for i := range 2 {
		if !l.allow("a") {
			t.Fatalf("token %d of the burst should be available", i+1)
		}
	}
	if l.allow("a") {
		t.Error("a third call inside the same instant should be refused")
	}
	if !l.allow("b") {
		t.Error("one caller must not spend another's budget")
	}
	now = now.Add(2 * time.Second)
	if !l.allow("a") {
		t.Error("the bucket should refill")
	}
}

// TestPublicModeRateLimits proves it is wired to the route that costs
// something, not merely implemented.
func TestPublicModeRateLimits(t *testing.T) {
	spy := newSpyServer(t)
	list := &Allowlist{origins: map[string]string{}}
	o, err := originKey(spy.URL)
	if err != nil {
		t.Fatal(err)
	}
	list.origins[o] = "fixture"
	s, err := New(Options{Version: "test", Public: true, Allowed: list, RatePerMinute: 1, RateBurst: 1})
	if err != nil {
		t.Fatal(err)
	}
	ts := httptest.NewServer(s)
	t.Cleanup(ts.Close)

	body := fmt.Sprintf(`{"target":{"endpoint":%q},"pacing":{"rps":0,"samples":1},"phases":{"only":["net"]}}`, spy.URL+"/mcp")
	if resp := postRun(t, ts, body); resp.StatusCode != http.StatusAccepted {
		t.Fatalf("the first run should be accepted, got %d", resp.StatusCode)
	}
	resp := postRun(t, ts, body)
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("the second run should be rate limited, got %d", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Error("a rate-limited response should say when to come back")
	}
}

// TestClientKeyIgnoresForwardedHeaderByDefault: trusting it unconditionally
// would let a caller mint a new identity per request.
func TestClientKeyIgnoresForwardedHeaderByDefault(t *testing.T) {
	r := httptest.NewRequest(http.MethodPost, "/api/runs", nil)
	r.RemoteAddr = "203.0.113.7:5555"
	r.Header.Set("X-Forwarded-For", "198.51.100.1")

	if got := clientKey(r, false); got != "203.0.113.7" {
		t.Errorf("without a trusted proxy the socket address decides, got %q", got)
	}
	if got := clientKey(r, true); got != "198.51.100.1" {
		t.Errorf("behind a trusted proxy the header decides, got %q", got)
	}
}

// TestLocalModeIsUnchanged: none of this may leak into the default posture,
// which still takes credentials and still demands a token.
func TestLocalModeIsUnchanged(t *testing.T) {
	s, ts := newTestServer(t)
	if s.limit != nil {
		t.Error("a local server should not rate limit its operator")
	}
	if resp := do(t, ts, http.MethodGet, "/api/runs/none/report.json", "", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("a local server still requires its token, got %d", resp.StatusCode)
	}
}

// TestLoadAllowlist covers the file path, including the ways an operator can
// get it wrong. Each of these is a deployment that must not start.
func TestLoadAllowlist(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}

	good := write("good.json", `{"servers":[
	  {"name":"Example","endpoint":"https://mcp.example.com/mcp"},
	  {"name":"Other","endpoint":"https://other.example.org/v1/mcp"}]}`)
	a, err := LoadAllowlist(good)
	if err != nil {
		t.Fatalf("a valid allowlist should load: %v", err)
	}
	if got := a.Endpoints(); len(got) != 2 {
		t.Errorf("two entries expected, got %v", got)
	}
	if got := a.Names(); len(got) != 2 || got[0] != "Example" {
		t.Errorf("names should come back sorted: %v", got)
	}
	// The path is origin-level: any path on an allowed origin is in scope,
	// because a server's endpoint path is its own business.
	if _, ok := a.Permits("https://mcp.example.com/some/other/path"); !ok {
		t.Error("another path on an allowed origin should be permitted")
	}
	if _, ok := a.Permits("https://mcp.example.com.evil.test/mcp"); ok {
		t.Error("a suffix of an allowed host is a different host")
	}
	if _, ok := a.Permits("http://mcp.example.com/mcp"); ok {
		t.Error("a different scheme is a different origin")
	}

	for _, tc := range []struct{ name, body string }{
		{"empty.json", `{"servers":[]}`},
		{"none.json", `{}`},
		{"plaintext.json", `{"servers":[{"name":"x","endpoint":"http://example.com/mcp"}]}`},
		{"loopback.json", `{"servers":[{"name":"x","endpoint":"https://127.0.0.1/mcp"}]}`},
		{"garbage.json", `not json at all`},
	} {
		if _, err := LoadAllowlist(write(tc.name, tc.body)); err == nil {
			t.Errorf("%s should not produce a usable allowlist", tc.name)
		}
	}
	if _, err := LoadAllowlist(filepath.Join(dir, "absent.json")); err == nil {
		t.Error("a missing allowlist file must be an error, not an empty list")
	}
}

// TestAllowlistNilIsClosed: a zero value must refuse, not permit. The
// difference decides what happens if a code path ever forgets to load one.
func TestAllowlistNilIsClosed(t *testing.T) {
	var a *Allowlist
	if _, ok := a.Permits("https://mcp.example.com/mcp"); ok {
		t.Error("a nil allowlist must permit nothing")
	}
	if a.Names() != nil || a.Endpoints() != nil {
		t.Error("a nil allowlist has no entries")
	}
}

// TestLimiterDefaults covers the fallbacks for unset options.
func TestLimiterDefaults(t *testing.T) {
	l := newLimiter(0, 0)
	if l.rate <= 0 || l.burst <= 0 {
		t.Errorf("zero options must fall back to something usable: rate=%v burst=%v", l.rate, l.burst)
	}
	if !l.allow("x") {
		t.Error("the default limiter should permit a first call")
	}
	// The sweep must not drop a bucket that is still in use.
	l2 := newLimiter(60, 1)
	base := time.Now()
	l2.nowFunc = func() time.Time { return base }
	l2.allow("keep")
	base = base.Add(11 * time.Minute)
	if !l2.allow("keep") {
		t.Error("a bucket refilled over eleven minutes should permit a call")
	}
}

// TestOriginKeyRejectsNonAbsolute covers the parse failures that make an
// endpoint unmatchable rather than accidentally matching.
func TestOriginKeyRejectsNonAbsolute(t *testing.T) {
	for _, bad := range []string{"", "/mcp", "mcp.example.com/mcp", "://x"} {
		if _, err := originKey(bad); err == nil {
			t.Errorf("%q is not an absolute URL", bad)
		}
	}
}
