// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"bytes"
	"context"
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/probe"

	sra2a "satellion.com/passmcp-reporting/a2a"
)

func run(t *testing.T, a *agent, opts Options) *Result {
	t.Helper()
	if opts.URL == "" {
		opts.URL = a.base
	}
	r, err := Run(context.Background(), opts)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func unsigned(binding, path string) func(string) map[string]any {
	return func(base string) map[string]any { return validCard(base, binding, path) }
}

// TestCardSchemaReportsErrorsWithPaths fetches a card with three defects
// from the well-known path and shows each is reported where it is.
//
// AC: A2A-01
func TestCardSchemaReportsErrorsWithPaths(t *testing.T) {
	a := &agent{auth: "refuse", card: func(base string) map[string]any {
		c := validCard(base, "JSONRPC", "/rpc")
		delete(c, "version")
		c["skills"].([]any)[0].(map[string]any)["tags"] = "cooking"
		c["url"] = base // an A2A 0.3 field
		return c
	}}
	a.start(t)
	r := run(t, a, Options{URL: a.base + "/some/agent/path"})
	if a.calls[0] != "GET "+WellKnownPath {
		t.Errorf("first request was %q, want the well-known card at the domain root", a.calls[0])
	}
	f := findingFor(t, r, "a2a.card_schema")
	if f.Status != "fail" || f.Severity != "major" {
		t.Fatalf("got %s/%s: %s", f.Status, f.Severity, f.Detail)
	}
	for _, w := range []string{"$.version: required", "$.skills[0].tags: must be an array", "$.url: not a field of AgentCard"} {
		if !strings.Contains(f.Detail, w) {
			t.Errorf("detail lacks %q: %s", w, f.Detail)
		}
	}
	if len(r.SchemaErrors) != 3 || !slices.Equal(f.Evidence, []string{cardRequest}) {
		t.Errorf("schema errors %v, evidence %v", r.SchemaErrors, f.Evidence)
	}
	if !r.Failed() {
		t.Error("a failed check did not fail the run")
	}
}

// AC: A2A-01
func TestCardSchemaPassesAValidCard(t *testing.T) {
	a := &agent{auth: "refuse", card: unsigned("JSONRPC", "/rpc")}
	a.start(t)
	r := run(t, a, Options{})
	f := findingFor(t, r, "a2a.card_schema")
	if f.Status != "pass" || !slices.Equal(f.Evidence, []string{cardRequest}) {
		t.Fatalf("got %s %v: %s", f.Status, f.Evidence, f.Detail)
	}
	if r.Agent.Name != "Recipe Agent" || r.Agent.ProtocolVersion != "1.0" || len(r.CardDigest) != 64 {
		t.Errorf("agent %+v digest %q", r.Agent, r.CardDigest)
	}
}

func TestCardSchemaFailsWhenThereIsNoCard(t *testing.T) {
	cases := map[string]http.HandlerFunc{
		"404":      func(w http.ResponseWriter, r *http.Request) { http.NotFound(w, r) },
		"not json": func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("<html>")) },
		"array":    func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("[]")) },
		"oversized": func(w http.ResponseWriter, _ *http.Request) {
			_, _ = w.Write(bytes.Repeat([]byte(" "), maxCardBytes+2))
		},
	}
	for name, h := range cases {
		t.Run(name, func(t *testing.T) {
			srv := httptest.NewServer(h)
			defer srv.Close()
			r, err := Run(context.Background(), Options{URL: srv.URL})
			if err != nil {
				t.Fatal(err)
			}
			if f := findingFor(t, r, "a2a.card_schema"); f.Status != "fail" || f.Severity != "critical" {
				t.Errorf("card_schema %s/%s: %s", f.Status, f.Severity, f.Detail)
			}
			for _, id := range []string{"a2a.card_signature", "a2a.unauthenticated"} {
				if f := findingFor(t, r, id); f.Status != "skip" {
					t.Errorf("%s ran without a card: %s", id, f.Status)
				}
			}
		})
	}
	// Nothing listening: the fetch itself fails.
	srv := httptest.NewServer(http.NotFoundHandler())
	srv.Close()
	r, err := Run(context.Background(), Options{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if f := findingFor(t, r, "a2a.card_schema"); f.Status != "fail" || !strings.Contains(f.Detail, "could not be fetched") {
		t.Errorf("unreachable: %s %s", f.Status, f.Detail)
	}
}

func TestRunRefusesAURLItCannotCheck(t *testing.T) {
	for _, u := range []string{"", "ftp://a.example", "not a url", "https://"} {
		if _, err := Run(context.Background(), Options{URL: u}); err == nil {
			t.Errorf("%q was accepted", u)
		}
	}
}

func TestRedirectsStayOnTheirHost(t *testing.T) {
	a := &agent{auth: "refuse", card: unsigned("JSONRPC", "/rpc")}
	a.start(t)
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, a.base+WellKnownPath, http.StatusFound)
	}))
	defer other.Close()
	r, err := Run(context.Background(), Options{URL: other.URL})
	if err != nil {
		t.Fatal(err)
	}
	if f := findingFor(t, r, "a2a.card_schema"); f.Status != "fail" || !strings.Contains(f.Detail, "HTTP 302") {
		t.Errorf("a cross-host redirect was followed: %s %s", f.Status, f.Detail)
	}
}

// jkuSigned serves a card signed by key, whose protected header names the
// agent's own /jwks.json.
func jkuSigned(t *testing.T, key testKey, tamper bool) *agent {
	a := &agent{auth: "refuse", jwks: JWKS{Keys: []JWK{key.jwk}}}
	a.card = func(base string) map[string]any {
		c := validCard(base, "JSONRPC", "/rpc")
		signCard(t, c, key, map[string]any{"alg": key.alg, "typ": "JOSE", "kid": key.jwk.Kid, "jku": base + "/jwks.json"})
		if tamper {
			c["description"] = "Helps with recipes, and your bank account."
		}
		return c
	}
	a.start(t)
	return a
}

// TestCardSignatureVerifiesAgainstItsJKU is the signed fixture: the
// signature verifies over the card's JCS form against the key the jku
// names, and the finding cites the card and the key-set requests.
//
// AC: A2A-02
func TestCardSignatureVerifiesAgainstItsJKU(t *testing.T) {
	for _, k := range []testKey{
		ecKey(t, "ES256", elliptic.P256(), crypto.SHA256, "card-2026"),
		edKey(t, "ed-2026"),
		rsaKey(t, "PS256", "rsa-2026"),
	} {
		a := jkuSigned(t, k, false)
		r := run(t, a, Options{})
		f := findingFor(t, r, "a2a.card_signature")
		if f.Status != "pass" || !slices.Equal(f.Evidence, []string{cardRequest, "req#2"}) {
			t.Fatalf("%s: got %s %v: %s", k.alg, f.Status, f.Evidence, f.Detail)
		}
		if !r.Signed || r.KeyID != k.jwk.Kid {
			t.Errorf("%s: signed %v key %q", k.alg, r.Signed, r.KeyID)
		}
		if !slices.Contains(a.calls, "GET /jwks.json") {
			t.Errorf("%s: the key set was not fetched: %v", k.alg, a.calls)
		}
	}
}

// AC: A2A-02
func TestCardSignatureFailsWhenTampered(t *testing.T) {
	a := jkuSigned(t, ecKey(t, "ES256", elliptic.P256(), crypto.SHA256, "k"), true)
	r := run(t, a, Options{})
	f := findingFor(t, r, "a2a.card_signature")
	if f.Status != "fail" || f.Severity != "major" || !strings.Contains(f.Detail, "canonical form") {
		t.Fatalf("got %s/%s: %s", f.Status, f.Severity, f.Detail)
	}
	if r.KeyID != "" {
		t.Errorf("a failed signature recorded key %q", r.KeyID)
	}
}

// AC: A2A-02
func TestCardSignatureFailsWhenTheKeyCannotBeResolved(t *testing.T) {
	key := ecKey(t, "ES256", elliptic.P256(), crypto.SHA256, "k")
	cases := map[string]struct {
		header func(base string) map[string]any
		jwks   JWKS
		want   string
	}{
		"jku answers 404": {
			header: func(base string) map[string]any {
				return map[string]any{"alg": "ES256", "kid": "k", "jku": base + "/missing.json"}
			},
			want: "HTTP 404",
		},
		"kid not in the set": {
			header: func(base string) map[string]any {
				return map[string]any{"alg": "ES256", "kid": "k", "jku": base + "/jwks.json"}
			},
			jwks: JWKS{Keys: []JWK{{Kid: "other"}, {Kid: "another"}}},
			want: `has no key "k"`,
		},
		"no key source": {
			header: func(string) map[string]any { return map[string]any{"alg": "ES256", "kid": "k"} },
			want:   "neither a jku nor a jwk",
		},
		"jku refused by policy": {
			header: func(string) map[string]any {
				return map[string]any{"alg": "ES256", "kid": "k", "jku": "http://10.0.0.1/jwks.json"}
			},
			want: "cannot be resolved",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			a := &agent{auth: "refuse", jwks: tc.jwks}
			a.card = func(base string) map[string]any {
				c := validCard(base, "JSONRPC", "/rpc")
				signCard(t, c, key, tc.header(base))
				return c
			}
			a.start(t)
			f := findingFor(t, run(t, a, Options{}), "a2a.card_signature")
			if f.Status != "fail" || !strings.Contains(f.Detail, tc.want) {
				t.Errorf("got %s: %s", f.Status, f.Detail)
			}
			if slices.Contains(a.calls, "GET /missing.json") && name != "jku answers 404" {
				t.Errorf("unexpected key fetch: %v", a.calls)
			}
		})
	}
}

func TestCardSignatureMalformedEntries(t *testing.T) {
	a := &agent{auth: "refuse", card: func(base string) map[string]any {
		c := validCard(base, "JSONRPC", "/rpc")
		c["signatures"] = []any{
			map[string]any{"protected": "", "signature": ""},
			map[string]any{"protected": "!!", "signature": "x"},
		}
		return c
	}}
	a.start(t)
	f := findingFor(t, run(t, a, Options{}), "a2a.card_signature")
	if f.Status != "fail" || !strings.Contains(f.Detail, "signature 1:") || !strings.Contains(f.Detail, "signature 2:") {
		t.Errorf("got %s: %s", f.Status, f.Detail)
	}
}

// AC: A2A-02
func TestCardSignatureEmbeddedKeyOnlyWarns(t *testing.T) {
	key := edKey(t, "self")
	a := &agent{auth: "refuse"}
	a.card = func(base string) map[string]any {
		c := validCard(base, "JSONRPC", "/rpc")
		jwk := map[string]any{"kty": key.jwk.Kty, "crv": key.jwk.Crv, "x": key.jwk.X, "kid": "self"}
		signCard(t, c, key, map[string]any{"alg": "EdDSA", "kid": "self", "jwk": jwk})
		return c
	}
	a.start(t)
	r := run(t, a, Options{})
	if f := findingFor(t, r, "a2a.card_signature"); f.Status != "warn" || r.KeyID != "self" {
		t.Errorf("got %s key %q: %s", f.Status, r.KeyID, f.Detail)
	}
}

// AC: A2A-02
func TestCardSignatureUnsignedIsInfo(t *testing.T) {
	a := &agent{auth: "refuse", card: unsigned("JSONRPC", "/rpc")}
	a.start(t)
	r := run(t, a, Options{})
	if f := findingFor(t, r, "a2a.card_signature"); f.Status != "info" || r.Signed {
		t.Errorf("got %s signed %v", f.Status, r.Signed)
	}
}

func TestCardSignatureNonCanonicalisableCard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// A number JSON accepts but no IEEE double can hold.
		_, _ = w.Write([]byte(`{"name":"a","signatures":[{"protected":"e30","signature":"AA"}],"x":1e400}`))
	}))
	defer srv.Close()
	r, err := Run(context.Background(), Options{URL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	if f := findingFor(t, r, "a2a.card_signature"); f.Status != "fail" || !strings.Contains(f.Detail, "canonicalised") {
		t.Errorf("got %s: %s", f.Status, f.Detail)
	}
}

// TestUnauthenticatedAgentThatServesFails is the A2A-03 case: a card with
// no security scheme, whose agent answers ListTasks with no credentials,
// fails and cites the one request that showed it.
//
// AC: A2A-03
func TestUnauthenticatedAgentThatServesFails(t *testing.T) {
	for _, tc := range []struct{ binding, path, call string }{
		{"JSONRPC", "/rpc", "POST /rpc"},
		{"HTTP+JSON", "/v1", "GET /v1/tasks?pageSize=1"},
	} {
		a := &agent{auth: "serve", card: unsigned(tc.binding, tc.path)}
		a.start(t)
		r := run(t, a, Options{})
		f := findingFor(t, r, "a2a.unauthenticated")
		if f.Status != "fail" || f.Severity != "critical" || !slices.Equal(f.Evidence, []string{"req#2"}) {
			t.Fatalf("%s: got %s/%s %v: %s", tc.binding, f.Status, f.Severity, f.Evidence, f.Detail)
		}
		if !strings.Contains(f.Detail, "declares no authentication") {
			t.Errorf("%s: %s", tc.binding, f.Detail)
		}
		if len(a.calls) != 2 || a.calls[1] != tc.call {
			t.Errorf("%s: calls %v, want exactly the card and %q", tc.binding, a.calls, tc.call)
		}
		if got := a.last.Get("A2A-Version"); got != "1.0" {
			t.Errorf("%s: A2A-Version %q", tc.binding, got)
		}
		if a.last.Get("Authorization") != "" {
			t.Errorf("%s: the call carried credentials", tc.binding)
		}
	}
}

// AC: A2A-03
func TestUnauthenticatedVerdicts(t *testing.T) {
	declared := func(base string) map[string]any {
		c := validCard(base, "JSONRPC", "/rpc")
		c["securitySchemes"] = map[string]any{"bearer": map[string]any{"httpAuthSecurityScheme": map[string]any{"scheme": "Bearer"}}}
		c["skills"].([]any)[0].(map[string]any)["securityRequirements"] = []any{
			map[string]any{"schemes": map[string]any{"oauth": map[string]any{"list": []any{"read"}}}},
		}
		return c
	}
	cases := []struct {
		name, auth, status, want string
		card                     func(string) map[string]any
	}{
		{"declared and refused", "refuse", "pass", "declares bearer, oauth", declared},
		{"declared and served", "serve", "fail", "but the agent answered", declared},
		{"undeclared and refused", "refuse", "warn", "declares no security scheme", unsigned("JSONRPC", "/rpc")},
		{"error answer", "error", "info", "JSON-RPC error", unsigned("JSONRPC", "/rpc")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a := &agent{auth: tc.auth, card: tc.card}
			a.start(t)
			f := findingFor(t, run(t, a, Options{}), "a2a.unauthenticated")
			if f.Status != tc.status || !strings.Contains(f.Detail, tc.want) {
				t.Errorf("got %s: %s", f.Status, f.Detail)
			}
			if f.Status == "pass" && !slices.Equal(f.Evidence, []string{"req#2"}) {
				t.Errorf("a pass without its request: %v", f.Evidence)
			}
		})
	}
}

func TestUnauthenticatedSkips(t *testing.T) {
	cases := map[string]func(string) map[string]any{
		"grpc only": unsigned("GRPC", ":443"),
		"interface refused by policy": func(base string) map[string]any {
			c := validCard(base, "JSONRPC", "/rpc")
			c["supportedInterfaces"] = []any{map[string]any{"url": "http://10.1.2.3/rpc", "protocolBinding": "JSONRPC", "protocolVersion": "1.0"}}
			return c
		},
	}
	for name, card := range cases {
		t.Run(name, func(t *testing.T) {
			a := &agent{auth: "serve", card: card}
			a.start(t)
			if f := findingFor(t, run(t, a, Options{}), "a2a.unauthenticated"); f.Status != "skip" || len(a.calls) != 1 {
				t.Errorf("got %s after calls %v: %s", f.Status, a.calls, f.Detail)
			}
		})
	}
}

func TestClassifyAndListTasksRequest(t *testing.T) {
	cases := []struct {
		binding string
		status  int
		body    string
		want    probeOutcome
	}{
		{"JSONRPC", 403, "", probeRefused},
		{"JSONRPC", 500, "", probeUnknown},
		{"JSONRPC", 200, "not json", probeUnknown},
		{"HTTP+JSON", 200, `{"error":1}`, probeUnknown},
		{"HTTP+JSON", 200, `{"tasks":[]}`, probeServed},
	}
	for _, tc := range cases {
		if got, _ := classify(tc.binding, tc.status, []byte(tc.body)); got != tc.want {
			t.Errorf("%s %d %q: got %v", tc.binding, tc.status, tc.body, got)
		}
	}
	i := iface{url: "https://a.example/v1/", binding: "HTTP+JSON", tenant: "acme co"}
	req, err := listTasksRequest(context.Background(), i)
	if err != nil || req.URL.String() != "https://a.example/v1/acme%20co/tasks?pageSize=1" {
		t.Fatalf("tenant path: %v %v", req, err)
	}
	i.binding = "JSONRPC"
	req, err = listTasksRequest(context.Background(), i)
	if err != nil {
		t.Fatal(err)
	}
	var body map[string]any
	_ = json.NewDecoder(req.Body).Decode(&body)
	if p, _ := body["params"].(map[string]any); p["tenant"] != "acme co" || body["method"] != "ListTasks" {
		t.Errorf("JSON-RPC body %v", body)
	}
	if _, err := listTasksRequest(context.Background(), iface{url: "::bad", binding: "JSONRPC"}); err == nil {
		t.Error("a bad URL built a request")
	}
}

// TestTransportPlainHTTPFromAPublicHostFails mirrors net.scheme: the card
// served over http from a name that is not this machine fails.
//
// AC: A2A-04
func TestTransportPlainHTTPFromAPublicHostFails(t *testing.T) {
	a := &agent{auth: "refuse", card: unsigned("JSONRPC", "/rpc")}
	tr := a.startAs(t, "http")
	r := run(t, a, Options{Transport: tr, Policy: publicPolicy()})
	f := findingFor(t, r, "a2a.transport")
	if f.Status != "fail" || f.Severity != "critical" || !slices.Equal(f.Evidence, []string{cardRequest}) {
		t.Fatalf("got %s/%s %v: %s", f.Status, f.Severity, f.Evidence, f.Detail)
	}
	if !strings.Contains(f.Detail, "example.com") {
		t.Errorf("detail does not name the host: %s", f.Detail)
	}
}

// AC: A2A-04
func TestTransportLoopbackHTTPIsInfo(t *testing.T) {
	a := &agent{auth: "refuse", card: unsigned("JSONRPC", "/rpc")}
	a.start(t)
	if f := findingFor(t, run(t, a, Options{}), "a2a.transport"); f.Status != "info" {
		t.Errorf("got %s: %s", f.Status, f.Detail)
	}
	for _, h := range []string{"localhost", "a.localhost", "127.0.0.1", "::1"} {
		if !isLoopback(h) {
			t.Errorf("%s is not loopback", h)
		}
	}
	if isLoopback("example.com") {
		t.Error("example.com is loopback")
	}
}

// AC: A2A-04
func TestTransportHTTPSPasses(t *testing.T) {
	a := &agent{auth: "refuse", card: unsigned("JSONRPC", "/rpc")}
	tr := a.startAs(t, "https")
	r := run(t, a, Options{Transport: tr, Policy: publicPolicy()})
	if f := findingFor(t, r, "a2a.transport"); f.Status != "pass" || !slices.Equal(f.Evidence, []string{cardRequest}) {
		t.Errorf("got %s %v: %s", f.Status, f.Evidence, f.Detail)
	}
	if f := findingFor(t, r, "a2a.unauthenticated"); f.Status != "warn" {
		t.Errorf("the HTTPS interface was not asked: %s %s", f.Status, f.Detail)
	}
	// An HTTPS agent that cannot be reached is not shown to be served
	// over HTTPS.
	r, err := Run(context.Background(), Options{URL: "https://example.com", Transport: failingTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	if f := findingFor(t, r, "a2a.transport"); f.Status != "skip" {
		t.Errorf("unreachable HTTPS: %s", f.Status)
	}
}

type failingTransport struct{}

func (failingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, context.DeadlineExceeded
}

// TestStatementVerifiesOffline builds the attestation for a run and
// verifies it with passmcp-reporting's own parser: no network, no passmcp.
//
// AC: A2A-05
func TestStatementVerifiesOffline(t *testing.T) {
	a := jkuSigned(t, ecKey(t, "ES256", elliptic.P256(), crypto.SHA256, "card-2026"), false)
	r := run(t, a, Options{})
	st, err := Statement(r, "0.0.9")
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	got, err := sra2a.Parse(b)
	if err != nil {
		t.Fatalf("passmcp-reporting refused the statement: %v\n%s", err, b)
	}
	if !got.Covers(r.Target) {
		t.Errorf("the statement does not cover %s", r.Target)
	}
	v, ok := got.VerdictFor("a2a.card_signature")
	if !ok || v.Status != "pass" {
		t.Errorf("card_signature verdict %+v", v)
	}
	p := got.Predicate
	if p.Card == nil || !p.Card.Signed || p.Card.KeyID != "card-2026" || p.Card.Digest != r.CardDigest {
		t.Errorf("card %+v", p.Card)
	}
	if p.Target.Transport != "http" || p.Target.Agent == nil || p.Target.Agent.Name != "Recipe Agent" {
		t.Errorf("target %+v", p.Target)
	}
	if n := p.Counts.Pass + p.Counts.Fail + p.Counts.Warn + p.Counts.Skip + p.Counts.Info; n != len(r.Findings) {
		t.Errorf("counts %+v for %d findings", p.Counts, len(r.Findings))
	}
	if !slices.IsSortedFunc(p.Verdicts, func(x, y attestation.Verdict) int { return strings.Compare(x.ID, y.ID) }) {
		t.Error("verdicts are not sorted by id")
	}
	// A statement whose counts disagree with its verdicts does not verify.
	if _, err := sra2a.Parse(bytes.Replace(b, []byte(`"status": "pass"`), []byte(`"status": "fail"`), 1)); err == nil {
		t.Error("an altered statement verified")
	}
}

func TestStatementForAnUnreachableAgent(t *testing.T) {
	r, err := Run(context.Background(), Options{URL: "https://example.com", Transport: failingTransport{}})
	if err != nil {
		t.Fatal(err)
	}
	st, err := Statement(r, "0.0.9")
	if err != nil {
		t.Fatalf("an unreachable agent has no statement: %v", err)
	}
	if st.Predicate.Target.Transport != "https" || st.Predicate.Target.Agent != nil {
		t.Errorf("target %+v", st.Predicate.Target)
	}
}

func TestWriteText(t *testing.T) {
	a := &agent{auth: "serve", card: func(base string) map[string]any {
		c := validCard(base, "JSONRPC", "/rpc")
		for i := range 7 {
			c["x"+strings.Repeat("y", i)] = 1
		}
		return c
	}}
	a.start(t)
	r := run(t, a, Options{})
	var b bytes.Buffer
	WriteText(&b, r)
	out := b.String()
	for _, w := range []string{"passmcp a2a check " + a.base, "agent  Recipe Agent 1.0.0 (A2A 1.0)", "FAIL  a2a.card_schema", "evidence: req#1", "fix: ", "schema errors (7):", "info  a2a.transport"} {
		if !strings.Contains(out, w) {
			t.Errorf("text lacks %q:\n%s", w, out)
		}
	}
	for st, want := range map[probe.Status]string{probe.Pass: "ok", probe.Warn: "warn", probe.Skip: "skip", probe.Info: "info"} {
		if mark(st) != want {
			t.Errorf("mark(%s) = %s", st, mark(st))
		}
	}
	if dash("") != "–" {
		t.Error("dash")
	}
}
