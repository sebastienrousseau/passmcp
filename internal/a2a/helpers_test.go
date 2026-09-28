// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"satellion.com/passmcp/auth"
)

// validCard returns a minimal valid A2A v1 card whose interface lives at
// base + path.
func validCard(base, binding, path string) map[string]any {
	return map[string]any{
		"name":        "Recipe Agent",
		"description": "Helps with recipes.",
		"version":     "1.0.0",
		"supportedInterfaces": []any{
			map[string]any{"url": base + path, "protocolBinding": binding, "protocolVersion": "1.0"},
		},
		"capabilities":       map[string]any{"streaming": false},
		"defaultInputModes":  []any{"text/plain"},
		"defaultOutputModes": []any{"text/plain"},
		"skills": []any{
			map[string]any{"id": "find", "name": "Find a recipe", "description": "Finds one.", "tags": []any{"cooking"}},
		},
	}
}

// roundTrip turns a Go map into the map a JSON decode produces, so numbers
// and nesting match what the run sees on the wire.
func roundTrip(t *testing.T, v any) map[string]any {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	m, err := decode(b)
	if err != nil {
		t.Fatal(err)
	}
	return m.(map[string]any)
}

func b64u(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// testKey is a signing key and its public JWK.
type testKey struct {
	alg  string
	sign func(input []byte) []byte
	jwk  JWK
}

func ecKey(t *testing.T, alg string, curve elliptic.Curve, h crypto.Hash, kid string) testKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	size := (curve.Params().BitSize + 7) / 8
	pad := func(n *big.Int) []byte { b := n.Bytes(); return append(make([]byte, size-len(b)), b...) }
	pt, err := k.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	crv := map[int]string{256: "P-256", 384: "P-384", 521: "P-521"}[curve.Params().BitSize]
	return testKey{
		alg: alg,
		jwk: JWK{Kty: "EC", Kid: kid, Crv: crv, X: b64u(pt[1 : 1+size]), Y: b64u(pt[1+size:])},
		sign: func(input []byte) []byte {
			hh := h.New()
			hh.Write(input)
			r, s, err := ecdsa.Sign(rand.Reader, k, hh.Sum(nil))
			if err != nil {
				t.Fatal(err)
			}
			return append(pad(r), pad(s)...)
		},
	}
}

func edKey(t *testing.T, kid string) testKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{alg: "EdDSA", jwk: JWK{Kty: "OKP", Kid: kid, Crv: "Ed25519", X: b64u(pub)},
		sign: func(input []byte) []byte { return ed25519.Sign(priv, input) }}
}

func rsaKey(t *testing.T, alg, kid string) testKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return testKey{alg: alg, jwk: JWK{Kty: "RSA", Kid: kid, N: b64u(k.N.Bytes()), E: b64u(big.NewInt(int64(k.E)).Bytes())},
		sign: func(input []byte) []byte {
			sum := sha256.Sum256(input)
			var sig []byte
			var err error
			if alg[0] == 'P' {
				sig, err = rsa.SignPSS(rand.Reader, k, crypto.SHA256, sum[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
			} else {
				sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, sum[:])
			}
			if err != nil {
				t.Fatal(err)
			}
			return sig
		}}
}

// signCard appends a signature over the card's signing payload, with the
// given protected header.
func signCard(t *testing.T, card map[string]any, key testKey, header map[string]any) {
	t.Helper()
	payload, err := SigningPayload(roundTrip(t, card))
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := json.Marshal(header)
	protected := b64u(hb)
	sig := key.sign([]byte(protected + "." + b64u(payload)))
	sigs, _ := card["signatures"].([]any)
	card["signatures"] = append(sigs, map[string]any{"protected": protected, "signature": b64u(sig)})
}

// agent is a fake A2A agent: it serves a card at the well-known path, a
// key set at /jwks.json, and ListTasks on the JSON-RPC and HTTP+JSON
// interfaces, answering as auth says.
type agent struct {
	mu    sync.Mutex
	card  func(base string) map[string]any
	jwks  JWKS
	auth  string // "serve", "refuse" or "error"
	calls []string
	last  http.Header // the headers of the latest request
	srv   *httptest.Server
	base  string // the URL the run is given
}

func (a *agent) handler(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	a.calls = append(a.calls, r.Method+" "+r.URL.RequestURI())
	a.last = r.Header.Clone()
	a.mu.Unlock()
	switch {
	case r.URL.Path == WellKnownPath:
		_ = json.NewEncoder(w).Encode(a.card(a.base))
	case r.URL.Path == "/jwks.json":
		_ = json.NewEncoder(w).Encode(a.jwks)
	case r.URL.Path == "/rpc" || strings.HasSuffix(r.URL.Path, "/tasks"):
		a.answer(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (a *agent) answer(w http.ResponseWriter, r *http.Request) {
	switch {
	case a.auth == "refuse":
		w.WriteHeader(http.StatusUnauthorized)
	case a.auth == "error":
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"passmcp-a2a-1","error":{"code":-32601,"message":"no"}}`))
	case r.URL.Path == "/rpc":
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":"passmcp-a2a-1","result":{"tasks":[],"nextPageToken":"","pageSize":1,"totalSize":0}}`))
	default:
		_, _ = w.Write([]byte(`{"tasks":[],"nextPageToken":"","pageSize":1,"totalSize":0}`))
	}
}

// start serves the agent on loopback, reachable at its real address.
func (a *agent) start(t *testing.T) {
	t.Helper()
	a.srv = httptest.NewServer(http.HandlerFunc(a.handler))
	a.base = a.srv.URL
	t.Cleanup(a.srv.Close)
}

// startAs serves the agent at a public-looking name: every connection is
// dialled to the fake, whatever host the URL names. tlsOn serves HTTPS
// with a certificate valid for example.com.
func (a *agent) startAs(t *testing.T, scheme string) http.RoundTripper {
	t.Helper()
	if scheme == "https" {
		a.srv = httptest.NewTLSServer(http.HandlerFunc(a.handler))
	} else {
		a.srv = httptest.NewServer(http.HandlerFunc(a.handler))
	}
	t.Cleanup(a.srv.Close)
	a.base = scheme + "://example.com"
	addr := a.srv.Listener.Addr().String()
	tr := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, addr)
	}}
	if scheme == "https" {
		pool := x509.NewCertPool()
		pool.AddCert(a.srv.Certificate())
		tr.TLSClientConfig = &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}
	}
	return tr
}

// publicPolicy resolves every name to a public address, so the strict URL
// policy is exercised without depending on DNS.
func publicPolicy() auth.URLPolicy {
	return auth.URLPolicy{Resolver: func(context.Context, string) ([]net.IP, error) {
		return []net.IP{net.ParseIP("93.184.215.14")}, nil
	}}
}

func findingFor(t *testing.T, r *Result, id string) (f struct {
	Status, Severity, Detail string
	Evidence                 []string
}) {
	t.Helper()
	for _, x := range r.Findings {
		if x.ID == id {
			f.Status, f.Severity, f.Detail, f.Evidence = string(x.Status), string(x.Severity), x.Detail, x.Evidence
			return f
		}
	}
	t.Fatalf("no finding %s", id)
	return f
}
