// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"crypto"
	"crypto/elliptic"
	"encoding/json"
	"strings"
	"testing"
)

func signed(t *testing.T, k testKey, payload []byte) (string, string) {
	t.Helper()
	hb, _ := json.Marshal(map[string]any{"alg": k.alg, "typ": "JOSE", "kid": k.jwk.Kid})
	protected := b64u(hb)
	return protected, b64u(k.sign([]byte(protected + "." + b64u(payload))))
}

// TestVerifyEveryAlgorithm signs and verifies with each algorithm passmcp
// accepts, and shows one altered byte of payload is refused.
//
// AC: A2A-02
func TestVerifyEveryAlgorithm(t *testing.T) {
	keys := []testKey{
		ecKey(t, "ES256", elliptic.P256(), crypto.SHA256, "p256"),
		ecKey(t, "ES384", elliptic.P384(), crypto.SHA384, "p384"),
		ecKey(t, "ES512", elliptic.P521(), crypto.SHA512, "p521"),
		edKey(t, "ed"),
		rsaKey(t, "RS256", "rs"),
		rsaKey(t, "PS256", "ps"),
	}
	payload := []byte(`{"name":"a"}`)
	for _, k := range keys {
		p, s := signed(t, k, payload)
		if err := Verify(p, s, payload, k.jwk); err != nil {
			t.Errorf("%s: a correct signature was refused: %v", k.alg, err)
		}
		if err := Verify(p, s, []byte(`{"name":"b"}`), k.jwk); err == nil {
			t.Errorf("%s: an altered payload verified", k.alg)
		}
	}
}

func TestVerifyRefusesMismatchesAndMalformedInput(t *testing.T) {
	es := ecKey(t, "ES256", elliptic.P256(), crypto.SHA256, "k")
	ed := edKey(t, "e")
	payload := []byte(`{}`)
	p, s := signed(t, es, payload)
	cases := map[string]error{
		"ed key for ES256":   Verify(p, s, payload, ed.jwk),
		"bad signature b64":  Verify(p, "!!", payload, es.jwk),
		"bad header b64":     Verify("!!", s, payload, es.jwk),
		"header not JSON":    Verify(b64u([]byte("nope")), s, payload, es.jwk),
		"header without alg": Verify(b64u([]byte(`{"kid":"k"}`)), s, payload, es.jwk),
		"unknown alg":        Verify(b64u([]byte(`{"alg":"HS256"}`)), s, payload, es.jwk),
		"short ES signature": Verify(p, b64u([]byte("short")), payload, es.jwk),
	}
	for name, err := range cases {
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	p384 := ecKey(t, "ES384", elliptic.P384(), crypto.SHA384, "k")
	if err := Verify(p, s, payload, p384.jwk); err == nil || !strings.Contains(err.Error(), "curve") {
		t.Errorf("a P-384 key verified an ES256 signature: %v", err)
	}
	pe, se := signed(t, ed, payload)
	if err := Verify(pe, se, payload, es.jwk); err == nil {
		t.Error("an EC key verified an EdDSA signature")
	}
	rs := rsaKey(t, "RS256", "r")
	pr, sr := signed(t, rs, payload)
	if err := Verify(pr, sr, payload, es.jwk); err == nil {
		t.Error("an EC key verified an RS256 signature")
	}
}

func TestJWKRefusesMalformedKeys(t *testing.T) {
	bad := []JWK{
		{Kty: "oct"},
		{Kty: "OKP", Crv: "X25519", X: b64u(make([]byte, 32))},
		{Kty: "OKP", Crv: "Ed25519", X: b64u(make([]byte, 5))},
		{Kty: "EC", Crv: "P-192", X: "a", Y: "b"},
		{Kty: "EC", Crv: "P-256", X: "!!", Y: "b"},
		{Kty: "EC", Crv: "P-256", X: b64u(make([]byte, 32)), Y: ""},
		{Kty: "EC", Crv: "P-256", X: b64u(make([]byte, 40)), Y: b64u(make([]byte, 32))},
		{Kty: "EC", Crv: "P-256", X: b64u(make([]byte, 32)), Y: b64u(make([]byte, 32))}, // not on the curve
		{Kty: "RSA", N: b64u(make([]byte, 64)), E: b64u([]byte{1, 0, 1})},               // too short
		{Kty: "RSA", N: "", E: "AQAB"},
		{Kty: "RSA", N: b64u(make([]byte, 256)), E: ""},
		{Kty: "RSA", N: b64u(make([]byte, 256)), E: b64u(make([]byte, 8))},
	}
	for i, k := range bad {
		if _, err := k.PublicKey(); err == nil {
			t.Errorf("key %d (%s) was accepted", i, k.Kty)
		}
	}
}

func TestJWKSFind(t *testing.T) {
	one := JWKS{Keys: []JWK{{Kid: "a"}}}
	if k, ok := one.Find(""); !ok || k.Kid != "a" {
		t.Error("a single-key set did not answer an empty kid")
	}
	two := JWKS{Keys: []JWK{{Kid: "a"}, {Kid: "b"}}}
	if _, ok := two.Find(""); ok {
		t.Error("an empty kid picked a key from an ambiguous set")
	}
	if k, ok := two.Find("b"); !ok || k.Kid != "b" {
		t.Error("kid b not found")
	}
	if _, ok := two.Find("c"); ok {
		t.Error("an absent kid was found")
	}
}
