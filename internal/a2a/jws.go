// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

// Header is the part of a JWS protected header an Agent Card signature
// uses (A2A v1.0 section 8.4.2).
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
	// Jku is the JWKS URL the verifying key is published at.
	Jku string `json:"jku,omitempty"`
	// Jwk is a key carried in the header itself (RFC 7515 section 4.1.3).
	// It proves the card was not altered after signing, not who signed it.
	Jwk *JWK `json:"jwk,omitempty"`
}

// JWK is a public JSON Web Key (RFC 7517) of the kinds A2A signatures use.
type JWK struct {
	Kty string `json:"kty"`
	Kid string `json:"kid,omitempty"`
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	N   string `json:"n,omitempty"`
	E   string `json:"e,omitempty"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// ParseHeader decodes a base64url protected header.
func ParseHeader(protected string) (Header, error) {
	raw, err := base64.RawURLEncoding.DecodeString(protected)
	if err != nil {
		return Header{}, fmt.Errorf("the protected header is not base64url: %w", err)
	}
	var h Header
	if err := json.Unmarshal(raw, &h); err != nil {
		return Header{}, fmt.Errorf("the protected header is not a JSON object: %w", err)
	}
	if h.Alg == "" {
		return Header{}, errors.New("the protected header names no alg")
	}
	return h, nil
}

// Find returns the key in the set with the given id. With no id, a set of
// exactly one key answers; anything else is ambiguous.
func (s JWKS) Find(kid string) (JWK, bool) {
	if kid == "" {
		if len(s.Keys) == 1 {
			return s.Keys[0], true
		}
		return JWK{}, false
	}
	for _, k := range s.Keys {
		if k.Kid == kid {
			return k, true
		}
	}
	return JWK{}, false
}

// Verify checks a JWS signature over payload with the protected header as
// signed. The signing input is BASE64URL(header) '.' BASE64URL(payload)
// (RFC 7515 section 5.2); the key must suit the header's algorithm.
func Verify(protected, signature string, payload []byte, key JWK) error {
	h, err := ParseHeader(protected)
	if err != nil {
		return err
	}
	sig, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return fmt.Errorf("the signature is not base64url: %w", err)
	}
	input := []byte(protected + "." + base64.RawURLEncoding.EncodeToString(payload))
	pub, err := key.PublicKey()
	if err != nil {
		return err
	}
	return verifyAlg(h.Alg, pub, input, sig)
}

func verifyAlg(alg string, pub crypto.PublicKey, input, sig []byte) error {
	switch alg {
	case "EdDSA":
		k, ok := pub.(ed25519.PublicKey)
		if !ok {
			return errors.New("alg EdDSA needs an Ed25519 (OKP) key")
		}
		if !ed25519.Verify(k, input, sig) {
			return errors.New("the signature does not verify")
		}
		return nil
	case "ES256", "ES384", "ES512":
		return verifyECDSA(alg, pub, input, sig)
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512":
		return verifyRSA(alg, pub, input, sig)
	}
	return fmt.Errorf("alg %q is not one passmcp verifies (EdDSA, ES256/384/512, RS256/384/512, PS256/384/512)", truncate(alg, 20))
}

func digestFor(alg string) (crypto.Hash, hash.Hash) {
	switch alg[2:] {
	case "384":
		return crypto.SHA384, sha512.New384()
	case "512":
		return crypto.SHA512, sha512.New()
	}
	return crypto.SHA256, sha256.New()
}

// verifyECDSA checks a JWS ECDSA signature, which is R and S as fixed-size
// big-endian integers concatenated (RFC 7518 section 3.4), not ASN.1.
func verifyECDSA(alg string, pub crypto.PublicKey, input, sig []byte) error {
	k, ok := pub.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("alg %s needs an EC key", alg)
	}
	want := map[string]elliptic.Curve{"ES256": elliptic.P256(), "ES384": elliptic.P384(), "ES512": elliptic.P521()}[alg]
	if k.Curve != want {
		return fmt.Errorf("alg %s needs curve %s, the key is %s", alg, want.Params().Name, k.Curve.Params().Name)
	}
	size := (k.Curve.Params().BitSize + 7) / 8
	if len(sig) != 2*size {
		return fmt.Errorf("an %s signature is %d bytes, this one is %d", alg, 2*size, len(sig))
	}
	_, h := digestFor(alg)
	h.Write(input)
	r, s := new(big.Int).SetBytes(sig[:size]), new(big.Int).SetBytes(sig[size:])
	if !ecdsa.Verify(k, h.Sum(nil), r, s) {
		return errors.New("the signature does not verify")
	}
	return nil
}

func verifyRSA(alg string, pub crypto.PublicKey, input, sig []byte) error {
	k, ok := pub.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("alg %s needs an RSA key", alg)
	}
	id, h := digestFor(alg)
	h.Write(input)
	sum := h.Sum(nil)
	var err error
	if alg[0] == 'P' {
		err = rsa.VerifyPSS(k, id, sum, sig, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
	} else {
		err = rsa.VerifyPKCS1v15(k, id, sum, sig)
	}
	if err != nil {
		return errors.New("the signature does not verify")
	}
	return nil
}

// PublicKey decodes the key.
func (k JWK) PublicKey() (crypto.PublicKey, error) {
	switch k.Kty {
	case "EC":
		return k.ecKey()
	case "RSA":
		return k.rsaKey()
	case "OKP":
		if k.Crv != "Ed25519" {
			return nil, fmt.Errorf("OKP curve %q is not Ed25519", truncate(k.Crv, 20))
		}
		x, err := b64(k.X, "x")
		if err != nil || len(x) != ed25519.PublicKeySize {
			return nil, errors.New("the Ed25519 key's x is not 32 bytes of base64url")
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("key type %q is not EC, RSA or OKP", truncate(k.Kty, 20))
}

func (k JWK) ecKey() (crypto.PublicKey, error) {
	curve := map[string]elliptic.Curve{"P-256": elliptic.P256(), "P-384": elliptic.P384(), "P-521": elliptic.P521()}[k.Crv]
	if curve == nil {
		return nil, fmt.Errorf("EC curve %q is not P-256, P-384 or P-521", truncate(k.Crv, 20))
	}
	x, err := b64(k.X, "x")
	if err != nil {
		return nil, err
	}
	y, err := b64(k.Y, "y")
	if err != nil {
		return nil, err
	}
	size := (curve.Params().BitSize + 7) / 8
	if len(x) > size || len(y) > size {
		return nil, fmt.Errorf("the EC key's coordinates are longer than %s allows", k.Crv)
	}
	// SEC 1 uncompressed point: 0x04 || X || Y, each padded to the curve
	// size. Parsing it checks the point is on the curve, so a malformed key
	// is refused before it is used.
	point := make([]byte, 1+2*size)
	point[0] = 4
	copy(point[1+size-len(x):1+size], x)
	copy(point[1+2*size-len(y):], y)
	pub, err := ecdsa.ParseUncompressedPublicKey(curve, point)
	if err != nil {
		return nil, errors.New("the EC key is not a point on its curve")
	}
	return pub, nil
}

func (k JWK) rsaKey() (crypto.PublicKey, error) {
	n, err := b64(k.N, "n")
	if err != nil {
		return nil, err
	}
	e, err := b64(k.E, "e")
	if err != nil {
		return nil, err
	}
	if len(e) == 0 || len(e) > 4 {
		return nil, errors.New("the RSA exponent is not a small integer")
	}
	exp := int(new(big.Int).SetBytes(e).Int64())
	mod := new(big.Int).SetBytes(n)
	if mod.BitLen() < 2048 {
		return nil, fmt.Errorf("the RSA key is %d bits; fewer than 2048 is not accepted", mod.BitLen())
	}
	return &rsa.PublicKey{N: mod, E: exp}, nil
}

func b64(s, name string) ([]byte, error) {
	if s == "" {
		return nil, fmt.Errorf("the key has no %s", name)
	}
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("the key's %s is not base64url", name)
	}
	return b, nil
}
