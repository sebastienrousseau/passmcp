// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// maxSignatures bounds how many signatures one card makes passmcp verify,
// and so how many key sets it makes passmcp fetch.
const maxSignatures = 5

// maxJWKSBytes bounds a fetched key set.
const maxJWKSBytes = 256 << 10

// sigOutcome is what verifying one signature produced.
type sigOutcome struct {
	kid      string
	alg      string
	keyFrom  string // the jku, or "the signature's own header"
	verified bool
	embedded bool // verified against a key carried in the header
	reason   string
}

// checkSignature is a2a.card_signature: a signed card must verify, over
// the JCS canonical form of the card with its signatures removed, against
// a key resolved from the source the signature declares (A2A v1.0 section
// 8.4.3). Signing is optional in A2A, so an unsigned card is observed, not
// failed.
func (s *session) checkSignature(ctx context.Context) probe.Finding {
	c := s.check("a2a.card_signature", "Agent Card signature verifies")
	if s.card == nil {
		return c.skip("the Agent Card could not be read, so there is no signature to check")
	}
	sigs, _ := s.card["signatures"].([]any)
	if len(sigs) == 0 {
		return c.ev(cardRequest).info("the Agent Card is not signed (signing is optional in A2A v1), so nothing binds it to its publisher")
	}
	s.res.Signed = true
	payload, err := SigningPayload(s.card)
	if err != nil {
		return c.ev(cardRequest).fail(probe.Major, "the card cannot be canonicalised for verification: "+err.Error(),
			"serve a card that is valid JSON with finite numbers, so RFC 8785 canonicalisation is defined")
	}
	var outs []sigOutcome
	for i, raw := range sigs {
		if i == maxSignatures {
			break
		}
		outs = append(outs, s.verifyOne(ctx, raw, payload))
	}
	return s.signatureVerdict(c, outs)
}

// signatureVerdict turns the outcomes into the finding: a signature that
// verifies against its declared key source passes; one that verifies only
// against a key embedded in its own header proves integrity and not
// origin, which is a warning; none verifying fails.
func (s *session) signatureVerdict(c *check, outs []sigOutcome) probe.Finding {
	c.ev(cardRequest)
	var embedded *sigOutcome
	for i := range outs {
		o := outs[i]
		if o.verified && !o.embedded {
			s.res.KeyID = o.kid
			return c.pass(fmt.Sprintf("signature by key %q (%s) verified against the key set at %s", truncate(o.kid, 80), o.alg, truncate(o.keyFrom, 200)))
		}
		if o.verified && embedded == nil {
			embedded = &outs[i]
		}
	}
	if embedded != nil {
		s.res.KeyID = embedded.kid
		return c.warn("the signature verifies only against a key carried in its own header, which shows the card was not altered after signing but not who signed it",
			"publish the signing key in a JWKS served over HTTPS from the agent's domain and name it with jku and kid in the protected header")
	}
	reasons := make([]string, len(outs))
	for i, o := range outs {
		reasons[i] = fmt.Sprintf("signature %d: %s", i+1, o.reason)
	}
	return c.fail(probe.Major, "no signature verifies: "+strings.Join(reasons, "; "),
		"sign the RFC 8785 canonical form of the card, with default values removed and the signatures member excluded, and publish the key at the jku the protected header names")
}

// verifyOne verifies one AgentCardSignature.
func (s *session) verifyOne(ctx context.Context, raw any, payload []byte) sigOutcome {
	m, _ := raw.(map[string]any)
	protected, _ := m["protected"].(string)
	signature, _ := m["signature"].(string)
	if protected == "" || signature == "" {
		return sigOutcome{reason: "the signature has no protected header or no signature value"}
	}
	h, err := ParseHeader(protected)
	if err != nil {
		return sigOutcome{reason: err.Error()}
	}
	out := sigOutcome{kid: h.Kid, alg: truncate(h.Alg, 20)}
	key, from, embedded, err := s.resolveKey(ctx, h)
	if err != nil {
		out.reason = "its key cannot be resolved: " + err.Error()
		return out
	}
	out.keyFrom, out.embedded = from, embedded
	if err := Verify(protected, signature, payload, key); err != nil {
		out.reason = err.Error() + " over the card's JCS canonical form"
		return out
	}
	out.verified = true
	return out
}

// resolveKey finds the verifying key from the source the protected header
// declares: the JWKS at jku, or a key embedded in the header. The
// unprotected header is not consulted; nothing in it is signed.
func (s *session) resolveKey(ctx context.Context, h Header) (JWK, string, bool, error) {
	if h.Jku != "" {
		key, err := s.keyFromJKU(ctx, h.Jku, h.Kid)
		return key, h.Jku, false, err
	}
	if h.Jwk != nil {
		return *h.Jwk, "the signature's own header", true, nil
	}
	return JWK{}, "", false, fmt.Errorf("the protected header names neither a jku nor a jwk (kid %q), and passmcp keeps no trusted key store", truncate(h.Kid, 80))
}

// keyFromJKU fetches the key set a signature names and picks its key.
func (s *session) keyFromJKU(ctx context.Context, jku, kid string) (JWK, error) {
	if err := s.opts.Policy.Validate(ctx, "JWKS URL", jku); err != nil {
		return JWK{}, err
	}
	ctx = telemetry.WithPhase(ctx, Phase, "signing key set")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jku, nil)
	if err != nil {
		return JWK{}, err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := s.client.Do(req)
	if err != nil {
		return JWK{}, fmt.Errorf("fetching %s: %s", truncate(jku, 200), errString(err))
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return JWK{}, fmt.Errorf("%s answered HTTP %d", truncate(jku, 200), resp.StatusCode)
	}
	var set JWKS
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxJWKSBytes)).Decode(&set); err != nil {
		return JWK{}, fmt.Errorf("%s is not a JSON Web Key Set", truncate(jku, 200))
	}
	key, ok := set.Find(kid)
	if !ok {
		return JWK{}, fmt.Errorf("the key set at %s has no key %q", truncate(jku, 200), truncate(kid, 80))
	}
	return key, nil
}
