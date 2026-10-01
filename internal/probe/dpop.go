// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"

	"satellion.com/passmcp/auth"
)

// Two things an enterprise buyer asks of a protected server, read from the
// metadata discovery already fetched. Neither is exercised: a DPoP-bound
// token needs a key passmcp would have to hold through the whole run, and
// MCP's profile for it (SEP-1932) is still a draft; an ID-JAG needs an
// enterprise identity provider passmcp is not. What the documents claim can
// still be checked against the RFCs that fix their meaning, and a claim
// that cannot be honoured is a finding without sending anything.

const (
	// idJAGProfile is the grant profile the Enterprise-Managed
	// Authorization extension advertises.
	idJAGProfile = "urn:ietf:params:oauth:grant-profile:id-jag"
	// jwtBearerGrant is the grant the ID-JAG is presented with at the token
	// endpoint (RFC 7523).
	jwtBearerGrant = "urn:ietf:params:oauth:grant-type:jwt-bearer" // #nosec G101 -- a registered grant type URN, not a secret
)

// weakDPoPAlgs returns the algorithms RFC 9449 §4.2 forbids for a proof:
// none, and symmetric MACs, whose key the verifier holds and so could use
// to forge a proof itself.
func weakDPoPAlgs(lists ...[]string) []string {
	var out []string
	seen := map[string]bool{}
	for _, l := range lists {
		for _, a := range l {
			if seen[a] {
				continue
			}
			if strings.EqualFold(a, "none") || strings.HasPrefix(strings.ToUpper(a), "HS") {
				seen[a] = true
				out = append(out, a)
			}
		}
	}
	return out
}

// checkDPoP reads what the resource, its authorization server and its 401
// challenge say about proof-of-possession, and whether they agree.
func checkDPoP(s *Session, prm *auth.ProtectedResourceMetadata, prmFrom string, md *auth.ServerMetadata, challenges []auth.Challenge, nonce string) Finding {
	c := s.check("discovery.dpop", "Proof-of-possession tokens (DPoP, RFC 9449)")
	c.ev(prmFrom, "issuer="+md.Issuer)
	schemes, offered := challengeSchemes(challenges)
	required := prm.DPoPBoundAccessTokensRequired
	if !required && !offered && len(prm.DPoPSigningAlgValuesSupported) == 0 && len(md.DPoPSigningAlgValuesSupported) == 0 {
		return c.info("not advertised: access tokens are bearer tokens, usable by whoever holds a copy")
	}
	if f, bad := dpopProblem(c, prm, md, required, offered, schemes); bad {
		return f
	}
	return c.info(dpopDetail(required, md.DPoPSigningAlgValuesSupported, nonce) + ". Not exercised: passmcp does not hold a bound token, and MCP's DPoP profile is still a draft")
}

// challengeSchemes lists the schemes the 401 challenges offered, and
// whether DPoP was among them.
func challengeSchemes(challenges []auth.Challenge) (schemes []string, offered bool) {
	for _, ch := range challenges {
		schemes = append(schemes, ch.Scheme)
		if strings.EqualFold(ch.Scheme, "DPoP") {
			offered = true
		}
	}
	return schemes, offered
}

// dpopProblem reports a DPoP advertisement that cannot be honoured as
// published; bad is false when there is none.
func dpopProblem(c *check, prm *auth.ProtectedResourceMetadata, md *auth.ServerMetadata, required, offered bool, schemes []string) (f Finding, bad bool) {
	if weak := weakDPoPAlgs(prm.DPoPSigningAlgValuesSupported, md.DPoPSigningAlgValuesSupported); len(weak) > 0 {
		return c.fail(Major, "DPoP proof algorithms include "+truncate(strings.Join(weak, ", "), 200),
			"RFC 9449 forbids none and symmetric MACs for proofs: a key the server can verify with is one it could sign with. List asymmetric algorithms such as ES256"), true
	}
	if required && len(md.DPoPSigningAlgValuesSupported) == 0 {
		return c.warn("the resource requires DPoP-bound tokens and its authorization server advertises no DPoP algorithms",
			"publish dpop_signing_alg_values_supported in the authorization server metadata so a client knows it can obtain a bound token"), true
	}
	if required && !offered {
		return c.warn("the resource requires DPoP-bound tokens but its 401 challenge offers only "+truncate(strings.Join(schemes, ", "), 200),
			"answer with a DPoP challenge (RFC 9449 §7.1) so a client learns the requirement from the refusal"), true
	}
	return Finding{}, false
}

// dpopDetail describes a consistent DPoP advertisement.
func dpopDetail(required bool, algs []string, nonce string) string {
	detail := "advertised"
	if required {
		detail = "required by the resource"
	}
	if len(algs) > 0 {
		detail += "; the authorization server accepts " + truncate(strings.Join(algs, ", "), 200)
	}
	if nonce != "" {
		detail += "; the challenge carries a DPoP-Nonce, so proofs cannot be made in advance"
	}
	return detail
}

// checkEnterpriseManaged reads whether the authorization server offers the
// Enterprise-Managed Authorization extension's grant, and whether it can.
func checkEnterpriseManaged(s *Session, md *auth.ServerMetadata) Finding {
	c := s.check("discovery.enterprise_managed", "Enterprise-Managed Authorization (ID-JAG)")
	c.ev("issuer=" + md.Issuer)
	if !contains(md.AuthorizationGrantProfilesSupported, idJAGProfile) {
		return c.info("not advertised: an enterprise identity provider cannot provision access to this server")
	}
	if len(md.GrantTypesSupported) > 0 && !contains(md.GrantTypesSupported, jwtBearerGrant) {
		return c.fail(Major, "the ID-JAG grant profile is advertised but grant_types_supported omits "+jwtBearerGrant,
			"the client presents the ID-JAG at the token endpoint as that grant type; list it, or stop advertising the profile")
	}
	return c.info("advertised. Not exercised: the exchange starts at an enterprise identity provider")
}
