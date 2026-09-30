// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"errors"
	"strings"

	"satellion.com/passmcp/auth"
)

// metadataFailure explains why no authorization server produced usable
// metadata: the detail, the advice and the reason the run is blocked. A
// refusal, a document that names another issuer and a document that is
// missing are three different problems, and the operator needs to be told
// which one happened.
func metadataFailure(errs []error) (detail, advice, blocked string) {
	if pe := firstPolicyError(errs); pe != nil {
		return pe.Error(),
			"the server named an authorization server passmcp will not talk to; fix the metadata, or re-run with --insecure-allow-http-auth / --insecure-allow-private-hosts if you trust this endpoint",
			"the authorization server this resource names was refused as unsafe"
	}
	var mm *auth.IssuerMismatchError
	for _, err := range errs {
		if errors.As(err, &mm) {
			return mm.Error(),
				"serve metadata whose issuer is exactly the URL listed in authorization_servers (RFC 8414 §3.3), or list the issuer the metadata names",
				"the authorization server metadata names another issuer"
		}
	}
	msgs := make([]string, len(errs))
	for i, err := range errs {
		msgs[i] = err.Error()
	}
	return "no authorization server published metadata: " + strings.Join(msgs, "; "),
		"serve /.well-known/oauth-authorization-server or /.well-known/openid-configuration",
		"authorization server metadata is not discoverable"
}
