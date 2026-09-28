// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"testing"
)

func TestDPoPIsReadFromTheMetadata(t *testing.T) {
	bearer := func(f *fakeServer) string {
		return fmt.Sprintf(`Bearer resource_metadata="%s/.well-known/oauth-protected-resource/mcp"`, f.srv.URL)
	}
	cases := []struct {
		name   string
		setup  func(*fakeServer)
		status Status
		want   string
	}{
		{"absent", func(*fakeServer) {}, Info, "not advertised"},
		{"symmetric", func(f *fakeServer) {
			f.q.asExtra = map[string]any{"dpop_signing_alg_values_supported": []string{"ES256", "HS256"}}
		}, Fail, "HS256"},
		{"none on the resource", func(f *fakeServer) {
			f.q.prmExtra = map[string]any{"dpop_signing_alg_values_supported": []string{"none"}}
		}, Fail, "none"},
		{"required without algorithms", func(f *fakeServer) {
			f.q.prmExtra = map[string]any{"dpop_bound_access_tokens_required": true}
		}, Warn, "advertises no DPoP algorithms"},
		{"required without a challenge", func(f *fakeServer) {
			f.q.prmExtra = map[string]any{"dpop_bound_access_tokens_required": true}
			f.q.asExtra = map[string]any{"dpop_signing_alg_values_supported": []string{"ES256"}}
		}, Warn, "offers only Bearer"},
		{"required and consistent", func(f *fakeServer) {
			f.q.prmExtra = map[string]any{"dpop_bound_access_tokens_required": true}
			f.q.asExtra = map[string]any{"dpop_signing_alg_values_supported": []string{"ES256", "EdDSA"}}
			f.q.challenge = bearer(f) + `, DPoP algs="ES256"`
			f.q.dpopNonce = "n-1"
		}, Info, "required by the resource; the authorization server accepts ES256, EdDSA; the challenge carries a DPoP-Nonce"},
		{"offered in the challenge only", func(f *fakeServer) {
			f.q.challenge = bearer(f) + `, DPoP algs="ES256"`
		}, Info, "advertised. Not exercised"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			tc.setup(f)
			_, fs := run(t, f, ccCreds(), nil)
			expect(t, fs, "discovery.dpop", tc.status, tc.want)
		})
	}
}

func TestEnterpriseManagedIsReadFromTheMetadata(t *testing.T) {
	cases := []struct {
		name   string
		extra  map[string]any
		status Status
		want   string
	}{
		{"absent", nil, Info, "not advertised"},
		{"profile without the grant", map[string]any{
			"authorization_grant_profiles_supported": []string{idJAGProfile},
		}, Fail, "omits " + jwtBearerGrant},
		{"profile with the grant", map[string]any{
			"authorization_grant_profiles_supported": []string{idJAGProfile},
			"grant_types_supported":                  []string{"authorization_code", jwtBearerGrant},
		}, Info, "advertised. Not exercised"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFakeServer(t)
			f.q.asExtra = tc.extra
			_, fs := run(t, f, ccCreds(), nil)
			expect(t, fs, "discovery.enterprise_managed", tc.status, tc.want)
		})
	}
}
