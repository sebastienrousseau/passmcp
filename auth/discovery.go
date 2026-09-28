// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// ProtectedResourceMetadata is the RFC 9728 document served by the MCP
// server (the resource) describing which authorization servers protect it.
type ProtectedResourceMetadata struct {
	Resource               string   `json:"resource"`
	AuthorizationServers   []string `json:"authorization_servers"`
	ScopesSupported        []string `json:"scopes_supported,omitempty"`
	BearerMethodsSupported []string `json:"bearer_methods_supported,omitempty"`
	ResourceName           string   `json:"resource_name,omitempty"`
	// DPoPSigningAlgValuesSupported and DPoPBoundAccessTokensRequired are
	// RFC 9728's DPoP fields: the proof algorithms the resource accepts,
	// and whether it refuses a token that is not bound to a key (RFC 9449).
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
	DPoPBoundAccessTokensRequired bool     `json:"dpop_bound_access_tokens_required,omitempty"`
}

// ServerMetadata is the RFC 8414 / OpenID Connect discovery document.
type ServerMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	GrantTypesSupported               []string `json:"grant_types_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	// ClientIDMetadataDocumentSupported advertises support for Client ID
	// Metadata Documents, where the client_id is an HTTPS URL to a JSON
	// document describing the client.
	ClientIDMetadataDocumentSupported bool `json:"client_id_metadata_document_supported,omitempty"`
	// AuthorizationResponseIssParameterSupported advertises RFC 9207: the
	// authorization response carries an iss the client must verify.
	AuthorizationResponseIssParameterSupported bool `json:"authorization_response_iss_parameter_supported,omitempty"`
	// DPoPSigningAlgValuesSupported lists the proof algorithms the token
	// endpoint accepts (RFC 9449 §5.1).
	DPoPSigningAlgValuesSupported []string `json:"dpop_signing_alg_values_supported,omitempty"`
	// AuthorizationGrantProfilesSupported names grant profiles, such as the
	// Identity Assertion JWT Authorization Grant that MCP's
	// Enterprise-Managed Authorization extension uses.
	AuthorizationGrantProfilesSupported []string `json:"authorization_grant_profiles_supported,omitempty"`
}

// ErrNoAuthorizationServers is returned when the PRM lists no servers.
var ErrNoAuthorizationServers = errors.New("auth: protected resource metadata lists no authorization_servers")

// Discoverer fetches OAuth metadata documents.
type Discoverer struct {
	Client *http.Client
	// Policy validates every URL taken from a remote document before it is
	// fetched. The zero value is the strict policy.
	Policy URLPolicy
}

func (d *Discoverer) httpClient() *http.Client {
	if d.Client == nil {
		return http.DefaultClient
	}
	return d.Client
}

// PRMCandidates returns, in priority order, the URLs at which the
// protected resource metadata for resourceURL should be looked up when the
// WWW-Authenticate challenge carries no resource_metadata hint: first the
// path-aware well-known location, then the origin root.
func PRMCandidates(resourceURL string) ([]string, error) {
	u, err := url.Parse(resourceURL)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host
	const wk = "/.well-known/oauth-protected-resource"
	path := strings.TrimSuffix(u.Path, "/")
	var out []string
	if path != "" {
		out = append(out, origin+wk+path)
	}
	out = append(out, origin+wk)
	return out, nil
}

// DiscoverPRM resolves the protected resource metadata for resourceURL.
// hint, when non-empty, is the resource_metadata value from the challenge
// and is tried first.
func (d *Discoverer) DiscoverPRM(ctx context.Context, resourceURL, hint string) (*ProtectedResourceMetadata, string, error) {
	var candidates []string
	var errs []error
	if hint != "" {
		// The hint comes from a WWW-Authenticate header, so it is chosen by
		// whoever answered the request. Validate before fetching.
		if err := d.Policy.Validate(ctx, "resource_metadata hint", hint); err != nil {
			errs = append(errs, err)
		} else {
			candidates = append(candidates, hint)
		}
	}
	fallback, err := PRMCandidates(resourceURL)
	if err != nil {
		return nil, "", fmt.Errorf("auth: invalid resource url: %w", err)
	}
	candidates = append(candidates, fallback...)

	for _, c := range candidates {
		var prm ProtectedResourceMetadata
		if err := d.getJSON(ctx, c, &prm); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c, err))
			continue
		}
		if len(prm.AuthorizationServers) == 0 {
			return nil, c, ErrNoAuthorizationServers
		}
		return &prm, c, nil
	}
	return nil, "", fmt.Errorf("auth: protected resource metadata not found: %w", errors.Join(errs...))
}

// ASMetadataCandidates returns the RFC 8414 and OIDC discovery URLs for an
// issuer, path-aware forms first as the MCP spec requires.
func ASMetadataCandidates(issuer string) ([]string, error) {
	u, err := url.Parse(issuer)
	if err != nil {
		return nil, err
	}
	origin := u.Scheme + "://" + u.Host
	path := strings.TrimSuffix(u.Path, "/")
	var out []string
	if path != "" {
		out = append(out,
			origin+"/.well-known/oauth-authorization-server"+path,
			origin+"/.well-known/openid-configuration"+path,
			origin+path+"/.well-known/openid-configuration",
		)
	} else {
		out = append(out,
			origin+"/.well-known/oauth-authorization-server",
			origin+"/.well-known/openid-configuration",
		)
	}
	return out, nil
}

// DiscoverServer fetches the authorization server metadata for issuer. The
// issuer and every endpoint in the document it returns are checked against
// the policy, so a resource cannot steer the client at a plaintext or
// internal host.
func (d *Discoverer) DiscoverServer(ctx context.Context, issuer string) (*ServerMetadata, error) {
	if err := d.Policy.Validate(ctx, "authorization server", issuer); err != nil {
		return nil, err
	}
	candidates, err := ASMetadataCandidates(issuer)
	if err != nil {
		return nil, fmt.Errorf("auth: invalid issuer: %w", err)
	}
	var errs []error
	for _, c := range candidates {
		var md ServerMetadata
		if err := d.getJSON(ctx, c, &md); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", c, err))
			continue
		}
		if md.TokenEndpoint == "" {
			errs = append(errs, fmt.Errorf("%s: missing token_endpoint", c))
			continue
		}
		if err := d.ValidateMetadata(ctx, &md); err != nil {
			return nil, err
		}
		return &md, nil
	}
	return nil, fmt.Errorf("auth: authorization server metadata not found: %w", errors.Join(errs...))
}

// ValidateMetadata checks every endpoint an authorization server published.
// It is exported so a caller that assembled metadata another way (an
// override, a cached document) can apply the same gate.
func (d *Discoverer) ValidateMetadata(ctx context.Context, md *ServerMetadata) error {
	for _, f := range []struct{ kind, raw string }{
		{"token endpoint", md.TokenEndpoint},
		{"authorization endpoint", md.AuthorizationEndpoint},
		{"registration endpoint", md.RegistrationEndpoint},
	} {
		if f.raw == "" {
			continue
		}
		if err := d.Policy.Validate(ctx, f.kind, f.raw); err != nil {
			return err
		}
	}
	return nil
}

func (d *Discoverer) getJSON(ctx context.Context, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	resp, err := d.httpClient().Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("http %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// CanonicalResource returns the RFC 8707 resource indicator for an MCP
// endpoint: scheme and host lower-cased, no fragment, no trailing slash on
// an empty path.
func CanonicalResource(endpoint string) (string, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return "", err
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("auth: resource %q must be absolute", endpoint)
	}
	u.Scheme = strings.ToLower(u.Scheme)
	u.Host = strings.ToLower(u.Host)
	u.Fragment = ""
	u.RawFragment = ""
	if u.Path == "/" {
		u.Path = ""
	}
	return u.String(), nil
}
