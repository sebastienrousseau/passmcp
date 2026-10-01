// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/trace"
	"satellion.com/passmcp/transport"
)

// ErrResourceMismatch reports a protected-resource metadata document whose
// "resource" does not identify the endpoint it was fetched for. RFC 9728
// requires the client to verify this binding: without it, a resource can
// hand out metadata for somebody else's API and collect tokens minted for
// it.
var ErrResourceMismatch = errors.New("passmcp: protected resource metadata does not identify this endpoint")

func (c *Client) checkResourceBinding(prm *auth.ProtectedResourceMetadata) error {
	if c.cfg.AllowResourceMismatch || prm.Resource == "" {
		return nil
	}
	canon, err := auth.CanonicalResource(c.cfg.Endpoint)
	if err != nil {
		return err
	}
	got, err := auth.CanonicalResource(prm.Resource)
	if err != nil {
		return fmt.Errorf("%w: resource %q is not an absolute URL", ErrResourceMismatch, prm.Resource)
	}
	if strings.TrimSuffix(got, "/") != strings.TrimSuffix(canon, "/") {
		return fmt.Errorf("%w: it claims %q but this endpoint is %q", ErrResourceMismatch, got, canon)
	}
	return nil
}

// Register obtains a client identity for the discovered server and records
// it on d.
func (c *Client) Register(ctx context.Context, d *Discovery) (*auth.Registration, error) {
	reg, err := c.reg.Register(ctx, d.Server, c.registrationOptions())
	if err != nil {
		return nil, err
	}
	d.Registration = reg
	return reg, nil
}

// ClientCredentialsSource builds the B2B token source from a completed
// discovery. It does not fetch a token until first use.
func (c *Client) ClientCredentialsSource(d *Discovery) (*auth.ClientCredentialsSource, error) {
	if d.Registration == nil {
		return nil, errors.New("passmcp: Register before building a token source")
	}
	if len(d.Server.GrantTypesSupported) > 0 && !slices.Contains(d.Server.GrantTypesSupported, "client_credentials") {
		return nil, fmt.Errorf("passmcp: authorization server %s does not advertise client_credentials", d.Server.Issuer)
	}
	return &auth.ClientCredentialsSource{
		HTTP: c.http, Endpoint: d.Endpoint(c.cfg.Auth.TokenAuthMethod),
		Creds:    auth.Credentials{ClientID: d.Registration.ClientID, ClientSecret: d.Registration.ClientSecret},
		Resource: d.Resource, Scope: d.Scope, Extra: c.cfg.Auth.Extra,
	}, nil
}

// StartAuthorization begins the authorization-code flow and returns the URL
// the user must visit plus the state to verify on redirect.
func (c *Client) StartAuthorization(d *Discovery) (string, string, error) {
	if d.Registration == nil {
		return "", "", errors.New("passmcp: Register before starting authorization")
	}
	if len(d.Server.CodeChallengeMethodsSupported) > 0 && !slices.Contains(d.Server.CodeChallengeMethodsSupported, "S256") {
		return "", "", fmt.Errorf("passmcp: authorization server %s does not support PKCE S256", d.Server.Issuer)
	}
	flow := &auth.AuthorizationCodeFlow{
		HTTP: c.http, Endpoint: d.Endpoint(c.cfg.Auth.TokenAuthMethod),
		Creds:    auth.Credentials{ClientID: d.Registration.ClientID, ClientSecret: d.Registration.ClientSecret},
		Resource: d.Resource, RedirectURI: c.cfg.Auth.RedirectURI, Scope: d.Scope, Extra: c.cfg.Auth.Extra,
	}
	u, err := flow.Start()
	if err != nil {
		return "", "", err
	}
	c.mu.Lock()
	c.pending = flow
	c.mu.Unlock()
	return u, flow.State(), nil
}

// CompleteAuthorization finishes the authorization-code flow with the code
// and state received on the redirect URI, then runs Initialize.
//
// It is shorthand for CompleteAuthorizationFrom with no issuer, and is kept
// for callers whose redirect handler does not surface the iss parameter.
func (c *Client) CompleteAuthorization(ctx context.Context, code, state string) (*ConnectResult, error) {
	return c.CompleteAuthorizationFrom(ctx, code, state, "")
}

// CompleteAuthorizationFrom finishes the authorization-code flow with the
// code, state and iss received on the redirect URI, then runs Initialize.
//
// iss is the RFC 9207 issuer identifier. When the authorization server
// advertised authorization_response_iss_parameter_supported, or simply sent
// one, it must match the issuer the code was requested from: that is what
// stops a mix-up attack where a malicious authorization server relays a
// code minted by an honest one.
func (c *Client) CompleteAuthorizationFrom(ctx context.Context, code, state, iss string) (*ConnectResult, error) {
	ctx = trace.Ensure(ctx)
	c.mu.Lock()
	flow := c.pending
	last := c.last
	c.mu.Unlock()
	if flow == nil {
		return nil, errors.New("passmcp: no authorization in progress; call Connect first")
	}
	if err := c.checkIssuer(last, iss); err != nil {
		return nil, err
	}
	src, err := flow.Complete(ctx, code, state)
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	c.pending = nil
	c.mu.Unlock()
	c.atr.SetSource(src)
	res, err := c.Initialize(ctx)
	if err != nil {
		return nil, fmt.Errorf("passmcp: initialize after authorization: %w", err)
	}
	out := &ConnectResult{Status: StatusConnected, Initialize: res}
	if last != nil {
		out.Discovery = last.Discovery
	}
	c.setLast(out)
	return out, nil
}

// ErrIssuerMismatch reports an authorization response whose iss parameter
// names a different authorization server than the one the request went to.
var ErrIssuerMismatch = errors.New("passmcp: authorization response came from the wrong issuer")

func (c *Client) checkIssuer(last *ConnectResult, iss string) error {
	if last == nil || last.Discovery == nil || last.Discovery.Server == nil {
		return nil
	}
	want := last.Discovery.Server.Issuer
	switch {
	case want == "":
		return nil
	case iss == "":
		if last.Discovery.Server.AuthorizationResponseIssParameterSupported {
			return fmt.Errorf("%w: %s advertises RFC 9207 but the redirect carried no iss", ErrIssuerMismatch, want)
		}
		return nil
	case strings.TrimSuffix(iss, "/") != strings.TrimSuffix(want, "/"):
		return fmt.Errorf("%w: redirect says %q, the code was requested from %q", ErrIssuerMismatch, iss, want)
	}
	return nil
}

// Resume connects using a previously obtained token source (for example a
// stored refresh token) without re-running discovery.
func (c *Client) Resume(ctx context.Context, src auth.TokenSource) (*ConnectResult, error) {
	c.atr.SetSource(src)
	return c.Connect(ctx)
}

func (c *Client) stepUp(ctx context.Context, required string) (auth.TokenSource, error) {
	if c.cfg.Auth.StepUp != nil {
		return c.cfg.Auth.StepUp(ctx, required)
	}
	src := c.atr.Source()
	if src == nil {
		return nil, errors.New("passmcp: insufficient_scope with no token source")
	}
	return src.WithScope(required), nil
}

func (c *Client) scope(challenge auth.Challenge, prm *auth.ProtectedResourceMetadata) string {
	if c.cfg.Auth.Scope != "" {
		return c.cfg.Auth.Scope
	}
	if s := challenge.Params["scope"]; s != "" {
		return s
	}
	if prm != nil && len(prm.ScopesSupported) > 0 {
		return strings.Join(prm.ScopesSupported, " ")
	}
	return ""
}

// Unauthorized extracts the Bearer challenge from a 401 transport error.
func Unauthorized(err error) (auth.Challenge, bool) {
	var he *transport.HTTPStatusError
	if !errors.As(err, &he) || he.StatusCode != http.StatusUnauthorized {
		return auth.Challenge{}, false
	}
	ch, ok := auth.FindBearer(auth.ParseWWWAuthenticate(he.Header.Get("WWW-Authenticate")))
	if !ok {
		// A 401 with no usable challenge still means "authorize"; the
		// well-known fallback handles discovery.
		return auth.Challenge{Scheme: "Bearer", Params: map[string]string{}}, true
	}
	return ch, true
}
