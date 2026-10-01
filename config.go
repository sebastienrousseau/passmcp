// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/transport"
)

// AuthMode selects how the client authorizes.
type AuthMode string

const (
	// AuthNone connects without credentials and fails on a 401.
	AuthNone AuthMode = "none"
	// AuthBearer sends a pre-issued token handed to the operator out of
	// band. No discovery or token exchange happens.
	AuthBearer AuthMode = "bearer"
	// AuthClientCredentials is the B2B flow: a confidential client
	// exchanges its own credentials for a token.
	AuthClientCredentials AuthMode = "client_credentials"
	// AuthAuthorizationCode is the B2C flow: an end user consents in a
	// browser and the client redeems the code with PKCE.
	AuthAuthorizationCode AuthMode = "authorization_code"
)

// Overrides pins authorization server endpoints when the server does not
// publish discovery metadata. Any field left empty is discovered.
type Overrides struct {
	AuthorizationURL string
	TokenURL         string
	Resource         string
}

// AuthConfig configures how the client authorizes.
type AuthConfig struct {
	Mode AuthMode
	// Token is the pre-issued bearer token for AuthBearer.
	Token string
	// Registration controls how a client identity is obtained.
	Registration auth.RegistrationOptions
	// RedirectURI is required for AuthAuthorizationCode.
	RedirectURI string
	// Scope requested on the first token request. When empty, the scope
	// from the WWW-Authenticate challenge (or PRM scopes_supported) is used.
	Scope string
	// Extra parameters sent on token requests (client credentials) or the
	// authorization request (authorization code). Use it for server
	// extensions such as a tenant profile identifier.
	Extra url.Values
	// TokenAuthMethod overrides the token endpoint auth method.
	TokenAuthMethod string
	// Overrides bypass discovery for the endpoints given.
	Overrides Overrides
	// StepUp, when set, is consulted on insufficient_scope; defaults to
	// re-requesting the token with the required scope.
	StepUp auth.StepUpFunc
}

// Config configures a Client.
type Config struct {
	// Endpoint is the MCP server URL (the Streamable HTTP endpoint).
	Endpoint string
	// HTTPClient supplies the base transport and timeouts. Its Transport
	// is wrapped with tracing, fixed headers and token handling.
	HTTPClient *http.Client
	// Timeout is the idle bound on requests when HTTPClient sets no
	// Timeout and the context no deadline (see DefaultTimeout). Zero
	// means DefaultTimeout; negative means no bound.
	Timeout time.Duration
	// Headers are sent verbatim on every request to the MCP server and, once
	// discovery has validated it, the authorization server (API keys, tenant
	// selectors, basic auth). They are never sent to an origin neither the
	// operator nor a validated discovery document named.
	Headers    map[string]string
	ClientInfo Implementation
	Auth       AuthConfig
	// URLPolicy governs which discovered URLs may be fetched or credentialed.
	// The zero value is strict: https only, public hosts only.
	URLPolicy auth.URLPolicy
	// AllowResourceMismatch permits a protected-resource metadata document
	// whose "resource" does not match the endpoint. RFC 9728 requires the
	// client to check this binding; skipping it invites a token mix-up.
	AllowResourceMismatch bool

	// Stdio, when set, runs the server as a child process and speaks to it
	// over its pipes instead of over HTTP. Endpoint must be empty.
	//
	// A stdio server is a program the operator names, so there is no URL to
	// authorize against and no discovery to perform: the trust decision was
	// made when they chose what to run. The authorization phases report
	// that rather than pretending to check it.
	Stdio *StdioConfig
}

// StdioConfig describes a server to run as a child process.
type StdioConfig struct {
	// Command is the program and Args its arguments, used as given. This
	// is not a shell: nothing is expanded, split or quoted.
	Command string
	Args    []string
	// Dir is the working directory; empty means the caller's.
	Dir string
	// Env replaces the child's environment entirely. Nil does NOT mean the
	// caller's — see transport.StdioConfig, which this becomes.
	Env []string
	// PassEnv names variables to forward from the caller's environment, for
	// a server that legitimately needs one.
	PassEnv []string
	// Inject are KEY=VALUE pairs passmcp adds about itself, after Env and
	// PassEnv and overriding either. It carries the proxy settings the
	// egress witness needs the child to honour; it is not a second way to
	// pass the caller's environment through.
	Inject []string
	// Observe, when set, is called after every exchange. It is how a
	// diagnostic records a pipe the way it records HTTP traffic, so a
	// finding over stdio can cite the message that produced it.
	Observe func(ctx context.Context, m transport.StdioMessage)
}

// prepareHTTPConfig validates an HTTP client's configuration and fills its
// defaults: no auth mode means none, and no client identity means passmcp's.
func prepareHTTPConfig(cfg *Config) error {
	if cfg.Endpoint == "" {
		return errors.New("passmcp: Endpoint is required")
	}
	if _, err := auth.CanonicalResource(cfg.Endpoint); err != nil {
		return err
	}
	if cfg.Auth.Mode == "" {
		cfg.Auth.Mode = AuthNone
	}
	if err := validateAuthConfig(cfg.Auth); err != nil {
		return err
	}
	if cfg.ClientInfo.Name == "" {
		cfg.ClientInfo = Implementation{Name: "passmcp", Version: DefaultClientVersion}
	}
	return nil
}

// validateAuthConfig checks the auth mode is known and has what it needs.
func validateAuthConfig(a AuthConfig) error {
	switch a.Mode {
	case AuthNone, AuthBearer, AuthClientCredentials, AuthAuthorizationCode:
	default:
		return fmt.Errorf("passmcp: unknown auth mode %q", a.Mode)
	}
	if a.Mode == AuthAuthorizationCode && a.RedirectURI == "" {
		return errors.New("passmcp: RedirectURI is required for authorization_code")
	}
	if a.Mode == AuthBearer && a.Token == "" {
		return errors.New("passmcp: Token is required for bearer")
	}
	return nil
}
