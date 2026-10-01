// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package passmcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"

	"satellion.com/passmcp/auth"
	"satellion.com/passmcp/trace"
	"satellion.com/passmcp/transport"
)

// Status of a Connect call.
type Status string

const (
	// StatusConnected means initialize succeeded.
	StatusConnected Status = "connected"
	// StatusAuthorizationRequired means the user must visit AuthorizationURL
	// and the caller must then call CompleteAuthorization.
	StatusAuthorizationRequired Status = "authorization_required"
)

// Discovery is what the authorization step learned about the server.
type Discovery struct {
	Challenge auth.Challenge
	PRM       *auth.ProtectedResourceMetadata
	PRMSource string // URL the PRM was fetched from ("" when overridden)
	Server    *auth.ServerMetadata
	// Registration is nil until Register has run.
	Registration *auth.Registration
	Resource     string
	Scope        string
	Overridden   bool
}

// Endpoint returns the token-layer view of the discovery.
func (d *Discovery) Endpoint(authMethod string) auth.Endpoint {
	return auth.Endpoint{AuthorizationURL: d.Server.AuthorizationEndpoint, TokenURL: d.Server.TokenEndpoint, AuthMethod: authMethod}
}

// ConnectResult describes the outcome of Connect.
type ConnectResult struct {
	Status           Status
	AuthorizationURL string // set when Status == StatusAuthorizationRequired
	State            string // OAuth state to verify on the redirect
	Initialize       *InitializeResult
	Discovery        *Discovery // populated when an auth flow ran
}

// Client is an MCP client bound to one server.
type Client struct {
	cfg  Config
	tr   transport.Conn
	atr  *auth.Transport
	http *http.Client // for discovery / token calls: traced + headers, no bearer
	disc *auth.Discoverer
	reg  *auth.Registrar

	// allowed is the set of origins that may receive credentials: the MCP
	// endpoint, plus any authorization server that survived validation.
	allowed *auth.OriginSet

	mu         sync.Mutex
	init       *InitializeResult
	pending    *auth.AuthorizationCodeFlow
	last       *ConnectResult
	negotiated *Negotiation
}

// DefaultClientVersion is the version passmcp announces to a server when the
// caller sets no ClientInfo of its own.
//
// It is a fallback, not the build version: cmd sets the real one from the
// ldflags stamp. Under this project's convention every release increments
// by 0.0.1, so the fallback is the first version, never one passmcp has not
// reached.
const DefaultClientVersion = "0.0.1"

// New builds a Client.
//
// Over HTTP it contacts nothing. With Config.Stdio set it starts the
// server process, because a pipe cannot exist before the process on the
// other end of it does — so that client owns a child process from here,
// and the caller must Close it. Use NewStdio to supply a context.
func New(cfg Config) (*Client, error) {
	return build(context.Background(), cfg)
}

// NewStdio builds a Client that runs the server as a child process.
//
// It is New with a context, for the one configuration where New does
// something a context belongs on. The process is running when this
// returns; the caller must Close.
func NewStdio(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Stdio == nil {
		return nil, errors.New("passmcp: NewStdio needs Config.Stdio")
	}
	return build(ctx, cfg)
}

func build(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.Stdio != nil {
		if cfg.Endpoint != "" {
			return nil, errors.New("passmcp: set Endpoint or Stdio, not both")
		}
		if strings.TrimSpace(cfg.Stdio.Command) == "" {
			return nil, errors.New("passmcp: Stdio needs a Command")
		}
		return newStdioClient(ctx, cfg)
	}
	if err := prepareHTTPConfig(&cfg); err != nil {
		return nil, err
	}
	base, baseRT := baseHTTP(cfg)
	// Every credential this client holds is bound to this set. It starts as
	// the endpoint the operator named and grows only when discovery
	// produces an authorization server that passed URLPolicy.
	allowed, err := auth.NewOriginSet(cfg.Endpoint)
	if err != nil {
		return nil, err
	}

	var plainRT http.RoundTripper = trace.RoundTripper{Base: baseRT}
	if len(cfg.Headers) > 0 {
		plainRT = auth.NewHeaderTransport(plainRT, cfg.Headers, allowed)
	}
	plain := *base
	plain.Transport = plainRT
	plain.CheckRedirect = auth.CheckRedirect(allowed, base.CheckRedirect)

	atr := auth.NewTransport(plainRT, nil)
	atr.Allowed = allowed
	if cfg.Auth.Mode == AuthBearer {
		atr.SetSource(auth.StaticSource{AccessToken: cfg.Auth.Token})
	}
	authed := *base
	authed.Transport = atr
	authed.CheckRedirect = auth.CheckRedirect(allowed, base.CheckRedirect)

	c := &Client{
		cfg:     cfg,
		tr:      transport.New(cfg.Endpoint, &authed),
		atr:     atr,
		http:    &plain,
		disc:    &auth.Discoverer{Client: &plain, Policy: cfg.URLPolicy},
		reg:     &auth.Registrar{Client: &plain, Policy: cfg.URLPolicy},
		allowed: allowed,
	}
	atr.StepUp = c.stepUp
	return c, nil
}

// newStdioClient starts the server and builds a client around its pipes.
//
// Everything HTTP-shaped is still constructed, empty: an origin set that
// admits nothing, a token transport with no source, an http.Client that
// will never be asked for a request. That is deliberate. A nil atr or a
// nil allowed would turn every accessor on this type into a method that
// panics for one kind of client, and the crash would land in a caller who
// had no reason to know which kind they were holding.
func newStdioClient(ctx context.Context, cfg Config) (*Client, error) {
	if cfg.ClientInfo.Name == "" {
		cfg.ClientInfo = Implementation{Name: "passmcp", Version: DefaultClientVersion}
	}
	// A credential mode other than none is an operator error worth naming
	// rather than ignoring. There is no origin to send a bearer token to,
	// no metadata to discover, and no authorization server: a stdio server
	// inherits its trust from the fact that the operator chose to run it.
	// Silently dropping a --token they passed would be the worst of the
	// three possible behaviours.
	switch cfg.Auth.Mode {
	case "", AuthNone:
		cfg.Auth.Mode = AuthNone
	default:
		return nil, fmt.Errorf("passmcp: auth mode %q has no meaning over stdio: a child process has no origin to authorize against; pass what the server needs in its arguments or with --stdio-env", cfg.Auth.Mode)
	}

	st, err := transport.StartStdio(ctx, transport.StdioConfig{
		Command: cfg.Stdio.Command,
		Args:    cfg.Stdio.Args,
		Dir:     cfg.Stdio.Dir,
		Env:     cfg.Stdio.Env,
		PassEnv: cfg.Stdio.PassEnv,
		Inject:  cfg.Stdio.Inject,
		Observe: cfg.Stdio.Observe,
	})
	if err != nil {
		return nil, err
	}

	allowed, err := auth.NewOriginSet()
	if err != nil {
		return nil, err
	}
	atr := auth.NewTransport(trace.RoundTripper{Base: http.DefaultTransport}, nil)
	atr.Allowed = allowed
	empty := &http.Client{Transport: trace.RoundTripper{Base: http.DefaultTransport}}
	c := &Client{
		cfg:     cfg,
		tr:      st,
		atr:     atr,
		http:    empty,
		disc:    &auth.Discoverer{Client: empty, Policy: cfg.URLPolicy},
		reg:     &auth.Registrar{Client: empty, Policy: cfg.URLPolicy},
		allowed: allowed,
	}
	return c, nil
}

// Close releases what the client owns.
//
// Over HTTP there is nothing to release and this returns nil. Over stdio
// it ends the server process and waits for it — which is why it exists,
// and why every caller should defer it whether or not it knows which
// transport it got. A tool that leaves a server running has done harm no
// report undoes.
func (c *Client) Close() error {
	if st, ok := c.tr.(*transport.Stdio); ok {
		return st.Close()
	}
	return nil
}

// Stdio returns the child-process transport, and false over HTTP. It is
// the counterpart of HTTP, for the probes that need the server's stderr or
// its exit status.
func (c *Client) Stdio() (*transport.Stdio, bool) {
	st, ok := c.tr.(*transport.Stdio)
	return st, ok
}

// AllowedOrigins lists the origins this client may send credentials to.
func (c *Client) AllowedOrigins() []string { return c.allowed.Origins() }

// admit adds the origins of the authorization server endpoints to the
// credential allow-list. It runs only after URLPolicy accepted them.
func (c *Client) admit(md *auth.ServerMetadata) error {
	for _, raw := range []string{md.Issuer, md.TokenEndpoint, md.AuthorizationEndpoint, md.RegistrationEndpoint} {
		if raw == "" {
			continue
		}
		if err := c.allowed.Add(raw); err != nil {
			return err
		}
	}
	return nil
}

// Config returns the configuration the client was built with.
func (c *Client) Config() Config { return c.cfg }

// Transport exposes the Streamable HTTP transport.
//
// It keeps its concrete type and its name: this is a published API and a
// client over HTTP is what almost every caller has. A client that is not
// speaking HTTP returns nil, which is the case HTTP reports without the
// nil check.
func (c *Client) Transport() *transport.Streamable {
	s, _ := c.tr.(*transport.Streamable)
	return s
}

// Conn exposes the connection whatever it is — HTTP, or a child process
// over its pipes. Everything a diagnostic does other than the raw HTTP
// conformance probes goes through this.
func (c *Client) Conn() transport.Conn { return c.tr }

// HTTP returns the Streamable HTTP transport, and false when the client is
// not speaking HTTP.
//
// It exists for the conformance probes that send a malformed body or a
// bogus session header — things that are HTTP requests rather than protocol
// messages, and have no equivalent over a pipe. Asking by type keeps that
// asymmetry visible at the call site instead of hiding it behind a method
// one transport can only fail.
func (c *Client) HTTP() (*transport.Streamable, bool) {
	s, ok := c.tr.(*transport.Streamable)
	return s, ok
}

// HTTPClient returns the client used for discovery and token requests: it
// carries tracing and fixed headers but no bearer token.
func (c *Client) HTTPClient() *http.Client { return c.http }

// Discoverer exposes the metadata fetcher.
func (c *Client) Discoverer() *auth.Discoverer { return c.disc }

// ServerInfo returns the initialize result, or nil before Connect.
func (c *Client) ServerInfo() *InitializeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.init
}

// LastConnect returns the most recent ConnectResult.
func (c *Client) LastConnect() *ConnectResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.last
}

// TokenSource returns the active token source, or nil when unauthenticated.
func (c *Client) TokenSource() auth.TokenSource { return c.atr.Source() }

// SetTokenSource installs a token source (for example one built by the
// caller from a stored refresh token).
func (c *Client) SetTokenSource(src auth.TokenSource) { c.atr.SetSource(src) }

// Connect runs the authorization state machine and the MCP handshake.
//
//	initialize ──200──▶ connected
//	     │401
//	     ▼
//	Discover (PRM: hint, then well-known → AS metadata) ─▶ Register
//	     │
//	     ├─ client_credentials ─▶ token ─▶ Initialize ─▶ connected
//	     └─ authorization_code ─▶ StatusAuthorizationRequired
//	                               (CompleteAuthorization finishes it)
//
// Each step is also exported so a caller can run them one at a time.
func (c *Client) Connect(ctx context.Context) (*ConnectResult, error) {
	ctx = trace.Ensure(ctx)
	res, err := c.Initialize(ctx)
	if err == nil {
		out := &ConnectResult{Status: StatusConnected, Initialize: res}
		c.setLast(out)
		return out, nil
	}
	challenge, ok := Unauthorized(err)
	if !ok {
		return nil, err
	}
	switch c.cfg.Auth.Mode {
	case AuthNone:
		return nil, fmt.Errorf("passmcp: server requires authorization but Auth.Mode is none: %w", err)
	case AuthBearer:
		return nil, fmt.Errorf("passmcp: server rejected the supplied bearer token: %w", err)
	}

	d, err := c.Discover(ctx, challenge)
	if err != nil {
		return nil, err
	}
	if _, err := c.Register(ctx, d); err != nil {
		return nil, err
	}
	out := &ConnectResult{Discovery: d}

	switch c.cfg.Auth.Mode {
	case AuthClientCredentials:
		src, err := c.ClientCredentialsSource(d)
		if err != nil {
			return nil, err
		}
		c.atr.SetSource(src)
		res, err := c.Initialize(ctx)
		if err != nil {
			return nil, fmt.Errorf("passmcp: initialize after token exchange: %w", err)
		}
		out.Status, out.Initialize = StatusConnected, res
		c.setLast(out)
		return out, nil

	case AuthAuthorizationCode:
		u, state, err := c.StartAuthorization(d)
		if err != nil {
			return nil, err
		}
		out.Status, out.AuthorizationURL, out.State = StatusAuthorizationRequired, u, state
		c.setLast(out)
		return out, nil
	}
	return nil, fmt.Errorf("passmcp: unknown auth mode %q", c.cfg.Auth.Mode)
}

// Discover resolves protected-resource and authorization-server metadata
// for the challenge, honouring Overrides. It does not register a client.
func (c *Client) Discover(ctx context.Context, challenge auth.Challenge) (*Discovery, error) {
	d := &Discovery{Challenge: challenge}
	ov := c.cfg.Auth.Overrides
	if ov.TokenURL != "" {
		d.Overridden = true
		d.Server = &auth.ServerMetadata{TokenEndpoint: ov.TokenURL, AuthorizationEndpoint: ov.AuthorizationURL, CodeChallengeMethodsSupported: []string{"S256"}}
		// Overrides come from the operator, not the server, so they are
		// admitted without the discovery policy. They still have to parse.
		if err := c.admit(d.Server); err != nil {
			return nil, err
		}
		d.Resource = ov.Resource
		if d.Resource == "" {
			d.Resource, _ = auth.CanonicalResource(c.cfg.Endpoint)
		}
		d.Scope = c.scope(challenge, nil)
		return d, nil
	}
	prm, src, err := c.disc.DiscoverPRM(ctx, c.cfg.Endpoint, challenge.Params["resource_metadata"])
	if err != nil {
		return nil, err
	}
	d.PRM, d.PRMSource = prm, src
	if err := c.checkResourceBinding(prm); err != nil {
		return nil, err
	}
	var derrs []error
	for _, issuer := range prm.AuthorizationServers {
		m, err := c.disc.DiscoverServer(ctx, issuer)
		if err != nil {
			derrs = append(derrs, err)
			continue
		}
		d.Server = m
		break
	}
	if d.Server == nil {
		return nil, fmt.Errorf("passmcp: no usable authorization server: %w", errors.Join(derrs...))
	}
	if ov.AuthorizationURL != "" {
		d.Server.AuthorizationEndpoint = ov.AuthorizationURL
	}
	if err := c.admit(d.Server); err != nil {
		return nil, err
	}
	d.Resource = ov.Resource
	if d.Resource == "" {
		d.Resource = prm.Resource
	}
	if d.Resource == "" {
		d.Resource, _ = auth.CanonicalResource(c.cfg.Endpoint)
	}
	d.Scope = c.scope(challenge, prm)
	return d, nil
}

func (c *Client) registrationOptions() auth.RegistrationOptions {
	o := c.cfg.Auth.Registration
	if o.Metadata.ClientName == "" {
		o.Metadata.ClientName = c.cfg.ClientInfo.Name
	}
	if o.Metadata.SoftwareVersion == "" {
		o.Metadata.SoftwareVersion = c.cfg.ClientInfo.Version
	}
	switch c.cfg.Auth.Mode {
	case AuthClientCredentials:
		if len(o.Metadata.GrantTypes) == 0 {
			o.Metadata.GrantTypes = []string{"client_credentials"}
		}
		if o.Metadata.TokenEndpointAuthMethod == "" {
			o.Metadata.TokenEndpointAuthMethod = "client_secret_basic"
		}
	case AuthAuthorizationCode:
		if len(o.Metadata.GrantTypes) == 0 {
			o.Metadata.GrantTypes = []string{"authorization_code", "refresh_token"}
		}
		if len(o.Metadata.ResponseTypes) == 0 {
			o.Metadata.ResponseTypes = []string{"code"}
		}
		if len(o.Metadata.RedirectURIs) == 0 {
			o.Metadata.RedirectURIs = []string{c.cfg.Auth.RedirectURI}
		}
		if o.Metadata.TokenEndpointAuthMethod == "" {
			o.Metadata.TokenEndpointAuthMethod = "none"
		}
	}
	return o
}

func (c *Client) setLast(r *ConnectResult) {
	c.mu.Lock()
	c.last = r
	if r.Initialize != nil {
		c.init = r.Initialize
	}
	c.mu.Unlock()
}
