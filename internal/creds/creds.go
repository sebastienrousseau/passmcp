// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package creds models the credentials an operator is handed for an MCP
// server: a bearer token, an API key header, HTTP basic, OAuth client
// credentials, or an interactive authorization-code login. It resolves
// them from flags, environment and profile, records where each came from,
// and hands every secret to the redactor so nothing leaks into a report.
package creds

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/auth"
)

// Mode is the credential kind.
type Mode string

const (
	// ModeAuto picks bearer/client-credentials/authorization-code from
	// which fields are set, and none when nothing is.
	ModeAuto Mode = "auto"
	// ModeNone sends no credentials.
	ModeNone Mode = "none"
	// ModeBearer sends a pre-issued token.
	ModeBearer Mode = "bearer"
	// ModeClientCredentials runs the OAuth 2.1 client-credentials grant.
	ModeClientCredentials Mode = "client-credentials"
	// ModeAuthorizationCode runs the interactive PKCE flow (see Store).
	ModeAuthorizationCode Mode = "authorization-code"
)

// Modes lists the accepted --auth values.
var Modes = []Mode{ModeAuto, ModeNone, ModeBearer, ModeClientCredentials, ModeAuthorizationCode}

// Environment variable names consulted when the matching flag is unset.
const (
	EnvToken        = "PASSMCP_TOKEN" //nolint:gosec // G101: the name of an environment variable, not a credential
	EnvClientID     = "PASSMCP_CLIENT_ID"
	EnvClientSecret = "PASSMCP_CLIENT_SECRET" //nolint:gosec // G101: the name of an environment variable, not a credential
	EnvBasic        = "PASSMCP_BASIC"         // user:password
)

// Credentials is everything that can identify passmcp to a server.
type Credentials struct {
	Mode Mode `json:"mode"`

	Token string `json:"-"`

	// Headers are sent verbatim on every request (API keys, tenant ids).
	Headers map[string]string `json:"headers,omitempty"`
	// BasicUser and BasicPassword become an Authorization: Basic header.
	BasicUser     string `json:"basic_user,omitempty"`
	BasicPassword string `json:"-"`

	ClientID          string `json:"client_id,omitempty"`
	ClientSecret      string `json:"-"`
	ClientMetadataURL string `json:"client_metadata_url,omitempty"`
	TokenAuthMethod   string `json:"token_auth_method,omitempty"`
	Scope             string `json:"scope,omitempty"`
	// Params are extra token-request or authorization-request parameters
	// (for example profile_id=tenant-1).
	Params url.Values `json:"params,omitempty"`

	// Overrides pin endpoints for servers without discovery.
	TokenURL string `json:"token_url,omitempty"`
	AuthURL  string `json:"auth_url,omitempty"`
	Resource string `json:"resource,omitempty"`

	RedirectPort int `json:"redirect_port,omitempty"`

	// WrongAudienceToken is a token the operator's own authorization server
	// issued for a different resource. auth.wrong_audience sends it to see
	// whether the server checks the audience; passmcp never mints one.
	WrongAudienceToken string `json:"-"`

	// Sources records where each populated field came from, keyed by
	// field name, for `--explain` and the report.
	Sources map[string]string `json:"sources,omitempty"`
}

// Set records a value and its source, ignoring empty values.
func (c *Credentials) set(field, value, source string) {
	if value == "" {
		return
	}
	if c.Sources == nil {
		c.Sources = map[string]string{}
	}
	c.Sources[field] = source
	switch field {
	case "token":
		c.Token = value
	case "client-id":
		c.ClientID = value
	case "client-secret":
		c.ClientSecret = value
	case "basic":
		user, pass, _ := strings.Cut(value, ":")
		c.BasicUser, c.BasicPassword = user, pass
	case "wrong-audience-token":
		c.WrongAudienceToken = value
	}
}

// FromEnv fills unset secret fields from the PASSMCP_* environment.
func (c *Credentials) FromEnv() {
	if c.Token == "" {
		c.set("token", os.Getenv(EnvToken), "env "+EnvToken)
	}
	if c.ClientID == "" {
		c.set("client-id", os.Getenv(EnvClientID), "env "+EnvClientID)
	}
	if c.ClientSecret == "" {
		c.set("client-secret", os.Getenv(EnvClientSecret), "env "+EnvClientSecret)
	}
	if c.BasicUser == "" {
		c.set("basic", os.Getenv(EnvBasic), "env "+EnvBasic)
	}
}

// SetFromFlag records a value supplied on the command line.
func (c *Credentials) SetFromFlag(field, value string) { c.set(field, value, "flag --"+field) }

// SetFromEnvName reads an operator-chosen environment variable.
func (c *Credentials) SetFromEnvName(field, envName string) error {
	if envName == "" {
		return nil
	}
	v, ok := os.LookupEnv(envName)
	if !ok {
		return fmt.Errorf("environment variable %s is not set", envName)
	}
	c.set(field, v, "env "+envName)
	return nil
}

// Effective resolves ModeAuto into a concrete mode.
func (c *Credentials) Effective() Mode {
	if c.Mode != ModeAuto && c.Mode != "" {
		return c.Mode
	}
	switch {
	case c.Token != "":
		return ModeBearer
	case c.ClientID != "" || c.ClientSecret != "" || c.ClientMetadataURL != "":
		return ModeClientCredentials
	}
	return ModeNone
}

// Validate checks the combination makes sense.
func (c *Credentials) Validate() error {
	if !c.knownMode() {
		return fmt.Errorf("unknown auth mode %q (want one of %s)", c.Mode, joinModes())
	}
	if err := c.validateModeInputs(); err != nil {
		return err
	}
	if (c.BasicUser != "" || c.BasicPassword != "") && c.BasicUser == "" {
		return errors.New("--basic must be user:password")
	}
	if c.AuthURL != "" && c.TokenURL == "" {
		return errors.New("--auth-url requires --token-url")
	}
	return nil
}

// knownMode reports whether the mode is one of Modes; an empty mode counts
// as auto.
func (c *Credentials) knownMode() bool {
	found := false
	for _, m := range Modes {
		if m == c.Mode || (c.Mode == "" && m == ModeAuto) {
			found = true
		}
	}
	return found
}

// validateModeInputs checks that the effective mode has the input it cannot
// run without.
func (c *Credentials) validateModeInputs() error {
	switch c.Effective() {
	case ModeBearer:
		if c.Token == "" {
			return errors.New("--auth bearer needs --token, --token-env or " + EnvToken)
		}
	case ModeClientCredentials:
		if c.ClientID == "" && c.ClientMetadataURL == "" {
			return errors.New("--auth client-credentials needs --client-id (or --client-metadata-url); the server may also offer dynamic registration, in which case pass --client-id \"\" explicitly")
		}
	}
	return nil
}

// Secrets lists every secret value for the redactor.
func (c *Credentials) Secrets() []string {
	out := []string{c.Token, c.ClientSecret, c.BasicPassword, c.WrongAudienceToken}
	for k, v := range c.Headers {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "key") || strings.Contains(lk, "token") || strings.Contains(lk, "secret") || lk == "authorization" || lk == "cookie" {
			out = append(out, v)
		}
	}
	return out
}

// Describe returns a one-line, secret-free description for banners.
func (c *Credentials) Describe() string {
	parts := []string{string(c.Effective())}
	if c.ClientID != "" {
		parts = append(parts, "client_id="+c.ClientID)
	}
	if c.ClientMetadataURL != "" {
		parts = append(parts, "cimd="+c.ClientMetadataURL)
	}
	if c.Scope != "" {
		parts = append(parts, "scope="+strconvQuote(c.Scope))
	}
	if len(c.Headers) > 0 {
		keys := make([]string, 0, len(c.Headers))
		for k := range c.Headers {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts = append(parts, "headers="+strings.Join(keys, ","))
	}
	if c.BasicUser != "" {
		parts = append(parts, "basic="+c.BasicUser)
	}
	if c.TokenURL != "" {
		parts = append(parts, "token_url="+c.TokenURL)
	}
	if len(c.Params) > 0 {
		parts = append(parts, "params="+c.Params.Encode())
	}
	return strings.Join(parts, " ")
}

// Apply translates the credentials into a passmcp.Config.
func (c *Credentials) Apply(cfg *passmcp.Config) {
	if cfg.Headers == nil && (len(c.Headers) > 0 || c.BasicUser != "") {
		cfg.Headers = map[string]string{}
	}
	for k, v := range c.Headers {
		cfg.Headers[k] = v
	}
	if c.BasicUser != "" {
		cfg.Headers["Authorization"] = "Basic " + base64.StdEncoding.EncodeToString([]byte(c.BasicUser+":"+c.BasicPassword))
	}
	cfg.Auth.Scope = c.Scope
	cfg.Auth.Extra = c.Params
	cfg.Auth.TokenAuthMethod = c.TokenAuthMethod
	cfg.Auth.Overrides = passmcp.Overrides{TokenURL: c.TokenURL, AuthorizationURL: c.AuthURL, Resource: c.Resource}
	cfg.Auth.Registration = auth.RegistrationOptions{ClientMetadataURL: c.ClientMetadataURL, StaticClientID: c.ClientID, StaticClientSecret: c.ClientSecret}
	switch c.Effective() {
	case ModeNone:
		cfg.Auth.Mode = passmcp.AuthNone
	case ModeBearer:
		cfg.Auth.Mode = passmcp.AuthBearer
		cfg.Auth.Token = c.Token
	case ModeClientCredentials:
		cfg.Auth.Mode = passmcp.AuthClientCredentials
	case ModeAuthorizationCode:
		cfg.Auth.Mode = passmcp.AuthAuthorizationCode
		port := c.RedirectPort
		if port == 0 {
			port = 8976
		}
		cfg.Auth.RedirectURI = fmt.Sprintf("http://127.0.0.1:%d/callback", port)
	}
}

// ParseHeader splits "Name: value" or "Name=value".
func ParseHeader(s string) (string, string, error) {
	for _, sep := range []string{":", "="} {
		if k, v, ok := strings.Cut(s, sep); ok && strings.TrimSpace(k) != "" {
			return strings.TrimSpace(k), strings.TrimSpace(v), nil
		}
	}
	return "", "", fmt.Errorf("header %q must be Name: value", s)
}

// ParseParam splits "key=value".
func ParseParam(s string) (string, string, error) {
	k, v, ok := strings.Cut(s, "=")
	if !ok || k == "" {
		return "", "", fmt.Errorf("param %q must be key=value", s)
	}
	return k, v, nil
}

func joinModes() string {
	s := make([]string, len(Modes))
	for i, m := range Modes {
		s[i] = string(m)
	}
	return strings.Join(s, ", ")
}

func strconvQuote(s string) string {
	if strings.ContainsAny(s, " \t") {
		return `"` + s + `"`
	}
	return s
}
