// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Token is an OAuth 2.1 access token with its refresh companion.
type Token struct {
	AccessToken  string
	TokenType    string
	RefreshToken string
	Scope        string
	Expiry       time.Time // zero when the server gave no expires_in
}

// Valid reports whether the token is present and not within skew of expiry.
func (t *Token) Valid(skew time.Duration) bool {
	if t == nil || t.AccessToken == "" {
		return false
	}
	if t.Expiry.IsZero() {
		return true
	}
	return time.Now().Add(skew).Before(t.Expiry)
}

// TokenError is an RFC 6749 §5.2 error response from the token endpoint.
type TokenError struct {
	StatusCode  int
	Code        string `json:"error"`
	Description string `json:"error_description"`
	URI         string `json:"error_uri"`
}

func (e *TokenError) Error() string {
	if e.Description != "" {
		return fmt.Sprintf("auth: token endpoint %s: %s", e.Code, e.Description)
	}
	return fmt.Sprintf("auth: token endpoint error %q (http %d)", e.Code, e.StatusCode)
}

// PKCE holds an S256 code verifier and its challenge.
type PKCE struct {
	Verifier  string
	Challenge string
	Method    string
}

// NewPKCE generates a 32-byte random verifier and S256 challenge.
func NewPKCE() (*PKCE, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return nil, err
	}
	v := base64.RawURLEncoding.EncodeToString(b[:])
	sum := sha256.Sum256([]byte(v))
	return &PKCE{Verifier: v, Challenge: base64.RawURLEncoding.EncodeToString(sum[:]), Method: "S256"}, nil
}

// NewState returns a random OAuth state value.
func NewState() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// Endpoint holds what the token layer needs from server metadata.
type Endpoint struct {
	AuthorizationURL string
	TokenURL         string
	// AuthMethod is "client_secret_basic" (default when a secret is set),
	// "client_secret_post", or "none".
	AuthMethod string
}

// Credentials identifies the client to the authorization server.
type Credentials struct {
	ClientID     string
	ClientSecret string
}

// tokenRequest posts an x-www-form-urlencoded grant to the token endpoint.
func tokenRequest(ctx context.Context, hc *http.Client, ep Endpoint, creds Credentials, form url.Values) (*Token, error) {
	if hc == nil {
		hc = http.DefaultClient
	}
	method := tokenAuthMethod(ep, creds)
	addFormClientAuth(form, method, creds)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, ep.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth: build token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	if method == "client_secret_basic" {
		req.SetBasicAuth(url.QueryEscape(creds.ClientID), url.QueryEscape(creds.ClientSecret))
	}
	resp, err := hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, err
	}
	return parseTokenResponse(resp.StatusCode, body)
}

// tokenAuthMethod is the client authentication the endpoint asked for, or,
// when it named none, basic for a confidential client and none otherwise.
func tokenAuthMethod(ep Endpoint, creds Credentials) string {
	method := ep.AuthMethod
	if method == "" {
		if creds.ClientSecret != "" {
			method = "client_secret_basic"
		} else {
			method = "none"
		}
	}
	return method
}

// addFormClientAuth puts the client's identity in the form body for the
// methods that carry it there.
func addFormClientAuth(form url.Values, method string, creds Credentials) {
	switch method {
	case "client_secret_post":
		form.Set("client_id", creds.ClientID)
		form.Set("client_secret", creds.ClientSecret)
	case "none":
		form.Set("client_id", creds.ClientID)
	}
}

// parseTokenResponse turns a token endpoint's answer into a Token, or into a
// TokenError when the status is not 200.
func parseTokenResponse(status int, body []byte) (*Token, error) {
	if status != http.StatusOK {
		te := &TokenError{StatusCode: status}
		if json.Unmarshal(body, te) != nil || te.Code == "" {
			te.Code = "http_" + fmt.Sprint(status)
			te.Description = truncate(body, 256)
		}
		return nil, te
	}
	var raw struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
		ExpiresIn    int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return nil, fmt.Errorf("auth: decode token response: %w", err)
	}
	if raw.AccessToken == "" {
		return nil, errors.New("auth: token response missing access_token")
	}
	t := &Token{AccessToken: raw.AccessToken, TokenType: raw.TokenType, RefreshToken: raw.RefreshToken, Scope: raw.Scope}
	if raw.ExpiresIn > 0 {
		t.Expiry = time.Now().Add(time.Duration(raw.ExpiresIn) * time.Second)
	}
	return t, nil
}

// TokenSource yields a valid access token, refreshing or re-acquiring as
// needed. Implementations must be safe for concurrent use.
type TokenSource interface {
	Token(ctx context.Context) (*Token, error)
	// Invalidate discards the cached token so the next call re-acquires.
	Invalidate()
	// WithScope returns a source that requests the given scope; used for
	// step-up after an insufficient_scope challenge.
	WithScope(scope string) TokenSource
}

// ExpirySkew is how far ahead of expiry a token is treated as expired.
const ExpirySkew = 30 * time.Second

// ClientCredentialsSource implements the B2B flow: OAuth 2.1 client
// credentials with an RFC 8707 resource indicator. Extra carries
// server-specific parameters (for example a tenant profile identifier) and
// is sent verbatim on every token request.
type ClientCredentialsSource struct {
	HTTP     *http.Client
	Endpoint Endpoint
	Creds    Credentials
	Resource string
	Scope    string
	Extra    url.Values

	mu  sync.Mutex
	tok *Token
}

// Token implements TokenSource.
func (s *ClientCredentialsSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok.Valid(ExpirySkew) {
		return s.tok, nil
	}
	form := url.Values{}
	for k, vs := range s.Extra {
		for _, v := range vs {
			form.Add(k, v)
		}
	}
	form.Set("grant_type", "client_credentials")
	if s.Resource != "" {
		form.Set("resource", s.Resource)
	}
	if s.Scope != "" {
		form.Set("scope", s.Scope)
	}
	tok, err := tokenRequest(ctx, s.HTTP, s.Endpoint, s.Creds, form)
	if err != nil {
		return nil, err
	}
	s.tok = tok
	return tok, nil
}

// Invalidate implements TokenSource.
func (s *ClientCredentialsSource) Invalidate() {
	s.mu.Lock()
	s.tok = nil
	s.mu.Unlock()
}

// WithScope implements TokenSource.
func (s *ClientCredentialsSource) WithScope(scope string) TokenSource {
	return &ClientCredentialsSource{HTTP: s.HTTP, Endpoint: s.Endpoint, Creds: s.Creds, Resource: s.Resource, Scope: scope, Extra: s.Extra}
}

// AuthorizationCodeFlow implements the B2C flow in two halves so the
// caller can drive a browser between them.
type AuthorizationCodeFlow struct {
	HTTP        *http.Client
	Endpoint    Endpoint
	Creds       Credentials
	Resource    string
	RedirectURI string
	Scope       string
	Extra       url.Values // extra authorization request parameters

	mu    sync.Mutex
	pkce  *PKCE
	state string
}

// Start returns the URL the end user must visit. It records the PKCE
// verifier and state for Complete.
func (f *AuthorizationCodeFlow) Start() (string, error) {
	if f.Endpoint.AuthorizationURL == "" {
		return "", errors.New("auth: authorization endpoint not set")
	}
	p, err := NewPKCE()
	if err != nil {
		return "", err
	}
	st, err := NewState()
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	f.pkce, f.state = p, st
	f.mu.Unlock()
	u, err := url.Parse(f.Endpoint.AuthorizationURL)
	if err != nil {
		return "", err
	}
	q := u.Query()
	for k, vs := range f.Extra {
		for _, v := range vs {
			q.Add(k, v)
		}
	}
	q.Set("response_type", "code")
	q.Set("client_id", f.Creds.ClientID)
	q.Set("redirect_uri", f.RedirectURI)
	q.Set("code_challenge", p.Challenge)
	q.Set("code_challenge_method", p.Method)
	q.Set("state", st)
	if f.Resource != "" {
		q.Set("resource", f.Resource)
	}
	if f.Scope != "" {
		q.Set("scope", f.Scope)
	}
	u.RawQuery = q.Encode()
	return u.String(), nil
}

// State returns the state issued by Start so a redirect handler can match it.
func (f *AuthorizationCodeFlow) State() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.state
}

// Complete exchanges the authorization code from the redirect for tokens.
// state must equal the value issued by Start.
func (f *AuthorizationCodeFlow) Complete(ctx context.Context, code, state string) (*RefreshingSource, error) {
	f.mu.Lock()
	pkce, want := f.pkce, f.state
	f.mu.Unlock()
	if pkce == nil {
		return nil, errors.New("auth: Complete called before Start")
	}
	// Constant time: state is a CSRF token, and an early-exit comparison
	// leaks its prefix to anyone who can time the redirect handler.
	if subtle.ConstantTimeCompare([]byte(state), []byte(want)) != 1 {
		return nil, errors.New("auth: state mismatch on redirect")
	}
	form := url.Values{}
	form.Set("grant_type", "authorization_code")
	form.Set("code", code)
	form.Set("redirect_uri", f.RedirectURI)
	form.Set("code_verifier", pkce.Verifier)
	if f.Resource != "" {
		form.Set("resource", f.Resource)
	}
	tok, err := tokenRequest(ctx, f.HTTP, f.Endpoint, f.Creds, form)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	f.pkce, f.state = nil, ""
	f.mu.Unlock()
	return &RefreshingSource{HTTP: f.HTTP, Endpoint: f.Endpoint, Creds: f.Creds, Resource: f.Resource, Scope: f.Scope, tok: tok}, nil
}

// RefreshingSource holds a token obtained interactively and uses the
// refresh_token grant when it expires. When no refresh token exists the
// caller must restart the interactive flow (ErrReauthRequired).
type RefreshingSource struct {
	HTTP     *http.Client
	Endpoint Endpoint
	Creds    Credentials
	Resource string
	Scope    string

	mu  sync.Mutex
	tok *Token
}

// ErrReauthRequired signals that the interactive flow must be re-run.
var ErrReauthRequired = errors.New("auth: token expired and no refresh token available; restart the authorization code flow")

// NewRefreshingSource wraps an existing token (for example one loaded from
// a secure store) in a source that will refresh it.
func NewRefreshingSource(hc *http.Client, ep Endpoint, creds Credentials, resource string, tok *Token) *RefreshingSource {
	return &RefreshingSource{HTTP: hc, Endpoint: ep, Creds: creds, Resource: resource, tok: tok}
}

// Token implements TokenSource.
func (s *RefreshingSource) Token(ctx context.Context) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok.Valid(ExpirySkew) {
		return s.tok, nil
	}
	if s.tok == nil || s.tok.RefreshToken == "" {
		return nil, ErrReauthRequired
	}
	form := url.Values{}
	form.Set("grant_type", "refresh_token")
	form.Set("refresh_token", s.tok.RefreshToken)
	if s.Resource != "" {
		form.Set("resource", s.Resource)
	}
	if s.Scope != "" {
		form.Set("scope", s.Scope)
	}
	tok, err := tokenRequest(ctx, s.HTTP, s.Endpoint, s.Creds, form)
	if err != nil {
		var te *TokenError
		if errors.As(err, &te) && te.Code == "invalid_grant" {
			return nil, fmt.Errorf("%w: %w", ErrReauthRequired, err)
		}
		return nil, err
	}
	if tok.RefreshToken == "" {
		tok.RefreshToken = s.tok.RefreshToken // servers may not rotate
	}
	s.tok = tok
	return tok, nil
}

// Invalidate implements TokenSource by forcing a refresh on next use.
func (s *RefreshingSource) Invalidate() {
	s.mu.Lock()
	if s.tok != nil {
		s.tok.AccessToken = ""
	}
	s.mu.Unlock()
}

// WithScope implements TokenSource. A scope change on a user-delegated
// token normally needs re-consent, so this returns a source whose next
// refresh requests the new scope; if the server refuses, the caller gets
// ErrReauthRequired and must restart the flow with the new scope.
func (s *RefreshingSource) WithScope(scope string) TokenSource {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := &RefreshingSource{HTTP: s.HTTP, Endpoint: s.Endpoint, Creds: s.Creds, Resource: s.Resource, Scope: scope}
	if s.tok != nil {
		t := *s.tok
		t.AccessToken = ""
		cp.tok = &t
	}
	return cp
}

// Current returns the cached token without refreshing (for persistence).
func (s *RefreshingSource) Current() *Token {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.tok == nil {
		return nil
	}
	t := *s.tok
	return &t
}
