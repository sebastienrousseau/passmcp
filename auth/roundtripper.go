// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
)

// InsufficientScopeError is returned when the resource server answers 403
// with error="insufficient_scope". Scope is the scope the server asked for,
// which the caller should use to step up.
type InsufficientScopeError struct {
	Scope       string
	Description string
}

func (e *InsufficientScopeError) Error() string {
	return fmt.Sprintf("auth: insufficient scope, server requires %q: %s", e.Scope, e.Description)
}

// StepUpFunc is invoked when a request needs a broader scope. It returns a
// replacement TokenSource (or an error to abort).
type StepUpFunc func(ctx context.Context, required string) (TokenSource, error)

// Transport is an http.RoundTripper that attaches Bearer tokens, retries
// once on 401 after invalidating the cached token, and converts 403
// insufficient_scope challenges into a step-up via StepUp.
//
// The token is attached only to origins in Allowed. Because an
// http.RoundTripper sits below http.Client's redirect handling, a
// RoundTripper that attaches credentials unconditionally re-attaches them on
// every hop of a redirect chain, including one that leaves the origin the
// operator named. Allowed is what stops a server answering 307 with a
// Location of its choosing from collecting the token.
type Transport struct {
	Base   http.RoundTripper
	StepUp StepUpFunc
	// Allowed lists the origins that may receive the token. When it is
	// empty, the transport pins the origin of the first request it carries
	// and refuses every other one thereafter.
	Allowed *OriginSet

	mu     sync.RWMutex
	source TokenSource
}

// NewTransport wraps base with token handling from src. The returned
// transport pins itself to the origin of the first request unless Allowed
// is populated first.
func NewTransport(base http.RoundTripper, src TokenSource) *Transport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &Transport{Base: base, source: src, Allowed: &OriginSet{}}
}

// Source returns the active token source.
func (t *Transport) Source() TokenSource {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.source
}

// SetSource replaces the active token source.
func (t *Transport) SetSource(src TokenSource) {
	t.mu.Lock()
	t.source = src
	t.mu.Unlock()
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
		return nil, errors.New("auth: request body is not replayable; set GetBody")
	}
	resp, err := t.do(req)
	if err != nil {
		return nil, err
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		// Token may have been revoked or the source may hold a stale one.
		// With no source there is nothing to retry with; hand the
		// challenge back to the caller.
		src := t.Source()
		if src == nil {
			return resp, nil
		}
		drain(resp)
		src.Invalidate()
		return t.do(req)
	case http.StatusForbidden:
		if req0 := insufficientScope(resp); req0 != nil {
			if t.StepUp == nil {
				drain(resp)
				return nil, req0
			}
			drain(resp)
			src, err := t.StepUp(req.Context(), req0.Scope)
			if err != nil {
				return nil, fmt.Errorf("auth: step-up failed: %w", err)
			}
			t.SetSource(src)
			return t.do(req)
		}
	}
	return resp, nil
}

func (t *Transport) do(req *http.Request) (*http.Response, error) {
	src := t.Source()
	if src == nil || !t.mayCredential(req) {
		return t.Base.RoundTrip(req)
	}
	tok, err := src.Token(req.Context())
	if err != nil {
		return nil, err
	}
	r := req.Clone(req.Context())
	if req.GetBody != nil {
		b, err := req.GetBody()
		if err != nil {
			return nil, err
		}
		r.Body = b
	}
	r.Header.Set("Authorization", "Bearer "+tok.AccessToken)
	return t.Base.RoundTrip(r)
}

// mayCredential reports whether req's origin is allowed to see the token,
// pinning the first origin seen when no allow-list was configured.
func (t *Transport) mayCredential(req *http.Request) bool {
	if t.Allowed == nil {
		return false
	}
	return t.Allowed.pin(req.URL)
}

func insufficientScope(resp *http.Response) *InsufficientScopeError {
	for _, ch := range ParseWWWAuthenticate(resp.Header.Get("WWW-Authenticate")) {
		if ch.Params["error"] == "insufficient_scope" {
			return &InsufficientScopeError{Scope: ch.Params["scope"], Description: ch.Params["error_description"]}
		}
	}
	return nil
}

func drain(resp *http.Response) {
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	_ = resp.Body.Close()
}
