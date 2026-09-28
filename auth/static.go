// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"net/http"
	"sync"
)

// StaticSource yields one pre-issued token and never refreshes it. Use it
// when the operator was handed a bearer token out of band.
type StaticSource struct{ AccessToken string }

// Token implements TokenSource.
func (s StaticSource) Token(context.Context) (*Token, error) {
	return &Token{AccessToken: s.AccessToken, TokenType: "Bearer"}, nil
}

// Invalidate implements TokenSource; a static token cannot be renewed.
func (StaticSource) Invalidate() {}

// WithScope implements TokenSource; the token's scope is fixed.
func (s StaticSource) WithScope(string) TokenSource { return s }

// HeaderTransport adds fixed headers (API keys, basic auth, tenant
// selectors) to requests bound for an allowed origin. Values are sent
// verbatim.
//
// Like Transport, it must consult an OriginSet: these headers are
// credentials too, and a RoundTripper re-applies them on every redirect hop
// unless something stops it. The receiver is a pointer so that a transport
// built without an explicit OriginSet can pin itself to the first origin it
// carries rather than silently dropping the headers.
type HeaderTransport struct {
	Base    http.RoundTripper
	Headers map[string]string
	// Allowed lists the origins that may receive the headers. When nil, the
	// transport allocates a set on first use and pins the first origin.
	Allowed *OriginSet

	once sync.Once
}

// NewHeaderTransport wraps base so that headers are added to requests bound
// for one of allowed's origins. A nil allowed pins the first origin used.
func NewHeaderTransport(base http.RoundTripper, headers map[string]string, allowed *OriginSet) *HeaderTransport {
	return &HeaderTransport{Base: base, Headers: headers, Allowed: allowed}
}

// RoundTrip implements http.RoundTripper.
func (t *HeaderTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if len(t.Headers) == 0 {
		return base.RoundTrip(req)
	}
	t.once.Do(func() {
		if t.Allowed == nil {
			t.Allowed = &OriginSet{}
		}
	})
	if !t.Allowed.pin(req.URL) {
		return base.RoundTrip(req)
	}
	r := req.Clone(req.Context())
	for k, v := range t.Headers {
		r.Header.Set(k, v)
	}
	return base.RoundTrip(r)
}
