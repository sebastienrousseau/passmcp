// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package trace carries a per-run trace identifier through context and
// stamps it on every outgoing HTTP request so a single onboarding run can be
// followed across the network boundary.
package trace

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
)

// Header is the request header carrying the trace identifier.
const Header = "X-MCP-Trace-ID"

type ctxKey struct{}

// NewID returns a fresh random 128-bit identifier in hex.
func NewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic("trace: crypto/rand unavailable: " + err.Error())
	}
	return hex.EncodeToString(b[:])
}

// WithID returns a context carrying id.
func WithID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, ctxKey{}, id)
}

// FromContext returns the trace ID stored in ctx, or "" when none is set.
func FromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	id, _ := ctx.Value(ctxKey{}).(string)
	return id
}

// Ensure returns ctx unchanged when it already carries a trace ID, otherwise
// a derived context with a newly generated one.
func Ensure(ctx context.Context) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	if FromContext(ctx) != "" {
		return ctx
	}
	return WithID(ctx, NewID())
}

// RoundTripper injects the context's trace ID into every request it sends.
type RoundTripper struct {
	Base http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t RoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	base := t.Base
	if base == nil {
		base = http.DefaultTransport
	}
	if id := FromContext(req.Context()); id != "" && req.Header.Get(Header) == "" {
		req = req.Clone(req.Context())
		req.Header.Set(Header, id)
	}
	return base.RoundTrip(req)
}
