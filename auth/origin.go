// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// Origin reduces a URL to the scheme://host tuple that scopes a credential.
// Scheme and host are lower-cased and the default port for the scheme is
// dropped, so https://Example.com:443/mcp and https://example.com/mcp share
// an origin.
func Origin(rawurl string) (string, error) {
	u, err := url.Parse(rawurl)
	if err != nil {
		return "", fmt.Errorf("auth: invalid origin %q: %w", rawurl, err)
	}
	return originOf(u)
}

func originOf(u *url.URL) (string, error) {
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("auth: %q has no scheme or host", u.Redacted())
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		return scheme + "://" + net.JoinHostPort(host, port), nil
	}
	return scheme + "://" + host, nil
}

// OriginSet is the set of origins a credential may be sent to. The zero
// value is an empty set that allows nothing; it is safe for concurrent use.
//
// A credential-bearing RoundTripper consults an OriginSet before attaching
// anything, so a redirect to a host the operator never named cannot carry
// the token. This is the defence against an MCP server answering 307 with a
// Location pointing at an attacker.
type OriginSet struct {
	mu  sync.RWMutex
	set map[string]struct{}
}

// NewOriginSet returns a set containing the origins of the given URLs.
func NewOriginSet(urls ...string) (*OriginSet, error) {
	o := &OriginSet{set: map[string]struct{}{}}
	for _, u := range urls {
		if err := o.Add(u); err != nil {
			return nil, err
		}
	}
	return o, nil
}

// Add admits the origin of rawurl.
func (o *OriginSet) Add(rawurl string) error {
	org, err := Origin(rawurl)
	if err != nil {
		return err
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.set == nil {
		o.set = map[string]struct{}{}
	}
	o.set[org] = struct{}{}
	return nil
}

// Allows reports whether u's origin is in the set. A nil set allows
// nothing: callers that want no restriction must say so explicitly.
func (o *OriginSet) Allows(u *url.URL) bool {
	if o == nil {
		return false
	}
	org, err := originOf(u)
	if err != nil {
		return false
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	_, ok := o.set[org]
	return ok
}

// pin admits u's origin if and only if the set is still empty, and reports
// whether u is allowed afterwards. It is how a transport with no configured
// origin binds itself to the first host it is used against.
func (o *OriginSet) pin(u *url.URL) bool {
	org, err := originOf(u)
	if err != nil {
		return false
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.set == nil {
		o.set = map[string]struct{}{}
	}
	if len(o.set) == 0 {
		o.set[org] = struct{}{}
		return true
	}
	_, ok := o.set[org]
	return ok
}

// Origins lists the admitted origins, for diagnostics.
func (o *OriginSet) Origins() []string {
	if o == nil {
		return nil
	}
	o.mu.RLock()
	defer o.mu.RUnlock()
	out := make([]string, 0, len(o.set))
	for k := range o.set {
		out = append(out, k)
	}
	return out
}

// ErrCrossOriginRedirect is returned by CheckRedirect when a response tries
// to move a credential-bearing request to an origin outside the set.
type ErrCrossOriginRedirect struct {
	From, To string
}

func (e *ErrCrossOriginRedirect) Error() string {
	return fmt.Sprintf("auth: refusing cross-origin redirect from %s to %s; credentials would leak to a host you did not name", e.From, e.To)
}

// MaxRedirects bounds a redirect chain even within one origin.
const MaxRedirects = 5

// CheckRedirect returns an http.Client CheckRedirect function that refuses
// to follow a redirect leaving the allowed origins. next, when non-nil, is
// consulted after the origin check so a caller's own policy still applies.
func CheckRedirect(allowed *OriginSet, next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	return func(req *http.Request, via []*http.Request) error {
		if len(via) >= MaxRedirects {
			return fmt.Errorf("auth: stopped after %d redirects", MaxRedirects)
		}
		if !allowed.Allows(req.URL) {
			from := "the request origin"
			if len(via) > 0 {
				if o, err := originOf(via[len(via)-1].URL); err == nil {
					from = o
				}
			}
			to, _ := originOf(req.URL)
			return &ErrCrossOriginRedirect{From: from, To: to}
		}
		if next != nil {
			return next(req, via)
		}
		return nil
	}
}
