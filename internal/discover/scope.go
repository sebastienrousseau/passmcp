// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
)

// ErrOutOfScope is returned for a request to a host the operator did not
// name. The request is never sent.
var ErrOutOfScope = errors.New("discover: host is not one of the named targets")

// scope is the set of hosts a discovery run may contact: the hosts of the
// targets the operator named, and nothing else.
//
// It is enforced in the transport rather than trusted to the prober, so a
// redirect, a server card that points elsewhere, or a bug in the probing
// code cannot reach a host the operator did not name. A blocked request is
// remembered, so a run can say what it declined to contact.
type scope struct {
	mu      sync.Mutex
	hosts   map[string]bool
	blocked map[string]bool
}

// newScope returns the scope of the given targets.
func newScope(targets []Target) *scope {
	s := &scope{hosts: map[string]bool{}, blocked: map[string]bool{}}
	for _, t := range targets {
		if u, err := url.Parse(t.URL); err == nil && u.Host != "" {
			s.hosts[hostKey(u)] = true
		}
	}
	return s
}

// hostKey is the host and port a URL addresses, with the scheme's default
// port made explicit, so https://a and https://a:443 are one host.
func hostKey(u *url.URL) string {
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "" {
		switch u.Scheme {
		case "http":
			port = "80"
		default:
			port = "443"
		}
	}
	return host + ":" + port
}

// allows reports whether u is inside the scope, and records it as blocked
// when it is not.
func (s *scope) allows(u *url.URL) bool {
	key := hostKey(u)
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hosts[key] {
		return true
	}
	s.blocked[key] = true
	return false
}

// Blocked lists the hosts a run declined to contact, sorted.
func (s *scope) Blocked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.blocked))
	for h := range s.blocked {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

// scopedTransport refuses any request outside the scope before it is sent.
type scopedTransport struct {
	scope *scope
	base  http.RoundTripper
}

// RoundTrip implements http.RoundTripper.
func (t *scopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !t.scope.allows(req.URL) {
		return nil, fmt.Errorf("%w: %s", ErrOutOfScope, req.URL.Host)
	}
	return t.base.RoundTrip(req)
}

// checkRedirect follows a redirect only to a host inside the scope, and
// then only a few times. A redirect elsewhere is reported to the caller as
// the response that carried it, never followed.
func (s *scope) checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= 3 {
		return http.ErrUseLastResponse
	}
	if !s.allows(req.URL) {
		return http.ErrUseLastResponse
	}
	return nil
}
