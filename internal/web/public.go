// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package web

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"sort"
	"strings"
	"sync"
	"time"

	"satellion.com/passmcp/internal/engine"
)

// Public mode is what makes it safe to answer the open internet.
//
// passmcp serve was written for one operator on their own machine: it binds
// loopback, mints a token, and the only person who can reach it already owns
// the process. Every guard in this file exists because that assumption is
// exactly what hosting removes.
//
// The rules are the server's, taken from how it was started. None of them is
// reachable from a request, because a field a client can set is a field a
// client can unset.

// Allowlist is the set of origins a public server will scan.
//
// It is an origin list rather than a URL list because a server's endpoint
// path is its own business — /mcp, /sse, /v1/mcp are all common — while the
// origin is the thing that decides who receives the request.
type Allowlist struct {
	origins map[string]string // origin -> display name
}

// allowFile is the on-disk shape, which is also the shape of a registry
// export, so a snapshot can be used without translation.
type allowFile struct {
	Servers []struct {
		Name     string `json:"name"`
		Endpoint string `json:"endpoint"`
	} `json:"servers"`
}

// LoadAllowlist reads the servers a public deployment may scan.
//
// An empty list is refused rather than treated as "allow everything": a
// misplaced path would otherwise turn the allowlist off, which is the one
// failure this file exists to prevent.
func LoadAllowlist(path string) (*Allowlist, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- the path is the operator's own allowlist
	if err != nil {
		return nil, fmt.Errorf("web: reading the allowlist: %w", err)
	}
	var f allowFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("web: the allowlist is not valid JSON: %w", err)
	}
	a := &Allowlist{origins: map[string]string{}}
	for _, s := range f.Servers {
		o, err := originOf(s.Endpoint)
		if err != nil {
			return nil, fmt.Errorf("web: allowlist entry %q: %w", s.Name, err)
		}
		a.origins[o] = s.Name
	}
	if len(a.origins) == 0 {
		return nil, fmt.Errorf("web: the allowlist in %s names no servers; "+
			"an empty allowlist would let a public server be pointed anywhere", path)
	}
	return a, nil
}

// NewAllowlist builds a list from endpoints, for tests and for callers that
// already hold a registry snapshot.
func NewAllowlist(endpoints ...string) (*Allowlist, error) {
	a := &Allowlist{origins: map[string]string{}}
	for _, e := range endpoints {
		o, err := originOf(e)
		if err != nil {
			return nil, err
		}
		a.origins[o] = o
	}
	return a, nil
}

// originKey reduces an endpoint to the scheme://host:port that will receive
// the request, without judging it. Admission is decided by membership of the
// list, and every member was validated by originOf when it was added — so
// re-validating here would only mean an entry could be accepted at load and
// refused at lookup, which is the sort of disagreement that gets worked
// around rather than fixed.
func originKey(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme == "" || u.Host == "" {
		return "", fmt.Errorf("%q is not an absolute URL", raw)
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// originOf is originKey plus the rules an entry must satisfy to be on the
// list at all. Only https survives, because a public runner sending a
// request over plaintext on someone's behalf is a downgrade they did not ask
// for — and loopback and private addresses are refused outright, since from
// a host those are the host's own network.
func originOf(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", fmt.Errorf("%q is not a URL: %w", raw, err)
	}
	if u.Scheme != "https" {
		return "", fmt.Errorf("%q is not https", raw)
	}
	if u.Host == "" {
		return "", fmt.Errorf("%q has no host", raw)
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsUnspecified() {
			return "", fmt.Errorf("%q is a private or loopback address", raw)
		}
	}
	if strings.EqualFold(host, "localhost") {
		return "", fmt.Errorf("%q is loopback", raw)
	}
	return strings.ToLower(u.Scheme + "://" + u.Host), nil
}

// Permits reports whether an endpoint may be scanned, and names it if so.
func (a *Allowlist) Permits(endpoint string) (string, bool) {
	if a == nil {
		return "", false
	}
	o, err := originKey(endpoint)
	if err != nil {
		return "", false
	}
	name, ok := a.origins[o]
	return name, ok
}

// Names lists the servers on the list, so the page can offer them rather
// than inviting someone to type a URL that will be refused.
func (a *Allowlist) Names() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.origins))
	for o, name := range a.origins {
		if name == "" {
			name = o
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Endpoints lists the allowed origins.
func (a *Allowlist) Endpoints() []string {
	if a == nil {
		return nil
	}
	out := make([]string, 0, len(a.origins))
	for o := range a.origins {
		out = append(out, o)
	}
	sort.Strings(out)
	return out
}

// --- credentials -----------------------------------------------------------

// credentialFieldsSet names the credential fields a request tried to use.
//
// It walks the struct rather than testing known field names on purpose. The
// dangerous fields here are not the obvious ones — Token and ClientSecret
// carry json:"-" and cannot arrive over the wire at all — but TokenEnv and
// ClientSecretEnv, which are ordinary JSON and are resolved with
// os.LookupEnv against THIS process's environment. A request naming
// CLOUDFLARE_API_TOKEN and an endpoint it controls would otherwise have the
// host read its own secret and post it to the caller.
//
// Walking the struct means a credential field added later is refused by
// default. A list of names would have to be remembered, and the cost of
// forgetting is a hosted credential leak.
func credentialFieldsSet(c engine.CredSpec) []string {
	var set []string
	v := reflect.ValueOf(c)
	t := v.Type()
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		fv := v.Field(i)
		if fv.IsZero() {
			continue
		}
		// Mode is the one field with a permitted value: "none" is the
		// absence of credentials, which is what public mode always uses.
		if f.Name == "Mode" {
			if s, ok := fv.Interface().(string); ok && (s == "" || s == "none") {
				continue
			}
		}
		set = append(set, jsonName(f))
	}
	sort.Strings(set)
	return set
}

func jsonName(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	name, _, _ := strings.Cut(tag, ",")
	if name == "" || name == "-" {
		// json:"-" fields cannot arrive from a request, but naming them
		// honestly beats printing an empty string if one ever is set.
		return strings.ToLower(f.Name)
	}
	return name
}

// publicSpec returns the spec a public server will actually run.
//
// The credentials are constructed, not sanitised: whatever arrived is
// discarded and replaced with an explicit absence. Sanitising leaves the
// question "did I remove everything?" open on every future change; building
// the value closes it.
func publicSpec(s engine.RunSpec) engine.RunSpec {
	s.Creds = engine.CredSpec{Mode: "none"}
	// A public deployment runs nothing. startRun already refuses a spec
	// naming a program, and this is the second place that has to be true:
	// if a later change moves the order of those checks, the reconstruction
	// must not be the thing that carried a command through.
	s.Target = engine.TargetSpec{Endpoint: s.Target.Endpoint}
	return s
}

// --- rate limiting ---------------------------------------------------------

// limiter is a token bucket per client address.
//
// Deliberately small and dependency-free: the job is to stop one caller
// consuming the run capacity everyone else is sharing, not to be a general
// traffic shaper.
type limiter struct {
	mu      sync.Mutex
	seen    map[string]*bucket
	rate    float64 // tokens per second
	burst   float64
	lastGC  time.Time
	nowFunc func() time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

func newLimiter(perMinute int, burst int) *limiter {
	if perMinute <= 0 {
		perMinute = 6
	}
	if burst <= 0 {
		burst = 3
	}
	return &limiter{
		seen:    map[string]*bucket{},
		rate:    float64(perMinute) / 60,
		burst:   float64(burst),
		nowFunc: time.Now,
	}
}

func (l *limiter) now() time.Time {
	if l.nowFunc != nil {
		return l.nowFunc()
	}
	return time.Now()
}

// allow takes a token for key, reporting whether one was available.
func (l *limiter) allow(key string) bool {
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()

	// Buckets are only interesting while they are below full; a full one is
	// indistinguishable from a caller that has never been seen. Sweeping
	// them keeps this map from growing with every address that ever called.
	if now.Sub(l.lastGC) > 10*time.Minute {
		for k, b := range l.seen {
			if now.Sub(b.last) > 10*time.Minute {
				delete(l.seen, k)
			}
		}
		l.lastGC = now
	}

	b, ok := l.seen[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.seen[key] = b
	}
	b.tokens += now.Sub(b.last).Seconds() * l.rate
	if b.tokens > l.burst {
		b.tokens = l.burst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clientKey identifies a caller for rate limiting.
//
// X-Forwarded-For is honoured only when the deployment says it is behind a
// proxy. Trusting it unconditionally would let any caller spoof a fresh
// identity per request and make the limiter decorative.
func clientKey(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			if first = strings.TrimSpace(first); first != "" {
				return first
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
