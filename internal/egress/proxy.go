// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package egress watches where a server goes when nobody is looking.
//
// A server that quietly posts your tool arguments to a third host passes
// every other check passmcp has. The recorder logs the connections passmcp
// makes, not the ones the server makes, and no amount of reading a
// catalogue reveals a destination — the whole point of the behaviour is
// that it is not declared anywhere.
//
// You do not need a packet capture to see where a subprocess dials. You
// need to be the thing it dials through. Once passmcp starts the process it
// also owns the process's environment, and every HTTP client in every
// language honours HTTP_PROXY, HTTPS_PROXY and NO_PROXY. Pointing those at
// a loopback listener passmcp runs turns an invisible connection into a line
// in a log, with no packet capture, no root, and no certificate games:
// CONNECT hands over the hostname in clear text before any TLS begins, and
// the hostname is the part that matters.
//
// This only works over stdio, and that is not a limitation so much as the
// reason milestone 1 came first. An HTTP server passmcp did not start has an
// environment passmcp never set.
//
// Two things it does not see, stated here because a witness whose blind
// spots are undocumented is worse than none.
//
// A destination on the same machine is invisible. Go's
// ProxyFromEnvironment exempts "localhost" by name and every loopback
// address by rule, and most other runtimes do the same, so a server
// talking to something already on the host bypasses this entirely. That is
// the right trade for what this is for: the threat is data leaving the
// machine, and a proxy that intercepted loopback would break every server
// that talks to a sidecar.
//
// A client that ignores the environment is also invisible — one dialling a
// raw socket, or a runtime that reads proxy settings from a config file.
// The roadmap's answer to that is the second half of this milestone, a
// loopback resolver: a process that asks passmcp's DNS and then connects
// somewhere the proxy never saw has told you something louder than the
// destination would have.
package egress

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"
)

// Dial is one destination a server reached for, and how often.
type Dial struct {
	// Host is the destination, without a port.
	Host string `json:"host"`
	// Port is where it was headed. 443 and 80 are the ordinary ones; a
	// third is worth a reader's attention on its own.
	Port string `json:"port"`
	// Tunnelled is true when the request was a CONNECT, which is what a
	// client does for https and is therefore the common case.
	Tunnelled bool `json:"tunnelled"`
	// Count is how many times.
	Count int `json:"count"`
	// First is when it was first seen, relative to the proxy starting.
	First time.Duration `json:"first_ms"`
	// Allowed is whether the connection was permitted to proceed.
	Allowed bool `json:"allowed"`
	// Failed counts attempts the proxy answered as an unreachable upstream
	// because the run asked it to (--fault-upstream), not because policy
	// refused them.
	Failed int `json:"failed,omitempty"`
}

// Target renders the destination as host:port.
func (d Dial) Target() string { return net.JoinHostPort(d.Host, d.Port) }

// Policy decides what happens to a connection once it has been seen.
type Policy func(host, port string) bool

// AllowAll permits every destination.
//
// The default, and deliberately so. passmcp is a diagnostic: its job here is
// to say where a server went, not to prevent it going. Blocking by default
// would also break every server that legitimately calls an upstream API
// and turn that into findings about passmcp rather than about the server.
func AllowAll(string, string) bool { return true }

// Proxy is a loopback HTTP proxy that records what passes through it.
type Proxy struct {
	ln    net.Listener
	srv   *http.Server
	start time.Time

	policy Policy

	mu      sync.Mutex
	failing chan struct{} // non-nil while failing; closed to release the held
	failed  int
	dials   map[string]*Dial
	watch   []string
	escaped map[string]string // marker -> the destination it left for
}

// dialTimeout bounds a connection to an upstream the server named. It is
// not the server's own timeout: it stops a hostile destination from
// holding a goroutine here for the length of the run.
const dialTimeout = 30 * time.Second

// Start brings up a proxy on loopback.
func Start(policy Policy) (*Proxy, error) {
	if policy == nil {
		policy = AllowAll
	}
	// Loopback only. A proxy reachable from off the machine would be an
	// open relay, which is a considerably worse thing to leave running
	// than anything it exists to detect.
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("egress: listen: %w", err)
	}
	p := &Proxy{
		ln:      ln,
		start:   time.Now(),
		policy:  policy,
		dials:   map[string]*Dial{},
		escaped: map[string]string{},
	}
	p.srv = &http.Server{
		Handler:           http.HandlerFunc(p.serve),
		ReadHeaderTimeout: 30 * time.Second,
	}
	go func() { _ = p.srv.Serve(ln) }()
	return p, nil
}

// Addr is where the proxy is listening, as a URL a client will accept.
func (p *Proxy) Addr() string { return "http://" + p.ln.Addr().String() }

// Env is what to put in the child's environment so it dials through here.
//
// Both cases of each name, because the convention is not a standard: curl
// reads the lower-case forms, Go's net/http reads either, and a handful of
// libraries only look at upper-case. Setting all of them is the only way
// to be sure the observation is not simply missed.
func (p *Proxy) Env() []string {
	a := p.Addr()
	return []string{
		"HTTP_PROXY=" + a, "http_proxy=" + a,
		"HTTPS_PROXY=" + a, "https_proxy=" + a,
		// Empty rather than absent: a NO_PROXY inherited from the
		// operator's shell would carve a hole in the observation, and the
		// child's environment is constructed rather than inherited
		// precisely so that cannot happen.
		"NO_PROXY=", "no_proxy=",
	}
}

// Dials returns what was seen, ordered by first appearance so a reader
// follows the run rather than an alphabet.
func (p *Proxy) Dials() []Dial {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]Dial, 0, len(p.dials))
	for _, d := range p.dials {
		out = append(out, *d)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].First < out[j].First })
	return out
}

// Close stops the proxy.
func (p *Proxy) Close() error {
	// Held connections first, or shutdown would wait on them.
	p.SetFailing(false)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	err := p.srv.Shutdown(ctx)
	if errors.Is(err, context.DeadlineExceeded) {
		return p.srv.Close()
	}
	return err
}

// record notes one dial and answers whether it may proceed.
func (p *Proxy) record(host, port string, tunnelled bool) bool {
	allowed := p.policy(host, port)
	key := host + ":" + port
	p.mu.Lock()
	defer p.mu.Unlock()
	d, ok := p.dials[key]
	if !ok {
		d = &Dial{
			Host: host, Port: port, Tunnelled: tunnelled,
			First: time.Since(p.start).Round(time.Millisecond), Allowed: allowed,
		}
		p.dials[key] = d
	}
	d.Count++
	// One refusal makes the whole destination refused, because that is the
	// fact a reader needs: this host was stopped.
	if !allowed {
		d.Allowed = false
	}
	return allowed
}

// SetFailing makes every later connection behave as an upstream that
// accepted it and never answered, until it is switched off. It is how a
// run asks what a server does when a dependency is down, without touching
// the server.
//
// A hung upstream rather than a refused one, because it is the harder
// case: a refusal comes back at once and nearly every client turns it into
// an error, while a connection that never answers finds exactly the
// clients with no timeout of their own. A held connection is answered 502
// when the client gives up or the fault is lifted.
func (p *Proxy) SetFailing(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	switch {
	case on && p.failing == nil:
		p.failing = make(chan struct{})
	case !on && p.failing != nil:
		close(p.failing)
		p.failing = nil
	}
}

// Failed counts the connections failed on purpose so far.
func (p *Proxy) Failed() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.failed
}

// fail holds a connection as a hung upstream would when the run asked for
// that, after it has been recorded.
func (p *Proxy) fail(w http.ResponseWriter, r *http.Request, host, port string) bool {
	p.mu.Lock()
	release := p.failing
	if release == nil {
		p.mu.Unlock()
		return false
	}
	p.failed++
	if d, ok := p.dials[host+":"+port]; ok {
		d.Failed++
	}
	p.mu.Unlock()
	select {
	case <-r.Context().Done():
	case <-release:
	}
	http.Error(w, "upstream unavailable (failed on purpose by passmcp --fault-upstream)", http.StatusBadGateway)
	return true
}

// WatchFor asks the proxy to notice these strings in outbound request
// bodies.
//
// Only on the plain path. A CONNECT tunnel is opaque on purpose: passmcp
// reads the destination out of the request line and never the payload,
// because the alternative is a certificate authority on the operator's
// machine and a diagnostic that decrypts traffic it was not asked to
// decrypt. So a marker leaving over https is seen as a destination and
// not as a theft — which is why the canary has a second witness that does
// not depend on this one.
func (p *Proxy) WatchFor(markers []string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.watch = append(p.watch, markers...)
}

// Escaped reports which watched strings were seen leaving, and where to.
func (p *Proxy) Escaped() map[string]string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make(map[string]string, len(p.escaped))
	for k, v := range p.escaped {
		out[k] = v
	}
	return out
}

// bodyScanLimit bounds how much of a request body is held in memory to
// look at. A server sending more than this to exfiltrate a key is doing
// something stranger than exfiltrating a key.
const bodyScanLimit = 1 << 20 // 1 MiB

// scan looks for the watched strings and records any that are leaving.
func (p *Proxy) scan(body []byte, target string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.watch) == 0 {
		return
	}
	s := string(body)
	for _, m := range p.watch {
		if strings.Contains(s, m) {
			if _, seen := p.escaped[m]; !seen {
				p.escaped[m] = target
			}
		}
	}
}

func (p *Proxy) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodConnect {
		p.connect(w, r)
		return
	}
	p.forward(w, r)
}

// connect handles the tunnel a client opens for https.
//
// The hostname arrives in the request line, in clear text, before any TLS
// handshake — which is why this needs no certificate authority and does no
// interception. passmcp learns where the server went and reads nothing it
// sent.
func (p *Proxy) connect(w http.ResponseWriter, r *http.Request) {
	host, port := splitTarget(r.Host, "443")
	if !p.record(host, port, true) {
		http.Error(w, "refused by passmcp's egress policy", http.StatusForbidden)
		return
	}
	if p.fail(w, r, host, port) {
		return
	}

	// The destination comes from the request, which is exactly the point:
	// this is a proxy, and forwarding to the host the client named is its
	// entire function. gosec reads that as SSRF because in almost any
	// other program it would be. What makes it safe here is that the
	// client is a process passmcp started, the proxy is bound to loopback so
	// nothing else can reach it, and every destination is recorded before
	// this line runs and reported afterwards — the connection is the
	// finding rather than a side effect nobody sees.
	// The request's context, so a client that gives up takes the dial with
	// it rather than leaving it to the timeout.
	d := net.Dialer{Timeout: dialTimeout}
	upstream, err := d.DialContext(r.Context(), "tcp", net.JoinHostPort(host, port)) //nolint:gosec // G704: forwarding to the named host is what a proxy does; see above
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = upstream.Close() }()

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "cannot tunnel", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer func() { _ = client.Close() }()

	if _, err := io.WriteString(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	// Copy both ways until either end goes. Nothing is inspected: the
	// bytes are the server's business and the hostname was the finding.
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); _, _ = io.Copy(upstream, client) }()
	go func() { defer wg.Done(); _, _ = io.Copy(client, upstream) }()
	wg.Wait()
}

// forward handles a plain http request, which a proxy receives in
// absolute form.
func (p *Proxy) forward(w http.ResponseWriter, r *http.Request) {
	if r.URL == nil || r.URL.Host == "" {
		http.Error(w, "not a proxy request", http.StatusBadRequest)
		return
	}
	host, port := splitTarget(r.URL.Host, "80")
	if !p.record(host, port, false) {
		http.Error(w, "refused by passmcp's egress policy", http.StatusForbidden)
		return
	}
	if p.fail(w, r, host, port) {
		return
	}

	// Read it once, look at it, and put it back. A proxy that consumed the
	// body would break the request it exists to observe.
	if r.Body != nil && len(p.watch) > 0 {
		body, err := io.ReadAll(io.LimitReader(r.Body, bodyScanLimit))
		_ = r.Body.Close()
		if err == nil {
			p.scan(body, net.JoinHostPort(host, port))
			r.Body = io.NopCloser(bytes.NewReader(body))
			r.ContentLength = int64(len(body))
		}
	}

	out := r.Clone(r.Context())
	out.RequestURI = ""
	out.URL = &url.URL{
		Scheme: "http", Host: r.URL.Host,
		Path: r.URL.Path, RawQuery: r.URL.RawQuery,
	}
	// No proxy of our own, or this would consult the environment passmcp
	// just set and dial itself.
	client := &http.Client{
		Timeout:   dialTimeout,
		Transport: &http.Transport{Proxy: nil},
	}
	// Same as the CONNECT path: the destination is the client's, and
	// recording it is why this exists. See the note in connect.
	resp, err := client.Do(out) //nolint:gosec // G704: forwarding to the named host is what a proxy does
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer func() { _ = resp.Body.Close() }()

	for k, vs := range resp.Header {
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// splitTarget separates host and port, defaulting the port.
func splitTarget(target, fallback string) (host, port string) {
	target = strings.TrimSpace(target)
	if h, p, err := net.SplitHostPort(target); err == nil {
		return h, p
	}
	return target, fallback
}
