// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package egress

import (
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// proxyClient is a client that dials through the proxy, the way a server
// reading HTTP_PROXY out of its environment would.
func proxyClient(t *testing.T, p *Proxy) *http.Client {
	t.Helper()
	u, err := url.Parse(p.Addr())
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &http.Transport{
			Proxy: http.ProxyURL(u),
			// The fixture upstreams are httptest TLS servers with their
			// own certificate. Nothing here inspects the tunnel; this is
			// so the fixture can complete a handshake through it.
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // a test fixture's self-signed certificate
		},
	}
}

func startProxy(t *testing.T, policy Policy) *Proxy {
	t.Helper()
	p, err := Start(policy)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close() })
	return p
}

// TestProxyRecordsAPlainRequest: a plain http call arrives in absolute
// form and names its destination in the request line.
func TestProxyRecordsAPlainRequest(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "hello")
	}))
	defer upstream.Close()

	p := startProxy(t, nil)
	res, err := proxyClient(t, p).Get(upstream.URL + "/thing")
	if err != nil {
		t.Fatalf("through the proxy: %v", err)
	}
	defer func() { _ = res.Body.Close() }()
	body, _ := io.ReadAll(res.Body)
	if string(body) != "hello" {
		t.Errorf("the response did not survive the proxy: %q", body)
	}

	dials := p.Dials()
	if len(dials) != 1 {
		t.Fatalf("want one destination, got %+v", dials)
	}
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "http://"))
	if dials[0].Host != host || dials[0].Port != port {
		t.Errorf("recorded %s, want %s:%s", dials[0].Target(), host, port)
	}
	if dials[0].Tunnelled {
		t.Error("a plain request is not a tunnel")
	}
	if !dials[0].Allowed {
		t.Error("the default policy should allow")
	}
}

// TestProxyRecordsATunnelWithoutReadingIt is the case that matters. An
// https destination arrives as CONNECT, in clear text, before any
// handshake — so the hostname is knowable with no certificate authority
// and no interception of what was actually sent.
func TestProxyRecordsATunnelWithoutReadingIt(t *testing.T) {
	const secret = "the-body-nobody-should-read"
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		if string(b) != secret {
			t.Errorf("the tunnelled body was altered: %q", b)
		}
		_, _ = io.WriteString(w, "ok")
	}))
	defer upstream.Close()

	p := startProxy(t, nil)
	res, err := proxyClient(t, p).Post(upstream.URL, "text/plain", strings.NewReader(secret))
	if err != nil {
		t.Fatalf("through the tunnel: %v", err)
	}
	defer func() { _ = res.Body.Close() }()

	dials := p.Dials()
	if len(dials) != 1 {
		t.Fatalf("want one destination, got %+v", dials)
	}
	if !dials[0].Tunnelled {
		t.Error("an https destination should be recorded as a tunnel")
	}
	host, port, _ := net.SplitHostPort(strings.TrimPrefix(upstream.URL, "https://"))
	if dials[0].Host != host || dials[0].Port != port {
		t.Errorf("recorded %s, want %s:%s", dials[0].Target(), host, port)
	}
}

// TestProxyCountsRepeats, so a report can say a destination was reached
// once or four hundred times.
func TestProxyCountsRepeats(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	p := startProxy(t, nil)
	c := proxyClient(t, p)
	for range 3 {
		res, err := c.Get(upstream.URL)
		if err != nil {
			t.Fatal(err)
		}
		_ = res.Body.Close()
	}
	dials := p.Dials()
	if len(dials) != 1 || dials[0].Count != 3 {
		t.Fatalf("want one destination counted 3 times, got %+v", dials)
	}
}

// TestProxyRefusesByPolicy: observing is the default, but a policy that
// says no has to actually stop the connection, not merely note it.
func TestProxyRefusesByPolicy(t *testing.T) {
	var reached bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
	}))
	defer upstream.Close()

	p := startProxy(t, func(string, string) bool { return false })
	res, err := proxyClient(t, p).Get(upstream.URL)
	if err == nil {
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusForbidden {
			t.Errorf("status %d, want 403", res.StatusCode)
		}
	}
	if reached {
		t.Error("a refused destination was reached anyway")
	}

	dials := p.Dials()
	if len(dials) != 1 {
		t.Fatalf("a refusal must still be recorded: %+v", dials)
	}
	if dials[0].Allowed {
		t.Error("the refusal was not recorded as one")
	}
}

// TestProxyEnvSetsBothCases: the variable name is a convention rather than
// a standard, and a library that reads only one spelling would otherwise
// slip past the observation entirely.
func TestProxyEnvSetsBothCases(t *testing.T) {
	p := startProxy(t, nil)
	env := strings.Join(p.Env(), "\n")
	for _, name := range []string{
		"HTTP_PROXY=", "http_proxy=", "HTTPS_PROXY=", "https_proxy=",
	} {
		if !strings.Contains(env, name+p.Addr()) {
			t.Errorf("%s is not pointed at the proxy:\n%s", name, env)
		}
	}
	// An inherited NO_PROXY would carve a hole in the observation.
	for _, name := range []string{"NO_PROXY=", "no_proxy="} {
		if !strings.Contains(env, name+"\n") && !strings.HasSuffix(env, name) {
			t.Errorf("%s is not neutralised:\n%s", name, env)
		}
	}
}

// TestProxyListensOnLoopbackOnly. A proxy reachable from off the machine
// is an open relay, which is worse than anything it exists to detect.
func TestProxyListensOnLoopbackOnly(t *testing.T) {
	p := startProxy(t, nil)
	host, _, err := net.SplitHostPort(strings.TrimPrefix(p.Addr(), "http://"))
	if err != nil {
		t.Fatal(err)
	}
	if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
		t.Errorf("listening on %q, want loopback", host)
	}
}

// TestProxyReportsAnUnreachableUpstream rather than hanging or pretending
// the connection succeeded.
func TestProxyReportsAnUnreachableUpstream(t *testing.T) {
	p := startProxy(t, nil)
	res, err := proxyClient(t, p).Get("http://127.0.0.1:1/nothing")
	if err == nil {
		defer func() { _ = res.Body.Close() }()
		if res.StatusCode != http.StatusBadGateway {
			t.Errorf("status %d, want 502", res.StatusCode)
		}
	}
	// It was still an attempt, and the attempt is the finding.
	if len(p.Dials()) != 1 {
		t.Errorf("a failed dial must still be recorded: %+v", p.Dials())
	}
}

// TestProxyCloseIsIdempotent, because it runs on a defer.
func TestProxyCloseIsIdempotent(t *testing.T) {
	p, err := Start(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Close(); err != nil {
		t.Fatalf("first close: %v", err)
	}
	_ = p.Close()
}

// TestSplitTargetDefaultsThePort.
func TestSplitTargetDefaultsThePort(t *testing.T) {
	for _, tc := range []struct{ in, fb, host, port string }{
		{"example.com:8443", "443", "example.com", "8443"},
		{"example.com", "443", "example.com", "443"},
		{"example.com", "80", "example.com", "80"},
		{" example.com ", "80", "example.com", "80"},
	} {
		h, p := splitTarget(tc.in, tc.fb)
		if h != tc.host || p != tc.port {
			t.Errorf("splitTarget(%q, %q) = %q, %q; want %q, %q", tc.in, tc.fb, h, p, tc.host, tc.port)
		}
	}
}

// TestProxyNoticesAWatchedStringLeaving is the canary's wire-side
// witness: a marker that exists nowhere else, seen in a body on its way
// out.
func TestProxyNoticesAWatchedStringLeaving(t *testing.T) {
	const marker = "passmcp-canary-deadbeef"
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
	}))
	defer upstream.Close()

	p := startProxy(t, nil)
	p.WatchFor([]string{marker})

	body := "-----BEGIN OPENSSH PRIVATE KEY-----\n" + marker + "\n"
	res, err := proxyClient(t, p).Post(upstream.URL, "text/plain", strings.NewReader(body))
	if err != nil {
		t.Fatalf("through the proxy: %v", err)
	}
	_ = res.Body.Close()

	// The body must arrive unchanged: a proxy that consumed it would
	// break the request it exists to observe.
	if received != body {
		t.Errorf("the body did not survive the scan:\n got %q\nwant %q", received, body)
	}

	escaped := p.Escaped()
	where, ok := escaped[marker]
	if !ok {
		t.Fatalf("the marker was not seen leaving: %+v", escaped)
	}
	if !strings.Contains(where, "127.0.0.1") {
		t.Errorf("the escape does not say where it went: %q", where)
	}
}

// TestProxyIgnoresBodiesWhenNothingIsWatched, so an ordinary run pays
// nothing for a feature it did not ask for.
func TestProxyIgnoresBodiesWhenNothingIsWatched(t *testing.T) {
	var received string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		received = string(b)
	}))
	defer upstream.Close()

	p := startProxy(t, nil)
	res, err := proxyClient(t, p).Post(upstream.URL, "text/plain", strings.NewReader("hello"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	if received != "hello" {
		t.Errorf("the body did not survive: %q", received)
	}
	if len(p.Escaped()) != 0 {
		t.Errorf("nothing was watched, yet something escaped: %+v", p.Escaped())
	}
}

// TestProxyDoesNotReportAMarkerThatDidNotLeave.
func TestProxyDoesNotReportAMarkerThatDidNotLeave(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()

	p := startProxy(t, nil)
	p.WatchFor([]string{"passmcp-canary-never-sent"})

	res, err := proxyClient(t, p).Post(upstream.URL, "text/plain", strings.NewReader("ordinary traffic"))
	if err != nil {
		t.Fatal(err)
	}
	_ = res.Body.Close()

	if len(p.Escaped()) != 0 {
		t.Errorf("a marker that never left was reported: %+v", p.Escaped())
	}
}

// TestEscapedIsACopy, so a caller cannot mutate what the proxy recorded.
func TestEscapedIsACopy(t *testing.T) {
	p := startProxy(t, nil)
	p.scan([]byte("x marker y"), "example.com:443")
	p.WatchFor([]string{"marker"})
	p.scan([]byte("x marker y"), "example.com:443")

	got := p.Escaped()
	if len(got) != 1 {
		t.Fatalf("want one escape, got %+v", got)
	}
	got["marker"] = "tampered"
	if p.Escaped()["marker"] == "tampered" {
		t.Error("Escaped handed out the proxy's own map")
	}
}

// TestScanRecordsTheFirstDestinationOnly: a marker leaving twice is one
// leak, and the first place it went is the one worth reporting.
func TestScanRecordsTheFirstDestinationOnly(t *testing.T) {
	p := startProxy(t, nil)
	p.WatchFor([]string{"m"})
	p.scan([]byte("m"), "first.example:443")
	p.scan([]byte("m"), "second.example:443")
	if got := p.Escaped()["m"]; got != "first.example:443" {
		t.Errorf("recorded %q, want the first destination", got)
	}
}

// A failing proxy holds a connection as a hung upstream would — for a
// tunnel and for a plain request — and answers 502 once the fault is
// lifted, counting each one.
func TestProxyHoldsConnectionsWhileFailing(t *testing.T) {
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Error("a failing proxy reached the upstream")
	}))
	defer upstream.Close()
	p := startProxy(t, nil)
	p.SetFailing(true)
	p.SetFailing(true) // idempotent: one fault, not two

	type result struct {
		status int
		err    error
	}
	done := make(chan result, 2)
	for _, target := range []string{upstream.URL, "http://plain.passmcp-fixture.invalid/x"} {
		go func() {
			res, err := proxyClient(t, p).Get(target) //nolint:noctx // bounded by the client timeout
			if err != nil {
				done <- result{err: err}
				return
			}
			_ = res.Body.Close()
			done <- result{status: res.StatusCode}
		}()
	}
	deadline := time.Now().Add(5 * time.Second)
	for p.Failed() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	select {
	case r := <-done:
		t.Fatalf("a held connection came back before the fault was lifted: %+v", r)
	case <-time.After(200 * time.Millisecond):
	}
	p.SetFailing(false)
	p.SetFailing(false)
	for i := 0; i < 2; i++ {
		r := <-done
		// A refused CONNECT surfaces as an error from the client; a plain
		// request as the 502 itself.
		if r.err == nil && r.status != http.StatusBadGateway {
			t.Errorf("released with %+v, want a 502", r)
		}
	}
	if p.Failed() != 2 {
		t.Errorf("failed %d, want 2", p.Failed())
	}
	var failed int
	for _, d := range p.Dials() {
		failed += d.Failed
	}
	if failed != 2 {
		t.Errorf("dials record %d failures, want 2: %+v", failed, p.Dials())
	}
}

// Closing lifts the fault, so shutdown does not wait on held connections.
func TestProxyCloseReleasesHeldConnections(t *testing.T) {
	p, err := Start(nil)
	if err != nil {
		t.Fatal(err)
	}
	p.SetFailing(true)
	go func() {
		res, err := proxyClient(t, p).Get("http://held.passmcp-fixture.invalid/") //nolint:noctx // bounded by the client timeout
		if err == nil {
			_ = res.Body.Close()
		}
	}()
	for p.Failed() == 0 {
		time.Sleep(10 * time.Millisecond)
	}
	t0 := time.Now()
	if err := p.Close(); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(t0); d > time.Second {
		t.Errorf("close waited %s on a held connection", d)
	}
}
