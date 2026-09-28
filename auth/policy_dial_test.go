// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
)

// recordingDial answers every dial with a closed pipe and remembers where
// it was asked to connect; fail makes the listed addresses refuse.
type recordingDial struct {
	got  []string
	fail map[string]bool
}

func (r *recordingDial) dial(_ context.Context, _, addr string) (net.Conn, error) {
	r.got = append(r.got, addr)
	if r.fail[addr] {
		return nil, errors.New("refused")
	}
	c, s := net.Pipe()
	_ = s.Close()
	return c, nil
}

func fixed(ips ...string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		out := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestDialContextConnectsToTheAddressesItChecked(t *testing.T) {
	r := &recordingDial{}
	d := URLPolicy{Resolver: fixed("8.8.8.8", "1.1.1.1")}.DialContext(r.dial)
	c, err := d(context.Background(), "tcp", "as.example:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = c.Close()
	if len(r.got) != 1 || r.got[0] != "8.8.8.8:443" {
		t.Fatalf("dialled %v; want the checked address, never the name", r.got)
	}

	r = &recordingDial{fail: map[string]bool{"8.8.8.8:443": true}}
	d = URLPolicy{Resolver: fixed("8.8.8.8", "1.1.1.1")}.DialContext(r.dial)
	if c, err := d(context.Background(), "tcp", "as.example:443"); err != nil {
		t.Fatalf("the second checked address should be tried: %v", err)
	} else {
		_ = c.Close()
	}
	if strings.Join(r.got, ",") != "8.8.8.8:443,1.1.1.1:443" {
		t.Fatalf("dialled %v", r.got)
	}
}

func TestDialContextRefusesAnyNonPublicAnswer(t *testing.T) {
	r := &recordingDial{}
	d := URLPolicy{Resolver: fixed("8.8.8.8", "10.0.0.5")}.DialContext(r.dial)
	_, err := d(context.Background(), "tcp", "as.example:443")
	var pe *PolicyError
	if !errors.As(err, &pe) || !strings.Contains(pe.Reason, "10.0.0.5") || !strings.Contains(pe.Reason, "at connect time") {
		t.Fatalf("want a policy error naming the private answer, got %v", err)
	}
	if len(r.got) != 0 {
		t.Fatalf("nothing may be dialled once an answer is private: %v", r.got)
	}
}

func TestDialContextLeavesTheOperatorsOwnHostsAlone(t *testing.T) {
	resolveCalled := false
	pol := URLPolicy{Resolver: func(context.Context, string) ([]net.IP, error) {
		resolveCalled = true
		return nil, errors.New("must not resolve")
	}}
	for name, tc := range map[string]struct {
		pol     URLPolicy
		addr    string
		trusted []string
	}{
		"trusted host, any case": {pol, "MCP.Internal:443", []string{"mcp.internal"}},
		"loopback name":          {pol, "localhost:8080", nil},
		"loopback address":       {pol, "127.0.0.1:8080", nil},
		"private allowed":        {URLPolicy{AllowPrivate: true, Resolver: pol.Resolver}, "as.example:443", nil},
		"no port":                {pol, "as.example", nil},
	} {
		r := &recordingDial{}
		c, err := tc.pol.DialContext(r.dial, tc.trusted...)(context.Background(), "tcp", tc.addr)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		_ = c.Close()
		if len(r.got) != 1 || r.got[0] != tc.addr {
			t.Errorf("%s: dialled %v, want %s as given", name, r.got, tc.addr)
		}
	}
	if resolveCalled {
		t.Error("an operator's own host was resolved by the policy")
	}
}

func TestDialContextReportsWhatStoppedIt(t *testing.T) {
	boom := errors.New("no such host")
	d := URLPolicy{Resolver: func(context.Context, string) ([]net.IP, error) { return nil, boom }}.DialContext(nil)
	if _, err := d(context.Background(), "tcp", "as.example:443"); !errors.Is(err, boom) {
		t.Errorf("a resolution failure is returned: %v", err)
	}
	r := &recordingDial{}
	d = URLPolicy{Resolver: fixed()}.DialContext(r.dial)
	if _, err := d(context.Background(), "tcp", "as.example:443"); err == nil || !strings.Contains(err.Error(), "no address") {
		t.Errorf("a name with no addresses is an error: %v", err)
	}
	r = &recordingDial{fail: map[string]bool{"8.8.8.8:443": true}}
	d = URLPolicy{Resolver: fixed("8.8.8.8")}.DialContext(r.dial)
	if _, err := d(context.Background(), "tcp", "as.example:443"); err == nil || err.Error() != "refused" {
		t.Errorf("the last dial error is returned: %v", err)
	}
}

func TestTransportUsesTheGuardedDialer(t *testing.T) {
	tr := URLPolicy{Resolver: fixed("192.168.1.9")}.Transport(nil)
	if tr.DialContext == nil {
		t.Fatal("no dialer installed")
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "as.example:443"); err == nil {
		t.Fatal("the transport's dialer must apply the policy")
	}
}

func TestEndpointTransportTrustsTheEndpointAndTheProxy(t *testing.T) {
	// Lower case cleared first: on Windows the two spellings are one
	// variable, so clearing it after would erase the value just set.
	t.Setenv("https_proxy", "")
	t.Setenv("http_proxy", "")
	t.Setenv("HTTPS_PROXY", "proxy.corp:3128") // no scheme, as Go accepts
	t.Setenv("HTTP_PROXY", "http://other.corp:8080")
	got := envProxyHosts()
	if strings.Join(got, ",") != "proxy.corp,other.corp" {
		t.Fatalf("proxy hosts = %v", got)
	}
	private := func(context.Context, string) ([]net.IP, error) { return []net.IP{net.ParseIP("10.0.0.1")}, nil }
	tr := URLPolicy{Resolver: private}.EndpointTransport("https://mcp.internal/mcp")
	for _, addr := range []string{"mcp.internal:443", "proxy.corp:3128"} {
		// Trusted hosts go to the real dialer; with nothing listening the
		// dial fails, but not on the policy.
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := tr.DialContext(ctx, "tcp", addr)
		var pe *PolicyError
		if errors.As(err, &pe) {
			t.Errorf("%s was refused by the policy: %v", addr, err)
		}
	}
	if _, err := tr.DialContext(context.Background(), "tcp", "as.example:443"); err == nil {
		t.Error("a discovered host resolving to a private address must be refused")
	}
	if tr := (URLPolicy{}).EndpointTransport("::not a url"); tr.DialContext == nil {
		t.Error("an unparsable endpoint still gets a guarded transport")
	}
}
