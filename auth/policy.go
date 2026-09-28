// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// URLPolicy decides whether a URL learned from a remote document may be
// fetched or sent credentials.
//
// Every endpoint in the OAuth chain after the operator's own is
// server-controlled: authorization_servers comes from the resource,
// token_endpoint and registration_endpoint come from the authorization
// server, and the resource_metadata hint comes from a response header. A
// client that follows them unchecked will exchange its client secret with
// whatever host the resource names, including a plaintext one or a cloud
// metadata address reachable from the CI runner passmcp is running on.
//
// The zero value is the strict policy: HTTPS only, public hosts only.
type URLPolicy struct {
	// AllowHTTP permits http:// URLs. Loopback is always permitted so a
	// local development authorization server keeps working.
	AllowHTTP bool
	// AllowPrivate permits hosts that resolve to loopback, link-local,
	// private or otherwise non-public addresses.
	AllowPrivate bool
	// Resolver is used to resolve hostnames; nil means the default resolver.
	Resolver func(ctx context.Context, host string) ([]net.IP, error)
}

// PolicyError explains why a discovered URL was refused.
type PolicyError struct {
	Kind   string // "authorization server", "token endpoint", ...
	URL    string
	Reason string
}

func (e *PolicyError) Error() string {
	return fmt.Sprintf("auth: refusing %s %q: %s", e.Kind, e.URL, e.Reason)
}

// Validate checks a URL discovered from a remote document. kind names the
// field for the error message.
func (p URLPolicy) Validate(ctx context.Context, kind, raw string) error {
	deny := func(reason string) error { return &PolicyError{Kind: kind, URL: raw, Reason: reason} }
	if raw == "" {
		return deny("empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return deny("not a URL: " + err.Error())
	}
	if u.Host == "" {
		return deny("not absolute")
	}
	scheme := strings.ToLower(u.Scheme)
	host := u.Hostname()
	loopback := isLoopbackHost(host)
	switch scheme {
	case "https":
	case "http":
		if !p.AllowHTTP && !loopback {
			return deny("must use https; a token or client secret sent here would cross the network in the clear")
		}
	default:
		return deny("scheme " + scheme + " is not http(s)")
	}
	if u.Fragment != "" {
		return deny("must not carry a fragment")
	}
	if p.AllowPrivate || loopback {
		return nil
	}
	ips, err := p.resolve(ctx, host)
	if err != nil {
		// A name that does not resolve is not a policy failure; the fetch
		// will fail on its own and say so more clearly than this could.
		return nil //nolint:nilerr // deliberate: resolution failure is not a refusal
	}
	for _, ip := range ips {
		if !isPublicIP(ip) {
			return deny(fmt.Sprintf("resolves to the non-public address %s; discovered endpoints must not point inside the network passmcp runs in (pass --insecure-allow-private-hosts if this is deliberate)", ip))
		}
	}
	return nil
}

// DialFunc makes a network connection, as net.Dialer.DialContext does.
type DialFunc func(ctx context.Context, network, addr string) (net.Conn, error)

// DialContext wraps dial so the policy holds for the connection itself,
// not only for the URL checked before it.
//
// Validate resolves a host to decide whether it is public; a connection by
// name resolves it again, and a server that controls its own DNS can
// answer the two lookups differently (DNS rebinding): public for the check,
// internal for the connection. The wrapped dialer resolves once, refuses
// the host if any answer is not public, and connects to exactly the
// addresses it checked.
//
// Hosts in trusted are the operator's own (the endpoint they named, a
// proxy from the environment) and are dialled as given, as are loopback
// hosts; with AllowPrivate every host is. dial nil means a net.Dialer.
func (p URLPolicy) DialContext(dial DialFunc, trusted ...string) DialFunc {
	if dial == nil {
		dial = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(addr)
		if err != nil || p.AllowPrivate || isLoopbackHost(host) || containsFold(trusted, host) {
			return dial(ctx, network, addr)
		}
		ips, err := p.resolve(ctx, host)
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if !isPublicIP(ip) {
				return nil, &PolicyError{Kind: "connection", URL: addr, Reason: fmt.Sprintf("resolves to the non-public address %s at connect time; discovered endpoints must not point inside the network passmcp runs in (pass --insecure-allow-private-hosts if this is deliberate)", ip)}
			}
		}
		return dialFirst(ctx, dial, network, port, host, ips)
	}
}

// dialFirst connects to the first of ips that answers.
func dialFirst(ctx context.Context, dial DialFunc, network, port, host string, ips []net.IP) (net.Conn, error) {
	err := fmt.Errorf("auth: %s resolves to no address", host)
	for _, ip := range ips {
		var c net.Conn
		if c, err = dial(ctx, network, net.JoinHostPort(ip.String(), port)); err == nil {
			return c, nil
		}
	}
	return nil, err
}

// Transport is a clone of http.DefaultTransport whose connections pass
// through DialContext(dial, trusted...). A proxy the environment names is
// trusted too: the transport connects to it for every request, the
// operator chose it, and name resolution then happens at the proxy, where
// passmcp cannot see it.
func (p URLPolicy) Transport(dial DialFunc, trusted ...string) *http.Transport {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.DialContext = p.DialContext(dial, append(envProxyHosts(), trusted...)...)
	return t
}

// EndpointTransport is Transport trusting only endpoint's own host: the
// transport for a client the operator pointed at endpoint, every other
// host of which was learned from a remote document.
func (p URLPolicy) EndpointTransport(endpoint string) *http.Transport {
	host := ""
	if u, err := url.Parse(endpoint); err == nil {
		host = u.Hostname()
	}
	return p.Transport(nil, host)
}

// envProxyHosts are the hosts of the proxies the environment names.
func envProxyHosts() []string {
	var out []string
	for _, k := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		v := os.Getenv(k)
		if v == "" {
			continue
		}
		if !strings.Contains(v, "://") {
			v = "http://" + v
		}
		// Windows reads HTTPS_PROXY and https_proxy as one variable.
		if u, err := url.Parse(v); err == nil && u.Hostname() != "" && !containsFold(out, u.Hostname()) {
			out = append(out, u.Hostname())
		}
	}
	return out
}

func containsFold(list []string, s string) bool {
	for _, v := range list {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func (p URLPolicy) resolve(ctx context.Context, host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return []net.IP{ip}, nil
	}
	if p.Resolver != nil {
		return p.Resolver(ctx, host)
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	out := make([]net.IP, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, a.IP)
	}
	return out, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback()
	}
	return false
}

// isPublicIP reports whether ip is routable on the public internet. The
// cloud metadata addresses (169.254.169.254, fd00:ec2::254) are link-local
// and unique-local respectively, so they are covered.
func isPublicIP(ip net.IP) bool {
	if isStdlibNonPublic(ip) {
		return false
	}
	return !isSpecialV4(ip)
}

// isStdlibNonPublic covers every non-routable class the stdlib names.
func isStdlibNonPublic(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast()
}

// isSpecialV4 reports the IPv4 ranges that are not public but that the
// stdlib predicates do not cover.
func isSpecialV4(ip net.IP) bool {
	// Carrier-grade NAT (RFC 6598) and IPv4 benchmarking ranges are not
	// covered by the stdlib predicates.
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 100 && v4[1]&0xc0 == 64: // 100.64.0.0/10
			return true
		case v4[0] == 198 && v4[1]&0xfe == 18: // 198.18.0.0/15
			return true
		case v4[0] == 192 && v4[1] == 0 && v4[2] == 0: // 192.0.0.0/24
			return true
		}
	}
	return false
}
