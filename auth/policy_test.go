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

// fixedResolver answers every lookup with the same address, so the policy
// can be exercised without touching DNS.
func fixedResolver(ips ...string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		out := make([]net.IP, 0, len(ips))
		for _, s := range ips {
			out = append(out, net.ParseIP(s))
		}
		return out, nil
	}
}

func TestURLPolicyRejectsPlaintextAndInternalHosts(t *testing.T) {
	strict := URLPolicy{Resolver: fixedResolver("93.184.216.34")}

	if err := strict.Validate(context.Background(), "authorization server", "https://as.example/x"); err != nil {
		t.Errorf("a public https issuer must be accepted: %v", err)
	}

	// Every one of these is an endpoint a resource server could name, and
	// each would receive a client secret or a token.
	for _, bad := range []struct{ name, raw string }{
		{"plaintext", "http://as.example/x"},
		{"non-http scheme", "ftp://as.example/x"},
		{"relative", "/well-known"},
		{"empty", ""},
		{"fragment", "https://as.example/x#frag"},
		{"unparsable", "://x"},
	} {
		if err := strict.Validate(context.Background(), "authorization server", bad.raw); err == nil {
			t.Errorf("%s must be refused: %q", bad.name, bad.raw)
		}
	}

	// The SSRF cases: a discovered endpoint must not point inside the
	// network the diagnostic is running in.
	for _, ip := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.5", "192.168.1.1", "100.64.0.1", "198.18.0.1", "192.0.0.1", "::1", "fd00::1"} {
		p := URLPolicy{Resolver: fixedResolver(ip)}
		err := p.Validate(context.Background(), "token endpoint", "https://looks-fine.example/token")
		if err == nil {
			t.Errorf("a name resolving to %s must be refused", ip)
			continue
		}
		var pe *PolicyError
		if !errors.As(err, &pe) || !strings.Contains(pe.Error(), "non-public") {
			t.Errorf("wrong error for %s: %v", ip, err)
		}
	}
}

func TestURLPolicyEscapeHatches(t *testing.T) {
	// Loopback is always allowed, so a local development authorization
	// server keeps working without flags.
	strict := URLPolicy{}
	for _, raw := range []string{"http://localhost:8080/token", "http://127.0.0.1:9000/token", "https://x.localhost/token"} {
		if err := strict.Validate(context.Background(), "token endpoint", raw); err != nil {
			t.Errorf("loopback must be allowed: %q: %v", raw, err)
		}
	}
	lax := URLPolicy{AllowHTTP: true, AllowPrivate: true, Resolver: fixedResolver("10.1.2.3")}
	if err := lax.Validate(context.Background(), "token endpoint", "http://internal.corp/token"); err != nil {
		t.Errorf("an opted-in private host must be allowed: %v", err)
	}
}

// TestURLPolicyFailsClosedWhenANameDoesNotResolve: Validate cannot say a
// host is public without its addresses, so a lookup that fails, or that
// answers with nothing, is a refusal rather than a pass left for the
// dial-time guard to catch.
func TestURLPolicyFailsClosedWhenANameDoesNotResolve(t *testing.T) {
	for _, proxy := range []string{"HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"} {
		t.Setenv(proxy, "")
	}
	for name, resolver := range map[string]func(context.Context, string) ([]net.IP, error){
		"lookup error": func(context.Context, string) ([]net.IP, error) { return nil, errors.New("nxdomain") },
		"empty answer": func(context.Context, string) ([]net.IP, error) { return nil, nil },
	} {
		p := URLPolicy{Resolver: resolver}
		err := p.Validate(context.Background(), "token endpoint", "https://nope.example/token")
		var pe *PolicyError
		if !errors.As(err, &pe) || !strings.Contains(pe.Reason, "resolve") {
			t.Errorf("%s: an unresolvable name must be refused, got %v", name, err)
		}
	}
	// The escape hatch still covers it: with private hosts allowed there
	// is nothing to resolve for.
	lax := URLPolicy{AllowPrivate: true, Resolver: func(context.Context, string) ([]net.IP, error) { return nil, errors.New("nxdomain") }}
	if err := lax.Validate(context.Background(), "token endpoint", "https://nope.example/token"); err != nil {
		t.Errorf("--insecure-allow-private-hosts resolves nothing: %v", err)
	}
}

// TestURLPolicyDefersToAProxyThatResolves: behind an HTTP proxy the
// operator named, names are resolved by the proxy and the local resolver
// may know none of them. Refusing there would break every proxied run, and
// the connection goes to the proxy, which the dial-time guard trusts as the
// operator's choice. It is the one case the policy cannot see into.
func TestURLPolicyDefersToAProxyThatResolves(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://proxy.corp.example:3128")
	p := URLPolicy{Resolver: func(context.Context, string) ([]net.IP, error) { return nil, errors.New("nxdomain") }}
	if err := p.Validate(context.Background(), "token endpoint", "https://as.example/token"); err != nil {
		t.Errorf("a proxied run must not need local resolution: %v", err)
	}
	// A name that resolves is still checked, proxy or not.
	internal := URLPolicy{Resolver: fixedResolver("10.0.0.5")}
	if err := internal.Validate(context.Background(), "token endpoint", "https://as.example/token"); err == nil {
		t.Error("a name resolving to a private address must be refused behind a proxy too")
	}
}

func TestValidateMetadataChecksEveryEndpoint(t *testing.T) {
	d := &Discoverer{Policy: URLPolicy{Resolver: fixedResolver("93.184.216.34")}}
	ok := &ServerMetadata{Issuer: "https://as.example", TokenEndpoint: "https://as.example/t", AuthorizationEndpoint: "https://as.example/a"}
	if err := d.ValidateMetadata(context.Background(), ok); err != nil {
		t.Fatalf("clean metadata: %v", err)
	}
	// An authorization server can publish a token endpoint anywhere; each
	// field has to be checked, not just the issuer.
	for _, m := range []*ServerMetadata{
		{TokenEndpoint: "http://as.example/t"},
		{TokenEndpoint: "https://as.example/t", AuthorizationEndpoint: "http://as.example/a"},
		{TokenEndpoint: "https://as.example/t", RegistrationEndpoint: "http://as.example/r"},
	} {
		if err := d.ValidateMetadata(context.Background(), m); err == nil {
			t.Errorf("a plaintext endpoint must be refused: %+v", m)
		}
	}
}

func TestIsPublicIP(t *testing.T) {
	for _, ip := range []string{"8.8.8.8", "93.184.216.34", "2606:4700::1111"} {
		if !isPublicIP(net.ParseIP(ip)) {
			t.Errorf("%s is public", ip)
		}
	}
	for _, ip := range []string{"0.0.0.0", "224.0.0.1", "169.254.1.1", "ff02::1", "fe80::1"} {
		if isPublicIP(net.ParseIP(ip)) {
			t.Errorf("%s is not public", ip)
		}
	}
}
