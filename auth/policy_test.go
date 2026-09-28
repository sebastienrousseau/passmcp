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
	// A name that does not resolve is left to the fetch to report.
	unres := URLPolicy{Resolver: func(context.Context, string) ([]net.IP, error) { return nil, errors.New("nxdomain") }}
	if err := unres.Validate(context.Background(), "token endpoint", "https://nope.example/token"); err != nil {
		t.Errorf("an unresolvable name is not a policy failure: %v", err)
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
