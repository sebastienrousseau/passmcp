// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"strings"
	"time"
)

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// phaseNet checks the endpoint URL, name resolution, TCP reachability and
// the TLS session before any MCP traffic. Nothing here needs credentials.
func phaseNet(ctx context.Context, s *Session) []Finding {
	// The client configuration's launch commands first: they are read from
	// a file, so no connection failure below can stop them being reported.
	out := launchConfigFindings(s)
	u := s.URL
	host := u.Hostname()
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}

	c := s.check("net.scheme", "Endpoint uses HTTPS")
	switch {
	case u.Scheme == "https":
		out = append(out, c.pass("scheme is https"))
	case isLoopback(host):
		out = append(out, c.info("plain http to loopback "+host+" (acceptable for local servers)"))
	default:
		out = append(out, c.fail(Critical, "plain http to a non-loopback host: tokens and content travel in clear text", "serve the MCP endpoint over TLS"))
	}

	c = s.check("net.dns", "Hostname resolves")
	t0 := time.Now()
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil {
		out = append(out, c.fail(Critical, "lookup failed: "+err.Error(), "check the URL; MCP endpoints often live on a different host than the product's web UI"))
		s.blocked = "hostname does not resolve"
		return out
	}
	out = append(out, c.ev(strings.Join(addrs, ", ")).pass(fmt.Sprintf("%d address(es) in %s", len(addrs), ms(time.Since(t0)))))

	c = s.check("net.tcp", "TCP connection")
	d := net.Dialer{Timeout: 10 * time.Second}
	t0 = time.Now()
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		out = append(out, c.fail(Critical, "connect failed: "+err.Error(), "check the port, firewall and that the server is running"))
		s.blocked = "endpoint is not reachable"
		return out
	}
	out = append(out, c.ev(conn.RemoteAddr().String()).pass("connected in "+ms(time.Since(t0))))

	if u.Scheme != "https" {
		_ = conn.Close()
		return out
	}
	return append(out, tlsFindings(ctx, s, conn, host)...)
}

// tlsFindings runs the TLS handshake over an open connection and checks the
// session and the certificate the server presented.
func tlsFindings(ctx context.Context, s *Session, conn net.Conn, host string) []Finding {
	var out []Finding
	c := s.check("net.tls", "TLS handshake and certificate")
	t0 := time.Now()
	tc := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		out = append(out, c.fail(Critical, "handshake failed: "+err.Error(), "fix the certificate chain or hostname; passmcp does not skip verification"))
		s.blocked = "TLS handshake fails"
		return out
	}
	cs := tc.ConnectionState()
	_ = tc.Close()
	detail := fmt.Sprintf("%s %s in %s", tls.VersionName(cs.Version), tls.CipherSuiteName(cs.CipherSuite), ms(time.Since(t0)))
	out = append(out, c.pass(detail))

	c = s.check("net.tls.version", "TLS version is 1.2 or newer")
	if cs.Version >= tls.VersionTLS13 {
		out = append(out, c.pass("TLS 1.3"))
	} else {
		out = append(out, c.warn("TLS 1.2 negotiated", "enable TLS 1.3 on the server"))
	}

	if len(cs.PeerCertificates) > 0 {
		out = append(out, certWindowFinding(s, cs.PeerCertificates[0]))
	}
	return out
}

// certWindowFinding is the net.tls.cert verdict on how long the leaf
// certificate has left.
func certWindowFinding(s *Session, leaf *x509.Certificate) Finding {
	c := s.check("net.tls.cert", "Certificate validity window")
	left := time.Until(leaf.NotAfter)
	days := int(left.Hours() / 24)
	ev := fmt.Sprintf("subject=%s issuer=%s notAfter=%s", leaf.Subject.CommonName, leaf.Issuer.CommonName, leaf.NotAfter.Format("2006-01-02"))
	switch {
	// Expiry is decided on the duration, not on the whole days: the
	// integer division rounds toward zero, so a certificate that expired
	// less than a day ago would otherwise count as expiring in 0 days.
	case left < 0:
		return c.ev(ev).fail(Critical, "certificate has expired", "renew the certificate")
	case days < 14:
		return c.ev(ev).warn(fmt.Sprintf("certificate expires in %d days", days), "renew before it lapses")
	default:
		return c.ev(ev).pass(fmt.Sprintf("valid for %d more days", days))
	}
}
