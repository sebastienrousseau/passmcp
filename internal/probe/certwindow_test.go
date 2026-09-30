// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/telemetry"
)

// TestCertWindowFinding exercises net.tls.cert directly. The fake servers
// speak plain HTTP, and a certificate a TLS handshake has just accepted is
// never expired, so no run reaches the fail and warn branches: they are
// taken here, from a certificate built to sit on each side of each edge.
func TestCertWindowFinding(t *testing.T) {
	s := &Session{Opts: Options{Recorder: telemetry.New()}}
	day := 24 * time.Hour
	for name, tc := range map[string]struct {
		notAfter time.Duration
		status   Status
		severity Severity
		detail   string
	}{
		"expired a week ago":      {-7 * day, Fail, Critical, "has expired"},
		"expired an hour ago":     {-time.Hour, Fail, Critical, "has expired"},
		"expires within the hour": {time.Hour, Warn, Minor, "expires in 0 days"},
		"expires in 13 days":      {13*day + time.Hour, Warn, Minor, "expires in 13 days"},
		"expires in 14 days":      {14*day + time.Hour, Pass, "", "valid for 14 more days"},
		"a year left":             {365*day + time.Hour, Pass, "", "valid for 365 more days"},
	} {
		leaf := &x509.Certificate{
			Subject:  pkix.Name{CommonName: "mcp.example.com"},
			Issuer:   pkix.Name{CommonName: "Example CA"},
			NotAfter: time.Now().Add(tc.notAfter),
		}
		f := certWindowFinding(s, leaf)
		if f.ID != "net.tls.cert" || f.Status != tc.status || f.Severity != tc.severity || !strings.Contains(f.Detail, tc.detail) {
			t.Errorf("%s: got %s/%s %q, want %s/%s containing %q", name, f.Status, f.Severity, f.Detail, tc.status, tc.severity, tc.detail)
		}
		// Every verdict cites the certificate it judged: there is no
		// request to point at, so this is the evidence (ADR-0002).
		want := "subject=mcp.example.com issuer=Example CA notAfter=" + leaf.NotAfter.Format("2006-01-02")
		if len(f.Evidence) != 1 || f.Evidence[0] != want {
			t.Errorf("%s: evidence = %v, want [%s]", name, f.Evidence, want)
		}
	}
}
