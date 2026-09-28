// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/report"
)

// personalRun checks a server whose read-only tool returns a customer
// record, capturing bodies, and returns the report directory.
func personalRun(t *testing.T) (dir, endpoint string) {
	t.Helper()
	f := newFakeServer(t)
	f.open, f.personal = true, true
	dir = t.TempDir()
	endpoint = f.srv.URL + "/mcp"
	out, _ := run(t, append([]string{"check", endpoint, "--capture-bodies", "--report-dir", dir,
		"--phases", "net,discovery,auth,handshake,catalog,execution"}, fastFlags()...)...)
	f.mu.Lock()
	called := f.calls["lookup_customer"]
	f.mu.Unlock()
	if called == 0 {
		t.Fatalf("the customer lookup was never called, so nothing was tested:\n%s", out)
	}
	return dir, endpoint
}

// AC: GDPR-01
func TestPersonalDataNeverReachesAReportOrLog(t *testing.T) {
	dir, _ := personalRun(t)
	for _, name := range []string{"report.json", "report.md", "report.html", "report.txt", "telemetry.ndjson", "telemetry.har"} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, pii := range []string{fakeCustomerName, fakeCustomerEmail, fakeCustomerPhone} {
			if strings.Contains(string(b), pii) {
				t.Errorf("%s carries %q", name, pii)
			}
		}
	}
	var r report.Report
	b, _ := os.ReadFile(filepath.Join(dir, "report.json"))
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Redaction == nil {
		t.Fatal("report.json has no redaction summary")
	}
	// Every value here sits under a personal-data key, so each is masked
	// as a field before the e-mail and phone patterns see it; the
	// telemetry package's own tests cover the patterns.
	if r.Redaction.PersonalData["field"] == 0 || r.Redaction.Total() == 0 {
		t.Errorf("redaction summary %v counts no masked field", r.Redaction.PersonalData)
	}
}

// AC: GDPR-02
func TestARunContactsOnlyTheTarget(t *testing.T) {
	dir, endpoint := personalRun(t)
	target, _ := url.Parse(endpoint)
	b, err := os.ReadFile(filepath.Join(dir, "telemetry.har"))
	if err != nil {
		t.Fatal(err)
	}
	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(b, &har); err != nil || len(har.Log.Entries) == 0 {
		t.Fatalf("HAR: %v, %d entries", err, len(har.Log.Entries))
	}
	// The fake's authorization server shares the target's origin, so every
	// request the run made — MCP, discovery and OAuth metadata — must be to
	// that one host. Anything else is passmcp phoning somewhere.
	for _, e := range har.Log.Entries {
		u, err := url.Parse(e.Request.URL)
		if err != nil || u.Host != target.Host {
			t.Errorf("the run contacted %s, which is not the target %s", e.Request.URL, target.Host)
		}
	}
}

// AC: GDPR-03
func TestToolsThatNamePersonalDataAreListed(t *testing.T) {
	dir, _ := personalRun(t)
	var r report.Report
	b, _ := os.ReadFile(filepath.Join(dir, "report.json"))
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if len(r.Catalog.PersonalData) != 1 || r.Catalog.PersonalData[0].Tool != "lookup_customer" {
		t.Fatalf("catalog.personalData = %+v, want only lookup_customer", r.Catalog.PersonalData)
	}
	var found bool
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.ID != "catalog.personal_data" {
				continue
			}
			found = true
			if f.Status != "info" {
				t.Errorf("catalog.personal_data is %s; it records an observation and judges nothing", f.Status)
			}
			if !strings.Contains(f.Detail, "customer_email") {
				t.Errorf("detail %q does not name the field", f.Detail)
			}
			if len(f.Controls.GDPR) == 0 {
				t.Errorf("catalog.personal_data carries no GDPR article")
			}
		}
	}
	if !found {
		t.Fatal("no catalog.personal_data finding")
	}
}
