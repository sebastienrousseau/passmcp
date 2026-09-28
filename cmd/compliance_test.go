// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/csv"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/egress"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/spec/controls"
)

// statementFrom re-derives a statement from a saved report after edit has
// changed it, so a test can put a finding in a statement that the fake
// server cannot produce — a failing certificate over plain HTTP.
func statementFrom(t *testing.T, reportJSON string, edit func(*report.Report)) (statement string, r *report.Report) {
	t.Helper()
	r = &report.Report{}
	if err := json.Unmarshal([]byte(reportJSON), r); err != nil {
		t.Fatal(err)
	}
	if edit != nil {
		edit(r)
	}
	st, err := attest.From(r)
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(st)
	if err != nil {
		t.Fatal(err)
	}
	return string(b), r
}

// failingCert adds a failing net.tls.cert finding that cites request 3,
// and counts it: a statement whose counts disagree with its verdicts is
// refused.
func failingCert(r *report.Report) {
	r.Counts.Fail++
	r.Phases = append(r.Phases, probe.PhaseResult{Name: "net", Findings: []probe.Finding{{
		ID: "net.tls.cert", Phase: "net", Title: "certificate", Status: probe.Fail,
		Severity: probe.Major, Detail: "certificate expired", Evidence: []string{"req#3"},
	}}})
}

// offline makes any use of the default HTTP transport fail the test.
type offline struct{ t *testing.T }

func (o offline) RoundTrip(r *http.Request) (*http.Response, error) {
	o.t.Errorf("an offline command made a request to %s", r.URL)
	return nil, errors.New("offline")
}

// AC: SOC2-03
func TestVerifyFrameworkJudgesEveryControlOffline(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)
	orig := http.DefaultTransport
	http.DefaultTransport = offline{t}
	defer func() { http.DefaultTransport = orig }()

	out, code := run(t, "verify", path, "--framework", "soc2")
	if code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	for _, want := range []string{"Trust Services Criteria", "evidenced", "CC6.1", "not covered by passmcp; docs/compliance/soc2.md"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}

	out, code = run(t, "verify", path, "--framework", "soc2", "--output", "json")
	if code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	var v struct {
		Framework struct {
			Framework string                `json:"framework"`
			Criteria  []controls.Assessment `json:"criteria"`
		} `json:"framework"`
	}
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatalf("%v:\n%s", err, out)
	}
	m, _ := controls.Load(controls.SOC2)
	if v.Framework.Framework != "soc2" || len(v.Framework.Criteria) != len(m.Criteria) {
		t.Fatalf("framework %q with %d criteria, want soc2 with %d", v.Framework.Framework, len(v.Framework.Criteria), len(m.Criteria))
	}

	if out, code := run(t, "verify", path, "--framework", "hipaa"); code == 0 {
		t.Errorf("an unknown framework was accepted:\n%s", out)
	}
}

// AC: ISO-03
func TestVerifyFrameworkISOWithoutNetwork(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)
	orig := http.DefaultTransport
	http.DefaultTransport = offline{t}
	defer func() { http.DefaultTransport = orig }()

	out, code := run(t, "verify", path, "--framework", "iso27001")
	if code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "27001") || !strings.Contains(out, "A.5.") {
		t.Errorf("no ISO controls in the output:\n%s", out)
	}
}

// AC: ISO-04
func TestCertificateFailureIsReportedAgainstA824WithItsRequest(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)
	statement, _ := statementFrom(t, reportJSON, failingCert)
	path := writeTemp(t, "att.json", statement)

	out, code := run(t, "verify", path, "--framework", "iso27001")
	if code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	line := lineWith(out, "A.8.24")
	if !strings.Contains(line, "failing") || !strings.Contains(line, "net.tls.cert fail req#3") {
		t.Errorf("A.8.24 line = %q, want failing citing net.tls.cert and req#3\n%s", line, out)
	}

	dir := t.TempDir()
	if out, code := run(t, "evidence", "--framework", "iso27001", "--out-dir", dir, path); code != 0 {
		t.Fatalf("evidence exited %d:\n%s", code, out)
	}
	rows := readCSV(t, filepath.Join(dir, "iso27001-evidence.csv"))
	row := rowFor(rows, "A.8.24")
	if row == nil || row[3] != "failing" || !strings.Contains(row[7], "net.tls.cert=fail (req#3)") {
		t.Errorf("A.8.24 row = %q", row)
	}
}

// AC: SOC2-04
func TestEvidenceWritesABundleWithoutCredentials(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)
	const secret = "s3cr3t-query-token"
	statement, _ := statementFrom(t, reportJSON, func(r *report.Report) {
		r.Target.Endpoint += "?access_token=" + secret
	})
	path := writeTemp(t, "att.json", statement)
	dir := t.TempDir()

	out, code := run(t, "evidence", "--framework", "soc2", "--from", "2000-01-01", "--to", "2999-12-31", "--out-dir", dir, path)
	if code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	for _, name := range []string{"soc2-evidence.json", "soc2-evidence.csv"} {
		if !strings.Contains(out, filepath.Join(dir, name)) {
			t.Errorf("stdout does not name %s:\n%s", name, out)
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), secret) {
			t.Errorf("%s carries the query-string token", name)
		}
	}
	var b controls.Bundle
	raw, _ := os.ReadFile(filepath.Join(dir, "soc2-evidence.json"))
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	cc61 := criterion(b, "CC6.1")
	if cc61 == nil || len(cc61.Observations) != 1 || len(cc61.Observations[0].Digest) != 64 {
		t.Fatalf("CC6.1 = %+v, want one observation carrying the statement's SHA-256", cc61)
	}
	rows := readCSV(t, filepath.Join(dir, "soc2-evidence.csv"))
	if got := rows[0]; strings.Join(got, ",") != "framework,criterion,title,state,target,ran_at,attestation_sha256,checks,regressed,reason" {
		t.Errorf("CSV header = %q", got)
	}
}

func TestEvidenceKeepsOnlyThePeriodAndRejectsBadInput(t *testing.T) {
	_, _, statement := attestFixture(t)
	path := writeTemp(t, "att.json", statement)
	dir := t.TempDir()

	if out, code := run(t, "evidence", "--framework", "gdpr", "--to", "2000-01-01", "--out-dir", dir, path); code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	var b controls.Bundle
	raw, _ := os.ReadFile(filepath.Join(dir, "gdpr-evidence.json"))
	if err := json.Unmarshal(raw, &b); err != nil {
		t.Fatal(err)
	}
	for _, c := range b.Criteria {
		if len(c.Observations) != 0 {
			t.Errorf("%s has an observation from outside the period", c.ID)
		}
	}

	notReport := writeTemp(t, "x.json", `{"hello":1}`)
	for name, args := range map[string][]string{
		"framework":  {"evidence", "--framework", "pci", path},
		"from":       {"evidence", "--framework", "soc2", "--from", "yesterday", path},
		"to":         {"evidence", "--framework", "soc2", "--to", "later", path},
		"order":      {"evidence", "--framework", "soc2", "--from", "2026-02-01", "--to", "2026-01-01", path},
		"statement":  {"evidence", "--framework", "soc2", notReport},
		"missing":    {"evidence", "--framework", "soc2", filepath.Join(dir, "absent.json")},
		"art30":      {"evidence", "--framework", "gdpr", "--out-dir", dir, "--report", notReport, path},
		"art30 file": {"evidence", "--framework", "gdpr", "--out-dir", dir, "--report", filepath.Join(dir, "absent.json"), path},
		"out-dir":    {"evidence", "--framework", "soc2", "--out-dir", filepath.Join(path, "sub"), path},
	} {
		if out, code := run(t, args...); code == 0 {
			t.Errorf("%s: bad input accepted:\n%s", name, out)
		}
	}
}

// AC: GDPR-04
func TestEvidenceWritesAnArt30InputWithEgressDestinations(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)
	edit := func(r *report.Report) {
		r.Counts.Info++
		r.Egress = []egress.Dial{{Host: "api.example.net", Port: "443", Count: 2, Allowed: true}}
		r.Phases = append(r.Phases, probe.PhaseResult{Name: "egress", Findings: []probe.Finding{{
			ID: "egress.hosts", Phase: "egress", Title: "destinations", Status: probe.Info, Detail: "1 destination",
		}}})
		r.Catalog.PersonalData = []probe.PersonalDataTool{{Tool: "lookup_customer", Fields: []string{"input.customer_email"}}}
	}
	statement, r := statementFrom(t, reportJSON, edit)
	stPath := writeTemp(t, "att.json", statement)
	rb, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	repPath := writeTemp(t, "report.json", string(rb))
	dir := t.TempDir()

	out, code := run(t, "evidence", "--framework", "gdpr", "--out-dir", dir, "--report", repPath, stPath)
	if code != 0 {
		t.Fatalf("exited %d:\n%s", code, out)
	}
	md, err := os.ReadFile(filepath.Join(dir, "gdpr-art30.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Art. 30", "api.example.net:443", "lookup_customer", "input.customer_email", "attestation SHA-256 `"} {
		if !strings.Contains(string(md), want) {
			t.Errorf("gdpr-art30.md lacks %q:\n%s", want, md)
		}
	}
	var doc struct {
		Records []art30Record `json:"records"`
	}
	raw, _ := os.ReadFile(filepath.Join(dir, "gdpr-art30.json"))
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Records) != 1 || !doc.Records[0].EgressObserved || doc.Records[0].Attestation == "" {
		t.Fatalf("records = %+v, want one watched run matched to its attestation", doc.Records)
	}

	// Without the witness, no destination list is claimed.
	plain := art30For(&report.Report{Started: time.Now()}, nil)
	var b strings.Builder
	if err := art30Markdown(&b, []art30Record{plain}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "not observed (run with --watch-egress") || !strings.Contains(b.String(), "none named") {
		t.Errorf("an unwatched run:\n%s", b.String())
	}
	watchedNone := plain
	watchedNone.EgressObserved = true
	b.Reset()
	_ = art30Markdown(&b, []art30Record{watchedNone})
	if !strings.Contains(b.String(), "none during the run") {
		t.Errorf("a watched run with no egress:\n%s", b.String())
	}
}

func TestArt30PurposePrefersInstructionsThenTitle(t *testing.T) {
	r := &report.Report{Server: &report.ServerInfo{Name: "s", Title: "A title"}}
	if got := art30For(r, nil).Purpose; got != "A title" {
		t.Errorf("purpose = %q", got)
	}
	r.Server.Purpose = "Answers questions"
	if got := art30For(r, nil).Purpose; got != "Answers questions" {
		t.Errorf("purpose = %q", got)
	}
}

// AC: GDPR-05
func TestRetainDeletesOldReportFilesAndLogsEach(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	dir := t.TempDir()
	old := time.Now().Add(-40 * 24 * time.Hour)
	for _, name := range []string{"policy.json", "notes.txt"} {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	args := append([]string{"check", f.srv.URL + "/mcp", "--phases", "net,handshake", "--report-dir", dir, "--retain", "30d"}, fastFlags()...)
	args = append(args, "--log-level", "info")
	_, stderr, _ := runCapturingStderr(t, args...)
	if _, err := os.Stat(filepath.Join(dir, "policy.json")); !os.IsNotExist(err) {
		t.Errorf("the old policy.json survived: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "notes.txt")); err != nil {
		t.Errorf("a file passmcp did not write was deleted: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "report.json")); err != nil {
		t.Errorf("the run's own report is missing: %v", err)
	}
	if !strings.Contains(stderr, "retention: deleted "+filepath.Join(dir, "policy.json")) {
		t.Errorf("the deletion was not logged on stderr:\n%s", stderr)
	}

	if out, code := run(t, "check", f.srv.URL+"/mcp", "--report-dir", dir, "--retain", "soon"); code == 0 {
		t.Errorf("a bad --retain was accepted:\n%s", out)
	}
}

// AC: ISO-01
func TestEveryJSONFindingCarriesThreeControlLists(t *testing.T) {
	_, reportJSON, _ := attestFixture(t)
	var doc struct {
		Phases []struct {
			Findings []map[string]json.RawMessage `json:"findings"`
		} `json:"phases"`
	}
	if err := json.Unmarshal([]byte(reportJSON), &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range doc.Phases {
		for _, f := range p.Findings {
			n++
			assertControlLists(t, string(f["id"]), f["controls"])
		}
	}
	if n == 0 {
		t.Fatal("the report has no findings")
	}

	// Streamed findings carry them too: they leave before the report is built.
	f := newFakeServer(t)
	f.open = true
	out, _ := run(t, append([]string{"check", f.srv.URL + "/mcp", "--output", "ndjson", "--phases", "net,handshake"}, fastFlags()...)...)
	streamed := 0
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		var ev struct {
			Type    string                     `json:"type"`
			Finding map[string]json.RawMessage `json:"finding"`
		}
		if json.Unmarshal([]byte(line), &ev) == nil && ev.Type == "finding" {
			streamed++
			assertControlLists(t, string(ev.Finding["id"]), ev.Finding["controls"])
		}
	}
	if streamed == 0 {
		t.Fatalf("no finding was streamed:\n%s", out)
	}
}

func assertControlLists(t *testing.T, id string, raw json.RawMessage) {
	t.Helper()
	var c map[string]*[]string
	if err := json.Unmarshal(raw, &c); err != nil {
		t.Errorf("finding %s: controls %s: %v", id, raw, err)
		return
	}
	for _, fw := range []string{"soc2", "iso27001", "gdpr"} {
		if c[fw] == nil {
			t.Errorf("finding %s: controls.%s is missing or null in %s", id, fw, raw)
		}
	}
}

func lineWith(s, sub string) string {
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, sub) {
			return l
		}
	}
	return ""
}

func readCSV(t *testing.T, path string) [][]string {
	t.Helper()
	f, err := os.Open(path) // #nosec G304 -- a file the test wrote
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	return rows
}

func rowFor(rows [][]string, id string) []string {
	for _, r := range rows {
		if len(r) > 1 && r[1] == id {
			return r
		}
	}
	return nil
}

func criterion(b controls.Bundle, id string) *controls.BundleCriterion {
	for i := range b.Criteria {
		if b.Criteria[i].ID == id {
			return &b.Criteria[i]
		}
	}
	return nil
}
