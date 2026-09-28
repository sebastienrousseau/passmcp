// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package policy

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// sampleReport is a run with one of every status and one assessed category
// and one unassessed, so both adapters have something of each to get wrong.
func sampleReport() *report.Report {
	r := &report.Report{
		Passmcp:  report.Meta{Version: "0.0.3", SchemaVersion: report.SchemaVersion},
		Target:   report.Target{Endpoint: "https://mcp.example.com/mcp", Host: "mcp.example.com", Scheme: "https"},
		Started:  time.Date(2027, 3, 1, 10, 0, 0, 0, time.UTC),
		Duration: probe.Millis(1500 * time.Millisecond),
		TraceID:  "trace-abc",
		Server:   &report.ServerInfo{Name: "acme-mcp", Version: "1.4.0", Protocol: "2026-07-28"},
		Phases: []probe.PhaseResult{
			{
				Name: "net", Title: "Connectivity", Status: probe.Pass,
				Findings: []probe.Finding{
					{ID: "net.dns", Phase: "net", Status: probe.Pass},
					{ID: "net.tls", Phase: "net", Status: probe.Info},
				},
			},
			{
				Name: "protocol", Title: "Protocol", Status: probe.Fail,
				Findings: []probe.Finding{
					{ID: "protocol.malformed_json", Phase: "protocol", Status: probe.Fail, Severity: probe.Minor},
					{ID: "protocol.id_echo", Phase: "protocol", Status: probe.Warn, Severity: probe.Minor},
					{ID: "protocol.accept_header", Phase: "protocol", Status: probe.Skip},
				},
			},
		},
		Counts: report.Counts{Pass: 1, Warn: 1, Fail: 1, Skip: 1, Info: 1},
	}
	r.Score = report.Score{
		Total: 82, Grade: "B", Assessed: 1, Of: 6,
		Categories: []report.Category{
			{Name: "protocol", Weight: 20, Assessed: true, Score: 82},
			{Name: "execution", Weight: 20, Assessed: false},
		},
	}
	return r
}

// The claim the two adapters exist to support: a live run and the signed
// statement derived from it must not be able to reach different verdicts.
// Anything either adapter drops or renames breaks it, and this compares the
// whole Result rather than a field at a time so a new rule is covered without
// anybody remembering to extend the test.
func TestTheSamePolicyAgreesOnARunAndItsStatement(t *testing.T) {
	r := sampleReport()
	st, err := attest.From(r)
	if err != nil {
		t.Fatal(err)
	}

	p := &Policy{
		Version: 1, Name: "agreement",
		Target:           &Target{Transport: "http", Endpoint: "https://mcp.example.com/mcp"},
		MustPass:         []string{"net.dns"},
		MustNotFail:      []string{"protocol.id_echo"},
		MaxFail:          ptr(1),
		MaxWarn:          ptr(1),
		MinScore:         ptr(80.0),
		MinCategoryScore: map[string]float64{"protocol": 80},
		ForbidSeverity:   Critical,
		Exemptions: []Exemption{{
			Check: "protocol.malformed_json", Reason: "known, fix is queued",
			Expires: Date{time.Date(2027, 12, 31, 0, 0, 0, 0, time.UTC)},
		}},
	}
	if err := p.Validate(); err != nil {
		t.Fatal(err)
	}

	fromRun := p.Evaluate(FromReport(r), day)
	fromClaim := p.Evaluate(FromStatement(st), day)

	if !reflect.DeepEqual(fromRun, fromClaim) {
		t.Errorf("the same policy reached different answers.\nfrom the run:   %+v\nfrom the claim: %+v",
			fromRun, fromClaim)
	}
	// And the answer is the one the fixture was built to produce, so a bug
	// that broke both adapters identically still fails here.
	if !fromRun.OK {
		t.Errorf("the policy was not met: %+v", fromRun.Rules)
	}
	if len(fromRun.Rules) != 8 {
		t.Errorf("%d rules for eight stated: %+v", len(fromRun.Rules), fromRun.Rules)
	}
	if len(fromRun.Exemptions) != 1 || !fromRun.Exemptions[0].Applied {
		t.Errorf("exemptions = %+v", fromRun.Exemptions)
	}

	// Agreement on a refusal matters as much as agreement on a pass, and the
	// policy above cannot show it: its severities are all minor and its
	// threshold is critical, so a subject carrying no severity at all reaches
	// the same answer. This second pass makes the severity decide.
	strict := &Policy{
		Version: 1, Name: "severity decides",
		ForbidSeverity: Minor,
		MustPass:       []string{"protocol.malformed_json"},
	}
	if err := strict.Validate(); err != nil {
		t.Fatal(err)
	}
	runStrict, claimStrict := strict.Evaluate(FromReport(r), day), strict.Evaluate(FromStatement(st), day)
	if !reflect.DeepEqual(runStrict, claimStrict) {
		t.Errorf("the two disagreed once severity mattered.\nfrom the run:   %+v\nfrom the claim: %+v",
			runStrict, claimStrict)
	}
	if runStrict.OK {
		t.Fatalf("a minor failure met forbid_severity: minor: %+v", runStrict.Rules)
	}
	var forbidden, required string
	for _, rule := range runStrict.Rules {
		switch rule.Rule {
		case "forbid_severity":
			forbidden = rule.Detail
		case "must_pass:protocol.malformed_json":
			required = rule.Detail
		}
	}
	// Both details name the severity, so an adapter that dropped it changes
	// the text even when it does not change the verdict.
	for _, want := range []string{"protocol.malformed_json (minor)"} {
		if !strings.Contains(forbidden, want) {
			t.Errorf("forbid_severity detail %q does not name %q", forbidden, want)
		}
	}
	if !strings.Contains(required, "fail (minor)") {
		t.Errorf("must_pass detail %q does not carry the severity", required)
	}
}

func TestFromReport(t *testing.T) {
	s := FromReport(sampleReport())
	if s.Transport != "http" || s.Endpoint != "https://mcp.example.com/mcp" {
		t.Errorf("target = %s %s", s.Transport, s.Endpoint)
	}
	// Every finding from every phase, not just the failing ones: a rule may
	// name any check, and a subject missing the passes could not answer
	// must_pass.
	if len(s.Verdicts) != 5 {
		t.Errorf("%d verdicts for five findings across two phases", len(s.Verdicts))
	}
	if s.Counts != (Counts{Pass: 1, Warn: 1, Fail: 1, Skip: 1, Info: 1}) {
		t.Errorf("counts = %+v", s.Counts)
	}
	if s.Score == nil || s.Score.Total != 82 {
		t.Fatalf("score = %+v", s.Score)
	}
	// An unassessed category is absent, not zero. Present-as-zero would fail
	// every min_category_score for a phase that did not run.
	if _, ok := s.Score.Categories["execution"]; ok {
		t.Error("an unassessed category was carried as a score")
	}
	if s.Score.Categories["protocol"] != 82 {
		t.Errorf("categories = %+v", s.Score.Categories)
	}
}

// A stdio run and an HTTP run do not contain the same checks, so a policy
// written for one must not silently apply to the other.
func TestStdioTransportIsCarried(t *testing.T) {
	r := sampleReport()
	r.Target = report.Target{Endpoint: "npx -y some-server", Scheme: "stdio"}
	if got := FromReport(r).Transport; got != "stdio" {
		t.Errorf("transport = %q", got)
	}
	st, err := attest.From(r)
	if err != nil {
		t.Fatal(err)
	}
	if got := FromStatement(st).Transport; got != "stdio" {
		t.Errorf("transport from the statement = %q", got)
	}
}

// A run that assessed nothing carries no score, and both adapters have to say
// so by leaving it nil rather than by reporting zero.
func TestASubjectWithNoScore(t *testing.T) {
	r := sampleReport()
	r.Score = report.Score{Assessed: 0, Of: 6}
	if s := FromReport(r); s.Score != nil {
		t.Errorf("score = %+v, want nil", s.Score)
	}
	st, err := attest.From(r)
	if err != nil {
		t.Fatal(err)
	}
	if s := FromStatement(st); s.Score != nil {
		t.Errorf("score from the statement = %+v, want nil", s.Score)
	}
}
