// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
)

func htmlFixture() *Report {
	return &Report{
		Passmcp:  Meta{Version: "test", SchemaVersion: SchemaVersion},
		Target:   Target{Endpoint: "https://mcp.example.com/mcp", Host: "mcp.example.com", Scheme: "https"},
		Started:  time.Date(2026, 9, 16, 10, 0, 0, 0, time.UTC),
		Duration: probe.Millis(1500 * time.Millisecond),
		TraceID:  "abc123",
		Auth:     AuthSummary{Mode: "bearer", Reached: true, Required: true, Issuer: "https://auth.example.com"},
		Server:   &ServerInfo{Name: "demo", Version: "1.0", Protocol: "2026-07-28"},
		Phases: []probe.PhaseResult{{
			Name: "catalog", Title: "Catalog", Status: probe.Fail,
			Duration: probe.Millis(42 * time.Millisecond), Summary: "1 tool · 1 issue",
			Findings: []probe.Finding{
				{ID: "catalog.tools.descriptions", Title: "Every tool has a useful description",
					Status: probe.Fail, Severity: probe.Major, Detail: "under 20 characters: lookup",
					Advice: "write a description an agent can act on", Evidence: []string{"req#18"}},
				{ID: "catalog.tools.list", Title: "tools/list", Status: probe.Pass, Detail: "1 tool"},
			},
		}},
		Counts: Counts{Fail: 1, Pass: 1},
		Score:  Score{Total: 72, Grade: "C", Assessed: 6, Of: 6},
	}
}

// Every string in a report came from a server nobody vetted. A tool
// description carrying a script tag has to arrive as text, or passmcp has
// turned a diagnostic into a delivery mechanism.
func TestHTMLEscapesHostileCatalog(t *testing.T) {
	r := htmlFixture()
	payloads := []string{
		`<script>alert(1)</script>`,
		`"><img src=x onerror=alert(1)>`,
		`</title><script>fetch('//evil')</script>`,
		`javascript:alert(1)`,
	}
	for i, p := range payloads {
		r.Catalog.Tools = append(r.Catalog.Tools, ToolSummary{Name: p, Description: p, Annotated: true})
		r.Phases[0].Findings = append(r.Phases[0].Findings, probe.Finding{
			ID: "hostile", Title: p, Status: probe.Warn, Detail: p, Advice: p,
		})
		_ = i
	}
	r.Target.Endpoint = `https://x/mcp"><script>alert(1)</script>`

	var b strings.Builder
	if err := HTML(&b, r, HTMLOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	out := b.String()

	// What matters is that no tag from the data survived as a tag. The
	// escaped text may still read "onerror=alert(1)" — as characters in a
	// text node, which is inert and is what a reader needs to see.
	for _, tag := range []string{"<script", "<img", "<iframe", "<object", "<embed"} {
		if strings.Contains(out, tag) {
			t.Errorf("a %q from server data survived as markup", tag)
		}
	}
	// The template inlines the passmcp mark in several places, so <svg is
	// counted rather than banned — against a baseline rendered from benign
	// data, so the assertion survives the mark being added somewhere else.
	if got, want := strings.Count(out, "<svg"), baselineSVGCount(t); got != want {
		t.Errorf("got %d <svg elements, want the template's own %d", got, want)
	}
	if strings.Contains(out, `href="javascript:`) || strings.Contains(out, `src="javascript:`) {
		t.Error("a javascript: URL survived")
	}
	// The text is still readable — escaping, not dropping.
	if !strings.Contains(out, "&lt;script&gt;") {
		t.Error("the payload should appear as escaped text so a reader can see it")
	}
}

func TestHTMLRendersTheEssentials(t *testing.T) {
	r := htmlFixture()
	var b strings.Builder
	if err := HTML(&b, r, HTMLOptions{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"Not ready for agents",       // the verdict
		"72",                         // the score
		"mcp.example.com",            // the target
		"catalog.tools.descriptions", // the finding id
		"What to fix first",          // the executive section
		"@media print",               // the PDF pipeline
		"2026-07-28",                 // the negotiated protocol
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the report is missing %q", want)
		}
	}
	// Self-contained: no external request, so it opens offline and cannot
	// phone home from a reviewer's machine.
	for _, bad := range []string{"<link rel=\"stylesheet\" href", "src=\"http", "@import url("} {
		if strings.Contains(out, bad) {
			t.Errorf("the report fetches something external: %q", bad)
		}
	}
}

// The short document carries what needs acting on; verbose carries the
// evidence that a passing check actually ran.
func TestHTMLVerbosity(t *testing.T) {
	r := htmlFixture()
	var short, full strings.Builder
	if err := HTML(&short, r, HTMLOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := HTML(&full, r, HTMLOptions{Verbose: true}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(short.String(), "req#18") {
		t.Error("the short report should not carry evidence references")
	}
	if !strings.Contains(full.String(), "req#18") {
		t.Error("the verbose report should carry evidence references")
	}
	if strings.Contains(short.String(), "catalog.tools.list") {
		t.Error("the short report should omit passing findings")
	}
	if !strings.Contains(full.String(), "catalog.tools.list") {
		t.Error("the verbose report should include passing findings")
	}
}

func TestFixFirstOrdersBySeverity(t *testing.T) {
	r := htmlFixture()
	r.Phases[0].Findings = []probe.Finding{
		{ID: "a", Status: probe.Warn, Severity: probe.Minor, Title: "minor warn"},
		{ID: "b", Status: probe.Fail, Severity: probe.Minor, Title: "minor fail"},
		{ID: "c", Status: probe.Fail, Severity: probe.Critical, Title: "critical fail"},
		{ID: "d", Status: probe.Pass, Title: "a pass"},
	}
	got := fixFirst(r)
	if len(got) != 3 {
		t.Fatalf("passing findings do not belong in what to fix first: %d", len(got))
	}
	if got[0].ID != "c" || got[1].ID != "b" || got[2].ID != "a" {
		t.Errorf("wrong order: %s %s %s", got[0].ID, got[1].ID, got[2].ID)
	}
	// A list of twenty priorities is not a list of priorities.
	for i := 0; i < 20; i++ {
		r.Phases[0].Findings = append(r.Phases[0].Findings, probe.Finding{ID: "x", Status: probe.Fail, Severity: probe.Major})
	}
	if len(fixFirst(r)) != 5 {
		t.Errorf("the list should be capped at five, got %d", len(fixFirst(r)))
	}
}

func TestHTMLVerdictMatchesText(t *testing.T) {
	// The two renderings must never say different things about the same
	// report, so they are checked against each other rather than separately.
	cases := []*Report{
		{Blocked: "first contact failed"},
		{Counts: Counts{Fail: 1}},
		{Counts: Counts{Warn: 1}},
		{Counts: Counts{Pass: 1}},
	}
	for _, r := range cases {
		gotHTML, _ := htmlVerdict(r)
		gotText, _ := verdict(r)
		if gotHTML != gotText {
			t.Errorf("html says %q, text says %q", gotHTML, gotText)
		}
	}
}
