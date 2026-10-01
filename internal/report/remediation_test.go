// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"bytes"
	"os"
	"regexp"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/probe"
)

// checkIDs reads the ids out of the generated inventory, which is itself
// generated from the call sites and gated. Going through it means this test
// cannot drift from the source without check-inventory failing first.
func checkIDs(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("../../docs/checks.md")
	if err != nil {
		t.Fatalf("reading the inventory: %v", err)
	}
	re := regexp.MustCompile("<span id=\"check-[a-z0-9_-]+\" data-can-fail=\"(true|false)\"></span>`([^`]+)`")
	out := map[string]bool{}
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out[m[2]] = true
	}
	if len(out) == 0 {
		t.Fatal("no check ids found; the inventory format changed and this test did not")
	}
	return out
}

// failableIDs are the checks the generator detected as able to reach a fail
// or a warn — the ones that can appear in a report's "what to fix first".
//
// The generator matches three shapes: a check bound then failed, one failed
// inline, and one handed to a helper that fails its own parameter. Those are
// every shape internal/probe uses, so the set is currently exact rather than
// a lower bound — every check that can fail is marked, and all 65 are
// covered.
//
// It is still a lower bound by construction: a fourth shape would go
// undetected and unguarded rather than failing the build for a check nobody
// can act on. That is the safe direction, and the reason to keep the
// detection honest rather than clever.
func failableIDs(t *testing.T) []string {
	t.Helper()
	b, err := os.ReadFile("../../docs/checks.md")
	if err != nil {
		t.Fatalf("reading the inventory: %v", err)
	}
	re := regexp.MustCompile("data-can-fail=\"true\"></span>`([^`]+)`")
	var out []string
	for _, m := range re.FindAllStringSubmatch(string(b), -1) {
		out = append(out, m[1])
	}
	if len(out) == 0 {
		t.Fatal("no failable checks found; the inventory format changed and this test did not")
	}
	return out
}

// TestEveryFailableCheckHasGuidance is the thoroughness gate.
//
// A check that can appear in "what to fix first" and has no guidance
// renders as a bare one-line advice string — which is where this whole
// catalogue started. Adding a failing check without writing for it should
// stop the build, not quietly regress the report.
func TestEveryFailableCheckHasGuidance(t *testing.T) {
	var missing []string
	for _, id := range failableIDs(t) {
		if _, ok := RemediationFor(id); !ok {
			missing = append(missing, id)
		}
	}
	if len(missing) > 0 {
		t.Errorf("%d check(s) can fail with no remediation written: %s",
			len(missing), strings.Join(missing, ", "))
	}
}

// TestRemediationKeysAreRealChecks is the guard that matters.
//
// Guidance filed under an id no check produces is guidance nobody will ever
// see, and it fails silently — the report simply renders without it. A typo
// here is invisible at run time, which is exactly the kind of mistake that
// survives review.
func TestRemediationKeysAreRealChecks(t *testing.T) {
	ids := checkIDs(t)
	for key := range remediations {
		// A family is keyed by its prefix; the inventory lists it as "*".
		lookup := key
		if strings.HasSuffix(key, ".") {
			lookup = key + "*"
		}
		if !ids[lookup] {
			t.Errorf("remediation %q matches no check in the inventory", key)
		}
	}
}

// TestRemediationGroupsDoNotOverlap: the guidance lives in one table per
// area, merged at init. A check id filed in two of them would have one
// entry silently replace the other, where a single map literal refused to
// compile.
func TestRemediationGroupsDoNotOverlap(t *testing.T) {
	seen := map[string]int{}
	for i, g := range remediationGroups {
		for id := range g {
			if j, ok := seen[id]; ok {
				t.Errorf("check %q has guidance in groups %d and %d", id, j, i)
			}
			seen[id] = i
		}
	}
	if len(seen) != len(remediations) {
		t.Errorf("groups hold %d ids, merged table %d", len(seen), len(remediations))
	}
}

// TestRemediationsAreUsable: an entry that explains without saying what to
// change is the thing this file exists to replace.
func TestRemediationsAreUsable(t *testing.T) {
	for id, r := range remediations {
		if strings.TrimSpace(r.Means) == "" {
			t.Errorf("%s: no Means", id)
		}
		if len(r.Steps) == 0 {
			t.Errorf("%s: no Steps — an explanation with no action is the status quo", id)
		}
		for i, s := range r.Steps {
			if strings.TrimSpace(s.Title) == "" || strings.TrimSpace(s.Body) == "" {
				t.Errorf("%s: step %d is incomplete", id, i)
			}
		}
		// Long enough to have said something. The shortest honest Means in
		// the set runs well past this; the bound is here to catch a
		// placeholder, not to police prose.
		if len(r.Means) < 120 {
			t.Errorf("%s: Means is %d characters, which is a stub", id, len(r.Means))
		}
	}
}

func TestRemediationForResolvesFamilies(t *testing.T) {
	// A concrete id wins outright.
	if _, ok := RemediationFor("catalog.tools.output_schema"); !ok {
		t.Error("a documented check resolved to nothing")
	}
	// An id nothing produces is absent rather than wrong. Using a made-up id
	// rather than a real-but-undocumented one, because the set of documented
	// checks is meant to grow and this assertion should not need revisiting
	// every time it does — which it just did.
	if _, ok := RemediationFor("not.a.real.check"); ok {
		t.Error("an unknown id resolved to guidance")
	}
	// Families resolve through their prefix, if any are registered.
	for key := range remediations {
		if !strings.HasSuffix(key, ".") {
			continue
		}
		if _, ok := RemediationFor(key + "an_observed_value"); !ok {
			t.Errorf("family %q did not resolve for an instance", key)
		}
	}
}

// guidedReport is a report whose worst finding has remediation written for
// it, so the renderers have something to show.
func guidedReport() *Report {
	r := &Report{
		Passmcp: Meta{Version: "t"},
		Target:  Target{Endpoint: "https://x/mcp"},
	}
	r.Phases = []probe.PhaseResult{{
		Name: "protocol", Title: "Protocol", Status: probe.Fail,
		Findings: []probe.Finding{{
			ID: "protocol.malformed_json", Phase: "protocol",
			Title: "Malformed JSON is rejected", Status: probe.Fail,
			Severity: probe.Minor, Detail: "HTTP 200 for a truncated body",
			Advice: "return 400 or -32700",
			DocURL: "https://satellion.com/passmcp/docs/checks/#check-protocol-malformed_json",
		}},
	}}
	r.Counts = Counts{Fail: 1}
	return r
}

// TestTextGuidanceIsBehindVerbose pins the split.
//
// The default output is read while the run is still fresh, by somebody who
// wants to know what is wrong. Five findings with three steps each is sixty
// lines of terminal nobody asked for, so the full explanation waits for
// --verbose — while the renderings that get forwarded carry it always.
func TestTextGuidanceIsBehindVerbose(t *testing.T) {
	var terse, verbose bytes.Buffer
	Text(&terse, guidedReport(), TextOptions{Width: 90})
	Text(&verbose, guidedReport(), TextOptions{Width: 90, Verbose: true})

	if strings.Contains(terse.String(), "What it means") {
		t.Error("the default text output carries the full guidance; it should stay scannable")
	}
	if !strings.Contains(terse.String(), "return 400 or -32700") {
		t.Error("the default output lost the one-line advice")
	}
	for _, want := range []string{"What it means", "How to fix it", "Reject a body that does not parse"} {
		if !strings.Contains(verbose.String(), want) {
			t.Errorf("--verbose output is missing %q", want)
		}
	}
}

// TestMarkdownCarriesGuidance: the Markdown rendering is what gets pasted
// into a ticket, and the person reading that ticket has no passmcp to run.
func TestMarkdownCarriesGuidance(t *testing.T) {
	var buf bytes.Buffer
	Markdown(&buf, guidedReport())
	got := buf.String()
	for _, want := range []string{
		"## What to do next",
		"**How to fix it**",
		"Reject a body that does not parse",
		"#check-protocol-malformed_json",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("markdown is missing %q", want)
		}
	}
}

// TestAttachGuidanceIsScopedToThisReport: a report about one server should
// carry advice about that server, not the whole catalogue.
func TestAttachGuidanceIsScopedToThisReport(t *testing.T) {
	r := guidedReport()
	// A passing check with guidance written for it, which must not appear.
	r.Phases = append(r.Phases, probe.PhaseResult{
		Name: "net", Title: "Network", Status: probe.Pass,
		Findings: []probe.Finding{{
			ID: "net.tls", Phase: "net", Title: "TLS", Status: probe.Pass,
		}},
	})

	if r.Guidance != nil {
		t.Fatal("guidance present before it was asked for")
	}
	r.AttachGuidance()

	if _, ok := r.Guidance["protocol.malformed_json"]; !ok {
		t.Error("the failing check's guidance is missing")
	}
	if _, ok := r.Guidance["net.tls"]; ok {
		t.Error("a passing check contributed guidance; the report is about what went wrong")
	}
	if len(r.Guidance) != 1 {
		t.Errorf("guidance has %d entries, want 1", len(r.Guidance))
	}
}

// TestAttachGuidanceDeduplicates is the reason this is a dictionary rather
// than a field on every finding.
func TestAttachGuidanceDeduplicates(t *testing.T) {
	r := guidedReport()
	same := r.Phases[0].Findings[0]
	for range 40 {
		r.Phases[0].Findings = append(r.Phases[0].Findings, same)
	}
	r.AttachGuidance()
	if len(r.Guidance) != 1 {
		t.Errorf("41 findings of one check produced %d entries, want 1", len(r.Guidance))
	}
}

// TestGuidanceAbsentWhenNothingFailed keeps a clean report clean.
func TestGuidanceAbsentWhenNothingFailed(t *testing.T) {
	r := &Report{Phases: []probe.PhaseResult{{
		Name: "net", Status: probe.Pass,
		Findings: []probe.Finding{{ID: "net.tls", Status: probe.Pass}},
	}}}
	r.AttachGuidance()
	if r.Guidance != nil {
		t.Errorf("a passing report carried %d guidance entries", len(r.Guidance))
	}
}
