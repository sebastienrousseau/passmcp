// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
)

// FuzzHTMLEscaping drives arbitrary server-controlled text through every
// place the report renders one.
//
// The property is not "it does not crash" — html/template will not crash.
// It is that no input, however shaped, can close a tag or an attribute and
// become markup. A diagnostic that renders a hostile catalog into an
// executable page has turned itself into the delivery mechanism.
func FuzzHTMLEscaping(f *testing.F) {
	f.Add("plain text")
	f.Add("<script>alert(1)</script>")
	f.Add(`"><img src=x onerror=alert(1)>`)
	f.Add("</title><style>body{display:none}</style>")
	f.Add(`'; DROP TABLE tools; --`)
	f.Add("\x00\x01\x02")
	f.Add(strings.Repeat("<", 500))
	f.Add("</textarea></script><script>x</script>")
	f.Add("javascript:alert(1)")
	f.Add("\u202e\u200b zero width and bidi")

	f.Fuzz(func(t *testing.T, hostile string) {
		r := &Report{
			Passmcp: Meta{Version: hostile, SchemaVersion: SchemaVersion},
			Target:  Target{Endpoint: hostile, Host: hostile, Scheme: "https"},
			Started: time.Unix(0, 0).UTC(),
			TraceID: hostile,
			Auth:    AuthSummary{Mode: hostile, Reached: true, Required: true, Issuer: hostile},
			Server:  &ServerInfo{Name: hostile, Version: hostile, Protocol: hostile},
			Phases: []probe.PhaseResult{{
				Name: hostile, Title: hostile, Status: probe.Fail, Summary: hostile,
				Skipped: hostile,
				Findings: []probe.Finding{{
					ID: hostile, Title: hostile, Status: probe.Fail, Severity: probe.Major,
					Detail: hostile, Advice: hostile, Evidence: []string{hostile},
				}},
			}},
			Catalog: Catalog{Tools: []ToolSummary{{Name: hostile, Title: hostile, Description: hostile}}},
			Counts:  Counts{Fail: 1},
			Score:   Score{Total: 50, Grade: hostile, Assessed: 1, Of: 6},
		}

		var b strings.Builder
		if err := HTML(&b, r, HTMLOptions{Verbose: true}); err != nil {
			t.Fatalf("rendering must not fail on server data: %v", err)
		}
		out := b.String()

		// The document's own markup is known and fixed. Anything beyond it
		// came from the input, so counting is enough: the template opens
		// exactly one <html>, one <head>, one <body>, one <style>.
		// Counted with their closing bracket so <head> does not match the
		// template's own <header>.
		//
		// <svg is counted rather than forbidden: the template inlines the
		// passmcp mark several times — masthead, cover, colophon, and the
		// running footer that repeats on every printed page — because a
		// report has to identify itself with no network available. The
		// baseline comes from rendering benign data rather than a literal,
		// so adding the mark somewhere else does not read as an injection.
		for tag, want := range map[string]int{"<html ": 1, "<head>": 1, "<body>": 1, "<style>": 1, "<svg": baselineSVGCount(t)} {
			if got := strings.Count(out, tag); got != want {
				t.Errorf("input produced %d %q, want %d", got, tag, want)
			}
		}
		// And no tag the template never writes may appear at all.
		for _, tag := range []string{"<script", "<img", "<iframe", "<object", "<embed", "<link", "<base", "<form"} {
			if strings.Contains(out, tag) {
				t.Errorf("input produced a %q element", tag)
			}
		}
		if strings.Count(out, "</style>") != 1 {
			t.Error("input opened or closed the stylesheet")
		}
		if strings.Contains(out, `href="javascript:`) || strings.Contains(out, `src="javascript:`) {
			t.Error("input produced a javascript: URL")
		}
	})
}

// FuzzFixFirst drives the "what to fix first" selection, which sorts and
// truncates attacker-influenced data.
func FuzzFixFirst(f *testing.F) {
	f.Add(uint8(0), uint8(0), 3)
	f.Add(uint8(4), uint8(3), 200)

	f.Fuzz(func(t *testing.T, statusSeed, sevSeed uint8, n int) {
		if n < 0 || n > 2000 {
			return
		}
		statuses := []probe.Status{probe.Pass, probe.Warn, probe.Fail, probe.Skip, probe.Info}
		severities := []probe.Severity{probe.Critical, probe.Major, probe.Minor, probe.Note, ""}
		var fs []probe.Finding
		for i := 0; i < n; i++ {
			fs = append(fs, probe.Finding{
				ID:       "f",
				Status:   statuses[(int(statusSeed)+i)%len(statuses)],
				Severity: severities[(int(sevSeed)+i)%len(severities)],
			})
		}
		got := fixFirst(&Report{Phases: []probe.PhaseResult{{Findings: fs}}})
		if len(got) > 5 {
			t.Errorf("returned %d findings; the list is capped at five", len(got))
		}
		for _, x := range got {
			if x.Status != probe.Fail && x.Status != probe.Warn {
				t.Errorf("a %s finding is not something to fix", x.Status)
			}
		}
		// Failures always precede warnings, whatever the input order.
		seenWarn := false
		for _, x := range got {
			if x.Status == probe.Warn {
				seenWarn = true
			} else if seenWarn && x.Status == probe.Fail {
				t.Error("a failure was ordered after a warning")
			}
		}
	})
}

// baselineSVGCount renders a report with nothing hostile in it and counts
// the marks the template writes on its own. Anything above this came from
// the data.
func baselineSVGCount(t *testing.T) int {
	t.Helper()
	var b strings.Builder
	if err := HTML(&b, htmlFixture(), HTMLOptions{Verbose: true}); err != nil {
		t.Fatalf("rendering the baseline must not fail: %v", err)
	}
	return strings.Count(b.String(), "<svg")
}
