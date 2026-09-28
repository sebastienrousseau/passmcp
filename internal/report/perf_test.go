// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"encoding/json"
	"io"
	"testing"
)

// "Fast" is unfalsifiable. A budget with a gate is the only version of a
// performance claim that survives a year of commits.
//
// What is gated here is allocation counts, not wall clock, and that is a
// deliberate departure from the roadmap's "every budget is a CI job".
// A time budget on a shared runner is a flaky gate, and a flaky gate
// teaches people to re-run the build until it goes green -- which is the
// same outcome as having no gate, reached more slowly and with less
// trust. Allocations are deterministic for a given input and toolchain,
// they catch the regression that actually matters (an accidental
// quadratic, a copy per finding), and they do not care how busy the
// machine is.
//
// The wall-clock numbers are measured and published rather than gated;
// see docs/reports.md. A performance claim without a method is marketing,
// and a performance gate that cries wolf is worse than neither.
//
// Every ceiling below is roughly twice what the code currently does. That
// is headroom for a toolchain that allocates differently, not permission
// to double: a change that moves one of these by half should be a change
// somebody meant to make.

// renderBudget is one renderer's allocation ceiling for a 200-tool report.
type renderBudget struct {
	name    string
	ceiling int
	render  func(*Report)
}

func TestRenderAllocationBudgets(t *testing.T) {
	r := bigReport(200)

	for _, b := range []renderBudget{
		// Measured at 7,039 on darwin/arm64, go1.27.
		{"text", 15000, func(r *Report) { Text(io.Discard, r, TextOptions{Width: 100, Verbose: true}) }},
		// Measured at 2,873.
		{"markdown", 8000, func(r *Report) { Markdown(io.Discard, r) }},
		// Measured at 10,015. The most expensive, and reasonably so: it
		// is the only renderer that escapes every string on the way out.
		{"html", 22000, func(r *Report) { _ = HTML(io.Discard, r, HTMLOptions{}) }},
		// Measured at 7. The encoder streams, and it should stay that
		// way: a JSON renderer that started buffering would show up here
		// as three orders of magnitude.
		{"json", 100, func(r *Report) { _ = json.NewEncoder(io.Discard).Encode(r) }},
	} {
		t.Run(b.name, func(t *testing.T) {
			got := int(testing.AllocsPerRun(3, func() { b.render(r) }))
			if got > b.ceiling {
				t.Errorf("rendering 200 tools as %s took %d allocations, over the %d budget.\n"+
					"Either the change is worth the cost and the budget moves with it in the same "+
					"commit, or something started copying per finding.", b.name, got, b.ceiling)
			}
			t.Logf("%s: %d allocations, budget %d", b.name, got, b.ceiling)
		})
	}
}

// TestRenderScalesLinearly is the regression this is really for.
//
// A report is a list, and rendering one should cost about twice as much
// for twice as many findings. An accidental quadratic passes every other
// test in this package -- it is correct, it is just unusable on the
// catalogue sizes that make a diagnostic worth running.
func TestRenderScalesLinearly(t *testing.T) {
	small := int(testing.AllocsPerRun(3, func() {
		_ = HTML(io.Discard, bigReport(50), HTMLOptions{})
	}))
	large := int(testing.AllocsPerRun(3, func() {
		_ = HTML(io.Discard, bigReport(200), HTMLOptions{})
	}))

	// Four times the findings, so linear means about four times the work.
	// Six is the line: comfortably above the constant overhead a small
	// report pays, comfortably below anything quadratic, which at this
	// ratio would be sixteen.
	if ratio := float64(large) / float64(small); ratio > 6 {
		t.Errorf("four times the findings cost %.1f times the allocations (%d then %d); "+
			"that is not linear, and on a real catalogue it will not be tolerable",
			ratio, small, large)
	}
}

// TestScoreDoesNotCopyTheReport: the score is computed by every surface
// and recomputed whenever a phase result changes, so it is the one piece
// of arithmetic worth keeping cheap.
func TestScoreDoesNotCopyTheReport(t *testing.T) {
	phases := bigReport(200).Phases
	// Measured at 815 allocations.
	const ceiling = 2000
	if got := int(testing.AllocsPerRun(3, func() { _ = ComputeScore(phases) })); got > ceiling {
		t.Errorf("scoring 400 findings took %d allocations, over the %d budget", got, ceiling)
	}
}
