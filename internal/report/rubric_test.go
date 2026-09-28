// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"testing"

	"satellion.com/passmcp/internal/probe"
)

// TestThePublishedRubricIsTheOneApplied. Rubric is what spec/rubric is
// generated from; if it described weights or bands ComputeScore did not
// use, the Apache-2.0 copy would teach implementers the wrong model.
func TestThePublishedRubricIsTheOneApplied(t *testing.T) {
	r := Rubric()
	if r.Version != RubricVersion {
		t.Errorf("version = %q, want %q", r.Version, RubricVersion)
	}
	total := 0
	for i, c := range r.Categories {
		total += c.Weight
		if c.Name != categories[i].Name || c.Weight != categories[i].Weight {
			t.Errorf("category %d = %+v, scorer uses %+v", i, c, categories[i])
		}
	}
	if total != 100 {
		t.Errorf("weights sum to %d", total)
	}
	for i := 1; i < len(r.Grades); i++ {
		if r.Grades[i].Min >= r.Grades[i-1].Min {
			t.Errorf("grade bands not descending: %+v", r.Grades)
		}
	}
	// One finding per outcome, each in its own category, so each deduction
	// the rubric publishes is observed once in a computed score.
	for _, tc := range []struct {
		st   probe.Status
		sev  probe.Severity
		want float64
	}{
		{probe.Fail, probe.Critical, r.Deductions.Critical},
		{probe.Fail, probe.Major, r.Deductions.Major},
		{probe.Fail, probe.Minor, r.Deductions.Minor},
		{probe.Fail, "", r.Deductions.Other},
		{probe.Warn, "", r.Deductions.Warn},
	} {
		sc := ComputeScore([]probe.PhaseResult{{Name: "net", Status: tc.st,
			Findings: []probe.Finding{{ID: "x", Status: tc.st, Severity: tc.sev}}}})
		if got := 100 - sc.Categories[0].Score; got != tc.want {
			t.Errorf("%s/%s deducted %v, rubric says %v", tc.st, tc.sev, got, tc.want)
		}
	}
}
