// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"

	"satellion.com/passmcp/internal/probe"
)

// RubricVersion is the version of the scoring rubric.
//
// It exists because a score is only comparable to another score computed the
// same way. "82/100" in a report from 2027 and "82/100" from 2029 are the
// same number about possibly different things, and an attestation that
// carries the total without the rubric behind it is publishing a figure
// nothing can be compared to.
//
// Increment it when the weights change, when a category is added or removed,
// or when the deduction model changes — anything that would move a score
// without the server moving. Never increment it for a new check inside an
// existing category: that is the rubric working, not changing.
//
// 1: six weighted categories — connectivity 10, authorization 20, protocol
// 20, catalog 15, execution 20, performance 15 — scored over the phases each
// names, with unassessed categories excluded from the weighting rather than
// counted as zero.
const RubricVersion = "1"

// CheckInventoryVersion is the version of the check catalogue the ids in a
// report belong to.
//
// It follows the same rule as SchemaVersion, for the same reason: increment it
// when an id is renamed, removed, or changes what it asserts, and never when
// one is added. A consumer holding an attestation from two years ago needs to
// know whether `catalog.tools.output_schema` still means what it meant then,
// and the generated inventory cannot tell it that on its own — docs/checks.md
// describes the current catalogue, not the one the statement was written
// against.
//
// 1: the catalogue as generated from the call sites, ids in the
// <phase>.<check> form with auth.source.* as the one computed family.
const CheckInventoryVersion = "1"

// Category groups phases for scoring.
type Category struct {
	Name       string   `json:"name"`
	Weight     int      `json:"weight"`
	Phases     []string `json:"phases"`
	Assessed   bool     `json:"assessed"`
	Score      float64  `json:"score"`
	Deductions []string `json:"deductions,omitempty"`
}

// Score is the weighted rating with its full derivation.
type Score struct {
	Total      float64    `json:"total"`
	Assessed   int        `json:"categories_assessed"`
	Of         int        `json:"categories_total"`
	Categories []Category `json:"categories"`
	// Grade is a coarse letter for dashboards: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, F below.
	Grade string `json:"grade"`
}

var categories = []Category{
	{Name: "connectivity", Weight: 10, Phases: []string{"net"}},
	{Name: "authorization", Weight: 20, Phases: []string{"discovery", "auth"}},
	{Name: "protocol", Weight: 20, Phases: []string{"handshake", "protocol", "resilience"}},
	{Name: "catalog", Weight: 15, Phases: []string{"catalog"}},
	{Name: "execution", Weight: 20, Phases: []string{"execution"}},
	{Name: "performance", Weight: 15, Phases: []string{"performance"}},
}

// Deduction points per severity. A category cannot go below zero.
var deduction = map[probe.Severity]float64{probe.Critical: 100, probe.Major: 40, probe.Minor: 15}

// defaultDeduction is what a failure with no recognised severity costs, and
// warnDeduction what a warning costs. Named rather than inlined because the
// published rubric reads them: a number that exists only inside a switch is
// a number nobody outside the code can check a score against.
const (
	defaultDeduction = 15
	warnDeduction    = 5
)

// GradeBand is one letter and the lowest total that earns it.
type GradeBand struct {
	Grade string  `json:"grade"`
	Min   float64 `json:"min"`
}

// grades are checked in order; the first band whose minimum the total
// reaches is the grade.
var grades = []GradeBand{{"A", 90}, {"B", 75}, {"C", 60}, {"D", 40}, {"F", 0}}

// RubricSpec is the scoring rubric as data: everything a third party needs
// to recompute a score from a list of findings, or to check one.
//
// It is published as spec/rubric under Apache-2.0 (ADR 0011) so that a
// gateway or registry can implement it without taking on this package's
// licence. It is built from the same variables ComputeScore reads, and a
// generator writes the published file from it, so the two cannot disagree.
type RubricSpec struct {
	Version    string          `json:"version"`
	Categories []RubricWeight  `json:"categories"`
	Deductions RubricDeduction `json:"deductions"`
	Grades     []GradeBand     `json:"grades"`
	// Rules are the parts of the model that are behaviour rather than
	// numbers, stated so an implementation can follow them.
	Rules []string `json:"rules"`
}

// RubricWeight is one category's weight and the phases scored under it.
type RubricWeight struct {
	Name   string   `json:"name"`
	Weight int      `json:"weight"`
	Phases []string `json:"phases"`
}

// RubricDeduction is what each outcome costs a category.
type RubricDeduction struct {
	Critical float64 `json:"failCritical"`
	Major    float64 `json:"failMajor"`
	Minor    float64 `json:"failMinor"`
	Other    float64 `json:"failOtherSeverity"`
	Warn     float64 `json:"warn"`
}

// Rubric returns the rubric ComputeScore applies.
func Rubric() RubricSpec {
	r := RubricSpec{
		Version: RubricVersion,
		Deductions: RubricDeduction{
			Critical: deduction[probe.Critical],
			Major:    deduction[probe.Major],
			Minor:    deduction[probe.Minor],
			Other:    defaultDeduction,
			Warn:     warnDeduction,
		},
		Grades: append([]GradeBand(nil), grades...),
		Rules: []string{
			"every category starts at 100 and each failing or warning finding in its phases deducts the amount for its outcome",
			"a category cannot go below 0",
			"a category is assessed when at least one of its phases ran and was not skipped; unassessed categories are excluded from the weighting, not counted as 0",
			"the total is the weight-averaged score of the assessed categories",
			"with no category assessed the grade is n/a",
			"pass, info and skip findings deduct nothing",
		},
	}
	for _, c := range categories {
		r.Categories = append(r.Categories, RubricWeight{Name: c.Name, Weight: c.Weight, Phases: append([]string(nil), c.Phases...)})
	}
	return r
}

// ComputeScore derives the score from findings. Only categories whose
// phases actually ran count; the report says how many were assessed so a
// high score on a partial run cannot be mistaken for a full one.
func ComputeScore(phases []probe.PhaseResult) Score {
	byName := map[string]probe.PhaseResult{}
	for _, p := range phases {
		byName[p.Name] = p
	}
	sc := Score{Of: len(categories)}
	var weighted, weights float64
	for _, cat := range categories {
		c := scoreCategory(cat, byName)
		if c.Assessed {
			sc.Assessed++
			weighted += c.Score * float64(c.Weight)
			weights += float64(c.Weight)
		}
		sc.Categories = append(sc.Categories, c)
	}
	if weights > 0 {
		sc.Total = weighted / weights
	}
	sc.Grade = gradeOf(sc)
	return sc
}

// scoreCategory starts a category at 100 and deducts for every failing or
// warning finding in its phases that ran, never going below zero.
func scoreCategory(cat Category, byName map[string]probe.PhaseResult) Category {
	c := cat
	c.Score = 100
	for _, pn := range c.Phases {
		p, ok := byName[pn]
		if !ok || p.Status == probe.Skip {
			continue
		}
		c.Assessed = true
		for _, f := range p.Findings {
			c.deduct(f)
		}
	}
	if c.Score < 0 {
		c.Score = 0
	}
	return c
}

// deduct charges one finding against the category: a failure by its
// severity, a warning by warnDeduction, anything else nothing.
func (c *Category) deduct(f probe.Finding) {
	switch f.Status {
	case probe.Fail:
		d := deduction[f.Severity]
		if d == 0 {
			d = defaultDeduction
		}
		c.Score -= d
		c.Deductions = append(c.Deductions, fmt.Sprintf("-%.0f %s: %s", d, f.ID, f.Detail))
	case probe.Warn:
		c.Score -= warnDeduction
		c.Deductions = append(c.Deductions, fmt.Sprintf("-%d %s: %s", warnDeduction, f.ID, f.Detail))
	}
}

// gradeOf is the first band whose minimum the total reaches, or n/a when no
// category was assessed.
func gradeOf(sc Score) string {
	if sc.Assessed == 0 {
		return "n/a"
	}
	for _, g := range grades {
		if sc.Total >= g.Min {
			return g.Grade
		}
	}
	return "n/a"
}
