// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package controls

import (
	"encoding/csv"
	"io"
	"sort"
	"strings"
	"time"
)

// Record is one attestation as an evidence bundle reads it: which target,
// when, the digest of the statement file, and its verdicts.
type Record struct {
	Target   string
	RanAt    time.Time
	Digest   string
	Verdicts []Verdict
}

// Observation is a criterion's state in one attestation.
type Observation struct {
	Target string       `json:"target"`
	RanAt  time.Time    `json:"ranAt"`
	Digest string       `json:"attestationSha256"`
	State  State        `json:"state"`
	Checks []CheckState `json:"checks,omitempty"`
	// Regressed marks an observation that is worse than the one before it
	// for the same target: evidenced then, failing now.
	Regressed bool `json:"regressed,omitempty"`
}

// BundleCriterion is one criterion across every attestation in the period.
type BundleCriterion struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	// State is the criterion's state at the latest attestation of each
	// target, reduced across targets: failing if any is failing.
	State        State         `json:"state"`
	Reason       string        `json:"reason,omitempty"`
	Observations []Observation `json:"observations,omitempty"`
	Regressed    bool          `json:"regressed,omitempty"`
}

// Bundle is the evidence for one framework over one period.
type Bundle struct {
	Framework Framework         `json:"framework"`
	Name      string            `json:"name"`
	Version   string            `json:"version"`
	Note      string            `json:"note"`
	From      *time.Time        `json:"from,omitempty"`
	To        *time.Time        `json:"to,omitempty"`
	Targets   []string          `json:"targets"`
	Criteria  []BundleCriterion `json:"criteria"`
}

// Bundle assesses every record inside [from, to] (either bound may be
// zero, meaning open) and lays the results out per criterion, oldest
// first, so a regression between two dates is visible and marked.
func (m *Mapping) Bundle(records []Record, from, to time.Time) Bundle {
	b := Bundle{Framework: m.Framework, Name: m.Name, Version: m.Version, Note: m.Note, Targets: []string{}}
	if !from.IsZero() {
		f := from.UTC()
		b.From = &f
	}
	if !to.IsZero() {
		t := to.UTC()
		b.To = &t
	}
	in := inPeriod(records, from, to)
	targets := map[string]bool{}
	assessed := make([][]Assessment, len(in))
	for i, r := range in {
		targets[r.Target] = true
		assessed[i] = m.Assess(r.Verdicts)
	}
	for t := range targets {
		b.Targets = append(b.Targets, t)
	}
	sort.Strings(b.Targets)
	for ci, c := range m.Criteria {
		b.Criteria = append(b.Criteria, bundleCriterion(c, ci, in, assessed))
	}
	return b
}

func inPeriod(records []Record, from, to time.Time) []Record {
	var in []Record
	for _, r := range records {
		if !from.IsZero() && r.RanAt.Before(from) {
			continue
		}
		if !to.IsZero() && r.RanAt.After(to) {
			continue
		}
		in = append(in, r)
	}
	sort.SliceStable(in, func(i, j int) bool { return in[i].RanAt.Before(in[j].RanAt) })
	return in
}

// bundleCriterion builds one criterion's row. assessed[i][ci] is the
// criterion's assessment in record i: Assess returns criteria in mapping
// order, so the index lines up.
func bundleCriterion(c Criterion, ci int, in []Record, assessed [][]Assessment) BundleCriterion {
	bc := BundleCriterion{ID: c.ID, Title: c.Title}
	if c.Reason != "" {
		bc.State, bc.Reason = NotCovered, c.Reason
		return bc
	}
	last := map[string]State{}
	for i, r := range in {
		a := assessed[i][ci]
		o := Observation{Target: r.Target, RanAt: r.RanAt.UTC(), Digest: r.Digest, State: a.State, Checks: a.Checks}
		if prev, ok := last[r.Target]; ok && prev == Evidenced && a.State == Failing {
			o.Regressed, bc.Regressed = true, true
		}
		last[r.Target] = a.State
		bc.Observations = append(bc.Observations, o)
	}
	bc.State = reduce(last)
	return bc
}

// reduce combines each target's latest state into one.
func reduce(latest map[string]State) State {
	if len(latest) == 0 {
		return NotAssessed
	}
	state := NotAssessed
	for _, s := range latest {
		switch s {
		case Failing:
			return Failing
		case Evidenced:
			state = Evidenced
		}
	}
	return state
}

// WriteCSV writes the bundle as one row per criterion and observation. A
// criterion with no observation still gets one row, so the CSV lists every
// criterion, as the JSON does.
func (b Bundle) WriteCSV(w io.Writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write([]string{"framework", "criterion", "title", "state", "target", "ran_at", "attestation_sha256", "checks", "regressed", "reason"}); err != nil {
		return err
	}
	for _, c := range b.Criteria {
		if len(c.Observations) == 0 {
			if err := cw.Write([]string{string(b.Framework), c.ID, c.Title, string(c.State), "", "", "", "", "", c.Reason}); err != nil {
				return err
			}
			continue
		}
		for _, o := range c.Observations {
			row := []string{string(b.Framework), c.ID, c.Title, string(o.State), o.Target, o.RanAt.Format(time.RFC3339), o.Digest, checkList(o.Checks), boolText(o.Regressed), c.Reason}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
	}
	cw.Flush()
	return cw.Error()
}

func checkList(cs []CheckState) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		p := c.ID + "=" + c.Status
		if len(c.Evidence) > 0 {
			p += " (" + strings.Join(c.Evidence, ", ") + ")"
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, "; ")
}

func boolText(b bool) string {
	if b {
		return "yes"
	}
	return ""
}
