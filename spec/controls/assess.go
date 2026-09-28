// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: Apache-2.0

package controls

import "sort"

// State is what a set of verdicts says about one criterion.
type State string

// The four states. A criterion is judged only from verdicts the statement
// carries; nothing is inferred from a check that did not run.
const (
	// Evidenced: at least one mapped check ran, and none of them failed or
	// warned.
	Evidenced State = "evidenced"
	// Failing: a mapped check failed or warned. A warning counts, because
	// an auditor reads an exception as an exception whatever its severity.
	Failing State = "failing"
	// NotAssessed: checks map to the criterion, but none of them ran — or
	// every one was skipped — in this statement.
	NotAssessed State = "not assessed"
	// NotCovered: no passmcp check can evidence the criterion at all, and
	// the mapping says why.
	NotCovered State = "not covered by passmcp"
)

// Verdict is the part of a check's result an assessment reads: its id,
// its status and the recorded requests that produced it.
type Verdict struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
}

// CheckState is one mapped check's contribution to a criterion.
type CheckState struct {
	ID       string   `json:"id"`
	Status   string   `json:"status"`
	Evidence []string `json:"evidence,omitempty"`
}

// Assessment is one criterion's state, with the checks that decided it.
type Assessment struct {
	ID     string       `json:"id"`
	Title  string       `json:"title"`
	State  State        `json:"state"`
	Checks []CheckState `json:"checks,omitempty"`
	// Reason is set for a criterion no check can evidence.
	Reason string `json:"reason,omitempty"`
}

// Assess judges every criterion of the framework from the verdicts alone.
// It makes no request and reads nothing but its arguments: a statement is
// verifiable offline, and so is what it says about a framework.
func (m *Mapping) Assess(verdicts []Verdict) []Assessment {
	byCriterion := map[string][]CheckState{}
	for _, v := range verdicts {
		e, ok := m.Lookup(v.ID)
		if !ok {
			continue
		}
		for _, c := range e.Controls {
			byCriterion[c] = append(byCriterion[c], CheckState(v))
		}
	}
	out := make([]Assessment, 0, len(m.Criteria))
	for _, c := range m.Criteria {
		a := Assessment{ID: c.ID, Title: c.Title}
		if c.Reason != "" {
			a.State, a.Reason = NotCovered, c.Reason
			out = append(out, a)
			continue
		}
		checks := byCriterion[c.ID]
		sort.SliceStable(checks, func(i, j int) bool { return checks[i].ID < checks[j].ID })
		a.Checks = checks
		a.State = stateOf(checks)
		out = append(out, a)
	}
	return out
}

// stateOf reduces a criterion's check results to one state.
func stateOf(checks []CheckState) State {
	ran := false
	for _, c := range checks {
		switch c.Status {
		case "fail", "warn":
			return Failing
		case "pass", "info":
			ran = true
		}
	}
	if ran {
		return Evidenced
	}
	return NotAssessed
}
