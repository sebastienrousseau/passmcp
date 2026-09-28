// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package fleet

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/telemetry"
)

// Change kinds, in the words a fleet report uses. The catalogue kinds are
// the baseline ladder's own.
const (
	KindToolAdded       = "tool-added"
	KindToolRemoved     = "tool-removed"
	KindAnnotation      = "annotation"
	KindDescription     = "description"
	KindSchema          = "schema"
	KindVerdictRegessed = "verdict-regressed"
	KindScoreDropped    = "score-dropped"
)

// Change is one difference between a server's previous run and this one.
type Change struct {
	Kind     string `json:"kind"`
	Tool     string `json:"tool,omitempty"`
	Check    string `json:"check,omitempty"`
	Severity string `json:"severity"`
	Detail   string `json:"detail"`
	Before   string `json:"before,omitempty"`
	After    string `json:"after,omitempty"`
}

// severity ranks, for ordering and for the worst change.
var severityRank = map[string]int{"noise": 0, "notable": 1, "serious": 2, "critical": 3}

// compareRuns diffs the previous recorded run against the one in dir:
// catalogue, verdicts and score.
func compareRuns(prev *latest, dir string, red *telemetry.Redactor) ([]Change, error) {
	beforeSnap, err := loadSnapshot(filepath.Join(prev.Dir, catalogueFile))
	if err != nil {
		return nil, err
	}
	afterSnap, err := loadSnapshot(filepath.Join(dir, catalogueFile))
	if err != nil {
		return nil, err
	}
	beforeSt, err := loadStatement(filepath.Join(prev.Dir, attestationFile))
	if err != nil {
		return nil, err
	}
	afterSt, err := loadStatement(filepath.Join(dir, attestationFile))
	if err != nil {
		return nil, err
	}
	changes := catalogueChanges(beforeSnap, afterSnap)
	changes = append(changes, verdictChanges(beforeSt, afterSt)...)
	changes = append(changes, scoreChange(beforeSt, afterSt)...)
	for i := range changes {
		changes[i].Detail = red.String(changes[i].Detail)
		changes[i].Before = red.String(changes[i].Before)
		changes[i].After = red.String(changes[i].After)
	}
	sort.SliceStable(changes, func(i, j int) bool {
		return severityRank[changes[i].Severity] > severityRank[changes[j].Severity]
	})
	return changes, nil
}

// catalogueChanges is the baseline ladder, with one escalation: a
// readOnlyHint that changes in either direction is critical in a fleet. The
// ladder rates withdrawing it as serious, because for one reviewed server it
// is the safer direction; across a fleet it means a tool that every client
// was treating as safe to call is now declared to change something, and
// that is exactly the silent widening a scheduled run exists to catch.
func catalogueChanges(before, after baseline.Snapshot) []Change {
	var out []Change
	for _, c := range baseline.Diff(before, after) {
		sev := c.Severity.String()
		if c.Kind == KindAnnotation && c.Detail != "destructiveHint changed" {
			sev = "critical"
		}
		out = append(out, Change{Kind: c.Kind, Tool: c.Tool, Severity: sev, Detail: c.Detail, Before: c.Was, After: c.Now})
	}
	return out
}

// verdictChanges are the checks whose outcome got worse.
func verdictChanges(before, after *attestation.Statement) []Change {
	d := attestation.Compare(before, after)
	out := make([]Change, 0, len(d.Regressed))
	for _, c := range d.Regressed {
		sev := "notable"
		if c.To == "fail" {
			sev = "serious"
		}
		out = append(out, Change{
			Kind: KindVerdictRegessed, Check: c.ID, Severity: sev,
			Detail: fmt.Sprintf("%s went from %s to %s", c.ID, c.From, c.To),
			Before: c.From, After: c.To,
		})
	}
	return out
}

// scoreChange reports a lower score, when the two runs can be compared.
func scoreChange(before, after *attestation.Statement) []Change {
	d := attestation.Compare(before, after)
	if d.ScoreFrom == nil || d.ScoreTo == nil || *d.ScoreTo >= *d.ScoreFrom {
		return nil
	}
	return []Change{{
		Kind: KindScoreDropped, Severity: "notable",
		Detail: fmt.Sprintf("the score fell from %.1f to %.1f", *d.ScoreFrom, *d.ScoreTo),
		Before: fmt.Sprintf("%.1f", *d.ScoreFrom), After: fmt.Sprintf("%.1f", *d.ScoreTo),
	}}
}

// worstOf is the highest severity and whether any change is critical.
func worstOf(changes []Change) (string, bool) {
	worst, rank := "", -1
	for _, c := range changes {
		if severityRank[c.Severity] > rank {
			worst, rank = c.Severity, severityRank[c.Severity]
		}
	}
	return worst, rank == severityRank["critical"]
}

func loadSnapshot(path string) (baseline.Snapshot, error) {
	var s baseline.Snapshot
	b, err := os.ReadFile(path) // #nosec G304 -- under the operator's state directory
	if err != nil {
		return s, err
	}
	return s, json.Unmarshal(b, &s)
}

func loadStatement(path string) (*attestation.Statement, error) {
	b, err := os.ReadFile(path) // #nosec G304 -- under the operator's state directory
	if err != nil {
		return nil, err
	}
	return attestation.Parse(b)
}
