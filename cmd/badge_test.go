// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/report"
)

// decodeBadge parses what the command wrote.
func decodeBadge(t *testing.T, out string) badgeEndpoint {
	t.Helper()
	var b badgeEndpoint
	if err := json.Unmarshal([]byte(out), &b); err != nil {
		t.Fatalf("the badge is not JSON: %v\n%s", err, out)
	}
	return b
}

// reportFixture writes a JSON report with the given score.
func reportFixture(t *testing.T, total float64, grade string, assessed, of int) string {
	t.Helper()
	rep := report.Report{Score: report.Score{
		Total: total, Grade: grade, Assessed: assessed, Of: of,
	}}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// TestBadgeRendersTheScore is the ordinary case: a shields endpoint
// document a project can commit and point at.
func TestBadgeRendersTheScore(t *testing.T) {
	path := reportFixture(t, 92.4, "A", 9, 9)

	out, code := run(t, "badge", path)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	b := decodeBadge(t, out)
	if b.SchemaVersion != 1 {
		t.Errorf("schemaVersion = %d, want 1", b.SchemaVersion)
	}
	if b.Label != "passmcp" {
		t.Errorf("label = %q", b.Label)
	}
	if !strings.Contains(b.Message, "92") {
		t.Errorf("message does not carry the score: %q", b.Message)
	}
	if b.IsError {
		t.Error("a scored run is not an error")
	}
}

// TestBadgeColourFollowsTheGrade: the badge and the report it came from
// must not disagree about where a boundary is, which is why the colour is
// derived from the grade rather than from the number a second time.
func TestBadgeColourFollowsTheGrade(t *testing.T) {
	for grade, want := range map[string]string{
		"A": "brightgreen",
		"B": "green",
		"C": "yellow",
		"D": "orange",
		"F": "red",
	} {
		if got := badgeColor(grade); got != want {
			t.Errorf("badgeColor(%q) = %q, want %q", grade, got, want)
		}
	}
	// Anything unrecognised is the worst colour, not the best. A badge
	// that defaults to green is a badge that lies when something upstream
	// changes.
	if got := badgeColor(""); got != "red" {
		t.Errorf("an unknown grade rendered %q, want red", got)
	}
}

// TestBadgeReportsNoVerdictAsAnError is the one that matters. A run that
// never reached a verdict has no score, and a badge reading 0/100 would
// repeat the exact mistake the exit-code contract exists to prevent: a
// pipeline going green because the endpoint was down.
func TestBadgeReportsNoVerdictAsAnError(t *testing.T) {
	path := reportFixture(t, 0, "", 0, 0)

	out, code := run(t, "badge", path)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	b := decodeBadge(t, out)
	if !b.IsError {
		t.Error("a run with no verdict must render as an error")
	}
	if strings.Contains(b.Message, "0/100") {
		t.Errorf("a run with no verdict must not show a score: %q", b.Message)
	}
	if !strings.Contains(b.Message, "no verdict") {
		t.Errorf("message = %q, want it to say there was no verdict", b.Message)
	}
}

// TestBadgeTakesALabel, for a project badging more than one server.
func TestBadgeTakesALabel(t *testing.T) {
	path := reportFixture(t, 80, "B", 9, 9)

	out, code := run(t, "badge", path, "--label", "billing mcp")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	if b := decodeBadge(t, out); b.Label != "billing mcp" {
		t.Errorf("label = %q", b.Label)
	}
}

// TestBadgeRejectsSomethingThatIsNotAReport, rather than emitting a badge
// for a document it did not understand.
func TestBadgeRejectsSomethingThatIsNotAReport(t *testing.T) {
	p := filepath.Join(t.TempDir(), "junk.json")
	if err := os.WriteFile(p, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code := run(t, "badge", p); code == 0 {
		t.Error("a file that is not a report should fail")
	}
}

// TestBadgeReadsStandardInput, so it composes with the rest of a pipeline
// the way attest does.
func TestBadgeReadsStandardInput(t *testing.T) {
	rep := report.Report{Score: report.Score{Total: 61, Grade: "C", Assessed: 9, Of: 9}}
	b, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	orig := os.Stdin
	os.Stdin = r
	t.Cleanup(func() { os.Stdin = orig })
	go func() { _, _ = w.Write(b); _ = w.Close() }()

	out, code := run(t, "badge")
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	got := decodeBadge(t, out)
	if got.Color != "yellow" {
		t.Errorf("color = %q, want yellow for a C", got.Color)
	}
}
