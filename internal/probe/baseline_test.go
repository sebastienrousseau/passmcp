// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/baseline"
	"satellion.com/passmcp/internal/telemetry"
)

// baseSession builds a session carrying a catalogue and, optionally, an
// approved snapshot to judge it against.
func baseSession(tools []passmcp.Tool, approved *baseline.Snapshot) *Session {
	return &Session{
		Tools: tools,
		Opts: Options{
			Recorder: &telemetry.Recorder{},
			Endpoint: "https://x/mcp",
			Baseline: approved,
		},
	}
}

func ro(name, desc string, readOnly bool) passmcp.Tool {
	b := readOnly
	return passmcp.Tool{
		Name: name, Description: desc,
		Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &b},
	}
}

// TestBaselineIsSilentWithoutOne: a check that invented a verdict from an
// absent file would be worse than no check, so it produces nothing at all.
func TestBaselineIsSilentWithoutOne(t *testing.T) {
	s := baseSession([]passmcp.Tool{ro("a", "A tool.", true)}, nil)
	if got := checkBaseline(s); len(got) != 0 {
		t.Fatalf("want no finding without a baseline, got %+v", got)
	}
}

// TestBaselinePassesAnUnchangedCatalogue, and says when it was approved.
func TestBaselinePassesAnUnchangedCatalogue(t *testing.T) {
	tools := []passmcp.Tool{ro("a", "A tool.", true), ro("b", "Another.", true)}
	snap := baseline.Take("https://x/mcp", tools)

	out := checkBaseline(baseSession(tools, &snap))
	if len(out) != 1 {
		t.Fatalf("want one finding, got %+v", out)
	}
	if out[0].Status != Pass {
		t.Fatalf("an unchanged catalogue did not pass: %+v", out[0])
	}
	if !strings.Contains(out[0].Detail, "unchanged") {
		t.Errorf("the detail does not say so: %q", out[0].Detail)
	}
}

// TestBaselineFailsAReadOnlyFlip is the rug pull the whole mechanism
// exists for, and it must name the tool and quote both sides.
func TestBaselineFailsAReadOnlyFlip(t *testing.T) {
	snap := baseline.Take("https://x/mcp", []passmcp.Tool{ro("sweep", "Tidies things up.", false)})
	now := []passmcp.Tool{ro("sweep", "Tidies things up.", true)}

	out := checkBaseline(baseSession(now, &snap))
	if len(out) != 1 || out[0].Status != Fail {
		t.Fatalf("a readOnlyHint flip did not fail: %+v", out)
	}
	if out[0].Severity != Critical {
		t.Errorf("severity = %v, want Critical", out[0].Severity)
	}
	if !strings.Contains(out[0].Detail, "sweep") {
		t.Errorf("the finding does not name the tool: %q", out[0].Detail)
	}
	if !strings.Contains(out[0].Detail, "critical") {
		t.Errorf("the finding does not carry the change's own severity: %q", out[0].Detail)
	}
	if out[0].Advice == "" {
		t.Error("a failing drift check has to say what to do")
	}
}

// TestBaselineWarnsOnANotableChange: an ordinary edit is worth seeing and
// is not a failure.
func TestBaselineWarnsOnANotableChange(t *testing.T) {
	snap := baseline.Take("https://x/mcp", []passmcp.Tool{ro("a", "Looks up a record.", true)})
	now := []passmcp.Tool{ro("a", "Looks up a record by its identifier.", true)}

	out := checkBaseline(baseSession(now, &snap))
	if len(out) != 1 || out[0].Status != Warn {
		t.Fatalf("an ordinary edit should warn, got %+v", out)
	}
}

// TestBaselineReportsNoiseAsInformation is the property that keeps the
// gate switched on.
func TestBaselineReportsNoiseAsInformation(t *testing.T) {
	before := passmcp.Tool{Name: "q", Description: "Queries.", InputSchema: []byte(`{"type":"object","properties":{"a":{"type":"string"}}}`)}
	after := passmcp.Tool{Name: "q", Description: "Queries.", InputSchema: []byte(`{"type":"object","properties":{"a":{"type":"string"},"b":{"type":"string"}}}`)}
	snap := baseline.Take("https://x/mcp", []passmcp.Tool{before})

	out := checkBaseline(baseSession([]passmcp.Tool{after}, &snap))
	if len(out) != 1 {
		t.Fatalf("want one finding, got %+v", out)
	}
	if out[0].Status != Info {
		t.Fatalf("a new optional property should be information, got %s: %q", out[0].Status, out[0].Detail)
	}
}

// TestBaselineRecordsWhatItSaw, which is what --approve promotes.
func TestBaselineRecordsWhatItSaw(t *testing.T) {
	snap := baseline.Take("https://x/mcp", []passmcp.Tool{ro("a", "A.", true)})
	now := []passmcp.Tool{ro("a", "A.", true), ro("b", "B.", true)}

	s := baseSession(now, &snap)
	_ = checkBaseline(s)
	if s.Snapshot == nil {
		t.Fatal("the run did not record the catalogue it saw")
	}
	if len(s.Snapshot.Tools) != 2 {
		t.Errorf("the recorded snapshot has %d tools, want 2", len(s.Snapshot.Tools))
	}
	if s.Snapshot.Digest == snap.Digest {
		t.Error("the recorded snapshot should differ from the approved one here")
	}
}

// TestBaselineRefusesAFutureFormat rather than misreading it.
func TestBaselineRefusesAFutureFormat(t *testing.T) {
	snap := baseline.Snapshot{Version: 99}
	out := checkBaseline(baseSession([]passmcp.Tool{ro("a", "A.", true)}, &snap))
	if len(out) != 1 || out[0].Status != Info {
		t.Fatalf("want an informational refusal, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "re-approve") {
		t.Errorf("the finding does not say what to do: %q", out[0].Detail)
	}
}

// TestBaselineTruncatesALongDiff: a catalogue that changed forty times has
// one problem, and a finding that scrolls is one nobody finishes.
func TestBaselineTruncatesALongDiff(t *testing.T) {
	var before, after []passmcp.Tool
	for _, n := range []string{"a", "b", "c", "d", "e"} {
		before = append(before, ro(n, "Same.", false))
		after = append(after, ro(n, "Same.", true))
	}
	snap := baseline.Take("https://x/mcp", before)

	out := checkBaseline(baseSession(after, &snap))
	if len(out) != 1 || out[0].Status != Fail {
		t.Fatalf("five flips did not fail: %+v", out)
	}
	if !strings.Contains(out[0].Detail, "and 2 more") {
		t.Errorf("the diff was not truncated: %q", out[0].Detail)
	}
}
