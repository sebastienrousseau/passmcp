// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// payloadSession builds a session carrying the results a run collected.
func payloadSession(tools []passmcp.Tool, results ...ToolResult) *Session {
	return &Session{
		Tools:       tools,
		ToolResults: results,
		Opts:        Options{Recorder: &telemetry.Recorder{}},
	}
}

func ok(name string, bytes int) ToolResult {
	return ToolResult{Name: name, Executed: true, OK: true, TextBytes: bytes}
}

func payloadFinding(t *testing.T, s *Session) Finding {
	t.Helper()
	out := checkPayloadSize(s)
	if len(out) != 1 {
		t.Fatalf("want one finding, got %+v", out)
	}
	return out[0]
}

// TestPayloadSkipsWithNothingToWeigh. A check that passed having measured
// nothing is a check somebody will later believe.
func TestPayloadSkipsWithNothingToWeigh(t *testing.T) {
	f := payloadFinding(t, payloadSession(nil))
	if f.Status != Skip {
		t.Fatalf("want a skip with no results, got %s %q", f.Status, f.Detail)
	}

	// A call that failed returned no content either.
	f = payloadFinding(t, payloadSession(nil, ToolResult{Name: "t", Executed: true, ToolError: "no"}))
	if f.Status != Skip {
		t.Errorf("a failed call is not an answer to weigh: %+v", f)
	}
}

// TestPayloadPassesAnOrdinaryResult.
func TestPayloadPassesAnOrdinaryResult(t *testing.T) {
	f := payloadFinding(t, payloadSession(nil, ok("small", 2048), ok("smaller", 100)))
	if f.Status != Pass {
		t.Fatalf("an ordinary result did not pass: %+v", f)
	}
	if !strings.Contains(f.Detail, "small") {
		t.Errorf("the finding does not name the largest: %q", f.Detail)
	}
}

// TestPayloadWarnsOnAnUnboundedResult is the case that matters: a caller
// cannot refuse delivery, so by the time the size is known the window has
// already been spent.
func TestPayloadWarnsOnAnUnboundedResult(t *testing.T) {
	f := payloadFinding(t, payloadSession(nil, ok("dump_everything", payloadTrouble+1)))
	if f.Status != Warn {
		t.Fatalf("an unbounded result did not warn: %+v", f)
	}
	if !strings.Contains(f.Detail, "dump_everything") {
		t.Errorf("the finding does not name the tool: %q", f.Detail)
	}
	if f.Advice == "" {
		t.Error("a warning has to say what to do about it")
	}
}

// TestPayloadAcceptsALargeResultThatKnowsItIsLarge. A server that says it
// paginated has thought about this, and reporting it as a defect is how a
// check gets ignored by the people who did the work.
func TestPayloadAcceptsALargeResultThatKnowsItIsLarge(t *testing.T) {
	tools := []passmcp.Tool{{
		Name:        "list_records",
		Description: "List records. Returns next_cursor when there are more.",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"cursor":{"type":"string"}}}`),
	}}
	f := payloadFinding(t, payloadSession(tools, ok("list_records", payloadTrouble+1)))
	if f.Status != Info {
		t.Fatalf("a paginated result should be an observation, got %s: %q", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "choice rather than an accident") {
		t.Errorf("the finding does not say why it is acceptable: %q", f.Detail)
	}
}

// TestPayloadNotesAMiddlingResultWithoutComplaining: between the two
// thresholds is worth a reader knowing and is not a defect.
func TestPayloadNotesAMiddlingResultWithoutComplaining(t *testing.T) {
	f := payloadFinding(t, payloadSession(nil, ok("chatty", payloadNotable+1)))
	if f.Status != Info {
		t.Fatalf("want an observation, got %s: %q", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "context") {
		t.Errorf("the finding does not say what the size costs: %q", f.Detail)
	}
}

// TestPayloadReportsTheLargest, not the last or the first.
func TestPayloadReportsTheLargest(t *testing.T) {
	f := payloadFinding(t, payloadSession(nil,
		ok("a", 1000), ok("biggest", payloadTrouble+1), ok("c", 2000)))
	if !strings.Contains(f.Detail, "biggest") {
		t.Errorf("the finding does not name the largest result: %q", f.Detail)
	}
}

// TestBoundedHintsReadBothPlaces: a server declares paging in its schema
// and admits truncation in its answer, and either is enough.
func TestBoundedHintsReadBothPlaces(t *testing.T) {
	inSchema := []passmcp.Tool{{
		Name:        "t",
		InputSchema: json.RawMessage(`{"type":"object","properties":{"page_token":{"type":"string"}}}`),
	}}
	if !saysItIsBounded(payloadSession(inSchema, ok("t", 10)), "t") {
		t.Error("a page_token in the schema was not recognised")
	}

	inAnswer := payloadSession(nil, ToolResult{
		Name: "t", Executed: true, OK: true, TextBytes: 10,
		SchemaIssues: []string{"output was truncated at 1000 rows"},
	})
	if !saysItIsBounded(inAnswer, "t") {
		t.Error("a truncation note in the result was not recognised")
	}

	if saysItIsBounded(payloadSession(nil, ok("t", 10)), "t") {
		t.Error("a result saying nothing was read as bounded")
	}
	if saysItIsBounded(payloadSession(nil, ok("t", 10)), "absent") {
		t.Error("an unknown tool was read as bounded")
	}
}
