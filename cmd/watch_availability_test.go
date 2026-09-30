// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/watch"
)

// approvedBaseline approves what the fake server serves now and returns
// the endpoint and the baseline path.
func approvedBaseline(t *testing.T) (*fakeServer, string, string) {
	t.Helper()
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	path := filepath.Join(t.TempDir(), "baseline.json")
	if _, code := run(t, append([]string{"check", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1",
		"--baseline", path, "--approve",
		// The catalogue is all a baseline needs; the later phases would
		// only add load to a suite that shares the machine with timing-
		// sensitive tests.
		"--phases", "net,discovery,auth,handshake,catalog"}, fastFlags()...)...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}
	return f, endpoint, path
}

// TestWatchOnceExitsOneWhenNothingAnswered is the documented contract: an
// unreachable server is a 1, never a 0 and never a 2. A CI gate that
// passed because the server was down would be a gate that passes on an
// outage.
func TestWatchOnceExitsOneWhenNothingAnswered(t *testing.T) {
	f, endpoint, path := approvedBaseline(t)
	f.srv.Close()

	out, stderr, code := runCapturingStderr(t, watchArgs(endpoint, "--once", "--baseline", path)...)
	if code != 1 {
		t.Fatalf("an unreachable server exited %d, want 1:\n%s\n%s", code, out, stderr)
	}
	if !strings.Contains(out, "transport_error") {
		t.Errorf("the pulse does not say what class of failure it was:\n%s", out)
	}
}

// TestWatchTextShowsLatencyAndASummary: per pulse, how long it took; at
// the end, the availability a person would quote.
func TestWatchTextShowsLatencyAndASummary(t *testing.T) {
	_, endpoint, path := approvedBaseline(t)
	out, code := run(t, watchArgs(endpoint, "--once", "--baseline", path)...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	for _, want := range []string{"unchanged", "ms", "summary", "1 of 1 pulse(s) answered (100.0%)", "p50", "p95", "p99", "worst failure streak 0"} {
		if !strings.Contains(out, want) {
			t.Errorf("text output lacks %q:\n%s", want, out)
		}
	}
}

// TestWatchNDJSONEndsWithASummary: the stream carries each pulse's
// latency and status, and its last line is the summary.
func TestWatchNDJSONEndsWithASummary(t *testing.T) {
	_, endpoint, path := approvedBaseline(t)
	out, code := run(t, watchArgs(endpoint, "--once", "--baseline", path, "--output", "ndjson")...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("want a pulse and a summary, got %d line(s):\n%s", len(lines), out)
	}
	pulse := decodeWatchLine(t, lines[0])
	if pulse.Kind != "pulse" || pulse.Status != "ok" || pulse.LatencyMS == nil || *pulse.LatencyMS <= 0 {
		t.Errorf("pulse line = %s", lines[0])
	}
	assertCleanSummaryLine(t, lines[1])
}

// assertCleanSummaryLine checks the summary line of one answered pulse.
func assertCleanSummaryLine(t *testing.T, line string) {
	t.Helper()
	sum := decodeWatchLine(t, line)
	if sum.Kind != "summary" || sum.Summary == nil {
		t.Fatalf("summary line = %s", line)
	}
	s := sum.Summary
	if got := [2]int{s.Pulses, s.ByStatus["ok"]}; got != [2]int{1, 1} || s.SuccessRate != 1 || s.Latency.P50 <= 0 {
		t.Errorf("summary line = %s", line)
	}
	if !strings.Contains(line, `"worst_failure_streak":0`) {
		t.Errorf("a clean run must still say its worst streak was zero: %s", line)
	}
}

// decodeWatchLine parses one NDJSON event.
func decodeWatchLine(t *testing.T, line string) watch.Event {
	t.Helper()
	var ev watch.Event
	if err := json.Unmarshal([]byte(line), &ev); err != nil {
		t.Fatalf("not an event: %v\n%s", err, line)
	}
	return ev
}

// TestWatchJSONIsOneDocument. --output json used to print the text form,
// which is not JSON; stdout carries the selected format or nothing.
func TestWatchJSONIsOneDocument(t *testing.T) {
	_, endpoint, path := approvedBaseline(t)
	out, code := run(t, watchArgs(endpoint, "--once", "--baseline", path, "--output", "json")...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	var doc struct {
		Target  string `json:"target"`
		Events  []struct{ Kind string }
		Summary struct {
			Pulses int `json:"pulses"`
		} `json:"summary"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("not one JSON document: %v\n%s", err, out)
	}
	if doc.Target != endpoint || len(doc.Events) != 1 || doc.Events[0].Kind != "pulse" || doc.Summary.Pulses != 1 {
		t.Errorf("document = %+v", doc)
	}
}
