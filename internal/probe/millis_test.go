// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// TestDurationFieldsHoldMilliseconds is the regression for a contract bug:
// every field tagged duration_ms was a bare time.Duration, so the JSON held
// nanoseconds under a name that promised milliseconds. Every dashboard
// reading passmcp's output was wrong by a factor of a million.
func TestDurationFieldsHoldMilliseconds(t *testing.T) {
	cases := []struct {
		name  string
		value any
		want  string
	}{
		{"finding", Finding{ID: "x", Duration: Millis(1500 * time.Millisecond)}, `"duration_ms":1500`},
		{"phase", PhaseResult{Name: "net", Duration: Millis(2 * time.Second)}, `"duration_ms":2000`},
		{"tool perf", ToolPerf{Name: "t", Cold: Millis(250 * time.Millisecond)}, `"cold_ms":250`},
		{"tool result", ToolResult{Name: "t", Duration: Millis(3 * time.Millisecond)}, `"duration_ms":3`},
		{"burst", ConcurrencyResult{Tool: "t", Wall: Millis(750 * time.Millisecond)}, `"wall_ms":750`},
		{"sub-millisecond", Finding{ID: "x", Duration: Millis(1500 * time.Microsecond)}, `"duration_ms":1.5`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b, err := json.Marshal(c.value)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(b), c.want) {
				t.Errorf("want %s in %s", c.want, b)
			}
		})
	}
}

func TestMillisRoundTrips(t *testing.T) {
	in := Finding{ID: "x", Duration: Millis(1234 * time.Millisecond)}
	b, err := json.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var out Finding
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatal(err)
	}
	if out.Duration != in.Duration {
		t.Errorf("round trip: %v != %v", out.Duration, in.Duration)
	}
	if out.Duration.Duration() != 1234*time.Millisecond {
		t.Errorf("Duration() = %v", out.Duration.Duration())
	}
	if got := Millis(time.Second).String(); got != "1s" {
		t.Errorf("String() = %q", got)
	}
	var bad Millis
	if err := bad.UnmarshalJSON([]byte(`"nope"`)); err == nil {
		t.Error("non-numeric milliseconds must be an error")
	}
}
