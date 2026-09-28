// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"math"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// series builds a sample series from a function of the call number.
func series(n int, f func(i int) int64) []int64 {
	out := make([]int64, n)
	for i := range out {
		out[i] = f(i)
	}
	return out
}

func TestTrendTellsALeakFromASawtoothAndAWarmUp(t *testing.T) {
	const mib = 1 << 20
	cases := []struct {
		name    string
		samples []int64
		rising  bool
		slopeLo float64
	}{
		{"flat", series(200, func(int) int64 { return 40 * mib }), false, 0},
		{"leak", series(200, func(i int) int64 { return 40*mib + int64(i)*128*1024 }), true, 120 * 1024},
		// A leak, seen over a window that catches more of it: the same
		// per-call rate as a settling heap, but it never stops.
		{"slow leak, long run", series(1000, func(i int) int64 { return 40*mib + int64(i)*20*1024 }), true, 19 * 1024},
		// Grows for the first fifteen calls and holds: the warm-up is not
		// a leak.
		{"warm-up then flat", series(200, func(i int) int64 { return 40*mib + int64(min(i, 15))*mib }), false, 0},
		// A collector's sawtooth: up two MiB a call, back to the floor
		// every ten. The slope is nearly nothing and the fit is poor.
		{"sawtooth", series(200, func(i int) int64 { return 40*mib + int64(i%10)*2*mib }), false, 0},
		// A Go process growing its heap towards its first collection: a
		// straight line, two mebibytes over the run, exactly what the
		// clean fixture did on a CI runner. Under the floor, not a leak.
		{"first-cycle ramp", series(200, func(i int) int64 { return 11*mib + int64(i)*11*1024 }), false, 10 * 1024},
		// Growth that decelerates: above the floor over the window, but the
		// last quarter has flattened, which a leak never does.
		{"settling heap", series(400, func(i int) int64 { return 40*mib + int64(float64(30*mib)*(1-math.Pow(0.985, float64(i)))) }), false, 0},
		{"falling", series(200, func(i int) int64 { return 80*mib - int64(i)*64*1024 }), false, -math.MaxFloat64},
		{"one sample", []int64{40 * mib}, false, 0},
		{"none", nil, false, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := fitTrend(tc.samples)
			if tr.Rising() != tc.rising {
				t.Errorf("Rising = %v, want %v: %+v", tr.Rising(), tc.rising, tr)
			}
			if tr.Slope < tc.slopeLo {
				t.Errorf("slope %.0f below %.0f", tr.Slope, tc.slopeLo)
			}
			if tr.Calls != len(tc.samples) {
				t.Errorf("Calls = %d", tr.Calls)
			}
		})
	}
	tr := fitTrend(series(200, func(i int) int64 { return int64(i) * 1000 }))
	if tr.Window != 180 || tr.R2 < 0.999 || tr.Start != 20000 || tr.End != 199000 || tr.Peak != 199000 || math.Abs(tr.Tail-tr.Slope) > 1 {
		t.Errorf("a straight line after a 20-sample warm-up: %+v", tr)
	}
}

func TestSoakCandidateIsTheFastestSuccess(t *testing.T) {
	results := []ToolResult{
		{Name: "slow", Executed: true, OK: true, Duration: 300},
		{Name: "failed", Executed: true, OK: false, Duration: 1},
		{Name: "skipped", Executed: false, Duration: 1},
		{Name: "b", Executed: true, OK: true, Duration: 20},
		{Name: "a", Executed: true, OK: true, Duration: 20},
	}
	if c, ok := soakCandidate(results); !ok || c.Name != "a" {
		t.Errorf("candidate = %+v, %v", c, ok)
	}
	if _, ok := soakCandidate(results[1:3]); ok {
		t.Error("a candidate with nothing successful")
	}
}

// Not asked for, not done: a default run makes no extra call.
func TestSoakRunsOnlyWhenAskedFor(t *testing.T) {
	_, fs := runStdioFixture(t, "serve")
	if f, ok := fs["resilience.soak_memory"]; ok {
		t.Fatalf("ran without --soak: %+v", f)
	}
	s := &Session{Opts: Options{Soak: 0, Recorder: telemetry.New()}}
	if fs := checkSoak(context.Background(), s); fs != nil {
		t.Errorf("%+v", fs)
	}
}

func TestSoakSaysWhyItCannotRun(t *testing.T) {
	s := &Session{Opts: Options{Soak: 100, Recorder: telemetry.New()}}
	if fs := checkSoak(context.Background(), s); len(fs) != 1 || fs[0].Status != Skip || !strings.Contains(fs[0].Detail, "started none") {
		t.Errorf("no pipe: %+v", fs)
	}
}

// runStdioSoaked runs the fixture with a soak of n calls and the given
// fixture knobs.
func runStdioSoaked(t *testing.T, n int, knobs ...string) map[string]Finding {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Run(context.Background(), Options{
		Stdio: &passmcp.StdioConfig{
			Command: self,
			Env:     append([]string{fakeEnv + "=serve"}, knobs...),
		},
		Recorder: telemetry.New(), Version: "t", RPS: -1, Samples: 1, Concurrency: 1,
		CallTimeout: 5 * time.Second,
		Soak:        n,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findingsByID(s)
}

// Off Linux there is no /proc to read, and the finding says so rather than
// passing a server it never measured.
func TestSoakIsSkippedByNameWhereMemoryCannotBeRead(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Linux reads it; see soak_linux_test.go")
	}
	fs := runStdioSoaked(t, SoakMinCalls)
	f, ok := fs["resilience.soak_memory"]
	if !ok {
		t.Fatal("no finding")
	}
	if f.Status != Skip || !strings.Contains(f.Detail, "only Linux") {
		t.Errorf("%s %q", f.Status, f.Detail)
	}
	// No call was made: the skip came before the loop.
	if len(f.Evidence) != 0 {
		t.Errorf("evidence on a skip that made no call: %v", f.Evidence)
	}
}
