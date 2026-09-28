// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// upstreamHost does not resolve, so an ordinary run's dial fails at once
// and the tool still succeeds; only the fault holds it open. A loopback
// address would bypass the proxy altogether.
const upstreamHost = "http://dependency.passmcp-fixture.invalid/lookup"

func runStdioFaulted(t *testing.T, mode string, fault bool) map[string]Finding {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	s, err := Run(context.Background(), Options{
		Stdio: &passmcp.StdioConfig{
			Command: self,
			Env:     []string{fakeEnv + "=" + mode, "PASSMCP_FIXTURE_DIAL=" + upstreamHost},
		},
		Recorder: telemetry.New(), Version: "t", RPS: -1, Samples: 1, Concurrency: 1,
		CallTimeout:   2 * time.Second,
		WatchEgress:   true,
		FaultUpstream: fault,
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	return findingsByID(s)
}

func TestUpstreamDownIsJudgedByWhatTheCallDoes(t *testing.T) {
	cases := []struct {
		mode   string
		status Status
		want   string
	}{
		{"upstream-timeout", Pass, "look: isError in"},
		{"upstream-hang", Fail, "look (no answer in 2s) did not come back"},
		{"upstream-crash", Fail, "exited when its upstreams were unreachable"},
		{"upstream-fallback", Pass, "answered anyway (a cache or a fallback): look in"},
		{"upstream-once", Info, "none of the 1 tools called (look) connected to anything"},
		{"serve", Skip, "connected to nothing through the proxy"},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			t.Parallel()
			fs := runStdioFaulted(t, tc.mode, true)
			f, ok := fs["resilience.upstream_down"]
			if !ok {
				t.Fatal("no finding")
			}
			if f.Status != tc.status || !strings.Contains(f.Detail, tc.want) {
				t.Fatalf("%s %q, want %s containing %q", f.Status, f.Detail, tc.status, tc.want)
			}
			if tc.status == Fail && f.Severity != Major {
				t.Errorf("severity %s", f.Severity)
			}
			// ADR 0002: a verdict rests on the calls that were made.
			if (tc.status == Pass || tc.status == Fail) && len(f.Evidence) == 0 {
				t.Errorf("%s with no evidence", f.Status)
			}
		})
	}
}

// Not asked for, not done: a default run is unchanged.
func TestUpstreamDownRunsOnlyWhenAskedFor(t *testing.T) {
	fs := runStdioFaulted(t, "upstream-hang", false)
	if f, ok := fs["resilience.upstream_down"]; ok {
		t.Fatalf("ran without --fault-upstream: %+v", f)
	}
}

func TestUpstreamDownSaysWhyItCannotRun(t *testing.T) {
	s := &Session{Opts: Options{FaultUpstream: true, Recorder: &telemetry.Recorder{}}, egressErr: "listen: denied"}
	if fs := checkUpstreamDown(context.Background(), s); len(fs) != 1 || fs[0].Status != Skip || !strings.Contains(fs[0].Detail, "listen: denied") {
		t.Errorf("%+v", fs)
	}
	s = &Session{Opts: Options{FaultUpstream: true, Recorder: &telemetry.Recorder{}}}
	if fs := checkUpstreamDown(context.Background(), s); len(fs) != 1 || fs[0].Status != Skip || !strings.Contains(fs[0].Detail, "no egress proxy") {
		t.Errorf("%+v", fs)
	}
}
