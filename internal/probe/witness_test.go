// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"errors"
	"runtime"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/internal/witness"
)

func witnessSession(o *witness.Observed, werr error) *Session {
	return &Session{
		Opts:       Options{Recorder: telemetry.New(), Stdio: &passmcp.StdioConfig{Dir: "/srv/app"}},
		witnessed:  o,
		witnessErr: werr,
	}
}

func byIDs(fs []Finding) map[string]Finding {
	out := map[string]Finding{}
	for _, f := range fs {
		out[f.ID] = f
	}
	return out
}

// TestWitnessFindingsJudgeWhatWasSeen, independent of the platform: the
// observations are given, and each lands on its own check.
func TestWitnessFindingsJudgeWhatWasSeen(t *testing.T) {
	o := &witness.Observed{
		Conns: []witness.Conn{
			{Proto: "tcp", Remote: "203.0.113.7:443"},
			{Proto: "tcp", Remote: "127.0.0.1:61000"},
		},
		Writes:    []string{"/srv/app/cache.db", "/home/u/.bashrc", "/dev/null"},
		Processes: []string{"git status"},
		Samples:   12, Interval: 100 * time.Millisecond,
	}
	fs := byIDs(checkWitness(witnessSession(o, nil)))
	c := fs["stdio.post_init_connections"]
	if c.Status != Warn || !strings.Contains(c.Detail, "tcp 203.0.113.7:443") || strings.Contains(c.Detail, "127.0.0.1") {
		t.Errorf("connections = %s %q; loopback must not be reported", c.Status, c.Detail)
	}
	w := fs["stdio.post_init_writes"]
	if w.Status != Warn || !strings.Contains(w.Detail, "/home/u/.bashrc") || strings.Contains(w.Detail, "cache.db") || strings.Contains(w.Detail, "/dev/null") {
		t.Errorf("writes = %s %q; the working directory and /dev must not be reported", w.Status, w.Detail)
	}
	p := fs["stdio.post_init_processes"]
	if p.Status != Info || !strings.Contains(p.Detail, "git status") {
		t.Errorf("processes = %s %q", p.Status, p.Detail)
	}
	for id, f := range fs {
		if !strings.Contains(f.Detail, "sampled every 100ms, 12 time(s)") {
			t.Errorf("%s does not state its sampling limit: %q", id, f.Detail)
		}
	}
}

// TestSeeingNothingIsNotAPass. Samples that found nothing are not
// evidence that nothing happened.
func TestSeeingNothingIsNotAPass(t *testing.T) {
	fs := checkWitness(witnessSession(&witness.Observed{Conns: []witness.Conn{{Proto: "tcp", Remote: "127.0.0.1:1"}}, Samples: 3, Interval: time.Second}, nil))
	for _, f := range fs {
		if f.Status != Info {
			t.Errorf("%s = %s: %s", f.ID, f.Status, f.Detail)
		}
	}
	if d := byIDs(fs)["stdio.post_init_connections"].Detail; !strings.Contains(d, "1 connection to loopback") {
		t.Errorf("loopback count missing: %q", d)
	}
}

func TestWitnessSkipsSayWhy(t *testing.T) {
	for werr, want := range map[error]string{
		witness.ErrUnsupported:     "only Linux publishes",
		errors.New("no such pgid"): "could not start: no such pgid",
		nil:                        "handshake did not complete",
	} {
		for _, f := range checkWitness(witnessSession(nil, werr)) {
			if f.Status != Skip || !strings.Contains(f.Detail, want) {
				t.Errorf("%v: %s = %s %q", werr, f.ID, f.Status, f.Detail)
			}
		}
	}
}

// TestAStdioRunOffLinuxSkipsTheWitnessByName, end to end.
func TestAStdioRunOffLinuxSkipsTheWitnessByName(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("covered by the Linux end-to-end test")
	}
	if runtime.GOOS == "windows" {
		t.Skip("the stdio fixture needs a Unix process group")
	}
	_, fs := runStdioFixture(t, "serve")
	for _, id := range []string{"stdio.post_init_connections", "stdio.post_init_writes", "stdio.post_init_processes"} {
		if f := fs[id]; f.Status != Skip || !strings.Contains(f.Detail, "only Linux") {
			t.Errorf("%s = %s %q", id, f.Status, f.Detail)
		}
	}
}

func TestUnder(t *testing.T) {
	roots := []string{"/srv/app", "/dev/"}
	for p, want := range map[string]bool{"/srv/app": true, "/srv/app/x": true, "/srv/application": false, "/dev/null": true, "/etc/passwd": false} {
		if got := under(p, roots); got != want {
			t.Errorf("under(%q) = %v", p, got)
		}
	}
}
