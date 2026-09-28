// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build linux

package probe

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// TestTheWitnessSeesWhatAToolCallDid. The fixture behaves perfectly until
// a tool is called, then connects out, writes outside its directory and
// starts a helper, holding all three open. A clean fixture run is the
// control: nothing it does after the handshake is reported.
func TestTheWitnessSeesWhatAToolCallDid(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	written := filepath.Join(t.TempDir(), "left-behind")
	run := func(mode string) map[string]Finding {
		o := Options{
			Stdio: &passmcp.StdioConfig{
				Command: self,
				Env:     []string{fakeEnv + "=" + mode, "PASSMCP_FIXTURE_WRITE=" + written},
				Dir:     t.TempDir(),
			},
			Recorder: telemetry.New(), Version: "t", RPS: -1, Samples: 3, Concurrency: 2,
			CallTimeout: 5 * time.Second,
		}
		s, err := Run(context.Background(), o)
		if err != nil {
			t.Fatal(err)
		}
		return findingsByID(s)
	}

	fs := run("acts-after-handshake")
	if f := fs["stdio.post_init_connections"]; f.Status != Warn || !strings.Contains(f.Detail, "udp 192.0.2.1:9") {
		t.Errorf("connections = %s %q", f.Status, f.Detail)
	}
	if f := fs["stdio.post_init_writes"]; f.Status != Warn || !strings.Contains(f.Detail, written) {
		t.Errorf("writes = %s %q", f.Status, f.Detail)
	}
	if f := fs["stdio.post_init_processes"]; f.Status != Info || !strings.Contains(f.Detail, "started 1 process") {
		t.Errorf("processes = %s %q", f.Status, f.Detail)
	}

	clean := run("serve")
	for _, id := range []string{"stdio.post_init_connections", "stdio.post_init_writes", "stdio.post_init_processes"} {
		if f := clean[id]; f.Status != Info {
			t.Errorf("clean run: %s = %s %q", id, f.Status, f.Detail)
		}
	}
}

// AC: ATK-05
// TestBindAllSeesAPortOnEveryInterface, end to end on Linux: the fixture
// listens on 0.0.0.0 and on loopback; only the first fails, naming its
// port. The clean fixture holds no listener and is recorded as info.
func TestBindAllSeesAPortOnEveryInterface(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	run := func(mode string) Finding {
		s, err := Run(context.Background(), Options{
			Stdio:    &passmcp.StdioConfig{Command: self, Env: []string{fakeEnv + "=" + mode}, Dir: t.TempDir()},
			Recorder: telemetry.New(), Version: "t", RPS: -1, Samples: 3, Concurrency: 2,
			CallTimeout: 5 * time.Second,
		})
		if err != nil {
			t.Fatal(err)
		}
		return findingsByID(s)["stdio.bind_all"]
	}
	f := run("listens-everywhere")
	if f.Status != Fail || !strings.Contains(f.Detail, "tcp 0.0.0.0:") || !strings.Contains(f.Detail, "(port ") || strings.Contains(f.Detail, "127.0.0.1") {
		t.Errorf("listens-everywhere: %s %q", f.Status, f.Detail)
	}
	if f := run("serve"); f.Status != Info || !strings.Contains(f.Detail, "none bound to every interface") {
		t.Errorf("serve: %s %q", f.Status, f.Detail)
	}
}
