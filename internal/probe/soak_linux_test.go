// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build linux

package probe

import (
	"strings"
	"testing"
)

// TestSoakSeesALeakAndNotAServerThatHolds. The leaking fixture keeps
// 256 KiB from every call, which is 50 MiB over the run and a straight
// line; the clean one is the control.
func TestSoakSeesALeakAndNotAServerThatHolds(t *testing.T) {
	t.Run("leak", func(t *testing.T) {
		t.Parallel()
		fs := runStdioSoaked(t, 200, "PASSMCP_FIXTURE_LEAK=262144")
		f := fs["resilience.soak_memory"]
		if f.Status != Fail || f.Severity != Major || !strings.Contains(f.Detail, "rose steadily") || !strings.Contains(f.Detail, "over 200 calls to look") {
			t.Errorf("%s %s %q", f.Status, f.Severity, f.Detail)
		}
		// ADR 0002: a verdict rests on the calls that were made.
		if len(f.Evidence) == 0 {
			t.Error("a fail with no evidence")
		}
	})
	t.Run("holds", func(t *testing.T) {
		t.Parallel()
		fs := runStdioSoaked(t, 200)
		f := fs["resilience.soak_memory"]
		if f.Status != Pass || !strings.Contains(f.Detail, "over 200 calls to look") || !strings.Contains(f.Detail, "warm-up") {
			t.Errorf("%s %q", f.Status, f.Detail)
		}
		if len(f.Evidence) == 0 {
			t.Error("a pass with no evidence")
		}
	})
	t.Run("dies", func(t *testing.T) {
		t.Parallel()
		fs := runStdioSoaked(t, 200, "PASSMCP_FIXTURE_DIE_AFTER=150")
		f := fs["resilience.soak_memory"]
		if f.Status != Fail || f.Severity != Major || !strings.Contains(f.Detail, "exited") || !strings.Contains(f.Detail, "of 200 to look") {
			t.Errorf("%s %s %q", f.Status, f.Severity, f.Detail)
		}
		if alive := fs["stdio.alive"]; alive.Status != Fail {
			t.Errorf("stdio.alive = %s %q; the exit should be judged afterwards", alive.Status, alive.Detail)
		}
	})
}
