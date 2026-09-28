// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/baseline"
)

// The cycle this exists for: approve a catalogue, come back later, and be
// told what changed. Both halves are run through the CLI, because a drift
// gate that only works when driven from Go is a drift gate nobody runs.

func baselineArgs(endpoint string, extra ...string) []string {
	base := []string{"check", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1"}
	return append(append(base, extra...), fastFlags()...)
}

// TestApproveWritesTheCatalogueItSaw is the first half: there is no file,
// --approve creates it, and what lands is the catalogue of this run.
func TestApproveWritesTheCatalogueItSaw(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), ".passmcp", "baseline.json")

	out, errOut, _ := runCapturingStderr(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", path, "--approve")...)
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("--approve did not write %s: %v\nstdout:\n%s\nstderr:\n%s", path, err, out, errOut)
	}

	snap, err := baseline.Load(path)
	if err != nil {
		t.Fatalf("what --approve wrote is not a snapshot: %v", err)
	}
	if snap.Version != baseline.Version {
		t.Errorf("version = %d, want %d", snap.Version, baseline.Version)
	}
	if len(snap.Tools) == 0 {
		t.Error("the approved snapshot has no tools in it")
	}
	if snap.Digest == "" {
		t.Error("the approved snapshot has no digest")
	}
}

// TestBaselinePassesAgainstItself: approving and immediately re-running
// must be quiet, or the gate reports drift on a server that has not moved.
func TestBaselinePassesAgainstItself(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "baseline.json")

	if _, code := run(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", path, "--approve")...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}
	out, _ := run(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", path)...)
	if strings.Contains(out, "change(s) since") {
		t.Errorf("an unchanged catalogue reported drift:\n%s", out)
	}
}

// TestBaselineDetectsAReadOnlyFlip is the second half, and the reason any
// of this exists. The approved file is edited to say the tool was not
// read-only; the server now says it is, which is the flip that makes a
// cautious client start invoking it.
func TestBaselineDetectsAReadOnlyFlip(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "baseline.json")

	if _, code := run(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", path, "--approve")...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}

	// Rewrite the approved file as though the tool had been approved while
	// declaring itself not read-only.
	snap, err := baseline.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var flipped string
	no := false
	for name, tool := range snap.Tools {
		if tool.ReadOnly != nil && *tool.ReadOnly {
			tool.ReadOnly = &no
			snap.Tools[name] = tool
			flipped = name
			break
		}
	}
	if flipped == "" {
		t.Skip("the fixture has no read-only tool to flip")
	}
	// The digest has to be rewritten too, or the check would notice the
	// mismatch rather than the change.
	fresh := *snap
	fresh.Digest = "stale-on-purpose"
	if err := baseline.Save(path, fresh); err != nil {
		t.Fatal(err)
	}

	out, _ := run(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", path)...)
	if !strings.Contains(out, flipped) {
		t.Errorf("the drift report does not name %q:\n%s", flipped, out)
	}
	if !strings.Contains(out, "readOnlyHint") {
		t.Errorf("the drift report does not say what changed:\n%s", out)
	}
}

// TestApproveNeedsABaselinePath: there is no sensible default location for
// somebody else's approval, so saying so beats guessing.
func TestApproveNeedsABaselinePath(t *testing.T) {
	f := newFakeServer(t)
	// Asserted on the exit code, as the policy tests do for the same
	// shape: diag holds its writer from package init, so the pipe this
	// helper installs does not capture what it prints.
	out, errOut, code := runCapturingStderr(t, baselineArgs(f.srv.URL+"/mcp", "--approve")...)
	if code == 0 {
		t.Fatalf("--approve without --baseline should fail:\n%s\n%s", out, errOut)
	}
}

// TestMissingBaselineWithoutApproveIsAnError: a typo in the path must not
// silently become "nothing to compare, all clear".
func TestMissingBaselineWithoutApproveIsAnError(t *testing.T) {
	f := newFakeServer(t)
	absent := filepath.Join(t.TempDir(), "nope.json")

	out, errOut, code := runCapturingStderr(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", absent)...)
	if code == 0 {
		t.Fatalf("a missing baseline should not pass silently:\n%s\n%s", out, errOut)
	}
}

// TestBaselineRejectsAFileThatIsNotASnapshot.
func TestBaselineRejectsAFileThatIsNotASnapshot(t *testing.T) {
	f := newFakeServer(t)
	path := filepath.Join(t.TempDir(), "junk.json")
	if err := os.WriteFile(path, []byte("not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, errOut, code := runCapturingStderr(t, baselineArgs(f.srv.URL+"/mcp", "--baseline", path)...)
	if code == 0 {
		t.Fatalf("a file that is not a snapshot should fail:\n%s\n%s", out, errOut)
	}
}
