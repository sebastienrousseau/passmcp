// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/baseline"
)

func watchArgs(endpoint string, extra ...string) []string {
	base := []string{"watch", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1"}
	return append(base, extra...)
}

// TestWatchNeedsABaseline: there is nothing to watch for without one, and
// saying so beats watching nothing.
func TestWatchNeedsABaseline(t *testing.T) {
	f := newFakeServer(t)
	out, errOut, code := runCapturingStderr(t, watchArgs(f.srv.URL+"/mcp", "--once")...)
	if code == 0 {
		t.Fatalf("watch without --baseline should fail:\n%s\n%s", out, errOut)
	}
}

// TestWatchIsQuietOnAnUnchangedCatalogue, and exits zero so a CI job
// passes.
func TestWatchIsQuietOnAnUnchangedCatalogue(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	path := filepath.Join(t.TempDir(), "baseline.json")

	// Approve what is there now.
	if _, code := run(t, append([]string{"check", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1",
		"--baseline", path, "--approve"}, fastFlags()...)...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}

	out, code := run(t, watchArgs(endpoint, "--once", "--baseline", path)...)
	if code != 0 {
		t.Fatalf("an unchanged catalogue exited %d:\n%s", code, out)
	}
	if !strings.Contains(out, "unchanged") {
		t.Errorf("the pulse does not say it was unchanged:\n%s", out)
	}
}

// TestWatchExitsTwoOnDrift is the gate. A watcher that saw a change and
// returned zero would be a gate that never fails.
func TestWatchExitsTwoOnDrift(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	path := filepath.Join(t.TempDir(), "baseline.json")

	if _, code := run(t, append([]string{"check", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1",
		"--baseline", path, "--approve"}, fastFlags()...)...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}

	// Rewrite the approved file so the current catalogue reads as drift:
	// a tool that was approved as not read-only.
	snap, err := baseline.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	var target string
	no := false
	for name, tool := range snap.Tools {
		if tool.ReadOnly != nil && *tool.ReadOnly {
			tool.ReadOnly = &no
			snap.Tools[name] = tool
			target = name
			break
		}
	}
	if target == "" {
		t.Skip("the fixture has no read-only tool to flip")
	}
	fresh := *snap
	fresh.Digest = "stale-on-purpose"
	if err := baseline.Save(path, fresh); err != nil {
		t.Fatal(err)
	}

	out, code := run(t, watchArgs(endpoint, "--once", "--baseline", path)...)
	if code != 2 {
		t.Fatalf("drift exited %d, want 2:\n%s", code, out)
	}
	if !strings.Contains(out, target) {
		t.Errorf("the report does not name the tool that changed:\n%s", out)
	}
	if !strings.Contains(out, "readOnlyHint") {
		t.Errorf("the report does not say what changed:\n%s", out)
	}
}

// TestWatchEmitsNDJSON, which is what a log pipeline consumes.
func TestWatchEmitsNDJSON(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	path := filepath.Join(t.TempDir(), "baseline.json")

	if _, code := run(t, append([]string{"check", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1",
		"--baseline", path, "--approve"}, fastFlags()...)...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}

	out, code := run(t, watchArgs(endpoint, "--once", "--baseline", path, "--output", "ndjson")...)
	if code != 0 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	line := strings.TrimSpace(out)
	if line == "" {
		t.Fatal("no event was emitted")
	}
	var ev map[string]any
	if err := json.Unmarshal([]byte(strings.Split(line, "\n")[0]), &ev); err != nil {
		t.Fatalf("the event is not JSON: %v\n%s", err, line)
	}
	if ev["kind"] != "pulse" {
		t.Errorf("kind = %v", ev["kind"])
	}
	if ev["digest"] == nil || ev["digest"] == "" {
		t.Error("the event carries no digest")
	}
}

// TestWatchApprovePromotesWhatItSaw, so a reviewed change settles.
func TestWatchApprovePromotesWhatItSaw(t *testing.T) {
	f := newFakeServer(t)
	endpoint := f.srv.URL + "/mcp"
	path := filepath.Join(t.TempDir(), "baseline.json")

	if _, code := run(t, append([]string{"check", endpoint, "--auth", "client-credentials",
		"--client-id", "cid", "--client-secret", "sec", "--param", "profile_id=t1",
		"--baseline", path, "--approve"}, fastFlags()...)...); code > 2 {
		t.Fatalf("the approving run failed outright (exit %d)", code)
	}
	before, err := baseline.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	stale := *before
	stale.Digest = "stale-on-purpose"
	if err := baseline.Save(path, stale); err != nil {
		t.Fatal(err)
	}

	// Approving during a watch settles it: exit zero, and the file now
	// matches what is served.
	if _, code := run(t, watchArgs(endpoint, "--once", "--baseline", path, "--approve")...); code != 0 {
		t.Fatalf("approving during a watch exited %d", code)
	}
	after, err := baseline.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if after.Digest == "stale-on-purpose" {
		t.Error("--approve did not write what the watch saw")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(err)
	}
}
