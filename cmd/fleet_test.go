// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"satellion.com/passmcp/internal/fleet"
)

// writeFleet writes a one-server fleet file pointing at the fake server.
func writeFleet(t *testing.T, endpoint string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "fleet.yaml")
	doc := "version: 1\npacing:\n  rps: 0\n  samples: 1\nservers:\n  - name: crm\n    endpoint: " + endpoint + "\n"
	if err := os.WriteFile(p, []byte(doc), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

// AC: FLEET-01
func TestFleetRunPrintsASummaryInEachFormat(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := writeFleet(t, f.srv.URL+"/mcp")
	state := filepath.Join(t.TempDir(), "state")

	out, _, _ := runCapturingStderr(t, "fleet", "run", path, "--state", state)
	if !strings.Contains(out, "SERVER") || !strings.Contains(out, "crm") {
		t.Fatalf("the text summary lists the server:\n%s", out)
	}
	out, _, _ = runCapturingStderr(t, "fleet", "run", path, "--state", state, "--output", "json")
	var sum fleet.Summary
	if err := json.Unmarshal([]byte(out), &sum); err != nil || len(sum.Servers) != 1 || sum.Servers[0].Grade == "" {
		t.Fatalf("the JSON summary has the server's grade: %v\n%s", err, out)
	}
	if sum.Servers[0].Previous == "" {
		t.Error("the second run compares with the first")
	}
	out, _, _ = runCapturingStderr(t, "fleet", "run", path, "--state", state, "--output", "ocsf")
	var events []map[string]any
	if err := json.Unmarshal([]byte(out), &events); err != nil {
		t.Fatalf("the OCSF output is an event array: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(state, "summary.json")); err != nil {
		t.Errorf("the summary is written to the state directory: %v", err)
	}
}

func TestFleetRunExitsNonZeroForAnUnreachableServer(t *testing.T) {
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	path := writeFleet(t, "http://127.0.0.1:1/mcp")
	out, _, code := runCapturingStderr(t, "fleet", "run", path, "--state", t.TempDir())
	if code != fleet.ExitError || !strings.Contains(out, "unreachable") {
		t.Fatalf("an unreachable server exits %d, got %d:\n%s", fleet.ExitError, code, out)
	}
}

// AC: OCSF-02, OCSF-05
func TestFleetOCSFGoesOnlyToTheNamedEndpoint(t *testing.T) {
	f := newFakeServer(t)
	f.open = true
	t.Setenv("XDG_CONFIG_HOME", t.TempDir())
	var posts atomic.Int32
	var body string
	siem := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		posts.Add(1)
		b, _ := io.ReadAll(r.Body)
		body = string(b)
	}))
	defer siem.Close()
	path := writeFleet(t, f.srv.URL+"/mcp")
	state := t.TempDir()
	_, _, _ = runCapturingStderr(t, "fleet", "run", path, "--state", state)
	if posts.Load() != 0 {
		t.Fatal("nothing is sent without --ocsf-endpoint")
	}
	_, stderr, _ := runCapturingStderr(t, "fleet", "run", path, "--state", state, "--log-level", "info",
		"--ocsf-endpoint", siem.URL, "--ocsf-header", "Authorization: Bearer siem")
	if posts.Load() != 1 || !strings.HasPrefix(strings.TrimSpace(body), "[") {
		t.Fatalf("want one POST of an event array, got %d: %.60s", posts.Load(), body)
	}
	if !strings.Contains(stderr, "to "+siem.URL) {
		t.Errorf("the destination is announced first:\n%s", stderr)
	}
	_, stderr, _ = runCapturingStderr(t, "fleet", "run", path, "--state", state, "--ocsf-endpoint", siem.URL, "--ocsf-header", "no colon")
	if !strings.Contains(stderr, "OCSF export failed") {
		t.Errorf("a bad header is a warning, not a crash:\n%s", stderr)
	}
}

func TestFleetRunRefusesBadInput(t *testing.T) {
	_, _, _ = runCapturingStderr(t, "fleet", "run", "/nonexistent/fleet.yaml")
	path := writeFleet(t, "https://x/mcp")
	out, _, _ := runCapturingStderr(t, "fleet", "run", path, "--output", "pdf")
	if strings.Contains(out, "SERVER") {
		t.Error("an unknown output format must not run the fleet")
	}
}

func TestStateDirFor(t *testing.T) {
	resetAll()
	// Absolute paths as this platform spells them: "/abs" is relative on
	// Windows.
	base, abs := t.TempDir(), filepath.Join(t.TempDir(), "abs")
	if got := stateDirFor(&fleet.File{}, base); got != filepath.Join(base, "fleet-state") {
		t.Errorf("default: %s", got)
	}
	if got := stateDirFor(&fleet.File{State: "runs"}, base); got != filepath.Join(base, "runs") {
		t.Errorf("relative: %s", got)
	}
	if got := stateDirFor(&fleet.File{State: abs}, base); got != abs {
		t.Errorf("absolute: %s", got)
	}
	fleetState = "/flag"
	defer func() { fleetState = "" }()
	if got := stateDirFor(&fleet.File{State: "runs"}, "/base"); got != "/flag" {
		t.Errorf("the flag wins: %s", got)
	}
	if progressDetail(fleet.ServerResult{Status: fleet.StatusUnreachable, Error: "x"}) != ": x" {
		t.Error("an unreachable server's detail is its error")
	}
	if !strings.Contains(progressDetail(fleet.ServerResult{Changes: []fleet.Change{{}}, Worst: "notable"}), "1 change") {
		t.Error("changes are counted")
	}
	if got := progressDetail(fleet.ServerResult{Score: 90, Grade: "A"}); !strings.Contains(got, "first recorded run") || strings.Contains(got, "unchanged") {
		t.Errorf("a run with nothing to compare with is not unchanged: %q", got)
	}
	if got := progressDetail(fleet.ServerResult{Score: 90, Grade: "A", Previous: "sha256:ab"}); !strings.Contains(got, "unchanged") {
		t.Errorf("a compared run with no changes is unchanged: %q", got)
	}
	if dash("") != "-" || dash("a") != "a" {
		t.Error("dash")
	}
}
