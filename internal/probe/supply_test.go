// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"runtime"
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// TestSupplyChainReadsTheServerBinary is end to end and pleasingly
// self-referential: the stdio fixture is this test binary, which is a Go
// program, so the run reports the module graph of the thing running it.
func TestSupplyChainReadsTheServerBinary(t *testing.T) {
	_, fs := runStdioFixture(t, "serve")

	f := fs["supply.buildinfo"]
	if f.Status != Info {
		t.Fatalf("supply.buildinfo = %s %q, want an inventory", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "built with go") {
		t.Errorf("the finding does not name the toolchain: %q", f.Detail)
	}
	if !strings.Contains(f.Detail, "dependencies") {
		t.Errorf("the finding does not count the graph: %q", f.Detail)
	}
	if len(f.Evidence) == 0 {
		t.Error("the graph must be carried as evidence")
	}

	// And the provenance question was asked, whatever the answer: a test
	// binary may or may not carry a version-control stamp.
	p := fs["supply.provenance"]
	if p.Status == "" {
		t.Error("supply.provenance did not run")
	}
}

// TestSupplyChainIsSilentOverHTTP: an endpoint is a URL, and a URL is not
// a file passmcp can open.
func TestSupplyChainIsSilentOverHTTP(t *testing.T) {
	s := &Session{Opts: Options{Recorder: &telemetry.Recorder{}, Endpoint: "https://x/mcp"}}
	if got := checkSupplyChain(s); len(got) != 0 {
		t.Fatalf("want nothing for an endpoint target, got %+v", got)
	}
}

// TestSupplyChainSaysWhenItIsNotAGoBinary. Most MCP servers are Python or
// TypeScript; that is an answer rather than a defect.
func TestSupplyChainSaysWhenItIsNotAGoBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixture is a shell")
	}
	// overStdio reads Pipe, so this drives the body directly rather than
	// starting a process solely to reach a branch about the file.
	s := &Session{Opts: Options{
		Recorder: &telemetry.Recorder{},
		Stdio:    &passmcp.StdioConfig{Command: "/bin/sh"},
	}}
	out := inspectTarget(s)
	if len(out) != 1 || out[0].Status != Info {
		t.Fatalf("want one informational finding, got %+v", out)
	}
	if !strings.Contains(out[0].Detail, "not a Go binary") {
		t.Errorf("the finding does not say why: %q", out[0].Detail)
	}
}

// TestShortRev abbreviates the way a person writes a commit.
func TestShortRev(t *testing.T) {
	if got := shortRev("c7e7eafa0dcdbf52772d2c1ca8002f7f9044df60"); got != "c7e7eafa0dcd" {
		t.Errorf("shortRev = %q", got)
	}
	if got := shortRev("abc"); got != "abc" {
		t.Errorf("a short revision should pass through, got %q", got)
	}
	if got := shortRev(""); !strings.Contains(got, "unrecorded") {
		t.Errorf("an absent revision should say so, got %q", got)
	}
}
