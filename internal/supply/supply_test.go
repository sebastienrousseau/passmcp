// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package supply

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"
)

// buildFixture compiles a tiny Go program and returns its path.
//
// A real binary rather than a golden file: the whole point is reading what
// the toolchain actually embedded, and a checked-in fixture would be
// reading what some past toolchain embedded once.
func buildFixture(t *testing.T, dirty bool) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no Go toolchain to build a fixture with")
	}
	dir := t.TempDir()

	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module fixture.example/server\n\ngo 1.24\n")
	write("main.go", "package main\n\nfunc main() {}\n")

	// A git checkout, so the toolchain stamps a revision. Without one
	// there is no provenance to read and half of this package is untested.
	if _, err := exec.LookPath("git"); err == nil {
		run := func(args ...string) {
			cmd := exec.Command("git", args...)
			cmd.Dir = dir
			cmd.Env = append(os.Environ(),
				"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.com",
				"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.com",
				"GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null",
			)
			_ = cmd.Run()
		}
		run("init", "-q")
		run("add", ".")
		run("-c", "commit.gpgsign=false", "commit", "-q", "-m", "fixture")
		if dirty {
			// An uncommitted change is the whole of the dirty case.
			write("main.go", "package main\n\nfunc main() { _ = 1 }\n")
		}
	}

	out := filepath.Join(dir, "server")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("could not build a fixture binary: %v\n%s", err, b)
	}
	return out
}

// TestInspectReadsTheModuleGraph is the claim the milestone rests on: a Go
// binary carries its own inventory.
func TestInspectReadsTheModuleGraph(t *testing.T) {
	b, err := Inspect(buildFixture(t, false))
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if b.GoVersion == "" {
		t.Error("no toolchain version")
	}
	if b.Main.Path != "fixture.example/server" {
		t.Errorf("main module = %q", b.Main.Path)
	}
	if b.GOOS != runtime.GOOS || b.GOARCH != runtime.GOARCH {
		t.Errorf("built for %s/%s, want %s/%s", b.GOOS, b.GOARCH, runtime.GOOS, runtime.GOARCH)
	}
	if !strings.Contains(b.Summary(), "fixture.example/server") {
		t.Errorf("the summary does not name the module: %q", b.Summary())
	}
}

// TestInspectFlagsADirtyBuild is the milestone's own proof. A binary built
// from a tree with uncommitted changes cannot be traced to any commit.
func TestInspectFlagsADirtyBuild(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("no git, so there is no version-control stamp to read")
	}

	clean, err := Inspect(buildFixture(t, false))
	if err != nil {
		t.Fatal(err)
	}
	if !clean.HasVCS {
		t.Skip("the toolchain did not stamp a revision here")
	}
	if clean.Dirty {
		t.Errorf("a clean checkout was reported dirty at %s", clean.Revision)
	}
	if clean.Revision == "" {
		t.Error("a clean checkout recorded no revision")
	}

	dirty, err := Inspect(buildFixture(t, true))
	if err != nil {
		t.Fatal(err)
	}
	if !dirty.Dirty {
		t.Error("a build from a modified tree was not flagged")
	}
}

// TestInspectRejectsSomethingThatIsNotAGoBinary, with an error a caller
// can tell apart from a missing file.
func TestInspectRejectsSomethingThatIsNotAGoBinary(t *testing.T) {
	name := "notgo"
	if runtime.GOOS == "windows" {
		// LookPath there resolves by extension, whatever the file holds,
		// so a name without one is not found at all and the error would
		// be about the lookup rather than about the contents.
		name += ".exe"
	}
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\necho hi\n"), 0o700); err != nil { //nolint:gosec // an executable fixture
		t.Fatal(err)
	}
	_, err := Inspect(p)
	if !errors.Is(err, ErrNotGo) {
		t.Fatalf("want ErrNotGo, got %v", err)
	}
}

// TestInspectResolvesThroughPATH, because the operator wrote what they
// would have typed.
func TestInspectResolvesThroughPATH(t *testing.T) {
	bin := buildFixture(t, false)
	dir, name := filepath.Split(bin)
	t.Setenv("PATH", strings.TrimSuffix(dir, string(filepath.Separator)))

	if _, err := Inspect(name); err != nil {
		t.Errorf("a program on PATH was not found: %v", err)
	}
}

// TestInspectOnNothing reports rather than panicking.
func TestInspectOnNothing(t *testing.T) {
	if _, err := Inspect("   "); err == nil {
		t.Error("an empty command should be an error")
	}
	if _, err := Inspect("passmcp-no-such-program-anywhere"); err == nil {
		t.Error("a missing program should be an error")
	}
}

// TestUnpinnedFindsModulesWithNoChecksum. A module with no h1: sum did not
// come through the proxy and cannot be verified afterwards.
func TestUnpinnedFindsModulesWithNoChecksum(t *testing.T) {
	b := &Build{Deps: []Module{
		{Path: "example.com/a", Version: "v1.0.0", Sum: "h1:abc="},
		{Path: "example.com/b", Version: "v1.0.0"},
		{Path: "example.com/c", Version: "v1.0.0", Sum: "  "},
	}}
	got := b.Unpinned()
	if len(got) != 2 || got[0] != "example.com/b" || got[1] != "example.com/c" {
		t.Errorf("Unpinned = %v, want b and c", got)
	}
	if len((&Build{}).Unpinned()) != 0 {
		t.Error("a binary with no dependencies reported unpinned ones")
	}
}

// TestSummaryReadsAsASentence, since it is what lands in the report.
func TestSummaryReadsAsASentence(t *testing.T) {
	b := &Build{
		GoVersion: "go1.27.1",
		Main:      Module{Path: "example.com/srv", Version: "v1.2.3"},
		GOOS:      "linux", GOARCH: "amd64",
		Deps: []Module{{Path: "a"}, {Path: "b"}},
	}
	got := b.Summary()
	for _, want := range []string{"example.com/srv v1.2.3", "go1.27.1", "linux/amd64", "2 direct"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q does not contain %q", got, want)
		}
	}

	// A development build has no meaningful version, and printing
	// "(devel)" as though it were one helps nobody.
	devel := &Build{GoVersion: "go1.27.1", Main: Module{Path: "x", Version: "(devel)"}}
	if strings.Contains(devel.Summary(), "(devel)") {
		t.Errorf("summary shows a placeholder version: %q", devel.Summary())
	}
}

// TestFromBuildInfoReadsWhatTheToolchainRecorded drives the conversion
// directly, with a synthetic record.
//
// The other tests here build a real binary, which is the right way to
// test that the reading works at all — but it makes the coverage of this
// function depend on whether a Go toolchain and a git are present, and on
// what they chose to stamp. The conversion itself has no such excuse.
func TestFromBuildInfoReadsWhatTheToolchainRecorded(t *testing.T) {
	bi := &debug.BuildInfo{
		GoVersion: "go1.27.1",
		Main:      debug.Module{Path: "example.com/srv", Version: "v1.2.3", Sum: "h1:main="},
		Deps: []*debug.Module{
			{Path: "example.com/z", Version: "v0.1.0", Sum: "h1:z="},
			{Path: "example.com/a", Version: "v2.0.0", Sum: "h1:a="},
			nil, // the toolchain can leave holes; they are not dependencies
			{
				Path: "example.com/old", Version: "v0.0.1",
				// A replaced module: what shipped is the replacement, so
				// that is what an inventory has to name.
				Replace: &debug.Module{Path: "example.com/new", Version: "v9.9.9", Sum: "h1:new="},
			},
		},
		Settings: []debug.BuildSetting{
			{Key: "GOOS", Value: "linux"},
			{Key: "GOARCH", Value: "arm64"},
			{Key: "vcs.revision", Value: "abcdef0123456789"},
			{Key: "vcs.modified", Value: "true"},
			{Key: "-ldflags", Value: "-s -w"}, // ignored
		},
	}

	b := fromBuildInfo("/srv/bin", bi)

	if b.Path != "/srv/bin" || b.GoVersion != "go1.27.1" {
		t.Errorf("path/version = %q %q", b.Path, b.GoVersion)
	}
	if b.GOOS != "linux" || b.GOARCH != "arm64" {
		t.Errorf("platform = %s/%s", b.GOOS, b.GOARCH)
	}
	if !b.HasVCS || b.Revision != "abcdef0123456789" || !b.Dirty {
		t.Errorf("vcs = %+v", struct {
			Has   bool
			Rev   string
			Dirty bool
		}{b.HasVCS, b.Revision, b.Dirty})
	}

	if len(b.Deps) != 3 {
		t.Fatalf("want 3 dependencies (the nil is not one), got %d: %+v", len(b.Deps), b.Deps)
	}
	// Sorted by import path, so two runs over one binary agree.
	if b.Deps[0].Path != "example.com/a" || b.Deps[2].Path != "example.com/z" {
		t.Errorf("not sorted by path: %+v", b.Deps)
	}
	// The replacement, not the thing it replaced.
	var found bool
	for _, d := range b.Deps {
		if d.Path == "example.com/new" && d.Version == "v9.9.9" {
			found = true
		}
		if d.Path == "example.com/old" {
			t.Error("a replaced module was reported instead of its replacement")
		}
	}
	if !found {
		t.Errorf("the replacement is missing: %+v", b.Deps)
	}
}

// TestFromBuildInfoOnACleanTarballBuild: no version-control settings at
// all is a different state from a dirty tree, and must not read as one.
func TestFromBuildInfoOnACleanTarballBuild(t *testing.T) {
	b := fromBuildInfo("/srv/bin", &debug.BuildInfo{
		GoVersion: "go1.27.1",
		Main:      debug.Module{Path: "example.com/srv"},
		Settings:  []debug.BuildSetting{{Key: "GOOS", Value: "darwin"}},
	})
	if b.HasVCS {
		t.Error("a build with no vcs settings claimed a stamp")
	}
	if b.Dirty {
		t.Error("a build with no vcs settings was reported dirty")
	}
	if b.Revision != "" {
		t.Errorf("revision = %q, want empty", b.Revision)
	}
}

// TestFromBuildInfoOnACleanCheckout.
func TestFromBuildInfoOnACleanCheckout(t *testing.T) {
	b := fromBuildInfo("/srv/bin", &debug.BuildInfo{
		GoVersion: "go1.27.1",
		Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "cafe"},
			{Key: "vcs.modified", Value: "false"},
		},
	})
	if !b.HasVCS || b.Dirty || b.Revision != "cafe" {
		t.Errorf("clean checkout read as %+v", b)
	}
}
