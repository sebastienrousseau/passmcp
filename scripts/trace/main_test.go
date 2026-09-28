// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"context"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	fixtureStories = "../../internal/trace/testdata/stories.json"
	fixtureRoot    = "../../internal/trace/testdata/mod"
)

func TestTraceWritesBothReports(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "trace")
	if err := mainErr(fixtureStories, fixtureRoot, false, false, dir, false, repo); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"trace.json", "trace.md"} {
		if b, err := os.ReadFile(filepath.Join(dir, name)); err != nil || len(b) == 0 {
			t.Errorf("%s: %v, %d bytes", name, err, len(b))
		}
	}
}

func TestTraceCheckFailsOnlyWhereTheStoryLives(t *testing.T) {
	// The fixture has a closed story with an untested criterion and a
	// malformed citation. Here both fail; from another repository the story
	// is not its to enforce, but its own malformed citation still is.
	err := mainErr(fixtureStories, fixtureRoot, true, false, "", false, repo)
	if err == nil || !strings.Contains(err.Error(), "2 traceability failure") {
		t.Fatalf("in the story's repository: %v", err)
	}
	err = mainErr(fixtureStories, fixtureRoot, true, false, "", false, "owner/other")
	if err == nil || !strings.Contains(err.Error(), "1 traceability failure") {
		t.Fatalf("in another repository: %v", err)
	}
}

func TestTraceReportsItsInputErrors(t *testing.T) {
	if err := mainErr(filepath.Join(t.TempDir(), "none.json"), fixtureRoot, false, false, "", false, repo); err == nil {
		t.Error("a missing snapshot is an error")
	}
	if err := mainErr(fixtureStories, filepath.Join(t.TempDir(), "none"), false, false, "", false, repo); err == nil {
		t.Error("a missing module root is an error")
	}
	file := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(file, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := mainErr(fixtureStories, fixtureRoot, false, false, filepath.Join(file, "dir"), false, repo); err == nil {
		t.Error("a report directory that cannot be made is an error")
	}
	if err := writeFile(filepath.Join(t.TempDir(), "x"), func(io.Writer) error { return errors.New("boom") }); err == nil {
		t.Error("a failed write is an error")
	}
	if err := writeFile(filepath.Join(file, "x"), func(io.Writer) error { return nil }); err == nil {
		t.Error("a file that cannot be created is an error")
	}
}

func TestRefreshRewritesTheSnapshotFromTheListing(t *testing.T) {
	listing, err := os.ReadFile("../../internal/trace/testdata/listing.json")
	if err != nil {
		t.Fatal(err)
	}
	orig := ghAPI
	t.Cleanup(func() { ghAPI = orig })
	var asked string
	ghAPI = func(_ context.Context, path string) ([]byte, error) { asked = path; return listing, nil }
	out := filepath.Join(t.TempDir(), "stories.json")
	if err := mainErr(out, ".", false, false, "", true, repo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(asked, "repos/"+repo+"/issues") || !strings.Contains(asked, "labels=user-story") {
		t.Errorf("asked gh for %q", asked)
	}
	if b, err := os.ReadFile(out); err != nil || len(b) == 0 {
		t.Fatalf("snapshot: %v, %d bytes", err, len(b))
	}

	ghAPI = func(context.Context, string) ([]byte, error) { return nil, errors.New("offline") }
	if err := refreshSnapshot(out); err == nil || !strings.Contains(err.Error(), "gh api") {
		t.Errorf("a failed listing is reported: %v", err)
	}
	ghAPI = func(context.Context, string) ([]byte, error) { return []byte("not json"), nil }
	if err := refreshSnapshot(out); err == nil {
		t.Error("a listing that is not JSON is an error")
	}
	ghAPI = func(context.Context, string) ([]byte, error) { return listing, nil }
	if err := refreshSnapshot(filepath.Join(out, "under-a-file")); err == nil {
		t.Error("a snapshot that cannot be written is an error")
	}
}

func TestMainRunsWithItsFlags(t *testing.T) {
	oldArgs, oldFlags := os.Args, flag.CommandLine
	t.Cleanup(func() { os.Args, flag.CommandLine = oldArgs, oldFlags })
	flag.CommandLine = flag.NewFlagSet("trace", flag.ContinueOnError)
	os.Args = []string{"trace", "-stories", fixtureStories, "-root", fixtureRoot, "-repo", "owner/other"}
	main()
}
