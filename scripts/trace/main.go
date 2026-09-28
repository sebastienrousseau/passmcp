// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// trace links every acceptance criterion in passmcp's user-story issues to
// the tests that prove it (issue #6).
//
//	go run ./scripts/trace/main.go                 # report, per story
//	go run ./scripts/trace/main.go -check          # fail on a closed story's untested criterion
//	go run ./scripts/trace/main.go -check -run -report-dir build/trace
//	go run ./scripts/trace/main.go -refresh        # rewrite testdata/stories.json with gh
//
// Everything but -refresh reads the committed snapshot, testdata/stories.json,
// so the gate never depends on the GitHub API being reachable: a fork's CI
// and an offline checkout trace exactly as the main repository does.
//
// A story implemented in another repository says so in its issue
// ("**Repository:** owner/name") and is enforced there, by the same tool
// run at a pinned passmcp version:
//
//	go run satellion.com/passmcp/scripts/trace@<version> -repo owner/name -check -run
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"

	"satellion.com/passmcp/internal/trace"
)

const repo = "sebastienrousseau/passmcp"

func main() {
	stories := flag.String("stories", "testdata/stories.json", "committed snapshot of the user-story issues")
	root := flag.String("root", ".", "module root to scan for tests")
	check := flag.Bool("check", false, "exit 1 when a closed story has a criterion without a test")
	run := flag.Bool("run", false, "run every cited test and record its result")
	reportDir := flag.String("report-dir", "", "write trace.json and trace.md here")
	refresh := flag.Bool("refresh", false, "rewrite the snapshot from GitHub with gh (networked)")
	thisRepo := flag.String("repo", repo, "this repository, as owner/name; stories whose issue names another are enforced there")
	flag.Parse()
	if err := mainErr(*stories, *root, *check, *run, *reportDir, *refresh, *thisRepo); err != nil {
		fmt.Fprintln(os.Stderr, "trace:", err)
		os.Exit(1)
	}
}

func mainErr(storiesPath, root string, check, run bool, reportDir string, refresh bool, thisRepo string) error {
	if refresh {
		return refreshSnapshot(storiesPath)
	}
	stories, err := trace.LoadStories(storiesPath)
	if err != nil {
		return err
	}
	cits, bad, err := trace.Scan(root)
	if err != nil {
		return err
	}
	r := trace.Build(stories, cits, bad)
	r.Repo, r.Origin = thisRepo, repo
	var runErr error
	if run {
		runErr = trace.RunCited(&r, root, trace.GoRunner)
	}
	if err := r.WriteText(os.Stdout); err != nil {
		return err
	}
	if reportDir != "" {
		if err := writeReports(r, reportDir); err != nil {
			return err
		}
	}
	if check {
		if f := r.Failures(); len(f) > 0 {
			for _, line := range f {
				fmt.Fprintln(os.Stderr, "trace:", line)
			}
			return errors.Join(runErr, fmt.Errorf("%d traceability failure(s)", len(f)))
		}
	}
	return runErr
}

func writeReports(r trace.Report, dir string) error {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return err
	}
	j, m := filepath.Join(dir, "trace.json"), filepath.Join(dir, "trace.md")
	if err := writeFile(j, r.WriteJSON); err != nil {
		return err
	}
	if err := writeFile(m, r.WriteMarkdown); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "trace: wrote %s and %s\n", j, m)
	return nil
}

// writeFile creates path and fills it with write. A file that fails to
// close is reported: a truncated report is worse than none.
func writeFile(path string, write func(io.Writer) error) (err error) {
	f, err := os.Create(path) // #nosec G304 -- the operator's own -report-dir
	if err != nil {
		return err
	}
	defer func() {
		if cerr := f.Close(); err == nil {
			err = cerr
		}
	}()
	return write(f)
}

// ghAPI lists a GitHub API path through the gh CLI, following every page.
// Tests replace it; nothing else does.
var ghAPI = func(ctx context.Context, path string) ([]byte, error) {
	// #nosec G204 -- path is built from the repo constant; no argument comes
	// from the operator or the network.
	return exec.CommandContext(ctx, "gh", "api", "--paginate", path).Output()
}

// refreshSnapshot is the only networked step: it lists every issue labelled
// user-story, open and closed, and rewrites the committed snapshot.
func refreshSnapshot(path string) error {
	out, err := ghAPI(context.Background(), "repos/"+repo+"/issues?labels=user-story&state=all&per_page=100")
	if err != nil {
		return fmt.Errorf("gh api: %w", err)
	}
	snap, err := trace.Snapshot(out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, snap, 0o600); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "trace: wrote %s\n", path)
	return nil
}
