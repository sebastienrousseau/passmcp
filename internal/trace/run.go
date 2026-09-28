// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"go/build"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Runner runs `go` with args in dir and returns its standard output. It is
// a parameter so the tests can stand in for the toolchain.
type Runner func(dir string, args ...string) ([]byte, error)

// GoRunner runs the real `go` command.
func GoRunner(dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(context.Background(), "go", args...) // #nosec G204 -- fixed binary; the arguments are package paths and test names this package built
	cmd.Dir = dir
	return cmd.Output()
}

// event is the part of a `go test -json` line this package reads.
type event struct {
	Action string
	Test   string
}

// RunCited runs every test that cites a criterion, once per package, and
// records each test's result in the report. It returns an error naming each
// cited test that failed or did not run: a criterion whose test cannot run
// is no more proven than one with no test.
func RunCited(r *Report, root string, run Runner) error {
	byPkg := map[string]map[string]bool{}
	for _, s := range r.Stories {
		for _, c := range s.Criteria {
			for _, t := range c.Tests {
				if byPkg[t.Package] == nil {
					byPkg[t.Package] = map[string]bool{}
				}
				byPkg[t.Package][t.Name] = true
			}
		}
	}
	results := map[string]string{} // package + "\x00" + test -> result
	pkgs := make([]string, 0, len(byPkg))
	for p := range byPkg {
		pkgs = append(pkgs, p)
	}
	sort.Strings(pkgs)
	for _, pkg := range pkgs {
		out, _ := run(root, "test", "-count=1", "-json", "-run", runPattern(byPkg[pkg]), pkg)
		for name, res := range parseEvents(out) {
			results[pkg+"\x00"+name] = res
		}
	}
	return record(r, results, root)
}

// runPattern is a -run expression that selects exactly the named tests.
func runPattern(names map[string]bool) string {
	quoted := make([]string, 0, len(names))
	for n := range names {
		quoted = append(quoted, regexp.QuoteMeta(n))
	}
	sort.Strings(quoted)
	return "^(" + strings.Join(quoted, "|") + ")$"
}

// parseEvents reads `go test -json` output and returns each top-level
// test's final action. Subtests are summarised by their parent.
func parseEvents(out []byte) map[string]string {
	res := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(out))
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		var ev event
		if json.Unmarshal(sc.Bytes(), &ev) != nil || ev.Test == "" || strings.Contains(ev.Test, "/") {
			continue
		}
		switch ev.Action {
		case "pass", "fail", "skip":
			res[ev.Test] = ev.Action
		}
	}
	return res
}

// record writes each result into the report and returns an error listing
// the cited tests that failed or never ran.
//
// A cited test whose file does not build on this platform (a _linux_test.go
// file, or a //go:build line that excludes it) is "other-platform", not
// "missing": it runs in the CI job for its platform, and failing a Mac for
// a Linux-only test would teach people to ignore the gate. A test that
// builds here and still did not run is missing.
func record(r *Report, results map[string]string, root string) error {
	var problems []string
	for si := range r.Stories {
		for ci := range r.Stories[si].Criteria {
			c := &r.Stories[si].Criteria[ci]
			for ti := range c.Tests {
				t := &c.Tests[ti]
				res := resultFor(*t, results, root)
				t.Result = res
				if res == "fail" || res == "missing" {
					problems = append(problems, fmt.Sprintf("%s: %s.%s %s", c.ID, t.Package, t.Name, res))
				}
			}
		}
	}
	if len(problems) > 0 {
		return fmt.Errorf("cited tests did not pass:\n  %s", strings.Join(problems, "\n  "))
	}
	return nil
}

// buildsHere reports whether the Go toolchain would compile file (relative
// to root) on this platform, by its file name and its build constraints.
// A file it cannot read counts as building here, so an unreadable file is
// still reported missing rather than excused.
func buildsHere(root, file string) bool {
	path := filepath.Join(root, filepath.FromSlash(file))
	ok, err := build.Default.MatchFile(filepath.Dir(path), filepath.Base(path))
	return err != nil || ok
}

// resultFor is a cited test's result: what go test reported, or, when it
// did not run, "other-platform" for a file that does not build here and
// "missing" for one that does.
func resultFor(t Test, results map[string]string, root string) string {
	if res, ok := results[t.Package+"\x00"+t.Name]; ok {
		return res
	}
	if !buildsHere(root, t.File) {
		return "other-platform"
	}
	return "missing"
}
