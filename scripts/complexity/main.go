// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// complexity enforces the complexity ceilings against a committed baseline
// that may only shrink.
//
// The ceilings are the portfolio's: cyclomatic complexity 10, cognitive
// complexity 15 and 60 lines per function, set in .golangci.yml, and 500
// lines per file, measured here. Code written before the ceilings were
// lowered exceeds them in places; each such function or file is recorded in
// .complexity-baseline with the value it had. The check fails when
//
//   - something over a ceiling is not in the baseline (a new offender),
//   - an offender's value rose above its baseline (it got worse),
//   - an offender's value fell, or it fell under the ceiling, and the
//     baseline still records the old value (the baseline must shrink with
//     it, so the improvement cannot be spent later).
//
// With -update it rewrites the baseline, but only to record improvements:
// it refuses while there is a new or worse offender. -init writes the first
// baseline and refuses when one exists. Beyond that there is no way to add
// an entry except editing the file by hand, which review sees.
//
// The function metrics come from golangci-lint, run with only gocyclo,
// gocognit and funlen enabled and the repository's own settings and
// exclusions (tests are exempt), so this and an editor's lint agree on
// every number. Files are measured when tracked, not tests and not under
// testdata. `make lint` runs golangci-lint with those three linters
// disabled and then this.
//
//	go run ./scripts/complexity [-update | -init] [-baseline .complexity-baseline]
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
	"strings"
)

// maxFileLines is the per-file ceiling. golangci-lint has no file-length
// linter, so this is the one ceiling set here.
const maxFileLines = 500

// Entry is one measurement over a ceiling.
type Entry struct {
	Metric string // cyclomatic, cognitive, lines, statements or file-lines
	File   string
	Func   string // "-" for a file-level metric
	Value  int
	line   int // orders same-named functions in one file; not recorded
}

// key identifies an entry across runs. Line numbers are left out because
// they move whenever anything above them changes.
func (e Entry) key() string { return e.Metric + " " + e.File + " " + e.Func }

// measureFunc produces the current offenders.
type measureFunc func() ([]Entry, error)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr, measureAll))
}

// run is main without the process: it returns the exit status.
func run(args []string, stdout, stderr io.Writer, measure measureFunc) int {
	fs := flag.NewFlagSet("complexity", flag.ContinueOnError)
	fs.SetOutput(stderr)
	path := fs.String("baseline", ".complexity-baseline", "baseline file")
	update := fs.Bool("update", false, "rewrite the baseline to record improvements")
	initial := fs.Bool("init", false, "write the first baseline; refused when one exists")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	current, err := measure()
	if err != nil {
		say(stderr, "complexity: %v\n", err)
		return 1
	}
	if *initial {
		return writeInitial(*path, current, stdout, stderr)
	}
	base, err := readBaseline(*path)
	if err != nil {
		say(stderr, "complexity: %v\n", err)
		return 1
	}
	return verdict(compare(base, current), current, *path, *update, stdout, stderr)
}

// verdict reports the comparison and, with update, records improvements.
func verdict(ps []problem, current []Entry, path string, update bool, stdout, stderr io.Writer) int {
	blocking := 0
	for _, p := range ps {
		say(stderr, "complexity: %s\n", p.msg)
		if p.blocking {
			blocking++
		}
	}
	switch {
	case blocking > 0:
		say(stderr, "complexity: %d new or worse offender(s); bring them under the ceiling, the baseline only shrinks\n", blocking)
		return 1
	case len(ps) > 0 && !update:
		say(stderr, "complexity: the baseline records values that improved; run `go run ./scripts/complexity -update` and commit %s\n", path)
		return 1
	case len(ps) > 0:
		if err := os.WriteFile(filepath.Clean(path), formatBaseline(current), 0o600); err != nil {
			say(stderr, "complexity: %v\n", err)
			return 1
		}
		say(stdout, "complexity: %s now records %d offender(s)\n", path, len(current))
		return 0
	}
	say(stdout, "complexity: %d offender(s), all in the baseline and none worse\n", len(current))
	return 0
}

// writeInitial records the first baseline. It is the one way to write
// entries the baseline did not already hold, so it refuses to replace a
// file that exists: a later offender is fixed, not recorded.
func writeInitial(path string, current []Entry, stdout, stderr io.Writer) int {
	f, err := os.OpenFile(filepath.Clean(path), os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		say(stderr, "complexity: -init: %v; the baseline is only ever shrunk with -update\n", err)
		return 1
	}
	_, werr := f.Write(formatBaseline(current))
	if err := errors.Join(werr, f.Close()); err != nil {
		say(stderr, "complexity: %v\n", err)
		return 1
	}
	say(stdout, "complexity: wrote %s with %d offender(s)\n", path, len(current))
	return 0
}

// say writes one line of the check's output. A failed write to a terminal
// or a CI log has nowhere better to be reported.
func say(w io.Writer, format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }

// problem is one difference between the baseline and a measurement.
// Blocking problems are regressions; the others are improvements the
// baseline has not recorded yet.
type problem struct {
	msg      string
	blocking bool
}

// compare lists every difference between the baseline and the current
// measurement, in a stable order.
func compare(base, current []Entry) []problem {
	was := map[string]int{}
	for _, e := range base {
		was[e.key()] = e.Value
	}
	var out []problem
	seen := map[string]bool{}
	for _, e := range current {
		seen[e.key()] = true
		old, ok := was[e.key()]
		switch {
		case !ok:
			out = append(out, problem{fmt.Sprintf("new offender: %s is %d", e.key(), e.Value), true})
		case e.Value > old:
			out = append(out, problem{fmt.Sprintf("worse: %s is %d, baseline %d", e.key(), e.Value, old), true})
		case e.Value < old:
			out = append(out, problem{fmt.Sprintf("improved: %s is %d, baseline %d; lower the baseline", e.key(), e.Value, old), false})
		}
	}
	for _, e := range base {
		if !seen[e.key()] {
			out = append(out, problem{fmt.Sprintf("fixed: %s is under the ceiling; remove it from the baseline", e.key()), false})
		}
	}
	return out
}

// measureAll runs every measurement from the repository root.
func measureAll() ([]Entry, error) { return measure(lintOutput, goFiles) }

// lintOutput runs golangci-lint with only the complexity linters, under
// the repository's settings and exclusions, and returns its JSON report.
func lintOutput() ([]byte, error) {
	return exec.CommandContext(context.Background(), "golangci-lint", "run",
		"--enable-only", "gocyclo,gocognit,funlen",
		"--output.json.path", "stdout", "--show-stats=false", "--allow-parallel-runners",
		"--max-issues-per-linter", "0", "--max-same-issues", "0",
		"./...").Output()
}

// goFiles lists the tracked Go files the file ceiling applies to: not
// tests, which the function ceilings exempt too, and not fixtures.
func goFiles() ([]byte, error) {
	return exec.CommandContext(context.Background(), "git", "ls-files", "--", "*.go", ":!:*_test.go", ":!:**/testdata/**").Output()
}

// measure combines the linter's function metrics with the file lengths.
func measure(lint, files func() ([]byte, error)) ([]Entry, error) {
	out, err := lint()
	// golangci-lint exits 1 when it found issues, which here is expected;
	// anything it could not run shows up as unparsable output instead.
	var exit *exec.ExitError
	if err != nil && (!errors.As(err, &exit) || exit.ExitCode() != 1) {
		return nil, fmt.Errorf("running golangci-lint: %w", err)
	}
	funcs, err := parseLint(out)
	if err != nil {
		return nil, err
	}
	list, err := files()
	if err != nil {
		return nil, fmt.Errorf("listing Go files: %w", err)
	}
	long, err := fileLengths(strings.Fields(string(list)), os.ReadFile)
	if err != nil {
		return nil, err
	}
	return sortEntries(append(funcs, long...)), nil
}
