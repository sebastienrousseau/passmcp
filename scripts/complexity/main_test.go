// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

const lintJSON = `{"Issues":[
{"FromLinter":"gocyclo","Text":"cyclomatic complexity 12 of func ` + "`(*T).Run`" + ` is high (> 10)","Pos":{"Filename":"a.go","Line":10}},
{"FromLinter":"gocognit","Text":"cognitive complexity 17 of func ` + "`parse`" + ` is high (> 15)","Pos":{"Filename":"b.go","Line":3}},
{"FromLinter":"funlen","Text":"Function 'Build' is too long (66 > 60)","Pos":{"Filename":"c.go","Line":40}},
{"FromLinter":"funlen","Text":"Function 'Build' has too many statements (52 > 50)","Pos":{"Filename":"c.go","Line":40}}
]}`

func TestParseLintReadsEveryLinter(t *testing.T) {
	got, err := parseLint([]byte(lintJSON))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cyclomatic a.go (*T).Run=12",
		"cognitive b.go parse=17",
		"lines c.go Build=66",
		"statements c.go Build=52",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i, e := range got {
		if s := e.key() + "=" + strconv.Itoa(e.Value); s != want[i] {
			t.Errorf("entry %d = %s, want %s", i, s, want[i])
		}
	}
}

// TestParseLintRefusesWhatItCannotRead: a linter that rewords its message
// must stop the check, not let the offender through as zero.
func TestParseLintRefusesWhatItCannotRead(t *testing.T) {
	if _, err := parseLint([]byte("not json")); err == nil {
		t.Error("malformed JSON was accepted")
	}
	reworded := `{"Issues":[{"FromLinter":"gocyclo","Text":"func f is complex","Pos":{"Filename":"a.go","Line":1}}]}`
	if _, err := parseLint([]byte(reworded)); err == nil || !strings.Contains(err.Error(), "a.go:1") {
		t.Errorf("an unrecognised message gave %v, want an error naming its position", err)
	}
	huge := `{"Issues":[{"FromLinter":"gocyclo","Text":"cyclomatic complexity 99999999999999999999 of func ` + "`f`" + `","Pos":{"Filename":"a.go","Line":1}}]}`
	if _, err := parseLint([]byte(huge)); err == nil {
		t.Error("an unrepresentable value was accepted")
	}
}

func TestFileLengths(t *testing.T) {
	files := map[string]string{
		"short.go": strings.Repeat("x\n", maxFileLines),
		"long.go":  strings.Repeat("x\n", maxFileLines+1),
	}
	read := func(name string) ([]byte, error) {
		s, ok := files[name]
		if !ok {
			return nil, os.ErrNotExist
		}
		return []byte(s), nil
	}
	got, err := fileLengths([]string{"short.go", "long.go"}, read)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].key() != "file-lines long.go -" || got[0].Value != maxFileLines+1 {
		t.Errorf("got %+v, want only long.go at %d lines", got, maxFileLines+1)
	}
	if _, err := fileLengths([]string{"missing.go"}, read); err == nil {
		t.Error("an unreadable file was skipped")
	}
}

// TestSortEntriesKeepsSameNamedFunctionsApart: funlen names a method
// without its receiver, so two in one file share a name.
func TestSortEntriesKeepsSameNamedFunctionsApart(t *testing.T) {
	got := sortEntries([]Entry{
		{Metric: "lines", File: "a.go", Func: "String", Value: 70, line: 90},
		{Metric: "lines", File: "a.go", Func: "String", Value: 65, line: 10},
		{Metric: "cognitive", File: "a.go", Func: "f", Value: 16},
	})
	want := []string{"cognitive a.go f", "lines a.go String", "lines a.go String#2"}
	for i, e := range got {
		if e.key() != want[i] {
			t.Errorf("entry %d = %q, want %q", i, e.key(), want[i])
		}
	}
	if got[1].Value != 65 {
		t.Errorf("the first String by line should keep the plain name; got value %d", got[1].Value)
	}
}

func TestCompare(t *testing.T) {
	base := []Entry{
		{Metric: "cyclomatic", File: "a.go", Func: "same", Value: 12},
		{Metric: "cyclomatic", File: "a.go", Func: "worse", Value: 12},
		{Metric: "cyclomatic", File: "a.go", Func: "better", Value: 14},
		{Metric: "cyclomatic", File: "a.go", Func: "fixed", Value: 11},
	}
	current := []Entry{
		{Metric: "cyclomatic", File: "a.go", Func: "same", Value: 12},
		{Metric: "cyclomatic", File: "a.go", Func: "worse", Value: 13},
		{Metric: "cyclomatic", File: "a.go", Func: "better", Value: 12},
		{Metric: "cyclomatic", File: "b.go", Func: "new", Value: 11},
	}
	got := compare(base, current)
	want := []struct {
		prefix   string
		blocking bool
	}{
		{"worse: cyclomatic a.go worse is 13, baseline 12", true},
		{"improved: cyclomatic a.go better is 12, baseline 14", false},
		{"new offender: cyclomatic b.go new is 11", true},
		{"fixed: cyclomatic a.go fixed", false},
	}
	if len(got) != len(want) {
		t.Fatalf("got %d problems, want %d: %+v", len(got), len(want), got)
	}
	for i, p := range got {
		if !strings.HasPrefix(p.msg, want[i].prefix) || p.blocking != want[i].blocking {
			t.Errorf("problem %d = %+v, want %q blocking=%t", i, p, want[i].prefix, want[i].blocking)
		}
	}
}

func TestBaselineRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline")
	es := []Entry{{Metric: "cognitive", File: "a.go", Func: "(*T).m", Value: 16}, {Metric: "file-lines", File: "b.go", Func: "-", Value: 600}}
	if err := os.WriteFile(path, formatBaseline(es), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := readBaseline(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != es[0] || got[1] != es[1] {
		t.Errorf("round trip gave %+v, want %+v", got, es)
	}
	if got, err := readBaseline(filepath.Join(t.TempDir(), "absent")); err != nil || got != nil {
		t.Errorf("a missing baseline gave %v, %v; want an empty one", got, err)
	}
	for _, bad := range []string{"cognitive 16 a.go\n", "cognitive many a.go f\n"} {
		if err := os.WriteFile(path, []byte(bad), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readBaseline(path); err == nil {
			t.Errorf("malformed line %q was accepted", bad)
		}
	}
	if _, err := readBaseline(t.TempDir()); err == nil {
		t.Error("a directory was read as a baseline")
	}
}

// fixed returns a measureFunc that reports es.
func fixed(es ...Entry) measureFunc { return func() ([]Entry, error) { return es, nil } }

func runIn(t *testing.T, path string, m measureFunc, args ...string) (int, string) {
	t.Helper()
	var out, errOut bytes.Buffer
	code := run(append([]string{"-baseline", path}, args...), &out, &errOut, m)
	return code, out.String() + errOut.String()
}

// TestRunOnlyEverShrinks walks the baseline's life: written once, held,
// refused a regression, and lowered only when a value improved.
func TestRunOnlyEverShrinks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "baseline")
	a := Entry{Metric: "cyclomatic", File: "a.go", Func: "f", Value: 12}
	b := Entry{Metric: "cognitive", File: "b.go", Func: "g", Value: 18}

	if code, out := runIn(t, path, fixed(a, b), "-init"); code != 0 {
		t.Fatalf("-init: %d %s", code, out)
	}
	if code, out := runIn(t, path, fixed(a, b), "-init"); code != 1 || !strings.Contains(out, "only ever shrunk") {
		t.Errorf("a second -init gave %d %s", code, out)
	}
	if code, out := runIn(t, path, fixed(a, b)); code != 0 || !strings.Contains(out, "2 offender(s)") {
		t.Errorf("an unchanged tree gave %d %s", code, out)
	}
	worse := a
	worse.Value = 13
	if code, out := runIn(t, path, fixed(worse, b), "-update"); code != 1 || !strings.Contains(out, "worse:") {
		t.Errorf("-update over a regression gave %d %s", code, out)
	}
	if code, out := runIn(t, path, fixed(a)); code != 1 || !strings.Contains(out, "fixed:") {
		t.Errorf("a fixed offender left in the baseline gave %d %s", code, out)
	}
	if code, out := runIn(t, path, fixed(a), "-update"); code != 0 {
		t.Errorf("-update after a fix gave %d %s", code, out)
	}
	if got, _ := readBaseline(path); len(got) != 1 || got[0] != a {
		t.Errorf("the baseline after -update is %+v, want only %+v", got, a)
	}
}

func TestRunReportsFailures(t *testing.T) {
	dir := t.TempDir()
	broken := func() ([]Entry, error) { return nil, errors.New("no linter") }
	if code, out := runIn(t, filepath.Join(dir, "b"), broken); code != 1 || !strings.Contains(out, "no linter") {
		t.Errorf("a failed measurement gave %d %s", code, out)
	}
	if code, _ := runIn(t, filepath.Join(dir, "b"), fixed(), "-nonsense"); code != 2 {
		t.Errorf("an unknown flag gave %d, want 2", code)
	}
	if code, _ := runIn(t, dir, fixed()); code != 1 {
		t.Error("an unreadable baseline was accepted")
	}
	if code, _ := runIn(t, filepath.Join(dir, "missing", "b"), fixed(), "-init"); code != 1 {
		t.Error("-init into a missing directory succeeded")
	}
	// -update that cannot write the improvement it found.
	sub := filepath.Join(dir, "readonly")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(sub, "b")
	e := Entry{Metric: "cyclomatic", File: "a.go", Func: "f", Value: 12}
	if code, _ := runIn(t, path, fixed(e), "-init"); code != 0 {
		t.Fatal("-init failed")
	}
	if err := os.Chmod(sub, 0o500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sub, 0o700) })
	if err := os.Chmod(path, 0o400); err != nil {
		t.Fatal(err)
	}
	if f, err := os.OpenFile(path, os.O_WRONLY, 0); err == nil {
		_ = f.Close()
		t.Skip("permissions do not stop this user writing a read-only file")
	}
	if code, out := runIn(t, path, fixed(), "-update"); code != 1 {
		t.Errorf("-update to a read-only baseline gave %d %s", code, out)
	}
}

func TestMeasure(t *testing.T) {
	dir := t.TempDir()
	long := filepath.Join(dir, "long.go")
	if err := os.WriteFile(long, []byte(strings.Repeat("x\n", maxFileLines+1)), 0o600); err != nil {
		t.Fatal(err)
	}
	lint := func() ([]byte, error) { return []byte(lintJSON), exitOne(t) }
	files := func() ([]byte, error) { return []byte(long + "\n"), nil }
	got, err := measure(lint, files)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5 {
		t.Errorf("got %d entries, want 4 from the linter and 1 file: %+v", len(got), got)
	}

	failing := []struct {
		name  string
		lint  func() ([]byte, error)
		files func() ([]byte, error)
	}{
		{"linter did not run", func() ([]byte, error) { return nil, errors.New("not found") }, files},
		{"linter output unreadable", func() ([]byte, error) { return []byte("{"), nil }, files},
		{"git failed", func() ([]byte, error) { return []byte(`{"Issues":[]}`), nil }, func() ([]byte, error) { return nil, errors.New("no git") }},
		{"file vanished", func() ([]byte, error) { return []byte(`{"Issues":[]}`), nil }, func() ([]byte, error) { return []byte(filepath.Join(dir, "gone.go")), nil }},
	}
	for _, tc := range failing {
		if _, err := measure(tc.lint, tc.files); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}
}

// exitOne returns the error a command exiting with status 1 produces,
// which is how golangci-lint says it found issues.
func exitOne(t *testing.T) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit 1").Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) {
		t.Skipf("no sh to produce an exit status: %v", err)
	}
	return err
}
