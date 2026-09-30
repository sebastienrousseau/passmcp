// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// lintPatterns read a value and a function name out of each linter's
// message. The capture groups are named because funlen puts the name first.
var lintPatterns = map[string][]struct {
	metric string
	re     *regexp.Regexp
}{
	"gocyclo":  {{"cyclomatic", regexp.MustCompile("^cyclomatic complexity (?P<value>\\d+) of func `(?P<func>[^`]+)`")}},
	"gocognit": {{"cognitive", regexp.MustCompile("^cognitive complexity (?P<value>\\d+) of func `(?P<func>[^`]+)`")}},
	"funlen": {
		{"lines", regexp.MustCompile(`^Function '(?P<func>[^']+)' is too long \((?P<value>\d+) >`)},
		{"statements", regexp.MustCompile(`^Function '(?P<func>[^']+)' has too many statements \((?P<value>\d+) >`)},
	},
}

// lintReport is the part of golangci-lint's JSON output read here.
type lintReport struct {
	Issues []struct {
		FromLinter string
		Text       string
		Pos        struct {
			Filename string
			Line     int
		}
	}
}

// parseLint turns golangci-lint's JSON report into entries. A message
// from one of the three linters that no pattern matches is an error: the
// linter changed its wording, and guessing would let an offender through.
func parseLint(out []byte) ([]Entry, error) {
	var rep lintReport
	if err := json.Unmarshal(out, &rep); err != nil {
		return nil, fmt.Errorf("reading golangci-lint output: %w", err)
	}
	var entries []Entry
	for _, is := range rep.Issues {
		e, err := lintEntry(is.FromLinter, is.Text)
		if err != nil {
			return nil, fmt.Errorf("%s:%d: %w", is.Pos.Filename, is.Pos.Line, err)
		}
		e.File, e.line = is.Pos.Filename, is.Pos.Line
		entries = append(entries, e)
	}
	return entries, nil
}

// lintEntry reads one linter message.
func lintEntry(linter, text string) (Entry, error) {
	for _, p := range lintPatterns[linter] {
		m := p.re.FindStringSubmatch(text)
		if m == nil {
			continue
		}
		v, err := strconv.Atoi(m[p.re.SubexpIndex("value")])
		if err != nil {
			return Entry{}, err
		}
		return Entry{Metric: p.metric, Func: m[p.re.SubexpIndex("func")], Value: v}, nil
	}
	return Entry{}, fmt.Errorf("unrecognised %s message %q", linter, text)
}

// fileLengths returns an entry for every file over maxFileLines lines.
func fileLengths(files []string, read func(string) ([]byte, error)) ([]Entry, error) {
	var out []Entry
	for _, f := range files {
		b, err := read(f)
		if err != nil {
			return nil, err
		}
		if n := bytes.Count(b, []byte("\n")); n > maxFileLines {
			out = append(out, Entry{Metric: "file-lines", File: f, Func: "-", Value: n})
		}
	}
	return out, nil
}

// sortEntries orders entries by key, and numbers same-named functions in
// one file (funlen names a method without its receiver) in line order,
// so each still has a key of its own.
func sortEntries(es []Entry) []Entry {
	sort.SliceStable(es, func(i, j int) bool {
		if es[i].key() != es[j].key() {
			return es[i].key() < es[j].key()
		}
		return es[i].line < es[j].line
	})
	seen := map[string]int{}
	for i := range es {
		k := es[i].key()
		seen[k]++
		if seen[k] > 1 {
			es[i].Func += "#" + strconv.Itoa(seen[k])
		}
	}
	return es
}

const baselineHeader = `# Complexity offenders recorded when the ceilings were lowered to the
# portfolio's (cyclomatic 10, cognitive 15, 60 lines per function, 500 per
# file). scripts/complexity fails on anything over a ceiling that is not
# here, on any value here that grew, and on any value here that shrank
# without this file following it. The file only ever gets shorter.
#
# metric value file function
`

// formatBaseline renders entries as the baseline file.
func formatBaseline(es []Entry) []byte {
	var b strings.Builder
	b.WriteString(baselineHeader)
	for _, e := range es {
		fmt.Fprintf(&b, "%s %d %s %s\n", e.Metric, e.Value, e.File, e.Func)
	}
	return []byte(b.String())
}

// readBaseline parses the baseline file. A missing file is an empty
// baseline, which is what a repository with no offenders has.
func readBaseline(path string) ([]Entry, error) {
	b, err := os.ReadFile(filepath.Clean(path))
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []Entry
	sc := bufio.NewScanner(bytes.NewReader(b))
	for n := 1; sc.Scan(); n++ {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		v, err := strconv.Atoi(f[min(1, len(f)-1)])
		if len(f) != 4 || err != nil {
			return nil, fmt.Errorf("%s:%d: want \"metric value file function\", got %q", path, n, line)
		}
		out = append(out, Entry{Metric: f[0], Value: v, File: f[2], Func: f[3]})
	}
	return out, sc.Err()
}
