// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// Test is one test that proves a criterion, and, once the cited tests have
// run, how it did.
type Test struct {
	Package string `json:"package"`
	Name    string `json:"name"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Result  string `json:"result,omitempty"` // "pass", "fail", "skip" or "missing" after RunCited
}

// Criterion is one ID a story defines, with the tests that cite it.
type Criterion struct {
	ID    string `json:"id"`
	Tests []Test `json:"tests"`
}

// Tested reports whether at least one test cites the criterion.
func (c Criterion) Tested() bool { return len(c.Tests) > 0 }

// StoryReport is one story's criteria and their coverage.
type StoryReport struct {
	Number int    `json:"number"`
	Title  string `json:"title"`
	State  string `json:"state"`
	// Home is the repository that implements the story, when the issue
	// names one; empty means the repository the tracker belongs to.
	Home     string      `json:"home,omitempty"`
	Criteria []Criterion `json:"criteria"`
}

// Untested returns the IDs of the story's criteria no test cites.
func (s StoryReport) Untested() []string {
	var ids []string
	for _, c := range s.Criteria {
		if !c.Tested() {
			ids = append(ids, c.ID)
		}
	}
	return ids
}

// Report is the whole trace: every story, the citations that match no
// story, and the malformed citations.
type Report struct {
	// Repo is the repository this trace runs in, as owner/name. A story
	// whose Home names another repository is traced there, not here.
	Repo string `json:"repo,omitempty"`
	// Origin is the repository whose issues the stories are, as owner/name.
	// A story whose issue names no repository is implemented there, so a
	// trace run in another repository leaves it alone.
	Origin    string        `json:"origin,omitempty"`
	Stories   []StoryReport `json:"stories"`
	Orphans   []Citation    `json:"orphans"`
	Malformed []Malformed   `json:"malformed"`
}

// Build joins stories and citations. A citation of an ID no story defines
// is an orphan: either the story was edited and the test was not, or the ID
// is mistyped.
func Build(stories []Story, cits []Citation, bad []Malformed) Report {
	byID := map[string][]Citation{}
	for _, c := range cits {
		byID[c.ID] = append(byID[c.ID], c)
	}
	defined := map[string]bool{}
	r := Report{Orphans: []Citation{}, Malformed: bad}
	if r.Malformed == nil {
		r.Malformed = []Malformed{}
	}
	for _, s := range stories {
		sr := StoryReport{Number: s.Number, Title: s.Title, State: s.State, Home: s.Home(), Criteria: []Criterion{}}
		for _, id := range s.Criteria() {
			defined[id] = true
			c := Criterion{ID: id, Tests: []Test{}}
			for _, cit := range byID[id] {
				c.Tests = append(c.Tests, Test{Package: cit.Package, Name: cit.Test, File: cit.File, Line: cit.Line})
			}
			sr.Criteria = append(sr.Criteria, c)
		}
		r.Stories = append(r.Stories, sr)
	}
	for _, c := range cits {
		if !defined[c.ID] {
			r.Orphans = append(r.Orphans, c)
		}
	}
	return r
}

// Failures lists what fails the gate: every criterion of a closed story
// that no test cites, and every malformed citation. Open stories never
// fail it; their gaps are reported, so a story can land test by test. A
// story implemented in another repository is enforced by that
// repository's own trace, so it never fails this one.
func (r Report) Failures() []string {
	var out []string
	for _, s := range r.Stories {
		if !strings.EqualFold(s.State, "closed") || r.elsewhere(s) {
			continue
		}
		for _, id := range s.Untested() {
			out = append(out, fmt.Sprintf("#%d is closed but %s has no test", s.Number, id))
		}
	}
	for _, m := range r.Malformed {
		out = append(out, fmt.Sprintf("%s:%d: %q is not a criterion ID", m.File, m.Line, m.Text))
	}
	return out
}

// printer writes formatted lines and keeps the first error, so a report
// written to a full disk or a closed pipe says so once, at the end.
type printer struct {
	w   io.Writer
	err error
}

func (p *printer) f(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, a...)
	}
}

// WriteText prints the per-story summary the operator reads.
func (r Report) WriteText(w io.Writer) error {
	p := &printer{w: w}
	for _, s := range r.Stories {
		tested := len(s.Criteria) - len(s.Untested())
		p.f("#%d %s [%s] %d/%d criteria tested\n", s.Number, s.Title, s.State, tested, len(s.Criteria))
		if r.elsewhere(s) {
			p.f("  implemented and enforced in %s\n", r.home(s))
		}
		for _, c := range s.Criteria {
			p.f("  %-10s %s\n", c.ID, testList(c))
		}
	}
	for _, o := range r.Orphans {
		p.f("orphan: %s cited by %s.%s (%s:%d) is in no story\n", o.ID, o.Package, o.Test, o.File, o.Line)
	}
	for _, m := range r.Malformed {
		p.f("malformed: %s:%d: %q\n", m.File, m.Line, m.Text)
	}
	return p.err
}

// testList names a criterion's tests, or says it has none.
func testList(c Criterion) string {
	if !c.Tested() {
		return "(no test)"
	}
	names := make([]string, 0, len(c.Tests))
	for _, t := range c.Tests {
		names = append(names, t.Package+"."+t.Name)
	}
	return strings.Join(names, ", ")
}

// WriteMarkdown writes the criterion-to-test table published beside a CI run.
func (r Report) WriteMarkdown(w io.Writer) error {
	p := &printer{w: w}
	p.f("# Acceptance criteria and their tests\n\n")
	for _, s := range r.Stories {
		p.f("## #%d %s (%s)\n\n| Criterion | Test | Result |\n| --- | --- | --- |\n", s.Number, s.Title, s.State)
		for _, c := range s.Criteria {
			if !c.Tested() {
				p.f("| %s | none | untested |\n", c.ID)
				continue
			}
			for _, t := range c.Tests {
				result := t.Result
				if result == "" {
					result = "not run"
				}
				p.f("| %s | `%s.%s` | %s |\n", c.ID, t.Package, t.Name, result)
			}
		}
		p.f("\n")
	}
	if len(r.Orphans) > 0 {
		p.f("## Citations of criteria no story defines\n\n")
		for _, o := range r.Orphans {
			p.f("- %s in `%s.%s` (%s:%d)\n", o.ID, o.Package, o.Test, o.File, o.Line)
		}
	}
	return p.err
}

// WriteJSON writes the report as indented JSON.
func (r Report) WriteJSON(w io.Writer) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(r)
}

// elsewhere reports whether s is implemented in a repository other than
// the one this trace runs in.
func (r Report) elsewhere(s StoryReport) bool {
	home := r.home(s)
	return home != "" && r.Repo != "" && !strings.EqualFold(home, r.Repo)
}

// home is the repository that implements s: the one its issue names, or
// else the one its issue belongs to.
func (r Report) home(s StoryReport) string {
	if s.Home != "" {
		return s.Home
	}
	return r.Origin
}
