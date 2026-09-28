// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package trace

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// fixture loads the fixture stories and scans the fixture module.
func fixture(t *testing.T) Report {
	t.Helper()
	stories, err := LoadStories("testdata/stories.json")
	if err != nil {
		t.Fatal(err)
	}
	cits, bad, err := Scan("testdata/mod")
	if err != nil {
		t.Fatal(err)
	}
	return Build(stories, cits, bad)
}

func criterion(t *testing.T, r Report, id string) Criterion {
	t.Helper()
	for _, s := range r.Stories {
		for _, c := range s.Criteria {
			if c.ID == id {
				return c
			}
		}
	}
	t.Fatalf("no criterion %s", id)
	return Criterion{}
}

// AC: TRACE-01
func TestTraceListsEachStorysCriteriaWithAndWithoutTests(t *testing.T) {
	r := fixture(t)
	if len(r.Stories) != 2 {
		t.Fatalf("stories = %d, want 2", len(r.Stories))
	}
	got := map[int][]string{}
	for _, s := range r.Stories {
		for _, c := range s.Criteria {
			got[s.Number] = append(got[s.Number], c.ID)
		}
	}
	// Only definitions count: the footer's example SOC2-01, the CVE number
	// and #1's mention of BETA-01 are not #1's criteria, and BETA-01 defined
	// twice in #2 is one criterion.
	want := map[int][]string{1: {"ALPHA-01", "ALPHA-02"}, 2: {"BETA-01", "BETA-02"}}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("criteria = %v, want %v", got, want)
	}
	if untested := r.Stories[0].Untested(); !reflect.DeepEqual(untested, []string{"ALPHA-02"}) {
		t.Fatalf("#1 untested = %v, want [ALPHA-02]", untested)
	}
	var out bytes.Buffer
	r.WriteText(&out)
	for _, want := range []string{
		"#1 A closed story [closed] 1/2 criteria tested",
		"ALPHA-01   ./alpha.TestBoth",
		"ALPHA-02   (no test)",
		"#2 An open story [open] 2/2 criteria tested",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("report lacks %q:\n%s", want, out.String())
		}
	}
}

// AC: TRACE-02
func TestTraceCountsCitationsAndReportsOrphans(t *testing.T) {
	r := fixture(t)
	// One test citing two IDs counts toward both.
	for _, id := range []string{"ALPHA-01", "BETA-01"} {
		found := false
		for _, tst := range criterion(t, r, id).Tests {
			found = found || (tst.Package == "./alpha" && tst.Name == "TestBoth")
		}
		if !found {
			t.Errorf("%s does not count ./alpha.TestBoth", id)
		}
	}
	// A fuzz target counts; a helper and a method never do.
	b1 := criterion(t, r, "BETA-01").Tests
	var names []string
	for _, tt := range b1 {
		names = append(names, tt.Name)
	}
	sort.Strings(names)
	if want := []string{"FuzzCited", "TestBoth", "TestElsewhere"}; !reflect.DeepEqual(names, want) {
		t.Errorf("BETA-01 tests = %v, want %v", names, want)
	}
	if n := len(criterion(t, r, "ALPHA-02").Tests); n != 0 {
		t.Errorf("ALPHA-02 has %d tests; a helper and a method must not count", n)
	}
	if len(r.Orphans) != 1 || r.Orphans[0].ID != "GHOST-01" || r.Orphans[0].Test != "TestOrphan" {
		t.Errorf("orphans = %+v, want GHOST-01 from TestOrphan", r.Orphans)
	}
	if len(r.Malformed) != 1 || r.Malformed[0].Text != "not-an-id" {
		t.Errorf("malformed = %+v, want not-an-id", r.Malformed)
	}
	var out bytes.Buffer
	r.WriteText(&out)
	if !strings.Contains(out.String(), "orphan: GHOST-01 cited by ./alpha.TestOrphan") {
		t.Errorf("orphan not reported:\n%s", out.String())
	}
}

// AC: TRACE-03
func TestTraceFailsOnlyClosedStoriesWithUntestedCriteria(t *testing.T) {
	r := fixture(t)
	f := r.Failures()
	want := []string{
		"#1 is closed but ALPHA-02 has no test",
		`alpha/alpha_test.go:16: "not-an-id" is not a criterion ID`,
	}
	if !reflect.DeepEqual(f, want) {
		t.Fatalf("failures = %q, want %q", f, want)
	}
	// Open: the same gap is reported and does not fail.
	r.Stories[0].State = "open"
	r.Malformed = nil
	if f := r.Failures(); len(f) != 0 {
		t.Fatalf("an open story failed the gate: %q", f)
	}
}

// fakeGo answers `go test -json` for the fixture module without running it.
func fakeGo(events map[string]string) Runner {
	return func(dir string, args ...string) ([]byte, error) {
		pkg := args[len(args)-1]
		var out bytes.Buffer
		for key, action := range events {
			p, name, _ := strings.Cut(key, " ")
			if p != pkg {
				continue
			}
			line, _ := json.Marshal(map[string]string{"Action": action, "Test": name})
			out.Write(line)
			out.WriteByte('\n')
			sub, _ := json.Marshal(map[string]string{"Action": "fail", "Test": name + "/sub"})
			out.Write(sub)
			out.WriteString("\nnot json\n")
		}
		return out.Bytes(), errors.New("exit status 1")
	}
}

// AC: TRACE-04
func TestTraceRunsCitedTestsAndReportsEachResult(t *testing.T) {
	r := fixture(t)
	var called []string
	run := fakeGo(map[string]string{"./alpha TestBoth": "pass", "./beta TestFails": "fail", "./beta FuzzCited": "skip"})
	err := RunCited(&r, "testdata/mod", func(dir string, args ...string) ([]byte, error) {
		called = append(called, strings.Join(args, " "))
		return run(dir, args...)
	})
	// One run per package, selecting exactly that package's cited tests.
	wantCalls := []string{
		"test -count=1 -json -run ^(TestBoth)$ ./alpha",
		"test -count=1 -json -run ^(FuzzCited|TestElsewhere|TestFails)$ ./beta",
	}
	if !reflect.DeepEqual(called, wantCalls) {
		t.Fatalf("calls = %q, want %q", called, wantCalls)
	}
	if err == nil || !strings.Contains(err.Error(), "BETA-02: ./beta.TestFails fail") {
		t.Fatalf("a failing cited test was not reported: %v", err)
	}
	results := map[string]string{}
	for _, s := range r.Stories {
		for _, c := range s.Criteria {
			for _, tst := range c.Tests {
				results[c.ID+" "+tst.Name] = tst.Result
			}
		}
	}
	want := map[string]string{"ALPHA-01 TestBoth": "pass", "BETA-01 TestBoth": "pass", "BETA-01 TestElsewhere": "other-platform", "BETA-01 FuzzCited": "skip", "BETA-02 TestFails": "fail"}
	if !reflect.DeepEqual(results, want) {
		t.Fatalf("results = %v, want %v", results, want)
	}
	var md bytes.Buffer
	r.WriteMarkdown(&md)
	for _, line := range []string{"| ALPHA-01 | `./alpha.TestBoth` | pass |", "| ALPHA-02 | none | untested |", "| BETA-02 | `./beta.TestFails` | fail |", "- GHOST-01 in `./alpha.TestOrphan`"} {
		if !strings.Contains(md.String(), line) {
			t.Errorf("markdown lacks %q:\n%s", line, md.String())
		}
	}
	var js bytes.Buffer
	if err := r.WriteJSON(&js); err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(js.Bytes(), &back); err != nil || !reflect.DeepEqual(back, r) {
		t.Fatalf("JSON report does not round-trip: %v", err)
	}
	// A cited test the toolchain never ran is missing, not passing.
	r2 := fixture(t)
	err = RunCited(&r2, "testdata/mod", fakeGo(nil))
	if err == nil || !strings.Contains(err.Error(), "./alpha.TestBoth missing") {
		t.Fatalf("a missing cited test was not reported: %v", err)
	}
}

// AC: TRACE-04
func TestTraceRunsCitedTestsWithTheRealToolchain(t *testing.T) {
	if testing.Short() {
		t.Skip("runs go test on the fixture module")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("no go toolchain on PATH")
	}
	r := fixture(t)
	err := RunCited(&r, "testdata/mod", GoRunner)
	if err == nil || !strings.Contains(err.Error(), "BETA-02: ./beta.TestFails fail") {
		t.Fatalf("the deliberately failing fixture test was not caught: %v", err)
	}
	if got := criterion(t, r, "ALPHA-01").Tests[0].Result; got != "pass" {
		t.Fatalf("./alpha.TestBoth = %q, want pass", got)
	}
	// A cited test that does not build on this platform is excused, not
	// missing, and does not appear among the failures.
	for _, tt := range criterion(t, r, "BETA-01").Tests {
		if tt.Name == "TestElsewhere" && tt.Result != "other-platform" {
			t.Errorf("./beta.TestElsewhere = %q, want other-platform", tt.Result)
		}
	}
	if strings.Contains(err.Error(), "TestElsewhere") {
		t.Errorf("a test for another platform failed the gate: %v", err)
	}
}

// failingWriter fails every write, as a full disk or a closed pipe does.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestReportsSayWhenTheyCannotBeWritten(t *testing.T) {
	r := fixture(t)
	if err := r.WriteText(failingWriter{}); err == nil || err.Error() != "disk full" {
		t.Errorf("WriteText = %v, want the write error", err)
	}
	if err := r.WriteMarkdown(failingWriter{}); err == nil || err.Error() != "disk full" {
		t.Errorf("WriteMarkdown = %v, want the write error", err)
	}
}

// AC: TRACE-05
func TestTraceReadsTheCommittedSnapshotOffline(t *testing.T) {
	// The committed snapshot is what the gate reads; loading it needs no
	// network and must yield stories with criteria.
	stories, err := LoadStories("../../testdata/stories.json")
	if err != nil {
		t.Fatalf("the committed snapshot does not load: %v", err)
	}
	if len(stories) == 0 {
		t.Fatal("the committed snapshot is empty")
	}
	for _, s := range stories {
		if len(s.Criteria()) == 0 {
			t.Errorf("#%d %q defines no criteria", s.Number, s.Title)
		}
	}
	// trace-refresh's conversion: every page of a paginated listing, pull
	// requests dropped, sorted by number, a trailing newline.
	listing, err := os.ReadFile("testdata/listing.json")
	if err != nil {
		t.Fatal(err)
	}
	snap, err := Snapshot(listing)
	if err != nil {
		t.Fatal(err)
	}
	var got []Story
	if err := json.Unmarshal(snap, &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Number != 4 || got[1].Number != 9 || !got[1].Closed() {
		t.Fatalf("snapshot = %+v, want #4 then closed #9", got)
	}
	if !bytes.HasSuffix(snap, []byte("\n")) {
		t.Error("snapshot has no trailing newline")
	}
	if _, err := Snapshot([]byte("{not a listing")); err == nil {
		t.Error("a malformed listing was accepted")
	}
	if _, err := LoadStories("testdata/listing.json"); err == nil {
		t.Error("a listing of several arrays was accepted as a snapshot")
	}
	if _, err := LoadStories("testdata/absent.json"); err == nil {
		t.Error("a missing snapshot was accepted")
	}
}

// AC: TRACE-03
// A closed story implemented in another repository is enforced by that
// repository's trace, not this one; a closed story implemented here still
// fails for every untested criterion.
func TestTraceEnforcesOnlyStoriesThisRepositoryImplements(t *testing.T) {
	story := func(n int, home string) Story {
		body := "- **HOME-0" + strconv.Itoa(n) + "**: **Given** a, **when** b, **then** c.\n"
		if home != "" {
			body = "**Repository:** " + home + "\n\n" + body
		}
		return Story{Number: n, Title: "s", State: "closed", Body: body}
	}
	stories := []Story{story(1, "owner/elsewhere"), story(2, "owner/here"), story(3, "")}
	r := Build(stories, nil, nil)
	r.Repo = "owner/here"
	got := r.Failures()
	want := []string{"#2 is closed but HOME-02 has no test", "#3 is closed but HOME-03 has no test"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("failures = %q, want %q", got, want)
	}
	if r.Stories[0].Home != "owner/elsewhere" {
		t.Errorf("home = %q", r.Stories[0].Home)
	}
	var out strings.Builder
	if err := r.WriteText(&out); err != nil || !strings.Contains(out.String(), "implemented and enforced in owner/elsewhere") {
		t.Errorf("the text report does not say where #1 is enforced:\n%s", out.String())
	}
	// A story whose issue names no repository belongs to the repository
	// its issue is in: enforced there, and left alone anywhere else.
	r.Origin = "owner/here"
	if got := r.Failures(); !reflect.DeepEqual(got, want) {
		t.Errorf("in the origin, failures = %q, want %q", got, want)
	}
	r.Repo = "owner/elsewhere"
	if got := r.Failures(); !reflect.DeepEqual(got, []string{"#1 is closed but HOME-01 has no test"}) {
		t.Errorf("in another repository, failures = %q; only its own story counts", got)
	}
	// Without a repository to compare with, nothing is excused.
	r.Repo = ""
	if n := len(r.Failures()); n != 3 {
		t.Errorf("with no repository set, %d failures, want 3", n)
	}
}
