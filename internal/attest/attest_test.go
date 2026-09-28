// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package attest

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// sample is a report with one of every status, so a statement built from it
// exercises the counting and the ordering.
func sample() *report.Report {
	r := &report.Report{
		Passmcp:  report.Meta{Version: "0.0.3", SchemaVersion: report.SchemaVersion},
		Target:   report.Target{Endpoint: "https://mcp.example.com/mcp", Host: "mcp.example.com", Scheme: "https"},
		Started:  time.Date(2026, 9, 19, 10, 0, 0, 0, time.UTC),
		Duration: probe.Millis(1500 * time.Millisecond),
		TraceID:  "trace-abc",
		Server: &report.ServerInfo{
			Name: "acme-mcp", Version: "1.4.0", Protocol: "2026-07-28",
		},
		Phases: []probe.PhaseResult{{
			Name: "protocol", Title: "Protocol", Status: probe.Fail,
			Findings: []probe.Finding{
				{ID: "protocol.ping", Phase: "protocol", Status: probe.Pass, Evidence: []string{"req#4"}},
				{ID: "protocol.malformed_json", Phase: "protocol", Status: probe.Fail, Severity: probe.Minor,
					DocURL: "https://satellion.com/passmcp/docs/checks/#check-protocol-malformed_json"},
				{ID: "protocol.accept_header", Phase: "protocol", Status: probe.Skip},
				{ID: "protocol.get_stream", Phase: "protocol", Status: probe.Info},
				{ID: "protocol.id_echo", Phase: "protocol", Status: probe.Warn, Severity: probe.Minor},
			},
		}},
		Counts: report.Counts{Pass: 1, Warn: 1, Fail: 1, Skip: 1, Info: 1},
	}
	r.Score = report.Score{
		Total: 82, Grade: "B", Assessed: 1, Of: 6,
		Categories: []report.Category{
			{Name: "protocol", Weight: 20, Assessed: true, Score: 82},
			{Name: "execution", Weight: 20, Assessed: false},
		},
	}
	return r
}

func TestFromProducesAValidStatement(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatalf("From: %v", err)
	}
	if st.Type != StatementType || st.PredicateType != PredicateType {
		t.Errorf("envelope = %q / %q", st.Type, st.PredicateType)
	}
	if got := st.Predicate.Target.Transport; got != "http" {
		t.Errorf("transport = %q", got)
	}
	if got := st.Predicate.JudgedAgainst.SpecRevision; got != "2026-07-28" {
		t.Errorf("specRevision = %q", got)
	}
	if st.Predicate.JudgedAgainst.Rubric != report.RubricVersion {
		t.Errorf("rubric = %q, want %q", st.Predicate.JudgedAgainst.Rubric, report.RubricVersion)
	}
	if st.Predicate.Took != "1.5s" {
		t.Errorf("took = %q", st.Predicate.Took)
	}
	if st.Predicate.Score == nil || st.Predicate.Score.By["protocol"] != 82 {
		t.Errorf("score = %+v", st.Predicate.Score)
	}
	if _, ok := st.Predicate.Score.By["execution"]; ok {
		t.Error("an unassessed category contributed a category score")
	}
}

// TestPassesTravelToo is the property that makes a statement usable at all.
//
// A consumer cannot tell "checked and fine" from "not checked" unless both are
// present, and for a conformance tool that is the whole difference. Carrying
// only the failures would make a statement look like a bug report.
func TestPassesTravelToo(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"protocol.ping":           "pass",
		"protocol.malformed_json": "fail",
		"protocol.accept_header":  "skip",
		"protocol.get_stream":     "info",
		"protocol.id_echo":        "warn",
	}
	if len(st.Predicate.Verdicts) != len(want) {
		t.Fatalf("%d verdicts, want %d", len(st.Predicate.Verdicts), len(want))
	}
	for id, status := range want {
		v, err := st.VerdictFor(id)
		if err != nil {
			t.Errorf("%s: %v", id, err)
			continue
		}
		if v.Status != status {
			t.Errorf("%s is %q, want %q", id, v.Status, status)
		}
	}
	if _, err := st.VerdictFor("protocol.never_ran"); !errors.Is(err, ErrNoSuchCheck) {
		t.Errorf("a check that is not in the statement returned %v, want ErrNoSuchCheck", err)
	}
}

// TestStatementIsDeterministic: two statements about the same run must be
// byte-identical, or a diff between two runs is a diff about passmcp.
func TestStatementIsDeterministic(t *testing.T) {
	a, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	b, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	ab, err := a.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	bb, err := b.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(ab) != string(bb) {
		t.Error("two statements about the same report differ")
	}

	// And the verdicts are ordered by id rather than by phase-walk order, so
	// reordering a phase's findings does not reorder the statement.
	shuffled := sample()
	f := shuffled.Phases[0].Findings
	f[0], f[4] = f[4], f[0]
	c, err := From(shuffled)
	if err != nil {
		t.Fatal(err)
	}
	cb, err := c.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if string(cb) != string(ab) {
		t.Error("reordering findings changed the statement; the verdicts are not canonically ordered")
	}
}

// TestDigestCoversTheTargetAndNothingElse.
//
// The digest is the tie between a statement and a server. Two different
// targets must not collide, the same target must always agree, and editing
// the predicate after the fact must break it — that last one is what an
// attestation is for.
func TestDigestCoversTheTargetAndNothingElse(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	if !st.Covers("http", "https://mcp.example.com/mcp") {
		t.Error("the statement does not cover the target it was built from")
	}
	if st.Covers("stdio", "https://mcp.example.com/mcp") {
		t.Error("the digest ignores the transport; an HTTP and a stdio statement would collide")
	}
	if st.Covers("http", "https://other.example.com/mcp") {
		t.Error("the digest ignores the endpoint")
	}

	// Rewrite the predicate's target and the statement must stop validating.
	tampered := *st
	tampered.Predicate.Target.Endpoint = "https://attacker.example.com/mcp"
	err = tampered.Validate()
	if err == nil {
		t.Fatal("a statement whose target was rewritten still validated")
	}
	if !strings.Contains(err.Error(), "does not cover the target") {
		t.Errorf("the error does not name the problem: %v", err)
	}
}

func TestValidateRefuses(t *testing.T) {
	cases := map[string]struct {
		mutate func(*Statement)
		want   string
	}{
		"a foreign envelope":  {func(s *Statement) { s.Type = "https://example.com/Statement/v1" }, "_type"},
		"a foreign predicate": {func(s *Statement) { s.PredicateType = "https://example.com/other" }, "predicateType"},
		"no subject":          {func(s *Statement) { s.Subject = nil }, "about nothing"},
		"two subjects":        {func(s *Statement) { s.Subject = append(s.Subject, s.Subject[0]) }, "one server"},
		"a nameless subject":  {func(s *Statement) { s.Subject[0].Name = "" }, "no name"},
		// The name is the only part of a statement most consumers display:
		// in-toto tooling shows subject[0].name, not the predicate. Left
		// unchecked it could name one server while the predicate described
		// another, and the digest — taken over the predicate's target —
		// would still recompute. That is a lie that survives verification.
		"a subject renamed to another server": {
			func(s *Statement) { s.Subject[0].Name = "https://trustworthy.example.com/mcp" },
			"but the predicate is about",
		},
		"no digest":                 {func(s *Statement) { s.Subject[0].Digest = nil }, "no sha256"},
		"a mislabelled digest":      {func(s *Statement) { s.Predicate.SubjectKind = "artifact" }, "subjectKind"},
		"no endpoint":               {func(s *Statement) { s.Predicate.Target.Endpoint = "" }, "no endpoint"},
		"no transport":              {func(s *Statement) { s.Predicate.Target.Transport = "" }, "no transport"},
		"an unknown transport":      {func(s *Statement) { s.Predicate.Target.Transport = "carrier-pigeon" }, "unknown transport"},
		"no instrument":             {func(s *Statement) { s.Predicate.Instrument.Version = "" }, "not identified"},
		"no run time":               {func(s *Statement) { s.Predicate.RanAt = time.Time{} }, "no run time"},
		"no verdicts":               {func(s *Statement) { s.Predicate.Verdicts = nil }, "no verdicts"},
		"no check inventory":        {func(s *Statement) { s.Predicate.JudgedAgainst.CheckInventory = "" }, "checkInventory"},
		"a score with no rubric":    {func(s *Statement) { s.Predicate.JudgedAgainst.Rubric = "" }, "no rubric"},
		"an unknown status":         {func(s *Statement) { s.Predicate.Verdicts[0].Status = "probably" }, "status"},
		"an unnamed verdict":        {func(s *Statement) { s.Predicate.Verdicts[0].ID = "" }, "no id"},
		"counts that do not add up": {func(s *Statement) { s.Predicate.Counts.Fail = 99 }, "counts disagree"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			st, err := From(sample())
			if err != nil {
				t.Fatal(err)
			}
			tc.mutate(st)
			err = st.Validate()
			if err == nil {
				t.Fatalf("accepted %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error does not mention %q: %v", tc.want, err)
			}
		})
	}
}

// TestParseRoundTrip: a statement has to survive the wire, because the whole
// point is that somebody else reads it.
func TestParseRoundTrip(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	back, err := Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if back.Predicate.Counts != st.Predicate.Counts {
		t.Errorf("counts did not round-trip: %+v vs %+v", back.Predicate.Counts, st.Predicate.Counts)
	}
	if !back.Covers("http", "https://mcp.example.com/mcp") {
		t.Error("the parsed statement does not cover its target")
	}

	if _, err := Parse([]byte("{not json")); err == nil {
		t.Error("Parse accepted something that is not JSON")
	}
	if _, err := Parse([]byte(`{"_type":"x"}`)); err == nil {
		t.Error("Parse accepted a statement with no predicate")
	}
}

// TestNoScoreWhenNothingWasAssessed: a run that reached nothing has no
// rating, and publishing 0/100 for it would read as a verdict rather than an
// absence.
func TestNoScoreWhenNothingWasAssessed(t *testing.T) {
	r := sample()
	r.Score = report.Score{Assessed: 0, Of: 6, Grade: "n/a"}
	st, err := From(r)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Score != nil {
		t.Errorf("a run that assessed nothing carried a score: %+v", st.Predicate.Score)
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), `"score"`) {
		t.Error("the absent score still appears in the JSON")
	}
}

// TestStdioTargetIsDistinguished: the two transports do not run the same
// checks, so a statement must say which it is even when the endpoint looks
// like a command rather than a URL.
func TestStdioTargetIsDistinguished(t *testing.T) {
	r := sample()
	r.Target = report.Target{Endpoint: "npx -y server-everything stdio", Scheme: "stdio"}
	st, err := From(r)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Target.Transport != "stdio" {
		t.Errorf("transport = %q", st.Predicate.Target.Transport)
	}
	if !st.Covers("stdio", "npx -y server-everything stdio") {
		t.Error("the digest does not cover the command")
	}
}

func TestFromRefusesNothing(t *testing.T) {
	if _, err := From(nil); err == nil {
		t.Error("From(nil) produced a statement")
	}
	// A report with no transport at all cannot produce a valid statement,
	// and From must refuse rather than emit one that fails Validate later
	// in somebody else's pipeline.
	r := sample()
	r.Target.Scheme = ""
	if _, err := From(r); err == nil {
		t.Error("a report with no scheme produced a statement")
	}
}

// TestMarshalIsIndentedAndNewlineTerminated: an attestation is read by people
// during an incident far more often than anyone expects.
func TestMarshalIsIndentedAndNewlineTerminated(t *testing.T) {
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	b, err := st.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), "\n  \"subject\"") {
		t.Error("not indented")
	}
	if !strings.HasSuffix(string(b), "\n") {
		t.Error("no trailing newline")
	}
	var generic map[string]json.RawMessage
	if err := json.Unmarshal(b, &generic); err != nil {
		t.Fatalf("not valid JSON: %v", err)
	}
	for _, key := range []string{"_type", "subject", "predicateType", "predicate"} {
		if _, ok := generic[key]; !ok {
			t.Errorf("the in-toto envelope is missing %q", key)
		}
	}
}

// TestAServerThatSaidNothing: a run that never completed a handshake has no
// server identity and no negotiated revision, and the statement must be
// honest about that rather than inventing an empty one.
func TestAServerThatSaidNothing(t *testing.T) {
	r := sample()
	r.Server = nil
	st, err := From(r)
	if err != nil {
		t.Fatal(err)
	}
	if st.Predicate.Target.Server != nil {
		t.Errorf("a server identity was invented: %+v", st.Predicate.Target.Server)
	}
	if st.Predicate.JudgedAgainst.SpecRevision != "" {
		t.Errorf("specRevision = %q for a run that negotiated none", st.Predicate.JudgedAgainst.SpecRevision)
	}
	// And it still validates: an unknown revision is a fact, not a defect.
	if err := st.Validate(); err != nil {
		t.Errorf("a statement from an incomplete run was refused: %v", err)
	}
}

// TestAFindingWithNoPhaseOfItsOwn takes the phase from the result that
// contains it. Every finding the engine emits carries one, but a report
// assembled by hand — in a test, or by a consumer building a fixture — may
// not, and losing the phase would break grouping downstream.
func TestAFindingWithNoPhaseOfItsOwn(t *testing.T) {
	r := sample()
	r.Phases[0].Findings[0].Phase = ""
	st, err := From(r)
	if err != nil {
		t.Fatal(err)
	}
	v, err := st.VerdictFor("protocol.ping")
	if err != nil {
		t.Fatal(err)
	}
	if v.Phase != "protocol" {
		t.Errorf("phase = %q, want the containing phase", v.Phase)
	}
}

// TestCoversRefusesAMalformedStatement: Covers is what a gateway calls, so it
// must answer false rather than panic when handed something odd.
func TestCoversRefusesAMalformedStatement(t *testing.T) {
	var empty Statement
	if empty.Covers("http", "https://x/mcp") {
		t.Error("an empty statement claimed to cover a target")
	}
	st, err := From(sample())
	if err != nil {
		t.Fatal(err)
	}
	st.Subject = append(st.Subject, st.Subject[0])
	if st.Covers("http", "https://mcp.example.com/mcp") {
		t.Error("a statement with two subjects claimed to cover a target")
	}
}
