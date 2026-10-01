// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package attest turns a finished report into a signed-able, portable
// statement about one MCP server.
//
// The reason this exists rather than "just use the JSON report" is that the
// report is a document and this is a claim. A document is read by a person; a
// claim is verified by a machine that was not present when the run happened —
// a gateway deciding whether to route to a server, a registry deciding what
// to display, an auditor deciding whether a control was met in March.
//
// It is an in-toto statement, so it slots into a pipeline enterprises are
// already being forced to build: the same envelope as SLSA provenance and an
// SBOM, the same signing, the same verification. Owning a predicate type is
// more durable than owning a product category, because formats outlive both.
//
// Four properties are deliberate, and each is a constraint rather than a
// nice-to-have:
//
//   - It states what it was judged against. A verdict with no basis has no
//     shelf life: "82/100" means nothing in 2029 unless the rubric and the
//     specification revision are attached to it.
//   - The subject digest is over a target descriptor, and the statement says
//     so. A digest that looked like an artifact hash while covering a URL
//     would be the kind of lie that survives review.
//   - It carries the verdict for every check that ran, not only the failures.
//     A consumer cannot otherwise tell "checked and fine" from "not checked",
//     which for a conformance tool is the whole difference.
//   - It verifies offline. A gateway must never have to call passmcp to trust a
//     statement passmcp produced.
//
// The statement types and the verifier live in the public, Apache-2.0
// package satellion.com/passmcp/attestation (ADR 0011), which
// imports only the standard library. This package keeps the one part that
// reads passmcp's own report types — building a statement — and re-exports
// the rest under the names the engine already uses.
package attest

import (
	"fmt"
	"sort"
	"time"

	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// The format identifiers, re-exported from the public package.
const (
	StatementType         = attestation.StatementType
	PredicateType         = attestation.PredicateType
	SubjectKindDescriptor = attestation.SubjectKindDescriptor
)

// Statement is attestation.Statement.
type Statement = attestation.Statement

// Subject is attestation.Subject.
type Subject = attestation.Subject

// Evaluation is attestation.Evaluation.
type Evaluation = attestation.Evaluation

// Target is attestation.Target.
type Target = attestation.Target

// ServerIdentity is attestation.ServerIdentity.
type ServerIdentity = attestation.ServerIdentity

// Basis is attestation.Basis.
type Basis = attestation.Basis

// Instrument is attestation.Instrument.
type Instrument = attestation.Instrument

// Verdict is attestation.Verdict.
type Verdict = attestation.Verdict

// Counts is attestation.Counts.
type Counts = attestation.Counts

// Score is attestation.Score.
type Score = attestation.Score

// ErrNoSuchCheck is attestation.ErrNoSuchCheck.
var ErrNoSuchCheck = attestation.ErrNoSuchCheck

// Plan is attestation.Plan.
type Plan = attestation.Plan

// Parse reads and validates a statement; see attestation.Parse.
func Parse(b []byte) (*Statement, error) { return attestation.Parse(b) }

// From builds a statement from a finished report.
//
// It reads and never writes: the report is the run's output and this is a
// second rendering of it, so a statement can always be regenerated from a
// kept report and compared.
func From(r *report.Report) (*Statement, error) {
	if r == nil {
		return nil, fmt.Errorf("attest: no report")
	}

	t := targetOf(r)
	ev := Evaluation{
		SubjectKind: SubjectKindDescriptor,
		Target:      t,
		JudgedAgainst: Basis{
			SpecRevision:   protocolOf(r),
			Rubric:         report.RubricVersion,
			CheckInventory: report.CheckInventoryVersion,
		},
		Instrument: Instrument{
			Name:          "passmcp",
			Version:       r.Passmcp.Version,
			SchemaVersion: r.Passmcp.SchemaVersion,
		},
		RanAt:   r.Started,
		Took:    time.Duration(r.Duration).Round(time.Millisecond).String(),
		Blocked: r.Blocked,
		TraceID: r.TraceID,
		Plan:    r.Plan,
		Counts: Counts{
			Pass: r.Counts.Pass, Warn: r.Counts.Warn, Fail: r.Counts.Fail,
			Skip: r.Counts.Skip, Info: r.Counts.Info,
		},
		Verdicts: verdictsOf(r),
		Score:    scoreOf(r),
	}

	st := &Statement{
		Type:          StatementType,
		PredicateType: PredicateType,
		Predicate:     ev,
		Subject:       []Subject{attestation.SubjectFor(t)},
	}
	if err := st.Validate(); err != nil {
		return nil, err
	}
	return st, nil
}

// targetOf describes what was judged: the transport, the endpoint, and
// the server's own account of itself when it gave one.
func targetOf(r *report.Report) Target {
	t := Target{
		Transport: transportOf(r),
		Endpoint:  r.Target.Endpoint,
	}
	if r.Server != nil {
		t.Server = &ServerIdentity{
			Name:     r.Server.Name,
			Version:  r.Server.Version,
			Protocol: r.Server.Protocol,
		}
	}
	return t
}

// verdictsOf lists the verdict for every finding in the report.
func verdictsOf(r *report.Report) []Verdict {
	var out []Verdict
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			out = append(out, Verdict{
				ID:       f.ID,
				Phase:    phaseOf(f, p),
				Status:   string(f.Status),
				Severity: string(f.Severity),
				Evidence: f.Evidence,
				Doc:      f.DocURL,
			})
		}
	}
	// Sorted by id, so two statements about the same run are byte-identical
	// and a diff between two runs is a diff about the server.
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// scoreOf is the score the statement carries, or nil.
//
// The score travels only when a category was actually assessed. A run
// that reached nothing has no rating, and publishing 0/100 for it would
// read as a verdict rather than an absence.
func scoreOf(r *report.Report) *Score {
	if r.Score.Assessed <= 0 {
		return nil
	}
	s := &Score{
		Total: r.Score.Total, Grade: r.Score.Grade,
		Assessed: r.Score.Assessed, Of: r.Score.Of,
		By: map[string]float64{},
	}
	for _, c := range r.Score.Categories {
		if c.Assessed {
			s.By[c.Name] = c.Score
		}
	}
	return s
}

// transportOf derives the transport from the report.
//
// It reads the scheme rather than a dedicated field because the report does
// not carry one yet — the stdio work adds Target.Transport, and when that
// lands this becomes a direct read with the scheme as the fallback for a
// statement generated from an older report. Deriving it is not optional: an
// HTTP run and a stdio run do not contain the same checks, so a consumer
// comparing two statements has to be told which kind each one is.
func transportOf(r *report.Report) string {
	switch {
	case r.Target.Scheme == "stdio":
		return "stdio"
	case r.Target.Scheme != "":
		return "http"
	default:
		return ""
	}
}

func protocolOf(r *report.Report) string {
	if r.Server != nil {
		return r.Server.Protocol
	}
	return ""
}

// phaseOf prefers the finding's own phase and falls back to the phase that
// contains it, because a finding assembled by hand in a test may not have one.
func phaseOf(f probe.Finding, p probe.PhaseResult) string {
	if f.Phase != "" {
		return f.Phase
	}
	return p.Name
}
