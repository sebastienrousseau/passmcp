// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"sort"
	"time"

	"satellion.com/passmcp-reporting/a2a"
	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/report"
)

// Statement turns a result into an in-toto statement with passmcp-reporting's
// A2A evaluation predicate, so a gateway or registry can verify it offline
// exactly as it verifies an MCP evaluation.
//
// It carries no score: there is no A2A rubric yet, and a number with no
// rubric behind it is one nothing can be compared to. The verdicts and
// their counts are the claim.
func Statement(r *Result, version string) (*a2a.Statement, error) {
	t := a2a.Target{Transport: schemeOf(r.Target), Endpoint: r.Target}
	if r.Agent != (AgentInfo{}) {
		t.Agent = &a2a.AgentIdentity{Name: r.Agent.Name, Version: r.Agent.Version, ProtocolVersion: r.Agent.ProtocolVersion}
	}
	ev := a2a.Evaluation{
		SubjectKind: a2a.SubjectKindDescriptor,
		Target:      t,
		JudgedAgainst: a2a.Basis{
			ProtocolVersion: r.Agent.ProtocolVersion,
			CheckInventory:  report.CheckInventoryVersion,
		},
		Instrument: attestation.Instrument{Name: "passmcp", Version: version, SchemaVersion: report.SchemaVersion},
		RanAt:      r.Started,
		Took:       time.Duration(r.Duration).Round(time.Millisecond).String(),
		Card:       &a2a.Card{URL: r.CardURL, Digest: r.CardDigest, Signed: r.Signed, KeyID: r.KeyID},
	}
	for _, f := range r.Findings {
		ev.Verdicts = append(ev.Verdicts, attestation.Verdict{
			ID: f.ID, Phase: f.Phase, Status: string(f.Status), Severity: string(f.Severity),
			Evidence: f.Evidence, Doc: f.DocURL,
		})
		tally(&ev.Counts, string(f.Status))
	}
	// Sorted by id, as the MCP statement is, so two statements about the
	// same run are byte-identical.
	sort.SliceStable(ev.Verdicts, func(i, j int) bool { return ev.Verdicts[i].ID < ev.Verdicts[j].ID })
	s := &a2a.Statement{
		Type:          attestation.StatementType,
		Subject:       []attestation.Subject{a2a.SubjectFor(t)},
		PredicateType: a2a.PredicateType,
		Predicate:     ev,
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

func schemeOf(endpoint string) string {
	if len(endpoint) >= 5 && endpoint[:5] == "http:" {
		return "http"
	}
	return "https"
}

func tally(c *attestation.Counts, status string) {
	switch status {
	case "pass":
		c.Pass++
	case "warn":
		c.Warn++
	case "fail":
		c.Fail++
	case "skip":
		c.Skip++
	case "info":
		c.Info++
	}
}
