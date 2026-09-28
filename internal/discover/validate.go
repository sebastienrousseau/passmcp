// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"satellion.com/passmcp-reporting/graph"
	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/engine"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// Validation is the read-only check a discovered endpoint was put through.
type Validation struct {
	// File is where the attestation was written; Digest is the SHA-256 of
	// its bytes, the value the graph records.
	File    string  `json:"attestation_file"`
	Digest  string  `json:"attestation_digest"`
	Score   float64 `json:"score"`
	Grade   string  `json:"grade"`
	Failing int     `json:"failing"`
	// Error is why the check could not produce a report, when it could not.
	Error string `json:"error,omitempty"`

	ranAt   time.Time
	failing []graph.Finding
	tools   []report.ToolSummary
	auth    string
}

// Checker runs the read-only check against one endpoint and returns its
// report. Tests replace it; EngineChecker is the real one.
type Checker func(ctx context.Context, endpoint string) (*report.Report, error)

// EngineChecker is the ordinary passmcp check, with no credentials and the
// default read-only policy (ADR 0004): only tools that declare
// readOnlyHint are ever invoked.
func EngineChecker(version string, rps float64, concurrency int) Checker {
	return func(ctx context.Context, endpoint string) (*report.Report, error) {
		spec := engine.RunSpec{
			Target:  engine.TargetSpec{Endpoint: endpoint},
			Creds:   engine.CredSpec{Mode: string(creds.ModeNone)},
			Pacing:  engine.PacingSpec{RPS: rps, Concurrency: concurrency},
			Output:  engine.OutputSpec{Format: engine.FormatJSON},
			Version: version,
		}
		res := engine.Run(ctx, spec, nil)
		if res.Report == nil {
			if res.Err != nil {
				return nil, res.Err
			}
			return nil, errors.New("the check produced no report")
		}
		return res.Report, nil
	}
}

// Validate checks every endpoint in res and writes an attestation for each
// into dir/attestations. An endpoint whose check fails to produce a report
// keeps the reason; the others are not held up by it.
func Validate(ctx context.Context, res *Result, check Checker, dir string) error {
	adir := filepath.Join(dir, "attestations")
	if err := os.MkdirAll(adir, 0o750); err != nil {
		return err
	}
	for i := range res.Endpoints {
		ep := &res.Endpoints[i]
		rep, err := check(ctx, ep.URL)
		if err != nil {
			ep.Attestation = &Validation{Error: err.Error()}
			continue
		}
		v, err := attestFrom(rep, adir, ep.URL)
		if err != nil {
			ep.Attestation = &Validation{Error: err.Error()}
			continue
		}
		v.auth = authOf(ep, rep)
		ep.Attestation = v
	}
	return nil
}

// attestFrom writes a report's attestation and summarises it.
func attestFrom(rep *report.Report, dir, endpoint string) (*Validation, error) {
	st, err := attest.From(rep)
	if err != nil {
		return nil, err
	}
	b, err := st.Marshal()
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(endpoint))
	file := filepath.Join(dir, hex.EncodeToString(sum[:8])+".json")
	if err := os.WriteFile(file, append(b, '\n'), 0o600); err != nil {
		return nil, err
	}
	v := &Validation{
		File: file, Digest: graph.Digest(append(b, '\n')),
		Score: rep.Score.Total, Grade: rep.Score.Grade,
		ranAt: rep.Started, tools: rep.Catalog.Tools,
	}
	for _, ph := range rep.Phases {
		for _, f := range ph.Findings {
			if f.Status == probe.Fail {
				v.failing = append(v.failing, graph.Finding{ID: f.ID, Severity: string(f.Severity)})
			}
		}
	}
	v.Failing = len(v.failing)
	return v, nil
}

// authOf is how the endpoint admits clients, as the evidence shows it.
func authOf(ep *Endpoint, rep *report.Report) string {
	switch {
	case ep.Exposed:
		return "none"
	case rep != nil && rep.Auth.Required:
		return "oauth"
	default:
		return "unknown"
	}
}

// ApplyGraph records a run in a graph: each endpoint as a server node,
// linked to every source that named it and, when validated, to its
// attestation and its tools. Applying the same result twice leaves the
// graph as it was, because every ID is derived from what the node is.
func ApplyGraph(g *graph.Graph, res *Result) {
	for _, ep := range res.Endpoints {
		sid := graph.ServerID("http", ep.URL)
		srv := &graph.ServerProps{Transport: "http", Endpoint: ep.URL, Name: ep.Server, Version: ep.Version}
		if ep.Exposed {
			srv.Auth = "none"
		}
		v := ep.Attestation
		if v != nil && v.Error == "" {
			score := v.Score
			srv.Score, srv.Grade, srv.Attestation, srv.Failing, srv.Auth = &score, v.Grade, v.Digest, v.failing, v.auth
		}
		g.Upsert(graph.Node{ID: sid, Kind: graph.KindServer, Label: ep.URL, Server: srv})
		for _, s := range ep.Sources {
			src := graph.SourceID(s.Type, s.Ref)
			g.Upsert(graph.Node{ID: src, Kind: graph.KindSource, Label: s.Ref, Source: &graph.SourceProps{Type: s.Type, Ref: s.Ref}})
			g.Link(graph.Edge{From: sid, To: src, Kind: graph.DiscoveredBy})
		}
		if v == nil || v.Error != "" {
			continue
		}
		applyAttestation(g, sid, v)
	}
}

// applyAttestation links a server to its attestation and its tools.
func applyAttestation(g *graph.Graph, sid string, v *Validation) {
	aid := graph.AttestationID(v.Digest)
	g.Upsert(graph.Node{ID: aid, Kind: graph.KindAttestation, Label: filepath.Base(v.File), Attestation: &graph.AttestationProps{
		Digest: v.Digest, PredicateType: attest.PredicateType, RanAt: v.ranAt.UTC().Format(time.RFC3339), File: v.File,
	}})
	g.Link(graph.Edge{From: sid, To: aid, Kind: graph.AttestedBy})
	for _, t := range v.tools {
		tp := &graph.ToolProps{Name: t.Name}
		if t.Annotated {
			ro, de := t.ReadOnly, t.Destructive
			tp.ReadOnlyHint, tp.DestructiveHint = &ro, &de
		}
		tid := graph.ToolID(sid, t.Name)
		g.Upsert(graph.Node{ID: tid, Kind: graph.KindTool, Label: t.Name, Tool: tp})
		g.Link(graph.Edge{From: sid, To: tid, Kind: graph.Exposes})
	}
}

// SaveGraph loads the graph in dir, applies the run and writes it back.
func SaveGraph(dir string, res *Result) error {
	g, err := graph.Load(dir)
	if err != nil {
		return fmt.Errorf("graph: %w", err)
	}
	ApplyGraph(g, res)
	return graph.Save(dir, g)
}
