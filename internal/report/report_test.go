// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
)

func phases(fs ...probe.Finding) []probe.PhaseResult {
	by := map[string][]probe.Finding{}
	for _, f := range fs {
		by[f.Phase] = append(by[f.Phase], f)
	}
	var out []probe.PhaseResult
	for _, name := range probe.PhaseNames() {
		if fl, ok := by[name]; ok {
			st := probe.Pass
			for _, f := range fl {
				if f.Status == probe.Fail {
					st = probe.Fail
				}
			}
			out = append(out, probe.PhaseResult{Name: name, Title: name, Status: st, Findings: fl})
		}
	}
	return out
}

func TestComputeScore(t *testing.T) {
	sc := ComputeScore(nil)
	if sc.Assessed != 0 || sc.Grade != "n/a" || sc.Total != 0 {
		t.Errorf("empty = %+v", sc)
	}
	ph := phases(
		probe.Finding{Phase: "net", ID: "a", Status: probe.Pass},
		probe.Finding{Phase: "auth", ID: "b", Status: probe.Fail, Severity: probe.Critical, Detail: "bad"},
		probe.Finding{Phase: "protocol", ID: "c", Status: probe.Warn, Detail: "meh"},
		probe.Finding{Phase: "protocol", ID: "d", Status: probe.Fail, Severity: probe.Major},
	)
	sc = ComputeScore(ph)
	if sc.Assessed != 3 {
		t.Errorf("assessed = %d", sc.Assessed)
	}
	by := map[string]Category{}
	for _, c := range sc.Categories {
		by[c.Name] = c
	}
	if by["connectivity"].Score != 100 || by["authorization"].Score != 0 || by["protocol"].Score != 55 {
		t.Errorf("categories = %+v", by)
	}
	if by["catalog"].Assessed {
		t.Error("catalog should not be assessed")
	}
	// weighted: (100*10 + 0*20 + 55*20) / 50 = 42
	if sc.Total != 42 || sc.Grade != "D" {
		t.Errorf("total = %v grade %s", sc.Total, sc.Grade)
	}
	if len(by["authorization"].Deductions) != 1 || !strings.Contains(by["authorization"].Deductions[0], "-100 b: bad") {
		t.Errorf("deductions = %v", by["authorization"].Deductions)
	}
}

func TestRenderersDoNotPanicAndMentionScore(t *testing.T) {
	r := &Report{Passmcp: Meta{Version: "t"}, Target: Target{Endpoint: "https://x/mcp"}, Started: time.Now(), TraceID: "abc",
		Server:    &ServerInfo{Name: "s", Version: "1", Protocol: "2025-11-25", Capabilities: []string{"tools"}},
		Phases:    phases(probe.Finding{Phase: "net", ID: "net.tls", Title: "TLS", Status: probe.Fail, Severity: probe.Critical, Detail: "expired", Advice: "renew", Evidence: []string{"req#1"}}),
		Catalog:   Catalog{Tools: []ToolSummary{{Name: "t1", Description: "d", ReadOnly: true, Required: []string{"q"}}}},
		Execution: Execution{Tools: []probe.ToolResult{{Name: "t1", Executed: true, OK: true, Duration: probe.Millis(time.Millisecond), ContentTypes: []string{"text"}, SchemaIssues: []string{"$.x: bad"}, NegativeTest: "ACCEPTED without required q"}}},
		Perf:      &probe.PerfResult{Ping: &probe.ToolPerf{Name: "ping", Samples: 3}, Tools: []probe.ToolPerf{{Name: "t1", Samples: 3, P50: probe.Millis(time.Millisecond)}}, Concurrency: &probe.ConcurrencyResult{Tool: "t1", Workers: 2, Calls: 4, OK: 4}},
	}
	r.Score = ComputeScore(r.Phases)
	var txt, md bytes.Buffer
	Text(&txt, r, TextOptions{Verbose: true})
	Markdown(&md, r)
	for _, out := range []string{txt.String(), md.String()} {
		for _, want := range []string{"expired", "renew", "t1", "$.x: bad", "req#1"} {
			if !strings.Contains(out, want) {
				t.Errorf("output lacks %q:\n%s", want, out)
			}
		}
	}
	if !strings.Contains(md.String(), "## Failures") {
		t.Error("markdown lacks failures section")
	}
	b, err := json.Marshal(r)
	if err != nil || !strings.Contains(string(b), `"grade"`) {
		t.Errorf("json: %v", err)
	}
	if got := r.Failures(); len(got) != 1 || got[0].ID != "net.tls" {
		t.Errorf("failures = %+v", got)
	}
}
