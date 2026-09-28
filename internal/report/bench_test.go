// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	"satellion.com/passmcp/internal/probe"
)

// "Fast" is unfalsifiable, so this measures the one thing passmcp controls
// the whole of: turning a finished report into a document.
//
// A run's wall clock belongs to the server. Roughly fifty requests,
// deliberately throttled, means the time a person waits is almost entirely
// somebody else's latency — which is why there is no benchmark here for a
// run. The render is different: it is passmcp's own work, it happens after
// the network is finished, and it is where an accidental quadratic would
// hide.

// bigReport builds a report the size of a catalogue nobody enjoys
// reviewing: 200 tools, each with a finding.
//
// 200 because that is the size at which the roadmap's own budget is
// stated, and because a report of that size is the one where a regression
// stops being theoretical.
func bigReport(tools int) *Report {
	r := &Report{
		Passmcp:  Meta{Version: "bench", SchemaVersion: SchemaVersion},
		Target:   Target{Endpoint: "https://mcp.example.com/mcp", Host: "mcp.example.com", Scheme: "https"},
		Started:  time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC),
		Duration: probe.Millis(90 * time.Second),
		TraceID:  "bench",
		Auth:     AuthSummary{Mode: "bearer", Reached: true, Required: true},
		Server:   &ServerInfo{Name: "big", Version: "1.0", Protocol: "2026-07-28"},
	}
	cat := probe.PhaseResult{Name: "catalog", Title: "Catalog", Status: probe.Fail}
	exec := probe.PhaseResult{Name: "execution", Title: "Execution", Status: probe.Warn}
	for i := range tools {
		name := fmt.Sprintf("tool_%03d", i)
		cat.Findings = append(cat.Findings, probe.Finding{
			ID: "catalog.tools.descriptions", Title: "Every tool has a useful description",
			Status: probe.Fail, Severity: probe.Major,
			Detail: "under 20 characters: " + name,
			Advice: "write a description an agent can act on",
			// Every string here came from a server nobody vetted, which
			// is what the escaping in the HTML renderer is for and what
			// makes this a realistic input rather than a friendly one.
			Evidence: []string{fmt.Sprintf("req#%d", i), `<script>alert(1)</script>`},
		})
		exec.Findings = append(exec.Findings, probe.Finding{
			ID: "execution.tools", Title: "Tool invocations", Status: probe.Info,
			Detail: name + " returned isError",
		})
	}
	r.Phases = []probe.PhaseResult{cat, exec}
	r.Score = ComputeScore(r.Phases)
	return r
}

func BenchmarkRenderText(b *testing.B) {
	r := bigReport(200)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		Text(io.Discard, r, TextOptions{Width: 100, Verbose: true})
	}
}

func BenchmarkRenderMarkdown(b *testing.B) {
	r := bigReport(200)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		Markdown(io.Discard, r)
	}
}

func BenchmarkRenderHTML(b *testing.B) {
	r := bigReport(200)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := HTML(io.Discard, r, HTMLOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRenderJSON(b *testing.B) {
	r := bigReport(200)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if err := json.NewEncoder(io.Discard).Encode(r); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkComputeScore is the one piece of arithmetic every run does and
// every surface repeats.
func BenchmarkComputeScore(b *testing.B) {
	phases := bigReport(200).Phases
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		_ = ComputeScore(phases)
	}
}
