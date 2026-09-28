// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"satellion.com/passmcp/internal/probe"
)

// mdPrinter writes one formatted fragment of a Markdown report.
type mdPrinter func(format string, a ...any)

// Markdown renders a shareable report.
func Markdown(w io.Writer, r *Report) {
	p := mdPrinter(func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) })
	mdHeader(p, r)
	mdFailuresAndWarnings(p, r)
	mdNextSteps(p, r)
	mdScoreBreakdown(p, r)
	mdStepByStep(p, r)
	mdCatalog(p, r)
	mdExecution(p, r)
	mdPerformance(p, r)
	t := r.Telemetry
	p("## Telemetry\n\n%d requests, %d errors, %s sent, %s received, %d new connections, wall %s.\n", t.Requests, t.Errors, humanBytes(t.BytesSent), humanBytes(t.BytesReceived), t.NewConns, fmtMS(t.Wall))
	if len(r.Files) > 0 {
		p("\nFiles: %s\n", strings.Join(r.Files, ", "))
	}
}

// mdHeader writes the title and the run's summary table, ending in the score.
func mdHeader(p mdPrinter, r *Report) {
	p("# MCP diagnostic: %s\n\n", r.Target.Endpoint)
	p("| | |\n|---|---|\n")
	p("| Passmcp | %s |\n| Started | %s |\n| Duration | %s |\n| Trace | `%s` |\n", r.Passmcp.Version, r.Started.Format(time.RFC3339), fmtMS(r.Duration), r.TraceID)
	if r.Server != nil {
		p("| Server | %s %s |\n| Protocol | %s |\n| Capabilities | %s |\n", r.Server.Name, r.Server.Version, r.Server.Protocol, strings.Join(r.Server.Capabilities, ", "))
	}
	p("| Auth | %s, required=%t |\n", r.Auth.Mode, r.Auth.Required)
	if r.Auth.Issuer != "" {
		p("| Issuer | %s |\n", r.Auth.Issuer)
	}
	if r.Blocked != "" {
		p("| **Score** | withheld: run stopped (%s) |\n\n", esc(r.Blocked))
	} else {
		p("| **Score** | **%.1f / 100 (grade %s)**, %d of %d categories assessed |\n\n", r.Score.Total, r.Score.Grade, r.Score.Assessed, r.Score.Of)
	}
}

// mdFailuresAndWarnings lists every failure, then every warning, each with
// its advice when it has any.
func mdFailuresAndWarnings(p mdPrinter, r *Report) {
	if fails := r.Failures(); len(fails) > 0 {
		p("## Failures\n\n")
		for _, f := range fails {
			p("- **%s** (%s, %s): %s", f.Title, f.Severity, f.Phase, f.Detail)
			if f.Advice != "" {
				p(" — *%s*", f.Advice)
			}
			p("\n")
		}
		p("\n")
	}
	if warns := r.Warnings(); len(warns) > 0 {
		p("## Warnings\n\n")
		for _, f := range warns {
			p("- **%s**: %s", f.Title, f.Detail)
			if f.Advice != "" {
				p(" — *%s*", f.Advice)
			}
			p("\n")
		}
		p("\n")
	}
}

// mdNextSteps writes the numbered list of what to do next, each step with
// its full remediation.
func mdNextSteps(p mdPrinter, r *Report) {
	steps := r.NextSteps()
	if len(steps) == 0 {
		return
	}
	p("## What to do next\n\n")
	for i, f := range steps {
		p("### %d. %s\n\n", i+1, f.Title)
		if d := strings.TrimSpace(f.Detail); d != "" {
			p("%s", esc(upperFirst(d)))
			if f.Advice != "" {
				p(" — %s", esc(f.Advice))
			}
			p("\n\n")
		}
		mdRemediation(p, f)
	}
}

// mdRemediation writes what a finding means and how to fix it.
func mdRemediation(p mdPrinter, f probe.Finding) {
	// The Markdown rendering is the one people paste into a ticket,
	// so it carries the whole explanation rather than a pointer to
	// it. A reader opening that ticket has no passmcp to run.
	rem, ok := RemediationFor(f.ID)
	if !ok {
		return
	}
	p("%s\n\n", esc(rem.Means))
	p("**How to fix it**\n\n")
	for _, st := range rem.Steps {
		p("1. **%s** — %s\n", esc(st.Title), esc(st.Body))
	}
	p("\n")
	if rem.Note != "" {
		p("> %s\n\n", esc(rem.Note))
	}
	if f.DocURL != "" {
		p("[What this check asserts](%s)\n\n", f.DocURL)
	}
}

// mdScoreBreakdown writes the per-category score table.
func mdScoreBreakdown(p mdPrinter, r *Report) {
	p("## Score breakdown\n\n| Category | Weight | Score | Deductions |\n|---|---|---|---|\n")
	for _, c := range r.Score.Categories {
		if !c.Assessed {
			p("| %s | %d | not assessed | |\n", c.Name, c.Weight)
			continue
		}
		p("| %s | %d | %.1f | %s |\n", c.Name, c.Weight, c.Score, strings.ReplaceAll(strings.Join(c.Deductions, "<br>"), "|", "\\|"))
	}
}

// mdStepByStep writes one table per phase that ran, then names the phases
// that did not and why.
func mdStepByStep(p mdPrinter, r *Report) {
	p("\n## Step by step\n\n")
	var skipped []string
	reason := r.Blocked
	for _, ph := range r.Phases {
		if ph.Skipped != "" {
			skipped = append(skipped, ph.Name)
			if reason == "" {
				reason = ph.Skipped
			}
			continue
		}
		p("### %s — %s (%s)\n\n", ph.Title, strings.ToUpper(string(ph.Status)), fmtMS(ph.Duration))
		p("| Status | Check | Observed | Evidence |\n|---|---|---|---|\n")
		for _, f := range ph.Findings {
			p("| %s | %s | %s | %s |\n", string(f.Status), f.Title, esc(joinNonEmpty(f.Detail, adviceMD(f))), esc(strings.Join(f.Evidence, "; ")))
		}
		p("\n")
	}

	if len(skipped) > 0 {
		p("Not run (%s): %s\n\n", esc(reason), strings.Join(skipped, ", "))
	}
}

// mdCatalog writes the table of tools the server lists.
func mdCatalog(p mdPrinter, r *Report) {
	if len(r.Catalog.Tools) == 0 {
		return
	}
	p("## Tools\n\n| Name | Read-only | Annotated | outputSchema | Required args | Description |\n|---|---|---|---|---|---|\n")
	for _, t := range r.Catalog.Tools {
		p("| `%s` | %s | %s | %s | %s | %s |\n", t.Name, yn(t.ReadOnly), yn(t.Annotated), yn(t.OutputSchema), strings.Join(t.Required, ", "), esc(trunc(t.Description, 120)))
	}
	p("\n")
}

// mdExecution writes the table of tool calls and how each went.
func mdExecution(p mdPrinter, r *Report) {
	if len(r.Execution.Tools) == 0 {
		return
	}
	p("## Execution\n\n| Tool | Result | Latency | Content | Missing-arg test |\n|---|---|---|---|---|\n")
	for _, t := range r.Execution.Tools {
		content := strings.Join(t.ContentTypes, "+")
		if t.Structured {
			content += " +structured"
		}
		p("| `%s` | %s | %s | %s | %s |\n", t.Name, esc(mdExecResult(t)), fmtMS(t.Duration), content, esc(t.NegativeTest))
	}
	p("\n")
}

// mdExecResult is the one-cell outcome of a tool call.
func mdExecResult(t probe.ToolResult) string {
	res := "skipped: " + t.SkipReason
	switch {
	case t.ProtoError != "":
		res = "protocol error: " + t.ProtoError
	case t.ToolError != "":
		res = "isError: " + firstLine(t.ToolError)
	case t.Executed:
		res = "ok"
		if len(t.SchemaIssues) > 0 {
			res = "schema: " + strings.Join(t.SchemaIssues, "; ")
		}
	}
	return res
}

// mdPerformance writes the latency table and, when one ran, the burst.
func mdPerformance(p mdPrinter, r *Report) {
	if r.Perf == nil || len(r.Perf.Tools) == 0 {
		return
	}
	p("## Performance\n\n| Call | Samples | Cold | p50 | p95 | Max |\n|---|---|---|---|---|---|\n")
	if r.Perf.Ping != nil {
		t := r.Perf.Ping
		p("| ping | %d | %s | %s | %s | %s |\n", t.Samples-t.Errors, fmtMS(t.Cold), fmtMS(t.P50), fmtMS(t.P95), fmtMS(t.Max))
	}
	for _, t := range r.Perf.Tools {
		p("| `%s` | %d | %s | %s | %s | %s |\n", t.Name, t.Samples-t.Errors, fmtMS(t.Cold), fmtMS(t.P50), fmtMS(t.P95), fmtMS(t.Max))
	}
	if c := r.Perf.Concurrency; c != nil {
		p("\nBurst of %d workers × %d calls on `%s`: %d ok, %d errors, %d rate-limited, %.1f calls/s, p50 %s, p95 %s.\n", c.Workers, c.Calls/c.Workers, c.Tool, c.OK, c.Errors, c.RateLimited, c.Throughput, fmtMS(c.P50), fmtMS(c.P95))
	}
	p("\n")
}

func adviceMD(f probe.Finding) string {
	if f.Advice == "" || (f.Status != probe.Fail && f.Status != probe.Warn) {
		return ""
	}
	return "→ " + f.Advice
}

func esc(s string) string { return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ") }
