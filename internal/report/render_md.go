// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/termsafe"
)

// mdPrinter writes one formatted fragment of a Markdown report.
type mdPrinter func(format string, a ...any)

// Markdown renders a shareable report. Its fixed text comes from the
// mdMessages catalogue; everything else is the run's own data.
//
// Server text is cleaned of terminal control sequences first, as for Text:
// a Markdown report is printed to a terminal as often as it is opened in a
// viewer, and a control character has no business in either.
func Markdown(w io.Writer, r *Report) {
	r = termsafe.Value(r)
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
	p("## %s\n\n", mdText("telemetry.heading"))
	p(mdText("telemetry.summary")+"\n", t.Requests, t.Errors, humanBytes(t.BytesSent), humanBytes(t.BytesReceived), t.NewConns, fmtMS(t.Wall))
	if len(r.Files) > 0 {
		p("\n%s: %s\n", mdText("telemetry.files"), strings.Join(r.Files, ", "))
	}
}

// mdHeader writes the title and the run's summary table, ending in the score.
func mdHeader(p mdPrinter, r *Report) {
	p("# %s: %s\n\n", mdText("title"), r.Target.Endpoint)
	p("| | |\n|---|---|\n")
	mdRow(p, "summary.passmcp", r.Passmcp.Version)
	mdRow(p, "summary.started", r.Started.Format(time.RFC3339))
	mdRow(p, "summary.duration", fmtMS(r.Duration))
	mdRow(p, "summary.trace", "`"+r.TraceID+"`")
	if r.Server != nil {
		mdRow(p, "summary.server", r.Server.Name+" "+r.Server.Version)
		mdRow(p, "summary.protocol", r.Server.Protocol)
		mdRow(p, "summary.capabilities", strings.Join(r.Server.Capabilities, ", "))
	}
	mdRow(p, "summary.auth", fmt.Sprintf("%s, %s=%t", r.Auth.Mode, mdText("summary.required"), r.Auth.Required))
	if r.Auth.Issuer != "" {
		mdRow(p, "summary.issuer", r.Auth.Issuer)
	}
	score := fmt.Sprintf(mdText("summary.scored"), r.Score.Total, r.Score.Grade, r.Score.Assessed, r.Score.Of)
	if r.Blocked != "" {
		score = fmt.Sprintf(mdText("summary.withheld"), esc(r.Blocked))
	}
	p("| **%s** | %s |\n\n", mdText("summary.score"), score)
}

// mdFailuresAndWarnings lists every failure, then every warning, each with
// its advice when it has any.
func mdFailuresAndWarnings(p mdPrinter, r *Report) {
	if fails := r.Failures(); len(fails) > 0 {
		p("## %s\n\n", mdText("failures.heading"))
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
		p("## %s\n\n", mdText("warnings.heading"))
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
	p("## %s\n\n", mdText("next.heading"))
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
	p("**%s**\n\n", mdText("next.fix"))
	for _, st := range rem.Steps {
		p("1. **%s** — %s\n", esc(st.Title), esc(st.Body))
	}
	p("\n")
	if rem.Note != "" {
		p("> %s\n\n", esc(rem.Note))
	}
	if f.DocURL != "" {
		p("[%s](%s)\n\n", mdText("next.asserts"), f.DocURL)
	}
}

// mdScoreBreakdown writes the per-category score table.
func mdScoreBreakdown(p mdPrinter, r *Report) {
	p("## %s\n\n", mdText("score.heading"))
	mdTableHead(p, "score.category", "score.weight", "score.score", "score.deductions")
	for _, c := range r.Score.Categories {
		if !c.Assessed {
			p("| %s | %d | %s | |\n", c.Name, c.Weight, mdText("score.not_assessed"))
			continue
		}
		p("| %s | %d | %.1f | %s |\n", c.Name, c.Weight, c.Score, strings.ReplaceAll(strings.Join(c.Deductions, "<br>"), "|", "\\|"))
	}
}

// mdStepByStep writes one table per phase that ran, then names the phases
// that did not and why.
func mdStepByStep(p mdPrinter, r *Report) {
	p("\n## %s\n\n", mdText("steps.heading"))
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
		mdTableHead(p, "steps.status", "steps.check", "steps.observed", "steps.evidence")
		for _, f := range ph.Findings {
			p("| %s | %s | %s | %s |\n", string(f.Status), f.Title, esc(joinNonEmpty(f.Detail, adviceMD(f))), esc(strings.Join(f.Evidence, "; ")))
		}
		p("\n")
	}

	if len(skipped) > 0 {
		p(mdText("steps.not_run")+"\n\n", esc(reason), strings.Join(skipped, ", "))
	}
}

// mdCatalog writes the table of tools the server lists.
func mdCatalog(p mdPrinter, r *Report) {
	if len(r.Catalog.Tools) == 0 {
		return
	}
	p("## %s\n\n", mdText("tools.heading"))
	mdTableHead(p, "tools.name", "tools.read_only", "tools.annotated", "tools.output_schema", "tools.required", "tools.description")
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
	p("## %s\n\n", mdText("exec.heading"))
	mdTableHead(p, "exec.tool", "exec.result", "exec.latency", "exec.content", "exec.negative")
	for _, t := range r.Execution.Tools {
		content := strings.Join(t.ContentTypes, "+")
		if t.Structured {
			content += " " + mdText("exec.structured")
		}
		p("| `%s` | %s | %s | %s | %s |\n", t.Name, esc(mdExecResult(t)), fmtMS(t.Duration), content, esc(t.NegativeTest))
	}
	p("\n")
}

// mdExecResult is the one-cell outcome of a tool call.
func mdExecResult(t probe.ToolResult) string {
	res := mdText("exec.skipped") + ": " + t.SkipReason
	switch {
	case t.ProtoError != "":
		res = mdText("exec.protocol_error") + ": " + t.ProtoError
	case t.ToolError != "":
		res = mdText("exec.is_error") + ": " + firstLine(t.ToolError)
	case t.Executed:
		res = mdText("exec.ok")
		if len(t.SchemaIssues) > 0 {
			res = mdText("exec.schema") + ": " + strings.Join(t.SchemaIssues, "; ")
		}
	}
	return res
}

// mdPerformance writes the latency table and, when one ran, the burst.
func mdPerformance(p mdPrinter, r *Report) {
	if r.Perf == nil || len(r.Perf.Tools) == 0 {
		return
	}
	p("## %s\n\n", mdText("perf.heading"))
	mdTableHead(p, "perf.call", "perf.samples", "perf.cold", "perf.p50", "perf.p95", "perf.max")
	if r.Perf.Ping != nil {
		t := r.Perf.Ping
		p("| %s | %d | %s | %s | %s | %s |\n", mdText("perf.ping"), t.Samples-t.Errors, fmtMS(t.Cold), fmtMS(t.P50), fmtMS(t.P95), fmtMS(t.Max))
	}
	for _, t := range r.Perf.Tools {
		p("| `%s` | %d | %s | %s | %s | %s |\n", t.Name, t.Samples-t.Errors, fmtMS(t.Cold), fmtMS(t.P50), fmtMS(t.P95), fmtMS(t.Max))
	}
	if c := r.Perf.Concurrency; c != nil {
		p("\n"+mdText("perf.burst")+"\n", c.Workers, c.Calls/c.Workers, c.Tool, c.OK, c.Errors, c.RateLimited, c.Throughput, fmtMS(c.P50), fmtMS(c.P95))
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
