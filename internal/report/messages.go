// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

// mdMessages is the catalogue of fixed text in the Markdown report, keyed
// by a stable message ID. It holds the words; the renderer owns the
// Markdown around them (heading markers, table pipes, emphasis), so a
// second language would replace this map and nothing else.
//
// Only passmcp's own text lives here. Strings that come from the server or
// from findings (titles, details, advice, remediation) do not.
//
// An entry whose value holds formatting verbs is a format string, and the
// renderer passes it exactly the arguments the English text consumes.
// TestMarkdownMessageIDsAreDefined fails when the renderer asks for an ID
// this map does not define, and when an entry is no longer used.
var mdMessages = map[string]string{
	"title": "MCP diagnostic",

	"summary.passmcp":      "Passmcp",
	"summary.started":      "Started",
	"summary.duration":     "Duration",
	"summary.trace":        "Trace",
	"summary.server":       "Server",
	"summary.protocol":     "Protocol",
	"summary.capabilities": "Capabilities",
	"summary.auth":         "Auth",
	"summary.required":     "required",
	"summary.issuer":       "Issuer",
	"summary.score":        "Score",
	"summary.withheld":     "withheld: run stopped (%s)",
	"summary.scored":       "**%.1f / 100 (grade %s)**, %d of %d categories assessed",

	"failures.heading": "Failures",
	"warnings.heading": "Warnings",

	"next.heading":  "What to do next",
	"next.fix":      "How to fix it",
	"next.asserts":  "What this check asserts",
	"score.heading": "Score breakdown",

	"score.category":     "Category",
	"score.weight":       "Weight",
	"score.score":        "Score",
	"score.deductions":   "Deductions",
	"score.not_assessed": "not assessed",

	"steps.heading":  "Step by step",
	"steps.status":   "Status",
	"steps.check":    "Check",
	"steps.observed": "Observed",
	"steps.evidence": "Evidence",
	"steps.not_run":  "Not run (%s): %s",

	"tools.heading":       "Tools",
	"tools.name":          "Name",
	"tools.read_only":     "Read-only",
	"tools.annotated":     "Annotated",
	"tools.output_schema": "outputSchema",
	"tools.required":      "Required args",
	"tools.description":   "Description",

	"exec.heading":        "Execution",
	"exec.tool":           "Tool",
	"exec.result":         "Result",
	"exec.latency":        "Latency",
	"exec.content":        "Content",
	"exec.negative":       "Missing-arg test",
	"exec.structured":     "+structured",
	"exec.skipped":        "skipped",
	"exec.protocol_error": "protocol error",
	"exec.is_error":       "isError",
	"exec.ok":             "ok",
	"exec.schema":         "schema",

	"perf.heading": "Performance",
	"perf.call":    "Call",
	"perf.samples": "Samples",
	"perf.cold":    "Cold",
	"perf.p50":     "p50",
	"perf.p95":     "p95",
	"perf.max":     "Max",
	"perf.ping":    "ping",
	"perf.burst":   "Burst of %d workers × %d calls on `%s`: %d ok, %d errors, %d rate-limited, %.1f calls/s, p50 %s, p95 %s.",

	"telemetry.heading": "Telemetry",
	"telemetry.summary": "%d requests, %d errors, %s sent, %s received, %d new connections, wall %s.",
	"telemetry.files":   "Files",
}

// mdText returns the catalogue text for id. An undefined ID renders as the
// ID itself, visibly wrong rather than blank; the test that parses the
// renderer keeps that from reaching a release.
func mdText(id string) string {
	if s, ok := mdMessages[id]; ok {
		return s
	}
	return id
}

// mdRow writes one label and value row of a two-column table.
func mdRow(p mdPrinter, id, value string) {
	p("| %s | %s |\n", mdText(id), value)
}

// mdTableHead writes a Markdown table's header row and its separator, one
// column per catalogue ID.
func mdTableHead(p mdPrinter, ids ...string) {
	p("|")
	for _, id := range ids {
		p(" %s |", mdText(id))
	}
	p("\n|")
	for range ids {
		p("---|")
	}
	p("\n")
}
