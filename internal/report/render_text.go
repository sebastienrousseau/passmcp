// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/muesli/termenv"
	"satellion.com/passmcp/internal/probe"
)

// TextOptions tune the terminal rendering.
type TextOptions struct {
	Color   bool
	Verbose bool // include the per-check detail and evidence references
	// Width is the column budget; 0 means 84.
	Width int
	// NoHeader omits the endpoint/server lines when the caller shows them.
	NoHeader bool
}

var (
	accent    = lipgloss.Color("#F56B5E")
	okColor   = lipgloss.Color("42")
	warnCol   = lipgloss.Color("214")
	failCol   = lipgloss.Color("203")
	okStyle   = lipgloss.NewStyle().Foreground(okColor)
	warnStyle = lipgloss.NewStyle().Foreground(warnCol)
	failStyle = lipgloss.NewStyle().Foreground(failCol)
	skipStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	infoStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
	headStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("252"))
	accentBld = lipgloss.NewStyle().Bold(true).Foreground(accent)
	boldStyle = lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255"))
	textStyle = lipgloss.NewStyle().Foreground(lipgloss.Color("252"))
	dimStyle  = lipgloss.NewStyle().Foreground(lipgloss.Color("244"))
)

func mark(st probe.Status, color bool) string {
	label := map[probe.Status]string{probe.Pass: "ok  ", probe.Warn: "warn", probe.Fail: "fail", probe.Skip: "skip", probe.Info: "info"}[st]
	if !color {
		return label
	}
	switch st {
	case probe.Pass:
		return okStyle.Render(label)
	case probe.Warn:
		return warnStyle.Render(label)
	case probe.Fail:
		return failStyle.Render(label)
	case probe.Skip:
		return skipStyle.Render(label)
	}
	return infoStyle.Render(label)
}

// Text renders the report to the terminal's scrollback: a plain-language
// verdict and what to improve first, for anyone; then the score and, with
// --verbose, the full per-check detail, for developers.
func Text(w io.Writer, r *Report, o TextOptions) {
	if o.Color {
		lipgloss.SetColorProfile(termenv.TrueColor)
	}
	width := o.Width
	if width <= 0 {
		width = 84
	}
	st := func(s lipgloss.Style, text string) string {
		if o.Color {
			return s.Render(text)
		}
		return text
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	section := func(title string) { p("\n%s\n", st(accentBld, title)) }

	// who we tested
	if !o.NoHeader {
		p("\n  %s\n", st(boldStyle, r.Target.Endpoint))
		p("  %s\n", st(dimStyle, serverLine(r)))
	}

	textVerdict(p, st, r, width)
	if r.Blocked != "" {
		if fix := firstAdvice(r); fix != "" {
			p("\n  %s %s\n", st(accentBld, "Try this"), wrapHang(fix, width-12, "           "))
		}
		writeFiles(p, st, r)
		return
	}

	textImprove(p, st, section, r, width, o)
	textScores(p, st, section, r, o)

	// the detail, for developers
	if o.Verbose {
		writeDetail(p, st, section, r, width, o)
	} else {
		section("More")
		p("  %s\n", st(dimStyle, "Re-run with --verbose for the per-check detail, or --report-dir DIR"))
		p("  %s\n", st(dimStyle, "to save the full report and request-by-request telemetry."))
	}

	// footer
	t := r.Telemetry
	if t.Requests > 0 {
		p("\n  %s\n", st(dimStyle, fmt.Sprintf("%d requests · %d errors · %s in · %s out · %s",
			t.Requests, t.Errors, humanBytes(t.BytesReceived), humanBytes(t.BytesSent), fmtMS(r.Duration))))
	}
	writeFiles(p, st, r)
}

// textVerdict writes the verdict in one sentence, with the score beside it
// when the run was not blocked, and the plain-language explanation.
func textVerdict(p textPrinter, st styler, r *Report, width int) {
	// the verdict, in one sentence
	phrase, style := verdict(r)
	p("\n  %s", st(style, phrase))
	if r.Blocked == "" {
		p("   %s   %s\n", st(dimStyle, fmt.Sprintf("%.0f / 100", r.Score.Total)), st(dimStyle, gradeWord(r.Score)))
	} else {
		p("\n")
	}
	p("\n%s\n", wrapIndent(explain(r), width-4, "  "))
}

// textImprove writes the numbered next steps, or says there are none.
func textImprove(p textPrinter, st styler, section func(string), r *Report, width int, o TextOptions) {
	// what to improve
	steps := r.NextSteps()
	section("What to improve")
	if len(steps) == 0 {
		p("  %s\n", st(dimStyle, "Nothing. Every check passed."))
		return
	}
	for i, f := range steps {
		p("%s  %s\n", st(accentBld, fmt.Sprintf("  %d", i+1)), st(boldStyle, sentence(f.Title)))
		if strings.TrimSpace(f.Detail) != "" {
			p("%s\n", wrapIndent(upperFirst(strings.TrimSpace(f.Detail)), width-6, "     "))
		}
		if f.Advice != "" {
			p("     %s %s\n", st(dimStyle, "→"), st(textStyle, wrapHang(f.Advice, width-8, "       ")))
		}
		// The full explanation is behind --verbose on purpose. The
		// default output is read while the run is still fresh, by
		// somebody who wants to know what is wrong; five findings with
		// three steps each is sixty lines of terminal for a reader who
		// has not asked for it. --output md and the HTML report carry
		// it unconditionally, because those are the ones forwarded to
		// people who cannot re-run the tool.
		if o.Verbose {
			textRemediation(p, st, f.ID, width)
		}
		if i < len(steps)-1 {
			p("\n")
		}
	}
}

// textRemediation writes what a finding means and how to fix it, when the
// catalogue has an entry for it.
func textRemediation(p textPrinter, st styler, id string, width int) {
	rem, ok := RemediationFor(id)
	if !ok {
		return
	}
	p("\n%s\n", st(dimStyle, "     What it means"))
	p("%s\n", wrapIndent(rem.Means, width-6, "     "))
	p("\n%s\n", st(dimStyle, "     How to fix it"))
	for n, step := range rem.Steps {
		p("     %s %s\n", st(accentBld, fmt.Sprintf("%d.", n+1)), st(boldStyle, step.Title))
		p("%s\n", wrapIndent(step.Body, width-9, "        "))
	}
	if rem.Note != "" {
		p("\n%s\n", wrapIndent(rem.Note, width-6, "     "))
	}
}

// textScores writes one line per scored category and how many were tested.
func textScores(p textPrinter, st styler, section func(string), r *Report, o TextOptions) {
	// how it scores
	section("How it scores")
	nameW := 0
	for _, c := range r.Score.Categories {
		if len(c.Name) > nameW {
			nameW = len(c.Name)
		}
	}
	for _, c := range r.Score.Categories {
		if !c.Assessed {
			p("  %-*s   %s\n", nameW, c.Name, st(skipStyle, "not tested"))
			continue
		}
		p("  %-*s   %s   %s\n", nameW, c.Name, dots(c.Score, o.Color), st(scoreStyle(c.Score), fmt.Sprintf("%3.0f", c.Score)))
	}
	p("  %s\n", st(dimStyle, fmt.Sprintf("%d of %d areas tested", r.Score.Assessed, r.Score.Of)))
}

func writeFiles(p func(string, ...any), st func(lipgloss.Style, string) string, r *Report) {
	for _, f := range r.Files {
		p("  %s\n", st(dimStyle, "saved "+f))
	}
}

func verdict(r *Report) (string, lipgloss.Style) {
	switch {
	case r.Blocked != "":
		return "Couldn't finish the check", failStyle.Bold(true)
	case r.Counts.Fail > 0:
		return "Not ready for agents", failStyle.Bold(true)
	case r.Counts.Warn > 0:
		return "Ready, with room to improve", warnStyle.Bold(true)
	default:
		return "Ready for agents", okStyle.Bold(true)
	}
}

func gradeWord(s Score) string {
	switch {
	case s.Total >= 90:
		return "Excellent"
	case s.Total >= 75:
		return "Good"
	case s.Total >= 60:
		return "Fair"
	case s.Total >= 40:
		return "Needs work"
	default:
		return "At risk"
	}
}

func explain(r *Report) string {
	if r.Blocked != "" {
		ran := 0
		for _, ph := range r.Phases {
			if ph.Skipped == "" {
				ran++
			}
		}
		return fmt.Sprintf("%s. passmcp got through %d of %d phases before stopping. Fix the problem below and run it again.",
			upperFirst(r.Blocked), ran, len(r.Phases))
	}
	fail, warn := r.Counts.Fail, r.Counts.Warn
	switch {
	case fail > 0 && warn > 0:
		return fmt.Sprintf("An agent will hit %s here, and there %s %s worth fixing before you roll this server out to your fleet.",
			count(fail, "problem"), plural(warn, "is", "are"), count(warn, "smaller thing"))
	case fail > 0:
		return fmt.Sprintf("An agent will hit %s here. Fix %s before you roll this server out to your fleet.",
			count(fail, "problem"), plural(fail, "it", "them"))
	case warn > 0:
		return fmt.Sprintf("Agents can connect to this server and use its tools. %s worth improving, but none of them blocks adoption.",
			upperFirst(count(warn, "thing"))+plural(warn, " is", " are"))
	default:
		return "Agents can connect to this server and use its tools. Nothing needs your attention."
	}
}

func firstAdvice(r *Report) string {
	for _, f := range append(r.Failures(), r.Warnings()...) {
		if f.Advice != "" {
			return f.Advice
		}
	}
	return ""
}

func dots(score float64, color bool) string {
	filled := int(score/20 + 0.5)
	if filled > 5 {
		filled = 5
	}
	if filled < 0 {
		filled = 0
	}
	full := strings.Repeat("●", filled)
	empty := strings.Repeat("○", 5-filled)
	if !color {
		return full + empty
	}
	return scoreStyle(score).Render(full) + skipStyle.Render(empty)
}

func scoreStyle(score float64) lipgloss.Style {
	switch {
	case score >= 90:
		return okStyle
	case score >= 60:
		return warnStyle
	default:
		return failStyle
	}
}

func serverLine(r *Report) string {
	if r.Server != nil {
		// "open, no sign-in" is a statement about who can reach the server,
		// and over a pipe nobody can: it has no address. Saying it anyway
		// would read as a reassurance passmcp never established.
		auth := "open, no sign-in"
		switch {
		case r.Target.Transport == "stdio":
			auth = "local process"
		case r.Auth.Required:
			auth = "requires sign-in"
		}
		return fmt.Sprintf("%s %s · MCP %s · %s", r.Server.Name, r.Server.Version, r.Server.Protocol, auth)
	}
	if !r.Auth.Reached {
		return "not reached"
	}
	return "MCP server"
}

// textPrinter and styler are the two closures Text threads through its
// sections: one writes a formatted fragment, the other applies a style only
// when colour is on.
type (
	textPrinter = func(string, ...any)
	styler      = func(lipgloss.Style, string) string
)

func writeDetail(p textPrinter, st styler, section func(string), r *Report, width int, o TextOptions) {
	section("Checks in detail")
	for _, ph := range r.Phases {
		if ph.Skipped != "" {
			p("  %s  %s  %s\n", mark(probe.Skip, o.Color), st(headStyle, ph.Title), st(dimStyle, "not run: "+ph.Skipped))
			continue
		}
		p("\n  %s  %s  %s\n", mark(ph.Status, o.Color), st(headStyle, ph.Title), st(dimStyle, "["+fmtMS(ph.Duration)+"]"))
		for _, f := range ph.Findings {
			writeDetailFinding(p, st, f, width, o)
		}
	}

	if len(r.Catalog.Tools) > 0 {
		section("Tools")
		p("  %-34s %-6s %-6s %-6s %s\n", "name", "ro", "annot", "outsch", "required args")
		for _, t := range r.Catalog.Tools {
			p("  %-34s %-6s %-6s %-6s %s\n", trunc(t.Name, 34), yn(t.ReadOnly), yn(t.Annotated), yn(t.OutputSchema), strings.Join(t.Required, ","))
		}
	}
	if len(r.Execution.Tools) > 0 || len(r.Execution.Resources) > 0 || len(r.Execution.Prompts) > 0 {
		section("What ran")
		writeDetailExecution(p, r, o)
	}
	if r.Perf != nil && (r.Perf.Ping != nil || len(r.Perf.Tools) > 0) {
		section("Speed")
		writeDetailSpeed(p, st, r)
	}

	if r.Auth.Reached && (r.Auth.Required || r.Auth.Token != nil) {
		section("Sign-in")
		writeDetailSignIn(p, st, r)
	}
}

// writeDetailFinding writes one check: its mark and title, a short detail
// for checks that passed, and the full detail and advice for ones that did
// not.
func writeDetailFinding(p textPrinter, st styler, f probe.Finding, width int, o TextOptions) {
	p("      %s  %s", mark(f.Status, o.Color), f.Title)
	if f.Detail != "" && (f.Status == probe.Pass || f.Status == probe.Info || f.Status == probe.Skip) {
		p("%s", st(dimStyle, ": "+trunc(f.Detail, width-len(f.Title)-14)))
	}
	p("\n")
	if f.Status == probe.Fail || f.Status == probe.Warn {
		if f.Detail != "" {
			p("%s\n", wrapIndent(f.Detail, width-12, "            "))
		}
		if f.Advice != "" {
			p("            %s %s\n", st(dimStyle, "→"), wrapHang(f.Advice, width-16, "              "))
		}
	}
	if o.Verbose && len(f.Evidence) > 0 {
		p("            %s\n", st(dimStyle, "evidence: "+strings.Join(f.Evidence, "; ")))
	}
}

// writeDetailExecution writes one line per tool call, resource read and
// prompt fetch.
func writeDetailExecution(p textPrinter, r *Report, o TextOptions) {
	for _, t := range r.Execution.Tools {
		writeDetailTool(p, t, o)
	}
	for _, rr := range r.Execution.Resources {
		status := probe.Pass
		if !rr.OK {
			status = probe.Fail
		}
		p("  %s  resource %-40s %s %s\n", mark(status, o.Color), trunc(rr.URI, 40), fmtMS(rr.Duration), rr.Error)
	}
	for _, pr := range r.Execution.Prompts {
		status := probe.Pass
		if !pr.OK {
			status = probe.Fail
		}
		p("  %s  prompt   %-40s %s %s\n", mark(status, o.Color), trunc(pr.Name, 40), fmtMS(pr.Duration), pr.Error)
	}
}

// writeDetailTool writes how one tool call went, with any schema issues
// beneath it.
func writeDetailTool(p textPrinter, t probe.ToolResult, o TextOptions) {
	switch {
	case !t.Executed:
		p("  %s  %-30s %s\n", mark(probe.Skip, o.Color), trunc(t.Name, 30), t.SkipReason)
	case t.ProtoError != "":
		p("  %s  %-30s %s (%s)\n", mark(probe.Fail, o.Color), trunc(t.Name, 30), t.ProtoError, fmtMS(t.Duration))
	case t.ToolError != "":
		p("  %s  %-30s error: %s (%s)\n", mark(probe.Warn, o.Color), trunc(t.Name, 30), firstLine(t.ToolError), fmtMS(t.Duration))
	default:
		status := probe.Pass
		if len(t.SchemaIssues) > 0 {
			status = probe.Fail
		}
		p("  %s  %-30s %s\n", mark(status, o.Color), trunc(t.Name, 30), fmtMS(t.Duration))
		for _, is := range t.SchemaIssues {
			p("        schema: %s\n", is)
		}
	}
}

// writeDetailSpeed writes the latency table, slowest tool first.
func writeDetailSpeed(p textPrinter, st styler, r *Report) {
	p("  %-30s %9s %9s %9s\n", "call", "p50", "p95", "max")
	if r.Perf.Ping != nil {
		t := r.Perf.Ping
		p("  %-30s %9s %9s %9s\n", "ping", fmtMS(t.P50), fmtMS(t.P95), fmtMS(t.Max))
	}
	tools := append([]probe.ToolPerf(nil), r.Perf.Tools...)
	sort.Slice(tools, func(i, j int) bool { return tools[i].P95 > tools[j].P95 })
	for _, t := range tools {
		flag := ""
		if t.P95.Duration() > 2*time.Second {
			flag = st(warnStyle, "  slow")
		}
		p("  %-30s %9s %9s %9s%s\n", trunc(t.Name, 30), fmtMS(t.P50), fmtMS(t.P95), fmtMS(t.Max), flag)
	}
}

// writeDetailSignIn writes the issuer and the token's type and expiry.
func writeDetailSignIn(p textPrinter, st styler, r *Report) {
	if r.Auth.Issuer != "" {
		p("  %s\n", st(dimStyle, "issuer "+r.Auth.Issuer))
	}
	if t := r.Auth.Token; t != nil {
		exp := "no expiry given"
		if !t.Expiry.IsZero() {
			exp = "expires in " + time.Until(t.Expiry).Round(time.Second).String()
		}
		p("  %s\n", st(dimStyle, fmt.Sprintf("token %s · %s", nonEmpty(t.Type, "bearer"), exp)))
	}
}

func count(n int, noun string) string {
	if n == 1 {
		return "one " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	return strings.ToUpper(string(r[0])) + string(r[1:])
}

func sentence(s string) string { return upperFirst(strings.TrimSpace(s)) }

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

// wrapIndent folds text to width and prefixes every line with indent.
func wrapIndent(s string, width int, indent string) string {
	if width < 20 {
		width = 20
	}
	var lines []string
	line := ""
	for _, word := range strings.Fields(s) {
		switch {
		case line == "":
			line = word
		case len(line)+1+len(word) > width:
			lines = append(lines, line)
			line = word
		default:
			line += " " + word
		}
	}
	if line != "" {
		lines = append(lines, line)
	}
	for i := range lines {
		lines[i] = indent + lines[i]
	}
	return strings.Join(lines, "\n")
}

// wrapHang wraps text to width; the first line has no indent (the caller
// printed a marker before it) and continuation lines get indent.
func wrapHang(s string, width int, indent string) string {
	return strings.TrimPrefix(wrapIndent(s, width, indent), indent)
}

func yn(b bool) string {
	if b {
		return "yes"
	}
	return "-"
}

func trunc(s string, n int) string {
	if n < 4 {
		n = 4
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

func firstLine(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

func humanBytes(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}
