// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	_ "embed"
	"fmt"
	"html/template"
	"io"
	"sort"
	"strings"
	"time"

	"satellion.com/passmcp/internal/probe"
)

//go:embed report.html.tmpl
var htmlTemplate string

//go:embed report.css
var htmlCSS string

// HTMLOptions tunes the rendering.
type HTMLOptions struct {
	// Verbose includes passing and informational findings, and the
	// evidence references. The default is the short document: what went
	// wrong and what to do about it.
	Verbose bool
}

// htmlView is what the template sees. The report is passed through
// unchanged; everything else is a value the template should not have to
// compute, because a template that computes is a template nobody can read.
type htmlView struct {
	Report       *Report
	CSS          template.CSS
	Verbose      bool
	Verdict      string
	VerdictClass string
	Explain      string
	GradeWord    string
	ScoreTotal   string
	Started      string
	AuthLine     string
	FixFirst     []FixItem
}

// FixItem is a finding with its guidance attached.
//
// The guidance is keyed by check id and identical for every run, so it is
// joined here at render time rather than carried on the Finding — which
// would put the same paragraphs into every JSON report, once per occurrence.
type FixItem struct {
	probe.Finding
	Remediation Remediation
	HasGuidance bool
}

var htmlTmpl = template.Must(template.New("report").Funcs(template.FuncMap{
	"inc":  func(i int) int { return i + 1 },
	"ms":   func(m probe.Millis) string { return fmtMS(m) },
	"join": func(ss []string, sep string) string { return strings.Join(ss, sep) },
	// visible decides which findings a reader sees. The short document
	// carries what needs acting on; the verbose one carries everything,
	// including the evidence that a passing check actually ran.
	"visible": func(fs []probe.Finding, verbose bool) []probe.Finding {
		if verbose {
			return fs
		}
		out := make([]probe.Finding, 0, len(fs))
		for _, f := range fs {
			if f.Status == probe.Fail || f.Status == probe.Warn {
				out = append(out, f)
			}
		}
		return out
	},
}).Parse(htmlTemplate))

// HTML writes the report as one self-contained document.
//
// It is the same document three ways: a file somebody opens offline, the
// page passmcp serve shows in a browser, and — through the print stylesheet —
// the PDF a board reads. One renderer, so the three cannot drift.
//
// Everything in it came from a server nobody vetted, so it is rendered
// through html/template, whose contextual escaping is the reason a tool
// description containing a script tag is text rather than a payload.
func HTML(w io.Writer, r *Report, opts HTMLOptions) error {
	phrase, class := htmlVerdict(r)
	view := htmlView{
		Report: r,
		// #nosec G203 -- htmlCSS is this repository's own stylesheet, embedded
		// at compile time. It is the one string in the document that is not
		// server data, and template.CSS is the correct type for it.
		CSS:          template.CSS(htmlCSS),
		Verbose:      opts.Verbose,
		Verdict:      phrase,
		VerdictClass: class,
		Explain:      explain(r),
		GradeWord:    gradeWord(r.Score),
		ScoreTotal:   fmt.Sprintf("%.0f", r.Score.Total),
		Started:      r.Started.Format(time.RFC1123),
		AuthLine:     htmlAuthLine(r),
		FixFirst:     withGuidance(fixFirst(r)),
	}
	return htmlTmpl.Execute(w, view)
}

// htmlVerdict mirrors the text renderer's verdict, without its lipgloss
// style: the two must always say the same thing about the same report.
func htmlVerdict(r *Report) (string, string) {
	switch {
	case r.Blocked != "":
		return "Couldn't finish the check", "fail"
	case r.Counts.Fail > 0:
		return "Not ready for agents", "fail"
	case r.Counts.Warn > 0:
		return "Ready, with room to improve", "warn"
	default:
		return "Ready for agents", "pass"
	}
}

func htmlAuthLine(r *Report) string {
	switch {
	// A child process has no address, so it is neither open nor protected:
	// whoever can run the command is who can use it.
	case r.Target.Transport == "stdio":
		return "local process"
	case !r.Auth.Reached:
		return "not reached"
	case !r.Auth.Required:
		return "open, no sign-in"
	case r.Auth.Issuer != "":
		return "protected via " + hostOf(r.Auth.Issuer)
	default:
		return "protected"
	}
}

func hostOf(issuer string) string {
	s := strings.TrimPrefix(strings.TrimPrefix(issuer, "https://"), "http://")
	if i := strings.IndexByte(s, '/'); i > 0 {
		s = s[:i]
	}
	return s
}

// fixFirst picks the findings worth acting on, worst first.
//
// A report that lists eighty checks in phase order buries the one thing
// that matters. This is the answer to "what do I do on Monday", and it is
// capped because a list of twenty priorities is not a list of priorities.
// withGuidance attaches the remediation for each finding that has one.
func withGuidance(fs []probe.Finding) []FixItem {
	out := make([]FixItem, 0, len(fs))
	for _, f := range fs {
		rem, ok := RemediationFor(f.ID)
		out = append(out, FixItem{Finding: f, Remediation: rem, HasGuidance: ok})
	}
	return out
}

func fixFirst(r *Report) []probe.Finding {
	const max = 5
	var out []probe.Finding
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.Status == probe.Fail || f.Status == probe.Warn {
				out = append(out, f)
			}
		}
	}
	rank := map[probe.Severity]int{probe.Critical: 0, probe.Major: 1, probe.Minor: 2, probe.Note: 3}
	sort.SliceStable(out, func(i, j int) bool {
		if (out[i].Status == probe.Fail) != (out[j].Status == probe.Fail) {
			return out[i].Status == probe.Fail
		}
		return rank[out[i].Severity] < rank[out[j].Severity]
	})
	if len(out) > max {
		out = out[:max]
	}
	return out
}
