// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package enrich writes plain-language explanations beside a finished
// report. It annotates and never adjudicates: every verdict, severity and
// check id in its output is copied from the report, and nothing a model says
// can change one. The report itself is only ever read.
//
// The model is optional. Without one, the document is still complete — each
// finding with passmcp's own remediation — and says why there is nothing more,
// so an operator who will not send findings anywhere loses nothing but the
// prose.
package enrich

import (
	"context"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// MaxItems bounds what one request carries. A report with more failing
// findings than this is usually one problem seen many times, and the
// explanation of the first forty is the explanation of the rest.
const MaxItems = 40

// maxDetail and maxAnswer bound text in both directions: finding details
// were written from server responses, and a model's answer is as untrusted
// as the server's.
const (
	maxDetail = 500
	maxAnswer = 2000
)

// Item is one finding as it leaves the machine: what a model needs to
// explain it and nothing more. Evidence references, telemetry, the
// authentication summary and the target's credentials are not in it.
type Item struct {
	ID       string        `json:"id"`
	Title    string        `json:"title"`
	Status   string        `json:"status"`
	Severity string        `json:"severity,omitempty"`
	Detail   string        `json:"detail,omitempty"`
	Means    string        `json:"means,omitempty"`
	Steps    []report.Step `json:"steps,omitempty"`
}

// Explanation is what a model says about one finding.
type Explanation struct {
	ID          string `json:"id"`
	Explanation string `json:"explanation"`
	Fix         string `json:"fix"`
}

// Model explains findings. An implementation must treat the items as data:
// their details came from the server under test.
type Model interface {
	Name() string
	Explain(ctx context.Context, items []Item) ([]Explanation, error)
}

// Items selects the findings worth explaining — failures, then warnings,
// most severe first — up to MaxItems, and reports how many were left out.
func Items(r *report.Report) (items []Item, omitted int) {
	var fs []probe.Finding
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.Status == probe.Fail || f.Status == probe.Warn {
				fs = append(fs, f)
			}
		}
	}
	sort.SliceStable(fs, func(i, j int) bool {
		if fs[i].Status != fs[j].Status {
			return fs[i].Status == probe.Fail
		}
		return rank(fs[i].Severity) < rank(fs[j].Severity)
	})
	if len(fs) > MaxItems {
		omitted = len(fs) - MaxItems
		fs = fs[:MaxItems]
	}
	for _, f := range fs {
		it := Item{ID: f.ID, Title: f.Title, Status: string(f.Status), Severity: string(f.Severity), Detail: bound(f.Detail, maxDetail)}
		if g, ok := report.RemediationFor(f.ID); ok {
			it.Means, it.Steps = g.Means, g.Steps
		}
		items = append(items, it)
	}
	return items, omitted
}

func rank(s probe.Severity) int {
	switch s {
	case probe.Critical:
		return 0
	case probe.Major:
		return 1
	case probe.Minor:
		return 2
	}
	return 3
}

// bound cuts s to n runes on a rune boundary.
func bound(s string, n int) string {
	s = strings.TrimSpace(s)
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// Document is the side-car: the report's verdicts, each with passmcp's
// guidance and, when a model answered, its explanation.
type Document struct {
	Endpoint string    `json:"endpoint"`
	RanAt    time.Time `json:"ranAt"`
	// Model names what wrote the explanations, or is empty when nothing did.
	Model string `json:"model,omitempty"`
	// Unavailable says why there are no explanations, when there are none.
	Unavailable string `json:"unavailable,omitempty"`
	// Omitted counts failing findings beyond MaxItems.
	Omitted  int     `json:"omitted,omitempty"`
	Findings []Entry `json:"findings"`
}

// Entry is one finding in the document.
type Entry struct {
	Item
	Explanation string `json:"explanation,omitempty"`
	Fix         string `json:"fix,omitempty"`
}

// Build explains r with m. A nil model, or one that fails, still gives a
// complete document; why is in Unavailable, and unavailable is the reason
// passed for a nil model.
func Build(ctx context.Context, r *report.Report, m Model, unavailable string) Document {
	items, omitted := Items(r)
	d := Document{Endpoint: r.Target.Endpoint, RanAt: r.Started, Omitted: omitted, Findings: make([]Entry, 0, len(items))}
	for _, it := range items {
		d.Findings = append(d.Findings, Entry{Item: it})
	}
	switch {
	case len(items) == 0:
		return d
	case m == nil:
		d.Unavailable = unavailable
		return d
	}
	answers, err := m.Explain(ctx, items)
	if err != nil {
		d.Unavailable = bound("the model could not be reached: "+err.Error(), 300)
		return d
	}
	d.Model = m.Name()
	byID := map[string]Explanation{}
	for _, a := range answers {
		byID[a.ID] = a
	}
	answered := 0
	for i := range d.Findings {
		// Only ids that were asked about are taken. The status and
		// severity stay the report's whatever the answer says.
		if a, ok := byID[d.Findings[i].ID]; ok {
			d.Findings[i].Explanation = bound(a.Explanation, maxAnswer)
			d.Findings[i].Fix = bound(a.Fix, maxAnswer)
			answered++
		}
	}
	if answered == 0 {
		d.Model = ""
		d.Unavailable = "the model answered, but about none of the findings it was asked about"
	}
	return d
}

// Markdown renders the document for a reader.
func (d Document) Markdown(w io.Writer) error {
	var b strings.Builder
	p := func(format string, a ...any) { fmt.Fprintf(&b, format, a...) }
	p("# Explanations for %s\n\n", d.Endpoint)
	p("Run of %s. Nothing here changes a verdict: statuses, severities and check ids are the report's.", d.RanAt.UTC().Format("2006-01-02 15:04 UTC"))
	switch {
	case d.Model != "":
		p(" Explanations are by %s and are marked as such; passmcp's own guidance is beside them.\n\n", d.Model)
	case d.Unavailable != "":
		p("\n\n> No explanations: %s. passmcp's own guidance for each finding follows.\n\n", d.Unavailable)
	default:
		p("\n\n")
	}
	if len(d.Findings) == 0 {
		p("Nothing failed or warned, so there is nothing to explain.\n")
	}
	for _, e := range d.Findings {
		sev := ""
		if e.Severity != "" {
			sev = ", " + e.Severity
		}
		p("## `%s` (%s%s)\n\n%s", e.ID, e.Status, sev, e.Title)
		if e.Detail != "" {
			p(": %s", e.Detail)
		}
		p("\n\n")
		if e.Explanation != "" {
			p("**%s:** %s\n\n", d.Model, e.Explanation)
			if e.Fix != "" {
				p("**Fix, per %s:** %s\n\n", d.Model, e.Fix)
			}
		}
		if e.Means != "" {
			p("**passmcp:** %s\n\n", e.Means)
		}
		for _, s := range e.Steps {
			p("- **%s.** %s\n", s.Title, s.Body)
		}
		if len(e.Steps) > 0 {
			p("\n")
		}
	}
	if d.Omitted > 0 {
		p("%d more failing or warning findings were not sent; they are in the report.\n", d.Omitted)
	}
	_, err := io.WriteString(w, b.String())
	return err
}
