// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"satellion.com/passmcp/internal/creds"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/internal/telemetry"
)

// explainCurl is the check id --curl reproduces.
var explainCurl string

// maxCurlPerFinding bounds how many requests one finding's evidence can
// expand to. A report is data from wherever it came from, and
// "req#1-999999999" must not become a billion lines.
const maxCurlPerFinding = 50

// evidenceRef matches a finding's citation of recorded requests: req#N or
// req#N-M (ADR-0002).
var evidenceRef = regexp.MustCompile(`req#(\d+)(?:-(\d+))?`)

// curlRepro is one reproducer: a cited request and the command for it.
type curlRepro struct {
	ID     string `json:"id"`
	Status string `json:"status"`
	Seq    int    `json:"seq"`
	Phase  string `json:"phase,omitempty"`
	Label  string `json:"label,omitempty"`
	telemetry.CurlCommand
}

// writeCurlRepro prints a redacted curl command for every recorded
// request the findings with check id cite.
func writeCurlRepro(w io.Writer, rep *report.Report, id string) error {
	findings := findingsWithID(rep, id)
	if len(findings) == 0 {
		return fmt.Errorf("--curl %s: the report has no finding with that check id", id)
	}
	if len(rep.Events) == 0 {
		return errors.New("--curl: the report carries no recorded requests; produce it with `passmcp check --output json --events` (add --capture-bodies to reproduce request bodies), or read report.json from a --report-dir")
	}
	repros, err := curlRepros(findings, rep.Events, curlRedactor())
	if err != nil {
		return err
	}
	if explainOutput == "json" {
		return writeIndentedJSON(w, repros)
	}
	writeCurlText(w, repros)
	return nil
}

// findingsWithID is every finding in the report with the check id.
func findingsWithID(rep *report.Report, id string) []probe.Finding {
	var out []probe.Finding
	for _, p := range rep.Phases {
		for _, f := range p.Findings {
			if f.ID == id {
				out = append(out, f)
			}
		}
	}
	return out
}

// curlRepros builds a reproducer for each distinct request the findings
// cite, in the order they were made.
func curlRepros(findings []probe.Finding, events []telemetry.Event, red *telemetry.Redactor) ([]curlRepro, error) {
	bySeq := make(map[int]telemetry.Event, len(events))
	for _, e := range events {
		bySeq[e.Seq] = e
	}
	var out []curlRepro
	seen := map[int]bool{}
	for _, f := range findings {
		for _, seq := range citedRequests(f.Evidence) {
			e, ok := bySeq[seq]
			if !ok || seen[seq] {
				continue
			}
			seen[seq] = true
			cc, err := telemetry.Curl(e, red)
			if err != nil {
				continue
			}
			out = append(out, curlRepro{ID: f.ID, Status: string(f.Status), Seq: seq, Phase: e.Phase, Label: e.Label, CurlCommand: cc})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--curl %s: the finding cites no recorded HTTP request (its evidence is not a request, the request was a stdio message, or the report dropped it)", findings[0].ID)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// citedRequests are the sequence numbers a finding's evidence cites.
func citedRequests(evidence []string) []int {
	var out []int
	for _, ev := range evidence {
		for _, m := range evidenceRef.FindAllStringSubmatch(ev, -1) {
			from, _ := strconv.Atoi(m[1])
			to := from
			if m[2] != "" {
				to, _ = strconv.Atoi(m[2])
			}
			for seq := from; seq <= to && seq < from+maxCurlPerFinding; seq++ {
				out = append(out, seq)
			}
		}
	}
	return out
}

// curlRedactor is the redactor the reproducer runs through. The report's
// events were redacted when recorded; this is the second pass, and it
// also knows the credentials in this shell's environment, so a report
// that somehow carried one of them does not hand it back.
func curlRedactor() *telemetry.Redactor {
	red := &telemetry.Redactor{}
	for _, name := range []string{creds.EnvToken, creds.EnvClientSecret, creds.EnvBasic} {
		v := os.Getenv(name)
		red.Add(v)
		if _, pass, ok := strings.Cut(v, ":"); ok {
			red.Add(pass)
		}
	}
	return red
}

// writeCurlText prints the reproducers as a script a shell can run.
func writeCurlText(w io.Writer, repros []curlRepro) {
	first := repros[0]
	_, _ = fmt.Fprintf(w, "# passmcp: reproducer for %s (%s)\n", commentSafe(first.ID), commentSafe(first.Status))
	if vars := allVariables(repros); len(vars) > 0 {
		_, _ = fmt.Fprintln(w, "# Credentials are placeholders. Export these before running:")
		for _, v := range vars {
			_, _ = fmt.Fprintf(w, "#   %s\n", v)
		}
		// Masking hides which credential was sent, including a probe's
		// deliberately invalid one; the reader has to be told.
		_, _ = fmt.Fprintln(w, "# Each stands for whatever was masked there: where the check sent a")
		_, _ = fmt.Fprintln(w, "# deliberately invalid or foreign credential, export one of those.")
	}
	for _, r := range repros {
		_, _ = fmt.Fprintf(w, "\n# req#%d %s\n", r.Seq, commentSafe(strings.TrimSpace(r.Phase+" "+r.Label)))
		for _, n := range r.Notes {
			_, _ = fmt.Fprintf(w, "# note: %s\n", commentSafe(n))
		}
		_, _ = fmt.Fprintln(w, r.Command)
	}
}

// allVariables is every placeholder the reproducers use, sorted.
func allVariables(repros []curlRepro) []string {
	set := map[string]bool{}
	for _, r := range repros {
		for _, v := range r.Variables {
			set[v] = true
		}
	}
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// commentSafe keeps text chosen by a server on one comment line: a
// newline in a label would end the comment and make the rest a command.
func commentSafe(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == ' ' || r == ' ' {
			return ' '
		}
		return r
	}, s)
	if r := []rune(s); len(r) > 120 {
		return string(r[:120]) + "…"
	}
	return s
}
