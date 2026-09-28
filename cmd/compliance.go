// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/spec/controls"
)

var (
	verifyFramework string

	evidenceFramework string
	evidenceFrom      string
	evidenceTo        string
	evidenceOutDir    string
	evidenceReports   []string
)

// frameworkResult is what `passmcp verify --framework` adds to a
// verification: every criterion of the framework, judged from the
// statement's verdicts alone.
type frameworkResult struct {
	Framework controls.Framework    `json:"framework"`
	Name      string                `json:"name"`
	Version   string                `json:"version"`
	Criteria  []controls.Assessment `json:"criteria"`
}

// assessFramework fills v.Framework when --framework was given. It reads
// the statement and the embedded mapping and nothing else: verify is an
// offline command, and so is what it says about a framework.
func assessFramework(st *attest.Statement, v *verification) error {
	if strings.TrimSpace(verifyFramework) == "" {
		return nil
	}
	f, err := controls.ParseFramework(verifyFramework)
	if err != nil {
		return err
	}
	m, err := controls.Load(f)
	if err != nil {
		return err
	}
	v.Framework = &frameworkResult{Framework: f, Name: m.Name, Version: m.Version, Criteria: m.Assess(verdictsOf(st))}
	return nil
}

func verdictsOf(st *attest.Statement) []controls.Verdict {
	out := make([]controls.Verdict, 0, len(st.Predicate.Verdicts))
	for _, v := range st.Predicate.Verdicts {
		out = append(out, controls.Verdict{ID: v.ID, Status: v.Status, Evidence: v.Evidence})
	}
	return out
}

// writeFramework prints the criteria a statement bears on. The ones no
// check can evidence are counted rather than listed: they are the same for
// every statement, and the generated manual page names each with its
// reason.
func writeFramework(w io.Writer, fr *frameworkResult) {
	if fr == nil {
		return
	}
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("\n%s — %s\n", fr.Name, fr.Version)
	notCovered := 0
	for _, a := range fr.Criteria {
		if a.State == controls.NotCovered {
			notCovered++
			continue
		}
		p("  %-13s %-9s %s%s\n", a.State, a.ID, a.Title, checkSummary(a.Checks))
	}
	if notCovered > 0 {
		p("  %d not covered by passmcp; docs/compliance/%s.md says why for each\n", notCovered, fr.Framework)
	}
}

func checkSummary(cs []controls.CheckState) string {
	if len(cs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		s := c.ID + " " + c.Status
		if len(c.Evidence) > 0 {
			s += " " + strings.Join(c.Evidence, ",")
		}
		parts = append(parts, s)
	}
	return " (" + strings.Join(parts, "; ") + ")"
}

var evidenceCmd = &cobra.Command{
	Use:   "evidence --framework soc2|iso27001|gdpr <attestation.json>...",
	Short: "Build a dated compliance evidence bundle from attestations, offline.",
	Long: `Build an evidence bundle for one framework from attestations taken over an
audit period. Nothing is contacted: the bundle is derived from the
statements and the published mapping in spec/controls.

For every criterion of the framework the bundle lists its state at each
attestation (evidenced, failing or not assessed) with the statement's
SHA-256 and date, and marks a criterion that got worse between two dates for
the same target. A criterion no passmcp check can evidence is listed as "not
covered by passmcp" with the reason, never as evidenced.

  passmcp evidence --framework soc2 --from 2026-01-01 --to 2026-06-30 \
    --out-dir ./audit ./attestations/*.json

writes soc2-evidence.json and soc2-evidence.csv. The statements carry no
secret by design, and target URLs pass through the same redaction as a
report, so a query-string token cannot reach the bundle.

With --framework gdpr and --report, it also writes gdpr-art30.json and
gdpr-art30.md: an input to the record of processing (Art. 30) for each
server: its stated purpose, the tools whose schemas name personal data,
the destinations it contacted when run with --watch-egress, and the
attestation that evidences it. It is an input, not the record: purposes,
legal bases and retention are the controller's to complete.

Nothing here makes an organisation compliant. A CPA firm attests SOC 2, an
accredited body certifies ISO 27001, and GDPR is the controller's
obligation. The bundle is evidence for them to use.`,
	Args: cobra.MinimumNArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		f, err := controls.ParseFramework(evidenceFramework)
		if err != nil {
			return err
		}
		from, to, err := evidencePeriod(evidenceFrom, evidenceTo)
		if err != nil {
			return err
		}
		m, err := controls.Load(f)
		if err != nil {
			return err
		}
		records, stmts, err := readRecords(args)
		if err != nil {
			return err
		}
		written, err := writeBundle(m.Bundle(records, from, to), evidenceOutDir)
		if err != nil {
			return err
		}
		if f == controls.GDPR && len(evidenceReports) > 0 {
			more, err := writeArt30(evidenceReports, stmts, evidenceOutDir)
			if err != nil {
				return err
			}
			written = append(written, more...)
		}
		for _, p := range written {
			_, _ = fmt.Fprintf(cmd.OutOrStdout(), "wrote %s\n", p)
		}
		return nil
	},
}

// evidencePeriod parses --from and --to as a date or a timestamp. A bare
// --to date includes the whole of that day.
func evidencePeriod(from, to string) (time.Time, time.Time, error) {
	parse := func(s string, endOfDay bool) (time.Time, error) {
		s = strings.TrimSpace(s)
		if s == "" {
			return time.Time{}, nil
		}
		if t, err := time.Parse(time.RFC3339, s); err == nil {
			return t, nil
		}
		t, err := time.Parse("2006-01-02", s)
		if err != nil {
			return time.Time{}, fmt.Errorf("%q is neither a date (2006-01-02) nor an RFC 3339 time", s)
		}
		if endOfDay {
			t = t.Add(24*time.Hour - time.Nanosecond)
		}
		return t, nil
	}
	f, err := parse(from, false)
	if err != nil {
		return f, f, err
	}
	t, err := parse(to, true)
	if err != nil {
		return f, t, err
	}
	if !f.IsZero() && !t.IsZero() && t.Before(f) {
		return f, t, errors.New("--to is before --from")
	}
	return f, t, nil
}

// statementFile is one parsed attestation with its file's digest.
type statementFile struct {
	st     *attest.Statement
	digest string
}

// readRecords parses every attestation named, refusing one that does not
// validate: evidence built on a statement that cannot be believed is not
// evidence.
func readRecords(paths []string) ([]controls.Record, []statementFile, error) {
	red := &telemetry.Redactor{}
	var records []controls.Record
	var stmts []statementFile
	for _, p := range paths {
		b, err := os.ReadFile(p) // #nosec G304 -- the operator named the file
		if err != nil {
			return nil, nil, err
		}
		st, err := attest.Parse(b)
		if err != nil {
			return nil, nil, fmt.Errorf("%s: %w", p, err)
		}
		sum := sha256.Sum256(b)
		digest := hex.EncodeToString(sum[:])
		records = append(records, controls.Record{
			Target:   red.URL(st.Predicate.Target.Endpoint),
			RanAt:    st.Predicate.RanAt,
			Digest:   digest,
			Verdicts: verdictsOf(st),
		})
		stmts = append(stmts, statementFile{st: st, digest: digest})
	}
	return records, stmts, nil
}

// writeBundle writes the bundle as JSON and CSV into dir.
func writeBundle(b controls.Bundle, dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	jsonPath := filepath.Join(dir, string(b.Framework)+"-evidence.json")
	csvPath := filepath.Join(dir, string(b.Framework)+"-evidence.csv")
	if err := writeFileWith(jsonPath, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(b)
	}); err != nil {
		return nil, err
	}
	if err := writeFileWith(csvPath, b.WriteCSV); err != nil {
		return nil, err
	}
	return []string{jsonPath, csvPath}, nil
}

func writeFileWith(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path) // #nosec G304 -- a file in the directory the operator chose
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// art30Record is one server's input to a record of processing.
type art30Record struct {
	Server string `json:"server"`
	Target string `json:"target"`
	// Purpose is the server's own statement of what it is for — its
	// instructions, or its title — or says that it gave none.
	Purpose string `json:"purpose"`
	// PersonalData are the tools whose schemas name personal-data fields.
	PersonalData []probe.PersonalDataTool `json:"personalDataTools"`
	// Destinations are where the server connected during the run. Only
	// meaningful when EgressObserved: without the witness, an empty list
	// means "not watched", not "none".
	Destinations   []string `json:"destinationsContacted"`
	EgressObserved bool     `json:"egressObserved"`
	// Attestation is the SHA-256 of the statement that evidences this
	// run, or empty when none of the attestations given is about it.
	Attestation string    `json:"attestationSha256,omitempty"`
	RanAt       time.Time `json:"ranAt"`
}

// art30Note is printed with every record, because a record of processing
// is the controller's document and this is an input to it.
const art30Note = "An input to the record of processing activities (GDPR Art. 30), not the record itself: the controller completes the purposes, legal basis, categories of data subjects, retention and safeguards."

// writeArt30 builds an Art. 30 input for each report and writes it as JSON
// and Markdown.
func writeArt30(reportPaths []string, stmts []statementFile, dir string) ([]string, error) {
	var records []art30Record
	for _, p := range reportPaths {
		b, err := os.ReadFile(p) // #nosec G304 -- the operator named the file
		if err != nil {
			return nil, err
		}
		var r report.Report
		if err := json.Unmarshal(b, &r); err != nil || r.Passmcp.SchemaVersion == 0 {
			return nil, fmt.Errorf("%s is not a passmcp JSON report", p)
		}
		records = append(records, art30For(&r, stmts))
	}
	doc := struct {
		Note    string        `json:"note"`
		Records []art30Record `json:"records"`
	}{art30Note, records}
	jsonPath := filepath.Join(dir, "gdpr-art30.json")
	mdPath := filepath.Join(dir, "gdpr-art30.md")
	if err := writeFileWith(jsonPath, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(doc)
	}); err != nil {
		return nil, err
	}
	if err := writeFileWith(mdPath, func(w io.Writer) error { return art30Markdown(w, records) }); err != nil {
		return nil, err
	}
	return []string{jsonPath, mdPath}, nil
}

func art30For(r *report.Report, stmts []statementFile) art30Record {
	rec := art30Record{Target: r.Target.Endpoint, RanAt: r.Started.UTC(), PersonalData: r.Catalog.PersonalData, Purpose: "not stated by the server"}
	if rec.PersonalData == nil {
		rec.PersonalData = []probe.PersonalDataTool{}
	}
	if s := r.Server; s != nil {
		rec.Server = strings.TrimSpace(s.Name + " " + s.Version)
		switch {
		case s.Purpose != "":
			rec.Purpose = s.Purpose
		case s.Title != "":
			rec.Purpose = s.Title
		}
	}
	rec.Destinations = []string{}
	for _, d := range r.Egress {
		rec.Destinations = append(rec.Destinations, d.Target())
	}
	rec.EgressObserved = watchedEgress(r)
	rec.Attestation = matchingStatement(r, stmts)
	return rec
}

// watchedEgress reports whether the egress witness ran: egress.hosts is
// present and was not merely recording that it could not start.
func watchedEgress(r *report.Report) bool {
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.ID == "egress.hosts" && !strings.Contains(f.Detail, "could not start") {
				return true
			}
		}
	}
	return false
}

// matchingStatement finds the attestation about the same run: the same
// target and the same start time, which a statement built from this
// report carries.
func matchingStatement(r *report.Report, stmts []statementFile) string {
	for _, s := range stmts {
		p := s.st.Predicate
		if p.Target.Endpoint == r.Target.Endpoint && p.RanAt.Equal(r.Started) {
			return s.digest
		}
	}
	return ""
}

func art30Markdown(w io.Writer, records []art30Record) error {
	p := &mdPrinter{w: w}
	p.linef("# Record of processing: inputs from passmcp")
	p.linef("")
	p.linef("%s", art30Note)
	for _, r := range records {
		p.linef("")
		p.linef("## %s", firstNonEmpty(r.Server, r.Target))
		p.linef("")
		p.linef("- **Target:** `%s`", r.Target)
		p.linef("- **Run:** %s", r.RanAt.Format(time.RFC3339))
		p.linef("- **Purpose, as the server states it:** %s", r.Purpose)
		if len(r.PersonalData) == 0 {
			p.linef("- **Tools that touch personal data:** none named in the published schemas")
		} else {
			p.linef("- **Tools that touch personal data:**")
			for _, t := range r.PersonalData {
				p.linef("  - `%s`: %s", t.Tool, strings.Join(t.Fields, ", "))
			}
		}
		switch {
		case !r.EgressObserved:
			p.linef("- **Destinations contacted:** not observed (run with --watch-egress to record them)")
		case len(r.Destinations) == 0:
			p.linef("- **Destinations contacted:** none during the run")
		default:
			p.linef("- **Destinations contacted:** %s", strings.Join(r.Destinations, ", "))
		}
		p.linef("- **Evidence:** attestation SHA-256 `%s`", firstNonEmpty(r.Attestation, "none given for this run"))
	}
	return p.err
}

func firstNonEmpty(a, b string) string {
	if strings.TrimSpace(a) != "" {
		return a
	}
	return b
}

type mdPrinter struct {
	w   io.Writer
	err error
}

func (p *mdPrinter) linef(format string, a ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format+"\n", a...)
	}
}

func init() {
	verifyCmd.Flags().StringVar(&verifyFramework, "framework", "", "also report each control of this framework (soc2, iso27001, gdpr) as evidenced, failing or not assessed")
	f := evidenceCmd.Flags()
	f.StringVar(&evidenceFramework, "framework", "", "the framework: soc2, iso27001 or gdpr")
	f.StringVar(&evidenceFrom, "from", "", "the start of the audit period (2006-01-02 or RFC 3339)")
	f.StringVar(&evidenceTo, "to", "", "the end of the audit period, inclusive")
	f.StringVar(&evidenceOutDir, "out-dir", ".", "where to write the bundle")
	f.StringArrayVar(&evidenceReports, "report", nil, "a JSON report to derive a GDPR Art. 30 input from (repeatable; --framework gdpr only)")
	_ = evidenceCmd.MarkFlagRequired("framework")
}
