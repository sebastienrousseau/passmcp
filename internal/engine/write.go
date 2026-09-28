// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"time"

	"satellion.com/passmcp/internal/attest"
	"satellion.com/passmcp/internal/ocsf"
	"satellion.com/passmcp/internal/report"
	"satellion.com/passmcp/internal/telemetry"
)

// Render writes the result to w in the spec's format.
//
// It lives here rather than in a surface so that "what a JSON report looks
// like" is one answer, whether it was asked for by a flag, a key press or
// an HTTP Accept header.
func (r *Result) Render(w io.Writer, spec RunSpec, termWidth int) error {
	if r.Report == nil {
		return nil
	}
	switch spec.Output.Format {
	case FormatJSON:
		rep := *r.Report
		if !spec.Output.WithEvents && spec.Output.ReportDir == "" {
			rep.Events = nil
		}
		if spec.Output.WithGuidance {
			rep.AttachGuidance()
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(rep)
	case FormatMD:
		report.Markdown(w, r.Report)
		return nil
	case FormatHTML:
		return report.HTML(w, r.Report, report.HTMLOptions{Verbose: spec.Output.Verbose})
	case FormatSARIF:
		return report.SARIF(w, r.Report, r.Report.Passmcp.Version)
	case FormatJUnit:
		return report.JUnit(w, r.Report)
	case FormatAttestation:
		return renderAttestation(w, r.Report)
	case FormatOCSF:
		return r.renderOCSF(w)
	case FormatNDJSON:
		// The events already streamed; this is the closing record.
		rep := *r.Report
		rep.Events = nil
		return json.NewEncoder(w).Encode(map[string]any{"type": "report", "report": rep})
	default:
		report.Text(w, r.Report, report.TextOptions{
			Color:   !spec.Output.NoColor,
			Verbose: spec.Output.Verbose,
			Width:   termWidth,
		})
		return nil
	}
}

// WriteDir saves the full report and telemetry under dir and records the
// files on the report. Every format is written, because a report directory
// is what somebody hands to another person and they should not have had to
// guess which rendering that person can open.
func (r *Result) WriteDir(spec RunSpec, version string) ([]string, error) {
	if r.Report == nil {
		return nil, nil
	}
	dir := spec.Output.ReportDir
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	if spec.Output.Retain > 0 {
		if err := sweepReportDir(dir, spec.Output.Retain, time.Now()); err != nil {
			return nil, err
		}
	}
	var files []string
	write := func(name string, fn func(io.Writer) error) error {
		p := filepath.Join(dir, name)
		f, err := os.Create(p) // #nosec G304 -- p is built from the caller's own report directory
		if err != nil {
			return err
		}
		if err := fn(f); err != nil {
			_ = f.Close()
			return err
		}
		files = append(files, p)
		return f.Close()
	}

	full := *r.Report
	if spec.Output.WithGuidance {
		full.AttachGuidance()
	}
	if r.Recorder != nil {
		full.Events = r.Recorder.Events()
	}
	steps := []struct {
		name string
		fn   func(io.Writer) error
	}{
		{"report.json", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(full)
		}},
		{"report.md", func(w io.Writer) error { report.Markdown(w, r.Report); return nil }},
		{"report.html", func(w io.Writer) error {
			return report.HTML(w, r.Report, report.HTMLOptions{Verbose: true})
		}},
		{"report.txt", func(w io.Writer) error {
			report.Text(w, r.Report, report.TextOptions{Verbose: true})
			return nil
		}},
		{"report.sarif", func(w io.Writer) error { return report.SARIF(w, r.Report, version) }},
		{"report.junit.xml", func(w io.Writer) error { return report.JUnit(w, r.Report) }},
		// The statement goes in the directory too, because the directory is
		// what somebody hands to another person — and the attestation is the
		// only file in it a machine can act on without reading prose.
		{"attestation.json", func(w io.Writer) error { return renderAttestation(w, r.Report) }},
		{"report.ocsf.json", r.renderOCSF},
		{"telemetry.ndjson", func(w io.Writer) error { return r.recorder().WriteNDJSON(w) }},
		{"telemetry.har", func(w io.Writer) error { return r.recorder().WriteHAR(w, version) }},
	}
	// The policy's answer, when one was applied. Separate from the report on
	// purpose: a report is about the server and this is about a decision
	// somebody made, and a consumer that wants one rarely wants the other.
	if r.Gate != nil {
		gate := *r.Gate
		steps = append(steps, struct {
			name string
			fn   func(io.Writer) error
		}{"policy.json", func(w io.Writer) error {
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			return enc.Encode(gate)
		}})
	}
	for _, s := range steps {
		if err := write(s.name, s.fn); err != nil {
			return nil, err
		}
	}
	r.Report.Files = files
	return files, nil
}

// renderAttestation writes the in-toto statement for a finished report.
func renderAttestation(w io.Writer, r *report.Report) error {
	st, err := attest.From(r)
	if err != nil {
		return err
	}
	b, err := st.Marshal()
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// OCSFEvents are the run's failing and warning findings as OCSF events,
// with every string passed through the run's redactor like every other
// format.
func (r *Result) OCSFEvents() []ocsf.Event {
	if r.Report == nil {
		return nil
	}
	return ocsf.FromReport(r.Report, ocsf.Options{
		ProductVersion: r.Report.Passmcp.Version,
		Redactor:       r.recorder().Redactor,
	})
}

// renderOCSF writes the OCSF events for a finished report.
func (r *Result) renderOCSF(w io.Writer) error {
	return ocsf.Write(w, r.OCSFEvents())
}

// recorder is nil-safe so WriteDir works for a result assembled by hand.
func (r *Result) recorder() *telemetry.Recorder {
	if r.Recorder == nil {
		return telemetry.New()
	}
	return r.Recorder
}
