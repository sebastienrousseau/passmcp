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
	if render, ok := r.renderers(spec)[spec.Output.Format]; ok {
		return render(w)
	}
	report.Text(w, r.Report, report.TextOptions{
		Color:   !spec.Output.NoColor,
		Verbose: spec.Output.Verbose,
		Width:   termWidth,
	})
	return nil
}

// renderers maps every format except text, which is the fallback, to the
// function that writes it.
func (r *Result) renderers(spec RunSpec) map[Format]func(io.Writer) error {
	return map[Format]func(io.Writer) error{
		FormatJSON: func(w io.Writer) error { return r.renderJSON(w, spec) },
		FormatMD:   func(w io.Writer) error { report.Markdown(w, r.Report); return nil },
		FormatHTML: func(w io.Writer) error {
			return report.HTML(w, r.Report, htmlOptions(spec, spec.Output.Verbose))
		},
		FormatSARIF:       func(w io.Writer) error { return report.SARIF(w, r.Report, r.Report.Passmcp.Version) },
		FormatJUnit:       func(w io.Writer) error { return report.JUnit(w, r.Report) },
		FormatAttestation: func(w io.Writer) error { return renderAttestation(w, r.Report) },
		FormatOCSF:        r.renderOCSF,
		// The events already streamed; this is the closing record.
		FormatNDJSON: func(w io.Writer) error {
			rep := *r.Report
			rep.Events = nil
			return json.NewEncoder(w).Encode(map[string]any{"type": "report", "report": rep})
		},
	}
}

// renderJSON writes the report as indented JSON, with the events only when
// they were asked for or are being saved anyway.
func (r *Result) renderJSON(w io.Writer, spec RunSpec) error {
	rep := *r.Report
	if !spec.Output.WithEvents && spec.Output.ReportDir == "" {
		rep.Events = nil
	}
	if spec.Output.WithGuidance {
		rep.AttachGuidance()
	}
	return writeIndented(w, rep)
}

// htmlOptions is the HTML rendering the spec asks for. With HTMLAssets the
// page links report.css, which WriteDir puts beside it in the report
// directory; stdout output saved into that directory finds it too.
func htmlOptions(spec RunSpec, verbose bool) report.HTMLOptions {
	opts := report.HTMLOptions{Verbose: verbose}
	if spec.Output.HTMLAssets {
		opts.Stylesheet = report.StylesheetFile
	}
	return opts
}

func writeIndented(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// dirFile is one file of a report directory and the function that writes it.
type dirFile struct {
	name string
	fn   func(io.Writer) error
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
	for _, f := range r.dirFiles(spec, version) {
		p := filepath.Join(dir, f.name)
		if err := writeFile(p, f.fn); err != nil {
			return nil, err
		}
		files = append(files, p)
	}
	r.Report.Files = files
	return files, nil
}

// writeFile creates p and writes it with fn.
func writeFile(p string, fn func(io.Writer) error) error {
	f, err := os.Create(p) // #nosec G304 -- p is built from the caller's own report directory
	if err != nil {
		return err
	}
	if err := fn(f); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// dirFiles lists what a report directory holds for this run.
func (r *Result) dirFiles(spec RunSpec, version string) []dirFile {
	full := *r.Report
	if spec.Output.WithGuidance {
		full.AttachGuidance()
	}
	if r.Recorder != nil {
		full.Events = r.Recorder.Events()
	}
	steps := []dirFile{
		{"report.json", func(w io.Writer) error { return writeIndented(w, full) }},
		{"report.md", func(w io.Writer) error { report.Markdown(w, r.Report); return nil }},
		{"report.html", func(w io.Writer) error {
			return report.HTML(w, r.Report, htmlOptions(spec, true))
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
	// The stylesheet report.html links, when it links one rather than
	// carrying it inline.
	if spec.Output.HTMLAssets {
		steps = append(steps, dirFile{report.StylesheetFile, func(w io.Writer) error {
			_, err := io.WriteString(w, report.Stylesheet())
			return err
		}})
	}
	// The policy's answer, when one was applied. Separate from the report on
	// purpose: a report is about the server and this is about a decision
	// somebody made, and a consumer that wants one rarely wants the other.
	if r.Gate != nil {
		gate := *r.Gate
		steps = append(steps, dirFile{"policy.json", func(w io.Writer) error { return writeIndented(w, gate) }})
	}
	return steps
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
