// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package engine

import "time"

// What a run produces: the formats a report renders as, and the output half
// of a RunSpec.

// Format is an output rendering.
type Format string

// The formats a report can be rendered as.
const (
	FormatText   Format = "text"
	FormatJSON   Format = "json"
	FormatMD     Format = "md"
	FormatNDJSON Format = "ndjson"
	// FormatHTML is one self-contained document: the file somebody opens
	// offline, the page passmcp serve shows, and — through its print
	// stylesheet — the PDF a board reads.
	FormatHTML Format = "html"
	// FormatSARIF and FormatJUnit exist so a run reaches the place a team
	// already looks: code scanning for one, the test panel for the other.
	// Neither is a richer report than JSON; both are the same findings in
	// the shape a specific reader will not accept a substitute for.
	FormatSARIF Format = "sarif"
	FormatJUnit Format = "junit"
	// FormatAttestation is not a report. Every other format here is the
	// findings arranged for a particular reader; this one is a claim about
	// the server, in the in-toto envelope a supply-chain pipeline already
	// verifies, and it is meant to be signed and handed to a machine that
	// was not present when the run happened. `passmcp verify` is the other
	// half of it.
	FormatAttestation Format = "attestation"
	// FormatOCSF is the failing and warning findings as OCSF 1.3 events, for a
	// SIEM: Vulnerability Finding or Compliance Finding, one per finding.
	FormatOCSF Format = "ocsf"
)

// Formats lists every valid output format.
var Formats = []Format{FormatText, FormatJSON, FormatMD, FormatNDJSON, FormatHTML, FormatSARIF, FormatJUnit, FormatAttestation, FormatOCSF}

// Valid reports whether f is a format passmcp can render.
func (f Format) Valid() bool {
	for _, v := range Formats {
		if f == v {
			return true
		}
	}
	return false
}

// OutputSpec says what to produce.
type OutputSpec struct {
	Format Format `json:"format,omitempty"`
	// ReportDir, when set, receives report.{txt,md,json} plus telemetry.
	ReportDir string `json:"report_dir,omitempty"`
	// Retain, when positive, is how long passmcp's own files in ReportDir
	// are kept: older ones are deleted before the run writes its own, and
	// each deletion is logged. Storage limitation (GDPR Art. 5(1)(e)) for
	// a directory a scheduled run writes to again and again.
	Retain time.Duration `json:"retain_ns,omitempty"`
	// CaptureBodies records request and response bodies, redacted and
	// capped, in the telemetry.
	CaptureBodies bool `json:"capture_bodies,omitempty"`
	// WithEvents embeds every telemetry event in the JSON report.
	WithEvents bool `json:"with_events,omitempty"`
	// WithGuidance embeds the remediation for each check that produced a
	// finding, as a dictionary keyed by check id. Off by default because
	// most consumers have doc_url and want the report small; on for the
	// ones that have to explain a finding somewhere passmcp cannot reach,
	// like a bot writing a pull request comment.
	WithGuidance bool `json:"with_guidance,omitempty"`
	// HTMLAssets writes the HTML report's stylesheet into ReportDir as
	// report.css and has the HTML link it rather than carry it inline, so
	// the page renders under a Content-Security-Policy that refuses inline
	// style. Off by default: the single file is what somebody can mail.
	HTMLAssets bool `json:"html_assets,omitempty"`
	// Verbose shows evidence references and info findings.
	Verbose bool `json:"verbose,omitempty"`
	// NoColor disables ANSI colour in the text rendering.
	NoColor bool `json:"no_color,omitempty"`
	// Interactive asks the surface to choose tools before the run. The
	// chosen names land in Policy.Only, so a run is reproducible from the
	// spec afterwards without asking again.
	Interactive bool `json:"interactive,omitempty"`
	// OTLPEndpoint, when set, receives the finished run as OpenTelemetry
	// traces. Export happens after the report is rendered and never
	// changes the exit code: a collector being down is not a finding
	// about the server under test.
	OTLPEndpoint string `json:"otlp_endpoint,omitempty"`
	// OTLPHeaders are extra headers on the export request, "Name: value",
	// for a collector that wants an API key or a tenant id.
	OTLPHeaders []string `json:"otlp_headers,omitempty"`
	// OCSFEndpoint is where the run's OCSF events are posted, when the
	// operator named one. Empty means they go nowhere.
	OCSFEndpoint string `json:"ocsf_endpoint,omitempty"`
	// OCSFHeaders are extra "Name: value" headers on that post, typically
	// the collector's token. Never serialised: a plan must not carry it.
	OCSFHeaders []string `json:"-"`
}
