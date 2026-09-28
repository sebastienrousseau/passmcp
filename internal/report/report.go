// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package report turns a probe session into a document: a scored,
// step-by-step account of what was observed, with the telemetry attached.
package report

import (
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"

	"satellion.com/passmcp"
	"satellion.com/passmcp-reporting/attestation"
	"satellion.com/passmcp/internal/egress"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
	"satellion.com/passmcp/spec/controls"
)

// Report is the full diagnostic output.
type Report struct {
	Passmcp  Meta         `json:"passmcp"`
	Target   Target       `json:"target"`
	Started  time.Time    `json:"started"`
	Duration probe.Millis `json:"duration_ms"`
	TraceID  string       `json:"trace_id"`

	Auth      AuthSummary         `json:"auth"`
	Server    *ServerInfo         `json:"server,omitempty"`
	Phases    []probe.PhaseResult `json:"phases"`
	Catalog   Catalog             `json:"catalog"`
	Execution Execution           `json:"execution"`
	Perf      *probe.PerfResult   `json:"performance,omitempty"`
	Score     Score               `json:"score"`
	// Blocked is the reason later phases were skipped, when the run did
	// not get through every phase.
	Blocked   string            `json:"blocked,omitempty"`
	Counts    Counts            `json:"counts"`
	Telemetry telemetry.Summary `json:"telemetry"`
	Events    []telemetry.Event `json:"events,omitempty"`
	Files     []string          `json:"files,omitempty"`
	// Guidance is the remediation for each check id present in this
	// report, filled only when the caller asked for it.
	//
	// A dictionary rather than a field on every finding, because the prose
	// is per-check and not per-occurrence: a catalog with forty poisoned
	// descriptions produces forty findings and one entry here. A consumer
	// joins on the finding's `id`.
	Guidance map[string]Remediation `json:"guidance,omitempty"`
	// Plan is how the run was made, carried into an attestation so the
	// measurement can be repeated. Nil for a report assembled by hand.
	Plan *attestation.Plan `json:"plan,omitempty"`
	// Egress lists where the server connected during the run, when the
	// egress witness was running (--watch-egress). It is the "recipients"
	// input to a GDPR Art. 30 record: `passmcp evidence --framework gdpr`
	// reads it from here.
	Egress []egress.Dial `json:"egress,omitempty"`
	// Redaction counts what the redactor masked in this run's recorded
	// traffic and in the report, so a reader can see that masking happened
	// without being shown what was masked.
	Redaction *telemetry.RedactionSummary `json:"redaction,omitempty"`
}

// AttachGuidance fills Guidance with the remediation for every check that
// produced a finding in this report.
//
// Only the ids actually present: a report about one server should not carry
// advice about checks that server passed, let alone all sixty-five.
func (r *Report) AttachGuidance() {
	if r == nil {
		return
	}
	g := map[string]Remediation{}
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.Status != probe.Fail && f.Status != probe.Warn {
				continue
			}
			if rem, ok := RemediationFor(f.ID); ok {
				g[f.ID] = rem
			}
		}
	}
	if len(g) == 0 {
		return
	}
	r.Guidance = g
}

// SchemaVersion is the version of the JSON report format. It changes when a
// field is removed or its meaning changes, never when one is added, so a
// consumer can pin a major version and keep reading.
//
// 1: initial published format. Every *_ms field holds milliseconds.
//
// The stdio transport tested that rule and did not break it, which is worth
// recording because the argument goes the other way at first glance.
// `target.endpoint` holds a command line for a stdio run, and a consumer
// that parsed it as a URL would fail — but no v1 consumer has ever been
// handed a stdio report, because passmcp could not produce one, and every
// report it can produce for an existing run is unchanged. `target.transport`
// is the added field that says which kind it is holding. Bumping to 2 would
// have made every pinned consumer reject HTTP reports that did not change,
// which is a real break in exchange for a hypothetical one.
const SchemaVersion = 1

// Meta identifies the passmcp build and the report format.
type Meta struct {
	Version string `json:"version"`
	// SchemaVersion lets a consumer detect a format it cannot read.
	SchemaVersion int `json:"schema_version"`
}

// Target is the server under test (secrets stripped).
type Target struct {
	// Endpoint is the URL, or over stdio the command line that was run.
	// Every rendering names the target through this field, so it is filled
	// either way rather than left empty for one transport.
	Endpoint string `json:"endpoint"`
	Host     string `json:"host"`
	Scheme   string `json:"scheme"`
	// Transport is "http" or "stdio". A consumer comparing two reports has
	// to be able to tell which kind of run it is reading: the two do not
	// contain the same checks, and the difference is not the server's.
	Transport string `json:"transport,omitempty"`
	// Command is the program and its arguments, when the transport is
	// stdio. Kept as a list so a consumer can re-run it without guessing
	// how it was quoted.
	Command []string `json:"command,omitempty"`
}

// URI renders the target as something a machine consumer can treat as a
// location.
//
// SARIF wants a URI, and over stdio there is no URL — the target is a
// command line, which is not one. A tool that put "npx -y thing" in a URI
// field would be handing a consumer a value it has to guess about, so this
// makes the shape explicit with a scheme and escapes the rest.
func (t Target) URI() string {
	if t.Transport != "stdio" {
		return t.Endpoint
	}
	u := url.URL{Scheme: "stdio", Opaque: url.PathEscape(t.Endpoint)}
	return u.String()
}

// Key is the short, stable identifier for the target, used where a
// consumer groups findings across runs.
//
// For HTTP that is the host. For stdio it has to be the command: the host
// is empty, and using it would give every stdio server on a machine the
// same identity — so two nights' runs against two different servers would
// merge into one alert.
func (t Target) Key() string {
	if t.Transport == "stdio" {
		return t.Endpoint
	}
	return t.Host
}

// AuthSummary is the credential and discovery summary.
type AuthSummary struct {
	Mode    string            `json:"mode"`
	Sources map[string]string `json:"sources,omitempty"`
	Reached bool              `json:"reached"`
	// Params are the extra token/authorization parameters sent (values are
	// operator-chosen identifiers, not secrets); Headers lists header names.
	Params       []string         `json:"params,omitempty"`
	Headers      []string         `json:"headers,omitempty"`
	Required     bool             `json:"required"`
	Issuer       string           `json:"issuer,omitempty"`
	PRMSource    string           `json:"prm_source,omitempty"`
	Registration string           `json:"registration,omitempty"`
	ClientID     string           `json:"client_id,omitempty"`
	Resource     string           `json:"resource,omitempty"`
	Token        *probe.TokenInfo `json:"token,omitempty"`
}

// ServerInfo is what initialize returned.
type ServerInfo struct {
	Name string `json:"name"`
	// Title is the server's human-readable name, when it gave one.
	Title string `json:"title,omitempty"`
	// Purpose is the start of the server's own instructions, bounded and
	// redacted: the server's statement of what it is for, which a record of
	// processing asks for and nothing else in the report carries.
	Purpose      string   `json:"purpose,omitempty"`
	Version      string   `json:"version"`
	Protocol     string   `json:"protocol_version"`
	Capabilities []string `json:"capabilities"`
	Instructions int      `json:"instructions_chars"`
	Session      bool     `json:"session_id"`
}

// ToolSummary is one catalog row.
type ToolSummary struct {
	Name         string   `json:"name"`
	Title        string   `json:"title,omitempty"`
	Description  string   `json:"description"`
	ReadOnly     bool     `json:"read_only"`
	Destructive  bool     `json:"destructive"`
	Annotated    bool     `json:"annotated"`
	OutputSchema bool     `json:"output_schema"`
	Required     []string `json:"required_args,omitempty"`
}

// Catalog lists what the server exposes.
type Catalog struct {
	Tools []ToolSummary `json:"tools"`
	// PersonalData lists the tools whose schemas name personal-data
	// fields (catalog.personal_data), by tool and field path.
	PersonalData []probe.PersonalDataTool   `json:"personal_data,omitempty"`
	Resources    []passmcp.Resource         `json:"resources,omitempty"`
	Templates    []passmcp.ResourceTemplate `json:"resource_templates,omitempty"`
	Prompts      []passmcp.Prompt           `json:"prompts,omitempty"`
}

// Execution collects invocation results.
type Execution struct {
	Tools     []probe.ToolResult     `json:"tools"`
	Resources []probe.ResourceResult `json:"resources,omitempty"`
	Prompts   []probe.PromptResult   `json:"prompts,omitempty"`
}

// Counts totals findings by status.
type Counts struct {
	Pass int `json:"pass"`
	Warn int `json:"warn"`
	Fail int `json:"fail"`
	Skip int `json:"skip"`
	Info int `json:"info"`
}

// targetOf describes what was diagnosed.
//
// A stdio run has no host, no scheme and no URL, so the fields that would
// be empty are left empty and the command takes the place of the endpoint —
// every rendering already names the target that way, and a report whose
// header says nothing would be worse than one that says which program ran.
func targetOf(s *probe.Session) Target {
	red := s.Opts.Recorder.Redactor
	if st := s.Opts.Stdio; st != nil {
		cmd := append([]string{st.Command}, st.Args...)
		for i, a := range cmd {
			// An argument is a place a secret lives: --api-key=… is
			// ordinary, and the report is the one place it must not be.
			cmd[i] = red.String(a)
		}
		return Target{
			Endpoint:  strings.Join(cmd, " "),
			Scheme:    "stdio",
			Transport: "stdio",
			Command:   cmd,
		}
	}
	t := Target{Endpoint: red.URL(s.Opts.Endpoint), Transport: "http"}
	if s.URL != nil {
		t.Host, t.Scheme = s.URL.Host, s.URL.Scheme
	}
	return t
}

// Build assembles a report from a finished session.
func Build(s *probe.Session, version string, includeEvents bool) *Report {
	r := &Report{
		Passmcp:  Meta{Version: version, SchemaVersion: SchemaVersion},
		Target:   targetOf(s),
		Started:  s.Started,
		Duration: probe.Millis(time.Since(s.Started)),
		TraceID:  s.TraceID,
		Phases:   s.Results,
		Perf:     s.Perf,
	}
	r.Auth = authSummary(s)
	r.Blocked = s.Blocked()
	r.Server = serverInfo(s)
	for _, t := range s.Tools {
		r.Catalog.Tools = append(r.Catalog.Tools, ToolSummary{Name: t.Name, Title: t.Title, Description: t.Description, ReadOnly: t.IsReadOnly(), Destructive: t.IsDestructive(), Annotated: t.Annotations != nil, OutputSchema: len(t.OutputSchema) > 0, Required: required(t)})
	}
	r.Catalog.Resources, r.Catalog.Templates, r.Catalog.Prompts = s.Resources, s.Templates, s.Prompts
	r.Catalog.PersonalData = s.PersonalData
	if s.Proxy != nil {
		r.Egress = s.Proxy.Dials()
	}
	r.Phases = redactFindings(s.Results, s.Opts.Recorder.Redactor)
	r.Execution = Execution{Tools: s.ToolResults, Resources: s.ResourceResults, Prompts: s.PromptResults}
	r.Counts = tallyFindings(s.Results)
	r.Score = ComputeScore(s.Results)
	r.Telemetry = s.Opts.Recorder.Summary()
	if includeEvents {
		r.Events = s.Opts.Recorder.Events()
	}
	if sum := s.Opts.Recorder.Redactor.Summary(); sum.Total() > 0 {
		r.Redaction = &sum
	}

	r.maskSecrets(s.Opts.Recorder.Redactor)
	return r
}

// redactFindings puts every finding's server-derived text through the
// redactor and fills its controls.
//
// A detail can quote what a server returned — a validation error that
// echoes a value, an excerpt of a description — and that text is where a
// personal datum the recorder masked in the telemetry would otherwise
// reach the report in the clear. Controls are filled here as well as when
// the finding is made, so a finding built any other way still carries
// three lists.
func redactFindings(phases []probe.PhaseResult, red *telemetry.Redactor) []probe.PhaseResult {
	// A copy, not an edit in place: the session's findings are shared with
	// whatever streamed them during the run, which may still be reading.
	if phases == nil {
		return nil
	}
	out := make([]probe.PhaseResult, len(phases))
	for i, p := range phases {
		p.Findings = append([]probe.Finding(nil), p.Findings...)
		for j := range p.Findings {
			f := &p.Findings[j]
			f.Detail = red.Text(f.Detail)
			f.Advice = red.Text(f.Advice)
			f.Controls = controls.For(f.ID)
		}
		out[i] = p
	}
	return out
}

// authSummary records how the run authenticated: the mode, where the
// credentials came from (parameter and header names, never values), and
// what discovery and registration found.
func authSummary(s *probe.Session) AuthSummary {
	a := AuthSummary{Mode: string(s.Opts.Creds.Effective()), Sources: s.Opts.Creds.Sources, Reached: s.Reached, Required: s.RequiresAuth, Token: s.Token}
	for k, vs := range s.Opts.Creds.Params {
		for _, v := range vs {
			a.Params = append(a.Params, k+"="+v)
		}
	}
	sort.Strings(a.Params)
	for k := range s.Opts.Creds.Headers {
		a.Headers = append(a.Headers, k)
	}
	sort.Strings(a.Headers)
	if d := s.Discovery; d != nil {
		if d.Server != nil {
			a.Issuer = d.Server.Issuer
		}
		a.PRMSource = d.PRMSource
		a.Resource = d.Resource
		if d.Registration != nil {
			a.Registration = d.Registration.Method
			a.ClientID = d.Registration.ClientID
		}
	}
	return a
}

// serverInfo describes the server the handshake reached, or nil when it
// never completed.
func serverInfo(s *probe.Session) *ServerInfo {
	if s.Init == nil {
		return nil
	}
	red := s.Opts.Recorder.Redactor
	si := &ServerInfo{Name: s.Init.ServerInfo.Name, Title: red.Text(clip(s.Init.ServerInfo.Title, 120)), Purpose: red.Text(clip(s.Init.Instructions, 280)), Version: s.Init.ServerInfo.Version, Protocol: s.Init.ProtocolVersion, Instructions: len(s.Init.Instructions), Session: s.SessionID}
	if s.Init.Capabilities.Tools != nil {
		si.Capabilities = append(si.Capabilities, "tools")
	}
	if s.Init.Capabilities.Resources != nil {
		si.Capabilities = append(si.Capabilities, "resources")
	}
	if s.Init.Capabilities.Prompts != nil {
		si.Capabilities = append(si.Capabilities, "prompts")
	}
	if s.Init.Capabilities.Logging != nil {
		si.Capabilities = append(si.Capabilities, "logging")
	}
	return si
}

// tallyFindings totals every phase's findings by status.
func tallyFindings(results []probe.PhaseResult) Counts {
	var c Counts
	for _, p := range results {
		for _, f := range p.Findings {
			switch f.Status {
			case probe.Pass:
				c.Pass++
			case probe.Warn:
				c.Warn++
			case probe.Fail:
				c.Fail++
			case probe.Skip:
				c.Skip++
			case probe.Info:
				c.Info++
			}
		}
	}
	return c
}

func required(t passmcp.Tool) []string {
	var s struct {
		Required []string `json:"required"`
	}
	_ = jsonUnmarshal(t.InputSchema, &s)
	sort.Strings(s.Required)
	return s.Required
}

// Failures returns fail findings ordered by severity, for the summary.
func (r *Report) Failures() []probe.Finding {
	var out []probe.Finding
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.Status == probe.Fail {
				out = append(out, f)
			}
		}
	}
	rank := map[probe.Severity]int{probe.Critical: 0, probe.Major: 1, probe.Minor: 2, probe.Note: 3}
	sort.SliceStable(out, func(i, j int) bool { return rank[out[i].Severity] < rank[out[j].Severity] })
	return out
}

// Warnings returns warn findings.
func (r *Report) Warnings() []probe.Finding {
	var out []probe.Finding
	for _, p := range r.Phases {
		for _, f := range p.Findings {
			if f.Status == probe.Warn {
				out = append(out, f)
			}
		}
	}
	return out
}

func joinNonEmpty(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}

// fmtMS renders a duration for a human. It is generic over time.Duration
// and probe.Millis, which share an underlying int64 of nanoseconds.
func fmtMS[T ~int64](v T) string {
	d := time.Duration(v)
	if d == 0 {
		return "-"
	}
	if d >= time.Second {
		return fmt.Sprintf("%.2fs", d.Seconds())
	}
	return fmt.Sprintf("%.1fms", float64(d)/float64(time.Millisecond))
}

// NextSteps returns the advice attached to failed and warned findings,
// failures first by severity, each once, so a reader knows what to change
// before anything else.
func (r *Report) NextSteps() []probe.Finding {
	seen := map[string]bool{}
	var out []probe.Finding
	for _, f := range append(r.Failures(), r.Warnings()...) {
		if f.Advice == "" || seen[f.ID] {
			continue
		}
		seen[f.ID] = true
		out = append(out, f)
	}
	return out
}

// clip bounds server text for the report, on a rune boundary.
func clip(s string, n int) string {
	s = strings.TrimSpace(s)
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}
