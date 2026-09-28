// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package ocsf renders passmcp's findings, and a fleet's changes, as Open
// Cybersecurity Schema Framework events.
//
// SARIF puts a finding in front of a developer and JUnit in front of a CI
// dashboard. A SOC reads neither: it reads its SIEM, and the schema the
// security industry is converging on for that is OCSF. An MCP server that
// starts failing should raise the same kind of alert as any other asset, and
// that only happens if the finding arrives in the shape the SIEM already
// correlates.
//
// Only failing and warning findings become events. A pass is not something
// a SOC acts on, and a stream that reported every passing check would bury
// the ones that matter.
//
// The schema version is pinned in Version. The event shapes are held to it by
// a golden-file test and by a validator that reads the class definitions
// vendored from schema.ocsf.io, so a change of shape cannot ship without the
// pin moving with it.
package ocsf

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/report"
)

// Version is the OCSF schema version every event is written against.
const Version = "1.3.0"

// OCSF identifiers used by passmcp's events.
const (
	CategoryFindings           = 2
	ClassVulnerabilityFinding  = 2002
	ClassComplianceFinding     = 2003
	ActivityCreate             = 1
	StatusNew                  = 1
	severityInformational      = 1
	severityLow                = 2
	severityMedium             = 3
	severityHigh               = 4
	severityCritical           = 5
	productName                = "passmcp"
	vendorName                 = "Sebastien Rousseau"
	complianceStandardPrefix   = "passmcp rubric "
	driftStandard              = "passmcp baseline"
	maxTextLength              = 2000
	vulnerabilityFindingName   = "Vulnerability Finding"
	complianceFindingName      = "Compliance Finding"
	findingsCategoryName       = "Findings"
	createActivityName         = "Create"
	statusNewName              = "New"
	driftFindingType           = "passmcp.drift"
	resourceTypeMCPServer      = "MCP Server"
	metadataLogName            = "passmcp"
	unmappedPassmcpKey         = "passmcp"
	complianceStatusFail       = "Fail"
	complianceStatusWarning    = "Warning"
	complianceStatusIDFail     = 3
	complianceStatusIDWarning  = 2
	defaultDriftComplianceNote = "the catalogue or verdicts changed since the last signed run"
)

// Redactor masks registered secrets in text. telemetry.Redactor is one; the
// interface keeps this package from depending on how secrets are held.
type Redactor interface {
	String(s string) string
}

// Options configure how events are written.
type Options struct {
	// ProductVersion is passmcp's own version.
	ProductVersion string
	// Redactor masks every string the event carries. Nil means no secrets
	// were registered, which is only true of a run made without credentials.
	Redactor Redactor
}

// Event is one OCSF finding event. Field names are the schema's own.
type Event struct {
	ActivityID      int             `json:"activity_id"`
	ActivityName    string          `json:"activity_name"`
	CategoryUID     int             `json:"category_uid"`
	CategoryName    string          `json:"category_name"`
	ClassUID        int             `json:"class_uid"`
	ClassName       string          `json:"class_name"`
	TypeUID         int64           `json:"type_uid"`
	TypeName        string          `json:"type_name"`
	Time            int64           `json:"time"`
	SeverityID      int             `json:"severity_id"`
	Severity        string          `json:"severity"`
	StatusID        int             `json:"status_id"`
	Status          string          `json:"status"`
	Message         string          `json:"message"`
	Metadata        Metadata        `json:"metadata"`
	FindingInfo     FindingInfo     `json:"finding_info"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities,omitempty"`
	Compliance      *Compliance     `json:"compliance,omitempty"`
	Resources       []Resource      `json:"resources,omitempty"`
	Unmapped        map[string]any  `json:"unmapped,omitempty"`
}

// Metadata names the producer and the schema version.
type Metadata struct {
	Version string  `json:"version"`
	Product Product `json:"product"`
	LogName string  `json:"log_name"`
}

// Product is passmcp.
type Product struct {
	Name       string `json:"name"`
	VendorName string `json:"vendor_name"`
	Version    string `json:"version,omitempty"`
}

// FindingInfo identifies the finding.
type FindingInfo struct {
	UID   string   `json:"uid"`
	Title string   `json:"title"`
	Desc  string   `json:"desc,omitempty"`
	Types []string `json:"types,omitempty"`
}

// Vulnerability describes a security weakness passmcp observed.
type Vulnerability struct {
	Title    string   `json:"title"`
	Desc     string   `json:"desc,omitempty"`
	Severity string   `json:"severity"`
	Refs     []string `json:"references,omitempty"`
}

// Compliance describes a deviation from what passmcp's rubric requires.
type Compliance struct {
	Standards []string `json:"standards"`
	Control   string   `json:"control"`
	Status    string   `json:"status"`
	StatusID  int      `json:"status_id"`
}

// Resource is the MCP server the event is about.
type Resource struct {
	Name string `json:"name"`
	Type string `json:"type"`
	UID  string `json:"uid"`
}

// FromReport turns a report's failing and warning findings into events.
func FromReport(r *report.Report, o Options) []Event {
	if r == nil {
		return nil
	}
	w := writer{o: o}
	var out []Event
	for _, p := range r.Phases {
		for i, f := range p.Findings {
			if f.Status != probe.Fail && f.Status != probe.Warn {
				continue
			}
			out = append(out, w.finding(r, p.Name, i, f))
		}
	}
	return out
}

// Drift is one change a fleet run found in a server since its last signed
// run. It is the neutral shape the fleet package hands over, so this
// package does not depend on how a fleet is run.
type Drift struct {
	Server   string
	Endpoint string
	Kind     string
	Tool     string
	// Severity is the baseline ladder's word: noise, notable, serious or
	// critical.
	Severity string
	Detail   string
	Before   string
	After    string
	// BeforeAttestation and AfterAttestation are the digests of the two
	// signed statements the change was found between.
	BeforeAttestation string
	AfterAttestation  string
	At                time.Time
}

// FromDrift turns a fleet's changes into compliance-finding events, each
// carrying the value before and after and both attestation digests.
func FromDrift(changes []Drift, o Options) []Event {
	w := writer{o: o}
	out := make([]Event, 0, len(changes))
	for _, c := range changes {
		out = append(out, w.drift(c))
	}
	return out
}

// Write encodes events as one JSON array, which is what --output ocsf
// prints and what --ocsf-endpoint posts.
func Write(w io.Writer, events []Event) error {
	if events == nil {
		events = []Event{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(events)
}

// writer holds the options while events are built.
type writer struct{ o Options }

// text masks secrets and bounds length: every string an event carries may
// have come from the server, and a SIEM is not the place a token surfaces.
func (w writer) text(s string) string {
	if w.o.Redactor != nil {
		s = w.o.Redactor.String(s)
	}
	if len(s) > maxTextLength {
		s = s[:maxTextLength] + "…"
	}
	return s
}

// base is the part every event shares.
func (w writer) base(class int, at time.Time, severityID int) Event {
	name := vulnerabilityFindingName
	if class == ClassComplianceFinding {
		name = complianceFindingName
	}
	return Event{
		ActivityID:   ActivityCreate,
		ActivityName: createActivityName,
		CategoryUID:  CategoryFindings,
		CategoryName: findingsCategoryName,
		ClassUID:     class,
		ClassName:    name,
		TypeUID:      int64(class)*100 + ActivityCreate,
		TypeName:     name + ": " + createActivityName,
		Time:         at.UTC().UnixMilli(),
		SeverityID:   severityID,
		Severity:     severityName(severityID),
		StatusID:     StatusNew,
		Status:       statusNewName,
		Metadata: Metadata{
			Version: Version,
			Product: Product{Name: productName, VendorName: vendorName, Version: w.o.ProductVersion},
			LogName: metadataLogName,
		},
	}
}

// finding builds the event for one failing or warning finding.
func (w writer) finding(r *report.Report, phase string, index int, f probe.Finding) Event {
	class := classOf(phase, f.ID)
	e := w.base(class, r.Started, severityOf(f))
	endpoint := w.text(r.Target.Endpoint)
	e.Message = w.text(f.Title + ": " + f.Detail)
	e.FindingInfo = FindingInfo{
		UID:   findingUID(r.TraceID, f.ID, index),
		Title: w.text(f.Title),
		Desc:  w.text(f.Detail),
		Types: []string{f.ID},
	}
	e.Resources = []Resource{{Name: endpoint, Type: resourceTypeMCPServer, UID: digestOf(endpoint)}}
	e.Unmapped = map[string]any{unmappedPassmcpKey: map[string]any{
		"check_id": f.ID,
		"phase":    phase,
		"status":   string(f.Status),
		"severity": string(f.Severity),
		"evidence": w.evidence(f.Evidence),
		"advice":   w.text(f.Advice),
		"trace_id": r.TraceID,
		"doc_url":  f.DocURL,
	}}
	if class == ClassVulnerabilityFinding {
		v := Vulnerability{Title: e.FindingInfo.Title, Desc: e.FindingInfo.Desc, Severity: e.Severity}
		if f.DocURL != "" {
			v.Refs = []string{f.DocURL}
		}
		e.Vulnerabilities = []Vulnerability{v}
		return e
	}
	e.Compliance = w.compliance(f)
	return e
}

// compliance is the compliance object for a rubric deviation.
func (w writer) compliance(f probe.Finding) *Compliance {
	c := &Compliance{
		Standards: []string{complianceStandardPrefix + report.RubricVersion},
		Control:   f.ID,
		Status:    complianceStatusFail,
		StatusID:  complianceStatusIDFail,
	}
	if f.Status == probe.Warn {
		c.Status, c.StatusID = complianceStatusWarning, complianceStatusIDWarning
	}
	return c
}

// evidence copies the request references, masked like every other string.
func (w writer) evidence(refs []string) []string {
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, w.text(r))
	}
	return out
}

// drift builds the event for one fleet change.
func (w writer) drift(c Drift) Event {
	e := w.base(ClassComplianceFinding, c.At, driftSeverity(c.Severity))
	endpoint := w.text(c.Endpoint)
	subject := c.Kind
	if c.Tool != "" {
		subject += " " + c.Tool
	}
	e.Message = w.text(c.Server + ": " + subject + ": " + c.Detail)
	e.FindingInfo = FindingInfo{
		UID:   digestOf(strings.Join([]string{c.Server, c.Kind, c.Tool, c.BeforeAttestation, c.AfterAttestation, c.Detail}, "\x00")),
		Title: w.text(c.Server + ": " + subject),
		Desc:  w.text(c.Detail),
		Types: []string{driftFindingType, c.Kind},
	}
	e.Compliance = &Compliance{
		Standards: []string{driftStandard},
		Control:   c.Kind,
		Status:    complianceStatusFail,
		StatusID:  complianceStatusIDFail,
	}
	e.Resources = []Resource{{Name: endpoint, Type: resourceTypeMCPServer, UID: digestOf(endpoint)}}
	e.Unmapped = map[string]any{unmappedPassmcpKey: map[string]any{
		"server":             w.text(c.Server),
		"kind":               c.Kind,
		"tool":               w.text(c.Tool),
		"severity":           c.Severity,
		"before":             w.text(c.Before),
		"after":              w.text(c.After),
		"before_attestation": c.BeforeAttestation,
		"after_attestation":  c.AfterAttestation,
		"note":               defaultDriftComplianceNote,
	}}
	return e
}

// vulnerabilityPrefixes are the check families a SOC treats as a security
// weakness rather than a conformance gap.
var vulnerabilityPrefixes = []string{
	"catalog.text.", "catalog.names.confusable", "catalog.toxic_combination",
	"protocol.origin", "execution.output_injection", "tools.annotation_honesty",
}

// vulnerabilityPhases are the phases whose findings are all security
// findings: who may connect, what the server reaches, what it runs.
var vulnerabilityPhases = map[string]bool{
	"net": true, "discovery": true, "auth": true, "egress": true, "fs": true, "supply": true, "stdio": true,
}

// classOf decides whether a finding is a vulnerability or a compliance gap.
func classOf(phase, id string) int {
	if vulnerabilityPhases[phase] || vulnerabilityPhases[prefixOf(id)] {
		return ClassVulnerabilityFinding
	}
	for _, p := range vulnerabilityPrefixes {
		if strings.HasPrefix(id, p) {
			return ClassVulnerabilityFinding
		}
	}
	return ClassComplianceFinding
}

// prefixOf is the first dotted segment of a check id.
func prefixOf(id string) string {
	head, _, _ := strings.Cut(id, ".")
	return head
}

// severityOf maps passmcp's status and severity onto OCSF's scale. A failure
// is at least Medium; a warning is at most Medium, because a warning is by
// definition something an agent can live with.
func severityOf(f probe.Finding) int {
	if f.Status == probe.Warn {
		if f.Severity == probe.Critical {
			return severityMedium
		}
		return severityLow
	}
	switch f.Severity {
	case probe.Critical:
		return severityCritical
	case probe.Major:
		return severityHigh
	default:
		return severityMedium
	}
}

// driftSeverity maps the baseline ladder onto OCSF's scale.
func driftSeverity(s string) int {
	switch s {
	case "critical":
		return severityCritical
	case "serious":
		return severityHigh
	case "notable":
		return severityMedium
	default:
		return severityInformational
	}
}

// severityName is the caption OCSF gives each severity_id.
func severityName(id int) string {
	switch id {
	case severityCritical:
		return "Critical"
	case severityHigh:
		return "High"
	case severityMedium:
		return "Medium"
	case severityLow:
		return "Low"
	default:
		return "Informational"
	}
}

// findingUID is stable for the same finding in the same run: a SIEM that
// receives the export twice deduplicates on it.
func findingUID(traceID, id string, index int) string {
	return digestOf(fmt.Sprintf("%s\x00%s\x00%d", traceID, id, index))
}

// digestOf is a short, stable identifier.
func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:16])
}
