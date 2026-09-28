// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"satellion.com/passmcp/internal/probe"
)

// SARIF renders the report as SARIF 2.1.0.
//
// The point of this format is that a security finding reaches the place
// people already look — GitHub code scanning, GitLab, Defect Dojo — instead
// of a log nobody opens after the build goes green.
//
// Two decisions are worth stating because a reader will otherwise assume
// the conventional answer:
//
// Passing checks are emitted, with result.kind "pass" and level "none".
// SARIF models a passing result deliberately, and dropping them would mean
// a consumer could not tell "passmcp checked this and it was fine" from
// "passmcp did not check this" — which for a conformance tool is the whole
// difference. Consumers that only surface failures filter on level, which
// costs them nothing.
//
// The location is the endpoint, as an absolute URI. There is no file to
// point at: passmcp tests a running server, not a checkout. A tool that
// invents a repository path so the result looks like a source finding is
// lying about where the problem is.
func SARIF(w io.Writer, r *Report, version string) error {
	if r == nil {
		return nil
	}

	rules, index := sarifRules(r)
	results := make([]sarifResult, 0, 64)
	for _, ph := range r.Phases {
		for _, f := range ph.Findings {
			kind, level := sarifKindLevel(f)
			results = append(results, sarifResult{
				RuleID:    f.ID,
				RuleIndex: index[f.ID],
				Kind:      kind,
				Level:     level,
				Message:   sarifMessage{Text: sarifText(f)},
				Locations: []sarifLocation{{
					PhysicalLocation: sarifPhysical{
						ArtifactLocation: sarifArtifact{URI: r.Target.URI()},
					},
					LogicalLocations: []sarifLogical{{
						Name:               f.Phase,
						FullyQualifiedName: f.ID,
						Kind:               "module",
					}},
				}},
				// The check id and the endpoint identify the same finding
				// across runs, which is what lets a consumer track one alert
				// rather than opening a new one every night.
				PartialFingerprints: map[string]string{
					"passmcpCheckId/v1": f.ID + "@" + r.Target.Key(),
				},
			})
		}
	}

	doc := sarifLog{
		Schema:  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
		Version: "2.1.0",
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:           "passmcp",
				Version:        version,
				InformationURI: "https://satellion.com/",
				Rules:          rules,
			}},
			AutomationDetails: &sarifAutomation{ID: r.TraceID},
			Results:           results,
		}},
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}

// sarifRules builds one rule per distinct check id, in a stable order.
//
// A run reports the same id more than once — a family produces one finding
// per value it met — and SARIF wants the rule described once and referenced
// by index.
func sarifRules(r *Report) ([]sarifRule, map[string]int) {
	seen := map[string]probe.Finding{}
	for _, ph := range r.Phases {
		for _, f := range ph.Findings {
			if _, ok := seen[f.ID]; !ok {
				seen[f.ID] = f
			}
		}
	}
	ids := make([]string, 0, len(seen))
	for id := range seen {
		ids = append(ids, id)
	}
	// Sorted, because a map is not, and a SARIF file that reorders itself
	// between two runs over the same server produces a diff with no change
	// in it.
	sort.Strings(ids)

	rules := make([]sarifRule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		f := seen[id]
		rule := sarifRule{
			ID:               id,
			Name:             sarifRuleName(id),
			ShortDescription: sarifMessage{Text: f.Title},
			HelpURI:          f.DocURL,
			Properties: &sarifRuleProps{
				Tags: []string{"mcp", f.Phase},
			},
		}
		if f.Advice != "" {
			rule.FullDescription = &sarifMessage{Text: f.Advice}
		}
		rules = append(rules, rule)
		index[id] = i
	}
	return rules, index
}

// sarifRuleName is the id in the PascalCase SARIF asks rule names to use.
// The id itself stays in ruleId, which is what consumers key on.
func sarifRuleName(id string) string {
	parts := strings.FieldsFunc(id, func(r rune) bool { return r == '.' || r == '_' })
	for i, p := range parts {
		if p == "" {
			continue
		}
		parts[i] = strings.ToUpper(p[:1]) + p[1:]
	}
	return strings.Join(parts, "")
}

// sarifKindLevel maps a passmcp status and severity onto SARIF's two axes.
//
// kind says what happened to the check; level says how loudly to say it.
// Keeping them separate is why a passing check can be reported at all.
func sarifKindLevel(f probe.Finding) (kind, level string) {
	switch f.Status {
	case probe.Fail:
		if f.Severity == probe.Minor {
			return "fail", "warning"
		}
		return "fail", "error"
	case probe.Warn:
		return "review", "warning"
	case probe.Info:
		return "informational", "note"
	case probe.Skip:
		return "notApplicable", "none"
	default:
		return "pass", "none"
	}
}

// sarifText is the message a person reads in the alert.
func sarifText(f probe.Finding) string {
	var b strings.Builder
	b.WriteString(f.Title)
	if f.Detail != "" {
		fmt.Fprintf(&b, ": %s", f.Detail)
	}
	if f.Advice != "" {
		fmt.Fprintf(&b, ". %s", f.Advice)
	}
	if len(f.Evidence) > 0 {
		fmt.Fprintf(&b, " (%s)", strings.Join(f.Evidence, ", "))
	}
	return b.String()
}

// --- the subset of SARIF 2.1.0 this writes --------------------------------
//
// Hand-written rather than generated: the schema is large, passmcp uses a
// small corner of it, and a generated model would put a dependency between
// a report format and somebody else's release cadence.

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool              sarifTool        `json:"tool"`
	AutomationDetails *sarifAutomation `json:"automationDetails,omitempty"`
	Results           []sarifResult    `json:"results"`
}

type sarifAutomation struct {
	ID string `json:"id,omitempty"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string          `json:"id"`
	Name             string          `json:"name,omitempty"`
	ShortDescription sarifMessage    `json:"shortDescription"`
	FullDescription  *sarifMessage   `json:"fullDescription,omitempty"`
	HelpURI          string          `json:"helpUri,omitempty"`
	Properties       *sarifRuleProps `json:"properties,omitempty"`
}

type sarifRuleProps struct {
	Tags []string `json:"tags,omitempty"`
}

type sarifResult struct {
	RuleID              string            `json:"ruleId"`
	RuleIndex           int               `json:"ruleIndex"`
	Kind                string            `json:"kind"`
	Level               string            `json:"level"`
	Message             sarifMessage      `json:"message"`
	Locations           []sarifLocation   `json:"locations,omitempty"`
	PartialFingerprints map[string]string `json:"partialFingerprints,omitempty"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical  `json:"physicalLocation"`
	LogicalLocations []sarifLogical `json:"logicalLocations,omitempty"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

type sarifLogical struct {
	Name               string `json:"name,omitempty"`
	FullyQualifiedName string `json:"fullyQualifiedName,omitempty"`
	Kind               string `json:"kind,omitempty"`
}
