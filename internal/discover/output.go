// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package discover

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// The rule IDs discovery reports under, in SARIF and in text.
const (
	RuleEndpoint    = "discovery.endpoint"
	RuleExposed     = "discovery.exposed_without_auth"
	RuleDisappeared = "discovery.disappeared"
)

// WriteJSON writes the result as indented JSON.
func WriteJSON(w io.Writer, res *Result) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(res)
}

// WriteText writes the result for a person to read.
func WriteText(w io.Writer, res *Result) {
	p := func(format string, a ...any) { _, _ = fmt.Fprintf(w, format, a...) }
	p("probed %d targets with %d requests; %d MCP endpoints proven\n", len(res.Targets), res.Requests, len(res.Endpoints))
	for _, e := range res.Endpoints {
		mark := "✓"
		if e.Exposed {
			mark = "✕"
		}
		p("\n%s %s  [%s]  %s by %s (req#%d)\n", mark, e.URL, e.Status, serverName(e), e.Method, e.Proof)
		if e.Exposed {
			p("  critical: exposed without authentication — tools/list answered with %d tools and no credentials (req#%d)\n", e.Tools, e.ExposedProof)
		}
		if v := e.Attestation; v != nil {
			if v.Error != "" {
				p("  check failed: %s\n", v.Error)
			} else {
				p("  checked: %.2f/100 grade %s, %d failing, attestation %s\n", v.Score, v.Grade, v.Failing, v.File)
			}
		}
	}
	for _, e := range res.Disappeared {
		p("\n! %s  [disappeared]  last seen %s\n", e.URL, e.LastSeen.Format("2006-01-02 15:04 MST"))
	}
	for _, pr := range res.Protected {
		p("\n· %s answered 401 to an unauthenticated handshake (req#%d); not proven to be MCP\n", pr.URL, pr.Proof)
	}
	if len(res.Blocked) > 0 {
		p("\nnot contacted, because no target named them: %s\n", strings.Join(res.Blocked, ", "))
	}
}

// serverName is how an endpoint's server introduced itself.
func serverName(e Endpoint) string {
	if e.Server == "" {
		return "an unnamed server"
	}
	if e.Version == "" {
		return e.Server
	}
	return e.Server + " " + e.Version
}

// sarifLog is the subset of SARIF 2.1.0 discovery writes.
type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID               string       `json:"id"`
	ShortDescription sarifMessage `json:"shortDescription"`
	DefaultConfig    sarifConfig  `json:"defaultConfiguration"`
}

type sarifConfig struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID    string          `json:"ruleId"`
	Level     string          `json:"level"`
	Message   sarifMessage    `json:"message"`
	Locations []sarifLocation `json:"locations"`
	// PartialFingerprints keep one alert per endpoint across nightly runs.
	PartialFingerprints map[string]string `json:"partialFingerprints"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysical `json:"physicalLocation"`
}

type sarifPhysical struct {
	ArtifactLocation sarifArtifact `json:"artifactLocation"`
}

type sarifArtifact struct {
	URI string `json:"uri"`
}

// WriteSARIF writes the result as SARIF 2.1.0, so an exposed endpoint
// raises a code-scanning alert beside everything else passmcp reports.
func WriteSARIF(w io.Writer, res *Result, version string) error {
	run := sarifRun{Tool: sarifTool{Driver: sarifDriver{
		Name: "passmcp discover", Version: version, InformationURI: "https://satellion.com/passmcp/docs/discovery/",
		Rules: []sarifRule{
			{ID: RuleEndpoint, ShortDescription: sarifMessage{Text: "An MCP endpoint was found among the named targets"}, DefaultConfig: sarifConfig{Level: "note"}},
			{ID: RuleExposed, ShortDescription: sarifMessage{Text: "critical: exposed without authentication"}, DefaultConfig: sarifConfig{Level: "error"}},
			{ID: RuleDisappeared, ShortDescription: sarifMessage{Text: "An endpoint a previous run found is gone"}, DefaultConfig: sarifConfig{Level: "warning"}},
		},
	}}, Results: []sarifResult{}}
	for _, e := range res.Endpoints {
		run.Results = append(run.Results, sarifFor(RuleEndpoint, "note", e.URL,
			fmt.Sprintf("%s endpoint (%s): %s proven by %s (req#%d)", e.Status, serverName(e), e.URL, e.Method, e.Proof)))
		if e.Exposed {
			run.Results = append(run.Results, sarifFor(RuleExposed, "error", e.URL,
				fmt.Sprintf("critical: exposed without authentication: %s listed %d tools to a client with no credentials (req#%d)", e.URL, e.Tools, e.ExposedProof)))
		}
	}
	for _, e := range res.Disappeared {
		run.Results = append(run.Results, sarifFor(RuleDisappeared, "warning", e.URL,
			fmt.Sprintf("%s was last seen %s and is no longer found", e.URL, e.LastSeen.UTC().Format("2006-01-02T15:04:05Z"))))
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(sarifLog{Schema: "https://json.schemastore.org/sarif-2.1.0.json", Version: "2.1.0", Runs: []sarifRun{run}})
}

// sarifFor builds one result located at an endpoint.
func sarifFor(rule, level, uri, text string) sarifResult {
	return sarifResult{
		RuleID: rule, Level: level, Message: sarifMessage{Text: text},
		Locations:           []sarifLocation{{PhysicalLocation: sarifPhysical{ArtifactLocation: sarifArtifact{URI: uri}}}},
		PartialFingerprints: map[string]string{"passmcpDiscovery/v1": rule + "@" + uri},
	}
}
