// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// maskSecrets passes every server-controlled string the report copies out of
// the session through the run's redactor.
//
// The recorder masks telemetry structurally (ADR 0003), but the report takes
// its catalogue, its execution results and its findings' text from the
// session, not from telemetry. A server that reflects the operator's token
// back — in a tool description, an error message or a result a finding
// quotes — would otherwise put it in report.json, report.md and report.html,
// which are exactly the files somebody hands to another person.
//
// It works on copies: the session belongs to the caller, and a surface that
// renders twice must not find its session edited by the first rendering.
// With no secret registered the redactor changes nothing, so a run made
// without credentials renders byte for byte as before.
func (r *Report) maskSecrets(red *telemetry.Redactor) {
	if red == nil {
		return
	}
	for i := range r.Catalog.Tools {
		t := &r.Catalog.Tools[i]
		t.Title, t.Description = red.String(t.Title), red.String(t.Description)
	}
	r.Catalog.Resources = maskResources(r.Catalog.Resources, red)
	r.Catalog.Templates = maskTemplates(r.Catalog.Templates, red)
	r.Catalog.Prompts = maskPrompts(r.Catalog.Prompts, red)
	r.Execution.Tools = maskToolResults(r.Execution.Tools, red)
	r.Execution.Resources = maskResourceResults(r.Execution.Resources, red)
	r.Execution.Prompts = maskPromptResults(r.Execution.Prompts, red)
	r.Phases = maskPhases(r.Phases, red)
}

func maskResources(in []passmcp.Resource, red *telemetry.Redactor) []passmcp.Resource {
	if in == nil {
		return nil
	}
	out := append([]passmcp.Resource(nil), in...)
	for i := range out {
		out[i].Name, out[i].Title, out[i].Description = red.String(out[i].Name), red.String(out[i].Title), red.String(out[i].Description)
		out[i].URI = red.URL(out[i].URI)
	}
	return out
}

func maskTemplates(in []passmcp.ResourceTemplate, red *telemetry.Redactor) []passmcp.ResourceTemplate {
	if in == nil {
		return nil
	}
	out := append([]passmcp.ResourceTemplate(nil), in...)
	for i := range out {
		out[i].Name, out[i].Title, out[i].Description = red.String(out[i].Name), red.String(out[i].Title), red.String(out[i].Description)
	}
	return out
}

func maskPrompts(in []passmcp.Prompt, red *telemetry.Redactor) []passmcp.Prompt {
	if in == nil {
		return nil
	}
	out := append([]passmcp.Prompt(nil), in...)
	for i := range out {
		out[i].Title, out[i].Description = red.String(out[i].Title), red.String(out[i].Description)
	}
	return out
}

func maskToolResults(in []probe.ToolResult, red *telemetry.Redactor) []probe.ToolResult {
	if in == nil {
		return nil
	}
	out := append([]probe.ToolResult(nil), in...)
	for i := range out {
		t := &out[i]
		t.ToolError, t.ProtoError, t.NegativeTest = red.String(t.ToolError), red.String(t.ProtoError), red.String(t.NegativeTest)
		t.SchemaIssues = maskStrings(t.SchemaIssues, red)
	}
	return out
}

func maskResourceResults(in []probe.ResourceResult, red *telemetry.Redactor) []probe.ResourceResult {
	if in == nil {
		return nil
	}
	out := append([]probe.ResourceResult(nil), in...)
	for i := range out {
		out[i].Error, out[i].URI = red.String(out[i].Error), red.URL(out[i].URI)
	}
	return out
}

func maskPromptResults(in []probe.PromptResult, red *telemetry.Redactor) []probe.PromptResult {
	if in == nil {
		return nil
	}
	out := append([]probe.PromptResult(nil), in...)
	for i := range out {
		out[i].Error = red.String(out[i].Error)
	}
	return out
}

// maskPhases copies the phases and their findings before masking, because
// the session's results are shared with whoever else reads the session.
func maskPhases(in []probe.PhaseResult, red *telemetry.Redactor) []probe.PhaseResult {
	if in == nil {
		return nil
	}
	out := append([]probe.PhaseResult(nil), in...)
	for i := range out {
		out[i].Summary = red.String(out[i].Summary)
		fs := append([]probe.Finding(nil), out[i].Findings...)
		for j := range fs {
			f := &fs[j]
			f.Title, f.Detail, f.Advice = red.String(f.Title), red.String(f.Detail), red.String(f.Advice)
			f.Evidence = maskStrings(f.Evidence, red)
		}
		out[i].Findings = fs
	}
	return out
}

func maskStrings(in []string, red *telemetry.Redactor) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = red.String(s)
	}
	return out
}
