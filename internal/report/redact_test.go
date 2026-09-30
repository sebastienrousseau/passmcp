// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/probe"
	"satellion.com/passmcp/internal/telemetry"
)

// A server that reflects the operator's token back — in a description, an
// error, a finding's quoted text — must not get it into the report.
func TestReportMasksReflectedSecrets(t *testing.T) {
	const secret = "reflected-s3cr3t-77"
	red := &telemetry.Redactor{}
	red.Add(secret)
	with := func(s string) string { return s + " " + secret }

	findings := []probe.Finding{{ID: "x", Title: with("t"), Detail: with("d"), Advice: with("a"), Evidence: []string{with("req#1")}}}
	phases := []probe.PhaseResult{{Name: "catalog", Summary: with("s"), Findings: findings}}
	tools := []probe.ToolResult{{Name: "t", ToolError: with("e"), ProtoError: with("p"), NegativeTest: with("n"), SchemaIssues: []string{with("i")}}}
	r := &Report{
		Phases: phases,
		Catalog: Catalog{
			Tools:     []ToolSummary{{Name: "t", Title: with("title"), Description: with("desc")}},
			Resources: []passmcp.Resource{{URI: "https://x/r?token=" + secret, Name: with("n"), Title: with("t"), Description: with("d")}},
			Templates: []passmcp.ResourceTemplate{{Name: with("n"), Title: with("t"), Description: with("d")}},
			Prompts:   []passmcp.Prompt{{Name: "p", Title: with("t"), Description: with("d")}},
		},
		Execution: Execution{
			Tools:     tools,
			Resources: []probe.ResourceResult{{URI: "https://x/r?token=" + secret, Error: with("e")}},
			Prompts:   []probe.PromptResult{{Name: "p", Error: with("e"), NegativeTest: with("n")}},
		},
	}
	r.maskSecrets(red)
	b, err := json.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(b), secret) {
		t.Fatalf("a reflected secret survived into the report:\n%s", b)
	}
	// The session's own data is untouched: the report masked copies.
	if !strings.Contains(findings[0].Detail, secret) || !strings.Contains(tools[0].ToolError, secret) || !strings.Contains(phases[0].Summary, secret) {
		t.Fatal("masking must not edit the session the report was built from")
	}
	// A nil redactor and empty sections are no-ops.
	empty := &Report{}
	empty.maskSecrets(nil)
	empty.maskSecrets(red)
	if empty.Phases != nil || empty.Catalog.Resources != nil {
		t.Error("masking an empty report must leave it empty")
	}
}
