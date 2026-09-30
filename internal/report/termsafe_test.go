// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/probe"
)

// hostileSeq is what a server that wanted to rewrite the operator's
// terminal would put in a string: clear the screen, retitle the window,
// and a carriage return to overwrite the line it is on.
const hostileSeq = "\x1b[2J\x1b]0;owned\x07\rok\u009b1A"

// hostileReport is a report whose every server-chosen string carries
// terminal control sequences.
func hostileReport() *Report {
	r := bigReport(2)
	r.Server = &ServerInfo{Name: "srv" + hostileSeq, Title: "t" + hostileSeq, Version: "1" + hostileSeq}
	r.Blocked = ""
	r.Phases[0].Findings[0].Detail = "detail" + hostileSeq
	r.Phases[0].Findings[0].Evidence = []string{"req#1", hostileSeq}
	r.Catalog.Tools = []ToolSummary{{Name: "tool" + hostileSeq, Description: "desc" + hostileSeq}}
	r.Execution.Tools = []probe.ToolResult{{Name: "tool" + hostileSeq, Executed: true, ToolError: "err" + hostileSeq}}
	return r
}

// TestTextAndMarkdownNeutraliseTerminalSequences is the reproducer for
// terminal escape injection: before the renderers cleaned server text,
// every byte of hostileSeq reached the operator's terminal.
func TestTextAndMarkdownNeutraliseTerminalSequences(t *testing.T) {
	r := hostileReport()
	var text, md bytes.Buffer
	Text(&text, r, TextOptions{Verbose: true, Width: 100})
	Markdown(&md, r)
	for name, out := range map[string]string{"text": text.String(), "markdown": md.String()} {
		if i := strings.IndexAny(out, "\x1b\r\a\u009b"); i >= 0 {
			t.Errorf("%s output carries a control character at %d: %q", name, i, out[max(0, i-20):min(len(out), i+20)])
		}
		if !strings.Contains(out, "srv") || !strings.Contains(out, "detail") {
			t.Errorf("%s output lost the text around the sequence", name)
		}
	}
	// The report the caller holds is not rewritten: the JSON rendering
	// is still owed exactly what the server sent.
	if r.Server.Name != "srv"+hostileSeq || r.Phases[0].Findings[0].Detail != "detail"+hostileSeq {
		t.Error("rendering text modified the report")
	}
}

// TestJSONKeepsServerTextFaithful pins the other half of the choice: the
// machine rendering escapes control characters itself and is not cleaned.
func TestJSONKeepsServerTextFaithful(t *testing.T) {
	b, err := json.Marshal(hostileReport())
	if err != nil {
		t.Fatal(err)
	}
	var back Report
	if err := json.Unmarshal(b, &back); err != nil {
		t.Fatal(err)
	}
	if back.Server.Name != "srv"+hostileSeq {
		t.Errorf("JSON round trip changed server text: %q", back.Server.Name)
	}
	if bytes.ContainsRune(b, 0x1b) {
		t.Error("JSON carries a raw ESC; the encoder should have escaped it")
	}
}
