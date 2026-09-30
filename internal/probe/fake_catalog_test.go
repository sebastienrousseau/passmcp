// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"slices"
)

// The fake server's answers for the catalogue and content methods, each
// shaped by the quirks in fake_test.go. Kept apart from the transport and
// authorization scaffolding so neither file grows past what a reader can
// hold.

// toolCatalog is what tools/list answers, shaped by the catalogue knobs.
func (f *fakeServer) toolCatalog() []map[string]any {
	yes, no := true, false
	tools := []map[string]any{
		{"name": "get_time", "description": "Returns the current time in ISO 8601 format", "inputSchema": map[string]any{"type": "object"}, "outputSchema": map[string]any{"type": "object", "required": []string{"iso"}, "properties": map[string]any{"iso": map[string]any{"type": "string"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
		{"name": "search", "description": "Search documents by query string", "inputSchema": map[string]any{"type": "object", "required": []string{"q"}, "properties": map[string]any{"q": map[string]any{"type": "string"}}}, "outputSchema": map[string]any{"type": "object", "required": []string{"hits"}, "properties": map[string]any{"hits": map[string]any{"type": "array"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
		{"name": "lax", "description": "Accepts anything without validation", "inputSchema": map[string]any{"type": "object", "required": []string{"x"}, "properties": map[string]any{"x": map[string]any{"type": "string"}}}, "annotations": map[string]any{"readOnlyHint": yes}},
	}
	if !f.q.readOnlyOnly {
		tools = append(tools, map[string]any{"name": "delete_all", "description": "Deletes every document permanently", "inputSchema": map[string]any{"type": "object"}})
	}
	tools = append(tools, f.q.extraTools...)
	switch f.q.catalog {
	case "dupes":
		tools = append(tools, map[string]any{"name": "get_time", "description": "Duplicate name for the same thing", "inputSchema": map[string]any{"type": "object"}, "annotations": map[string]any{"readOnlyHint": yes}})
	case "bad":
		tools = []map[string]any{
			{"name": "nodesc", "inputSchema": map[string]any{"type": "string"}, "annotations": map[string]any{"readOnlyHint": yes}},
			{"name": "shortdesc", "description": "tiny", "inputSchema": map[string]any{"properties": map[string]any{}}, "outputSchema": map[string]any{"type": "object"}, "annotations": map[string]any{"readOnlyHint": yes}, "title": "T"},
			{"name": "brokenschema", "description": "Has an unparsable input schema", "inputSchema": "not-json-object", "annotations": map[string]any{"readOnlyHint": no, "destructiveHint": no}},
		}
	case "empty":
		tools = nil
	case "noschema":
		// A catalogue with nothing for a schema check to read.
		tools = []map[string]any{{"name": "bare", "description": "A tool that declares no schema at all", "annotations": map[string]any{"readOnlyHint": yes}}}
	}
	return tools
}

// listTools is what one tools/list answers, varied between calls by the
// toolOrder knob; ok is false for a listing that fails.
func (f *fakeServer) listTools() (tools []map[string]any, ok bool) {
	n := f.toolLists.Add(1)
	if f.q.toolsFail || (f.q.toolOrder == "failsecond" && n > 1) {
		return nil, false
	}
	tools = f.toolCatalog()
	if n%2 == 1 {
		return tools, true
	}
	switch f.q.toolOrder {
	case "shuffle":
		slices.Reverse(tools)
	case "grow":
		tools = append(tools, map[string]any{"name": "late_arrival", "description": "A tool registered between two listings", "inputSchema": map[string]any{"type": "object"}, "annotations": map[string]any{"readOnlyHint": true}})
	}
	return tools, true
}

// readContents is what resources/read answers, shaped by the knobs.
func (f *fakeServer) readContents(params json.RawMessage) map[string]any {
	if f.q.resourcesEmpty {
		return map[string]any{"contents": []map[string]any{}}
	}
	var p struct {
		URI string `json:"uri"`
	}
	_ = json.Unmarshal(params, &p)
	item := map[string]any{"uri": p.URI, "mimeType": "text/plain", "text": "hello"}
	switch f.q.readURI {
	case "":
	case "-":
		delete(item, "uri")
	default:
		item["uri"] = f.q.readURI
	}
	return map[string]any{"contents": []map[string]any{item}}
}

// renderPrompt is what prompts/get answers, shaped by the knobs: a result,
// or a refusal code (negative for JSON-RPC, positive for an HTTP status).
func (f *fakeServer) renderPrompt(params json.RawMessage) (map[string]any, int) {
	var p struct {
		Args map[string]string `json:"arguments"`
	}
	_ = json.Unmarshal(params, &p)
	_, hasDoc := p.Args["doc"]
	switch {
	case f.q.promptsFail:
		return nil, -32602
	case !hasDoc && !f.q.promptOptional && !f.q.promptLenient:
		if f.q.promptMissingCode != 0 {
			return nil, f.q.promptMissingCode
		}
		return nil, -32602
	case f.q.promptsEmpty:
		return map[string]any{"messages": []map[string]any{}}, 0
	}
	return map[string]any{"messages": []map[string]any{{"role": "user", "content": map[string]any{"type": "text", "text": "Summarise"}}}}, 0
}
