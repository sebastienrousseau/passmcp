// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"satellion.com/passmcp"
)

func gen(t *testing.T, schema string, fill bool) map[string]any {
	t.Helper()
	g := NewGenerator(7)
	g.FillOptional = fill
	out, err := g.Arguments(json.RawMessage(schema))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGeneratorBranches(t *testing.T) {
	a := gen(t, `{"type":"object","required":["a","b","c","d","e","f","g","h","i","j","k","l","m","n","o","p","q"],"properties":{
	  "a":{"oneOf":[{"type":"integer","minimum":5,"maximum":5}]},
	  "b":{"anyOf":[{"type":"boolean"}]},
	  "c":{"allOf":[{"type":"number","minimum":2,"maximum":2}]},
	  "d":{"type":"array","minItems":2},
	  "e":{"type":"integer","minimum":10},
	  "f":{"type":"integer","maximum":10},
	  "g":{"type":"number","minimum":1.5},
	  "h":{"type":"number","maximum":1.5},
	  "i":{"type":"number"},
	  "j":{"type":"integer","exclusiveMinimum":3,"exclusiveMaximum":5},
	  "k":{"type":"string","pattern":"^x"},
	  "l":{"type":"string","description":"the name of it"},
	  "m":{"type":"string","description":"search query","maxLength":3},
	  "n":{"type":["null","integer"]},
	  "o":{"type":"null"},
	  "p":{"properties":{"z":{"type":"string","format":"email"}},"required":["z"]},
	  "q":{"items":{"type":"string","format":"uri"}}
	}}`, false)
	if a["a"] != int64(5) || a["c"] != float64(2) || len(a["d"].([]any)) != 2 || a["d"].([]any)[0] != "item" {
		t.Errorf("combinators/array: %v", a)
	}
	if v := a["e"].(int64); v < 10 || v > 19 {
		t.Errorf("min only: %v", v)
	}
	if v := a["f"].(int64); v > 10 || v < 1 {
		t.Errorf("max only: %v", v)
	}
	if v := a["g"].(float64); v < 1.5 {
		t.Errorf("float min: %v", v)
	}
	if v := a["h"].(float64); v > 1.5 {
		t.Errorf("float max: %v", v)
	}
	if _, ok := a["i"].(float64); !ok {
		t.Errorf("plain number: %v", a["i"])
	}
	if a["j"] != int64(4) {
		t.Errorf("exclusive bounds: %v", a["j"])
	}
	if a["k"] != "probe" || a["l"] != "Example" || a["m"] != "exa" {
		t.Errorf("strings: %v %v %v", a["k"], a["l"], a["m"])
	}
	if _, ok := a["n"].(int64); !ok || a["o"] != nil {
		t.Errorf("type list / null: %v %v", a["n"], a["o"])
	}
	if a["p"].(map[string]any)["z"] != "probe@example.com" || a["q"].([]any)[0] != "https://example.com/probe" {
		t.Errorf("inferred object/array: %v %v", a["p"], a["q"])
	}
	for f, want := range map[string]string{"date": "2026-01-15", "date-time": "2026-01-15T10:30:00Z", "time": "10:30:00Z", "uuid": "123e4567-e89b-12d3-a456-426614174000", "ipv4": "192.0.2.1", "hostname": "example.com", "url": "https://example.com/probe"} {
		out := gen(t, `{"type":"object","required":["v"],"properties":{"v":{"type":"string","format":"`+f+`"}}}`, false)
		if out["v"] != want {
			t.Errorf("format %s = %v", f, out["v"])
		}
	}
	// Depth cap: nested objects below MaxDepth come back as nil.
	deep := `{"type":"object","required":["a"],"properties":{"a":{"type":"object","required":["b"],"properties":{"b":{"type":"object","required":["c"],"properties":{"c":{"type":"string"}}}}}}}`
	g := NewGenerator(1)
	g.MaxDepth = 1
	out, _ := g.Arguments(json.RawMessage(deep))
	if inner, _ := out["a"].(map[string]any); inner == nil || inner["b"] != nil {
		t.Errorf("depth cap not applied: %v", out)
	}
	// Non-object top-level schema yields an empty object; null schema too.
	if out := gen(t, `{"type":"string"}`, false); len(out) != 0 {
		t.Errorf("non-object: %v", out)
	}
	if out := gen(t, `null`, false); len(out) != 0 {
		t.Errorf("null: %v", out)
	}
	// Properties that are not schemas are skipped; examples are used.
	if out := gen(t, `{"type":"object","required":["x","y"],"properties":{"x":5,"y":{"examples":["ex"]}}}`, false); out["y"] != "ex" || out["x"] != nil {
		t.Errorf("non-schema property: %v", out)
	}
	if _, ok := num(json.Number("3")); !ok {
		t.Error("json.Number")
	}
	if _, ok := num(int64(3)); !ok {
		t.Error("int64")
	}
	if typeOf(map[string]any{"type": []any{"null"}}) != "string" {
		t.Error("only-null type list defaults to string")
	}
}

func TestValidateBranches(t *testing.T) {
	cases := []struct {
		schema, value string
		issues        int
	}{
		{`{"allOf":[{"type":"string"},{"minLength":3}]}`, `"ab"`, 1},
		{`{"type":"object","additionalProperties":{"type":"integer"}}`, `{"x":1.5}`, 1},
		{`{"type":"integer"}`, `"s"`, 1},
		{`{"const":1}`, `2`, 1},
		{`{"type":"string","minLength":2,"maxLength":3}`, `"abcd"`, 1},
		{`{"type":["string","null"]}`, `null`, 0},
		{`{"type":["string","null"]}`, `1`, 1},
		{`{"type":"boolean"}`, `true`, 0},
		{`{"type":"number"}`, `"x"`, 1},
		{`{"type":"array","items":{"type":"integer"}}`, `{"a":1}`, 1},
		{`{"type":"object"}`, `[1]`, 1},
		{`{"type":"null"}`, `false`, 1},
		{`{"type":"unknown-type"}`, `1`, 0},
		{`{"type":3}`, `1`, 0},
		{`{"anyOf":[3,{"type":"integer"}]}`, `1`, 0},
		{`{"type":"object","properties":{"a":{"type":"integer"}},"additionalProperties":true}`, `{"a":1,"b":2}`, 0},
	}
	for _, c := range cases {
		got := Validate(json.RawMessage(c.schema), json.RawMessage(c.value))
		if len(got) != c.issues {
			t.Errorf("%s vs %s: got %v want %d", c.schema, c.value, got, c.issues)
		}
	}
	if jsonTypeName(json.Number("1")) != "number" || jsonTypeName(true) != "boolean" || jsonTypeName(nil) != "null" || jsonTypeName(struct{}{}) == "" {
		t.Error("jsonTypeName")
	}
	if Validate(json.RawMessage(`{"type":"object"}`), json.RawMessage(`{bad`)) == nil {
		t.Error("invalid value json")
	}
}

func TestLatenciesAndLimiterEdges(t *testing.T) {
	var l Latencies
	l.Add(3)
	l.Add(1)
	l.Add(2)
	if l.Percentile(0) != 1 || l.Percentile(-5) != 1 || l.Percentile(150) != 3 || l.Percentile(1) != 1 {
		t.Errorf("percentile bounds: %v %v %v", l.Percentile(0), l.Percentile(150), l.Percentile(1))
	}
	var z Latencies
	z.Add(0)
	z.Add(0)
	z.Add(0)
	if !z.IsOutlier(time.Second, 4, time.Millisecond) {
		t.Error("zero median: anything above floor is an outlier")
	}
	if NewLimiter(1, 0).burst != 1 {
		t.Error("burst floor")
	}
	lim := NewLimiter(1000, 3)
	for i := 0; i < 3; i++ {
		if err := lim.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
}

type errModel struct{}

func (errModel) Step(context.Context, *Conversation) (Action, error) {
	return Action{}, errors.New("model down")
}

type structuredCaller struct{}

func (structuredCaller) CallTool(context.Context, string, any) (*passmcp.CallToolResult, error) {
	return &passmcp.CallToolResult{Content: []passmcp.Content{{Type: "text", Text: "t"}}, StructuredContent: json.RawMessage(`{"a":1}`)}, nil
}

type failingCaller struct{}

func (failingCaller) CallTool(context.Context, string, any) (*passmcp.CallToolResult, error) {
	return nil, errors.New("transport down")
}

func TestAgentLoopMoreBranches(t *testing.T) {
	yes := true
	tools := []passmcp.Tool{{Name: "ro", Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: &yes}}}
	budget := AgentBudget{MaxTurns: 3, MaxToolCalls: 1, MaxRepeats: 5, TurnTimeout: time.Second}
	out := runAgent(context.Background(), structuredCaller{}, errModel{}, tools, "t", budget, Policy{}, nil)
	if out.Completed || len(out.Findings) != 1 || out.Findings[0] != "model error: model down" {
		t.Errorf("model error: %+v", out)
	}
	// Structured content appended; then tool-call cap reached on the second call.
	m := &scripted{[]Action{{ToolName: "ro", Arguments: map[string]any{"q": "1"}}, {ToolName: "ro", Arguments: map[string]any{"q": "2"}}, {Final: "x"}}}
	out = runAgent(context.Background(), structuredCaller{}, m, tools, "t", budget, Policy{}, nil)
	if out.ToolCalls != 1 || len(out.Transcript) == 0 || out.Transcript[0].Result != "t\n{\"a\":1}" || len(out.Findings) != 1 {
		t.Errorf("cap: %+v", out)
	}
	// Transport error counts as failed.
	m = &scripted{[]Action{{ToolName: "ro", Arguments: map[string]any{"q": "1"}}, {Final: "x"}}}
	out = runAgent(context.Background(), failingCaller{}, m, tools, "t", budget, Policy{}, nil)
	if out.FailedCalls != 1 || out.Transcript[0].Error != "transport down" {
		t.Errorf("transport error: %+v", out)
	}
	// Cancelled context trips the limiter.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	lim := NewLimiter(0.001, 1)
	_ = lim.Wait(context.Background())
	out = runAgent(ctx, structuredCaller{}, m, tools, "t", budget, Policy{}, lim)
	if len(out.Findings) != 1 || out.Findings[0][:9] != "cancelled" {
		t.Errorf("cancel: %+v", out)
	}
	if issues := validateArgs(passmcp.Tool{InputSchema: json.RawMessage(`{"type":"object"}`)}, map[string]any{"f": func() {}}); len(issues) != 1 {
		t.Errorf("unencodable args: %v", issues)
	}
}
