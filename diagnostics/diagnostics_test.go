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

func bp(b bool) *bool { return &b }

func TestPolicyDefaults(t *testing.T) {
	ro := passmcp.Tool{Name: "ro", Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: bp(true)}}
	mut := passmcp.Tool{Name: "mut", Annotations: &passmcp.ToolAnnotations{DestructiveHint: bp(false)}}
	destr := passmcp.Tool{Name: "d", Annotations: &passmcp.ToolAnnotations{DestructiveHint: bp(true)}}
	bare := passmcp.Tool{Name: "bare"}

	p := Policy{}
	if !p.Decide(ro).Execute || p.Decide(mut).Execute || p.Decide(destr).Execute || p.Decide(bare).Execute {
		t.Error("default policy must only execute read-only tools")
	}
	if p.Decide(bare).Reason != "no annotations: destructive by spec default" {
		t.Errorf("reason = %q", p.Decide(bare).Reason)
	}
	p = Policy{AllowMutations: true}
	if !p.Decide(mut).Execute || p.Decide(destr).Execute || p.Decide(bare).Execute {
		t.Error("AllowMutations must not unlock destructive tools")
	}
	p = Policy{AllowDestructive: true, Deny: []string{"bare"}}
	if !p.Decide(destr).Execute || p.Decide(bare).Execute {
		t.Error("AllowDestructive unlocks destructive; Deny always wins")
	}
	p = Policy{Only: []string{"mut"}, AllowMutations: true}
	if p.Decide(ro).Execute || !p.Decide(mut).Execute {
		t.Error("Only restricts execution")
	}
}

func TestGeneratorFromSchema(t *testing.T) {
	schema := json.RawMessage(`{
	  "type":"object","required":["q","n","kind","when","tags"],
	  "properties":{
	    "q":{"type":"string","minLength":4},
	    "n":{"type":"integer","minimum":3,"maximum":3},
	    "kind":{"type":"string","enum":["a","b"]},
	    "when":{"type":"string","format":"date-time"},
	    "tags":{"type":"array","items":{"type":"string"},"minItems":2},
	    "opt":{"type":"boolean"},
	    "nested":{"type":"object","required":["x"],"properties":{"x":{"const":7}}}
	  }}`)
	g := NewGenerator(1)
	args, err := g.Arguments(schema)
	if err != nil {
		t.Fatal(err)
	}
	if len(args["q"].(string)) < 4 || args["n"] != int64(3) || args["when"] != "2026-01-15T10:30:00Z" {
		t.Errorf("args = %v", args)
	}
	if k := args["kind"]; k != "a" && k != "b" {
		t.Errorf("enum not honoured: %v", k)
	}
	if len(args["tags"].([]any)) != 2 {
		t.Errorf("minItems not honoured: %v", args["tags"])
	}
	if _, ok := args["opt"]; ok {
		t.Error("optional filled without FillOptional")
	}
	b, _ := json.Marshal(args)
	if issues := Validate(schema, b); len(issues) != 0 {
		t.Errorf("generated args do not validate: %v", issues)
	}
	g.FillOptional = true
	args, _ = g.Arguments(schema)
	if args["nested"].(map[string]any)["x"] != float64(7) {
		t.Errorf("nested const: %v", args["nested"])
	}
	if a, err := g.Arguments(nil); err != nil || len(a) != 0 {
		t.Errorf("nil schema: %v %v", a, err)
	}
	if _, err := g.Arguments(json.RawMessage(`{broken`)); err == nil {
		t.Error("expected parse error")
	}
}

func TestValidate(t *testing.T) {
	schema := json.RawMessage(`{"type":"object","required":["hits","n"],"additionalProperties":false,
	  "properties":{"hits":{"type":"array","items":{"type":"string"}},"n":{"type":"integer","maximum":10},"k":{"enum":["x","y"]}}}`)
	if v := Validate(schema, json.RawMessage(`{"hits":["a"],"n":3,"k":"x"}`)); len(v) != 0 {
		t.Errorf("valid doc flagged: %v", v)
	}
	v := Validate(schema, json.RawMessage(`{"hits":"oops","n":10.5,"k":"z","extra":1}`))
	want := 4
	if len(v) != want {
		t.Errorf("got %d issues, want %d: %v", len(v), want, v)
	}
	if v := Validate(schema, json.RawMessage(`{"hits":[]}`)); len(v) != 1 {
		t.Errorf("missing required: %v", v)
	}
	one := json.RawMessage(`{"oneOf":[{"type":"string"},{"type":"number"}]}`)
	if v := Validate(one, json.RawMessage(`true`)); len(v) == 0 {
		t.Error("oneOf with no match must fail")
	}
	if v := Validate(one, json.RawMessage(`"s"`)); len(v) != 0 {
		t.Errorf("oneOf string: %v", v)
	}
	if v := Validate(nil, json.RawMessage(`1`)); v != nil {
		t.Error("empty schema accepts anything")
	}
}

func TestLatencies(t *testing.T) {
	var l Latencies
	if l.Percentile(50) != 0 || l.Summarize().Count != 0 {
		t.Error("empty latencies must be zero")
	}
	for i := 1; i <= 100; i++ {
		l.Add(time.Duration(i) * time.Millisecond)
	}
	s := l.Summarize()
	if s.P50 != 50*time.Millisecond || s.P95 != 95*time.Millisecond || s.P99 != 99*time.Millisecond || s.Max != 100*time.Millisecond {
		t.Errorf("summary = %+v", s)
	}
	if !l.IsOutlier(600*time.Millisecond, 4, 500*time.Millisecond) || l.IsOutlier(150*time.Millisecond, 4, 500*time.Millisecond) {
		t.Error("outlier detection")
	}
}

func TestLimiter(t *testing.T) {
	l := NewLimiter(50, 1)
	start := time.Now()
	for i := 0; i < 6; i++ {
		if err := l.Wait(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if el := time.Since(start); el < 80*time.Millisecond {
		t.Errorf("limiter too fast: %s", el)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	l2 := NewLimiter(0.001, 1)
	l2.Wait(context.Background())
	if err := l2.Wait(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("err = %v", err)
	}
	if err := (*Limiter)(nil).Wait(ctx); err != nil {
		t.Error("nil limiter must be a no-op")
	}
}

func TestScore(t *testing.T) {
	if s, why := Score(&Report{}); s != 0 || len(why) != 1 {
		t.Errorf("zero tools: %v %v", s, why)
	}
	if s, _ := Score(&Report{ToolsDiscovered: 3}); s != 100 {
		t.Errorf("no execution, no deductions: %v", s)
	}
	rep := &Report{ToolsDiscovered: 4, ToolsExecuted: 2, ToolErrors: 1, SchemaMismatches: []string{"a"}, Latency: Summary{P99: 3 * time.Second}, Unannotated: []string{"x", "y"}}
	s, why := Score(rep)
	if s != 100-25-5-10-2 {
		t.Errorf("score = %v (%v)", s, why)
	}
	rep = &Report{ToolsDiscovered: 1, ToolsExecuted: 1, ProtocolErrors: 1, SchemaMismatches: make([]string, 10), Latency: Summary{P99: 5 * time.Second}, Unannotated: make([]string, 9), MissingSchemas: make([]string, 9), Agent: &AgentOutcome{Findings: make([]string, 9)}}
	if s, _ := Score(rep); s != 0 {
		t.Errorf("floor at zero: %v", s)
	}
}

// scripted model for the agent loop.
type scripted struct{ actions []Action }

func (s *scripted) Step(ctx context.Context, conv *Conversation) (Action, error) {
	i := len(conv.Turns)
	if i >= len(s.actions) {
		return s.actions[len(s.actions)-1], nil
	}
	return s.actions[i], nil
}

type fakeCaller struct{ calls int }

func (f *fakeCaller) CallTool(ctx context.Context, name string, args any) (*passmcp.CallToolResult, error) {
	f.calls++
	if name == "fail" {
		return &passmcp.CallToolResult{IsError: true, Content: []passmcp.Content{{Type: "text", Text: "bad"}}}, nil
	}
	return &passmcp.CallToolResult{Content: []passmcp.Content{{Type: "text", Text: "ok"}}}, nil
}

func TestAgentLoopBudgetsAndPolicy(t *testing.T) {
	tools := []passmcp.Tool{
		{Name: "ro", InputSchema: json.RawMessage(`{"type":"object","required":["q"],"properties":{"q":{"type":"string"}}}`), Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: bp(true)}},
		{Name: "danger"},
		{Name: "fail", Annotations: &passmcp.ToolAnnotations{ReadOnlyHint: bp(true)}},
	}
	budget := AgentBudget{MaxTurns: 4, MaxToolCalls: 10, MaxRepeats: 1, TurnTimeout: time.Second}

	// Completes normally with one valid call.
	m := &scripted{[]Action{{ToolName: "ro", Arguments: map[string]any{"q": "x"}}, {Final: "done"}}}
	fc := &fakeCaller{}
	out := runAgent(context.Background(), fc, m, tools, "t", budget, Policy{}, nil)
	if !out.Completed || out.ToolCalls != 1 || len(out.Findings) != 0 || out.Final != "done" {
		t.Errorf("out = %+v", out)
	}

	// Policy blocks destructive tool; unknown tool and bad args are findings.
	m = &scripted{[]Action{{ToolName: "danger"}, {ToolName: "nope"}, {ToolName: "ro", Arguments: map[string]any{}}, {Final: "x"}}}
	fc = &fakeCaller{}
	out = runAgent(context.Background(), fc, m, tools, "t", budget, Policy{}, nil)
	if fc.calls != 1 || out.Transcript[0].Error != "tool blocked by safety policy" || len(out.Findings) != 2 {
		t.Errorf("out = %+v calls=%d", out, fc.calls)
	}

	// Identical repeated call trips the loop detector.
	m = &scripted{[]Action{{ToolName: "ro", Arguments: map[string]any{"q": "x"}}}}
	out = runAgent(context.Background(), &fakeCaller{}, m, tools, "t", budget, Policy{}, nil)
	if out.Completed || out.ToolCalls != 1 || len(out.Findings) != 1 {
		t.Errorf("repeat: %+v", out)
	}

	// Turn cap with alternating args.
	m = &scripted{[]Action{{ToolName: "ro", Arguments: map[string]any{"q": "1"}}, {ToolName: "ro", Arguments: map[string]any{"q": "2"}}, {ToolName: "fail", Arguments: map[string]any{"q": "3"}}, {ToolName: "ro", Arguments: map[string]any{"q": "4"}}, {ToolName: "ro", Arguments: map[string]any{"q": "5"}}}}
	out = runAgent(context.Background(), &fakeCaller{}, m, tools, "t", budget, Policy{}, nil)
	if out.Completed || out.Turns != 4 || out.FailedCalls != 1 || len(out.Findings) != 1 {
		t.Errorf("turn cap: %+v", out)
	}
}

// TestArgumentsAreReproducibleFromTheSeed pins the contract --seed makes: the
// same seed and schema produce the same arguments. An object with several
// properties is the case that broke it, because the properties were visited
// in Go's randomised map order and each draws from the same generator.
func TestArgumentsAreReproducibleFromTheSeed(t *testing.T) {
	schema := json.RawMessage(`{"type":"object",
		"required":["a","b","c","d","e","f","g","h"],
		"properties":{
			"a":{"type":"integer"},"b":{"type":"integer"},"c":{"type":"number"},
			"d":{"type":"string"},"e":{"type":"integer"},"f":{"type":"number"},
			"g":{"type":"string","enum":["x","y","z"]},"h":{"type":"integer"}}}`)
	first, err := NewGenerator(7).Arguments(schema)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := json.Marshal(first)
	for i := 0; i < 50; i++ {
		got, err := NewGenerator(7).Arguments(schema)
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := json.Marshal(got); string(b) != string(want) {
			t.Fatalf("seed 7 produced different arguments on run %d:\n got %s\nwant %s", i+2, b, want)
		}
	}
}
