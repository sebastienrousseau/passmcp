// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"
)

// TestGeneratorSurvivesHostileBounds is the regression for a panic: a
// schema declaring maximum 1e19 overflowed the int64 conversion and reached
// rand.Int64N with a non-positive argument. Generated code emits bounds
// like that for "unbounded" fields, so it took no malice to crash a run.
func TestGeneratorSurvivesHostileBounds(t *testing.T) {
	schemas := map[string]string{
		"int64 overflow":     `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":0,"maximum":1e19}}}`,
		"negative overflow":  `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":-1e19,"maximum":0}}}`,
		"both overflow":      `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":-1e300,"maximum":1e300}}}`,
		"inverted bounds":    `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":10,"maximum":1}}}`,
		"exclusive collapse": `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","exclusiveMinimum":5,"exclusiveMaximum":6}}}`,
		"huge minLength":     `{"type":"object","required":["s"],"properties":{"s":{"type":"string","minLength":1000000000}}}`,
		"huge minItems":      `{"type":"object","required":["a"],"properties":{"a":{"type":"array","minItems":1000000000,"items":{"type":"string"}}}}`,
		"only maximum":       `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","maximum":1e19}}}`,
		"only minimum":       `{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":1e19}}}`,
	}
	for name, schema := range schemas {
		t.Run(name, func(t *testing.T) {
			g := NewGenerator(1)
			g.FillOptional = true
			args, err := g.Arguments(json.RawMessage(schema))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			b, err := json.Marshal(args)
			if err != nil {
				t.Fatalf("arguments must be encodable: %v", err)
			}
			// A generated request must stay a request, not a payload.
			if len(b) > 1<<20 {
				t.Errorf("generated %d bytes of arguments", len(b))
			}
		})
	}
}

const refSchema = `{
  "type":"object",
  "required":["addr"],
  "properties":{"addr":{"$ref":"#/$defs/Address"}},
  "$defs":{"Address":{"type":"object","required":["city","zip"],
    "properties":{"city":{"type":"string"},"zip":{"type":"integer","minimum":1000,"maximum":9999}}}}
}`

// TestValidateResolvesLocalRefs: pydantic, zod and the official SDKs all
// emit $defs plus $ref for any nested model. A validator that ignores $ref
// reports no violations for those schemas at all — a false pass, in a tool
// whose whole claim is that nothing is reported as passing without evidence.
func TestValidateResolvesLocalRefs(t *testing.T) {
	bad := `{"addr":{"city":123}}`
	issues := Validate(json.RawMessage(refSchema), json.RawMessage(bad))
	joined := strings.Join(issues, "; ")
	if !strings.Contains(joined, "missing required property \"zip\"") {
		t.Errorf("a required property behind a $ref must be checked: %v", issues)
	}
	if !strings.Contains(joined, "expected type string") {
		t.Errorf("a type behind a $ref must be checked: %v", issues)
	}
	if got := Validate(json.RawMessage(refSchema), json.RawMessage(`{"addr":{"city":"Paris","zip":7500}}`)); len(got) != 0 {
		t.Errorf("a conforming value must produce no violations: %v", got)
	}
}

func TestGeneratorResolvesLocalRefs(t *testing.T) {
	args, err := NewGenerator(7).Arguments(json.RawMessage(refSchema))
	if err != nil {
		t.Fatal(err)
	}
	addr, ok := args["addr"].(map[string]any)
	if !ok {
		t.Fatalf("addr was not built from its $ref: %#v", args)
	}
	if _, ok := addr["city"]; !ok {
		t.Errorf("nested required property missing: %#v", addr)
	}
	// What the generator produces must satisfy the schema it came from.
	b, _ := json.Marshal(args)
	if issues := Validate(json.RawMessage(refSchema), b); len(issues) != 0 {
		t.Errorf("generated arguments violate their own schema: %v", issues)
	}
}

// A self-referential model must terminate rather than recurse forever.
func TestRecursiveRefTerminates(t *testing.T) {
	schema := `{"type":"object","properties":{"next":{"$ref":"#"}}}`
	if got := Validate(json.RawMessage(schema), json.RawMessage(`{"next":{"next":{"next":{}}}}`)); len(got) != 0 {
		t.Errorf("recursive schema: %v", got)
	}
	defs := `{"type":"object","required":["node"],"properties":{"node":{"$ref":"#/$defs/Node"}},"$defs":{"Node":{"type":"object","properties":{"next":{"$ref":"#/$defs/Node"}}}}}`
	if _, err := NewGenerator(1).Arguments(json.RawMessage(defs)); err != nil {
		t.Errorf("recursive $defs: %v", err)
	}
}

// An unresolvable reference is reported, not silently passed over.
func TestExternalRefIsReported(t *testing.T) {
	schema := `{"type":"object","properties":{"x":{"$ref":"https://example.com/other.json"}}}`
	issues := Validate(json.RawMessage(schema), json.RawMessage(`{"x":1}`))
	if len(issues) == 0 || !strings.Contains(issues[0], "outside the document") {
		t.Errorf("an external $ref must be reported as unchecked, got %v", issues)
	}
	broken := `{"type":"object","properties":{"x":{"$ref":"#/$defs/Missing"}}}`
	if got := Validate(json.RawMessage(broken), json.RawMessage(`{"x":1}`)); len(got) == 0 {
		t.Error("a dangling local pointer must be reported")
	}
}

// Deep nesting must be bounded rather than exhausting the stack.
func TestValidateDepthIsBounded(t *testing.T) {
	depth := MaxSchemaDepth * 4
	schema := strings.Repeat(`{"type":"array","items":`, depth) + `{"type":"string"}` + strings.Repeat(`}`, depth)
	value := strings.Repeat(`[`, depth) + `"x"` + strings.Repeat(`]`, depth)
	issues := Validate(json.RawMessage(schema), json.RawMessage(value))
	joined := strings.Join(issues, "; ")
	if !strings.Contains(joined, "nests deeper") {
		t.Errorf("a deeply nested schema must stop with a note, got %v", len(issues))
	}
}

func TestResolverPointerEscaping(t *testing.T) {
	// RFC 6901 escaping: ~1 is "/" and ~0 is "~".
	schema := `{"type":"object","properties":{"x":{"$ref":"#/$defs/a~1b"}},"$defs":{"a/b":{"type":"string"}}}`
	if got := Validate(json.RawMessage(schema), json.RawMessage(`{"x":1}`)); len(got) == 0 {
		t.Error("an escaped pointer must resolve and then catch the type error")
	}
	arr := `{"type":"object","properties":{"x":{"$ref":"#/list/1"}},"list":[{"type":"number"},{"type":"string"}]}`
	if got := Validate(json.RawMessage(arr), json.RawMessage(`{"x":1}`)); len(got) == 0 {
		t.Error("an array index pointer must resolve")
	}
}

// TestValidateIsDeterministic pins the ordering of the violation list.
//
// Violations are collected by walking `properties`, which is a map, so
// before this the same schema and value returned the same problems in a
// different order run to run. Two things depended on that not happening:
// a report somebody diffs against a previous run, and any test asserting
// the output — which is how it was found, as a godoc example that passed
// locally and failed on CI twice in six runs.
func TestValidateIsDeterministic(t *testing.T) {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"alpha":   {"type": "integer"},
			"bravo":   {"type": "integer"},
			"charlie": {"type": "integer"},
			"delta":   {"type": "integer"},
			"echo":    {"type": "integer"},
			"foxtrot": {"type": "integer"}
		},
		"additionalProperties": false
	}`)
	value := json.RawMessage(`{"alpha":"x","bravo":"x","charlie":"x","delta":"x","echo":"x","foxtrot":"x"}`)

	first := Validate(schema, value)
	if len(first) != 6 {
		t.Fatalf("expected six violations, got %d: %v", len(first), first)
	}
	// Enough iterations that map ordering would differ at least once.
	for i := range 50 {
		got := Validate(schema, value)
		if !slices.Equal(got, first) {
			t.Fatalf("run %d returned a different order:\n first: %v\n got:   %v", i, first, got)
		}
	}
	if !slices.IsSorted(first) {
		t.Errorf("violations should be sorted so a report diffs cleanly: %v", first)
	}
}
