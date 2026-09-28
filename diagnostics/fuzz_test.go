// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"encoding/json"
	"testing"
)

func FuzzValidate(f *testing.F) {
	f.Add(`{"type":"object","required":["a"],"properties":{"a":{"type":"integer","maximum":3}}}`, `{"a":2}`)
	f.Add(`{"oneOf":[{"type":"string"},{"type":"number"}]}`, `true`)
	f.Add(`{"type":"array","items":{"enum":["x"]},"maxItems":1}`, `["x","y"]`)
	f.Add(`{broken`, `{}`)
	f.Add(`{}`, `{broken`)
	f.Add(`{"type":"object","properties":{"a":{"$ref":"#/$defs/A"}},"$defs":{"A":{"type":"integer"}}}`, `{"a":"no"}`)
	f.Add(`{"type":"object","properties":{"a":{"$ref":"#"}}}`, `{"a":{"a":{}}}`)
	f.Add(`{"$ref":"#/$defs/missing"}`, `{}`)
	f.Add(`{"$ref":"https://example.com/x.json"}`, `1`)
	f.Fuzz(func(t *testing.T, schema, value string) {
		_ = Validate(json.RawMessage(schema), json.RawMessage(value))
	})
}

func FuzzArguments(f *testing.F) {
	f.Add(`{"type":"object","required":["q","n"],"properties":{"q":{"type":"string","minLength":3},"n":{"type":"integer","minimum":1,"maximum":9}}}`)
	f.Add(`{"type":"object","properties":{"deep":{"type":"object","properties":{"x":{"type":"array","items":{"type":"boolean"},"minItems":2}}}}}`)
	f.Add(`{"anyOf":[{"type":"object","properties":{"a":{"const":1}}}]}`)
	f.Add(`null`)
	f.Add(`{broken`)
	// Bounds that overflow the int64 conversion: this shape panicked
	// rand.Int64N before the generator clamped its bounds.
	f.Add(`{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":0,"maximum":1e19}}}`)
	f.Add(`{"type":"object","required":["n"],"properties":{"n":{"type":"integer","minimum":-1e300,"maximum":1e300}}}`)
	// Sizes that would turn a probe into a payload.
	f.Add(`{"type":"object","required":["s"],"properties":{"s":{"type":"string","minLength":1000000000}}}`)
	f.Add(`{"type":"object","required":["a"],"properties":{"a":{"type":"array","minItems":1000000000,"items":{"type":"string"}}}}`)
	// Local references, including one that points at itself.
	f.Add(`{"type":"object","properties":{"a":{"$ref":"#/$defs/A"}},"$defs":{"A":{"type":"string"}}}`)
	f.Add(`{"type":"object","properties":{"a":{"$ref":"#"}}}`)
	f.Add(`{"$ref":"#/nope"}`)
	f.Fuzz(func(t *testing.T, schema string) {
		g := NewGenerator(1)
		g.FillOptional = true
		args, err := g.Arguments(json.RawMessage(schema))
		if err != nil {
			return
		}
		b, err := json.Marshal(args)
		if err != nil {
			t.Fatalf("generated arguments are not JSON-encodable: %v", err)
		}
		// No schema, however hostile, may turn a diagnostic probe into a
		// payload aimed at the server under test.
		if len(b) > 8<<20 {
			t.Fatalf("generated %d bytes of arguments", len(b))
		}
	})
}
