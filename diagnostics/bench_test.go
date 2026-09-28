// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"encoding/json"
	"testing"
)

var benchSchema = json.RawMessage(`{"type":"object","required":["q","n","tags"],"properties":{"q":{"type":"string","minLength":3},"n":{"type":"integer","minimum":1,"maximum":9},"tags":{"type":"array","items":{"type":"string"},"minItems":2},"nested":{"type":"object","properties":{"x":{"enum":["a","b"]}}}}}`)

func BenchmarkValidate(b *testing.B) {
	doc := json.RawMessage(`{"q":"abc","n":3,"tags":["x","y"],"nested":{"x":"a"}}`)
	for i := 0; i < b.N; i++ {
		Validate(benchSchema, doc)
	}
}

func BenchmarkArguments(b *testing.B) {
	g := NewGenerator(1)
	g.FillOptional = true
	for i := 0; i < b.N; i++ {
		_, _ = g.Arguments(benchSchema)
	}
}
