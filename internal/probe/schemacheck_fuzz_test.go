// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import "testing"

// FuzzSchemaValid feeds the structural schema check whatever a server might
// put in an inputSchema. It must never panic, must finish on a schema that
// refers to itself, and must stay inside its issue cap.
func FuzzSchemaValid(f *testing.F) {
	for _, seed := range []string{
		`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}`,
		`{"$ref":"#"}`,
		`{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`,
		`{"$anchor":"me","properties":{"self":{"$ref":"#me"}}}`,
		`{"$ref":"#/properties/a","properties":{"a":{"$ref":"#/properties/a"}}}`,
		`{"items":[{"$ref":"#/items/0"}],"prefixItems":[{"$ref":"#/prefixItems/0"}]}`,
		`{"$ref":"#/%7e0/~1/00/-1"}`,
		`{"type":["string",1,"string"],"required":[1,"x"],"$schema":7}`,
		`{"allOf":[],"anyOf":{},"not":"x","enum":1}`,
		`[{"$ref":"#/0"}]`,
		`"x"`,
		`null`,
		``,
	} {
		f.Add([]byte(seed))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		issues := checkSchemaDoc(data)
		if len(issues) > maxSchemaIssues {
			t.Fatalf("%d issues, over the cap of %d", len(issues), maxSchemaIssues)
		}
		for _, is := range issues {
			if is.Level < schemaInfo || is.Level > schemaInvalid {
				t.Fatalf("issue with level %d out of range: %+v", is.Level, is)
			}
		}
	})
}
