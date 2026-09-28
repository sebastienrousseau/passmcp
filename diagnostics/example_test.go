// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics_test

import (
	"encoding/json"
	"fmt"

	"satellion.com/passmcp/diagnostics"
)

// A tool declares an inputSchema, and an agent will send whatever the model
// produces. Validate answers the question that matters before a call goes
// out: would this argument object satisfy the contract the tool published?
func ExampleValidate() {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": {
			"email":  {"type": "string", "minLength": 3},
			"limit":  {"type": "integer", "minimum": 1, "maximum": 100}
		},
		"required": ["email"],
		"additionalProperties": false
	}`)

	value := json.RawMessage(`{"email": "", "limit": 500, "sort": "asc"}`)

	for _, v := range diagnostics.Validate(schema, value) {
		fmt.Println(v)
	}
	// Output:
	// $.email: shorter than minLength 3
	// $.limit: above maximum 100
	// $: unexpected property "sort"
}

// $ref and $defs are what pydantic, zod and the official SDKs emit for any
// nested model, so a validator that skips them passes every schema it
// cannot read. Local pointers are resolved.
func ExampleValidate_ref() {
	schema := json.RawMessage(`{
		"type": "object",
		"properties": { "user": {"$ref": "#/$defs/user"} },
		"required": ["user"],
		"$defs": {
			"user": {
				"type": "object",
				"properties": {"id": {"type": "integer"}},
				"required": ["id"]
			}
		}
	}`)

	fmt.Println(diagnostics.Validate(schema, json.RawMessage(`{"user": {"id": "not-a-number"}}`)))
	// Output:
	// [$.user.id: expected type integer, got string]
}
