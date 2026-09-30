// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"fmt"
	"strings"
	"testing"

	"satellion.com/passmcp/internal/creds"
)

// issueAt finds the issue at ptr, or reports that there is none.
func issueAt(is []schemaIssue, ptr string) (schemaIssue, bool) {
	for _, i := range is {
		if i.Pointer == ptr {
			return i, true
		}
	}
	return schemaIssue{}, false
}

func TestSchemaDocAcceptsValidSchemas(t *testing.T) {
	for _, s := range []string{
		`true`,
		`false`,
		`{}`,
		`{"type":"object","properties":{"a":{"type":"string"}},"required":["a"]}`,
		`{"type":["string","null"]}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`,
		`{"$schema":"https://json-schema.org/draft/2020-12/schema#","type":"object"}`,
		`{"$defs":{"x":{"type":"integer"}},"properties":{"a":{"$ref":"#/$defs/x"}}}`,
		`{"properties":{"a":{"$ref":"#"}}}`,
		`{"$defs":{"a/b":{"type":"string"},"c d":{}},"properties":{"x":{"$ref":"#/$defs/a~1b"},"y":{"$ref":"#/$defs/c%20d"}}}`,
		`{"prefixItems":[{"type":"string"}],"items":{"type":"number"}}`,
		`{"allOf":[{"$ref":"#/$defs/n"}],"$defs":{"n":{"$anchor":"node","properties":{"next":{"$ref":"#node"}}}}}`,
		`{"anyOf":[{"$ref":"#/anyOf/1"},{"type":"string"}]}`,
		`{"enum":["a","b"],"description":"d","title":"t","default":"a","examples":["a"]}`,
		`{"allOf":[{"properties":{"a":{}}}],"required":["a"]}`,
	} {
		if got := checkSchemaDoc([]byte(s)); len(got) != 0 {
			t.Errorf("%s: want no issues, got %+v", s, got)
		}
	}
}

func TestSchemaDocFindsStructuralErrors(t *testing.T) {
	cases := []struct {
		schema, ptr string
		level       schemaLevel
		msg         string
	}{
		{`"object"`, "", schemaInvalid, "a string"},
		{`[1]`, "", schemaInvalid, "an array"},
		{`{bad`, "", schemaInvalid, "not JSON"},
		{`{"type":"text"}`, "/type", schemaInvalid, `"text"`},
		{`{"type":5}`, "/type", schemaInvalid, "a number"},
		{`{"type":["string",1]}`, "/type/1", schemaInvalid, "a number"},
		{`{"type":["string","string"]}`, "/type/1", schemaInvalid, "repeats"},
		{`{"type":[]}`, "/type", schemaInvalid, "empty"},
		{`{"required":"a"}`, "/required", schemaInvalid, "array of strings"},
		{`{"required":[1]}`, "/required/0", schemaInvalid, "a number"},
		{`{"properties":{"a":{}},"required":["b"]}`, "/required/0", schemaWarn, `"b"`},
		{`{"type":"object","required":["b"]}`, "/required/0", schemaWarn, `"b"`},
		{`{"properties":[]}`, "/properties", schemaInvalid, "object"},
		{`{"properties":{"a":"string"}}`, "/properties/a", schemaInvalid, "a string"},
		{`{"properties":{"a":{"type":"varchar"}}}`, "/properties/a/type", schemaInvalid, `"varchar"`},
		{`{"properties":{"a/b":{"type":7}}}`, "/properties/a~1b/type", schemaInvalid, "a number"},
		{`{"properties":{"a":{"$ref":"#/$defs/missing"}}}`, "/properties/a/$ref", schemaInvalid, "does not resolve"},
		{`{"required":["a"],"properties":{"a":{"$ref":"#/required"}}}`, "/properties/a/$ref", schemaInvalid, "an array"},
		{`{"$ref":"#/$defs/x/0"}`, "/$ref", schemaInvalid, "does not resolve"},
		{`{"$ref":"#nowhere"}`, "/$ref", schemaInvalid, "no $anchor"},
		{`{"$ref":7}`, "/$ref", schemaInvalid, "a number"},
		{`{"$ref":"#/%zz"}`, "/$ref", schemaInvalid, "does not resolve"},
		{`{"$ref":"https://example.com/s.json"}`, "/$ref", schemaInfo, "external"},
		{`{"$schema":"http://json-schema.org/draft-07/schema#"}`, "/$schema", schemaInfo, "draft-07"},
		{`{"$schema":"https://example.com/my-dialect"}`, "/$schema", schemaWarn, "unknown dialect"},
		{`{"$schema":1}`, "/$schema", schemaInvalid, "a number"},
		{`{"x-internal":true}`, "/x-internal", schemaInfo, "unknown keyword"},
		{`{"items":"x"}`, "/items", schemaInvalid, "a string"},
		{`{"items":[{"type":"string"}]}`, "/items", schemaWarn, "prefixItems"},
		{`{"items":[{"type":"varchar"}]}`, "/items/0/type", schemaInvalid, `"varchar"`},
		{`{"allOf":{}}`, "/allOf", schemaInvalid, "array"},
		{`{"allOf":[]}`, "/allOf", schemaInvalid, "empty"},
		{`{"oneOf":[3]}`, "/oneOf/0", schemaInvalid, "a number"},
		{`{"enum":"a"}`, "/enum", schemaInvalid, "array"},
		{`{"$defs":{"a":null}}`, "/$defs/a", schemaInvalid, "null"},
		{`{"not":{"type":"nope"}}`, "/not/type", schemaInvalid, `"nope"`},
	}
	for _, c := range cases {
		got := checkSchemaDoc([]byte(c.schema))
		is, ok := issueAt(got, c.ptr)
		if !ok {
			t.Errorf("%s: no issue at %q; got %+v", c.schema, c.ptr, got)
			continue
		}
		if is.Level != c.level || !strings.Contains(is.Msg, c.msg) {
			t.Errorf("%s at %q: got level %d %q, want level %d containing %q", c.schema, c.ptr, is.Level, is.Msg, c.level, c.msg)
		}
	}
}

// A schema that refers to itself is ordinary — a linked list, a tree — and
// the check must finish on it rather than follow the reference forever.
func TestSchemaDocTerminatesOnSelfReference(t *testing.T) {
	for _, s := range []string{
		`{"$ref":"#"}`,
		`{"$defs":{"a":{"$ref":"#/$defs/b"},"b":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`,
		`{"$anchor":"me","properties":{"self":{"$ref":"#me"}}}`,
	} {
		if got := checkSchemaDoc([]byte(s)); len(got) != 0 {
			t.Errorf("%s: want no issues, got %+v", s, got)
		}
	}
}

// Nesting is bounded, and so is the number of issues one schema can raise:
// the server writes the schema, and it is not allowed to make the report
// arbitrarily large or the walk arbitrarily deep.
func TestSchemaDocIsBounded(t *testing.T) {
	deep := strings.Repeat(`{"properties":{"a":`, 200) + `{}` + strings.Repeat(`}}`, 200)
	got := checkSchemaDoc([]byte(deep))
	if len(got) != 1 || got[0].Level != schemaInfo || !strings.Contains(got[0].Msg, "deeper than") {
		t.Errorf("deep schema: got %+v", got)
	}
	var b strings.Builder
	b.WriteString(`{"properties":{`)
	for i := range 500 {
		if i > 0 {
			b.WriteString(",")
		}
		fmt.Fprintf(&b, `"p%d":{"type":"bogus"}`, i)
	}
	b.WriteString(`}}`)
	got = checkSchemaDoc([]byte(b.String()))
	if len(got) != maxSchemaIssues {
		t.Errorf("issues = %d, want the cap %d", len(got), maxSchemaIssues)
	}
}

func TestSchemaPointerEscaping(t *testing.T) {
	if got := escapePointer("a/b~c"); got != "a~1b~0c" {
		t.Errorf("escapePointer = %q", got)
	}
}

// catalogOnly runs every phase up to the catalog against f.
func catalogOnly(t *testing.T, f *fakeServer) map[string]Finding {
	t.Helper()
	f.acceptAnyToken = true
	_, fs := run(t, f, &creds.Credentials{Mode: creds.ModeBearer, Token: "tok-1234"}, func(o *Options) {
		o.Only = []string{"net", "discovery", "auth", "handshake", "catalog"}
	})
	return fs
}

// schemaTool is a read-only tool with the given input schema.
func schemaTool(name string, schema any) map[string]any {
	return map[string]any{"name": name, "description": "A tool with a hand-written schema", "inputSchema": schema, "annotations": map[string]any{"readOnlyHint": true}}
}

func TestCatalogSchemaValid(t *testing.T) {
	// The fake's own catalogue is valid, and the pass cites the listing it
	// was read from.
	fs := catalogOnly(t, newFakeServer(t))
	expect(t, fs, "catalog.tools.schema_valid", Pass, "schemas")
	if f := fs["catalog.tools.schema_valid"]; len(f.Evidence) == 0 || len(fs["catalog.tools.list"].Evidence) == 0 || f.Evidence[0] != fs["catalog.tools.list"].Evidence[0] {
		t.Errorf("schema_valid must cite the tools/list request: %v vs %v", f.Evidence, fs["catalog.tools.list"].Evidence)
	}

	// Structure a client cannot read fails, naming the tool and pointer.
	f := newFakeServer(t)
	f.q.extraTools = []map[string]any{
		schemaTool("typo", map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"type": "varchar"}}}),
		schemaTool("dangling", map[string]any{"type": "object", "properties": map[string]any{"q": map[string]any{"$ref": "#/$defs/gone"}}}),
	}
	fs = catalogOnly(t, f)
	expect(t, fs, "catalog.tools.schema_valid", Fail, "typo inputSchema#/properties/q/type")
	expect(t, fs, "catalog.tools.schema_valid", Fail, "dangling inputSchema#/properties/q/$ref")
	if fs["catalog.tools.schema_valid"].Severity != Major {
		t.Errorf("severity = %s", fs["catalog.tools.schema_valid"].Severity)
	}

	// An output schema is held to the same structure.
	f = newFakeServer(t)
	bad := schemaTool("out", map[string]any{"type": "object"})
	bad["outputSchema"] = map[string]any{"type": "object", "required": "iso"}
	f.q.extraTools = []map[string]any{bad}
	expect(t, catalogOnly(t, f), "catalog.tools.schema_valid", Fail, "out outputSchema#/required")

	// A required name nothing declares is valid, and still a warning.
	f = newFakeServer(t)
	f.q.extraTools = []map[string]any{schemaTool("undeclared", map[string]any{"type": "object", "properties": map[string]any{"a": map[string]any{}}, "required": []string{"b"}})}
	expect(t, catalogOnly(t, f), "catalog.tools.schema_valid", Warn, `undeclared inputSchema#/required/0`)

	// An unknown keyword is only noted.
	f = newFakeServer(t)
	f.q.extraTools = []map[string]any{schemaTool("vendor", map[string]any{"type": "object", "x-vendor": true})}
	expect(t, catalogOnly(t, f), "catalog.tools.schema_valid", Info, "vendor inputSchema#/x-vendor: unknown keyword")

	// A catalogue whose tools carry no schema at all has nothing to examine.
	f = newFakeServer(t)
	f.q.catalog = "noschema"
	expect(t, catalogOnly(t, f), "catalog.tools.schema_valid", Skip, "no tool declares")
}
