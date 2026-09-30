// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// A structural check of a JSON Schema, as far as an MCP client depends on
// one: the parts a client reads to generate arguments, validate them, and
// render the tool. It is not a validator of instances and not a full
// meta-schema check, and it is hand-rolled on purpose — the module keeps
// two direct dependencies, and the questions asked here are a few dozen
// lines of tree walking.
//
// It walks the parsed document, never a reference: a $ref is checked by
// resolving its pointer against the root, which is a walk down a finite
// tree, so a schema that refers to itself (a linked list, a tree) is
// checked in one pass and cannot loop. Depth and issue count are both
// bounded, because the server wrote the schema.

// schemaLevel ranks one schema issue.
type schemaLevel int

const (
	// schemaInfo is an observation: an unknown keyword, a reference
	// passmcp does not follow.
	schemaInfo schemaLevel = iota
	// schemaWarn is valid JSON Schema a client is likely to misread.
	schemaWarn
	// schemaInvalid is structure the specification does not allow.
	schemaInvalid
)

// schemaIssue is one structural observation about a schema, addressed by
// JSON pointer from the schema's root.
type schemaIssue struct {
	Level   schemaLevel
	Pointer string
	Msg     string
}

const (
	// maxSchemaDepth bounds how deeply nested subschemas are examined.
	maxSchemaDepth = 64
	// maxSchemaIssues bounds how many issues one schema can raise.
	maxSchemaIssues = 64
	// dialect2020 is the dialect MCP assumes when a schema names none.
	dialect2020 = "https://json-schema.org/draft/2020-12/schema"
)

// kwKind is what a keyword's value must be.
type kwKind int

const (
	kwUnknown    kwKind = iota
	kwAny               // known; its value is not something a client parses as a schema
	kwSchema            // a schema
	kwSchemaMap         // an object whose values are schemas
	kwSchemaList        // a non-empty array of schemas
	kwItems             // a schema, or the pre-2020-12 array form
	kwType
	kwRequired
	kwRef
	kwDialect
	kwArray // an array of anything
)

// keywords are the JSON Schema 2020-12 keywords, plus the earlier drafts'
// that are still common in the wild (definitions, dependencies), which a
// client reads the same way and would be noise to report.
var keywords = map[string]kwKind{
	"$schema": kwDialect, "$ref": kwRef,
	"$id": kwAny, "$anchor": kwAny, "$dynamicRef": kwAny, "$dynamicAnchor": kwAny,
	"$vocabulary": kwAny, "$comment": kwAny, "$recursiveRef": kwAny, "$recursiveAnchor": kwAny,
	"$defs": kwSchemaMap, "definitions": kwSchemaMap, "properties": kwSchemaMap,
	"patternProperties": kwSchemaMap, "dependentSchemas": kwSchemaMap,
	"allOf": kwSchemaList, "anyOf": kwSchemaList, "oneOf": kwSchemaList, "prefixItems": kwSchemaList,
	"not": kwSchema, "if": kwSchema, "then": kwSchema, "else": kwSchema, "contains": kwSchema,
	"additionalProperties": kwSchema, "propertyNames": kwSchema, "unevaluatedItems": kwSchema,
	"unevaluatedProperties": kwSchema, "contentSchema": kwSchema, "additionalItems": kwSchema,
	"items": kwItems, "type": kwType, "required": kwRequired, "enum": kwArray,
	"const": kwAny, "multipleOf": kwAny, "maximum": kwAny, "exclusiveMaximum": kwAny,
	"minimum": kwAny, "exclusiveMinimum": kwAny, "maxLength": kwAny, "minLength": kwAny,
	"pattern": kwAny, "maxItems": kwAny, "minItems": kwAny, "uniqueItems": kwAny,
	"maxContains": kwAny, "minContains": kwAny, "maxProperties": kwAny, "minProperties": kwAny,
	"dependentRequired": kwAny, "dependencies": kwAny, "format": kwAny,
	"contentEncoding": kwAny, "contentMediaType": kwAny,
	"title": kwAny, "description": kwAny, "default": kwAny, "deprecated": kwAny,
	"readOnly": kwAny, "writeOnly": kwAny, "examples": kwAny,
}

// jsonTypes are the seven JSON Schema primitive types.
var jsonTypes = map[string]bool{
	"null": true, "boolean": true, "object": true, "array": true,
	"number": true, "string": true, "integer": true,
}

// olderDialects are the published drafts before 2020-12, by the name a
// reader knows them by.
var olderDialects = map[string]string{
	"http://json-schema.org/draft-04/schema":       "draft-04",
	"http://json-schema.org/draft-06/schema":       "draft-06",
	"http://json-schema.org/draft-07/schema":       "draft-07",
	"https://json-schema.org/draft-07/schema":      "draft-07",
	"https://json-schema.org/draft/2019-09/schema": "2019-09",
}

// checkSchemaDoc parses raw and reports its structural issues.
func checkSchemaDoc(raw json.RawMessage) []schemaIssue {
	var root any
	if err := json.Unmarshal(raw, &root); err != nil {
		return []schemaIssue{{Level: schemaInvalid, Msg: "not JSON: " + truncate(err.Error(), 80)}}
	}
	w := &schemaWalker{root: root}
	w.schema(root, "", 0)
	return w.issues
}

// schemaWalker carries one document's walk: its root, for resolving
// references, and what it found.
type schemaWalker struct {
	root    any
	issues  []schemaIssue
	anchors map[string]bool
}

// add records an issue unless the cap has been reached.
func (w *schemaWalker) add(l schemaLevel, ptr, msg string) {
	if len(w.issues) < maxSchemaIssues {
		w.issues = append(w.issues, schemaIssue{Level: l, Pointer: ptr, Msg: msg})
	}
}

// schema examines one subschema: a boolean, or an object of keywords.
func (w *schemaWalker) schema(v any, ptr string, depth int) {
	if depth > maxSchemaDepth {
		w.add(schemaInfo, ptr, fmt.Sprintf("nested deeper than %d levels; not examined further", maxSchemaDepth))
		return
	}
	switch n := v.(type) {
	case bool:
	case map[string]any:
		for _, k := range sortedKeys(n) {
			w.keyword(n, k, ptr+"/"+escapePointer(k), depth)
		}
	default:
		w.add(schemaInvalid, ptr, "a schema must be an object or a boolean, not "+jsonKind(v))
	}
}

// keyword examines one keyword of a schema object.
func (w *schemaWalker) keyword(n map[string]any, k, ptr string, depth int) {
	switch kind := keywords[k]; kind {
	case kwUnknown:
		w.add(schemaInfo, ptr, "unknown keyword")
	case kwAny:
	case kwSchema, kwSchemaMap, kwSchemaList, kwItems:
		w.subschemas(kind, n[k], ptr, depth)
	default:
		w.value(kind, n, n[k], ptr)
	}
}

// subschemas examines a keyword whose value is, or holds, schemas.
func (w *schemaWalker) subschemas(kind kwKind, v any, ptr string, depth int) {
	switch kind {
	case kwSchema:
		w.schema(v, ptr, depth+1)
	case kwSchemaMap:
		w.schemaMap(v, ptr, depth)
	case kwSchemaList:
		w.schemaList(v, ptr, depth)
	default:
		w.items(v, ptr, depth)
	}
}

// value examines a keyword whose value has a shape of its own.
func (w *schemaWalker) value(kind kwKind, n map[string]any, v any, ptr string) {
	switch kind {
	case kwType:
		w.typeKeyword(v, ptr)
	case kwRequired:
		w.required(n, v, ptr)
	case kwRef:
		w.ref(v, ptr)
	case kwDialect:
		w.dialect(v, ptr)
	default: // kwArray
		if _, ok := v.([]any); !ok {
			w.add(schemaInvalid, ptr, "must be an array, not "+jsonKind(v))
		}
	}
}

// schemaMap examines an object whose every value is a schema.
func (w *schemaWalker) schemaMap(v any, ptr string, depth int) {
	m, ok := v.(map[string]any)
	if !ok {
		w.add(schemaInvalid, ptr, "must be an object of schemas, not "+jsonKind(v))
		return
	}
	for _, k := range sortedKeys(m) {
		w.schema(m[k], ptr+"/"+escapePointer(k), depth+1)
	}
}

// schemaList examines a non-empty array of schemas.
func (w *schemaWalker) schemaList(v any, ptr string, depth int) {
	a, ok := v.([]any)
	switch {
	case !ok:
		w.add(schemaInvalid, ptr, "must be an array of schemas, not "+jsonKind(v))
		return
	case len(a) == 0:
		w.add(schemaInvalid, ptr, "must not be empty")
		return
	}
	for i, s := range a {
		w.schema(s, ptr+"/"+strconv.Itoa(i), depth+1)
	}
}

// items examines items: a schema in 2020-12, or an array in the drafts
// before it, which a 2020-12 client reads differently.
func (w *schemaWalker) items(v any, ptr string, depth int) {
	if _, ok := v.([]any); ok {
		w.add(schemaWarn, ptr, "the array form of items is from draft 2019-09 and earlier; 2020-12 names it prefixItems")
		w.schemaList(v, ptr, depth)
		return
	}
	w.schema(v, ptr, depth+1)
}

// typeKeyword examines type: one type name, or a non-empty array of
// distinct ones.
func (w *schemaWalker) typeKeyword(v any, ptr string) {
	switch t := v.(type) {
	case string:
		w.typeName(t, ptr)
	case []any:
		if len(t) == 0 {
			w.add(schemaInvalid, ptr, "type must not be empty")
		}
		seen := map[string]bool{}
		for i, e := range t {
			p := ptr + "/" + strconv.Itoa(i)
			s, ok := e.(string)
			switch {
			case !ok:
				w.add(schemaInvalid, p, "a type name must be a string, not "+jsonKind(e))
			case seen[s]:
				w.add(schemaInvalid, p, fmt.Sprintf("type repeats %q", truncate(s, 40)))
			default:
				seen[s] = true
				w.typeName(s, p)
			}
		}
	default:
		w.add(schemaInvalid, ptr, "type must be a string or an array of strings, not "+jsonKind(v))
	}
}

// typeName examines one type name.
func (w *schemaWalker) typeName(s, ptr string) {
	if !jsonTypes[s] {
		w.add(schemaInvalid, ptr, fmt.Sprintf("%q is not a JSON Schema type", truncate(s, 40)))
	}
}

// required examines required: an array of strings, each naming a property
// the schema declares.
func (w *schemaWalker) required(n map[string]any, v any, ptr string) {
	a, ok := v.([]any)
	if !ok {
		w.add(schemaInvalid, ptr, "required must be an array of strings, not "+jsonKind(v))
		return
	}
	props, _ := n["properties"].(map[string]any)
	elsewhere := declaresElsewhere(n)
	for i, e := range a {
		p := ptr + "/" + strconv.Itoa(i)
		s, ok := e.(string)
		switch {
		case !ok:
			w.add(schemaInvalid, p, "a required name must be a string, not "+jsonKind(e))
		case props == nil && elsewhere:
			// Declared, if at all, by a subschema or a reference this
			// check does not merge.
		case props[s] == nil:
			w.add(schemaWarn, p, fmt.Sprintf("required names %q, which properties does not declare", truncate(s, 40)))
		}
	}
}

// declaresElsewhere reports whether a schema's properties may come from
// somewhere other than its own properties keyword.
func declaresElsewhere(n map[string]any) bool {
	for _, k := range []string{"allOf", "anyOf", "oneOf", "$ref", "$dynamicRef", "patternProperties", "additionalProperties", "if", "dependentSchemas"} {
		if _, ok := n[k]; ok {
			return true
		}
	}
	return false
}

// dialect examines $schema.
func (w *schemaWalker) dialect(v any, ptr string) {
	s, ok := v.(string)
	if !ok {
		w.add(schemaInvalid, ptr, "$schema must be a string, not "+jsonKind(v))
		return
	}
	d := strings.TrimSuffix(s, "#")
	if d == dialect2020 {
		return
	}
	if name, ok := olderDialects[d]; ok {
		w.add(schemaInfo, ptr, "declares "+name+"; MCP clients assume 2020-12 and may read it differently")
		return
	}
	w.add(schemaWarn, ptr, fmt.Sprintf("unknown dialect %q; a client cannot tell how to read this schema", truncate(s, 80)))
}

// ref examines $ref: a local reference must resolve to a schema.
func (w *schemaWalker) ref(v any, ptr string) {
	s, ok := v.(string)
	if !ok {
		w.add(schemaInvalid, ptr, "$ref must be a string, not "+jsonKind(v))
		return
	}
	frag, local := strings.CutPrefix(s, "#")
	switch {
	case !local:
		w.add(schemaInfo, ptr, fmt.Sprintf("external $ref %q is not resolved by passmcp", truncate(s, 80)))
	case frag == "":
	case strings.HasPrefix(frag, "/"):
		w.pointerRef(s, frag, ptr)
	default:
		if !w.hasAnchor(frag) {
			w.add(schemaInvalid, ptr, fmt.Sprintf("$ref %q names no $anchor in this schema", truncate(s, 80)))
		}
	}
}

// pointerRef resolves a JSON pointer fragment against the root and
// requires it to land on a schema.
func (w *schemaWalker) pointerRef(ref, frag, ptr string) {
	target, ok := resolvePointer(w.root, frag)
	switch {
	case !ok:
		w.add(schemaInvalid, ptr, fmt.Sprintf("$ref %q does not resolve", truncate(ref, 80)))
	case !isSchemaValue(target):
		w.add(schemaInvalid, ptr, fmt.Sprintf("$ref %q resolves to %s, not a schema", truncate(ref, 80), jsonKind(target)))
	}
}

// hasAnchor reports whether the document declares name as an $anchor or
// $dynamicAnchor, collecting them once.
func (w *schemaWalker) hasAnchor(name string) bool {
	if w.anchors == nil {
		w.anchors = map[string]bool{}
		collectAnchors(w.root, w.anchors, 0)
	}
	return w.anchors[name]
}

// collectAnchors records every anchor declared in v, to a bounded depth.
func collectAnchors(v any, into map[string]bool, depth int) {
	if depth > maxSchemaDepth {
		return
	}
	switch n := v.(type) {
	case map[string]any:
		for k, e := range n {
			if s, ok := e.(string); ok && (k == "$anchor" || k == "$dynamicAnchor") {
				into[s] = true
			}
			collectAnchors(e, into, depth+1)
		}
	case []any:
		for _, e := range n {
			collectAnchors(e, into, depth+1)
		}
	}
}

// resolvePointer walks an RFC 6901 pointer, percent-encoded as a URI
// fragment, down from root.
func resolvePointer(root any, frag string) (any, bool) {
	p, err := url.PathUnescape(frag)
	if err != nil {
		return nil, false
	}
	cur := root
	for _, tok := range strings.Split(p, "/")[1:] {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		next, ok := step(cur, tok)
		if !ok {
			return nil, false
		}
		cur = next
	}
	return cur, true
}

// step takes one pointer token into an object or array.
func step(cur any, tok string) (any, bool) {
	switch n := cur.(type) {
	case map[string]any:
		v, ok := n[tok]
		return v, ok
	case []any:
		i, err := strconv.Atoi(tok)
		if err != nil || i < 0 || i >= len(n) || (len(tok) > 1 && tok[0] == '0') {
			return nil, false
		}
		return n[i], true
	}
	return nil, false
}

// isSchemaValue reports whether v has the shape of a schema.
func isSchemaValue(v any) bool {
	switch v.(type) {
	case bool, map[string]any:
		return true
	}
	return false
}

// jsonKind names the JSON type of a decoded value, with an article.
func jsonKind(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "a boolean"
	case float64:
		return "a number"
	case string:
		return "a string"
	case []any:
		return "an array"
	}
	return "an object"
}

// escapePointer escapes one RFC 6901 reference token.
func escapePointer(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "~", "~0"), "/", "~1")
}

// sortedKeys returns an object's keys in order, so a report lists issues
// the same way on every run.
func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
