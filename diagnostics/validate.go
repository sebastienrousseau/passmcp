// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"encoding/json"
	"fmt"
	"math"
	"sort"
	"strings"
)

// Validate checks value against a JSON Schema and returns human-readable
// violations. It implements the structural core used by MCP tool schemas:
// type, properties, required, additionalProperties=false, items, enum,
// const, minimum/maximum, minLength/maxLength, minItems/maxItems,
// oneOf/anyOf/allOf, and local "$ref"/"$defs" pointers. It does not check
// patterns or formats, and a $ref pointing outside the document is reported
// as unchecked rather than passed over in silence.
func Validate(schema, value json.RawMessage) []string {
	if len(schema) == 0 {
		return nil
	}
	var s map[string]any
	if err := json.Unmarshal(schema, &s); err != nil {
		return []string{"schema is not valid JSON: " + err.Error()}
	}
	var v any
	dec := json.NewDecoder(strings.NewReader(string(value)))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return []string{"value is not valid JSON: " + err.Error()}
	}
	var out []string
	r := newResolver(s)
	v8 := &validator{r: r}
	v8.validate(s, v, "$", 0, &out)
	out = append(out, r.externalRefIssues()...)
	// Violations are collected by walking `properties`, which is a map, so
	// without this two runs over the same schema return the same problems
	// in a different order. That makes a report undiffable and a test
	// flaky — runner.go was already sorting its copy downstream, which
	// treated the symptom. Sorting here fixes it for every caller.
	sort.Strings(out)
	return out
}

type validator struct{ r *resolver }

func (x *validator) validate(s map[string]any, v any, path string, depth int, out *[]string) {
	if depth > MaxSchemaDepth {
		*out = append(*out, fmt.Sprintf("%s: schema nests deeper than %d levels; not checked further", path, MaxSchemaDepth))
		return
	}
	s = x.r.deref(s, depth)
	validateNode(x, s, v, path, depth, out)
}

func validateNode(x *validator, s map[string]any, v any, path string, depth int, out *[]string) {
	validateConstEnum(s, v, path, out)
	x.validateAllOf(s, v, path, depth, out)
	x.validateAlternatives(s, v, path, depth, out)
	if !typeMatches(s["type"], v) {
		*out = append(*out, fmt.Sprintf("%s: expected type %v, got %s", path, s["type"], jsonTypeName(v)))
		return
	}
	switch val := v.(type) {
	case map[string]any:
		x.validateObject(s, val, path, depth, out)
	case []any:
		x.validateArray(s, val, path, depth, out)
	case string:
		validateString(s, val, path, out)
	case json.Number:
		validateNumber(s, val, path, out)
	}
}

// validateConstEnum checks const and enum, which compare the whole value.
func validateConstEnum(s map[string]any, v any, path string, out *[]string) {
	if c, ok := s["const"]; ok && !jsonEqual(c, v) {
		*out = append(*out, fmt.Sprintf("%s: expected const %v", path, c))
	}
	if e, ok := s["enum"].([]any); ok {
		found := false
		for _, cand := range e {
			if jsonEqual(cand, v) {
				found = true
				break
			}
		}
		if !found {
			*out = append(*out, fmt.Sprintf("%s: value not in enum", path))
		}
	}
}

// validateAllOf checks the value against every allOf branch, each under
// its own path so a violation names the branch.
func (x *validator) validateAllOf(s map[string]any, v any, path string, depth int, out *[]string) {
	for _, k := range []string{"allOf"} {
		if alts, ok := s[k].([]any); ok {
			for i, a := range alts {
				if sub, ok := a.(map[string]any); ok {
					x.validate(sub, v, fmt.Sprintf("%s(allOf[%d])", path, i), depth+1, out)
				}
			}
		}
	}
}

// validateAlternatives counts the oneOf and anyOf branches the value
// satisfies: anyOf needs at least one, oneOf exactly one.
func (x *validator) validateAlternatives(s map[string]any, v any, path string, depth int, out *[]string) {
	for _, k := range []string{"oneOf", "anyOf"} {
		if alts, ok := s[k].([]any); ok && len(alts) > 0 {
			matches := x.countMatches(alts, v, path, depth)
			if matches == 0 || (k == "oneOf" && matches > 1) {
				*out = append(*out, fmt.Sprintf("%s: matches %d of %s alternatives", path, matches, k))
			}
		}
	}
}

// countMatches is how many schema branches the value satisfies outright.
func (x *validator) countMatches(alts []any, v any, path string, depth int) int {
	matches := 0
	for _, a := range alts {
		sub, ok := a.(map[string]any)
		if !ok {
			continue
		}
		var tmp []string
		x.validate(sub, v, path, depth+1, &tmp)
		if len(tmp) == 0 {
			matches++
		}
	}
	return matches
}

// validateObject checks required properties, then each property against
// its own schema or against additionalProperties.
func (x *validator) validateObject(s map[string]any, val map[string]any, path string, depth int, out *[]string) {
	props, _ := s["properties"].(map[string]any)
	for _, r := range stringSlice(s["required"]) {
		if _, ok := val[r]; !ok {
			*out = append(*out, fmt.Sprintf("%s: missing required property %q", path, r))
		}
	}
	for name, pv := range val {
		if ps, ok := props[name].(map[string]any); ok {
			x.validate(ps, pv, path+"."+name, depth+1, out)
			continue
		}
		if ap, ok := s["additionalProperties"]; ok {
			x.validateAdditional(ap, name, pv, path, depth, out)
		}
	}
}

// validateAdditional applies additionalProperties to a property the schema
// does not name: false forbids it, a schema checks it.
func (x *validator) validateAdditional(ap any, name string, pv any, path string, depth int, out *[]string) {
	switch a := ap.(type) {
	case bool:
		if !a {
			*out = append(*out, fmt.Sprintf("%s: unexpected property %q", path, name))
		}
	case map[string]any:
		x.validate(a, pv, path+"."+name, depth+1, out)
	}
}

// validateArray checks the item count bounds and each item.
func (x *validator) validateArray(s map[string]any, val []any, path string, depth int, out *[]string) {
	if mn, ok := num(s["minItems"]); ok && float64(len(val)) < mn {
		*out = append(*out, fmt.Sprintf("%s: fewer than %v items", path, mn))
	}
	if mx, ok := num(s["maxItems"]); ok && float64(len(val)) > mx {
		*out = append(*out, fmt.Sprintf("%s: more than %v items", path, mx))
	}
	if items, ok := s["items"].(map[string]any); ok {
		for i, iv := range val {
			x.validate(items, iv, fmt.Sprintf("%s[%d]", path, i), depth+1, out)
		}
	}
}

// validateString checks the length bounds.
func validateString(s map[string]any, val string, path string, out *[]string) {
	if mn, ok := num(s["minLength"]); ok && float64(len(val)) < mn {
		*out = append(*out, fmt.Sprintf("%s: shorter than minLength %v", path, mn))
	}
	if mx, ok := num(s["maxLength"]); ok && float64(len(val)) > mx {
		*out = append(*out, fmt.Sprintf("%s: longer than maxLength %v", path, mx))
	}
}

// validateNumber checks the minimum and maximum.
func validateNumber(s map[string]any, val json.Number, path string, out *[]string) {
	f, _ := val.Float64()
	if mn, ok := num(s["minimum"]); ok && f < mn {
		*out = append(*out, fmt.Sprintf("%s: below minimum %v", path, mn))
	}
	if mx, ok := num(s["maximum"]); ok && f > mx {
		*out = append(*out, fmt.Sprintf("%s: above maximum %v", path, mx))
	}
}

func typeMatches(t any, v any) bool {
	switch tt := t.(type) {
	case nil:
		return true
	case string:
		return typeIs(tt, v)
	case []any:
		for _, x := range tt {
			if s, ok := x.(string); ok && typeIs(s, v) {
				return true
			}
		}
		return false
	}
	return true
}

func typeIs(t string, v any) bool {
	switch t {
	case "object":
		_, ok := v.(map[string]any)
		return ok
	case "array":
		_, ok := v.([]any)
		return ok
	case "string":
		_, ok := v.(string)
		return ok
	case "boolean":
		_, ok := v.(bool)
		return ok
	case "null":
		return v == nil
	case "number":
		_, ok := v.(json.Number)
		return ok
	case "integer":
		n, ok := v.(json.Number)
		if !ok {
			return false
		}
		f, err := n.Float64()
		return err == nil && f == math.Trunc(f)
	}
	return true
}

func jsonTypeName(v any) string {
	switch v.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string"
	case bool:
		return "boolean"
	case nil:
		return "null"
	case json.Number:
		return "number"
	}
	return fmt.Sprintf("%T", v)
}

func jsonEqual(a, b any) bool {
	ab, _ := json.Marshal(a)
	bb, _ := json.Marshal(b)
	return string(ab) == string(bb)
}
