// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package a2a

import (
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"unicode/utf8"
)

// SchemaError is one way a card departs from the A2A v1 AgentCard, at the
// JSON path where it does.
type SchemaError struct {
	Path    string `json:"path"`
	Message string `json:"message"`
}

func (e SchemaError) String() string { return e.Path + ": " + e.Message }

// maxSchemaErrors bounds what one card can put in a report. The card is
// written by whoever runs the agent; a pathological one should cost a
// line, not a megabyte.
const maxSchemaErrors = 50

// ValidateCard reports every way a decoded card is not an A2A v1 AgentCard.
// An empty result means the card is valid.
func ValidateCard(card any) []SchemaError {
	v := &validator{}
	m, ok := card.(map[string]any)
	if !ok {
		return []SchemaError{{Path: "$", Message: "the Agent Card is not a JSON object"}}
	}
	v.object("$", m, agentCard)
	return v.errs
}

type validator struct{ errs []SchemaError }

func (v *validator) add(path, format string, a ...any) {
	if len(v.errs) < maxSchemaErrors {
		v.errs = append(v.errs, SchemaError{Path: path, Message: fmt.Sprintf(format, a...)})
	}
}

// object checks one message: its required fields, its oneof, and each
// member it carries, in a stable order so two runs report the same list.
func (v *validator) object(path string, m map[string]any, s *shape) {
	for _, name := range sortedKeys(s.fields) {
		if f := s.fields[name]; f.required {
			if _, ok := m[name]; !ok {
				v.add(path+"."+name, "required by %s, and missing", s.name)
			}
		}
	}
	v.oneof(path, m, s)
	for _, name := range sortedKeys(m) {
		f, known := s.fields[name]
		if !known {
			v.add(path+"."+name, "not a field of %s in A2A v1", s.name)
			continue
		}
		v.value(path+"."+name, m[name], f)
	}
}

func (v *validator) oneof(path string, m map[string]any, s *shape) {
	if len(s.oneof) == 0 {
		return
	}
	n := 0
	for _, name := range s.oneof {
		if _, ok := m[name]; ok {
			n++
		}
	}
	if n != 1 {
		v.add(path, "%s must set exactly one of %v; it sets %d", s.name, s.oneof, n)
	}
}

// value checks one member against its declared type.
func (v *validator) value(path string, x any, f field) {
	switch f.kind {
	case kString:
		v.str(path, x, f)
	case kBool:
		if _, ok := x.(bool); !ok {
			v.add(path, "must be a boolean")
		}
	case kObject:
		if m, ok := x.(map[string]any); ok {
			v.object(path, m, f.elem)
			return
		}
		v.add(path, "must be an object (%s)", f.elem.name)
	case kArray:
		v.array(path, x, f)
	case kMap:
		v.mapOf(path, x, f.elem)
	case kStringMap:
		v.stringMap(path, x)
	case kStruct:
		if _, ok := x.(map[string]any); !ok {
			v.add(path, "must be a JSON object")
		}
	}
}

func (v *validator) str(path string, x any, f field) {
	s, ok := x.(string)
	if !ok {
		v.add(path, "must be a string")
		return
	}
	if len(f.enum) > 0 && !slices.Contains(f.enum, s) {
		v.add(path, "must be one of %v, not %q", f.enum, truncate(s, 40))
	}
	if f.url && s != "" {
		if u, err := url.Parse(s); err != nil || !u.IsAbs() || u.Host == "" {
			v.add(path, "must be an absolute URL, not %q", truncate(s, 80))
		}
	}
}

func (v *validator) array(path string, x any, f field) {
	a, ok := x.([]any)
	if !ok {
		v.add(path, "must be an array")
		return
	}
	for i, e := range a {
		p := path + "[" + strconv.Itoa(i) + "]"
		if f.elem != nil {
			v.value(p, e, field{kind: kObject, elem: f.elem})
			continue
		}
		v.value(p, e, field{kind: f.elemKind})
	}
}

func (v *validator) mapOf(path string, x any, s *shape) {
	m, ok := x.(map[string]any)
	if !ok {
		v.add(path, "must be an object mapping names to %s", s.name)
		return
	}
	for _, k := range sortedKeys(m) {
		v.value(path+"."+k, m[k], field{kind: kObject, elem: s})
	}
}

func (v *validator) stringMap(path string, x any) {
	m, ok := x.(map[string]any)
	if !ok {
		v.add(path, "must be an object of strings")
		return
	}
	for _, k := range sortedKeys(m) {
		if _, ok := m[k].(string); !ok {
			v.add(path+"."+k, "must be a string")
		}
	}
}

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// truncate bounds text that came from the agent before it reaches a report.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n] + "…"
}
