// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package diagnostics

import (
	"fmt"
	"strconv"
	"strings"
)

// MaxSchemaDepth bounds recursion through a schema. A schema is supplied by
// the server under test, so neither its nesting nor its $ref graph can be
// trusted to terminate.
const MaxSchemaDepth = 64

// resolver dereferences local JSON pointers inside one schema document.
//
// Almost every MCP tool schema in the wild is generated — pydantic, zod,
// and the Go and TypeScript SDKs all emit "$defs" plus "$ref" for any
// nested model. A validator that ignores $ref silently reports no problems
// for those schemas, which is worse than reporting that it could not check
// them.
type resolver struct {
	root     map[string]any
	inFlight map[string]bool
	// External records $refs that point outside this document; they cannot
	// be resolved and are reported rather than ignored.
	External []string
}

func newResolver(root map[string]any) *resolver {
	return &resolver{root: root, inFlight: map[string]bool{}}
}

// deref follows s["$ref"] until it reaches a schema with no $ref. Sibling
// keywords alongside a $ref are preserved, as JSON Schema 2019-09 onwards
// requires. A cycle or an unresolvable pointer yields the schema unchanged
// and, for an external ref, a note on the resolver.
func (r *resolver) deref(s map[string]any, depth int) map[string]any {
	if r == nil || s == nil || depth > MaxSchemaDepth {
		return s
	}
	ref, ok := s["$ref"].(string)
	if !ok || ref == "" {
		return s
	}
	if !strings.HasPrefix(ref, "#") {
		r.noteExternal(ref)
		return withoutRef(s)
	}
	if r.inFlight[ref] {
		// A recursive model (a tree node referring to itself). Stopping here
		// is correct: the instance is finite, so the cycle ends with it.
		return withoutRef(s)
	}
	target, ok := r.pointer(ref)
	if !ok {
		r.noteExternal(ref)
		return withoutRef(s)
	}
	r.inFlight[ref] = true
	target = r.deref(target, depth+1)
	delete(r.inFlight, ref)

	// Merge: the referenced schema first, then any siblings of the $ref,
	// which win.
	out := make(map[string]any, len(target)+len(s))
	for k, v := range target {
		out[k] = v
	}
	for k, v := range s {
		if k != "$ref" {
			out[k] = v
		}
	}
	return out
}

func (r *resolver) noteExternal(ref string) {
	for _, e := range r.External {
		if e == ref {
			return
		}
	}
	r.External = append(r.External, ref)
}

// pointer walks an RFC 6901 JSON pointer from the document root.
func (r *resolver) pointer(ref string) (map[string]any, bool) {
	frag := strings.TrimPrefix(ref, "#")
	if frag == "" || frag == "/" {
		return r.root, true
	}
	if !strings.HasPrefix(frag, "/") {
		return nil, false // a plain-name anchor, not a pointer
	}
	var cur any = r.root
	for _, raw := range strings.Split(strings.TrimPrefix(frag, "/"), "/") {
		tok := strings.ReplaceAll(strings.ReplaceAll(raw, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	m, ok := cur.(map[string]any)
	return m, ok
}

func withoutRef(s map[string]any) map[string]any {
	if _, ok := s["$ref"]; !ok {
		return s
	}
	out := make(map[string]any, len(s))
	for k, v := range s {
		if k != "$ref" {
			out[k] = v
		}
	}
	return out
}

// externalRefIssues renders the unresolvable references as findings.
func (r *resolver) externalRefIssues() []string {
	if r == nil || len(r.External) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.External))
	for _, ref := range r.External {
		out = append(out, fmt.Sprintf("$ref %q points outside the document and was not checked", ref))
	}
	return out
}
