// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/diagnostics"
)

// catalogText is every string in a catalog that reaches the model.
//
// The list is the point. A reviewer reads tool descriptions; the model also
// reads titles, resource descriptions, prompt argument descriptions, and
// every `description` inside an inputSchema — and the schema is where
// published poisoning has most often been found, because it is the part
// nobody renders.
func catalogText(tools []passmcp.Tool, res []passmcp.Resource, prompts []passmcp.Prompt) []textField {
	var fields []textField
	for _, t := range tools {
		fields = append(fields,
			textField{where: fmt.Sprintf("tool %q description", t.Name), text: t.Description, owner: t.Name},
			textField{where: fmt.Sprintf("tool %q title", t.Name), text: t.Title, owner: t.Name},
		)
		fields = append(fields, owned(schemaText(fmt.Sprintf("tool %q inputSchema", t.Name), t.InputSchema), t.Name)...)
		fields = append(fields, owned(schemaText(fmt.Sprintf("tool %q outputSchema", t.Name), t.OutputSchema), t.Name)...)
	}
	for _, r := range res {
		fields = append(fields,
			textField{where: fmt.Sprintf("resource %q description", r.Name), text: r.Description, owner: r.Name},
			textField{where: fmt.Sprintf("resource %q title", r.Name), text: r.Title, owner: r.Name},
		)
	}
	for _, p := range prompts {
		fields = append(fields,
			textField{where: fmt.Sprintf("prompt %q description", p.Name), text: p.Description, owner: p.Name},
			textField{where: fmt.Sprintf("prompt %q title", p.Name), text: p.Title, owner: p.Name},
		)
		for _, a := range p.Arguments {
			fields = append(fields, textField{
				where: fmt.Sprintf("prompt %q argument %q description", p.Name, a.Name),
				text:  a.Description,
				owner: p.Name,
			})
		}
	}
	return fields
}

type textField struct {
	where string
	text  string
	// owner is the catalog entry the field belongs to. Most checks here do
	// not care, because a poisoned string is poisoned wherever it sits.
	// Shadowing is the exception: it turns entirely on whether the text
	// governs its own tool or somebody else's.
	owner string
}

// owned stamps the owning catalog entry onto fields lifted out of a schema.
// schemaText walks a document and has no idea whose document it is.
func owned(fields []textField, owner string) []textField {
	for i := range fields {
		fields[i].owner = owner
	}
	return fields
}

// schemaDepthLimit bounds the walk. A schema deep enough to exceed it is
// already a finding of its own in the validator; this is here so a
// self-referential or hostile schema cannot make the scan run forever.
const schemaDepthLimit = 12

// schemaText collects every description and title inside a JSON Schema.
func schemaText(where string, raw json.RawMessage) []textField {
	if len(raw) == 0 {
		return nil
	}
	var doc any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil
	}
	var out []textField
	poisonWalkSchema(doc, where, 0, &out)
	return out
}

// poisonWalkSchema appends every description and title under node to out,
// depth first, stopping below schemaDepthLimit.
func poisonWalkSchema(node any, path string, depth int, out *[]textField) {
	if depth > schemaDepthLimit {
		return
	}
	switch n := node.(type) {
	case map[string]any:
		// Sorted, because a map is not, and a report whose findings
		// reorder between two runs over the same server is a diff with
		// no change in it.
		keys := make([]string, 0, len(n))
		for k := range n {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := n[k]
			if s, ok := v.(string); ok && (k == "description" || k == "title") {
				*out = append(*out, textField{where: path + "." + k, text: s})
				continue
			}
			poisonWalkSchema(v, path+"."+k, depth+1, out)
		}
	case []any:
		for i, v := range n {
			poisonWalkSchema(v, fmt.Sprintf("%s[%d]", path, i), depth+1, out)
		}
	}
}

// scanCatalog reports what the catalog says to the model that it does not
// say to the person reading it.
func scanCatalog(s *Session, res []passmcp.Resource, prompts []passmcp.Prompt) []Finding {
	var sigs []diagnostics.Signal
	fields := catalogText(s.Tools, res, prompts)
	for _, f := range fields {
		sigs = append(sigs, diagnostics.ScanText(f.where, f.text)...)
	}
	for _, t := range s.Tools {
		sigs = append(sigs, diagnostics.ScanName(fmt.Sprintf("tool %q name", t.Name), t.Name)...)
	}
	for _, p := range prompts {
		sigs = append(sigs, diagnostics.ScanName(fmt.Sprintf("prompt %q name", p.Name), p.Name)...)
	}

	byKind := map[diagnostics.SignalKind][]diagnostics.Signal{}
	for _, sig := range sigs {
		byKind[sig.Kind] = append(byKind[sig.Kind], sig)
	}

	// One check per kind, so a reader can tell "there is a hidden
	// character somewhere" from "a description is addressed to the model".
	// They are different problems with different answers.
	// Each call opens its check with literal arguments and hands it to
	// verdict, which decides pass, warn or fail from the signals.
	//
	// Both halves have to be visible to the tools that read this package.
	// scripts/checkinventory parses (*Session).check call sites for the
	// published inventory, so the id must be a literal here rather than a
	// variable — an earlier version held these in a table of strings and the
	// five checks were simply absent from the inventory. The same tool marks
	// which checks can fail, by finding .fail and .warn; those live in
	// verdict, so it follows a check passed to a helper that fails it.
	out := []Finding{
		verdict(s.check("catalog.text.hidden", "Catalog text has nothing hidden in it"),
			byKind[diagnostics.SignalHidden],
			"no invisible or bidirectional characters",
			"remove the characters; a description that needs them is a description a reviewer cannot check"),
		verdict(s.check("catalog.text.comments", "Catalog text carries no hidden comments"),
			byKind[diagnostics.SignalComment],
			"no HTML comments",
			"move the content into the description itself, or delete it: a rendered catalog hides a comment and the model does not"),
		verdict(s.check("catalog.text.instructions", "Catalog text describes rather than instructs"),
			byKind[diagnostics.SignalInstruction],
			"no text addressed to the model",
			"describe what the tool does; an instruction aimed at the model is indistinguishable from one an attacker planted"),
		verdict(s.check("catalog.text.secret_paths", "Catalog text names no credential locations"),
			byKind[diagnostics.SignalSecretPath],
			"no credential paths named",
			"if the tool genuinely reads these, say so in prose an operator approves rather than in a schema field"),
		verdict(s.check("catalog.text.encoded", "Catalog text is written, not encoded"),
			byKind[diagnostics.SignalEncoded],
			"nothing encoded",
			"write the text; base64 in a description is unreadable to the reviewer approving it and perfectly readable to the model, which is the only reason to put it there"),
		verdict(s.check("catalog.names.confusable", "Names use a single script"),
			byKind[diagnostics.SignalConfusable],
			"every name is single-script",
			"use one script per name; a mixed-script name exists to render like a name the user already trusts"),
		checkShadowing(s, fields),
	}
	return out
}

// describeSignals renders the findings a maintainer has to act on.
//
// It names at most three: a catalog with forty poisoned descriptions has
// one problem, not forty, and a finding that scrolls is a finding nobody
// reads to the end of.
func describeSignals(sigs []diagnostics.Signal) string {
	sort.SliceStable(sigs, func(i, j int) bool {
		return severityRank(sigs[i].Severity) < severityRank(sigs[j].Severity)
	})
	var b strings.Builder
	fmt.Fprintf(&b, "%d occurrence(s); ", len(sigs))
	shown := min(len(sigs), 3)
	for i := range shown {
		if i > 0 {
			b.WriteString("; ")
		}
		fmt.Fprintf(&b, "%s %s — %q", sigs[i].Where, sigs[i].Detail, sigs[i].Excerpt)
	}
	if len(sigs) > shown {
		fmt.Fprintf(&b, "; and %d more", len(sigs)-shown)
	}
	return b.String()
}

func severityRank(s diagnostics.SignalSeverity) int {
	switch s {
	case diagnostics.SeverityCritical:
		return 0
	case diagnostics.SeverityMajor:
		return 1
	default:
		return 2
	}
}

// verdict turns the signals found for one kind into that check's finding.
//
// Severity carries straight through from the scanner: it decides what
// cannot be honest documentation, and this only decides how loudly to say
// so.
func verdict(c *check, found []diagnostics.Signal, clean, fix string) Finding {
	if len(found) == 0 {
		return c.pass(clean)
	}
	detail := describeSignals(found)
	switch worst, _ := diagnostics.Worst(found); worst {
	case diagnostics.SeverityCritical:
		return c.fail(Critical, detail, fix)
	case diagnostics.SeverityMajor:
		return c.fail(Major, detail, fix)
	default:
		return c.warn(detail, fix)
	}
}
