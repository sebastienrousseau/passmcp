// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"satellion.com/passmcp"
)

// A catalogue is not free. Every tool an agent can reach is loaded into the
// context window before the model has decided anything, on every call, and
// it is billed that way. Nothing else in the ecosystem measures it, because
// no other tool treats catalogue size as a correctness property — a server
// can satisfy every MUST in the specification and still cost a fortune to
// look at, or be large enough that the model chooses badly from it.
//
// The second half of this file is the other way a compliant server fails an
// agent: a parameter described as `arg1: string`. The protocol is satisfied
// and the model has nothing to reason with, so it guesses.

// Budget defaults, in approximate tokens.
//
// These are judgements rather than measurements, and they are stated here so
// they can be argued with. A catalogue at the warn threshold costs roughly a
// twentieth of a 200k window on every single call before any work is done;
// at the fail threshold it is a design problem rather than a large server.
const (
	// CatalogueTokenBudget is where a catalogue stops being free.
	CatalogueTokenBudget = 10000
	// CatalogueTokenHard is where it stops being defensible.
	CatalogueTokenHard = 4 * CatalogueTokenBudget
	// ToolTokenBudget is the per-tool figure. A tool that needs more than
	// this to describe itself is usually several tools.
	ToolTokenBudget = 500
)

// TokenRule names the approximation, in the finding itself.
//
// passmcp has no model dependency and is not going to acquire one to count
// tokens, so this is an estimate and says so everywhere it appears. Four
// characters per token is the standard rule of thumb and is close enough for
// a budget; the byte count beside it is exact, and a reader who needs
// precision can tokenise the bytes with whatever their model actually uses.
const TokenRule = "chars÷4"

// approxTokens estimates the token cost of a string.
func approxTokens(n int) int {
	if n == 0 {
		return 0
	}
	return (n + 3) / 4
}

// toolWeight is the JSON an agent actually loads for one tool: everything
// the client sends to the model, and nothing else.
func toolWeight(t passmcp.Tool) int {
	b, err := json.Marshal(t)
	if err != nil {
		// Unmarshalable is not measurable. Returning zero would understate
		// the catalogue, so fall back to the parts.
		return len(t.Name) + len(t.Title) + len(t.Description) +
			len(t.InputSchema) + len(t.OutputSchema)
	}
	return len(b)
}

// catalogueTokens is what the catalogue costs to look at, in the same
// estimated tokens the budget check reports.
//
// Shared so the cache-hint check reasons about the same number rather than
// computing a second one that could drift from it.
func catalogueTokens(tools []passmcp.Tool) int {
	total := 0
	for _, t := range tools {
		total += toolWeight(t)
	}
	return approxTokens(total)
}

// checkCatalogueBudget measures what the catalogue costs to look at.
func checkCatalogueBudget(s *Session) []Finding {
	tools := s.Tools
	if len(tools) == 0 {
		return nil
	}

	type weighed struct {
		name  string
		bytes int
	}
	var each []weighed
	total := 0
	for _, t := range tools {
		w := toolWeight(t)
		total += w
		each = append(each, weighed{t.Name, w})
	}
	sort.Slice(each, func(i, j int) bool { return each[i].bytes > each[j].bytes })

	totalTok := approxTokens(total)
	c := s.check("catalog.budget.tokens", "Catalogue fits a context budget")
	detail := fmt.Sprintf("%d tools, %s, ≈%d tokens (%s)", len(tools), humanBytes(total), totalTok, TokenRule)

	// The three largest, because "it is too big" is not actionable and
	// "these three are 60% of it" is.
	var worst []string
	for i := 0; i < len(each) && i < 3; i++ {
		worst = append(worst, fmt.Sprintf("%s ≈%d", each[i].name, approxTokens(each[i].bytes)))
	}
	ev := "largest: " + strings.Join(worst, ", ")

	switch {
	case totalTok > CatalogueTokenHard:
		return []Finding{c.ev(ev).fail(Major,
			fmt.Sprintf("%s — over %d, which every call pays for before the model has chosen anything", detail, CatalogueTokenHard),
			"split the server, or adopt progressive discovery so a client can page the catalogue instead of loading all of it")}
	case totalTok > CatalogueTokenBudget:
		return []Finding{c.ev(ev).warn(
			fmt.Sprintf("%s — over the %d-token budget", detail, CatalogueTokenBudget),
			"trim the schemas an agent does not need at selection time, or split the server")}
	}

	// Under budget overall, but one tool can still be the problem.
	var fat []string
	for _, w := range each {
		if approxTokens(w.bytes) > ToolTokenBudget {
			fat = append(fat, fmt.Sprintf("%s ≈%d", w.name, approxTokens(w.bytes)))
		}
	}
	if len(fat) > 0 {
		return []Finding{c.ev(ev).warn(
			fmt.Sprintf("%s; %s over %d tokens each: %s", detail, plural(len(fat), "tool"), ToolTokenBudget, strings.Join(fat, ", ")),
			"a tool that needs more than "+fmt.Sprint(ToolTokenBudget)+" tokens to describe itself is usually several tools")}
	}
	return []Finding{c.ev(ev).pass(detail)}
}

// schemaProperty is the part of a JSON Schema property this cares about.
//
// Deliberately not a JSON Schema implementation: the question is whether a
// model reading this has anything to go on, and that is answered by which
// keywords are present rather than by whether the schema is valid.
type schemaProperty struct {
	Type        any             `json:"type"`
	Description string          `json:"description"`
	Enum        []any           `json:"enum"`
	Pattern     string          `json:"pattern"`
	Format      string          `json:"format"`
	Default     json.RawMessage `json:"default"`
	Examples    []any           `json:"examples"`
	Minimum     *float64        `json:"minimum"`
	Maximum     *float64        `json:"maximum"`
	MinLength   *int            `json:"minLength"`
	MaxLength   *int            `json:"maxLength"`
}

// constrained reports whether the property says anything about its shape
// beyond a bare type.
func (p schemaProperty) constrained() bool {
	return len(p.Enum) > 0 || p.Pattern != "" || p.Format != "" ||
		len(p.Default) > 0 || len(p.Examples) > 0 ||
		p.Minimum != nil || p.Maximum != nil || p.MinLength != nil || p.MaxLength != nil
}

type toolSchema struct {
	Properties map[string]schemaProperty `json:"properties"`
	Required   []string                  `json:"required"`
}

// budgetParamGaps collects, across the catalogue, the parameters a model
// cannot reason about, and how many parameters were looked at.
type budgetParamGaps struct {
	undescribedRequired, undescribedOptional, unconstrained []string
	params                                                  int
}

// addTool files each of one tool's parameters, in name order. A tool whose
// input schema is absent or unreadable contributes nothing.
func (g *budgetParamGaps) addTool(t passmcp.Tool) {
	var sch toolSchema
	if len(t.InputSchema) == 0 || json.Unmarshal(t.InputSchema, &sch) != nil {
		return
	}
	required := map[string]bool{}
	for _, r := range sch.Required {
		required[r] = true
	}
	names := make([]string, 0, len(sch.Properties))
	for n := range sch.Properties {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		p := sch.Properties[n]
		g.params++
		ref := t.Name + "." + n
		switch {
		case strings.TrimSpace(p.Description) == "":
			if required[n] {
				g.undescribedRequired = append(g.undescribedRequired, ref)
			} else {
				g.undescribedOptional = append(g.undescribedOptional, ref)
			}
		case !p.constrained():
			g.unconstrained = append(g.unconstrained, ref)
		}
	}
}

// checkParameterAmbiguity looks for the parameters a model cannot reason
// about.
//
// A required parameter with no description is the one that breaks calls: the
// model must supply it and has been told nothing but a type. An optional one
// is a warning, and a described-but-unconstrained one is worth noting only
// in aggregate.
func checkParameterAmbiguity(s *Session) []Finding {
	if len(s.Tools) == 0 {
		return nil
	}
	c := s.check("catalog.semantic.ambiguity", "Parameters are described well enough to use")

	var g budgetParamGaps
	for _, t := range s.Tools {
		g.addTool(t)
	}
	undescribedRequired, undescribedOptional, unconstrained, params := g.undescribedRequired, g.undescribedOptional, g.unconstrained, g.params

	if params == 0 {
		return []Finding{c.skip("no tool declares any parameters")}
	}
	summary := fmt.Sprintf("%s across %s", plural(params, "parameter"), plural(len(s.Tools), "tool"))

	switch {
	case len(undescribedRequired) > 0:
		return []Finding{c.fail(Major,
			fmt.Sprintf("%s; %s required and undescribed: %s", summary,
				plural(len(undescribedRequired), "parameter"), list(undescribedRequired)),
			"describe every required parameter: the model has to supply it and a bare type tells it nothing, so it guesses")}
	case len(undescribedOptional) > 0:
		return []Finding{c.warn(
			fmt.Sprintf("%s; %s optional and undescribed: %s", summary,
				plural(len(undescribedOptional), "parameter"), list(undescribedOptional)),
			"describe optional parameters too, or the model cannot tell when supplying one would help")}
	case len(unconstrained) > 0:
		return []Finding{c.info(fmt.Sprintf(
			"%s, all described; %s carry no enum, pattern, format, bound, default or example",
			summary, plural(len(unconstrained), "parameter")))}
	}
	return []Finding{c.pass(summary + ", all described and constrained")}
}

// humanBytes renders a size for a finding.
func humanBytes(n int) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.1f KB", float64(n)/(1<<10))
	default:
		return fmt.Sprintf("%d B", n)
	}
}
