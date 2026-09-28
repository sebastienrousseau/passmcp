// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strings"

	"satellion.com/passmcp"
	"satellion.com/passmcp/internal/telemetry"
)

// phaseCatalog lists tools, resources and prompts and audits their
// descriptions and schemas without invoking anything.
func phaseCatalog(ctx context.Context, s *Session) []Finding {
	var out []Finding
	caps := s.Init.Capabilities
	pctx := func(label string) context.Context { return telemetry.WithPhase(ctx, "catalog", label) }

	// ---- tools ----
	out = append(out, catalogTools(pctx, s, caps)...)
	tools := s.Tools
	if len(tools) > 0 {
		out = append(out, checkPersonalData(s, tools)...)
	}

	// ---- resources ----
	out = append(out, catalogResources(pctx, s, caps)...)
	res := s.Resources

	// ---- prompts ----
	out = append(out, catalogPrompts(pctx, s, caps)...)
	prompts := s.Prompts

	// ---- what the catalog says to the model ----
	//
	// Everything above asks whether the catalog is well formed. This asks
	// whether it is honest, which is a different question and the one an
	// agent is exposed to: a description is not documentation, it is input
	// the model reads before deciding what to call.
	if len(tools) > 0 || len(res) > 0 || len(prompts) > 0 {
		out = append(out, scanCatalog(s, res, prompts)...)
	}
	if len(tools) > 0 {
		out = append(out, checkToxicCombination(s))
	}
	if f, ok := checkCrossServerShadowing(ctx, s); ok {
		out = append(out, f)
	}

	if len(tools) == 0 && len(res) == 0 && len(prompts) == 0 {
		out = append(out, s.check("catalog.empty", "Server exposes something").fail(Critical, "no tools, resources or prompts", "an MCP server with an empty catalog has nothing for an agent to use"))
	}
	return out
}

// catalogTools lists the tools, records them on the session, and audits
// them when there are any.
func catalogTools(pctx func(string) context.Context, s *Session, caps passmcp.ServerCapabilities) []Finding {
	var out []Finding
	c := s.check("catalog.tools.list", "tools/list")
	tools, cacheHints, err := s.Client.ListToolsWithHints(pctx("tools/list"))
	switch {
	case err != nil && caps.Tools != nil:
		out = append(out, c.fail(Critical, "capability advertised but listing failed: "+err.Error(), "implement tools/list"))
	case err != nil:
		out = append(out, c.info("not supported: "+err.Error()))
	case caps.Tools == nil && len(tools) > 0:
		out = append(out, c.warn(fmt.Sprintf("%d tools listed but the tools capability was not declared", len(tools)), "declare capabilities.tools on initialize"))
	default:
		out = append(out, c.pass(fmt.Sprintf("%d tools", len(tools))))
	}
	s.Tools = tools
	if len(tools) > 0 {
		out = append(out, auditTools(s, tools, cacheHints)...)
	}
	return out
}

// toolGaps names the tools missing each property the audit looks for.
type toolGaps struct {
	noDesc, shortDesc, badSchema, noAnn, noOut, noTitle, dups []string
}

// findToolGaps walks the tools once and sorts each into the gaps it has.
func findToolGaps(tools []passmcp.Tool) toolGaps {
	var g toolGaps
	names := map[string]int{}
	for _, t := range tools {
		names[t.Name]++
		d := strings.TrimSpace(t.Description)
		switch {
		case d == "":
			g.noDesc = append(g.noDesc, t.Name)
		case len(d) < 20:
			g.shortDesc = append(g.shortDesc, t.Name)
		}
		if !schemaIsObject(t.InputSchema) {
			g.badSchema = append(g.badSchema, t.Name)
		}
		if t.Annotations == nil {
			g.noAnn = append(g.noAnn, t.Name)
		}
		if len(t.OutputSchema) == 0 {
			g.noOut = append(g.noOut, t.Name)
		}
		if t.Title == "" && (t.Annotations == nil || t.Annotations.Title == "") {
			g.noTitle = append(g.noTitle, t.Name)
		}
	}
	for n, k := range names {
		if k > 1 {
			g.dups = append(g.dups, n)
		}
	}
	sort.Strings(g.dups)
	return g
}

// auditTools judges a non-empty tool list: names, descriptions, schemas,
// annotations, then what the catalogue costs and whether it changed.
func auditTools(s *Session, tools []passmcp.Tool, cacheHints passmcp.CacheHints) []Finding {
	g := findToolGaps(tools)
	out := toolShapeFindings(s, g)
	// Whether the annotations exist, and then whether they are true.
	// The second is the one passmcp has a stake in: it invokes what
	// readOnlyHint: true claims is safe.
	c := s.check("catalog.tools.annotations", "Tools declare behaviour annotations")
	if len(g.noAnn) > 0 {
		out = append(out, c.warn(fmt.Sprintf("%d of %d without annotations: %s", len(g.noAnn), len(tools), list(g.noAnn)), "add readOnlyHint/destructiveHint; unannotated tools are treated as destructive and skipped by cautious clients"))
	} else {
		out = append(out, c.pass("all annotated"))
	}
	out = append(out, checkAnnotationHonesty(s))
	out = append(out, checkIdempotency(s))
	out = append(out, outputSchemaFinding(s, g, len(tools)))
	if len(g.noTitle) > 0 {
		out = append(out, s.check("catalog.tools.title", "Tools have a human title").info(fmt.Sprintf("%d without title", len(g.noTitle))))
	}

	// What the catalogue costs to look at, and whether a model has
	// anything to reason with once it has. Both are properties the
	// specification does not require and an agent pays for anyway.
	out = append(out, checkCatalogueBudget(s)...)
	out = append(out, checkParameterAmbiguity(s)...)

	// Whether the server did anything about that cost.
	out = append(out, checkCacheHints(s, cacheHints, catalogueTokens(tools))...)

	// And whether this is still the catalogue somebody signed off.
	out = append(out, checkBaseline(s)...)
	return out
}

// toolShapeFindings judges the unique names, descriptions and input
// schemas.
func toolShapeFindings(s *Session, g toolGaps) []Finding {
	var out []Finding
	c := s.check("catalog.tools.unique", "Tool names are unique")
	if len(g.dups) > 0 {
		out = append(out, c.fail(Major, "duplicates: "+strings.Join(g.dups, ", "), "tool names must be unique"))
	} else {
		out = append(out, c.pass("no duplicates"))
	}
	c = s.check("catalog.tools.descriptions", "Every tool has a useful description")
	switch {
	case len(g.noDesc) > 0:
		out = append(out, c.fail(Major, "missing: "+list(g.noDesc), "an agent cannot choose a tool it cannot read about"))
	case len(g.shortDesc) > 0:
		out = append(out, c.warn("under 20 characters: "+list(g.shortDesc), "describe what the tool does, when to use it, and what it returns"))
	default:
		out = append(out, c.pass("all described"))
	}
	c = s.check("catalog.tools.input_schema", "inputSchema is a JSON Schema object")
	if len(g.badSchema) > 0 {
		out = append(out, c.fail(Major, "not type:object: "+list(g.badSchema), "inputSchema must describe an object"))
	} else {
		out = append(out, c.pass("all object schemas"))
	}
	return out
}

// outputSchemaFinding judges how many tools declare an outputSchema.
func outputSchemaFinding(s *Session, g toolGaps, total int) Finding {
	c := s.check("catalog.tools.output_schema", "Tools declare outputSchema")
	switch {
	case len(g.noOut) == total:
		return c.warn("none declare outputSchema", "add outputSchema and return structuredContent so results are machine-checkable")
	case len(g.noOut) > 0:
		return c.info(fmt.Sprintf("%d of %d without outputSchema: %s", len(g.noOut), total, list(g.noOut)))
	default:
		return c.pass("all declared")
	}
}

// catalogResources lists the resources and their templates, records them
// on the session, and audits the URIs and MIME types.
func catalogResources(pctx func(string) context.Context, s *Session, caps passmcp.ServerCapabilities) []Finding {
	var out []Finding
	c := s.check("catalog.resources.list", "resources/list")
	res, err := s.Client.ListResources(pctx("resources/list"))
	switch {
	case err != nil && caps.Resources != nil:
		out = append(out, c.fail(Major, "capability advertised but listing failed: "+err.Error(), "implement resources/list"))
	case err != nil:
		out = append(out, c.info("not supported"))
	case caps.Resources == nil && len(res) > 0:
		out = append(out, c.warn(fmt.Sprintf("%d resources listed without the capability declared", len(res)), "declare capabilities.resources"))
	default:
		out = append(out, c.pass(fmt.Sprintf("%d resources", len(res))))
	}
	s.Resources = res
	if len(res) > 0 {
		out = append(out, auditResources(s, res)...)
	}
	if caps.Resources != nil {
		c = s.check("catalog.resources.templates", "resources/templates/list")
		tpl, err := s.Client.ListResourceTemplates(pctx("resources/templates/list"))
		if err != nil {
			out = append(out, c.info("not supported: "+truncate(err.Error(), 80)))
		} else {
			s.Templates = tpl
			out = append(out, c.pass(fmt.Sprintf("%d templates", len(tpl))))
		}
	}
	return out
}

// auditResources judges a non-empty resource list: absolute URIs and
// declared MIME types.
func auditResources(s *Session, res []passmcp.Resource) []Finding {
	var out []Finding
	var badURI, noMime []string
	for _, r := range res {
		if u, err := url.Parse(r.URI); err != nil || u.Scheme == "" {
			badURI = append(badURI, r.URI)
		}
		if r.MimeType == "" {
			noMime = append(noMime, r.Name)
		}
	}
	c := s.check("catalog.resources.uris", "Resource URIs are absolute")
	if len(badURI) > 0 {
		out = append(out, c.fail(Minor, list(badURI), "use scheme://… URIs"))
	} else {
		out = append(out, c.pass("all absolute"))
	}
	if len(noMime) > 0 {
		out = append(out, s.check("catalog.resources.mime", "Resources declare mimeType").info(fmt.Sprintf("%d without mimeType", len(noMime))))
	}
	return out
}

// catalogPrompts lists the prompts, records them on the session, and
// checks that each prompt and argument is described.
func catalogPrompts(pctx func(string) context.Context, s *Session, caps passmcp.ServerCapabilities) []Finding {
	var out []Finding
	c := s.check("catalog.prompts.list", "prompts/list")
	prompts, err := s.Client.ListPrompts(pctx("prompts/list"))
	switch {
	case err != nil && caps.Prompts != nil:
		out = append(out, c.fail(Major, "capability advertised but listing failed: "+err.Error(), "implement prompts/list"))
	case err != nil:
		out = append(out, c.info("not supported"))
	case caps.Prompts == nil && len(prompts) > 0:
		out = append(out, c.warn(fmt.Sprintf("%d prompts listed without the capability declared", len(prompts)), "declare capabilities.prompts"))
	default:
		out = append(out, c.pass(fmt.Sprintf("%d prompts", len(prompts))))
	}
	s.Prompts = prompts
	if len(prompts) > 0 {
		noDesc := undescribedPrompts(prompts)
		c = s.check("catalog.prompts.descriptions", "Prompts and arguments are described")
		if len(noDesc) > 0 {
			out = append(out, c.warn("undescribed: "+list(noDesc), "describe each prompt and argument"))
		} else {
			out = append(out, c.pass("all described"))
		}
	}
	return out
}

// undescribedPrompts names each prompt, and each prompt.argument, that
// has no description.
func undescribedPrompts(prompts []passmcp.Prompt) []string {
	var noDesc []string
	for _, p := range prompts {
		if strings.TrimSpace(p.Description) == "" {
			noDesc = append(noDesc, p.Name)
		}
		for _, a := range p.Arguments {
			if strings.TrimSpace(a.Description) == "" {
				noDesc = append(noDesc, p.Name+"."+a.Name)
			}
		}
	}
	return noDesc
}

func schemaIsObject(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	var s struct {
		Type any `json:"type"`
	}
	if json.Unmarshal(raw, &s) != nil {
		return false
	}
	switch t := s.Type.(type) {
	case string:
		return t == "object"
	case []any:
		for _, v := range t {
			if v == "object" {
				return true
			}
		}
	case nil:
		// Some servers omit type and only give properties; accept that.
		var p struct {
			Properties map[string]any `json:"properties"`
		}
		return json.Unmarshal(raw, &p) == nil && p.Properties != nil
	}
	return false
}

func list(ss []string) string {
	sort.Strings(ss)
	if len(ss) > 8 {
		return strings.Join(ss[:8], ", ") + fmt.Sprintf(" (+%d more)", len(ss)-8)
	}
	return strings.Join(ss, ", ")
}
