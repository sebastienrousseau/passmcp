// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

//go:build ignore

// ecosystem generates the family table in docs/ecosystem.md and the
// ecosystem.json that repositories outside this one read, and with -check
// fails when either has drifted from the manifest.
//
// REPO-STANDARD requires a CI-checked table of which repository has what, so
// a multi-repository family cannot silently drift. AGENTS.md forbids
// hand-writing a redundant copy of anything that has a primary definition.
// Together those two rules mean the table in the manual cannot be typed by a
// human, which is what this program is for.
//
// It is the same arrangement as scripts/checkinventory, for the same reason,
// and deliberately so: a contributor who has met one has met both.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"

	"satellion.com/passmcp/internal/ecosystem"
)

// The generated region of the manual. Everything between these markers is
// this program's; everything outside is prose, and prose is not generated.
const (
	begin = "<!-- BEGIN generated family table — run `make ecosystem`; do not edit by hand -->"
	end   = "<!-- END generated family table -->"

	// The README carries a shorter version of the same table. It is
	// generated from the same manifest rather than kept in step by hand:
	// a family map that disagrees with itself in two files is worse than
	// one that exists in neither.
	readmeBegin = "<!-- BEGIN generated readme family table — run `make ecosystem`; do not edit by hand -->"
	readmeEnd   = "<!-- END generated readme family table -->"
)

const (
	docPath    = "docs/ecosystem.md"
	jsonPath   = "ecosystem.json"
	readmePath = "README.md"
)

func main() {
	check := flag.Bool("check", false, "verify the committed files match the manifest instead of writing them")
	flag.Parse()

	errs := ecosystem.Validate()
	errs = append(errs, ecosystem.ValidateSites()...)
	if len(errs) > 0 {
		for _, err := range errs {
			fmt.Fprintf(os.Stderr, "ecosystem: %v\n", err)
		}
		fmt.Fprintln(os.Stderr, "\nThe manifest contradicts itself; nothing generated from it would be trustworthy.")
		os.Exit(1)
	}

	doc, err := os.ReadFile(docPath)
	if err != nil {
		fail(err)
	}
	updated, err := replaceRegion(string(doc), renderTable(), begin, end, docPath)
	if err != nil {
		fail(err)
	}
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		fail(err)
	}
	updatedReadme, err := replaceRegion(string(readme), renderReadmeTable(), readmeBegin, readmeEnd, readmePath)
	if err != nil {
		fail(err)
	}
	manifest, err := renderJSON()
	if err != nil {
		fail(err)
	}

	if *check {
		var stale []string
		if updated != string(doc) {
			stale = append(stale, docPath)
		}
		if updatedReadme != string(readme) {
			stale = append(stale, readmePath)
		}
		if committed, err := os.ReadFile(jsonPath); err != nil || !bytes.Equal(committed, manifest) {
			stale = append(stale, jsonPath)
		}
		if len(stale) > 0 {
			fmt.Fprintf(os.Stderr, "ecosystem: %s is stale — the manifest in internal/ecosystem says something else.\nRun: make ecosystem\n", strings.Join(stale, " and "))
			os.Exit(1)
		}
		fmt.Printf("ecosystem: %s and %s match the manifest (%d repositories)\n", docPath, jsonPath, len(ecosystem.Family))
		return
	}

	if err := os.WriteFile(docPath, []byte(updated), 0o644); err != nil { //nolint:gosec // documentation, not a secret
		fail(err)
	}
	if err := os.WriteFile(readmePath, []byte(updatedReadme), 0o644); err != nil { //nolint:gosec // documentation, not a secret
		fail(err)
	}
	if err := os.WriteFile(jsonPath, manifest, 0o644); err != nil { //nolint:gosec // a published manifest
		fail(err)
	}
	fmt.Printf("ecosystem: wrote %s and %s (%d repositories: %d shipping, %d planned, %d rejected)\n",
		docPath, jsonPath, len(ecosystem.Family),
		len(ecosystem.ByStatus(ecosystem.Shipping)),
		len(ecosystem.ByStatus(ecosystem.Planned)),
		len(ecosystem.ByStatus(ecosystem.Rejected)))
}

func fail(err error) {
	fmt.Fprintf(os.Stderr, "ecosystem: %v\n", err)
	os.Exit(1)
}

// replaceRegion swaps the generated region for body, leaving the prose alone.
func replaceRegion(doc, body, from, to, path string) (string, error) {
	i := strings.Index(doc, from)
	j := strings.Index(doc, to)
	if i < 0 || j < 0 || j < i {
		return "", fmt.Errorf("%s has no generated region; it needs the BEGIN and END markers", path)
	}
	return doc[:i+len(from)] + "\n\n" + body + "\n" + doc[j:], nil
}

// renderReadmeTable is the one-glance version: every repository, its status,
// its licence and what it owns. The manual carries the reasoning; a README
// that carried all of it would bury the install instructions.
func renderReadmeTable() string {
	var b strings.Builder
	b.WriteString("| Repository | Status | Licence | What it owns |\n|---|---|---|---|\n")
	for _, r := range ecosystem.Family {
		if r.Status == ecosystem.Rejected {
			continue
		}
		name := "`" + r.Name + "`"
		if r.Name == "passmcp" {
			name = "**`" + r.Name + "`**"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s |\n", name, r.Status, r.Licence, r.Role)
	}
	return tidyMarkdown(b.String())
}

// renderTable writes the three tables the manual carries: what exists, what
// is planned, and what was rejected. The third is not padding — a rejection
// with a recorded reason is the only kind that stays rejected.
func renderTable() string {
	var b strings.Builder

	b.WriteString("### Shipping\n\n")
	b.WriteString("| Repository | Licence | Lockstep | What it owns |\n|---|---|---|---|\n")
	for _, r := range ecosystem.ByStatus(ecosystem.Shipping) {
		fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", r.Name, r.Licence, yesNo(r.Lockstep), r.Role)
	}

	if planned := ecosystem.ByStatus(ecosystem.Planned); len(planned) > 0 {
		b.WriteString("\n### Planned\n\n")
		b.WriteString("**These do not exist yet.** They are recorded so the layout cannot drift\n")
		b.WriteString("silently once they do, and so nobody goes looking for them. Every row states\n")
		b.WriteString("the boundary that forces a separate repository and the criterion for\n")
		b.WriteString("archiving it.\n\n")
		for _, r := range planned {
			fmt.Fprintf(&b, "#### `%s`\n\n", r.Name)
			fmt.Fprintf(&b, "%s\n\n", r.Role)
			fmt.Fprintf(&b, "- **Licence** %s · **%s** · **Lockstep** %s\n", r.Licence, r.Language, yesNo(r.Lockstep))
			fmt.Fprintf(&b, "- **Why separate** %s\n", r.Boundary)
			fmt.Fprintf(&b, "- **Archive when** %s\n\n", r.Kill)
		}
	}

	b.WriteString("\n### The ssg surfaces\n\n")
	b.WriteString("Both web surfaces are generated by [`ssg`](https://static-site-generator.com/)\n")
	b.WriteString("from a theme in the [SSG theme suite](https://github.com/sebastienrousseau/ssg-themes.github.io).\n")
	b.WriteString("That is an invariant, not a habit: `make ssg-check` fails the build when a\n")
	b.WriteString("page appears outside a layout, when a configuration stops matching this\n")
	b.WriteString("table, or when CI would install an ssg older than the theme requires.\n\n")
	b.WriteString("| Surface | Theme | Vendored from | Layouts | Output | Embedded |\n|---|---|---|---|---|---|\n")
	for _, s := range ecosystem.Sites {
		fmt.Fprintf(&b, "| `%s` | %s | `%s` (min ssg %s) | `%s` | `%s` | %s |\n",
			s.Name, s.Theme, s.Revision, s.MinSSG, s.Layouts, s.Output, yesNo(s.Embedded))
	}
	if len(ecosystem.ThemeDeltas) > 0 {
		fmt.Fprintf(&b, "\nThe layouts are vendored so the site builds in CI with nothing but the `ssg`\n"+
			"binary. %d file(s) deliberately differ from the theme, each with a recorded\n"+
			"reason — a declared delta is a patch on its way upstream, and an undeclared\n"+
			"one is a fork nobody decided to make. The list is in\n"+
			"[`internal/ecosystem/sites.go`](https://github.com/sebastienrousseau/passmcp/blob/main/internal/ecosystem/sites.go).\n", len(ecosystem.ThemeDeltas))
	}

	if rejected := ecosystem.ByStatus(ecosystem.Rejected); len(rejected) > 0 {
		b.WriteString("### Considered and rejected\n\n")
		b.WriteString("| Repository | Why not |\n|---|---|\n")
		for _, r := range rejected {
			fmt.Fprintf(&b, "| `%s` | %s |\n", r.Name, r.Reason)
		}
	}

	return tidyMarkdown(b.String())
}

// tidyMarkdown makes the generated region satisfy markdownlint, rather than
// leaving it to whoever last edited a WriteString.
//
// Two rules matter here and both were broken on the first run: MD022 wants a
// blank line above and below every heading, and MD012 forbids two blank lines
// in a row. Hand-tuning the writers to satisfy them is how a generator grows
// a spacing bug every time a section is added, so the guarantee is made once,
// at the end, over the whole block.
func tidyMarkdown(md string) string {
	var out []string
	for _, line := range strings.Split(md, "\n") {
		heading := strings.HasPrefix(line, "#")
		if heading && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) != "" {
			out = append(out, "")
		}
		// Never two blank lines in a row.
		if strings.TrimSpace(line) == "" && len(out) > 0 && strings.TrimSpace(out[len(out)-1]) == "" {
			continue
		}
		out = append(out, line)
		if heading {
			out = append(out, "")
		}
	}
	return strings.TrimRight(strings.Join(out, "\n"), "\n")
}

// jsonRepo is the published shape. It is separate from the Go type on
// purpose: this one is a contract with repositories that are not written in
// Go, so it changes only deliberately.
type jsonRepo struct {
	Name      string   `json:"name"`
	Status    string   `json:"status"`
	Role      string   `json:"role"`
	Language  string   `json:"language"`
	Licence   string   `json:"license,omitempty"`
	Boundary  string   `json:"boundary,omitempty"`
	Lockstep  bool     `json:"lockstep"`
	Artefacts []string `json:"artifacts,omitempty"`
	Kill      string   `json:"archive_when,omitempty"`
	Reason    string   `json:"rejected_because,omitempty"`
}

// jsonSite and jsonDelta are the published shape of the ssg surfaces, so a
// repository that is not written in Go can read which theme revision a site
// was vendored from.
type jsonSite struct {
	Name     string `json:"name"`
	Config   string `json:"config"`
	Layouts  string `json:"layouts"`
	Output   string `json:"output"`
	Embedded bool   `json:"embedded"`
	Theme    string `json:"theme"`
	Upstream string `json:"upstream"`
	Revision string `json:"revision"`
	MinSSG   string `json:"min_ssg_version"`

	Deltas []jsonDelta `json:"declared_deltas,omitempty"`
}

type jsonDelta struct {
	File       string `json:"file"`
	Reason     string `json:"reason"`
	Upstreamed string `json:"upstreamed,omitempty"`
}

func renderJSON() ([]byte, error) {
	out := struct {
		Comment       string     `json:"_comment"`
		SchemaVersion int        `json:"schema_version"`
		Family        string     `json:"family"`
		Standard      string     `json:"standard"`
		Repositories  []jsonRepo `json:"repositories"`
		Sites         []jsonSite `json:"sites"`
	}{
		Comment: "Generated from internal/ecosystem by scripts/ecosystem. Do not edit by hand. " +
			"Every repository in the family verifies its own row against this file in CI.",
		SchemaVersion: 1,
		Family:        "passmcp",
		Standard:      "REPO-STANDARD.md",
	}
	for _, r := range ecosystem.Family {
		jr := jsonRepo{
			Name: r.Name, Status: string(r.Status), Role: r.Role, Language: r.Language,
			Licence: r.Licence, Boundary: r.Boundary, Lockstep: r.Lockstep,
			Kill: r.Kill, Reason: r.Reason,
		}
		for _, a := range r.Artefacts {
			jr.Artefacts = append(jr.Artefacts, string(a))
		}
		out.Repositories = append(out.Repositories, jr)
	}
	for _, s := range ecosystem.Sites {
		js := jsonSite{
			Name: s.Name, Config: s.Config, Layouts: s.Layouts, Output: s.Output,
			Embedded: s.Embedded, Theme: s.Theme, Upstream: s.Upstream,
			Revision: s.Revision, MinSSG: s.MinSSG,
		}
		for _, d := range ecosystem.DeltasFor(s.Name) {
			js.Deltas = append(js.Deltas, jsonDelta{File: d.File, Reason: d.Reason, Upstreamed: d.Upstreamed})
		}
		out.Sites = append(out.Sites, js)
	}
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}
