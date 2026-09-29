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
	"regexp"
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
	docPath       = "docs/ecosystem.md"
	jsonPath      = "ecosystem.json"
	readmePath    = "README.md"
	changelogPath = "CHANGELOG.md"
)

// versionHeading matches the newest release heading; the first match is the
// newest because the changelog is in reverse order.
var versionHeading = regexp.MustCompile(`(?m)^## \[(\d+\.\d+\.\d+)\]`)

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

	files, err := render()
	if err != nil {
		fail(err)
	}
	if *check {
		verify(files)
		return
	}
	for _, f := range files {
		if err := os.WriteFile(f.path, f.want, 0o644); err != nil { //nolint:gosec // documentation and a published manifest, not secrets
			fail(err)
		}
	}
	fmt.Printf("ecosystem: wrote %s, %s and %s (%d repositories: %d released, %d unreleased, %d rejected)\n",
		docPath, readmePath, jsonPath, len(ecosystem.Family),
		len(ecosystem.ByStatus(ecosystem.Released)),
		len(ecosystem.ByStatus(ecosystem.Unreleased)),
		len(ecosystem.ByStatus(ecosystem.Rejected)))
}

// generated is one file this program owns, as committed and as it should be.
type generated struct {
	path      string
	committed []byte
	want      []byte
}

// render reads the committed files and computes what each should contain.
func render() ([]generated, error) {
	doc, err := os.ReadFile(docPath)
	if err != nil {
		return nil, err
	}
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		return nil, err
	}
	changelog, err := os.ReadFile(changelogPath)
	if err != nil {
		return nil, err
	}
	version, err := changelogVersion(string(changelog))
	if err != nil {
		return nil, err
	}
	wantDoc, err := replaceRegion(string(doc), renderTable(), begin, end, docPath)
	if err != nil {
		return nil, err
	}
	wantReadme, err := replaceRegion(string(readme), renderReadmeTable(version), readmeBegin, readmeEnd, readmePath)
	if err != nil {
		return nil, err
	}
	manifest, err := renderJSON()
	if err != nil {
		return nil, err
	}
	// A missing ecosystem.json is simply stale; the write path creates it.
	committedJSON, _ := os.ReadFile(jsonPath)
	return []generated{
		{docPath, doc, []byte(wantDoc)},
		{readmePath, readme, []byte(wantReadme)},
		{jsonPath, committedJSON, manifest},
	}, nil
}

// verify fails the process when any generated file has drifted.
func verify(files []generated) {
	var stale []string
	for _, f := range files {
		if !bytes.Equal(f.committed, f.want) {
			stale = append(stale, f.path)
		}
	}
	if len(stale) > 0 {
		fmt.Fprintf(os.Stderr, "ecosystem: %s is stale — the manifest in internal/ecosystem says something else.\nRun: make ecosystem\n", strings.Join(stale, " and "))
		os.Exit(1)
	}
	fmt.Printf("ecosystem: %s, %s and %s match the manifest (%d repositories)\n", docPath, readmePath, jsonPath, len(ecosystem.Family))
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

// renderReadmeTable is the family section every README in the family
// carries word for word: the version sentence and the component table. The
// version is read from CHANGELOG.md's newest heading, the one place it is
// authored, so a release cannot leave the sentence behind.
func renderReadmeTable(version string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Every component is released at **%s** and moves in lockstep: one version "+
		"across the family, released together "+
		"([docs/ecosystem.md](https://github.com/sebastienrousseau/passmcp/blob/main/docs/ecosystem.md)).\n\n", version)
	b.WriteString("| Component | Purpose | Use case |\n| :--- | :--- | :--- |\n")
	for _, r := range ecosystem.Family {
		if r.Status == ecosystem.Rejected {
			continue
		}
		fmt.Fprintf(&b, "| [%s](%s) | %s | %s |\n", r.Name, r.URL(), r.Purpose, r.UseCase)
	}
	return tidyMarkdown(b.String())
}

// changelogVersion is the newest "## [x.y.z]" heading in CHANGELOG.md.
func changelogVersion(changelog string) (string, error) {
	m := versionHeading.FindStringSubmatch(changelog)
	if m == nil {
		return "", fmt.Errorf("%s has no '## [x.y.z]' heading to take the family version from", changelogPath)
	}
	return m[1], nil
}

// renderTable writes the three tables the manual carries: what is released,
// what is not yet released, and what was rejected. The third is not padding — a rejection
// with a recorded reason is the only kind that stays rejected.
func renderTable() string {
	var b strings.Builder

	b.WriteString("### Released\n\n")
	b.WriteString("| Repository | Licence | Lockstep | What it owns |\n|---|---|---|---|\n")
	for _, r := range ecosystem.ByStatus(ecosystem.Released) {
		fmt.Fprintf(&b, "| [`%s`](%s) | %s | %s | %s |\n", r.Name, r.URL(), r.Licence, yesNo(r.Lockstep), r.Role)
	}

	if unreleased := ecosystem.ByStatus(ecosystem.Unreleased); len(unreleased) > 0 {
		b.WriteString("\n### Not yet released\n\n")
		b.WriteString("**Nothing is installable from these yet.** Each starts at the family's\n")
		b.WriteString("version and joins the release with its first tag. Every row states the\n")
		b.WriteString("boundary that forces a separate repository and the criterion for\n")
		b.WriteString("archiving it.\n\n")
		for _, r := range unreleased {
			fmt.Fprintf(&b, "#### [`%s`](%s)\n\n", r.Name, r.URL())
			fmt.Fprintf(&b, "%s\n\n", r.Role)
			fmt.Fprintf(&b, "- **Licence** %s · **%s** · **Lockstep** %s\n", r.Licence, r.Language, yesNo(r.Lockstep))
			fmt.Fprintf(&b, "- **Why separate** %s\n", r.Boundary)
			fmt.Fprintf(&b, "- **Archive when** %s\n\n", r.Kill)
		}
	}

	b.WriteString("\n### The ssg surfaces\n\n")
	b.WriteString("Every web surface built here is generated by [`ssg`](https://static-site-generator.com/)\n")
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
	Name       string   `json:"name"`
	Repository string   `json:"repository"`
	Status     string   `json:"status"`
	Role       string   `json:"role"`
	Language   string   `json:"language"`
	Licence    string   `json:"license,omitempty"`
	Boundary   string   `json:"boundary,omitempty"`
	Lockstep   bool     `json:"lockstep"`
	Artefacts  []string `json:"artifacts,omitempty"`
	Kill       string   `json:"archive_when,omitempty"`
	Reason     string   `json:"rejected_because,omitempty"`
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
		// 2: statuses became released/unreleased/rejected, and repository
		// names a row whose component name is not its repository.
		SchemaVersion: 2,
		Family:        "passmcp",
		Standard:      "REPO-STANDARD.md",
	}
	for _, r := range ecosystem.Family {
		jr := jsonRepo{
			Name: r.Name, Repository: r.RepoName(), Status: string(r.Status), Role: r.Role, Language: r.Language,
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
