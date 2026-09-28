// SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
// SPDX-License-Identifier: GPL-3.0-only

// Package ecosystem is the family manifest: which repositories exist around
// passmcp, what each one owns, and which of the standard artefacts it carries.
//
// REPO-STANDARD requires a CI-checked table of which repository has what, so
// that a multi-repository family cannot silently drift. This is that table,
// and it is a typed Go value rather than a configuration file for three
// reasons: the compiler checks it, a test can assert invariants over it, and
// nothing has to parse it.
//
// It is the single source. docs/ecosystem.md's table and the ecosystem.json
// that non-Go repositories read are both generated from here by
// scripts/ecosystem, and CI fails when either has drifted — the same
// arrangement as the generated check inventory, for the same reason.
package ecosystem

import (
	"fmt"
	"sort"
	"strings"
)

// Status is how far a repository has actually got.
//
// Planned is recorded rather than omitted so that the layout cannot drift
// silently once it exists, and so nobody goes looking for it. A map that
// lists things which do not exist is worse than no map only when it fails to
// say so — this says so.
type Status string

// The statuses a repository can be in.
const (
	// Shipping means it exists, releases, and is covered by CI.
	Shipping Status = "shipping"
	// Planned means designed here and not yet created.
	Planned Status = "planned"
	// Rejected means considered and deliberately not built. The reason is
	// the point: a rejection with no recorded reason gets re-argued every
	// six months.
	Rejected Status = "rejected"
)

// Artefact is one of the standard files or directories REPO-STANDARD expects.
// A repository's row lists the ones it carries, and the verifier checks that
// passmcp's own row is true of the working tree.
type Artefact string

// The artefacts the standard asks for. Not every repository needs every one:
// GNUmakefile is for anything shipping a binary, pkg/ for anything
// distributed, and a data repository needs almost none of them.
const (
	Readme       Artefact = "README.md"
	Changelog    Artefact = "CHANGELOG.md"
	Licence      Artefact = "LICENSE"
	Licences     Artefact = "LICENSES"
	Reuse        Artefact = "REUSE.toml"
	Development  Artefact = "DEVELOPMENT.md"
	Security     Artefact = "SECURITY.md"
	Support      Artefact = "SUPPORT.md"
	Governance   Artefact = "GOVERNANCE.md"
	Conduct      Artefact = "CODE_OF_CONDUCT.md"
	Contributing Artefact = "CONTRIBUTING.md"
	Agents       Artefact = "AGENTS.md"
	Citation     Artefact = "CITATION.cff"
	Makefile     Artefact = "Makefile"
	GNUMakefile  Artefact = "GNUmakefile"
	Docs         Artefact = "docs"
	ADRs         Artefact = "docs/adr"
	Examples     Artefact = "examples"
	Packaging    Artefact = "pkg"
	Scripts      Artefact = "scripts"
	SupplyChain  Artefact = "supply-chain"
	DevContainer Artefact = ".devcontainer"
	EditorConfig Artefact = ".editorconfig"
	PreCommit    Artefact = ".pre-commit-config.yaml"
	Workflows    Artefact = ".github/workflows"
)

// Repo is one repository in the family.
type Repo struct {
	// Name is the repository name, which is also its directory name under
	// the language root in the working checkout.
	Name string
	// Status says whether it exists.
	Status Status
	// Role is the one-line answer to "what is this for".
	Role string
	// Language is the primary toolchain, or "data" for a dataset.
	Language string
	// Licence is the SPDX expression. It differs across the family on
	// purpose: the engine is copyleft, the pieces that have to be embedded
	// by other people's software are not, and the dataset is neither.
	Licence string
	// Boundary is why this is a separate repository rather than a directory.
	// A row that cannot answer this is sprawl, and the test enforces that
	// every non-central row answers it.
	Boundary string
	// Lockstep says whether it carries passmcp's version. docs/ecosystem.md
	// states the rule; this records which rows it binds.
	Lockstep bool
	// Artefacts are the standard files this repository carries.
	Artefacts []Artefact
	// Kill is the criterion for archiving it. A satellite with no stated
	// kill criterion is a permanent maintenance obligation nobody agreed
	// to take on.
	Kill string
	// Reason is why a Rejected row was rejected.
	Reason string
}

// Family is the whole manifest.
var Family = []Repo{
	{
		Name:     "passmcp",
		Status:   Shipping,
		Role:     "The engine, every check, and the three peer surfaces: CLI, TUI and the embedded local web UI.",
		Language: "go",
		Licence:  "GPL-3.0-only",
		Lockstep: true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Development, Security, Support,
			Governance, Conduct, Contributing, Agents, Citation, Makefile, GNUMakefile,
			Docs, ADRs, Examples, Packaging, Scripts, SupplyChain, DevContainer,
			EditorConfig, PreCommit, Workflows,
		},
	},
	{
		Name:     "passmcp-reporting",
		Status:   Shipping,
		Role:     "The attestation predicate, its JSON Schema and the offline verifier, as a module with no dependencies; the report schema, the renderers and the rubric as data follow when a consumer needs them.",
		Language: "go",
		Licence:  "Apache-2.0",
		Boundary: "Licence and dependency graph. A GPL-3.0 library cannot be embedded by the gateways and registries the strategy depends on, and a package inside passmcp's module drags passmcp's dependencies into any importer's go.sum, so the format and the verifier have to live where they can be imported clean.",
		Lockstep: true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Development, Security, Support,
			Governance, Conduct, Contributing, Agents, Citation, Makefile,
			Docs, ADRs, Examples, Scripts, EditorConfig, PreCommit, Workflows,
		},
		Kill: "No third party has adopted the predicate twelve months after v1. Fold it back into passmcp and stop paying the two-repository cost.",
	},
	{
		Name:     "passmcp-server",
		Status:   Shipping,
		Role:     "An MCP server exposing passmcp's diagnostics as read-only tools, so an agent can evaluate a server, or check an attestation about one, from inside the editor.",
		Language: "go",
		Licence:  "GPL-3.0-only",
		Boundary: "Distribution surface. Its deliverable is a registry listing — server.json, glama.json, a container catalogue entry — which is a different release artefact with a different review path.",
		Lockstep: true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Development, Security, Support,
			Governance, Conduct, Contributing, Agents, Citation, Makefile,
			Docs, ADRs, Scripts, EditorConfig, PreCommit, Workflows,
		},
		Kill: "Registry listings produce no measurable referrals across two quarters.",
	},
	{
		Name:     "satellion.com",
		Status:   Shipping,
		Role:     "The public site at satellion.com, built with SSG against passmcp's latest release: the home page, the manual and a sample report passmcp generates.",
		Language: "web",
		Licence:  "GPL-3.0-only",
		Boundary: "A different release cadence and toolchain: the site follows passmcp's releases daily and builds with SSG and MkDocs, which the engine's CI should not need.",
		Lockstep: false,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Security, Conduct, Contributing,
			Makefile, Scripts, Workflows,
		},
		Kill: "The page's numbers stop coming from a passmcp release.",
	},
	{
		Name:     "passmcp-action",
		Status:   Shipping,
		Role:     "The GitHub Action wrapping the published image by digest, and a GitLab CI template.",
		Language: "composite",
		Licence:  "Apache-2.0",
		Boundary: "The Marketplace requires its own repository. It is also the cheapest verifiable traction signal, because GitHub publishes the usage count.",
		Lockstep: true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Development, Security, Support,
			Governance, Conduct, Contributing, Agents, Citation, Makefile,
			Docs, ADRs, Examples, Scripts, EditorConfig, PreCommit, Workflows,
		},
		Kill: "None. It is the lowest-cost, highest-signal artefact in the family.",
	},
	{
		Name:     "passmcp-lsp",
		Status:   Planned,
		Role:     "A language server over MCP artefacts — server.json, tool schemas, client configuration, passmcp policy and attestation files — with check-id hover from the guidance catalogue.",
		Language: "go",
		Licence:  "Apache-2.0",
		Boundary: "Editor embedding. It ships inside editors and extension marketplaces whose licensing and release cadence are not passmcp's; the extensions live in its own editors/ directory rather than a repository each.",
		Lockstep: false,
		Kill:     "The guidance hover goes unused. Scoped so that cutting it costs one repository and no capability.",
	},
	{
		Name:     "passmcp-census",
		Status:   Planned,
		Role:     "The published reliability census: the dataset, the methodology, the disclosure log and the reproduction command.",
		Language: "data",
		Licence:  "CC-BY-4.0",
		Boundary: "Licence and cadence. A GPL repository cannot cleanly carry a CC-BY dataset, and a quarterly data release has no business sharing a version with a fortnightly tool release.",
		Lockstep: false,
		Kill:     "The census is not repeated on schedule. Delete it rather than leave a stale dataset presented as current.",
	},
	{
		Name:     "passmcp-gateway",
		Status:   Rejected,
		Role:     "An in-path MCP gateway.",
		Language: "—",
		Reason:   "Fourteen incumbents, two of them free and open source, one of them AWS. Being in the data path would also convert passmcp from a tool that touches nothing into a production dependency trusted with traffic.",
	},
	{
		Name:     "passmcp-registry",
		Status:   Rejected,
		Role:     "An index of MCP servers.",
		Language: "—",
		Reason:   "Contested by the official registry, the container catalogue and four directories, two of which already publish a score. Supply the signal they display instead.",
	},
	{
		Name:     "passmcp-wasm",
		Status:   Rejected,
		Role:     "A browser build of the engine.",
		Language: "—",
		Reason:   "CORS blocks a browser build against most servers. A build target, not a repository.",
	},
}

// Validate reports every way the manifest contradicts itself.
//
// It returns all the problems rather than the first, because a contributor
// fixing a manifest wants the list.
func Validate() []error {
	var errs []error
	seen := map[string]bool{}
	for _, r := range Family {
		switch {
		case r.Name == "":
			errs = append(errs, fmt.Errorf("a row has no name"))
			continue
		case seen[r.Name]:
			errs = append(errs, fmt.Errorf("%s: listed twice", r.Name))
			continue
		}
		seen[r.Name] = true
		errs = append(errs, rowProblems(r)...)
	}
	if !seen["passmcp"] {
		errs = append(errs, fmt.Errorf("the manifest does not list passmcp, which is the one row that cannot be missing"))
	}
	return errs
}

// rowProblems reports what one row, already known to be named and not a
// duplicate, says that contradicts itself.
func rowProblems(r Repo) []error {
	var errs []error
	if r.Role == "" {
		errs = append(errs, fmt.Errorf("%s: no role; a row that cannot say what it is for is sprawl", r.Name))
	}
	errs = append(errs, statusProblems(r)...)
	art := map[Artefact]bool{}
	for _, a := range r.Artefacts {
		if art[a] {
			errs = append(errs, fmt.Errorf("%s: artefact %s listed twice", r.Name, a))
		}
		art[a] = true
	}
	return errs
}

// statusProblems reports what a row's status requires of it and it lacks.
func statusProblems(r Repo) []error {
	var errs []error
	switch r.Status {
	case Shipping, Planned:
		if r.Licence == "" {
			errs = append(errs, fmt.Errorf("%s: no licence, and the licence boundaries are the reason this family has the shape it does", r.Name))
		}
		if r.Name != "passmcp" && r.Boundary == "" {
			errs = append(errs, fmt.Errorf("%s: no boundary; every repository other than the centre must say why it is not a directory", r.Name))
		}
		if r.Name != "passmcp" && r.Kill == "" {
			errs = append(errs, fmt.Errorf("%s: no kill criterion; a satellite without one is a permanent obligation nobody agreed to", r.Name))
		}
		if r.Reason != "" {
			errs = append(errs, fmt.Errorf("%s: has a rejection reason but is not rejected", r.Name))
		}
	case Rejected:
		if r.Reason == "" {
			errs = append(errs, fmt.Errorf("%s: rejected with no reason, so it will be re-argued in six months", r.Name))
		}
		if len(r.Artefacts) > 0 || r.Lockstep {
			errs = append(errs, fmt.Errorf("%s: rejected but carries artefacts or lockstep", r.Name))
		}
	default:
		errs = append(errs, fmt.Errorf("%s: unknown status %q", r.Name, r.Status))
	}
	return errs
}

// Lookup returns the row for name.
func Lookup(name string) (Repo, bool) {
	for _, r := range Family {
		if r.Name == name {
			return r, true
		}
	}
	return Repo{}, false
}

// ByStatus returns the rows with the given status, in manifest order.
func ByStatus(s Status) []Repo {
	var out []Repo
	for _, r := range Family {
		if r.Status == s {
			out = append(out, r)
		}
	}
	return out
}

// ArtefactList renders a row's artefacts as a sorted, comma-separated string,
// for a generated table.
func (r Repo) ArtefactList() string {
	out := make([]string, len(r.Artefacts))
	for i, a := range r.Artefacts {
		out[i] = string(a)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
