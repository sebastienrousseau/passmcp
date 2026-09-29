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
// A status names a fact that can be checked, a tag or its absence, rather
// than an intention: "shipping" and "planned" said how a row felt, and a
// reader could not tell from either whether there was anything to install.
type Status string

// The statuses a repository can be in.
const (
	// Released means the repository exists and carries the family's current
	// version as a tag.
	Released Status = "released"
	// Unreleased means the repository is part of the family and starts at
	// the family's version, and that version has not been tagged there yet.
	// Nothing is installable from it until it is.
	Unreleased Status = "unreleased"
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
	// Name is the component's name as the family table shows it. For every
	// row but the website it is also the repository name.
	Name string
	// Repository is the GitHub repository when it differs from Name. The
	// website is named for its domain, satellion.com, and lives in
	// satellion.github.io.
	Repository string
	// Status says whether it exists.
	Status Status
	// Role is the one-line answer to "what is this for", as the manual
	// states it.
	Role string
	// Purpose and UseCase are the two cells of the family table every README
	// in the family carries, word for word. They are shorter than Role on
	// purpose: the README table is read at a glance.
	Purpose string
	UseCase string
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
	// Lockstep says whether it carries passmcp's version. Every row that is
	// not rejected must: docs/ecosystem.md states the rule, and Validate
	// refuses a live row outside it.
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

// Family is the whole manifest, in the order the family table lists it.
//
// Every row that is not rejected is in lockstep: one version across the
// family, released together. docs/ecosystem.md records when and why that
// became true of the language server and the census, which were once outside
// it.
var Family = []Repo{
	{
		Name:     "passmcp",
		Status:   Released,
		Role:     "The engine, every check, and the three peer surfaces: CLI, TUI and the embedded local web UI.",
		Purpose:  "The MCP server diagnostic: checks in nine phases, every finding tied to the request that showed it, signed attestations",
		UseCase:  "Test a server before your agents trust it, and gate it in CI",
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
		Status:   Released,
		Role:     "The attestation predicate, its JSON Schema and the offline verifier, as a module with no dependencies; the report schema, the renderers and the rubric as data follow when a consumer needs them.",
		Purpose:  "The attestation format, its JSON Schemas and offline verifier, the graph model, and the agentgateway processor",
		UseCase:  "Verify an attestation in a gateway, registry or pipeline",
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
		Status:   Released,
		Role:     "An MCP server exposing passmcp's diagnostics as read-only tools, so an agent can evaluate a server, or check an attestation about one, from inside the editor.",
		Purpose:  "passmcp's diagnostics as read-only MCP tools",
		UseCase:  "Evaluate a server, or check an attestation, from inside the agent",
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
		Name:     "passmcp-action",
		Status:   Released,
		Role:     "The GitHub Action wrapping the published image by digest, and a GitLab CI template.",
		Purpose:  "passmcp in GitHub Actions and GitLab CI, the image pinned by digest",
		UseCase:  "Fail a build on the findings you choose",
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
		Name:     "passmcp-graph",
		Status:   Released,
		Role:     "A local graph of which agents use which MCP servers, which tools those servers expose and which identities reach them, built from passmcp's attestations, reports and MCP client configurations, queried offline and gated by policy in CI.",
		Purpose:  "A local graph of agents, servers, tools and identities built from attestations",
		UseCase:  "Find inherited risk and over-privilege, and gate on policy",
		Language: "go",
		Licence:  "GPL-3.0-only",
		Boundary: "It consumes evidence rather than producing it. It reads attestations, reports and client configurations, makes no network request, and carries a store and a query language of its own that the diagnostic does not need.",
		Lockstep: true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Security, Conduct, Contributing,
			Agents, Makefile, Docs, Scripts, EditorConfig, Workflows,
		},
		Kill: "Not yet recorded: the owner has not stated one, and this row is the reminder that one is owed.",
	},
	{
		Name:     "passmcp-registry",
		Status:   Released,
		Role:     "A signed public scorecard of the remote servers in the MCP Registry: each checked read-only and without credentials by a pinned passmcp release, every result an offline-verifiable attestation, and anything that would expose a vulnerability withheld for its owner first.",
		Purpose:  "A signed public scorecard of the MCP Registry's remote servers",
		UseCase:  "Check a public server's standing before connecting to it",
		Language: "go",
		Licence:  "AGPL-3.0-only AND CC-BY-4.0",
		Boundary: "A hosted service with its own operational and disclosure duties, under its own licences: the code is AGPL-3.0-only and the published scorecard CC-BY-4.0.",
		Lockstep: true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Development, Security, Support,
			Governance, Conduct, Contributing, Agents, Makefile, Docs, Scripts,
			EditorConfig, Workflows,
		},
		Kill: "Not yet recorded: the owner has not stated one, and this row is the reminder that one is owed.",
	},
	{
		Name:     "passmcp-lsp",
		Status:   Unreleased,
		Role:     "A language server over MCP artefacts — server.json, tool schemas, client configuration, passmcp policy and attestation files — with check-id hover from the guidance catalogue.",
		Purpose:  "A language server for MCP artefacts, with check-id hover from the guidance catalogue",
		UseCase:  "Catch mistakes in server.json, tool schemas and client configuration while editing",
		Language: "go",
		Licence:  "Apache-2.0",
		Boundary: "Editor embedding. It ships inside editors and extension marketplaces whose licensing is not passmcp's; the extensions live in its own editors/ directory rather than a repository each.",
		Lockstep: true,
		Kill:     "The guidance hover goes unused. Scoped so that cutting it costs one repository and no capability.",
	},
	{
		Name:     "passmcp-census",
		Status:   Unreleased,
		Role:     "The published reliability census: the dataset, the methodology, the disclosure log and the reproduction command.",
		Purpose:  "The published reliability census: dataset, methodology, disclosure log and reproduction command",
		UseCase:  "Cite ecosystem-wide reliability figures, and reproduce them",
		Language: "data",
		Licence:  "CC-BY-4.0",
		Boundary: "Licence. A GPL repository cannot cleanly carry a CC-BY dataset.",
		Lockstep: true,
		Kill:     "The census is not repeated on schedule. Delete it rather than leave a stale dataset presented as current.",
	},
	{
		Name:       "satellion.com",
		Repository: "satellion.github.io",
		Status:     Released,
		Role:       "The public site at satellion.com, built with SSG against passmcp's latest release: the home page, the manual and a sample report passmcp generates.",
		Purpose:    "The website, the Go module paths and the format URIs",
		UseCase:    "Read the manual, and resolve `satellion.com/...` imports",
		Language:   "web",
		Licence:    "GPL-3.0-only",
		Boundary:   "A different toolchain: the site builds with SSG and MkDocs against passmcp's latest release, which the engine's CI should not need.",
		Lockstep:   true,
		Artefacts: []Artefact{
			Readme, Changelog, Licence, Licences, Reuse, Security, Conduct, Contributing,
			Makefile, Scripts, Workflows,
		},
		Kill: "The page's numbers stop coming from a passmcp release.",
	},
	{
		Name:     "passmcp-gateway",
		Status:   Rejected,
		Role:     "An in-path MCP gateway.",
		Language: "—",
		Reason:   "Fourteen incumbents, two of them free and open source, one of them AWS. Being in the data path would also convert passmcp from a tool that touches nothing into a production dependency trusted with traffic.",
	},
	{
		Name:     "passmcp-wasm",
		Status:   Rejected,
		Role:     "A browser build of the engine.",
		Language: "—",
		Reason:   "CORS blocks a browser build against most servers. A build target, not a repository.",
	},
	{
		Name:     "passmcp-proxy",
		Status:   Rejected,
		Role:     "An in-path proxy that inspects, or sanitises and rewrites, live traffic between an agent and a server (also proposed as passmcp-inspector and passmcp-shield).",
		Language: "—",
		Reason:   "The gateway again under another name: in the data path is in the data path whether it only watches or also rewrites (ADR 0007). A rewriting shield would also judge by classifier rather than cite the request that showed the property (ADR 0002). Live inspection is the official MCP Inspector's job.",
	},
	{
		Name:     "passmcp-fuzz",
		Status:   Rejected,
		Role:     "A stress and fuzzing tool that sends servers malformed input, oversized payloads and connection churn (also proposed as passmcp-chaos).",
		Language: "—",
		Reason:   "An adversarial mode in its own repository, which ADR 0008 rules out behind a flag and behind a verb alike: the read-only posture is what lets a security team approve passmcp. Resilience is already a phase of the check, and passmcp fuzzes its own parsers.",
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
	switch r.Status {
	case Released, Unreleased:
		return liveProblems(r)
	case Rejected:
		var errs []error
		if r.Reason == "" {
			errs = append(errs, fmt.Errorf("%s: rejected with no reason, so it will be re-argued in six months", r.Name))
		}
		if len(r.Artefacts) > 0 || r.Lockstep {
			errs = append(errs, fmt.Errorf("%s: rejected but carries artefacts or lockstep", r.Name))
		}
		return errs
	default:
		return []error{fmt.Errorf("%s: unknown status %q", r.Name, r.Status)}
	}
}

// liveProblems reports what a released or unreleased row lacks. Every such
// row is a real repository in the family, so it needs what the family table
// and the manual say about it, and it carries the family's version.
func liveProblems(r Repo) []error {
	var errs []error
	if r.Licence == "" {
		errs = append(errs, fmt.Errorf("%s: no licence, and the licence boundaries are the reason this family has the shape it does", r.Name))
	}
	if r.Purpose == "" || r.UseCase == "" {
		errs = append(errs, fmt.Errorf("%s: no purpose or use case, so the family table every README carries has an empty cell", r.Name))
	}
	if !r.Lockstep {
		errs = append(errs, fmt.Errorf("%s: not in lockstep; every repository in the family carries one version", r.Name))
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
	return errs
}

// RepoName is the GitHub repository that holds the row: Repository when it
// is set, and Name otherwise.
func (r Repo) RepoName() string {
	if r.Repository != "" {
		return r.Repository
	}
	return r.Name
}

// URL is the row's repository on GitHub.
func (r Repo) URL() string {
	return "https://github.com/sebastienrousseau/" + r.RepoName()
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
