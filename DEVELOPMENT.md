<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Development

The single entry point for working on passmcp: toolchain, how to reproduce
every CI gate locally, how the tests are laid out, and how a release is cut.

If a gate fails in CI and you cannot reproduce it from this file, that is a
bug in this file — please report it.

## Contents

- [Requirements](#requirements)
- [Everyday tasks](#everyday-tasks)
- [Reproducing every CI gate](#reproducing-every-ci-gate)
- [Coverage](#coverage)
- [Test layout](#test-layout)
- [Trying it against a real server](#trying-it-against-a-real-server)
- [Generated artefacts](#generated-artefacts)
- [Release model](#release-model)
- [Conventions](#conventions)

## Requirements

| Tool | Version | Why |
|---|---|---|
| Go | as pinned by the `go` directive in `go.mod` | `GOTOOLCHAIN=auto` downloads it; CI never pins a version separately, so `go.mod` is the single source of truth |
| make | any | Task runner for everything below |

Optional, only needed for the gate that uses them:

| Tool | Used by |
|---|---|
| `golangci-lint` | `make lint` |
| `goreleaser` | release dry runs |
| `groff` | manpage rendering check |
| `markdownlint-cli2`, `codespell`, `lychee` | the Docs Lint workflow and `pre-commit` |
| `nix` | optional; `nix develop` provides every row above, pinned |

Nothing else is required. There is no code generation step in the build,
no vendored dependency tree, and no CGO — `CGO_ENABLED=0` everywhere, which
is what makes the released binaries static and the cross-compilation
trivial.

```sh
git clone https://github.com/sebastienrousseau/passmcp.git
cd passmcp
make            # format, vet, lint, tests, build
```

## Everyday tasks

`make help` lists every target. The ones you will actually use:

| Command | What it does |
|---|---|
| `make build` | Compile `passmcp` into `build/` with version metadata |
| `make test` | Run the suite |
| `make test-race` | Race detector with randomised test order |
| `make fuzz` | Run every fuzz target for a short, fixed budget |
| `make docs` | Generate manpages and completions into `build/` |
| `make docs-lock` | Regenerate `docs/requirements.txt` after editing `docs/requirements.in` |
| `make checks` | Regenerate `docs/checks.md` from the check call sites |
| `make install` | Install under `PREFIX` (default `/usr/local`) |
| `make uninstall` | Remove everything `install` placed |
| `make clean` | Remove build output |

## Reproducing every CI gate

Every gate below is a job in `.github/workflows/`. The left column is what
CI runs; the right column is the identical command locally. If you run all
of them and they pass, CI will pass — the only thing you cannot reproduce
is the cross-platform matrix.

| CI job | Reproduce locally |
|---|---|
| Build and test | `go build ./... && make test` |
| Race and shuffled tests | `make test-race` |
| Lint | `make lint` |
| Vulnerability scan | `go run golang.org/x/vuln/cmd/govulncheck@latest ./...` |
| Licence headers (SPDX) | `make spdx-check` |
| SBOM drift | `make sbom` |
| Example compilation | `make example-check` |
| API compatibility | `make api-check` |
| Check inventory | `make checks-verify` (regenerate with `make checks`) |
| Acceptance-criteria trace | `make trace-check` (report only: `make trace`) |
| Fuzz targets | `make fuzz` |
| Install contract | `make install-smoke` |
| Manpage rendering | `make docs && groff -man -Tutf8 -ww build/man/passmcp.1 >/dev/null` |
| Docs lint (markdown, spelling, links) | `pre-commit run --all-files` |

Coverage has its own section below.

To check a release without publishing anything:

```sh
goreleaser release --snapshot --clean --skip=publish,sign,announce
```

That builds every target, runs the manpage/completion generation hook, and
produces the archives and packages in `dist/` for inspection. The same path
runs in CI via the release workflow's `workflow_dispatch` dry-run.

## Coverage

The threshold is 85% of statements, per package, and the rationale is in
[Conventions](#conventions) below. Two workflows measure it:

| Workflow | What it does | Reproduce locally |
|---|---|---|
| CI, Coverage Gate | Fails when any package is below 85% (`cmd/passmcp`, a two-line `main`, is exempt) | `make coverage` |
| Coverage Badge (`coverage.yml`) | On every push to `main`, measures the whole module and publishes the result as a shields.io endpoint document at <https://sebastienrousseau.com/passmcp/coverage.json>, which the README's badge renders | `go test -coverprofile=coverage.out ./... && go run ./scripts/coveragebadge -profile coverage.out -exclude /cmd/passmcp/main.go` |

The badge's colour is brightgreen from 90%, green from 85%, yellow from 70%
and red below. The figure is truncated to one decimal rather than rounded, so
it never shows the gate as met when it is not.

## Test layout

Tests live beside the code they cover — there is no top-level `tests/`
directory, which is the Go convention and keeps a package's seams private
to it.

| Pattern | Purpose |
|---|---|
| `<pkg>/<pkg>_test.go` | The package's main suite |
| `testserver_test.go`, `internal/probe/fake_test.go` | Fake MCP and authorization servers under `httptest`, with knobs for the failure modes each phase must observe |
| `*_fuzz_test.go` | Fuzz targets: `FuzzParseWWWAuthenticate` (`auth`), `FuzzReadSSE` (`transport`), `FuzzValidate` and `FuzzArguments` (`diagnostics`), `FuzzSchemaValid` (`internal/probe`); run for a fixed duration per push by `scripts/fuzz.sh` |
| `cmd/*_test.go` | Flag validation, credential resolution and config precedence |

Three properties the suite deliberately enforces:

- **No live servers.** No test contacts a real MCP server or authorization
  server. Every phase is exercised against `httptest` fakes that speak the
  real protocol — a 401 with a `WWW-Authenticate` challenge, protected
  resource metadata at the well-known path, dynamic registration, a token
  endpoint, sessions that 404 when unknown.
- **Secrets are asserted absent.** `TestFullRunClientCredentials` serialises
  every recorded telemetry event and fails if an operator-supplied secret,
  a dynamically registered client secret or an issued token appears in it.
- **The destructive tool is a tripwire.** The fake server panics if its
  unannotated `delete_all` tool is ever invoked under the default policy.

### Acceptance criteria are tests

Every issue labelled `user-story` defines its acceptance criteria as IDs,
for example `- **SOC2-01**: **Given** …`. Those criteria are the
specification, and each is proved by at least one test that cites it on the
line above its declaration:

```go
// AC: SOC2-01, ISO-01
func TestFindingsCarryControlMappings(t *testing.T) { … }
```

`make trace` lists, per story, which criteria have a test and which do not,
and reports orphans: IDs a test cites but no story defines. `make
trace-check` is the CI gate. It fails when a **closed** story has a
criterion with no test, or when a citation is malformed. It runs every
cited test and writes the criterion-to-result table to `build/trace/`. An
open story's gaps are reported without failing the build, so a story can
land test by test. Close a story only once `make trace-check` is green
with it marked closed.

The stories come from `testdata/stories.json`, a committed snapshot, so the
gate never needs the GitHub API: a fork and an offline checkout trace
exactly as CI does. Refresh it with `make trace-refresh`, which uses `gh`
and is the only networked step, then commit the result. The logic lives in
`internal/trace`; `scripts/trace/main.go` is the command.

## Trying it against a real server

`scripts/demo-corral.sh` builds passmcp, starts
[corralctl](https://github.com/sebastienrousseau/corralctl)'s MCP server
in HTTP mode on a loopback port, runs a full `passmcp check` with real
arguments for its lookup tools, and stops the server on exit. It needs
`corralctl` on `PATH`. Any other Streamable HTTP server works the same way:

```sh
make build
./build/passmcp check http://127.0.0.1:7777/mcp --rps 0 --report-dir ./out
```

## Generated artefacts

Manpages and shell completions are **generated, never committed**:

```sh
make docs        # -> build/man/*.1, build/completions/*
```

They are rendered from the live cobra command tree, which is what keeps them
in step with `--help`. A committed `.1` drifts the first time a flag changes
and nothing catches it.

`build/` is git-ignored. It is deliberately **not** `dist/`: goreleaser owns
that directory and cleans it after running its before-hooks, which would
delete the generated pages before packaging.

The README demo, `.github/demo.gif`, is the one generated file that is
committed, because GitHub renders it from the tree. Regenerate it with
`make demo` whenever the output it shows changes: it builds `passmcp` and the
example server into `build/demo` and records `.github/demo.tape` with
[VHS](https://github.com/charmbracelet/vhs), which needs `vhs`, `ttyd` and
`ffmpeg` on `PATH`. Leave 90 seconds between renders: the example server a
render starts stops itself then, and holds its port until it does.

## Release model

Releases are tag-triggered and fully automated. Nothing is published by
hand.

1. Prepare the release on a `feat/vX.Y.Z` branch: `CHANGELOG.md` gains a
   `## [X.Y.Z]` heading, and pre-1.0 the patch digit moves. Merge to
   `main`.
   The branch also adds `docs/releases/vX.Y.Z.md`, the release's
   highlights: the only part of the release page written by hand.
2. Dry-run the pipeline: run the Release workflow via `workflow_dispatch`
   with `dry_run: true`. It builds and packages everything, prints the
   release page it would publish for those artefacts, and stops before
   publishing, signing and attesting.
3. Tag and push: `git tag -s vX.Y.Z && git push origin vX.Y.Z`.
4. The workflow builds the target matrix, signs with keyless cosign,
   attaches SLSA provenance and a CycloneDX SBOM, and publishes archives,
   deb and rpm packages, the Homebrew formula, the AUR package and the
   container image.
5. Its last step writes the release page in the family layout:
   title `passmcp X.Y.Z`, the highlights, GitHub's generated
   `## What's Changed` (and `## New Contributors` when there are any), the
   SHA-256 of every attached asset under `## Checksums`, and the
   `**Full Changelog**` link. It reads the page back and fails unless
   GitHub shows what it composed. Nothing on the page is edited by hand.

To see the page a tag has, or would have, without publishing anything
(`gh` needs a token with contents access for GitHub's generated notes):

```sh
go run ./scripts/releasepage -name passmcp -tag vX.Y.Z
```

The title goes to stderr and the notes to stdout. `-publish` writes the
page, which is the workflow's job, not a local one.

Every commit must be **cryptographically signed** and carry a DCO
`Signed-off-by` trailer. See [CONTRIBUTING.md](CONTRIBUTING.md).

## Conventions

**Coverage threshold: 85% of statements, enforced per package.**

A threshold chosen once and defended beats chasing a number, so here is the
defence. passmcp's code is network-facing: nine phases, each a sequence of
requests to a server that may answer with any status, any body, or nothing
at all, and each of those outcomes has a defensive branch that turns it
into a finding rather than a panic. Many of those branches — a 3xx on the
token endpoint, an SSE stream that ends mid-event, a certificate that
expires during the run — can only be reached by teaching the fake server
one more failure mode, and the cost of that scaffolding rises faster than
the value of the branch it reaches. 100% is not the goal. What the suite
must do instead is exercise every phase against a real fake server that
speaks the real protocol, so that the findings a user reads were produced
by the same code path a live server would take. The number is a floor that
keeps a new phase from landing untested; the fake servers are what make the
tests mean something.

**Documentation on every exported declaration.** The library packages
(`passmcp`, `auth`, `transport`, `diagnostics`, `trace`) are the public face
of the module on pkg.go.dev, and an undocumented export renders as an empty
paragraph. `make lint` runs `revive`'s exported-comment check.

**Licence headers on every file.** Enforced by `make spdx-check`. Run
`go run scripts/spdx_sweep.go` to add missing ones.

**Diagnostics go to stderr; stdout carries the selected output format.**
This is what keeps `--output json` and `--output ndjson` pipeable. A
`fmt.Println` on a diagnostic path is a bug; use `internal/diag`.

**A finding passes only on evidence.** Each check records the range of
recorder sequence numbers it made (`req#12-14`), and `pass` is reserved for
a property a request actually showed. See
[docs/adr/0002-findings-cite-requests.md](docs/adr/0002-findings-cite-requests.md).
