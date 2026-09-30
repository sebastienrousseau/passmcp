<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Working on passmcp as an AI agent

Invariants for AI-assisted contributions. These are the things that are
expensive to discover from the diff alone, and the ones where a plausible
change is wrong for a reason the code does not state.

Read [DEVELOPMENT.md](DEVELOPMENT.md) first for the toolchain and the local
equivalent of every CI gate. This file is only the constraints.

## Hard gates

Nothing merges without these. All of them are reproducible locally.

| Gate | Command |
|---|---|
| 85% statement coverage, every package | `go test ./... -cover` |
| Race detector, randomised order | `make test-race` |
| Lint at zero findings | `make lint` |
| SPDX header on every source file | `make spdx-check` |
| `SBOM.md` agrees with `go.mod` | `make sbom-check` |
| Examples still compile | `make example-check` |
| Fuzz targets still build and run | `make fuzz` |
| Install tree is correct | `make install-smoke` |

Coverage is not negotiable downward. If a new branch is hard to reach,
extend the fake server in `internal/probe/fake_test.go` with a knob that
produces it — that is the established pattern, not an exception made for
the new code. Never reach a branch by pointing a test at a live server.

## Commits

- **Every commit must be cryptographically signed and carry a DCO
  `Signed-off-by` trailer.** An agent's shell usually cannot reach the
  maintainer's ssh-agent; hand the commits over as a script rather than
  producing unsigned history that has to be rewritten.
- Conventional Commits for the subject line.
- Never rewrite published history. `main` and any pushed branch are
  append-only.

## Versioning

- SemVer. Pre-1.0, the patch digit moves for everything.
- Version work happens on a `feat/vX.Y.Z` branch, one release per branch.
- The version lives in the newest `## [x.y.z]` heading in `CHANGELOG.md`
  and nowhere else in the tree. `cmd.Version` is injected at build time
  through `-ldflags`; never hard-code a version there.
- A CHANGELOG section that exists is not a release. Check `git tag` and
  the GitHub releases before assuming a version is spent.

## Things that look like bugs and are not

- **There are two transports to the same endpoint.** `Session.Client`
  carries the operator's credentials; `Session.Bare` carries nothing but
  the trace header. The first-contact and invalid-token probes use
  `Bare` on purpose: the bearer round-tripper would otherwise add the
  real token and a server that accepts anything would look open. Do not
  "simplify" them onto one client
  ([ADR-0001](docs/adr/0001-bare-transport-for-unauthenticated-probes.md)).
- **A static `--client-id` beats dynamic registration.** `auth.Registrar`
  tries a Client ID Metadata Document, then operator-supplied
  credentials, then RFC 7591 registration. An operator who was handed a
  client id chose it; registering a fresh one behind their back is the
  bug.
- **Content types are not trusted by the redactor.** A token endpoint
  that answers `text/plain` still carries an `access_token`; the recorder
  sniffs for `{` and masks structurally. A change that keys redaction on
  `Content-Type` alone reintroduces a leak the tests catch.
- **`isError` results from generated arguments are not failures.** A
  tool that rejects `"probe"` as a repository name is behaving
  correctly; the execution phase reports them as info, and `--arg`
  supplies real values. Do not count them against the score.
- **Manpages and completions are absent from the tree by design.** They
  are generated into `build/`. Do not commit them.
- **`build/` is not `dist/`.** goreleaser owns `dist/` and cleans it
  after its before-hooks run, which would delete generated pages before
  packaging.

## Things that are load-bearing

- **Stdout carries the selected output format; diagnostics go to
  stderr.** This is what keeps `--output json` and `--output ndjson`
  pipeable. A `fmt.Println` on a diagnostic path is a bug; use
  `internal/diag`.
- **A finding passes only on evidence.** `pass` needs a request that
  showed the property; `info` records an observation without judgement;
  `skip` names a reason. A check that returns `pass` without making a
  request — or when the request failed — is the most damaging change
  available in this codebase, because the score is derived from findings
  ([ADR-0002](docs/adr/0002-findings-cite-requests.md)).
- **Blocked means skipped, not passed.** When a phase sets
  `Session.blocked`, every later phase is recorded as skipped with that
  reason and its category is reported as not assessed. Never let a
  later phase run against a client that never connected.
- **Read-only by default.** `diagnostics.Policy` invokes only tools
  with `readOnlyHint: true`; a tool without annotations is destructive
  under the MCP specification's default. Weakening this to make a
  server score higher is not an option
  ([ADR-0004](docs/adr/0004-read-only-by-default.md)).
- **Everything the server returns is untrusted.** Tool names,
  descriptions, schemas, content and error strings are chosen by whoever
  runs the server. New report fields that carry server text must be
  bounded (`truncate`) and, where a credential could travel in them,
  pass through the recorder's `Redactor`
  ([ADR-0003](docs/adr/0003-structural-redaction-at-the-recorder.md)).
- **Every secret is registered before the first request.** `probe.Run`
  hands `creds.Credentials.Secrets()` to the redactor before building
  the client. A new credential kind must add its secret there.

## Scope

- Do not couple a structure or documentation cleanup to a behaviour
  change. They review differently and the cleanup is what gets dropped.
- Do not add a dependency without saying why in the commit. The module
  has ten direct dependencies and a hand-maintained `SBOM.md` that CI
  checks against `go.mod`; a new one is not free.
- Do not add a CI gate that does not currently pass. A red gate on
  arrival teaches everyone to ignore it.
