<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Changelog

All notable changes to passmcp are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions are
[Semantic Versioning](https://semver.org/) shaped.

**Versions increment by 0.0.1 a release, whatever the release contains.**
The sequence runs `v0.0.1`, `v0.0.2`, … and reaches `v0.1.0` only after
`v0.0.999`. A new transport, a new output format or a new phase is still a
patch bump. The slow climb is deliberate: it lets maturity be earned over
many releases rather than declared, and a version number is not where this
project announces that a change felt big.

## [0.0.4] — 2026-09-30

### Added

- **Seven new checks, 138 in all.**
  - `protocol.notification_ack`: the reply to `notifications/initialized`
    is 202 with an empty body, judged from the handshake's own exchange.
  - `protocol.content_type`: a POST reply is `application/json` or
    `text/event-stream`.
  - `protocol.missing_session`: a request without the issued
    `Mcp-Session-Id` is refused.
  - `catalog.tools.schema_valid`: each tool's input and output schema is
    structurally valid JSON Schema, with local `$ref`s resolved and
    self-reference bounded. Hand-rolled, no new dependency, and fuzzed.
  - `catalog.tools.order`: `tools/list` answers in a stable order, which
    prompt caching depends on.
  - `execution.resources.uri`: a resource read returns the URI asked for.
  - `execution.prompts.validation`: `prompts/get` without a required
    argument is refused with -32602.
- **Servers on MCP revision 2024-11-05 are graded, not refused.**
  `handshake.protocol_version` warns and names what the revision lacks;
  checks for features it predates are skipped with the revision named. A
  server on the old HTTP+SSE transport is named as such instead of
  failing with an opaque HTTP 405.
- **`passmcp read` and `passmcp prompt`**, read-only counterparts to
  `call` for `resources/read` and `prompts/get`.
- **Availability and latency in `passmcp watch`**: each pulse records its
  latency, a status and an error kind, and the run ends with a success
  rate, p50/p95/p99 and the worst failure streak.
- **`passmcp explain --curl <check-id>`** prints a curl command that
  reproduces the requests a finding cites, with every credential replaced
  by a placeholder such as `${PASSMCP_TOKEN}`.
- **A README demo**, rendered from `.github/demo.tape` by `make demo`.

### Changed

- **passmcp requires passmcp-reporting v0.0.4**, the family's release;
  its API, schemas and predicate are unchanged.
- **A reply that is not JSON names its content type** ("got text/html;
  likely a login, SSO or firewall page, or the wrong path") instead of a
  JSON decode error.
- **`watch --output json` prints one JSON document** (events and a
  summary); it used to print the text form.
- **Release pages are composed by the release workflow** in the family
  layout (Highlights, What's Changed, Checksums, Full Changelog).
- A server that negotiates 2025-03-26 no longer has `outputSchema` checked,
  since that field arrived in 2025-06-18.

### Fixed

- **`watch --once` exits 1** when the server cannot be reached, as the
  documentation says; it exited 0.
- `protocol.missing_session` evidences no SOC 2 or ISO/IEC 27001 control
  and is mapped to none.
- The web shell no longer claims five checks need a stdio server; it names
  what those checks watch.

## [0.0.3] — 2026-09-30

### Changed

- **passmcp requires passmcp-reporting v0.0.3**, the family's release;
  its API, schemas and predicate are unchanged.

### Fixed

- **Stateless tool calls mirror `x-mcp-header` arguments.** Under
  2026-07-28, an argument whose schema carries `x-mcp-header` must also be
  sent as an `Mcp-Param-{Name}` header. passmcp sent none, so a strict
  server answered `tools/call` with -32020 and the execution phase
  reported the server as failing for passmcp's own omission. Strings,
  booleans and integers under a plain `properties` chain are now mirrored,
  encoded like `Mcp-Name`; invalid header names and other types are left
  out.
- **Paging a list stops on a cursor cycle.** `tools/list`,
  `resources/list`, `resources/templates/list` and `prompts/list` stopped
  only when a server repeated the cursor it was just given, so cursors
  that looped over two or more pages kept passmcp paging until the call
  timed out. A revisited cursor, or a list longer than 1,000 pages, now
  fails with `ErrPaginationCycle`, naming the method.
- **`passmcp login` checks the RFC 9207 issuer on the redirect.** It read
  only `code` and `state`, so a redirect naming another authorization
  server, the mix-up attack, was accepted and its token stored, and a
  server that advertises `authorization_response_iss_parameter_supported`
  could never complete a login. It now passes `iss` to the check the
  library already makes.
- **The family manifest lists passmcp-lsp and passmcp-census as
  released.** Both shipped 0.0.2 with the rest of the family, but the
  manifest tagged with passmcp 0.0.2 still called them unreleased, so
  every page generated from it, satellion.com's family table included,
  said so too.

## [0.0.2] — 2026-09-29

The family's second release, and the first in which every repository in
the family moves together: passmcp-lsp and passmcp-census, never tagged
at 0.0.1, first ship at 0.0.2.

### Added

- **Servers that fail on purpose.** `go run ./examples/servers -flaw NAME`
  serves a local MCP server with one deliberate defect, and `-list` names
  each defect and the check that catches it. A test runs passmcp's engine
  against every one on each CI run, so the table cannot drift from what
  passmcp reports.

### Changed

- **The family manifest lists every repository, in one version.**
  `passmcp-graph` and `passmcp-registry` join it as released repositories,
  `passmcp-lsp` and `passmcp-census` as not yet released, and every row is
  in lockstep. Statuses name facts (`released`, `unreleased`, `rejected`)
  rather than intentions, and `ecosystem.json` moves to schema version 2 with
  a `repository` field, because the website's repository is
  `satellion.github.io`.
- **passmcp requires passmcp-reporting v0.0.2**, the family's release of
  the attestation format; its API and predicate are unchanged from v0.0.1.
- **Two more proposals are recorded as considered and rejected**:
  `passmcp-proxy` (an in-path inspector or sanitising shield, ADR 0007) and
  `passmcp-fuzz` (a stress and fuzzing tool, ADR 0008), each with its reason
  in the family table so neither is re-argued from scratch.
- **The README carries the family's standard badge row and component
  table**, and `scripts/readme-check.sh` enforces the badge row.
- **Coverage is published.** A Pages workflow writes the coverage badge's
  endpoint document from the figure CI measures.
- **`scripts/verify-release-versions.sh` runs on every push**, reading the
  version from `CHANGELOG.md` when no tag is given.

### Fixed

- **`protocol.id_echo` names the id the server sent back.** A server that
  answered with the wrong id was reported as `got 0x…`, a memory address,
  rather than the id it returned; a reply with no id now says so.

## [0.0.1] — 2026-09-29

The first release.

### Added

- **A diagnostic for any MCP server.** `passmcp check` connects the way an
  agent would and runs 131 checks in nine phases, from the network and
  discovery through authentication, the handshake, the protocol, the
  catalogue, execution, performance and resilience. Every finding cites the
  request that showed it, and a check that cannot show its property skips
  and says why.
- **Read-only by default.** Only tools annotated `readOnlyHint: true` are
  invoked; anything else needs `--allow-mutations`.
- **Reports and attestations.** Text, Markdown, HTML, JSON, NDJSON, SARIF,
  JUnit and OCSF reports, and an in-toto attestation that a gateway, a
  registry or an auditor can verify offline with passmcp-reporting.
- **Compliance evidence for SOC 2, ISO/IEC 27001 and GDPR.** Every check is
  mapped to the Trust Services Criteria, the 2022 Annex A controls and GDPR
  articles it evidences, or marked `none` with a reason, in Apache-2.0 data
  under `spec/controls/`. `passmcp verify --framework` judges each control
  from an attestation offline, and `passmcp evidence` writes dated CSV and
  JSON bundles. Mappings, not certifications: an auditor certifies.
- **Checks for the attack classes research shows are exploited:**
  cross-server shadowing (`--client-config`), toxic capability
  combinations, instructions injected through tool output, tokens minted
  for another audience (`--wrong-audience-token-env`; passmcp never forges
  one), stdio servers listening on every interface, and unsafe launch
  configuration.
- **`passmcp fleet run`** checks every server in a fleet file, writes an
  attestation per server and reports what changed since the last run by
  kind and severity. A `readOnlyHint` that flips, or a description that
  gains instructions, is critical whatever the score, and an unreachable
  server is reported as such, never as passing. A Kubernetes CronJob
  example ships in `examples/kubernetes/`, and `make e2e-kind` runs it in a
  real cluster and judges it from outside the process.
- **`passmcp discover`** probes only the targets and sources the operator
  names, and records each endpoint that completes an MCP handshake in a
  passmcp-graph store with `--graph`.
- **`passmcp a2a check`** validates an A2A Agent Card, verifies its JWS
  signature over the JCS form, and checks its authentication and
  transport.
- **OCSF export:** `--output ocsf` writes failing and warning findings, and
  fleet changes, as OCSF 1.3.0 events; `--ocsf-endpoint` posts them to the
  operator's collector.
- **`--user-agent`** sets the User-Agent on every HTTP request of a run, and
  **`--retain <duration>`** deletes old reports from `--report-dir`.
- **An acceptance-criteria gate:** every user story's criteria are traced to
  the tests that cite them (`// AC: <ID>`), and a closed story with an
  untested criterion fails the build.

### Security

- **Secrets and personal data are masked** in every report, NDJSON
  telemetry and HAR file, including a token a server echoes back in a tool
  description.
- **Discovered endpoints stay outside the operator's network.** A URL
  learned from a server is checked when it is found and again when it is
  connected to, against the same resolved addresses, so DNS rebinding cannot
  point passmcp inside the network it runs in.
- **EU Cyber Resilience Act evidence:** `SECURITY.md` states the report
  channel and the Article 14 timeline, releases carry a CycloneDX SBOM per
  artefact and SLSA provenance, dependency CVEs that do not affect passmcp
  get an OpenVEX statement, and `docs/compliance/cra.md` links every claim
  to its evidence.
- **No telemetry.** passmcp sends nothing anywhere the operator did not
  name (ADR 0006).
