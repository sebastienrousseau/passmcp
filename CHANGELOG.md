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
