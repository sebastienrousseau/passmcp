---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp's own Statement of Applicability against ISO/IEC 27001:2022 Annex A, as a software supplier: which controls apply to the project, how it meets them, and the file or workflow that is the evidence.
---

# Statement of Applicability: passmcp as a supplier

This page is for an organisation that has passmcp inside its ISMS scope and
needs to enter it in its supplier register (A.5.19–A.5.22). It states, for
each ISO/IEC 27001:2022 Annex A control relevant to a software supplier,
whether it applies to the passmcp project, how the project meets it, and the
file or workflow in this repository that is the evidence.

It is a self-assessment. The passmcp project holds no ISO/IEC 27001
certificate, and a document cannot confer one. What it can do is point at
evidence a reviewer can open. `make soa-check`, which the release preflight
runs, fails when a file cited below does not exist, so the statement cannot
outlive its evidence.

Context that decides applicability: passmcp is an open-source command-line
tool. It is developed in public by a single named maintainer, operates no
hosted service (ADR 0012) and collects no telemetry (ADR 0006). Controls
about premises, employees and production operations are therefore mostly
not applicable, and the table says why each one is not.

## Organisational controls

| Control | Applies | How passmcp meets it | Evidence |
|---|---|---|---|
| A.5.1 Policies for information security | Yes | The security policy, the governance model and the agent invariants are published in the repository. | `SECURITY.md`, `GOVERNANCE.md`, `AGENTS.md` |
| A.5.7 Threat intelligence | Yes | The threat model is documented, and dependency advisories are read weekly and on every change from two databases. | `docs/security-model.md`, `.github/workflows/security.yml` |
| A.5.8 Information security in project management | Yes | Security gates are part of the definition of done for every change, and design decisions are recorded as ADRs. | `AGENTS.md`, `CONTRIBUTING.md`, `docs/adr/README.md` |
| A.5.14 Information transfer | Yes | passmcp transfers nothing to its maintainers: no telemetry, ever, as a product guarantee. | `docs/adr/0006-no-client-telemetry.md` |
| A.5.21 Managing information security in the ICT supply chain | Yes | Dependencies are few, listed and checked in CI; updates arrive through Dependabot; every release ships an SBOM. | `SBOM.md`, `supply-chain/README.md`, `.github/dependabot.yml`, `.goreleaser.yaml` |
| A.5.23 Information security for use of cloud services | Partly | The project uses GitHub for source, CI and release distribution only; no customer data is processed in any cloud service. | `.github/workflows/release.yml` |
| A.5.24 Information security incident management planning and preparation | Yes | Vulnerabilities are reported privately, acknowledged within 72 hours and fixed within 90 days. | `SECURITY.md` |
| A.5.26 Response to information security incidents | Yes | The disclosure process and timelines are published. | `SECURITY.md` |
| A.5.32 Intellectual property rights | Yes | Every file carries an SPDX licence header, checked in CI, with licence texts in the repository. | `REUSE.toml`, `LICENSE`, `LICENSES` |
| A.5.33 Protection of records | Yes | Releases are signed and their history is append-only; every change is recorded in the changelog. | `CHANGELOG.md`, `.github/workflows/release.yml` |
| A.5.34 Privacy and protection of PII | Yes | Credentials and personal data are redacted structurally before anything is written, and nothing is uploaded. | `docs/adr/0003-structural-redaction-at-the-recorder.md`, `internal/telemetry/redact.go`, `docs/adr/0006-no-client-telemetry.md` |
| A.5.37 Documented operating procedures | Yes | Development, CI and signing procedures are documented. | `DEVELOPMENT.md`, `docs/ci.md`, `docs/signing.md` |
| A.5.2–A.5.6, A.5.9–A.5.13, A.5.15–A.5.20, A.5.22, A.5.25, A.5.27–A.5.31, A.5.35, A.5.36 | No | These govern an organisation's own assets, people, suppliers and legal obligations. The project has no premises, no staff and no customer data, so it has none of them to govern; an organisation using passmcp covers them in its own ISMS. | — |

## People controls

| Control | Applies | How passmcp meets it | Evidence |
|---|---|---|---|
| A.6.1–A.6.8 | No | The project has no employees. The maintainer is named, and contributors are bound by the code of conduct and the DCO sign-off on every commit. | `MAINTAINERS.md`, `CODE_OF_CONDUCT.md`, `.github/workflows/dco.yml` |

## Physical controls

| Control | Applies | How passmcp meets it | Evidence |
|---|---|---|---|
| A.7.1–A.7.14 | No | The project operates no premises, equipment or media; source, CI and releases are hosted on GitHub. | — |

## Technological controls

| Control | Applies | How passmcp meets it | Evidence |
|---|---|---|---|
| A.8.4 Access to source code | Yes | Write access is held by the one named maintainer, and every change reaches the default branch through a pull request whose base branch CI checks. | `MAINTAINERS.md`, `.github/workflows/pr-base.yml` |
| A.8.8 Management of technical vulnerabilities | Yes | OSV, govulncheck, CodeQL and the OpenSSF Scorecard run in CI and weekly. | `.github/workflows/security.yml`, `.github/workflows/codeql.yml`, `.github/workflows/scorecard.yml` |
| A.8.9 Configuration management | Yes | Dependencies are pinned with checksums, linter and release configurations are versioned, and CI actions are pinned by commit. | `go.sum`, `.golangci.yml`, `.goreleaser.yaml` |
| A.8.12 Data leakage prevention | Yes | Secret scanning runs on every push, and the recorder masks secrets and personal data before they reach a report. | `.github/workflows/secret-scan.yml`, `internal/telemetry/redact.go` |
| A.8.19 Installation of software on operational systems | Yes | Users can verify signatures, checksums and provenance before installing. | `pkg/VERIFY.md` |
| A.8.24 Use of cryptography | Yes | Release artefacts and images are signed keylessly with Sigstore, and signing is documented. | `docs/signing.md`, `.goreleaser.yaml` |
| A.8.25 Secure development life cycle | Yes | Coverage, race, lint, fuzz and API gates run on every change. | `AGENTS.md`, `.github/workflows/ci.yml` |
| A.8.26 Application security requirements | Yes | The security model and the read-only-by-default rule are documented and enforced. | `docs/security-model.md`, `docs/adr/0004-read-only-by-default.md` |
| A.8.27 Secure system architecture and engineering principles | Yes | The architecture and its security decisions are documented. | `docs/architecture.md`, `docs/adr/0001-bare-transport-for-unauthenticated-probes.md` |
| A.8.28 Secure coding | Yes | gosec runs in lint and CodeQL analyses the code. | `.golangci.yml`, `.github/workflows/codeql.yml` |
| A.8.29 Security testing in development and acceptance | Yes | Fuzzing (30s per target on every push, longer weekly), the race detector and servers that misbehave on purpose run in CI. | `.github/workflows/ci.yml`, `.github/workflows/fuzz.yml`, `internal/hostile/hostile.go` |
| A.8.30 Outsourced development | Partly | Development is not outsourced; outside contributions arrive as pull requests reviewed under the contributing guide and signed off. | `CONTRIBUTING.md`, `.github/workflows/dco.yml` |
| A.8.32 Change management | Yes | Every change is a pull request that must pass CI, recorded in the changelog; decisions are recorded as ADRs. | `CHANGELOG.md`, `docs/adr/README.md` |
| A.8.33 Test information | Yes | Tests run against fake and hostile fixture servers, never a live server or real data. | `internal/probe/fake_test.go`, `internal/hostile/hostile.go` |
| A.8.1–A.8.3, A.8.5–A.8.7, A.8.10, A.8.11, A.8.13–A.8.18, A.8.20–A.8.23, A.8.31, A.8.34 | No | These concern an organisation's own endpoints, networks, backups, logging and production systems. passmcp operates none: it is a program the organisation runs. | — |
