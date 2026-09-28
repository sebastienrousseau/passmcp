---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How passmcp meets the EU Cyber Resilience Act obligations that can apply to it, with the file or workflow that evidences each claim.
---

# The EU Cyber Resilience Act

The Cyber Resilience Act ([Regulation (EU) 2024/2847](https://eur-lex.europa.eu/eli/reg/2024/2847/oj))
sets security obligations for products with digital elements placed on
the EU market. Its reporting obligations for actively exploited
vulnerabilities (Article 14) apply from 11 September 2026, and most of the
rest from 11 December 2027.

This page says what passmcp does, and each statement links to the file or
workflow that is its evidence. The release preflight checks that every
statement has a link and that every file it names exists.

## Role

- **passmcp is open source and has no commercial offering.** It is published
  under GPL-3.0 by one maintainer, with no paid tier, hosted service or
  support contract ([ADR 0012](../adr/0012-everything-stays-open.md),
  [LICENSE](https://github.com/sebastienrousseau/passmcp/blob/main/LICENSE)).
- **Its role under the Act depends on commercial activity it does not have
  today.** Free and open-source software supplied outside a commercial
  activity is outside the manufacturer obligations (recital 18). Whoever
  offers passmcp commercially, including this project if that changes, is a
  manufacturer for that offering. An organisation that supports it
  commercially without selling it may be an open-source software steward
  (Article 24), whose duties are lighter. A superseding decision record
  would state the role ([the decision records](../adr/README.md)).
- **The project meets the reporting obligations anyway.** It follows the
  Article 14 timeline for actively exploited vulnerabilities, so adopting
  passmcp does not leave a gap in an adopter's own compliance
  ([SECURITY.md](https://github.com/sebastienrousseau/passmcp/blob/main/SECURITY.md)).

## Reporting and handling vulnerabilities

- **One private report channel, acknowledged within 72 hours**: GitHub
  private vulnerability reporting
  ([SECURITY.md](https://github.com/sebastienrousseau/passmcp/blob/main/SECURITY.md)).
- **An actively exploited vulnerability is reported on the Article 14
  timeline**: an early warning within 24 hours, a notification within 72
  hours, and a final report within 14 days of a fix
  ([SECURITY.md](https://github.com/sebastienrousseau/passmcp/blob/main/SECURITY.md)).
  The release preflight fails if the policy stops saying so
  ([scripts/cra/main.go](https://github.com/sebastienrousseau/passmcp/blob/main/scripts/cra/main.go)).
- **A fixed vulnerability's release notes name its advisory ID and the
  affected versions**, and the preflight fails a highlights file that
  announces a security fix without both
  ([docs/releases/README.md](../releases/README.md),
  [internal/cra/advisory.go](https://github.com/sebastienrousseau/passmcp/blob/main/internal/cra/advisory.go)).
- **The security contact is machine-readable**:
  [satellion.com/.well-known/security.txt](https://satellion.com/.well-known/security.txt)
  names the contact and the policy, and the site's build fails when its
  `Expires` date is less than 30 days away.

## Support period and security updates

- **The latest release is supported.** Releases move by one patch number
  (0.0.x), and a security fix ships as the next release. Nothing is
  backported to an older one
  ([SECURITY.md](https://github.com/sebastienrousseau/passmcp/blob/main/SECURITY.md)).
- **Updates are delivered through the same channels as every release**:
  GitHub Releases, the container image on ghcr.io, `go install` from the
  module proxy, the Homebrew cask, deb and rpm packages, and the AUR
  ([.goreleaser.yaml](https://github.com/sebastienrousseau/passmcp/blob/main/.goreleaser.yaml),
  [the release workflow](https://github.com/sebastienrousseau/passmcp/blob/main/.github/workflows/release.yml),
  [packaging](../packaging.md)).
- **Dependencies are watched for advisories** weekly and on every change,
  by govulncheck and OSV-Scanner
  ([the security workflow](https://github.com/sebastienrousseau/passmcp/blob/main/.github/workflows/security.yml)),
  with Dependabot proposing updates
  ([.github/dependabot.yml](https://github.com/sebastienrousseau/passmcp/blob/main/.github/dependabot.yml)).

## What every release carries

- **A CycloneDX SBOM for every artefact**: each archive and each `.deb` and
  `.rpm` package
  ([.goreleaser.yaml](https://github.com/sebastienrousseau/passmcp/blob/main/.goreleaser.yaml)).
- **SLSA build provenance**, attached to the release as
  `checksums.txt.intoto.jsonl`
  ([the release workflow](https://github.com/sebastienrousseau/passmcp/blob/main/.github/workflows/release.yml)).
- **An audit of the published assets**: the release workflow's last step
  fails when an artefact has no SBOM or the release has no provenance
  ([internal/cra/assets.go](https://github.com/sebastienrousseau/passmcp/blob/main/internal/cra/assets.go)).
- **An OpenVEX statement** when govulncheck reports a vulnerability in a
  dependency that does not affect passmcp. It says `not_affected`, and why:
  the vulnerable package is not imported, or none of its vulnerable
  symbols is reachable
  ([internal/cra/vex.go](https://github.com/sebastienrousseau/passmcp/blob/main/internal/cra/vex.go)).
- **A keyless Sigstore signature over the checksums**
  ([.goreleaser.yaml](https://github.com/sebastienrousseau/passmcp/blob/main/.goreleaser.yaml),
  [signing](../signing.md)).

## Security by design

- **No telemetry, ever** ([ADR 0006](../adr/0006-no-client-telemetry.md)).
- **Read-only by default**: only tools declaring `readOnlyHint` are called
  ([ADR 0004](../adr/0004-read-only-by-default.md)).
- **Secrets are redacted structurally at the recorder**
  ([ADR 0003](../adr/0003-structural-redaction-at-the-recorder.md)).
- **The threat model and what is out of scope** are written down
  ([the security model](../security-model.md)).
