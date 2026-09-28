---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How a release's notes are written: the highlights file, and what a release that fixes a vulnerability must say.
---

# Release notes

Every release's page is composed from `docs/releases/v<VERSION>.md`, the
only part written by hand. It holds a `## Highlights ⭐️` section of two to
four bullets, each `* **<Feature>**: <one or two plain sentences>`. The
release script adds GitHub's generated change list, the SHA-256 of every
asset and the Full Changelog link.

## A release that fixes a vulnerability

The EU Cyber Resilience Act expects a security update to say what it
fixes and for which versions, and so do the people deciding whether to
upgrade. A highlight that announces a fixed vulnerability:

- **starts its label with "Security fix"**, so it cannot be mistaken for
  an ordinary change;
- **names its advisory ID**: the GitHub security advisory (`GHSA-…`), and
  the CVE or Go vulnerability ID (`CVE-…`, `GO-…`) where one exists;
- **states the affected versions**, as `Affected versions: v0.0.3 to
  v0.0.8`.

For example:

```markdown
* **Security fix: a redirect no longer carries the API key**: GHSA-xxxx-xxxx-xxxx. Affected versions: v0.0.3 to v0.0.8. Upgrade to this release; there is no workaround.
```

The release preflight (`go run ./scripts/cra/main.go preflight`) fails a
highlights file where a "Security fix" names no advisory ID, or where any
advisory ID comes without its affected versions.

## Vulnerabilities in dependencies that do not affect passmcp

`govulncheck` reports vulnerabilities in passmcp's dependencies and whether
passmcp's code reaches them. When a release carries a dependency with a
known vulnerability that passmcp does not reach, the release attaches an
OpenVEX document, `passmcp.openvex.json`, that says `not_affected` for each
one, with the reason:

- `vulnerable_code_not_present`: passmcp requires the module but does not
  import the vulnerable package;
- `vulnerable_code_not_in_execute_path`: the package is imported, but no
  vulnerable symbol is reachable from passmcp's code.

A vulnerability passmcp does reach is `affected`, and is fixed before the
release rather than documented. The release workflow generates and
validates the document:

```sh
govulncheck -format json ./... > vuln.json
go run ./scripts/cra/main.go vex --in vuln.json \
  --product pkg:golang/satellion.com/passmcp@v0.0.1 \
  --out passmcp.openvex.json
```
