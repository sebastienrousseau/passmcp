<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Maintainers

passmcp is currently maintained by a single person. This document
records the current maintainer, the external services and accounts
that are load-bearing for the project, and the procedure for
succession or fork.

## Current maintainer

| Role       | Name               | Contact                           | Time zone |
|------------|--------------------|-----------------------------------|-----------|
| Maintainer | Sebastien Rousseau | <sebastian.rousseau@gmail.com>    | Europe/London |
|            |                    | GitHub: [@sebastienrousseau](https://github.com/sebastienrousseau) |               |

Best-effort response windows:

- **Security advisories** (via GitHub private vulnerability reporting):
  acknowledgement within **72 hours**; fix within **90 days**.
- **Pull requests**: first review within **7 days**.
- **Issues**: triaged within **7 days**.

## External services and accounts

These are the services and accounts that passmcp depends on. A succession
event requires the new maintainer to either take over each account
(where possible) or reconstitute the same integration under their own
account and update the linked configuration file.

| # | Service                            | Account / Location                                       | Purpose                                     | Configuration reference                     |
|---|------------------------------------|----------------------------------------------------------|---------------------------------------------|---------------------------------------------|
| 1 | GitHub organisation and repository | `satellion.com/passmcp`                        | Source of truth for code, issues, releases  | this repository                             |
| 2 | GitHub Actions                     | Same repo                                                | CI, release pipeline, SLSA provenance       | `.github/workflows/`                        |
| 3 | GitHub Container Registry (ghcr)   | `ghcr.io/sebastienrousseau/passmcp`                           | Multi-arch OCI images                       | `.goreleaser.yaml`                          |
| 4 | Homebrew tap                       | `github.com/sebastienrousseau/homebrew-tap`                 | macOS Homebrew installs                     | `.goreleaser.yaml` (`brews:` block)         |
| 5 | Arch User Repository (AUR)         | `aur.archlinux.org/packages/passmcp` (maintainer `srousseau`); also `passmcp-server-bin`, `passmcp-agentgateway-extmcp` | Arch Linux installs | the AUR repositories; `scripts/aur-bump.sh` |
| 6 | Signing key (SSH)                  | The maintainer's key, as published on their GitHub profile (`https://github.com/sebastienrousseau.keys`) | Signs release tags and commits | `.github/workflows/release.yml` |
| 7 | Sigstore keyless signing           | Fulcio + Rekor (via GitHub OIDC)                         | Cosigns every release artefact              | `.goreleaser.yaml` (`sboms`/`signs` blocks) |
| 8 | Dependabot / Scorecard             | GitHub-native, tied to the repo                          | Vulnerability alerts, OSSF score            | `.github/dependabot.yml`                    |

## Succession procedure

The single-maintainer model creates real bus-factor risk. This is the
concrete plan for handing over — either voluntarily to a co-maintainer
or, after prolonged unavailability, to a community fork.

### Voluntary hand-off (planned)

1. **Announce**: open a public issue on the repository at least
   **two weeks** before the change. Link this document.
2. **Add the new maintainer as an owner of the `sebastienrousseau`
   organisation** so the repository, its Actions secrets and its
   package namespace move together.
3. **Update `MAINTAINERS.md`** with the new maintainer's contact,
   response-window commitments, and time zone.
4. **Rotate signing key** in a coordinated release:
   - The outgoing maintainer publishes a final release note revoking
     the old key.
   - The incoming maintainer publishes their key on their GitHub
     profile, updates row 6 above, and cuts the next release using it.
5. **Transfer external accounts** in this order (each independent):
   - Homebrew tap: transfer repository ownership or fork + retire old.
   - AUR: add the new maintainer as co-maintainer for one release
     cycle, then transfer primary.
   - ghcr.io: stays with the organisation; only the `.goreleaser.yaml`
     image path changes if the organisation is renamed.
6. **Publish a "governance change" release note** listing every
   updated identifier so downstream users can reason about the
   transition.

### Community fork (unplanned)

passmcp is licensed GPL-3.0. If the maintainer becomes unresponsive
for **≥ 6 months** (no issue comments, no releases, no PR merges), the
community is explicitly encouraged to fork the project. `GOVERNANCE.md`
codifies this window. A community fork:

- May keep the name **only after** the old repository is archived by
  its owner. Otherwise it should adopt a distinguishing name.
- Must **not** reuse the outgoing maintainer's signing key — the new
  fork publishes its own key in its `MAINTAINERS.md`.
- Should re-verify each external-service entry in this table under
  its own accounts; the outgoing accounts (Homebrew tap, AUR,
  ghcr.io) are not transferable without cooperation.

### Emergency (compromise or coercion)

If the maintainer's account or signing key is compromised:

1. **Immediately** publish a security advisory on the repository (or on
   any working communication channel if the repo is inaccessible)
   naming the last known-good release tag.
2. Rotate the SSH signing key and update row 6 above.
3. Revoke the compromised GitHub PAT / OIDC subject; Sigstore-signed
   artefacts remain verifiable against Rekor as long as the entries
   themselves are legitimate.
4. If in doubt, users should treat all releases signed after the
   compromise as untrusted until re-verified against Rekor entries and
   the SLSA provenance.

## Contact

For anything not covered here, or to propose becoming a co-maintainer,
open an issue on the repository. For security-sensitive matters,
follow [SECURITY.md](SECURITY.md) instead.
