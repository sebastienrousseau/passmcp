<!--
SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
SPDX-License-Identifier: GPL-3.0-only
-->

# Packaging

One directory per distribution format, for packagers looking for the
recipe rather than reading the release pipeline to find it.

**Each recipe has exactly one source of truth, and it is not this
directory.** A copy of a `PKGBUILD` here would be a second place to
change and a first place to forget, and the version in it would be wrong
the day after it was written. Every page below points at the file that
actually produces the artefact, and describes what comes out.

| Format | Recipe | Produced by |
| --- | --- | --- |
| [deb](deb/README.md) | `.goreleaser.yaml` → `nfpms` | release workflow |
| [rpm](rpm/README.md) | `.goreleaser.yaml` → `nfpms` | release workflow |
| [aur](aur/README.md) | the AUR repositories themselves | `scripts/aur-bump.sh`, after each release |
| [brew](brew/README.md) | `.goreleaser.yaml` → `brews` | release workflow |
| [nix](nix/README.md) | `flake.nix` | in-repo, built on demand |
| [docker](docker/README.md) | `Dockerfile` + `.goreleaser.yaml` | release workflow |

## Before packaging

Read [`docs/packaging.md`](../docs/packaging.md) first. It is addressed
to you: licence grant, minimum-toolchain policy, dependency pin model,
offline build instructions, and what to watch on a version bump.

Then read [`VERIFY.md`](VERIFY.md), which is how to check that the
artefact you are about to package is the one this project built.
