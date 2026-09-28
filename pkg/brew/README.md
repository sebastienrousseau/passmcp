<!--
SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
SPDX-License-Identifier: GPL-3.0-only
-->

# Homebrew

**Recipe:** the `brews` section of
[`.goreleaser.yaml`](../../.goreleaser.yaml), which generates the formula
from the release's own checksums. Not duplicated here; see
[`../README.md`](../README.md) for why.

Publishing happens in the `brew` job of
[`release.yml`](../../.github/workflows/release.yml), not in goreleaser.
The job opens a pull request on `sebastienrousseau/homebrew-tap` and merges
it immediately, so nothing waits for a human, and it is a separate job so
that an unreachable tap cannot fail the release after its artefacts and
provenance are published.

A formula rather than a cask, because a formula works on both macOS and
Linux, and installs the manpages and completions alongside the binary.

## Install

```bash
brew tap sebastienrousseau/tap
brew install passmcp
```

The tap repository must exist and the `HOMEBREW_TAP_TOKEN` secret must
be set before the first release, or the `brew` job reports the missing
token and the formula is not published.

Verify the artefact first; see [`../VERIFY.md`](../VERIFY.md).
