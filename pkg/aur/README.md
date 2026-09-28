<!--
SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
SPDX-License-Identifier: GPL-3.0-only
-->

# Arch User Repository

Three packages, all maintained by `srousseau`:

| Package | What it installs | Built from |
| --- | --- | --- |
| [`passmcp`](https://aur.archlinux.org/packages/passmcp) | `passmcp`, its manpages and bash, zsh and fish completions | the release's source tarball |
| [`passmcp-server-bin`](https://aur.archlinux.org/packages/passmcp-server-bin) | [passmcp-server](https://github.com/sebastienrousseau/passmcp-server); depends on `passmcp` | the release archives, checked against `checksums.txt` |
| [`passmcp-agentgateway-extmcp`](https://aur.archlinux.org/packages/passmcp-agentgateway-extmcp) | the agentgateway ExtMcp processor | passmcp-reporting's source tarball |

```bash
yay -S passmcp    # or: paru -S passmcp
```

`passmcp-bin` on the AUR is an unrelated project with the same name.

## The recipe

**The source of truth is each package's AUR repository**
(`ssh://aur@aur.archlinux.org/<package>.git`), not a copy here: a
`PKGBUILD` in this directory would be a second place to change and a
first place to forget. `passmcp` builds from source, as Arch's Go
packaging guidelines describe (PIE, external linking, the build's own
`CFLAGS` and `LDFLAGS`), and runs the same `scripts/gen_docs.go` step as
the release for its manpages and completions.

## After a release

[`scripts/aur-bump.sh`](../../scripts/aur-bump.sh) moves all three
packages to the release: it sets the version, recomputes every checksum
from the published tarballs and `checksums.txt`, then builds, installs and
lints each package with `makepkg` and `namcap` in an Arch Linux container
before regenerating `.SRCINFO`. It pushes only with `--push`, and only
from a machine whose SSH key the AUR account holds.
