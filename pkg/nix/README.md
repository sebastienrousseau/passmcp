<!--
SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
SPDX-License-Identifier: GPL-3.0-only
-->

# Nix

**Recipe:** [`flake.nix`](../../flake.nix) at the repository root. Unlike
the other formats this one is not generated at release time: it is the
source of truth, built from source on demand, and usable from a checkout.

## Before first use

`flake.lock` is not committed yet and `vendorHash` is
`pkgs.lib.fakeHash`: nix was not installed on the machine that wrote the
flake, and neither value can be produced honestly without it. On a
machine with nix:

```bash
nix flake lock
nix build 2>&1 | grep 'got:'   # copy the hash into vendorHash
nix build
```

and commit both changes.

## Run without installing

```bash
nix run github:sebastienrousseau/passmcp -- --help
```

## Build

```bash
nix build github:sebastienrousseau/passmcp
./result/bin/passmcp version
```

The package installs manpages and shell completions alongside the
binary, generated from the cobra command tree during `postInstall`
rather than committed.

## Development shell

```bash
nix develop
```

Every tool the CI gates need, pinned by `flake.lock`.

## Version

Read from the newest release heading in `CHANGELOG.md`, so the flake
cannot drift from the changelog.

## nixpkgs

Not yet submitted. A packager taking this upstream should build from
source with `buildGoModule` as the flake does.
