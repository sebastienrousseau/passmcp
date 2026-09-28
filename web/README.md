<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# passmcp's web surface

This directory holds the source for the application shell that `passmcp serve`
serves. The shell is built by [SSG](https://static-site-generator.com/) from
the passmcp theme and committed under `internal/web/dist`, so the binary needs
no toolchain at run time and no assets beside it.

## Build

```sh
make web-shell
```

That runs `ssg build -f web/ssg.toml` and copies the icons from `brand/`
afterwards, which matters because ssg wipes its output directory: anything
committed inside `internal/web/dist` that ssg did not write is destroyed on
the next build.

Output lands in `internal/web/dist`, where `//go:embed` picks it up. Rebuild
and commit the output whenever anything under `web/` changes — the embedded
copy is what ships, so a change here that is not rebuilt is a change that
does not exist. It has already happened once: the shell shipped advertising
the wrong check count, with every asset under a `/passmcp/` base path left
over from an older `base_url`. CI now asserts both.

## Why the layouts are vendored

`web/_layouts` is a copy of the passmcp theme from the SSG theme suite. A
product site that needs a second repository checked out to build is a
product site that breaks the week nobody is looking, so the theme travels
with the code that uses it. Update it by copying the theme in again.

## What belongs here, and what does not

The shell is a presenter. It builds an `engine.RunSpec`, posts it, and draws
the events that come back. No check, no policy and no default lives in this
directory: anything decided here would be a capability the CLI and the TUI
do not have, and the three surfaces are peers.
