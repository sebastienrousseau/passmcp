---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Install passmcp and run your first diagnostic against a live MCP server — one command, a verdict in plain language, and a list of what to fix.
---

# Getting started

## Install

```bash
go install satellion.com/passmcp/cmd/passmcp@v0.0.4
```

A binary installed this way reports the version it was installed at.
Release archives, `.deb`/`.rpm` packages and the Homebrew formula are
described in the repository's `pkg/` directory.

From source:

```bash
git clone https://github.com/sebastienrousseau/passmcp && cd passmcp
make build            # build/passmcp
make install          # /usr/local/bin/passmcp, manpages, completions
```

## First run

Against an open server:

```bash
passmcp check https://mcp.example.com/mcp
```

Against a server that gave you a bearer token:

```bash
export MCP_TOKEN=…
passmcp check https://mcp.example.com/mcp --token-env MCP_TOKEN
```

Against a server that is a program rather than a URL — which most of them
are:

```bash
passmcp check --stdio -- npx -y @modelcontextprotocol/server-everything stdio
```

passmcp starts it, diagnoses it, and stops it again. Everything after `--`
belongs to the server, including its own flags. See
[Servers that are programs](stdio.md) for what it is handed and which
checks apply.

The text report lists the nine phases in order, each finding with its
status, what was observed and what to do about it, then the catalog,
execution and performance tables, the score with every deduction, and a
telemetry summary. Add `--report-dir ./out` to keep every format plus the
raw telemetry.

## Commands

| Command | Does |
|---|---|
| `passmcp check <endpoint>` | the full nine-phase diagnostic |
| `passmcp connect <endpoint>` | net, discovery, auth and handshake only |
| `passmcp tools <endpoint>` | the connection phases plus the catalog audit, no invocations |
| `passmcp call <endpoint> <tool>` | one tool invocation with `--arg field=value` or `--json` |
| `passmcp read <endpoint> <uri>` | read one resource (`resources/read`) and print its contents |
| `passmcp prompt <endpoint> <name>` | render one prompt (`prompts/get`) with `--arg name=value` |
| `passmcp login <endpoint>` | authorize as a user in the browser and store the token |
| `passmcp config init\|validate\|show` | the configuration file |
| `passmcp version` | print the version |

An endpoint can be replaced by `--profile <name>` when the config file
names one; see [Configuration](configuration.md). `check`, `connect`, `tools`,
`call`, `read` and `prompt` also accept `--stdio -- <command>` in place of
an endpoint; for `call`, `read` and `prompt` the tool name, URI or prompt
name comes before the `--`.

`read` and `prompt` work like `call`: the same credential flags, `--output
text` or `json` (the result, its duration and a telemetry summary), exit 1
when the server returns an error. Both are non-mutating by the MCP
specification, so unlike tool execution in `check` no policy flag gates
them ([ADR 0004](adr/0004-read-only-by-default.md)). Text contents are
printed as they are; binary resource contents are described by URI, size
and MIME type rather than written to the terminal.

## Exit status

| Code | Meaning |
|---|---|
| 0 | the run completed and no finding failed |
| 2 | the run completed and at least one finding failed |
| 1 | passmcp itself could not run: bad flags, unreachable config, an internal error |

Warnings do not change the exit status. A CI job that should fail on a
warning can read the JSON report's `counts.warn` instead.

## Where output goes

Results go to stdout in the format `--output` selects. Diagnostics, what
passmcp is doing and why something was skipped, go to stderr under
`--log-level` (`error`, `warn`, `info`, `debug`), or `PASSMCP_LOG_LEVEL`
for a whole shell session. `--output json` therefore stays pipeable no
matter how noisy the run is.
