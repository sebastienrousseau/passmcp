---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp is a diagnostic for Model Context Protocol servers: nine phases, 131 checks, run from your own machine against a live server.
---

# passmcp

passmcp connects to a remote [Model Context Protocol](https://modelcontextprotocol.io)
server the way an agent would, with the credentials you were given, and
writes down, step by step, what actually happened.

```bash
passmcp check https://mcp.example.com/mcp --token-env MCP_TOKEN
```

Nine phases run in order: network and TLS, authorization discovery,
credentials and token, the initialize handshake, protocol conformance,
the tool/resource/prompt catalog, safe execution with content validation,
latency and concurrency, and recovery from a lost session or token.
Every finding cites the requests that produced it, and nothing is marked
as passing without one.

## Where to go

| Page | What it covers |
|---|---|
| [Getting started](getting-started.md) | install, first run, exit codes |
| [Credentials](credentials.md) | every way to hand passmcp what the server gave you |
| [The nine phases](phases.md) | each check, what pass and fail mean, the finding ids |
| [Reports and telemetry](reports.md) | output formats, the report directory, HAR and NDJSON, scoring |
| [Configuration](configuration.md) | the config file, profiles, precedence, the token store |
| [Library use](library.md) | the Go packages the CLI is built on |
| [Comparison](COMPARISON.md) | passmcp beside MCP Inspector, curl scripts and hosted playgrounds |
| [Benchmarks](BENCHMARKS.md) | what passmcp's own work costs, and which budgets CI gates |

## Safety, in one paragraph

Only tools that declare `readOnlyHint: true` are invoked. A tool without
annotations is destructive by the specification's own default, so it is
skipped and the catalog phase says so. `--allow-mutations` and
`--allow-destructive` are explicit opt-ins. Requests are throttled to
two per second unless you say otherwise. Secrets never reach the report:
tokens, client secrets, API keys and OAuth codes are redacted at the
recorder, including tokens the server issued during the run.
