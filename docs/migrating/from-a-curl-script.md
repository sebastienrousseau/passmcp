---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Replace the shell script that POSTs initialize and tools/list with a tool that handles auth, both protocol revisions and event streams.
---

# From a curl script

You have a shell script that POSTs an `initialize`, grabs the
`Mcp-Session-Id`, and fires `tools/list` and a `tools/call` or two. It
works until the server adds authorization, changes the protocol version,
or starts answering with an event stream.

## What carries over

- **The JSON-RPC bodies.** passmcp sends the same messages; you can see them
  with `--capture-bodies --report-dir ./out` and diff them against yours.
- **The headers.** `--header "Name: value"` sends any fixed header your
  script did. `Accept`, `MCP-Protocol-Version` and `Mcp-Session-Id` are
  handled for you.
- **The token.** If the script exported a token and passed it as
  `Authorization: Bearer`, `--token-env` does the same.

## What is different

- **Discovery instead of hard-coding.** On a 401, passmcp parses the
  challenge, fetches the protected-resource metadata and the authorization
  server metadata, registers a client if the server offers it, and obtains
  a token, reporting each step. Your script needed the token endpoint
  pasted in; passmcp finds it, and `--token-url` is there for servers that
  publish nothing.
- **SSE and sessions.** passmcp reads JSON or `text/event-stream` responses,
  echoes the session id, and re-initializes on a 404 so a lost session is
  recovered rather than crashing the run.
- **Structured output.** Instead of `jq` over raw responses, `--output
  json` gives you findings, catalog, execution results, latency
  percentiles and the score in one document.

## What passmcp will not do

- Run arbitrary sequences of calls. passmcp's execution phase calls each
  permitted tool once with generated or supplied arguments, then repeats
  the successful ones for latency. Keep your script for scenario tests and
  use `passmcp call` inside it where a timed, recorded single call is useful.
- Skip the safety policy. A script calls what it is told; passmcp will not
  invoke a tool without `readOnlyHint` unless you pass `--allow-mutations`
  or `--allow-destructive`.
