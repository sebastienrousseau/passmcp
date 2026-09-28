---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Hosted MCP playgrounds connect from someone else's infrastructure. passmcp runs the same checks from yours, against the same server.
---

# From an online playground

Hosted playgrounds connect to your server from their infrastructure, list
the tools, and let you try calls in a browser. They are convenient and
they are someone else's computer.

## What carries over

- **The connection details.** The URL and whatever credential the
  playground asked for map onto passmcp's flags and `PASSMCP_*` variables.
- **The catalog view.** `passmcp tools` gives the same list, as text,
  Markdown or JSON, plus the audit findings.

## What is different

- **Your credentials stay with you.** passmcp runs where you run it. Tokens
  and client secrets are registered with a redactor before the first
  request and never appear in the report, the telemetry or the HAR file;
  the token store is written with mode 0600.
- **Network truth.** A playground reaches your server from its network;
  passmcp reaches it from yours, and the net phase records DNS, TCP and TLS
  timings and certificate details for that path.
- **Repeatable.** The same command against the same server produces a
  comparable score. Put it in CI and diff the JSON.
- **Local servers.** A playground cannot reach `127.0.0.1`; passmcp can, and
  reports plain HTTP to loopback as acceptable rather than as a failure.

## What passmcp will not do

- Host anything or share a link. The Markdown report is what you share.
- Drive an LLM against the server. The `diagnostics.Model` interface
  exists for a model-driven probe, but no vendor adapter ships in this
  module.
