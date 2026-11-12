---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Using passmcp alongside @modelcontextprotocol/conformance: SDK fixture grading versus zero-fixture diagnostics on deployed HTTP and stdio servers.
---

# From `@modelcontextprotocol/conformance`

`@modelcontextprotocol/conformance` is the official MCP conformance runner.
It grades SDK reference servers against specification scenarios (`server` and
`tier-check`) and tests MCP clients against a controlled scenario server
(`client`). passmcp diagnoses any deployed HTTP or `stdio` MCP server as it
stands, with no reference fixtures compiled into the server.

## What carries over

- **Unattended CI gating.** Both tools run from a pipeline and fail the step
  through their exit status when checks fail.
- **Specification revisions.** Both cover handshake-era Streamable HTTP
  (`2025-11-25` and earlier) and the stateless `2026-07-28` revision
  (`server/discover`, mirrored routing headers, SEP-2549 caching hints, Tasks
  and SEP-2164 resource errors).
- **Expected-failure baselines.** Where `conformance` accepts a YAML
  `--expected-failures` list (`scenario` or `scenario:check-id`), passmcp
  evaluates an acceptance policy (`--policy`) or a signed catalogue baseline
  (`--baseline`).

## What is different

- **No `test_*` fixtures on the server.** Many `conformance` server scenarios
  call predetermined fixture names (`test_simple_text`, `test_sampling`,
  `test_elicitation`, `test://static-text`) so an SDK reference server can
  prove every protocol feature. Against a production server that does not ship
  those fixtures, those scenarios fail unless listed in a baseline. passmcp
  discovers whatever tools, resources and prompts the server actually exposes,
  synthesises safe arguments from each `inputSchema` (or takes `--arg`), and
  skips optional capabilities the server did not declare.
- **`stdio` servers and process custody.** `passmcp check -- <command>` runs
  local child-process servers over pipes and checks process survival, clean
  `stdout` framing, clean exit on `stdin` EOF, orphan processes, outbound
  egress (`--watch-egress`), upstream fault handling (`--fault-upstream`) and
  planted credential decoys (`--plant-canaries`).
- **Read-only invocation policy.** passmcp invokes only tools annotated with
  `readOnlyHint: true` unless explicitly permitted, treating unannotated tools
  as destructive per the MCP specification.
- **Redacted wire evidence and attestations.** Every passed or failed finding
  cites the recorded exchanges (`req#N`) in a structurally redacted HAR file,
  and `passmcp attest` signs an in-toto DSSE attestation of the run.

## What passmcp will not do

- **Grade an SDK for official conformance tiers.** Use
  `@modelcontextprotocol/conformance` and `tier-check` against your SDK's
  reference fixture server to measure spec-tier coverage.
- **Test an MCP client.** passmcp is a client-side diagnostic that probes
  servers; testing how a host or client SDK handles server responses belongs
  to `npx @modelcontextprotocol/conformance client`.
- **Drive interactive client callbacks.** passmcp declares no sampling or
  elicitation capabilities and validates `input_required` responses
  observationally rather than completing synthetic multi-round-trip fixtures.
