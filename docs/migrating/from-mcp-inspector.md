---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Moving from MCP Inspector to passmcp: the same connection, run non-interactively, with findings and evidence instead of a form to fill.
---

# From MCP Inspector

MCP Inspector is a browser UI for poking at one server by hand: connect,
see the tool list, fill a form, read the result. passmcp is the
non-interactive counterpart that runs the same connection and then keeps
going.

## What carries over

- **The endpoint and the credentials.** Whatever you typed into the
  Inspector's connection panel maps onto a flag: the URL is the positional
  argument, a bearer token is `--token-env`, a custom header is `--header`,
  an OAuth client is `--auth client-credentials --client-id …`. The
  Inspector's browser-based OAuth login is `passmcp login`.
- **The tool list and schemas.** `passmcp tools <endpoint>` prints the same
  catalog, plus the audit the Inspector does not do: duplicate names,
  missing descriptions, non-object `inputSchema`, missing annotations and
  `outputSchema`.
- **One call at a time.** `passmcp call <endpoint> <tool> --arg field=value`
  is the Inspector's form, with the request timed and recorded.

## What is different

- **Unattended.** There is no UI. Output goes to stdout in `text`, `json`,
  `md` or `ndjson`, and the exit status is 2 when any finding failed, so a
  pipeline can gate on it.
- **Every phase, not just the happy path.** The Inspector shows you what
  the server returns when you ask nicely. passmcp also sends an invalid
  token, an unknown method, malformed JSON, a bogus session id, and a call
  with a required argument missing, and reports how the server handled
  each.
- **Evidence.** Each finding cites the requests behind it as `req#N`; with
  `--report-dir` the HAR file opens in the same devtools you used with the
  Inspector, but with connection timings and TLS details attached.
- **Safety policy.** The Inspector runs whatever you click. passmcp invokes
  only tools that declare `readOnlyHint` unless you opt in, and treats an
  unannotated tool as destructive, because that is the specification's
  default.

## What passmcp will not do

- Show you a form. Arguments come from the schema (generated) or from
  `--arg`.
- Follow server-initiated messages on a long-lived stream. passmcp checks
  that the GET stream opens and then closes it.
- Keep the connection open for you to explore. Use the Inspector for that;
  use passmcp to write down what the server does.
