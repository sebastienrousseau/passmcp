---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How passmcp compares with @modelcontextprotocol/conformance, MCP Inspector, a hand-written curl script and a hosted playground, and what each is still better at.
---

# Comparison

Teams testing MCP implementations reach for different tools depending on the
job: `@modelcontextprotocol/conformance`, MCP Inspector, a curl script, or a
hosted playground. Each is good at something passmcp deliberately does not do.
This page says what passmcp adds and what it leaves to them. Every cell comes
from the migration guide for that tool, which says what carries over, what is
different and what passmcp will not do.

| Dimension | passmcp | `@modelcontextprotocol/conformance` | MCP Inspector | curl script | Hosted playground |
| :--- | :---: | :---: | :---: | :---: | :---: |
| Runs unattended and gates CI on its exit status | yes | yes | no | yes | no |
| Diagnoses a production server without `test_*` fixtures | yes | baseline needed | yes | yes | yes |
| Probes `stdio` child processes (framing, exit, orphans, egress) | yes | no | partial | no | no |
| Sends negative-path probes: invalid token, unknown method, malformed JSON, bogus session, missing argument | yes | partial | no | no | no |
| Cites the requests behind each finding, with a redacted HAR file | yes | no | no | no | no |
| Discovers authorization instead of a pasted token endpoint | yes | yes | yes | no | varies |
| Runs from your network, so credentials stay on your machine | yes | yes | yes | yes | no |
| Reaches a server on `127.0.0.1` | yes | yes | yes | yes | no |
| Invokes only read-only tools unless told otherwise | yes | fixture-driven | you choose | you choose | you choose |
| Grades SDK reference servers (`tier-check`) and tests MCP clients | no | yes | no | no | no |
| Lets you explore interactively, one form at a time | no | no | yes | no | yes |
| Runs arbitrary call sequences and custom scenarios | no | yes | no | yes | no |
| Follows server-initiated messages on a long-lived stream | no | yes | yes | no | varies |

"varies" means it depends on which playground; there is more than one.
"you choose" means the tool runs whatever call you make, which is its
point and not a flaw. "baseline needed" means scenarios expecting SDK
`test_*` fixtures fail against a production server unless listed in
`--expected-failures`.

## What each is still better at

- **`@modelcontextprotocol/conformance`** grades SDK reference servers for
  official spec tiers (`tier-check`), exercises multi-step fixture scenarios
  such as sampling and elicitation callbacks, and tests MCP clients against a
  mock server (`client`). Use it to certify an SDK or test a client; use
  passmcp to diagnose a real server as deployed.
- **MCP Inspector** is the tool for exploring one server by hand: a form
  per tool, a connection that stays open, server-initiated messages as
  they arrive. passmcp checks that the stream opens and closes it.
- **A curl script** runs exactly the sequence you wrote. passmcp calls each
  permitted tool once and repeats the ones that worked for latency; keep
  the script for scenario tests and use `passmcp call` inside it where a
  timed, recorded call helps.
- **A hosted playground** needs nothing installed and gives you a link to
  share. passmcp hosts nothing; the Markdown report is what you share.

## The guides

- [From `@modelcontextprotocol/conformance`](migrating/from-mcp-conformance.md)
- [From MCP Inspector](migrating/from-mcp-inspector.md)
- [From a curl script](migrating/from-a-curl-script.md)
- [From an online playground](migrating/from-an-online-playground.md)
