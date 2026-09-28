---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How passmcp compares with MCP Inspector, a hand-written curl script and a hosted playground, and what each is still better at.
---

# Comparison

Before passmcp, most people test an MCP server with one of three things:
MCP Inspector, a curl script, or a hosted playground. Each is good at
something passmcp deliberately does not do. This page says what passmcp adds
and what it leaves to them. Every cell comes from the migration guide
for that tool, which says what carries over, what is different and what
passmcp will not do.

| Dimension | passmcp | MCP Inspector | curl script | Hosted playground |
| :--- | :---: | :---: | :---: | :---: |
| Runs unattended and gates CI on its exit status | yes | no | yes | no |
| Sends negative-path probes: invalid token, unknown method, malformed JSON, bogus session, missing argument | yes | no | no | no |
| Cites the requests behind each finding, with a HAR file | yes | no | no | no |
| Discovers authorization instead of a pasted token endpoint | yes | yes | no | varies |
| Runs from your network, so credentials stay on your machine | yes | yes | yes | no |
| Reaches a server on `127.0.0.1` | yes | yes | yes | no |
| Invokes only read-only tools unless told otherwise | yes | you choose | you choose | you choose |
| Lets you explore interactively, one form at a time | no | yes | no | yes |
| Runs arbitrary call sequences and scenarios | no | no | yes | no |
| Follows server-initiated messages on a long-lived stream | no | yes | no | varies |

"varies" means it depends on which playground; there is more than one.
"you choose" means the tool runs whatever call you make, which is its
point and not a flaw.

## What each is still better at

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

- [From MCP Inspector](migrating/from-mcp-inspector.md)
- [From a curl script](migrating/from-a-curl-script.md)
- [From an online playground](migrating/from-an-online-playground.md)
