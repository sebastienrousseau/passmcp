---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
name: "passmcp"
short_name: "SC"
title: "passmcp — test any MCP server, from your own machine"
description: "Nine phases, 131 checks, every finding tied to the request that produced it. Runs where your credentials already live."
keywords: "MCP server testing, Model Context Protocol, MCP diagnostics, MCP security"
author: "Sebastien Rousseau"
date: "2026-09-16"
layout: "app"
language: "en-GB"
schema: "page"
changefreq: "weekly"
copyright_year: "2026"
form_origin: "'self'"
theme_style: "style-passmcp"
theme_colour: "#08545c"
brand_mark: "S"
footer_note: "A verdict is worth what its evidence is worth."
eyebrow: "Running locally · nothing leaves this machine"
headline: "Test an MCP server."
lead: "Nine phases, 131 checks, both protocol generations. Every finding is tied to the request that produced it, and the whole run happens here — the endpoint, the credentials and the report never leave this machine."
cta_primary: "Run diagnostic"
cta_secondary: "Method"
---

passmcp runs the same diagnostic here as it does on the command line: the
browser builds a run specification, the binary executes it, and the events
stream back as each phase finishes. Nothing about the run differs from
`passmcp check` — the surfaces are peers, not wrappers.
