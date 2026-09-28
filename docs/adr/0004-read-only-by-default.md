---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp invokes only the tools that declare readOnlyHint unless you explicitly ask it to go further.
---

# 0004 — Only tools declaring `readOnlyHint` are invoked by default

**Status:** Accepted · **Date:** 2026-09-11

## Context

The execution phase invokes tools with generated arguments so it can
measure latency, validate `structuredContent` against `outputSchema`, and
check that a missing required argument is rejected. An MCP server is
routinely pointed at production data: a tool named `send_email` or
`delete_record` does exactly that when called.

The MCP specification gives every tool four behaviour hints and defines
their defaults: `readOnlyHint` is `false`, `destructiveHint` is `true`,
`idempotentHint` is `false`, `openWorldHint` is `true`. A tool that
declares nothing is, by the specification's own reading, a destructive
one.

The first prototype called every tool.

## Decision

`diagnostics.Policy` decides what may run, and the default policy invokes
a tool only when its annotations declare `readOnlyHint: true`. A tool with
no annotations is skipped with the reason *no annotations: destructive by
spec default*, and the catalog phase warns that such tools exist.

Two explicit opt-ins widen it. `--allow-mutations` adds tools that declare
`destructiveHint: false`. `--allow-destructive` adds everything and is
documented as suitable for the operator's own test tenant. `--only` and
`--deny` narrow either set by name, and `--arg` lets the operator supply
real arguments in place of generated ones.

The same policy applies to the agentic probe in `diagnostics`: a model
that asks for a blocked tool is told so, and the refusal is a finding
about the tool's description, not an override.

Resources are read and prompts are rendered without a policy check, because
the specification defines both operations as non-mutating.

## Consequences

Against a well-annotated server the phase is safe and useful. Against a
server with no annotations it executes nothing, and says so: the finding
*0 of N tools executed: none permitted by policy* carries the advice to
add `readOnlyHint` or to opt in. A poorly annotated server scores lower
for that, which is the intended pressure.

The cost is that the first run against a typical server is less
informative than it could be. That is the right default for a tool whose
alternative failure is an email sent or a row deleted in someone's
production system.

The fake server in the probe suite panics if its unannotated tool is ever
called under the default policy, so a regression here fails the build
rather than a customer.

## What would make this wrong

A server that lies — `readOnlyHint: true` on a tool that writes. The
hints are advisory and the specification says so. passmcp cannot detect the
lie; it can only report what the server declared, and the report says
*read-only tools* under *Safety policy* so the reader knows the basis.
If a class of servers with dishonest hints appears, the mitigation is a
`--deny` list in a profile, not a change to the default.
