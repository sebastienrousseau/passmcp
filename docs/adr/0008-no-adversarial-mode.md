---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp has no adversarial or exploit mode — not behind a flag, and not behind a separate verb — and what that closes.
---

# 0008 — passmcp has no adversarial mode

**Status:** Accepted · **Date:** 2026-09-22

## Context

The implementation plan proposed opt-in adversarial probes: sending
exploit-shaped input to a server's tools to find injection and
request-forgery flaws, as the 2026 dynamic study of internet-facing MCP
servers did. It recommended putting them behind a separate verb with a
written statement that the operator owns the target, so that the default
tool stayed as safe as it is today.

Three things argue against building it at all.

**The posture is the product.** An operator points passmcp at production
because it is read-only by default, throttled, and sends nothing designed
to break anything ([ADR 0004](0004-read-only-by-default.md)). That is what
lets a security team approve the binary in an afternoon. A binary that
*contains* an exploit mode has to be reviewed as one, whatever the default,
and the review is paid by every team that evaluates passmcp.

**A gate is a sentence, not a control.** A flag or a verb that asks the
operator to confirm they own the target stops nobody who does not. The
same binary is distributed to everyone, including through `passmcp serve
--public`; code that is present is code that can be reached.

**The findings would break ADR 0002.** A finding passes only on evidence.
An exploit probe's evidence is a server doing something harmful because it
was asked to. Establishing that honestly means doing the harm, and a
diagnostic that reports "your server is vulnerable" on the strength of a
heuristic match would be the most damaging kind of result this project can
produce.

## Decision

**passmcp contains no adversarial or exploit probes**, in any command, behind
any flag. The "separate verb" option is closed, not deferred.

What stays, because it is not adversarial:

- Protocol conformance probes that send malformed or unusual *protocol*
  messages and check the server rejects them — the `protocol.*` phase as it
  exists. These test the server's parser, not its tools.
- `execution.*` calls to read-only tools with generated arguments, and to
  mutating tools only under `--allow-mutations`, on a server the operator
  names ([ADR 0004](0004-read-only-by-default.md)).
- Observation of what a server does on its own: egress, canaries, process
  custody. Watching is not attacking.

The census fence in the plan is satisfied by construction: there is
nothing adversarial for `passmcp survey` to reach.

## Consequences

Two published failure classes — injection through tool arguments and
request forgery to cloud metadata — stay outside what passmcp reports. The
documentation says so plainly, and points an operator who needs that
testing at dedicated security tooling and a scoped engagement.

The competitive table loses a row nobody else in passmcp's lane fills
either. That is a cost worth paying for a tool whose adoption depends on
touching nothing it was not asked to.

## What would make this wrong

A standard, independently maintained harness for exercising MCP servers
adversarially under a documented authorisation model — something passmcp
could *invoke* on an operator's behalf without shipping the payloads
itself. If one exists and is widely trusted, integrating with it is a new
decision, recorded as a new ADR that supersedes this one.
