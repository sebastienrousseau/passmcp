---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp probes an MCP server for unauthenticated access over a second transport that carries no credential at all.
---

# 0001 — Unauthenticated probes use a second, credential-free transport

**Status:** Accepted · **Date:** 2026-09-11

## Context

The client's transport chain is `bearer → fixed headers → trace →
recorder → base`. Every request through it carries whatever the operator
supplied: a bearer token, an `X-API-Key` header, basic credentials.

Two checks only mean something if they arrive with none of that:

- **First contact.** The discovery phase sends `initialize` without
  credentials to learn whether the server enforces authorization at all.
  A 200 here means "open server"; a 401 means "protected, go discover".
- **Invalid-token rejection.** The auth phase sends one request with a
  made-up bearer token. A 2xx here is a critical finding: the server
  accepts anything.

The first implementation sent both through the client's transport and
deleted the `Authorization` header from the request. The bearer
round-tripper put the real one back. Against a server that accepts any
token, first contact returned 200 — the server was reported as open, the
auth phase was skipped, and the critical finding was never reached. The
test that exposed it was the one that mattered:
`TestServerAcceptingGarbageTokenIsCritical` passed with a token the server
had never issued.

## Decision

`probe.Session` holds two transports to the same endpoint. `Client` is the
credentialled one. `Bare` is built from the recorder-wrapped base with
only the trace round-tripper on top — no token source, no header
transport, no basic auth. The first-contact and invalid-token probes use
`Bare`; everything else uses `Client`.

## Consequences

The two probes now observe what an unauthenticated stranger would. The
recorder still sees both transports, so their requests appear in the
telemetry with the same trace id and are citable as evidence.

The cost is a second `transport.Streamable` whose session state must not
be confused with the client's. `Bare.Reset()` is called after each probe
so a session id the server hands out to the stranger is never reused.

## What would make this wrong

A credential kind that cannot be removed from a request — mutual TLS,
say, where the client certificate is part of the connection rather than a
header. `Bare` shares the base transport, so it would present the
certificate too. If passmcp grows mTLS support, `Bare` needs its own base
transport without the client certificate, and this record gets a
successor.
