---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp redacts secrets structurally at the recorder instead of trusting content types or pattern-matching its own output.
---

# 0003 — Secrets are redacted structurally at the recorder, and content types are not trusted

**Status:** Accepted · **Date:** 2026-09-11

## Context

passmcp's output is meant to be shared: a report handed to the team that
runs the server, a HAR file attached to a bug. It therefore holds the one
thing that must never travel — the credentials the run was made with, and
the tokens the run obtained.

Redacting at the print site is the obvious approach and the wrong one.
There are many print sites (text, Markdown, JSON, NDJSON, HAR, the stderr
banner) and one more is always being added. And the secrets are not all
known up front: a client-credentials run *receives* an access token from
the token endpoint, a login *receives* a refresh token, dynamic
registration *receives* a client secret. A redactor that only knows what
the operator typed misses all of those.

The first test that serialised the telemetry after a full run found both
kinds of leak: the dynamically registered client secret, and every issued
access token, each sitting in a captured response body.

## Decision

Redaction lives in one place, `telemetry.Redactor`, and is applied when
an event is *recorded*, before any renderer sees it. It works in three
layers:

1. **By name.** `Authorization`, `Cookie`, `Set-Cookie` and any header
   whose name contains `key`, `token` or `secret` are masked whatever
   their value (the scheme word, `Bearer` or `Basic`, is kept so the
   report shows what was attempted). Query and form parameters named
   `code`, `state`, `access_token`, `refresh_token`, `client_secret`,
   `code_verifier`, `token`, `api_key`, `password` are masked.
2. **Structurally.** A JSON body is parsed and the keys `access_token`,
   `refresh_token`, `id_token`, `client_secret`,
   `registration_access_token`, `code`, `code_verifier`, `password`,
   `api_key` and `secret` are replaced, recursively. Their values are
   registered as secrets at the same time, so from that event onward
   they are masked wherever they appear — in a later body, in a URL, in
   an error string.
3. **By value.** Every registered secret (operator-supplied ones before
   the first request; discovered ones as they arrive) is replaced
   wherever it occurs, longest first, in raw and URL-escaped form.

**Content types are not trusted.** A token endpoint that answers
`text/plain` still carries an `access_token`. The recorder decides
whether a body is JSON by looking at its first non-space byte, not at the
`Content-Type` header. Bodies are buffered for this purpose even when
`--capture-bodies` is off, so secret registration does not depend on
whether the operator asked to keep bodies.

## Consequences

Every renderer is safe by construction, and a new one cannot leak what
it never receives. The test that matters is a whole-run assertion
(`TestFullRunClientCredentials`): serialise every event and grep for
every secret the fake server ever minted.

The cost is a JSON parse of every response body, capped at `BodyCap`,
and a redactor that must be reachable from the recorder — `Recorder.New`
creates one so a recorder without a redactor cannot exist.

## What would make this wrong

A secret that arrives in a shape none of the three layers recognise: a
binary token in a custom header whose name contains none of the trigger
words, or a JSON key a server invents. The by-name lists are the weak
point and are expected to grow. A server that returns a credential in a
place passmcp does not look is, for now, an accepted gap; the mitigation
is that `--capture-bodies` is off by default, so the unrecognised body
is never written to a report unless the operator asks.
