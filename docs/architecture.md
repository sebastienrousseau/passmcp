---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How passmcp is built, for people changing it: the transport chain, the phase engine, the recorder, and where findings come from.
---

# Architecture

How passmcp works, for people changing it.

## The shape of it

passmcp does one thing: it connects to a remote MCP server the way an agent
would and writes down, step by step, what actually happened. Every phase
makes real requests through one recorder, every finding cites the requests
that produced it, and the score is derived from the findings rather than
asserted separately.

## Package layout

```text
cmd/passmcp            main(); nothing but a call into cmd
cmd/                 cobra commands, shared flag groups, config precedence
internal/probe       the nine phases and the Session they share
internal/report      Report model, scoring, text/Markdown renderers
internal/telemetry   httptrace recorder, redaction, HAR/NDJSON export
internal/creds       credential model, env resolution, token store
internal/config      flag-keyed config file with defaults and profiles
internal/diag        levelled diagnostics, always to stderr
internal/tui         Bubble Tea run view (phase list, report viewport), tool selector, braille logo
passmcp (root)         public client: Connect state machine, catalog, calls
auth/                RFC 9110/9728/8414/7591/8707 + PKCE, token sources
transport/           Streamable HTTP: JSON-RPC over POST, SSE, sessions
diagnostics/         policy, schema-driven arguments, validator, limiter
trace/               per-run trace id in context and X-MCP-Trace-ID
```

Dependencies run one way:

```text
cmd ──► probe ──► passmcp ──► auth
  │       │         └────► transport
  │       ├──► creds ──► auth
  │       ├──► telemetry ──► trace
  │       └──► diagnostics ──► passmcp
  ├──► report ──► probe
  └──► config
```

## The run

`probe.Run` builds one `http.Client` whose transport is wrapped by the
telemetry recorder, then wraps that again for the client: trace header,
fixed headers (API keys, basic auth), and the bearer transport. A second,
bare transport to the same endpoint carries nothing but the trace header;
the discovery and auth phases use it for the requests that must arrive
unauthenticated (first contact, the garbage-token probe). Without it, the
bearer transport would silently add the real token and a server that
accepts anything would look open.

Phases run in order. Each returns findings; a phase that discovers the
server cannot be reached, or that credentials are missing for a protected
server, sets `Session.blocked` and every later phase is recorded as
skipped with that reason. The report therefore never shows a category as
assessed when its phase did not run.

## Generated artefacts

Manpages and shell completions are generated from the cobra command tree
by `scripts/gen_docs.go` at build time and never committed, so they cannot
drift from `--help`. `tools.go` pins `cobra/doc` in `go.mod` so the
generator resolves offline.

## Findings

A finding is `{id, title, status, severity, detail, evidence, advice}`.
`status` is one of pass/warn/fail/skip/info. Evidence is the range of
recorder sequence numbers made while the check ran (`req#12-14`), so the
JSON report and the HAR file can be cross-referenced by `seq`.

The rule for status: pass needs a request that showed the property; info
records an observation with no judgement; warn is a deviation an agent can
live with; fail is one it cannot. Severity on fail drives the score:
critical zeroes the category, major costs 40, minor 15; every warn costs 5.

## Redaction

The recorder owns a `Redactor`. Operator-supplied secrets are registered
before the first request. Header values are masked by name policy
(Authorization, Cookie, anything containing key/token/secret). Query
parameters and form fields are masked by name. JSON bodies are masked
structurally: `access_token`, `refresh_token`, `client_secret`, `code`
and friends are replaced and their values registered, so a token issued
in the middle of a run is masked in every later event. Content types are
not trusted; a body that starts with `{` is treated as JSON.

## Safety

`diagnostics.Policy` decides what may be invoked. By default only tools
that declare `readOnlyHint: true` run. The MCP specification's default for
a tool without annotations is destructive, and passmcp honours that: such
tools are skipped and the catalog phase warns about them.
`--allow-mutations` unlocks non-destructive mutations; `--allow-destructive`
unlocks everything and is documented as dangerous. Requests are throttled
to `--rps` (default 2) unless `--allow-load` is given for the burst.
