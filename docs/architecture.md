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

Packages fall into layers. `go list ./...` and each package's doc comment
are the authoritative list; this section is the map.

```text
surfaces        cmd/ (cobra commands, flags, config precedence),
                cmd/passmcp (main), internal/tui (terminal views),
                internal/web (passmcp serve: browser app and --public mode)
orchestration   internal/engine: the one place a run is configured
                (RunSpec), validated and started, for every surface
multi-target    internal/fleet (scheduled sets), internal/watch (drift),
                internal/discover (find and prove MCP endpoints)
diagnostic      internal/probe (the phases and their Session), with
                internal/egress, canary, witness, supply, clientconf and
                diagnostics/ (policy, generated arguments, validation)
results         internal/report (model, score, renderers), attest,
                baseline, policy (gates), enrich, ocsf, otlp, a2a
support         internal/telemetry (recorder, redaction, HAR/NDJSON),
                internal/creds, config, diag, termsafe
public library  passmcp (root client), auth/, transport/, diagnostics/,
                trace/, attestation/, spec/controls; none imports
                internal/ or cmd/, and only attestation/ (which forwards
                to passmcp-reporting) goes beyond the standard library
```

Dependencies run one way:

```text
cmd ──► web, fleet, watch, discover ──► engine
engine ──► probe ──► passmcp ──► auth, transport
   │         ├──► creds ──► auth, telemetry
   │         ├──► telemetry ──► trace
   │         └──► diagnostics ──► passmcp
   └──► report, attest, baseline, policy, ocsf, otlp ──► probe (Finding)
```

The result packages import `probe` only for the `Finding` model.
`discover` reaches `engine` to validate what it found, which is the one
edge that points from a source package to the orchestrator.

## The run

Every surface builds an `engine.RunSpec` and calls `engine.Run`, which
validates it and hands probe its options. `probe.Run` builds one `http.Client` whose transport is wrapped by the
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
(`telemetry.SensitiveHeader`: Authorization, Proxy-Authorization,
cookies, anything containing key, token, secret, password or auth). Query
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
