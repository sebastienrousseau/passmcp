---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why the attestation schema and the scoring rubric are published under Apache-2.0 while the engine stays GPL-3.0, and what that does and does not unblock yet.
---

# 0011 — The attestation format is Apache-2.0; the engine stays GPL

**Status:** Accepted · **Date:** 2026-09-22

## Context

passmcp's position depends on other software consuming what it produces:
gateways gating on an attestation, registries displaying it, CI systems
verifying it. The engine is GPL-3.0-only, and none of those will embed GPL
code or implement a format whose only definition is GPL source. The plan's
answer was a separate `passmcp-reporting` repository under Apache-2.0, and
that repository was blocked on this decision.

## Decision

**The attestation predicate's schema and the scoring rubric are licensed
Apache-2.0.** They live in `spec/`, are generated from the Go that
implements them by `scripts/specgen`, and CI fails when either drifts from
the source:

- `spec/attestation/mcp-evaluation-v1.schema.json` — the in-toto Statement
  and the `mcp-evaluation/v1` predicate, as JSON Schema 2020-12, derived
  from the `internal/attest` types. A test validates a statement passmcp
  actually writes against it, and checks that tampered statements fail.
- `spec/rubric/rubric-v1.json` — weights, deductions, grade bands and the
  scoring rules, read from the same variables `ComputeScore` uses.
- `spec/README.md` — the format described for an implementer.

The format is Apache-2.0, not CC-BY, because it is consumed as code — a
schema compiled into a validator — and Apache-2.0 carries the patent grant
that implementers and their legal teams look for.

**The engine stays GPL-3.0-only**, including the Go that produces and
verifies statements, for now. The copyright in every relicensed file is
held by the one maintainer, so no contributor consent was needed; that
stops being true with the first outside contribution to `internal/attest`,
which is a reason to extract soon rather than late.

## What this unblocks, and what it does not

It unblocks **implementing** the format elsewhere: a gateway can write its
own verifier against the schema and the rubric today.

It does not yet unblock **embedding passmcp's verifier**. `internal/attest`
builds statements from `internal/probe` and `internal/report`, which are
GPL, so the verifier cannot be lifted out as it stands. The next step is to
split the statement types and `Validate` into a package that imports only
the standard library, then license that package Apache-2.0 and move it with
the schema into `passmcp-reporting`. That is a structure change and is done
on its own, not coupled to this decision.

Signing (W5) and the gateway pull requests (W8) are no longer blocked on a
licence question, only on that extraction.

## Update — 2026-09-22: the verifier is extracted

The next step above is done. The statement types, `Parse`, `Validate`,
`Covers`, `VerdictFor` and a `SubjectFor` helper now live in the public
package `satellion.com/passmcp/attestation`, licensed
Apache-2.0 and importing only the standard library, with its own tests and
fixture under the same licence. `internal/attest` keeps the builder that
reads passmcp's report types and re-exports the rest, and the published
schema is unchanged. Moving the package to `passmcp-reporting` is now a copy.

## Update — 2026-09-23: the verifier has its own module

Preparing the first gateway contribution showed the copy was not enough on
its own: a Go consumer importing `passmcp/attestation` records every one of
passmcp's dependencies in its `go.sum`, because Go resolves modules rather
than packages. The package now lives unchanged in the module
`satellion.com/passmcp-reporting`, with the schema generated
there from its types; passmcp imports it back, and `passmcp/attestation` is a
deprecated forwarder so no importer breaks. The rubric stays here, generated
from the scorer. passmcp-reporting's
[ADR 0001](https://github.com/sebastienrousseau/passmcp-reporting/blob/main/docs/adr/0001-verifier-in-its-own-module.md)
records the split.

## What would make this wrong

A format adopted under a different licence by the specification's own
process — for example if the MCP project standardises an evaluation
predicate. Then the right move is to align with it, and this record is
superseded.
