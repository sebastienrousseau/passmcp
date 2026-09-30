---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why every passmcp finding cites the requests that produced it, and why the score is derived from findings rather than asserted.
---

# 0002 — Every finding cites the requests that produced it; the score is derived from findings

**Status:** Accepted · **Date:** 2026-09-11

## Context

A diagnostic tool is trusted exactly as far as its claims can be checked.
"Protocol conformance: pass" is worth nothing if the reader cannot see
which request was sent and what came back. And a score that is computed
separately from the findings — a formula over counters — can drift from
them: a phase can fail while the number stays high, or the number can
drop for a reason no finding explains.

The first prototype had both problems. It kept counters (`FailedCalls`,
`SchemaMismatches`) and derived a score from them, with a deduction table
nobody could trace back to a specific observation.

## Decision

Two rules, both enforced in `internal/probe` and `internal/report`.

**A finding carries evidence.** Every check is opened with
`Session.check(id, title)`, which records the recorder's sequence number
at that moment. When the check is closed with `pass`, `fail`, `warn`,
`info` or `skip`, the range of requests made in between is attached as
`req#N` or `req#N-M`. Those numbers are the `seq` field in
`telemetry.ndjson` and the entry index in `telemetry.har`, so the
JSON report, the NDJSON and the HAR cross-reference by construction.

`pass` is reserved for a property a request actually showed. A check
that made no request cannot pass; it can only be `info` (an observation
without judgement) or `skip` (with a reason).

**The score is a function of the findings and nothing else.**
`report.ComputeScore` walks the phase results. Each category starts at
100; a `fail` deducts by severity (critical 100, major 40, minor 15), a
`warn` deducts 5, and every deduction is listed with the finding id and
detail that caused it. A category whose phases did not run is reported
as *not assessed* and excluded from the weighted mean, and the report
says how many categories were assessed, so a partial run cannot pass for
a full one.

## Consequences

A reader who doubts a finding can open the HAR file at the cited entry
and see the request. A reader who doubts the score can read the
deductions and find the finding behind each one. There is no third
source of truth.

The cost is discipline in the phase code: a check must be opened before
its requests and closed after them, and a helper that makes requests
outside a check produces uncited telemetry. The `check` builder makes the
correct shape the easy one.

## What would make this wrong

A finding whose evidence is not a request — a static analysis of a
schema, say, that needs no round trip. Those exist already
(`catalog.tools.unique`) and are closed as `pass` with an empty evidence
list, which the rule above forbids by the letter. The spirit is that a
`pass` must be *checkable*; for a schema property the catalog listing it
was derived from is the evidence, and it is cited by the
`catalog.tools.list` finding immediately before. If findings without a
citable basis multiply, evidence should grow a second kind — a pointer
into the report's own catalog — and this record gets a successor.

## Enforcement

Added 2026-09-30. The rule is enforced in code rather than by review
alone. `check.done` records a `pass` that carries no evidence (no request
in its window and nothing cited with `ev`) as `info`, with a note in its
detail, unless the check is listed in `derivedChecks`
(`internal/probe/evidence.go`) with where its evidence is: the exception
this record describes, made explicit and reviewable. The probe test
suite fails if any test produces such a pass, so a new check that
forgets its evidence is caught before it ships, and
`TestDerivedChecksAreRealChecks` keeps the list to checks that exist.
