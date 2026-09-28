---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Architecture decision records for passmcp — what was decided, what it cost, and what would make each decision wrong.
---

# Architecture Decision Records

Decisions that will be questioned later, with the reasoning that produced
them. Each record states what was decided, what it cost, and what would
make it wrong — so a future change can tell "this was considered and
rejected" apart from "nobody thought about it".

Records are immutable once merged. A decision that changes gets a new
record superseding the old one, not an edit.

A record whose *reasoning* turns out to be overstated is the one case that
is corrected in place, in a dated section that leaves the original claim
visible. Rewriting the argument silently would defeat the point of writing
it down; removing the record would lose the fact that the decision was
made on a weaker basis than it appeared.

| # | Decision | Status |
|---|---|---|
| [0001](0001-bare-transport-for-unauthenticated-probes.md) | Unauthenticated probes use a second, credential-free transport | Accepted |
| [0002](0002-findings-cite-requests.md) | Every finding cites the requests that produced it; the score is derived from findings | Accepted |
| [0003](0003-structural-redaction-at-the-recorder.md) | Secrets are redacted structurally at the recorder, and content types are not trusted | Accepted |
| [0004](0004-read-only-by-default.md) | Only tools declaring `readOnlyHint` are invoked by default | Accepted |
| [0005](0005-public-mode-is-the-same-binary.md) | The hosted diagnostic is the same binary, and it accepts no credentials | Accepted |
| [0006](0006-no-client-telemetry.md) | passmcp contains no client-side telemetry, and *0 bytes uploaded* is a product guarantee | Accepted |
| [0007](0007-not-a-gateway.md) | passmcp measures servers and is never in the data path between an agent and one (the line drawn, 2026-09-24) | Accepted |
| [0008](0008-no-adversarial-mode.md) | passmcp contains no adversarial or exploit probes, in any command | Accepted |
| [0009](0009-token-counts-are-estimates.md) | Token counts are named estimates; no tokenizer vocabulary is embedded | Accepted |
| [0010](0010-provenance-is-reported-not-verified.md) | Provenance is reported from the binary; signatures are verified with cosign or gh | Accepted |
| [0011](0011-attestation-format-is-apache.md) | The attestation schema and rubric are Apache-2.0; the engine stays GPL-3.0 | Accepted |
| [0012](0012-everything-stays-open.md) | No paid tier yet: every roadmap feature is built in the open until adoption says where the line goes | Accepted |
