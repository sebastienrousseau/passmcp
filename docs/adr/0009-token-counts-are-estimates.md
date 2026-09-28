---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp reports catalogue token cost as a named estimate and does not embed a third-party tokenizer vocabulary.
---

# 0009 — Token counts are estimates, and say so

**Status:** Accepted · **Date:** 2026-09-22

## Context

`catalog.budget.tokens` reports what a server's catalogue costs a model to
read. It counts bytes exactly and estimates tokens as characters divided by
four, and the finding prints that rule (`TokenRule`) so nobody mistakes
the estimate for a measurement.

The roadmap asked for more: embed a byte-pair-encoding vocabulary, about
1.6 MB, and count exactly, with agreement to within 1% of a reference
tokenizer as the proof.

## Decision

**No tokenizer vocabulary is embedded.** Token counts stay estimates, and
every finding that carries one names the rule that produced it.

The reasons, in order of weight:

1. **There is no reference to be exact against.** Every model family
   tokenizes differently, and the tokenizers of several widely used models
   are not published. An exact count against one public vocabulary is a
   precise answer to a question the reader did not ask: it measures one
   model's cost and would be read as the cost. A named estimate is the
   honest form of an answer that differs by model.
2. **Licensing and supply chain.** A third-party vocabulary file is data
   with its own licence and provenance, in a repository whose SBOM is
   hand-checked against `go.mod` and whose files are REUSE-annotated. The
   module graph would not change, but the review burden would, and the
   benefit is the false precision of point 1.
3. **The decision the finding supports does not need it.** The budget's
   thresholds (10,000 and 40,000 tokens for a catalogue, 500 for one tool)
   separate a lean catalogue from a heavy one by factors, not by percent.
   Offenders are named by relative weight, which the estimate orders
   correctly.

Milestone 4 closes with the estimate. Its proof becomes: bytes are exact,
the estimate's rule is printed in the finding, and the offenders are
ordered by the same measure.

## What would make this wrong

A tokenizer that the models an operator actually uses share, published
under a licence compatible with redistribution. Then exact counts would
measure something real, and embedding it would be a new decision.
