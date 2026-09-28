---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp reports what a server binary says about its own provenance and leaves signature verification to the tools built for it.
---

# 0010 — Provenance is reported, not verified

**Status:** Accepted · **Date:** 2026-09-22

## Context

The supply-chain milestone ended with "cosign bundle and SLSA attestation
verification", on the reasoning that the signature mathematics is in the
standard library.

The mathematics is. The protocol around it is not small: a Sigstore
bundle's verification checks a certificate chain to the Fulcio roots, a
transparency-log inclusion proof and its signed checkpoint, the signed
timestamps, and an identity policy over the certificate's extensions, all
against trust roots that rotate. Done without the Sigstore libraries, that
is weeks of security-critical code in which a subtle mistake produces a
false "verified" — the single most damaging result a tool like this can
emit ([ADR 0002](0002-findings-cite-requests.md)).

The narrower alternative — report whether a binary *has* published
provenance — needs a lookup against a transparency log or a release host,
which is a new network destination for a weaker answer.

## Decision

**passmcp reports provenance and does not verify signatures.**

- `supply.provenance` and `passmcp sbom` report what the binary records
  about itself: the commit, whether the tree was dirty, and every
  dependency's checksum. That is read off the file, offline, and it is the
  part of the report a server cannot influence by answering differently.
- Signature and provenance *verification* is done with the tools built and
  maintained for it — `cosign verify-blob` and `gh attestation verify` —
  and the documentation shows how, next to the bill of materials.

## Consequences

passmcp does not claim a verified supply chain for anything, and its
documentation says so. Its own releases stay signed and attested, and are
verified the same way it tells operators to verify anyone else's.

## What would make this wrong

A Sigstore verifier that can be used without adding a module to the core
binary — for example one maintained as a standalone, audited executable
that passmcp could invoke and cite. Then verification becomes a new decision.
