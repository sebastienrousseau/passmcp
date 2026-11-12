---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp's MCP client and server SDKs live in six Apache-2.0 lockstep repositories (passmcp-sdk-<lang>), and the conformance and attestation contract they share.
---

# 0013 — Language SDKs are Apache-2.0 lockstep satellites

**Status:** Accepted · **Date:** 2026-11-12

## Context

`passmcp` diagnoses MCP servers across 139 checks in nine phases and emits
signed `in-toto` attestations (`mcp-evaluation/v1`). Two recurring gaps follow
every diagnostic run:

1. **Fixing findings happens in server and client SDKs, not in the probe.**
   Operators whose servers fail `protocol.origin`, `protocol.unknown_resource`
   (SEP-2164), `catalog.cache_hints` (SEP-2549), `server/discover` stateless
   routing, or missing `readOnlyHint` annotations often hit defaults in the
   library they built on, across Go, Python, Java, C++, TypeScript, and Rust.
2. **Embedding cannot take GPL-3.0 or a CLI dependency graph.** As recorded in
   [ADR 0011](0011-attestation-format-is-apache.md), `satellion.com/passmcp`
   stays GPL-3.0-only, exposes client-side packages only, and brings terminal UI
   and CLI dependencies into `go.sum`. `satellion.com/passmcp-reporting`
   provides the zero-dependency Go attestation verifier under Apache-2.0, while
   Python, Java, C++, TypeScript, and Rust services still have to hand-roll
   subject-digest recomputation (`transport + "\n" + trim(endpoint)`) and
   verdict checks against `mcp-evaluation-v1.schema.json`.

## Decision

Add six lockstep SDK satellites to the family manifest in `internal/ecosystem`,
starting at `Status: Unreleased` on `feat/v0.0.10`:

| Repository | Language | Licence | Package coordinate |
|---|---|---|---|
| `passmcp-sdk-go` | Go | Apache-2.0 | `satellion.com/passmcp-sdk-go` |
| `passmcp-sdk-python` | Python | Apache-2.0 | `passmcp-sdk` (`passmcp_sdk`) |
| `passmcp-sdk-java` | Java | Apache-2.0 | `com.satellion:passmcp-sdk` |
| `passmcp-sdk-cpp` | C++20 | Apache-2.0 | `passmcp::sdk` (CMake) |
| `passmcp-sdk-typescript` | TypeScript | Apache-2.0 | `@passmcp/sdk` |
| `passmcp-sdk-rust` | Rust | Apache-2.0 | `passmcp-sdk` |

Naming uses the `passmcp-sdk-<lang>` prefix so capability satellites
(`passmcp-server`, `passmcp-lsp`, `passmcp-graph`, `passmcp-registry`) never
collide with language runtimes.

## Shared conformance and attestation contract

Every `passmcp-sdk-<lang>` repository implements the same two halves:

1. **Conforming MCP client and server (`2025-06-18`, `2025-11-25`, `2026-07-28`)**:
   - `stdio` (newline-delimited JSON-RPC 2.0) and Streamable HTTP transports
     with strict `Origin` checking by default on local and remote HTTP servers.
   - OAuth 2.1 with S256 PKCE, RFC 9728 Protected Resource Metadata, and
     RFC 8414 Authorization Server Metadata discovery.
   - Capability-gated dispatch: undeclared capabilities are omitted from
     `initialize` and `server/discover` and rejected with JSON-RPC `-32601`;
     stateless `server/discover` answers in one round-trip on `2026-07-28`.
   - SEP-2164 unknown-resource errors (`-32602` with `error.data.uri` on
     `2026-07-28`, configurable `-32002` on earlier revisions) and SEP-2549
     list cache hints (`_meta.ttlMs >= 0`, `_meta.cacheScope` in
     `{"public", "private"}`).
   - Safe defaults matching [ADR 0004](0004-read-only-by-default.md): client
     policies treat unannotated tools as destructive unless explicitly opted in.
   - CI gates each SDK's reference server against a pinned `passmcp` release
     (`0` failures) and `@modelcontextprotocol/conformance`.
2. **Offline `passmcp` attestation verification**:
   - Parses and validates `https://in-toto.io/Statement/v1` envelopes carrying
     `https://satellion.com/attestation/mcp-evaluation/v1` (and
     `a2a-evaluation/v1`), recomputing SHA-256 and SHA-512 over the canonical
     target descriptor (`transport + "\n" + trim(endpoint)`) and checking
     verdict tallies, rubric presence, `Covers(transport, endpoint)`, and
     `VerdictFor(checkID)` against `passmcp-reporting`'s test vectors.
   - `passmcp-sdk-go` imports `satellion.com/passmcp-reporting` directly rather
     than duplicating the Go verifier.

## Why six separate repositories, and what it costs

- **Licence and dependency isolation**: Apache-2.0 carries the patent grant
  embedders require while keeping the `passmcp` diagnostic engine GPL-3.0-only
  ([ADR 0011](0011-attestation-format-is-apache.md)).
- **Native packaging and release pipelines**: PyPI wheels, Maven Central JARs,
  CMake/vcpkg/Conan targets, npm/JSR packages, Cargo crates, and Go modules
  each expect repository-root manifests, tag layouts, and language-specific CI
  matrices that would turn the `passmcp` repository into a polyglot monorepo.
- **Accepted cost**: six lockstep repositories inherit the family's one-version
  rule ([docs/ecosystem.md](../ecosystem.md#the-version-rule)). Each carries an
  explicit archive criterion in `internal/ecosystem/family.go` so an SDK without
  adoption twelve months after its first release is archived cleanly rather than
  kept on life support.

## What would make this wrong

- Official MCP SDKs in one or more of these languages adopt strict
  conformance-by-default (`Origin` enforcement, SEP-2164, SEP-2549, stateless
  `server/discover`, read-only execution policies) and native `in-toto`
  evaluation verification, leaving only a thin wrapper. In that case the
  affected `passmcp-sdk-<lang>` repository meets its kill criterion and is
  archived in favour of upstream.
