<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Dependency provenance

REPO-STANDARD asks for a dependency provenance policy — `cargo-vet` or the
ecosystem equivalent — with exemptions regenerated on every dependency
change. Go has no `cargo-vet`, and pretending otherwise by inventing a file
format nothing reads would be worse than writing down what actually holds.

This directory is that statement. It is short because Go's answer is mostly
in the toolchain rather than in a review ledger.

## What replaces a review ledger here

| Concern | Go's mechanism | Where it is enforced |
|---|---|---|
| A dependency changed under us | `go.sum`, committed | `go mod verify` in CI; a mismatch is a hard failure |
| The module proxy served something different to someone else | The public checksum database, `sum.golang.org` | Default `GOSUMDB`; never disabled in CI |
| A dependency has a known vulnerability | `govulncheck`, `osv-scanner` | `security.yml`, every push |
| A dependency was added without anyone noticing | `go.mod` diff in review, plus dependency review | `dependency-review` on every pull request |
| A transitive dependency reaches the library's consumers | The dependency count itself | See the policy below |

## The policy that does the real work

**The direct dependency list is short on purpose, and every addition is
argued in the pull request that adds it.**

`go.mod` has nine direct dependencies. Six are the terminal UI; two are the
command-line parser; one is passmcp's own attestation verifier,
[`passmcp-reporting`](https://github.com/sebastienrousseau/passmcp-reporting),
split out under Apache-2.0 so that a gateway can import it without this
module's graph, and itself importing only the standard library. Everything
else — HTTP, TLS, JSON-RPC framing, OAuth,
JSON Schema validation, SARIF, JUnit, OTLP export, HAR — is written against
the standard library.

That is a deliberate trade with a cost: more code here, and a JSON Schema
validator that is ours to maintain. It buys three things a review ledger
cannot. A supply-chain compromise has almost no surface to arrive through.
`CGO_ENABLED=0` yields a genuinely static binary that runs in a scratch
container. And a diagnostic that an auditor is asked to trust can have its
dependency list read in full in under a minute.

## What a reviewer should check

1. `go.mod`'s direct block has not grown. If it has, the pull request says why,
   and the answer is not "it was convenient".
2. `go.sum` changed only in the ways the `go.mod` diff implies.
3. `make all` is green, which includes `govulncheck` and the advisory scan.
4. No build tag or environment variable disables `GOSUMDB` or `GOFLAGS`
   verification anywhere in CI.

## Why there is no KEYS.asc

Release signing is keyless: cosign with an OIDC workflow identity. There is
no long-lived key to publish, so the thing to verify is the certificate's
workflow identity rather than a fingerprint. `pkg/VERIFY.md` has the exact
command and the expected identity.
