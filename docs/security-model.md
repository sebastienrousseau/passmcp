---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp's security model and assurance case: the trust boundary, the threat model, structural redaction, and what each release guarantees.
---

# passmcp — Security Model & Assurance Case

**Status:** Living document. Last full review: 2026-09-11.
**Owner:** Sebastien Rousseau ([@sebastienrousseau](https://github.com/sebastienrousseau)).
**Scope:** the `passmcp` binary, the library packages it is built on, the
release pipeline that produces its artefacts, and the on-disk state it
keeps (the token store and any report directory).

This document is passmcp's **assurance case**: a structured argument that the
project is secure to a stated level, with the evidence that backs each
claim. It is deliberately narrower and more explicit than a marketing-style
"security policy". Reviewers, packagers, and downstream users should be
able to read this document and understand *what passmcp protects*, *what it
does not protect*, *what could go wrong*, and *what compensating controls
exist*.

---

## 1. What passmcp is

passmcp is a Go command-line tool that connects to a remote Model Context
Protocol server the way an agent would — with credentials an operator
supplies — and reports, step by step, what it observed. It makes real
requests: OAuth discovery and token exchange, the MCP handshake, catalog
listing, tool invocations, resource reads, prompt renders, repeated and
parallel calls.

It is:

- A **client** of the server under test. It never listens on the network
  except for the loopback redirect that `passmcp login` opens for the
  duration of one authorization.
- A **holder of credentials** for the duration of a run, and of a user
  token between runs when `passmcp login` was used.
- A **writer of reports** that describe a server in detail and can, with
  `--capture-bodies`, include what it returned.

## 2. Trust boundaries

passmcp operates across four trust boundaries:

| # | Boundary                                | Direction | What crosses it                                                        |
|---|-----------------------------------------|-----------|------------------------------------------------------------------------|
| 1 | Operator's shell → `passmcp` process      | in        | CLI flags, `PASSMCP_*` environment, the config file, the token store     |
| 2 | `passmcp` → authorization server          | out       | metadata fetches, registration, token requests carrying client secrets |
| 3 | `passmcp` → MCP server                    | out/in    | JSON-RPC over HTTPS with a bearer token; every byte of the reply is untrusted |
| 4 | `passmcp` → report directory and stdout   | out       | findings, catalog, telemetry, optionally captured bodies               |

The threat model is about **limiting blast radius**: passmcp runs with
credentials the operator chose against servers the operator chose. It
cannot make a server safe; it can make sure that running it does not leak
the credential, does not damage the server's data, and does not let the
server's output reach the report unbounded.

## 3. Security properties (claims)

We claim the following properties. Each is followed by the evidence.

### C1. No credential reaches the report, the telemetry, or the logs

**Argument.** Every HTTP exchange passes through one recorder
(`internal/telemetry`), and every operator-supplied secret is registered
with its redactor before the client is built. The redactor masks by
header name, by URL and form parameter name, and structurally inside JSON
bodies, where it also registers the values it finds — so a token issued in
the middle of a run is masked in every later event. Content types are not
trusted; a body that starts with `{` is treated as JSON. The stderr
banner and the report's credential summary print the *source* of each
credential (flag, environment variable, profile, store), never its value.

**Evidence.**

- `probe.Run` calls `Recorder.Redactor.Add` for every value in
  `creds.Credentials.Secrets()` before constructing the client.
- `internal/telemetry/recorder_test.go` asserts that `Authorization`,
  `X-Api-Key` and `Set-Cookie` are masked, that a registered secret in a
  request body is masked, that `code=` in a query string is masked, and
  that the HAR export contains no secret.
- `TestFullRunClientCredentials` in `internal/probe` serialises every
  recorded event after a full nine-phase run and fails if the operator's
  client secret, the dynamically registered client secret or any issued
  access token appears.
- `internal/creds/creds_test.go` asserts `Describe()` leaks no secret.
- The token store is written `0600` in a `0700` directory, atomically
  (`internal/creds/store.go`).

### C2. Unauthenticated probes are actually unauthenticated

**Argument.** The client's transport chain adds the operator's bearer
token, fixed headers and basic credentials to every request. Two checks —
first contact, and the invalid-token rejection probe — only mean something
if they arrive with none of those. A second transport to the same
endpoint, carrying nothing but the trace header, exists for them.

**Evidence.** `Session.Bare` in `internal/probe/probe.go`;
`TestServerAcceptingGarbageTokenIsCritical` fails a server that answers
200 to a made-up token even when the operator supplied a valid one.
[ADR-0001](adr/0001-bare-transport-for-unauthenticated-probes.md).

### C3. passmcp does not mutate the server under test unless told to

**Argument.** `diagnostics.Policy` decides what may be invoked. By
default only tools declaring `readOnlyHint: true` run. A tool without
annotations is destructive under the MCP specification's defaults and is
skipped. `--allow-mutations` unlocks tools that declare
`destructiveHint: false`; `--allow-destructive` unlocks everything and is
documented as dangerous. Resources are read and prompts rendered, both
of which the specification defines as non-mutating. Requests are throttled
to `--rps` (default 2) including the parallel burst, unless `--allow-load`
is passed.

**Evidence.** `TestPolicyDefaults` in `diagnostics`; the fake server in
`internal/probe/fake_test.go` panics if its unannotated `delete_all` tool
is called, and every probe test runs under the default policy.
[ADR-0004](adr/0004-read-only-by-default.md).

There is no adversarial mode to enable: no flag or command sends
exploit-shaped input to a server's tools
([ADR-0008](adr/0008-no-adversarial-mode.md)). What passmcp sends is protocol
conformance probes, calls permitted by the policy above, and one request
with an invalid token.

### C4. Server output cannot flood or corrupt the report

**Argument.** Every string the server chooses — tool names, descriptions,
error text, content — is bounded before it enters a finding, and response
bodies are capped at 1 MiB on the raw transport and at `BodyCap` (64 KiB)
in captured telemetry. Findings never embed server text unescaped into
the Markdown renderer's table cells.

**Evidence.** `truncate` in `internal/probe`; `io.LimitReader` in
`transport.Streamable.Do`; `Recorder.BodyCap`; `esc` in
`internal/report/render_md.go`.

### C5. The release artefacts you download are the artefacts we built

**Argument.** Every release is built by a GitHub-hosted runner from a
semantic-version tag, signed keylessly with cosign (Sigstore), and
accompanied by a SLSA build provenance attestation and a CycloneDX SBOM,
all published together to the same GitHub Release.

**Evidence.** `.github/workflows/release.yml` and `.goreleaser.yaml`;
every action is SHA-pinned per OpenSSF Scorecard `Pinned-Dependencies`.

### C6. The parsing boundaries are fuzzed

**Argument.** Every byte of a `WWW-Authenticate` header, an SSE stream or a
tool's JSON Schema comes from the server under test. The parsers for
each are fuzz targets run on every push.

**Evidence.** `FuzzParseWWWAuthenticate` (`auth`), `FuzzReadSSE`
(`transport`), `FuzzValidate` and `FuzzArguments` (`diagnostics`),
driven by `scripts/fuzz.sh` and `.github/workflows/fuzz.yml`.

## 4. Threats considered and out of scope

### In scope

- **Credential in a report shared with a third party**: mitigated by C1.
  `--capture-bodies` is off by default because a server's own response
  content is not passmcp's to redact.
- **A server that accepts any token** looking healthy: mitigated by C2;
  reported as a critical finding.
- **Running passmcp against production and deleting something**: mitigated
  by C3.
- **Hostile server output** (oversized bodies, injected Markdown, control
  characters in tool names): mitigated by C4.
- **Supply chain against release**: mitigated by SHA-pinned actions,
  cosign and SLSA (C5).
- **Dependency compromise**: mitigated by Dependabot on `go.mod`,
  `govulncheck` in CI, and a two-dependency module; `go.sum` locks
  transitive hashes.

### Out of scope

- **A server that logs the credentials passmcp sends.** Boundary 2 and 3
  are the operator's choice; passmcp cannot prevent the far side from
  recording what it was sent.
- **Compromise of the maintainer's laptop or GitHub account.** The
  maintainer's account is the root of trust; if it is compromised, a
  malicious release could be signed and shipped. Sigstore's Rekor
  transparency log makes such a release publicly auditable after the
  fact but does not prevent it. Users concerned about this scenario
  should pin to a specific release tag and checksum.
- **A malicious config file or token store on the operator's machine.**
  Both are read with the operator's own permissions; an attacker who can
  write them can already run commands as the operator.
- **Denial of service against the server under test.** The throttle and
  the bounded burst are there to avoid it by accident; `--allow-load`
  removes the throttle on purpose and is the operator's decision.
- **Rate-limit exhaustion of the operator's own quota** on a shared
  authorization server.
- **Injection and request-forgery testing of the server's tools.** passmcp
  contains no adversarial probes and will not
  ([ADR-0008](adr/0008-no-adversarial-mode.md)). That testing belongs to
  dedicated security tooling under a scoped, authorised engagement.

## 5. Assumptions

- The credentials the operator supplies are scoped to the server under
  test. passmcp requests the scope the server's challenge names, or what
  `--scope` says, and nothing broader.
- The operator's clock is roughly correct (needed for TLS validation and
  token expiry arithmetic).
- The operator runs a supported OS: recent Linux, macOS ≥ 14, or
  Windows 11.
- A report directory is treated with the same care as the server's own
  responses when `--capture-bodies` is on.

## 6. Compensating controls (bus factor + solo maintainer)

passmcp has a single maintainer. This is a real risk to sustained security
response. Mitigations:

- **Public assurance case (this doc)**: a successor maintainer or
  reviewing packager can pick up where the current maintainer left off
  without back-channel context.
- **Documented signing key location**: `MAINTAINERS.md` records where the
  release-signing key is published; a successor can publish a new key
  and users can reason about the transition.
- **Documented external services**: `MAINTAINERS.md` catalogues every
  external account (organisation, ghcr.io, Homebrew tap, AUR) so
  continuity is auditable rather than tribal.
- **Fork-and-continue is explicit**: GPL-3.0 licensing + the six-month
  unresponsive-maintainer clause in `GOVERNANCE.md` normalise the
  community-fork path.

## 7. Review and update

This document is re-reviewed on every release that touches:

- Any file in `internal/telemetry/`, `internal/creds/`, `auth/` or
  `transport/`.
- Any change to `diagnostics.Policy`.
- Any file in `.github/workflows/`.
- Any new dependency.

Otherwise it is re-reviewed annually.

If you have questions or believe a claim above is not adequately
supported by the linked evidence, please file a security advisory per
[SECURITY.md](https://github.com/sebastienrousseau/passmcp/blob/main/SECURITY.md).
