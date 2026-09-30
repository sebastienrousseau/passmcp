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
is passed, and neither the rate nor the burst can be raised without
bound: `--rps` above 100 or `--concurrency` above 64 is refused before a
run starts (`engine.ValidatePace`).

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
the Markdown renderer's table cells. Every rendering meant for a person
(the text and Markdown reports, the live TUI and tool selector, the
human diagnostic format, and the text output of `call`, `read`,
`prompt` and `watch`) removes ANSI escape sequences and C0 and C1
control characters from server text before it reaches a terminal, so a
tool name or an error string cannot move the cursor, retitle the window
or write to the clipboard. The machine renderings (JSON, NDJSON, SARIF,
HAR, structured diagnostics) keep the server's text exactly: their
encoders escape control characters, and a consumer of them is owed what
the server sent.

**Evidence.** `truncate` in `internal/probe`; `io.LimitReader` in
`transport.Streamable.Do`; `Recorder.BodyCap`; `esc` in
`internal/report/render_md.go`; `internal/termsafe`, with
`TestTextAndMarkdownNeutraliseTerminalSequences`,
`TestRunViewNeutralisesServerText`, `TestSelectorNeutralisesToolNames`,
`TestHumanFormatNeutralisesTerminalSequences` and
`TestTextOutputsNeutraliseServerText`.

### C5. The release artefacts you download are the artefacts we built

**Argument.** Every release is built by a GitHub-hosted runner from a
semantic-version tag, signed keylessly with cosign (Sigstore), and
accompanied by a SLSA build provenance attestation and a CycloneDX SBOM,
all published together to the same GitHub Release.

**Evidence.** `.github/workflows/release.yml` and `.goreleaser.yaml`;
every action is SHA-pinned per OpenSSF Scorecard `Pinned-Dependencies`.

### C6. The parsing boundaries are fuzzed

**Argument.** Every byte of a `WWW-Authenticate` header, an SSE stream or a
tool's JSON Schema comes from the server under test, and so do the tool
names and arguments passmcp encodes into MCP parameter headers. The
parsers for each, and that encoder, are fuzz targets run on every push.

**Evidence.** `FuzzParseWWWAuthenticate` (`auth`), `FuzzReadSSE` and
`FuzzHeaderValue` (`transport`), `FuzzValidate` and `FuzzArguments`
(`diagnostics`),
`FuzzSchemaValid` (`internal/probe`), `FuzzParse`
(`internal/clientconf`) and `FuzzString` (`internal/termsafe`, the
terminal-sequence filter every person-facing rendering of server text
passes through), driven by `scripts/fuzz.sh` and
`.github/workflows/fuzz.yml`.

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
  `govulncheck` in CI, library packages that import only the standard
  library, and every direct dependency listed in `SBOM.md` and checked
  against `go.mod` in CI; `go.sum` locks transitive hashes.

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
  external account (GitHub repository, ghcr.io, Homebrew tap, AUR) so
  continuity is auditable rather than tribal.
- **Fork-and-continue is explicit**: GPL-3.0 licensing + the six-month
  unresponsive-maintainer clause in `GOVERNANCE.md` normalise the
  community-fork path.

## 7. Secure design principles

The claims in section 3 hold because the design follows the principles
Saltzer and Schroeder set out in *The Protection of Information in
Computer Systems* (1975). This section is the argument that each one was
applied, with the code that applies it and the test that would fail if
it stopped being true.

### Economy of mechanism

Each security decision is made in one small place, so there is one place
to review.

- **One recorder.** Every HTTP exchange passes through
  `telemetry.Recorder.Wrap`, and redaction happens there and nowhere else
  ([ADR-0003](adr/0003-structural-redaction-at-the-recorder.md)).
- **One invocation policy.** `diagnostics.Policy.Decide` is a single
  function of about twenty lines that answers "may this tool run".
- **One engine for three surfaces.** The CLI, the TUI and the web shell
  build a `RunSpec` for the same `internal/engine`;
  `TestEveryRunFlagHasASpecField` (`cmd/parity_test.go`) fails when a
  flag configures a run outside it.
- **Few moving parts on the wire.** The library packages (`passmcp`,
  `auth`, `transport`, `diagnostics`) import only the standard library.
  The JSON Schema validator is hand-rolled rather than a dependency, and
  fuzzed (`FuzzValidate`, `FuzzSchemaValid`).

### Fail-safe defaults

Access is decided by permission, not exclusion: the zero value of every
guard is the strict one, and an unknown case is refused.

- **Tools.** A zero `diagnostics.Policy` invokes only tools that declare
  `readOnlyHint: true`; a tool without annotations is destructive, as the
  MCP specification's default says (`TestPolicyDefaults`,
  [ADR-0004](adr/0004-read-only-by-default.md)).
- **Discovered URLs.** A zero `auth.URLPolicy` requires HTTPS and a
  public address; the overrides are opt-in flags
  (`TestURLPolicyRejectsPlaintextAndInternalHosts`,
  `TestURLPolicyEscapeHatches`).
- **Credentials.** A nil `auth.OriginSet` allows no origin at all.
- **TLS.** A failed handshake is a critical finding that stops the run;
  passmcp does not retry without verification (`tlsFindings` in
  `internal/probe/phase_net.go`).
- **Blocked runs.** When a phase sets `Session.blocked`, every later
  phase is recorded as skipped with the reason, never passed.
- **The hosted diagnostic.** `passmcp serve --public` scans only an
  allowlist it was started with, and a missing allowlist admits nothing
  (`TestAllowlistNilIsClosed`,
  [ADR-0005](adr/0005-public-mode-is-the-same-binary.md)).
- **The token store.** On Unix a store readable by group or others is
  refused rather than read (`TestStoreRefusesWorldReadableFile`).

### Complete mediation

Every access is checked, every time, not once per run.

- Every request goes through `Recorder.Wrap`, so no request escapes
  redaction.
- Every credentialed request is checked against the allowed origins
  (`auth.Transport.mayCredential`), and every redirect hop again by
  `auth.CheckRedirect`, capped at `auth.MaxRedirects` (5)
  (`TestBearerDoesNotFollowRedirectOffOrigin`,
  `TestRedirectLeakIsRefused`).
- Every URL a server advertises is checked by `URLPolicy.Validate`
  before use, and every connection is checked again at dial time by
  `URLPolicy.DialContext`, which dials only the addresses it checked, so
  a DNS answer that changes between the two is still caught
  (`TestDialContextRefusesAnyNonPublicAnswer`,
  `TestAnAuthorizationServerThatRebindsIsNeverReached`). Each layer fails
  closed on its own: `Validate` refuses a name that does not resolve
  rather than leaving it to the dial
  (`TestURLPolicyFailsClosedWhenANameDoesNotResolve`). The exception is a
  run behind a proxy from the environment, where the proxy resolves names
  and the connection goes only to it
  (`TestURLPolicyDefersToAProxyThatResolves`); passmcp cannot see which
  address the proxy then reaches.
- Every web shell request is checked for the per-run token and for its
  origin (`TestGuards`).

### Open design

Nothing in passmcp's security depends on its design being secret. The
source is GPL-3.0, the reasoning is in the
[decision records](adr/README.md) and this document, and a release can be
rebuilt bit for bit from its tag ([packaging.md](packaging.md)). The only
secrets are the operator's credentials and the web shell's per-run
token.

### Separation of privilege

Where one condition could be forged or mistaken, two are required.

- **A mutating tool** runs only when the tool declares
  `destructiveHint: false` **and** the operator passes
  `--allow-mutations`. Either alone is not enough
  (`diagnostics.Policy.Decide`).
- **A web shell request** needs the per-run token **and** a same-origin
  `Origin` (`TestGuards`).
- **A program started from the browser** needs `--allow-stdio` on the
  command line, and public mode refuses it whatever is passed
  (`TestBrowserCannotStartAProgram`, `TestAllowStdioIsWhatPermitsIt`,
  `TestPublicModeNeverRunsAProgram`).

### Least privilege

Each part gets what its task needs and nothing more.

- **On the server under test**, passmcp reads by default and throttles
  to `--rps` (claim C3).
- **At the authorization server**, it requests the scope the challenge
  names, or what `--scope` says (section 5).
- **A stdio server** does not inherit passmcp's environment; a variable
  it needs is passed by name with `--stdio-env`
  (`TestStdioEnvIsNotInherited`, `TestStdioPassEnvForwardsByName`).
- **In CI**, every workflow sets its default token permissions to none
  or read-only and grants write scopes per job, only where a job
  publishes, signs or attests (`.github/workflows/`).

### Least common mechanism

The mechanism that carries credentials is not shared with the checks
that must run without them. The first-contact and invalid-token probes
use `Session.Bare`, a second transport that carries only the trace
header, so the bearer round-tripper cannot add the operator's token to
them (`TestServerAcceptingGarbageTokenIsCritical`,
[ADR-0001](adr/0001-bare-transport-for-unauthenticated-probes.md)).

### Psychological acceptability

The safe path is the one with no flags, and a refusal says how to
proceed deliberately. A discovered endpoint on a private address is
refused with the flag that allows it (`--insecure-allow-private-hosts`);
an insecure token store is refused with the `chmod 600` that fixes it
(`creds.ErrInsecurePermissions`). The flags that weaken a default say so
in their names: `--insecure-allow-http-auth`,
`--insecure-allow-private-hosts`, `--allow-destructive`.

## 8. Common weaknesses countered

The weaknesses below are the ones from MITRE's
[CWE](https://cwe.mitre.org/) list that apply to a network client
holding credentials and reading hostile input. Each row names the
countermeasure and the evidence for it.

| Weakness | How passmcp counters it | Evidence |
|---|---|---|
| **CWE-918** Server-side request forgery: a server steering passmcp's requests | URLs a server advertises (resource metadata, authorization servers, token, authorization and registration endpoints, an A2A `jku`) must be HTTPS and resolve to public addresses; the check is repeated at dial time against DNS rebinding; credentials never follow a redirect off the allowed origins | `auth.URLPolicy`, `auth.OriginSet`, `auth.CheckRedirect`; `TestValidateMetadataChecksEveryEndpoint`, `TestDialContextConnectsToTheAddressesItChecked`, `TestAnAuthorizationServerThatRebindsIsNeverReached`, `TestCheckRedirect` |
| **CWE-200**, **CWE-532** Exposure of credentials, including in logs | Structural redaction at the one recorder, of every registered secret and every token seen mid-run; credential sources, never values, in banners; `explain --curl` emits placeholders; keyring secrets never reach a command line; the token store is `0600` in a `0700` directory | Claim C1; `TestFullRunClientCredentials`, `TestSecretsNeverSerialise`, `FuzzCredentialRedaction`, `TestCurlNeverCarriesASecret`, `TestKeychainSetKeepsSecretOutOfArgv`, `TestReportMasksReflectedSecrets` |
| **CWE-522** Insufficiently protected credentials in transit | OAuth endpoints must be HTTPS unless `--insecure-allow-http-auth`; plain HTTP to a non-loopback MCP endpoint is a critical finding | `auth.URLPolicy`; `phaseNet` in `internal/probe/phase_net.go` |
| **CWE-295** Improper certificate validation | TLS uses Go's standard verification everywhere; nothing outside tests sets `InsecureSkipVerify`; a failed handshake stops the run, and an expired certificate is critical | `tlsFindings`, `certWindowFinding`; `TestCertificateFailureIsReportedAgainstA824WithItsRequest` |
| **CWE-400**, **CWE-770** Uncontrolled resource consumption | Response bodies capped (32 MiB, and 1 MiB for OAuth documents), SSE streams capped in bytes and events, schema recursion bounded at depth 64, pagination stops on a cursor cycle, telemetry bounded in events and body size, requests throttled to `--rps`, which is itself capped at 100 with `--concurrency` capped at 64, `watch` pulses no faster than every 30 s, a library client without a timeout of its own abandons a request after 60 s without progress | `transport.MaxResponseBytes`, `MaxStreamEvents`, `diagnostics.MaxSchemaDepth`, `Recorder.BodyCap`, `engine.ValidatePace`, `transport.IdleTimeout`; `TestValidateBoundsThePace`, `TestDefaultClientDoesNotWaitForeverOnASilentServer`, `TestIdleTimeoutKeepsAStreamThatMakesProgress`, `TestResponseBodyIsBounded`, `TestStreamEventsAreBounded`, `TestValidateDepthIsBounded`, `TestRecursiveRefTerminates`, `TestListToolsStopsOnACursorCycle`, `TestRecorderIsBounded`, `TestProbeSurvivesHostileServers`, `TestRunRefusesAnImpoliteInterval` |
| **CWE-20** Improper input validation | Every server-sent structure is parsed defensively, and the parsers of server bytes are fuzzed: `WWW-Authenticate`, SSE, JSON Schema, client configuration; run specifications are validated before a run; fleet names are restricted to a safe pattern | `engine.RunSpec.Validate`; `FuzzParseWWWAuthenticate`, `FuzzReadSSE`, `FuzzHeaderValue`, `FuzzValidate`, `FuzzSchemaValid`, `FuzzParse`, `FuzzRunSpecJSON`; `TestValidate`, `TestParseRefusesInlineSecretsAndMistakes` |
| **CWE-117** Improper output neutralization for logs | A finding's detail is collapsed to one line before it is recorded, so server text cannot forge a line in the text report or a log; structured logs are JSON-encoded; Markdown table cells are escaped; the HTML report is rendered through `html/template` and fuzzed; hidden bidi and zero-width characters are shown as code points in poisoning excerpts | `oneLine` and `truncate` in `internal/probe`, `esc` in `internal/report/render_md.go`, `diagnostics.visible`; `FuzzHTMLEscaping`, `TestHTMLEscapesHostileCatalog`, `TestScanTextFindsHiddenCharacters` |
| **CWE-150** Improper neutralization of escape, meta or control sequences | Server text written for a person (text and Markdown reports, TUI, human diagnostics, `call`/`read`/`prompt`/`watch` text) has ANSI escape sequences and C0/C1 control characters removed at the renderer; machine formats stay faithful and are escaped by their encoders | `internal/termsafe`; `TestStringRemovesControlSequences`, `TestTextAndMarkdownNeutraliseTerminalSequences`, `TestTextOutputsNeutraliseServerText` |
| **CWE-78**, **CWE-88** OS command and argument injection | No shell is ever invoked; a stdio server is executed as named with its arguments as given; keyring keys are encoded before they reach a helper; the web shell cannot start a program unless `--allow-stdio` is passed | `transport/stdio.go`, `internal/creds/keyring.go`; `TestKeyNeverEscapesTheCommand`, `TestAHostileKeyCannotReachTheShell`, `TestBrowserCannotStartAProgram` |
| **CWE-352**, **CWE-346** Cross-site request forgery and origin validation | `passmcp login` binds its redirect listener to `127.0.0.1`, checks `state` in constant time, always uses PKCE S256 and refuses a server that advertises PKCE methods without it, and checks the RFC 9207 `iss`; authorization server metadata must name, exactly, the issuer it was fetched for (RFC 8414 §3.3); the web shell requires its per-run token and a same-origin request | `auth.NewPKCE`, `auth.NewState`, `checkIssuer` in `client.go`, `auth.IssuerMismatchError`; `TestLoginWrongState`, `TestLoginRejectsMixUpIssuer`, `TestAuthorizationCodeFlow`, `TestDiscoverServerRequiresTheIssuerItAskedFor`, `TestAuthorizationServerNamingAnotherIssuerBlocks`, `TestGuards`, `TestRemoteBindRefused` |
| **CWE-22** Path traversal | Report files have fixed names inside the operator's directory; names derived from data are hashes (discovery) or must match a safe pattern (fleet) | `engine.Result.WriteDir`, `safeName` in `internal/fleet/file.go`; `TestParseRefusesInlineSecretsAndMistakes` |
| **CWE-798** Hard-coded credentials | No credential is compiled in; every one comes from the operator. Gitleaks scans every push to `main`, every pull request and, weekly, the whole history | `.github/workflows/secret-scan.yml` |
| **CWE-494** Download of code without integrity check | Release artefacts carry SHA-256 checksums, keyless cosign signatures and SLSA provenance, and rebuild bit for bit | Claim C5; [pkg/VERIFY.md](https://github.com/sebastienrousseau/passmcp/blob/main/pkg/VERIFY.md), [packaging.md](packaging.md) |

## 9. Review and update

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
