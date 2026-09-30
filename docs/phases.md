---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  The nine phases of a passmcp run, in order — what each one probes on an MCP server, and how its findings turn into a score.
---

# The nine phases

Phases run in order. Each returns findings with a status (`pass`, `warn`,
`fail`, `skip`, `info`), a severity on failures (`critical`, `major`,
`minor`), what was observed, advice, and evidence: the range of recorded
requests that produced it (`req#12-14`). A phase that finds the server
unreachable, or credentials missing for a protected server, blocks every
later phase; they are recorded as skipped with the reason.

Run a subset with `--phases net,discovery,auth` or leave one out with
`--skip-phases performance`.

A server that is a program rather than a URL runs the same phases, but two
of them have no subject over a pipe and two are replaced by checks about the
process instead. [Servers that are programs](stdio.md) has the details, and
every check a stdio run does not make appears in its report as skipped, by
id, with the reason.

## net: Network and TLS

No MCP traffic yet.

| Finding | Checks |
|---|---|
| `net.scheme` | https; plain http to a non-loopback host is critical |
| `net.dns` | the hostname resolves |
| `net.tcp` | a TCP connection opens |
| `net.tls` | the handshake completes and the certificate verifies; passmcp never skips verification |
| `net.tls.version` | TLS 1.3, warning on 1.2 |
| `net.tls.cert` | not expired; warning inside 14 days |

Over stdio there is nothing to resolve, connect to or verify, so this phase
asks the question those checks were really asking — is the thing on the
other end there — with `stdio.process` and `stdio.environment` instead.

## discovery: Authorization discovery

First contact is made with a bare transport carrying no credentials of
any kind, even when you supplied some, so the server's own enforcement is
what is observed.

| Finding | Checks |
|---|---|
| `discovery.first_contact` | 200 means open; 401 means protected; 403 or anything else is a deviation. A 4xx followed by a `GET` whose first event is `endpoint` is named as the 2024-11-05 HTTP+SSE transport ([below](#older-revisions)) |
| `discovery.creds_unused` | warns when credentials were supplied to an open server |
| `discovery.challenge` | a `WWW-Authenticate: Bearer` challenge with `resource_metadata` |
| `discovery.prm` | RFC 9728 protected-resource metadata: the hint, then the path-aware and root well-known locations |
| `discovery.prm.resource` | the PRM's `resource` matches the endpoint |
| `discovery.as` | RFC 8414 or OpenID discovery for each listed authorization server |
| `discovery.as.https`, `discovery.as.pkce`, `discovery.as.grants` | TLS on the authorization server, S256 advertised, grant types |
| `discovery.registration` | Client ID Metadata Documents or dynamic registration offered |
| `discovery.dpop` | DPoP (RFC 9449) as the metadata and the 401 describe it: asymmetric proof algorithms only; a resource that requires bound tokens names algorithms at its authorization server and a `DPoP` challenge. Read, not exercised; absence is info while MCP's profile is a draft |
| `discovery.enterprise_managed` | the Enterprise-Managed Authorization grant profile (ID-JAG): when advertised, `grant_types_supported` must include the JWT bearer grant it is presented with. Read, not exercised |
| `discovery.override` | discovery bypassed because `--token-url` was given |

## auth: Credentials and token

| Finding | Checks |
|---|---|
| `auth.mode`, `auth.source.*` | which mode is in use and where each credential came from |
| `auth.registration` | how the client identity was obtained: cimd, static or dcr |
| `auth.token` | the token was obtained (or loaded from the store); a failed exchange names the OAuth error |
| `auth.token.type`, `auth.token.expiry`, `auth.token.scope` | `token_type` is Bearer, `expires_in` is present and not tiny, granted scope covers what was requested |
| `auth.rejects_garbage` | a made-up bearer token is answered with 401 and a challenge; a 2xx here is critical |

## handshake: MCP initialize handshake

| Finding | Checks |
|---|---|
| `handshake.initialize` | initialize succeeds with the credentials |
| `handshake.protocol_version` | the negotiated version: the newest passes, `2025-06-18` and `2025-03-26` are information, `2024-11-05` is a warning ([below](#older-revisions)) |
| `handshake.server_info` | name and version populated |
| `handshake.capabilities` | tools, resources, prompts, logging declared |
| `handshake.instructions` | server instructions present |
| `handshake.session` | an `Mcp-Session-Id` was issued (stateless servers are noted, not penalised) |

### Older revisions

passmcp offers the newest handshake revision it speaks, `2025-11-25`, and
accepts any of `2025-06-18`, `2025-03-26` and `2024-11-05` in answer, as the
specification's version negotiation allows. A server on an older revision
is graded rather than refused, and a check about a field its revision does
not have is skipped with the revision named, rather than passed on the
absence or failed for it:

| Introduced in | What | Checks skipped on an earlier revision |
|---|---|---|
| `2025-03-26` | tool annotations | `catalog.tools.annotations`, `catalog.tools.annotation_honesty`, `catalog.tools.idempotency` |
| `2025-06-18` | structured tool output (`outputSchema`, `structuredContent`) | `catalog.tools.output_schema`, and `execution.content` unless a call returned an empty result, which is a violation on any revision |

`2024-11-05` is a warning on `handshake.protocol_version` rather than
information, because what it lacks is what a cautious client acts on. It
predates tool annotations, so nothing separates a read-only tool from a
destructive one, and the execution phase invokes no tool under the default
policy ([ADR-0004](adr/0004-read-only-by-default.md)): `execution.tools` is
skipped and says so. `--allow-mutations` does not change that, because it
adds only tools that declare `destructiveHint: false`; `--allow-destructive`
does, and belongs only where the tools are known to be safe to call.

Over a pipe, that is the whole difference. Over HTTP there is a second
one: the transport of `2024-11-05` was HTTP+SSE, which Streamable HTTP
replaced in `2025-03-26` and which passmcp does not implement. A server
that answers a Streamable HTTP `POST` and negotiates `2024-11-05` is run
like any other. A server that refuses the `POST` with a 4xx and opens an
event stream on `GET` whose first event is `endpoint` is on the old
transport: `discovery.first_contact` fails and names it, and the run stops
there. If the server can also run as a program, `passmcp check --stdio`
checks it.

## protocol: Protocol conformance

Deliberately unusual requests, checked against what JSON-RPC 2.0 and the
MCP specification require.

| Finding | Checks |
|---|---|
| `protocol.mrtr` | whether a request for client input can be answered: every `inputRequests` entry has a method and a correlation id. Emitted from the execution phase, where the observations exist |
| `protocol.extensions` | the extensions `server/discover` advertises, separated into the specification's own and an author's, with their identifiers checked for reverse-DNS shape |
| `protocol.deprecated_features` | whether a server on `2026-07-28` still answers `initialize` and `ping`, and whether `supportedVersions` says it means to |
| `protocol.ping` | ping answers |
| `protocol.unknown_method` | an unknown method returns JSON-RPC -32601, not an HTTP error |
| `protocol.id_echo` | the response id matches the request id and `jsonrpc` is "2.0" |
| `protocol.malformed_json` | a truncated body is refused with 400 or -32700 |
| `protocol.invalid_params` | `tools/call` without a name is refused |
| `protocol.unknown_tool` | calling a tool that does not exist is reported, not answered with success |
| `protocol.accept_header`, `protocol.get_stream` | informational: strictness about `Accept`, and whether GET opens a server event stream |
| `protocol.bogus_session` | a session id the server never issued is rejected |
| `protocol.version_header` | a bad `MCP-Protocol-Version` is rejected |
| `protocol.tasks.unknown_id`, `protocol.tasks.capability` | for a server advertising the Tasks extension: an unknown task id gets -32602, and a client that did not declare the extension gets -32021 |
| `protocol.tasks.undeclared` | no task is returned to a call that did not declare the extension |
| `protocol.tasks.lifecycle` | a task created by calling a read-only tool is retrievable at once, carries the required fields, reaches a terminal state within 30 seconds and keeps it; passmcp cancels any task it does not see finish |
| `protocol.origin` | a request from a foreign `Origin` is refused, as the transport requires against DNS rebinding; failing on loopback or a private address, a warning on a public host |
| `protocol.notification_ack` | the `notifications/initialized` the handshake sent was answered `202 Accepted` with no body, as the transport requires; judged from that recorded exchange, with no extra request. Skipped on `2026-07-28`, which has no handshake |

## catalog: Tool, resource and prompt catalog

Lists everything; invokes nothing.

| Finding | Checks |
|---|---|
| `catalog.tools.list`, `catalog.resources.list`, `catalog.prompts.list` | each list succeeds when its capability is declared, and nothing lists without one |
| `catalog.tools.unique` | tool names are unique |
| `catalog.tools.descriptions` | every tool has a description of at least 20 characters |
| `catalog.tools.input_schema` | `inputSchema` describes an object |
| `catalog.tools.annotations` | tools declare `readOnlyHint`/`destructiveHint`; unannotated tools are treated as destructive |
| `catalog.tools.idempotency` | information: which state-changing tools declare `idempotentHint`, and which leave it at the specification's default of "not safe to repeat"; a read-only tool declaring it is not idempotent is a warning |
| `catalog.tools.output_schema` | tools declare `outputSchema` |
| `catalog.resources.uris`, `catalog.resources.mime`, `catalog.resources.templates` | absolute URIs, mime types, template listing |
| `catalog.prompts.descriptions` | prompts and their arguments are described |
| `catalog.empty` | critical when there are no tools, resources or prompts at all |
| `catalog.text.hidden` | invisible characters and bidirectional overrides in any catalog text |
| `catalog.text.comments` | HTML comments, which a rendered catalog hides and a model reads |
| `catalog.text.instructions` | text addressed to the model rather than describing the tool |
| `catalog.text.secret_paths` | descriptions naming SSH keys, AWS credentials, dotenv files or credential environment variables |
| `catalog.names.confusable` | a name mixing scripts, which is how one tool is made to render like another |

### What the last five are about

A tool description is not documentation. It is input to the model, read
before the model decides what to call, with the same standing as the user's
own words. Everything above this point asks whether the catalog is *well
formed*; these five ask whether it is *honest*.

They read every string that reaches the model, not just the ones a catalog
viewer renders: tool and resource descriptions and titles, prompt argument
descriptions, and every `description` and `title` inside an `inputSchema` or
`outputSchema`. The schema is where published poisoning has most often been
found, for the obvious reason — it is the part nobody looks at.

Severity is calibrated deliberately, because a scanner people learn to
ignore is worse than none:

| Severity | What earns it |
|---|---|
| `critical` | text with no honest reading — telling the reader to disregard earlier instructions, to conceal something from the user, to act as a different agent; a bidirectional override; a mixed-script name |
| `major` | text a legitimate author very rarely writes and should be told about anyway — a reference to the system prompt, a pseudo-tag like `<IMPORTANT>`, a named credential path, an HTML comment |
| `minor` | worth a reader's attention, not worth a failed build — a dotenv path, a description directing the model's behaviour |

Each finding names the field it came from and quotes it, with invisible
characters rendered as their code points, because "an instruction was found"
is not something a maintainer can act on and `…<U+202E>nothing…` is.

## execution: Safe execution and content validation

| Finding | Checks |
|---|---|
| `execution.policy` | the policy in force |
| `execution.tools` | each permitted tool invoked with generated arguments (or yours, via `--arg tool.field=value`); protocol errors and timeouts fail, `isError` results are reported honestly |
| `execution.content` | `structuredContent` validates against `outputSchema`; a declared schema with no structured content is a violation |
| `execution.validation` | each tool with required arguments is called once more with one omitted, and must reject the call |
| `execution.resources` | up to `--max-resources` resources read; failures and empty reads reported |
| `execution.prompts` | up to `--max-prompts` prompts rendered with placeholder arguments |

## performance: Latency and concurrency

| Finding | Checks |
|---|---|
| `performance.ping` | `--samples` pings: p50, p95, max |
| `performance.tools` | tools that succeeded, repeated `--samples` times — all of them up to ten, otherwise the five slowest plus five picked by a seed from the target, so two runs repeat the same tools; p95 above 2 s warns |
| `performance.warmup` | a first call far slower than the median |
| `performance.concurrency` | `--concurrency` workers × `--samples` calls on the fastest tool; errors fail, 429 without `Retry-After` warns |
| `performance.throttle`, `performance.rate_limit` | whether the burst was throttled by passmcp, and with `--allow-load`, whether the server rate-limited it |

Every timed call passes through passmcp's recorder, because a finding has to
cite the request it came from. Its cost was measured on loopback, where it is
not hidden by the network: indistinguishable from noise for a 200-byte
answer, about 0.1 ms at 20 KB, and about 1.2 ms at 500 KB. Against a real
server, whose round trip is tens of milliseconds, that is inside the
spread of the samples. passmcp keeps the recorder on rather than publish
latency figures it cannot cite.

## resilience: Session and token recovery

| Finding | Checks |
|---|---|
| `resilience.session_reinit` | with the session id replaced by garbage, the client sees a 404, re-initializes, and the next call succeeds |
| `resilience.token_refresh` | with the cached token invalidated, the next call obtains a fresh one and succeeds |

A pipe has neither a session to lose nor a token to renew — the connection
*is* the session. What this phase asks over stdio instead is whether the
process survived the run (`stdio.alive`), whether it kept the transport
clean (`stdio.stdout_clean`), and what it logged on the way
(`stdio.stderr`). Those run even when an earlier phase blocked the rest,
because a server that stopped answering is exactly when they are the
findings that explain everything else.

It also reports what the server did after its handshake, on Linux, from
samples of its process group under `/proc` taken while every other phase
ran. Whatever was open when the handshake completed is bootstrap and is
not reported; after it, the only reason to act is a request passmcp sent.

| Finding | Reports |
|---|---|
| `stdio.post_init_connections` | a socket to a non-loopback address that did not go through passmcp's proxy; a warning |
| `stdio.post_init_writes` | a file open for writing outside the working directory, passmcp's scratch home and `/dev`, `/proc`, `/sys`; a warning |
| `stdio.post_init_processes` | processes started in the server's group; information |

These are samples, taken every 100 ms, and each finding says so: a
connection opened and closed between two samples is not seen, so seeing
nothing is information, never a pass. The roadmap asked for a sandbox that
snaps shut at the handshake; that cannot be built from outside, because
Landlock and seccomp are restrictions a process applies to itself.
Off Linux the three are skipped by name.

With `--soak N`, the run asks the one question fifty requests cannot: does
the server's memory settle, or does every call leave something behind? The
fastest tool that succeeded in the execution phase is called `N` more times
in sequence, paced by `--rps` like every other call, and the resident
memory of the server's process group is read from `/proc` after each. The
first tenth of the samples is dropped as warm-up — a runtime that grows its
heap for a few dozen calls and then holds is behaving well — and a
least-squares line is fitted through the rest.

| Finding | Checks |
|---|---|
| `resilience.soak_memory` | the line through resident memory against call number is not a leak: it explains less than 60% of the variation, or adds up to less than sixteen mebibytes and less than a quarter of where the window started, or has flattened over the last quarter of the window. A line that fits, adds up and is still rising fails as major, as does a server that stops answering or exits part way through |

The measurement is the slope, not the peak: a collector's sawtooth has a
slope and no fit, a warm-up has a fit and no slope after the cut, and a
heap that is settling flattens before the end. The floor is high on
purpose: a runtime growing its heap towards its first collection rises in
a straight line for as long as the window is shorter than one collection
cycle, and a rise of a few mebibytes cannot be told from that ramp by its
shape. The numbers are in the finding either way. It
needs at least 100 calls, a program to run (the memory read is of a process
passmcp started, so `--soak` without `--stdio` is refused), and Linux to read
it on; elsewhere it is skipped by name. At the default pacing a thousand
calls take about eight minutes; `--rps 0` removes the throttle for a server
you own.

With `--fault-upstream`, the run ends by asking what an agent sees when a
server's dependency is down. The proxy `--watch-egress` points the server
at (the flag implies it) holds every new connection open without answering,
as a hung upstream would, and up to three tools that succeeded earlier are
called again with the same arguments. Only a call during which the server
tried to connect counts.

| Finding | Checks |
|---|---|
| `resilience.upstream_down` | a call whose upstream never answers comes back — an error, `isError`, or an answer from a cache — within the call timeout. One that does not come back, or a server that exits, fails as major |

It is off by default, because it is the one part of a run that makes the
server's world worse on purpose, and it needs a program to run: an endpoint
passmcp did not start cannot be pointed at the proxy, so `--fault-upstream`
without `--stdio` is refused rather than silently skipped.
