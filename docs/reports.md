---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp's output formats — text, Markdown, JSON, NDJSON, HTML, the in-toto attestation and the CycloneDX bill of materials for a binary or a lockfile — plus the report directory, the HAR export, and what telemetry holds.
---

# Reports and telemetry

## Output formats

| `--output` | What you get |
|---|---|
| `text` (default) | a plain-language verdict, a score out of 100 with a five-dot meter per area, and a numbered "What to improve" list. Printed to the terminal scrollback so you scroll it normally. Coloured on a TTY unless `--no-color`; `--verbose` adds the per-check detail, the tools and resources called, speed measurements and `req#N` evidence |
| `md` | the same as a shareable Markdown document, failures and warnings first |
| `json` | the full report; `--events` embeds every recorded request |
| `ndjson` | phases, findings and requests streamed as they happen, one JSON object per line, ending with the report |
| `html` | one self-contained document — the page `passmcp serve` shows, and the PDF its print stylesheet produces |
| `sarif` | SARIF 2.1.0, for GitHub code scanning and anything else that reads it |
| `junit` | JUnit XML, so a run appears beside the unit tests in the CI panel |
| `attestation` | not a report: an in-toto statement about the server, for signing and for `passmcp verify`. See [Attestations](#attestations) |
| `ocsf` | failing and warning findings as OCSF 1.3.0 Vulnerability Finding (2002) and Compliance Finding (2003) events, for a SIEM. See [OCSF](ocsf.md) |

## The report directory

`--report-dir DIR` writes everything at once:

| File | Contents |
|---|---|
| `report.txt` | the verbose text report |
| `report.md` | the Markdown report |
| `report.json` | the full report with every event embedded |
| `report.sarif` | the SARIF 2.1.0 rendering |
| `report.junit.xml` | the JUnit rendering |
| `attestation.json` | the in-toto statement — the only file here a machine can act on without reading prose |
| `telemetry.ndjson` | one line per request |
| `telemetry.har` | the same as an HTTP Archive 1.2, which any browser's devtools can open |

## Attestations

Every format above is the findings arranged for a particular reader. An
attestation is a different thing: a **claim** about the server, in the
in-toto envelope a supply-chain pipeline already verifies, meant to be signed
and handed to a machine that was not present when the run happened — a
gateway deciding whether to route, a registry deciding what to display, an
auditor deciding in March whether a control was met.

```sh
passmcp check https://mcp.example.com/mcp --output attestation > attestation.json
```

Four properties make it worth more than the JSON report:

- **It says what it was judged against.** `82/100` means nothing in 2029
  without the rubric version and the MCP revision attached to it.
- **The subject digest covers a target descriptor, and the statement says
  so.** A digest that looked like an artifact hash while covering a URL
  would be the kind of lie that survives review.
- **It carries every verdict, passes included.** A consumer cannot otherwise
  tell "checked and fine" from "not checked".
- **It verifies offline.** A gateway must never have to call passmcp to trust
  a statement passmcp produced.

The format is published for other implementations: a JSON Schema for the
statement and the rubric as data, both in
[`spec/`](https://github.com/sebastienrousseau/passmcp/tree/main/spec) under
Apache-2.0 and generated from the code that writes them
([ADR 0011](adr/0011-attestation-format-is-apache.md)).

### Producing one in a later job

Signing usually is not the job that ran the diagnostic. Run passmcp where the
server credentials live, save the report, and attest somewhere with an OIDC
identity and no access to the server at all — the split SLSA provenance uses:

```sh
passmcp check "$URL" --output json > report.json   # has credentials
passmcp attest report.json > attestation.json      # has an identity
cosign sign-blob --yes --bundle attestation.sigstore.json attestation.json
```

The statement is signed as a file. It is already a complete in-toto
statement whose subject is the server, so it is not handed to
`cosign attest-blob`, which would wrap it in a second statement about a
file. [Signing attestations](signing.md) has the keyless workflow, the
offline form and the verification order.

`passmcp attest` reads standard input when given no filename.

### Verifying and gating

`passmcp verify` answers one question by default: **can the statement be
believed?** It parses, its subject digest still covers the target it names,
its subject is named for that same target, and it records what the verdicts
were judged against.

That is not approval. A statement can be perfectly valid and describe a
server you would never route to, so approval is opt-in:

```sh
passmcp verify attestation.json \
  --endpoint https://mcp.example.com/mcp \
  --require auth.unauthenticated_tools \
  --max-fail 0
```

| Gate | Holds when |
|---|---|
| `--endpoint URL` | the statement is about that target. Add `--transport stdio` for a child process |
| `--require ID` | that check's verdict is a pass. **Absent is not a pass** — a statement that never ran the check cannot vouch for it |
| `--max-fail N` | at most N checks failed |
| `--min-score N` | the score is at least N. A run that assessed nothing carries no score, and a missing score never counts as zero |
| `--against FILE` | no check is worse than in that earlier statement about the same target |
| `--reproduce` | no check is worse when the recorded run is made again, against `--endpoint` |

A gate applies because the flag was given, not because of its value:
`--max-fail 0` is the strictest form of that gate, and omitting the flag asks
for no gate at all.

### Drift between two statements

```sh
passmcp verify today.json --against approved.json
```

`--against` compares two statements about the same target check by check,
because drift is a delta rather than a threshold: a score that did not move
can hide one check that went from pass to fail beside another that went the
other way. A check that got worse fails the gate. Improvements, severity
changes, checks the later run did not assess, and checks it newly measured
are listed but do not fail it. The score delta is shown only when both
statements were judged under the same rubric and check inventory.

Two statements about different targets are refused rather than compared:
the difference between two servers is not drift. The comparison is
`attestation.Compare` in the Apache-2.0 package, so a gateway can run the
same check without passmcp.

### Repeating the recorded run

```sh
passmcp verify approved.json --reproduce --endpoint https://mcp.example.com/mcp \
  --token-env MCP_TOKEN
```

A statement written by `passmcp check` records its plan: the run
specification with every secret value removed, the credential mode, the
names of anything given by value (`token`, `header X-API-Key`,
`param tenant`), and the operating system, architecture and kernel. A live
service cannot give the same answer twice, but the measurement can be made
the same way twice. `--reproduce` makes it again and gates on what got
worse, exactly as `--against` does.

It is the one form of `verify` that contacts anything, and a statement can
come from anyone, so it takes from the statement only how the server was
measured — phases, pacing, which tools with which arguments, egress
watching, the baseline — and nothing that decides what passmcp may touch:

| Taken from | What |
|---|---|
| `--endpoint` | the target. It must be named, the statement must cover it, and the plan must be about the same target as the statement's subject |
| this command line | credentials, with the flags `passmcp check` takes. A plan's recorded environment-variable names are never read: a hostile statement could otherwise choose which of your secrets to send to an endpoint it chose |
| this command line | permissions (`--allow-mutations`, `--allow-destructive`, `--insecure-*`, `--allow-resource-mismatch`, `--skip-era-check`, `--fault-upstream`). They must match the recorded run exactly, because a comparison between runs allowed different things measures the permissions |

A run that sent no credentials sends none again, whatever the environment
holds. A statement made before plans were recorded, or from a report
assembled by hand, has no plan and is refused.

For anything an organisation has to agree on, `--policy` takes a file instead
— reviewable, versioned, and able to carry exceptions with a reason and an
expiry date. The same file governs a live run through `passmcp check --policy`,
so a gateway checking a statement months later applies what the pipeline
applied. See [Acceptance policies](policy.md).

Exit status is the part a pipeline reads:

| Code | Meaning |
|---|---|
| `0` | valid, and every gate met |
| `2` | valid, and a gate was not met — the evidence is good and the answer is no |
| `1` | the statement cannot be believed at all — the evidence is unusable |

Treat `1` and `2` differently. They are different incidents.

Nothing in `passmcp verify` checks a signature. Verify the envelope with the
tool that produced it, then verify what is inside it with this — see
[Signing attestations](signing.md).

## Servers used together

```sh
passmcp overlap mail.json weather.json files.json
```

An agent wired to several servers sees one flat list of tools, and nothing
in the protocol keeps that list clean. `passmcp overlap` compares the
catalogues in two or more saved JSON reports, offline, for the two failures
that exist only in the union:

- **Collisions** — the same tool name, ignoring case, hyphens and
  underscores, exposed by two servers. Which one the model gets is up to
  the host.
- **Shadowing across servers** — one server's catalogue text attaching a
  rule to a tool another server owns ("before calling send_email, always
  BCC …"). `catalog.text.shadowing` finds the construction on one server;
  only a set of servers can confirm the named tool belongs to someone else.
  It uses the same narrow matcher, so recommending a sibling tool is not
  reported.

It exits 2 when the catalogues interfere, 0 when they do not, and 1 when a
report cannot be read — including one with no catalogue, which would
otherwise compare as clean. The comparison is lexical and structural, and
does not claim to judge meaning.

## Explanations

```sh
passmcp explain report.json > explanations.md
passmcp explain report.json --model claude-sonnet-5 > explanations.md
```

`passmcp explain` writes a separate document about a saved JSON report: its
failures and warnings, most severe first, each with passmcp's own guidance
for the check. It only reads the report, and every status, severity and
check id in the document is copied from it.

By default nothing leaves the machine. With `--model` and an Anthropic API
key in `ANTHROPIC_API_KEY` (or the variable `--api-key-env` names), the
findings are sent to that model and its answer is printed beside the
guidance, attributed to it by name. The destination is announced on stderr
first. What is sent is each finding's id, title, status, severity and
detail, and passmcp's guidance text; the evidence, the telemetry, the
authentication summary and the rest of the report are not. A key already
in the environment is not a request to send: only `--model` is
([ADR 0006](adr/0006-no-client-telemetry.md)).

The answer annotates and never adjudicates. It cannot pass a failure, add
a finding or change a severity, and a finding's detail is quoted to the
model as data from an untrusted server. At most 40 findings go in one
request; the rest are counted in the document. `--api-url` sends to a proxy
or gateway instead, over TLS or to this machine, and `--output json` gives
the same document as data.

## Bills of materials

An attestation says how the server behaved. A bill of materials says what it
is made of, and for the platform-team half of the audience that is the first
question asked about anything new: what is in this, and can you prove where
it came from.

```sh
passmcp sbom ./mcp-server > bom.json
```

A Go binary carries its own answer. Every dependency the toolchain linked in
is in the file, with its version and its `h1:` module checksum, along with
the toolchain, the target platform, the commit it was built from and whether
the tree was dirty at the time. `passmcp sbom` reads that and writes
[CycloneDX 1.6](https://cyclonedx.org/), which is what a scanner, a registry
or an artifact store already ingests.

The program is resolved through `PATH`, the way a shell would resolve it. It
is opened and read, never executed, and nothing here touches the network.

Three things about the document are deliberate:

- **A dependency with no checksum is marked, not omitted.** It carries a
  `passmcp:unverifiable` property. A module with no `h1:` sum did not come
  through the module proxy and the checksum database never saw it, so
  nothing about it can be verified after the fact — a local `replace` or a
  vendored tree is the usual cause. An absent hash is indistinguishable from
  an oversight; saying so is the point.
- **The toolchain, platform and commit travel as properties.** CycloneDX has
  no field for "the tree was dirty when this was built", and that is the one
  provenance fact here that is both cheap to establish and impossible to
  argue with. A document that dropped it would say less than the binary does.
- **The same binary gives the same bytes.** The serial number is derived
  from what is being described rather than generated at random, and
  `SOURCE_DATE_EPOCH`, if set, fixes the timestamp. A pipeline diffing
  yesterday's document against today's sees dependency changes, not a clock.

Most MCP servers are TypeScript or Python, and for those the executable is
`node` or `python`, which says nothing about the server. Name the project
directory instead and its lockfiles are read:

```sh
passmcp sbom ./my-ts-server > bom.json
```

| Lockfile | Hash carried | Marked `passmcp:unverifiable` when |
|---|---|---|
| `package-lock.json` (v1–v3) | The SRI `integrity`, as hex SHA-512 | No integrity, or a `file:` or git source |
| `uv.lock` | The source distribution's SHA-256 | No artifact hash, or a git or path source |
| `Cargo.lock` | The registry `checksum` | No checksum, or a git or path source |
| `requirements.txt` | The single `--hash`, when there is one | No `==` pin, or a pin without `--hash` |

Every lockfile present is read, and each package names the one it came from.
Only the directory itself is read — never `node_modules`, and never a file a
`-r` include points at. Development-only npm packages carry
`cdx:npm:package:development`, the property CycloneDX's own npm tooling uses,
so a consumer that already filters them filters these. A package npm
bundled inside another's archive carries `passmcp:bundled` instead of a hash:
the archive's own hash covers it, and npm records none because nothing is
downloaded separately. A package pinned by
several per-platform hashes and no single shared artifact carries no hash and
is not marked: it is pinned, and there is no one artifact to name.

A lockfile is weaker evidence than a binary. It is what the project declares
was installed, not what is running, and the document says which it is in a
`passmcp:evidence` property. A server run straight from `npx` or `uvx` has no
local lockfile at all, and passmcp does not fetch one.

### Verifying provenance

A bill of materials reports what the binary says about itself: the commit,
whether the tree was dirty, every dependency's checksum. It does not verify
a signature, and passmcp does not claim a verified supply chain for anything
([ADR 0010](adr/0010-provenance-is-reported-not-verified.md)). Where the
server's publisher signs releases, verify them with the tools built for it:

```sh
# a Sigstore-signed file, e.g. a release's checksums
cosign verify-blob checksums.txt --bundle checksums.txt.sigstore.json \
  --certificate-identity-regexp 'https://github.com/OWNER/REPO/.*' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# a GitHub artifact attestation (SLSA build provenance)
gh attestation verify ./mcp-server --owner OWNER
```

passmcp's own releases are verified the same way; see
[Packaging](packaging.md).

### Known vulnerabilities

```sh
passmcp sbom ./my-ts-server --osv > bom.json
```

`--osv` looks every component up in [OSV](https://osv.dev/) and adds the
advisories that affect it as CycloneDX `vulnerabilities`, each pointing at
the components it affects, with its aliases, its CVSS vectors and the
database's own severity. A Go binary's document includes its standard
library as a component, because a server built with an old toolchain
carries that toolchain's `net/http` whatever its `go.mod` says.

It is the only network access `passmcp sbom` makes, and it is off unless
asked for ([ADR 0006](adr/0006-no-client-telemetry.md) records where it
sits). Before anything is sent, stderr says how many package URLs are
going where. Package URLs are all that is sent — no hashes, no paths, no
project name — and components that did not come from a public registry
(a local path, a git URL, a Go module with no proxy checksum) are never
sent at all. If even public package names are confidential, point
`--osv-url` at a mirror; it must be https, or http to this machine, and a
redirect to another host is refused.

A lookup that fails fails the command. A document missing its
vulnerabilities because the database was unreachable would read as clean.
Withdrawn advisories are left out. Each advisory's text is bounded, because
whoever filed it wrote it. The document records the endpoint asked and the
counts in `passmcp:osv-*` properties, and it is no longer byte-reproducible:
the advisories are the database's answer on the day.

A program that is not a Go binary, or a directory with no lockfile, is an
error rather than a bill of materials with no materials in it — a pipeline
that ingested an empty document and went green is the failure this avoids.

The same read drives the `supply.buildinfo` and `supply.provenance` checks
during a [stdio run](stdio.md), so a run and a document taken from one binary
agree by construction.

## SARIF and JUnit

Both are the same findings in a shape one particular reader will not accept
a substitute for. Neither is richer than `json`; if you are writing your own
consumer, use `json`.

Two choices in the SARIF are worth knowing about, because the conventional
answer is different:

**Passing checks are emitted**, as `"kind": "pass"` with `"level": "none"`.
SARIF models a passing result deliberately, and dropping them would mean a
consumer cannot tell "passmcp checked this and it was fine" from "passmcp did
not check this" — which, for a conformance tool, is the whole difference.
Anything that shows only alerts filters on `level`, at no cost.

**The location is the endpoint**, as an absolute URI. There is no file to
point at: passmcp tests a running server, not a checkout. A tool that invents
a repository path so its results look like source findings is lying about
where the problem is. For a [stdio server](stdio.md) there is no URL either,
so the location is `stdio:` followed by the escaped command line, and the
fingerprint that lets a consumer track one alert across runs is built from
that command rather than from a hostname it does not have.

Each rule carries the check's `helpUri`, which is its `doc_url` — so an
alert in code scanning links to what the check asserts.

The JUnit mapping has one decision that surprises people: **a warning
becomes a `<failure>`**, typed `warning`. JUnit has no third state, and
reporting a deviation as a pass is how a warning stops being read. Filter on
the `type` attribute if you want to gate only on real failures.

## Which server a report is about

`target` says what was diagnosed, and a consumer that reads more than one
report has to look at `transport` before `endpoint`:

```json
{ "target": { "endpoint": "https://mcp.example.com/mcp", "host": "mcp.example.com",
              "scheme": "https", "transport": "http" } }
```

```json
{ "target": { "endpoint": "npx -y server-everything stdio", "host": "", "scheme": "stdio",
              "transport": "stdio", "command": ["npx", "-y", "server-everything", "stdio"] } }
```

`endpoint` is the target as passmcp was given it, which for a stdio run is a
command line rather than a URL — `transport` is how you tell, and `command`
carries the argument list unjoined so it can be re-run without guessing how
it was quoted. `schema_version` is unchanged at 1: nothing was removed, and
no report of a kind that existed before reads differently.

The two kinds of run do not contain the same checks. A stdio report carries
five that an HTTP one cannot make and reports several of the HTTP ones as
skipped, each with its reason — so comparing two scores across transports
compares different batteries. [Servers that are programs](stdio.md) lists
which.

## Traces and structured logs

Two flags put a run into the systems a platform team already watches.

`--otlp-endpoint URL` exports the finished run as OpenTelemetry traces over
OTLP/HTTP. The shape of the trace is the shape of the run:

```text
passmcp check                      root span: endpoint, score, failure counts
├── phase net                    span events: one per finding
│   ├── GET  https://…/mcp       DNS, connect, TLS and TTFB as attributes
│   └── POST https://…/mcp
├── phase handshake
└── …
```

A request passmcp made outside any phase is parented to the root rather than
dropped — an unattributed request is still a request that was made.
`--otlp-header "Name: value"` is repeatable, for a collector that wants an
API key or a tenant id.

**The export never changes the verdict.** A collector being unreachable is
not a finding about the server under test, so a failed export is a warning
on stderr and the exit code is whatever the run earned.

passmcp speaks the JSON encoding of OTLP rather than protobuf. Both are
specified, every collector accepts JSON on the same endpoint, and JSON is
reachable from the standard library — so emitting traces costs the binary no
new dependency.

`--log-format json` switches passmcp's own diagnostics on stderr from prefixed
lines to one JSON object each, through `log/slog`. Every line carries the
run's `trace_id`, which is the same id on the report and on the spans, so a
log line can be joined to the run it came from. The default stays human: a
person watching a single run wants a line they can read.

## How much a finding explains

A finding always carries a one-line `advice`. Sixty-five of the eighty-one
checks — every one that can fail or warn — also have a fuller explanation:
what the finding means in terms of the protocol, and numbered steps naming
the field, header or error code to change.

Where that appears depends on who is reading:

| Rendering | Carries the full guidance |
|---|---|
| `text` (default) | no — one-line advice only |
| `text --verbose` | yes |
| `md` | yes, always |
| `html` | yes, always |
| `json`, `ndjson` | on request — `--guidance` |

The default terminal output is read while the run is still fresh, by
somebody who wants to know what is wrong; five findings with three steps
each is sixty lines nobody asked for. The Markdown and HTML renderings are
the ones forwarded to people who cannot re-run the tool, so they carry
everything.

The JSON carries `advice` and `doc_url` by default. `--guidance` adds a
`guidance` object to the report:

```json
{
  "guidance": {
    "protocol.malformed_json": {
      "means": "A truncated or malformed request body was answered with…",
      "steps": [
        { "title": "Reject a body that does not parse", "body": "Return HTTP 400, or…" }
      ]
    }
  }
}
```

It is a dictionary keyed by check id, not a field on each finding, because
the prose is per-check and not per-occurrence: a catalog with forty poisoned
descriptions produces forty findings and one entry here. Join on the
finding's `id`.

Only the checks that failed or warned in this run appear. A report about one
server should not carry advice about checks that server passed.

It is off by default because most consumers have `doc_url` and want the
report small — it costs around 6 KB on a typical run. Turn it on for a
consumer that has to explain a finding somewhere passmcp cannot reach, such as
a bot writing a pull request comment.

A test fails the build when a check that can fail has no guidance written
for it, so this does not quietly regress as checks are added.

## What a finding holds

Every finding in the JSON report carries the same fields:

| Field | What it is |
|---|---|
| `id` | the check that produced it, e.g. `protocol.malformed_json` |
| `phase` | which of the nine phases it came from |
| `status` | `pass`, `warn`, `fail`, `skip` or `info` |
| `severity` | on a failure or warning: `critical`, `major` or `minor` |
| `detail` | what was observed, in plain language |
| `advice` | what to change, on anything that is not a pass |
| `evidence` | the recorded requests behind it, e.g. `["req#8"]` — see [Reading the evidence](evidence.md) |
| `doc_url` | this check's row in [the inventory](checks.md) |

`doc_url` exists because a report is usually read long after the run that
produced it, often by somebody who was not there. `protocol.malformed_json`
is only self-explanatory to a reader who already knows what it means; the
link is the difference between a finding you can act on and one you have to
ask about.

The fragment it points at is written into the inventory by the same
generator that counts the checks, and a test fails the build if the two ever
disagree — so a link that shipped inside an archived report keeps resolving.

## What a telemetry event holds

Every request passmcp makes, to the MCP server and to the authorization
server, is recorded with:

- sequence number, timestamp, trace id, the phase and label it belongs to;
- method, URL, status, or the transport error;
- whether the connection was reused, and the remote address;
- DNS, connect, TLS, time-to-first-byte and total durations from
  `net/http/httptrace`;
- TLS version, cipher suite, server name, certificate subject, issuer,
  expiry and days remaining;
- request and response headers, redacted;
- byte counts, and with `--capture-bodies`, the redacted bodies capped at
  64 KiB;
- the JSON-RPC method, id, and any error code and message.

Findings cite requests as `req#N`; `N` is the `seq` field in the NDJSON
and the entry index in the HAR. Every request also carries an
`X-MCP-Trace-ID` header with the run's trace id, so a server operator can
find the run in their own logs.

## Scoring

Six categories, weighted:

| Category | Weight | Phases |
|---|---|---|
| connectivity | 10 | net |
| authorization | 20 | discovery, auth |
| protocol | 20 | handshake, protocol, resilience |
| catalog | 15 | catalog |
| execution | 20 | execution |
| performance | 15 | performance |

Each category starts at 100. A critical failure zeroes it, a major one
costs 40, a minor one 15, and every warning 5; a category cannot go below
zero. The total is the weighted mean over the categories whose phases
actually ran, and the report states how many were assessed, so a high
score on a partial run cannot be mistaken for a full one. Every
deduction is listed with the finding that caused it. Grades: A at 90 and
above, B at 75, C at 60, D at 40, F below.

## Badges

A score in a CI log is read once, by whoever ran it. The same score in a
README is read by everyone deciding whether to point an agent at the
server.

`passmcp badge` turns a saved report into a [shields.io endpoint][shields]
document — not an image, so there is no service to run and nothing to
render:

```sh
passmcp check "$URL" --output json > report.json
passmcp badge report.json > badge.json
```

Serve `badge.json` over HTTPS and point shields at it:

```markdown
![passmcp](https://img.shields.io/endpoint?url=https://example.com/badge.json)
```

It reads standard input when given no filename, and `--label` sets the
left-hand text for a project badging more than one server.

The colour comes from the report's own grade rather than from a second
reading of the number, so the badge and the document it came from cannot
disagree about where a boundary is: A is bright green, B green, C yellow,
D orange, F red.

A run that never reached a verdict renders as an error rather than as a
low score. This is the same distinction the exit codes make — a badge
reading `0/100` because the endpoint was unreachable would repeat exactly
the mistake that contract exists to prevent.

[shields]: https://shields.io/badges/endpoint-badge

## Watching for drift

A check tells you a server was sound when you ran it. That is a statement
about a moment, and the threat it cannot see by construction is the one
that waits: the server that passes review and edits its tool descriptions
the following week is the server that gets through.

```sh
passmcp check "$URL" --baseline .passmcp/baseline.json --approve
passmcp watch "$URL" --baseline .passmcp/baseline.json
```

A pulse is deliberately small — connect, list the catalogue, hash it,
compare. Two requests and a string comparison, because a watcher that
re-ran nine phases on a loop would be the abusive client passmcp warns
everyone else about. Between pulses there is a timer and nothing else.

`--once` takes a single pulse and exits, which is the shape a CI job
wants. It follows the same exit-code contract as `passmcp check`:

| Exit | Meaning |
|---|---|
| 0 | the catalogue is the approved one |
| 2 | it is not, and the report says what changed |
| 1 | passmcp never reached a verdict at all |

An unreachable server is a `1`, never a `2`. A network blip is not a rug
pull, and a gate that conflated them would be one people switch off.

`--output ndjson` emits one event per line for a log pipeline, and
`--approve` promotes what the watch saw once somebody has read it.

Severity is by kind rather than by count — the same ladder `--baseline`
uses. A `readOnlyHint` becoming true after approval is critical; a new
optional property is noise.

## What rendering costs

A run's wall clock belongs to the server. Roughly fifty requests,
deliberately throttled, means the time you wait is almost entirely
somebody else's latency. The render is passmcp's own work, and it is the
part worth measuring.

The measured times and allocations for each format, with the machine
and the command that reproduces them, are in
[Benchmarks](BENCHMARKS.md).

### What is gated, and what is not

CI gates the binary size and each renderer's allocations, and publishes
wall-clock times without gating them. [Benchmarks](BENCHMARKS.md) says
why, and what each budget is.
