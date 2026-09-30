---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How passmcp discover finds MCP endpoints among hosts the operator names, what counts as proof, and what it will not do.
---

# Discovery

`passmcp discover` answers one question for an operator: which of the hosts
I run are serving MCP, and which of those answer anyone who asks? It
probes the targets you name, proves each endpoint it finds with a cited
request, and flags the ones that list their tools without credentials.

```sh
passmcp discover --targets targets.txt
passmcp discover --from-config ~/.cursor/mcp.json --validate --report-dir out
passmcp discover --targets targets.txt --state discovery-state.json --output sarif
```

## Explicit targets only

Discovery is not a scanner. It contacts the hosts you list and nothing
else, which is the same line [ADR 0008](adr/0008-no-adversarial-mode.md)
draws for the rest of passmcp: the tool checks what its operator owns, and
does not reach for what nobody named.

- A targets file names single hosts. A CIDR range (`10.0.0.0/24`,
  `2001:db8::/32`), a wildcard (`*.example`) or a non-HTTP scheme is
  rejected with the file and line, and the run does not start.
- Every request goes through a scoped transport. A request to a host
  that is not a target is refused before it is sent, so it is neither
  sent nor recorded; the host is listed under "blocked" in the output.
- Redirects are followed only within the scope, and at most three times.
  A redirect to another host stops at the redirect.
- A URL found in a well-known document is probed only when it is on the
  same host. A document that points somewhere else is a pointer to a
  host you did not name: it is not followed, and the host is listed as
  blocked.
- Default ports are the same host: `https://a.example` and
  `https://a.example:443` are one target.

## Sources

Targets come from sources you name, and each endpoint records every
source that led to it.

| Flag | Reads | Notes |
|---|---|---|
| `--targets FILE` | one hostname, `host:port` or URL per line | `#` comments and blank lines ignored; a bare name is `https` |
| `--from-config FILE` | an MCP client configuration | Claude Desktop and Cursor (`mcpServers`), VS Code (`servers`, `mcp.servers`), Zed (`context_servers`); comments and trailing commas are accepted. Servers started as programs are skipped. |
| `--from-gateway FILE` | an agentgateway or Obot configuration | every absolute `http(s)` URL in the file |
| `--from-registry NS` | the MCP Registry at `--registry-url` | only servers named `NS/…`, and `NS` must have at least three labels (`io.github.example`) |

Every flag repeats. A source file is read as text, and only URLs are
kept from it.

**Gateway limitation.** Gateway files are scanned for absolute URLs
rather than parsed, which keeps a YAML parser out of the module's
dependencies and treats both formats alike. A backend written as
separate host, port and path fields is not found; list it as a URL, or
put it in a targets file.

**Registry scope.** The registry's search is a substring match, so
discovery keeps only servers whose name starts with your namespace and
refuses a namespace broad enough to list other publishers' servers.

## What is probed

On each target, discovery tries these paths in turn:

| Path | Role |
|---|---|
| `/mcp` | Streamable HTTP endpoint |
| `/sse` | legacy HTTP+SSE endpoint |
| `/.well-known/mcp` | a document that may point at an endpoint |
| `/.well-known/mcp/server-card.json` | a Server Card, which may point at an endpoint |

A target given as a URL with a path is tried at that path first. The
Server Card location is still a draft in the MCP specification; if it
moves, `--paths` replaces the whole list without a release.

## What counts as an endpoint

An answer counts only when it is MCP:

- an `initialize` result that carries a `protocolVersion` or
  `serverInfo`; or
- a `server/discover` result, for a stateless server that does not use a
  session.

The request that showed it is cited as `req#N` and can be found in
`telemetry.ndjson`. A well-known document is never proof on its own: it
is a pointer, and the endpoint it names still has to answer. An HTTP 200
with some other body is not an endpoint.

An endpoint that answers `401` is listed as protected, with the
`resource_metadata` URL from its challenge when it gives one.

**Exposed without authentication.** After a handshake, discovery sends
one `tools/list` with no credentials. If it returns a tools array, the
endpoint is reported as `critical: exposed without authentication`,
citing that request. Discovery never calls a tool.

## Validation and the graph

`--validate` runs the full read-only check against each endpoint found,
with no credentials and the default policy
([ADR 0004](adr/0004-read-only-by-default.md)): only tools annotated
`readOnlyHint: true` are ever invoked. Each run writes an attestation to
`<report-dir>/attestations/`, or to `passmcp-discovery/attestations/`
without `--report-dir`, and the endpoint's entry carries its score,
grade and failing check IDs. A check that could not run is recorded on
its endpoint with the error; it does not stop the others.

`--graph DIR` records the result in a passmcp-graph store: a server node
per endpoint, linked to a node for each source that named it, to its
attestation, and to the tools it exposes. Applying the same result twice
changes nothing.

## State between runs

`--state FILE` compares this run with the last one and then saves it.
Each endpoint is marked `new` or `seen`, with the time it was first
seen. An endpoint from the state file that did not answer is reported as
`disappeared`, but only when its host was probed in this run; an
endpoint on a host you left out this time is kept, not reported.

## Pacing

`--rps` (default 2, at most 100) caps requests per second across the
whole run, and `--concurrency` (default 4, at most 64) caps targets
probed at once. `--rps 0` turns the cap off. `--timeout` bounds each request.

## Output

Stdout carries the format chosen with `--output`; progress goes to
stderr.

| Format | Content |
|---|---|
| `text` | one line per endpoint, then protected, disappeared and blocked hosts |
| `json` | the full result: targets, endpoints with sources and proof, protected, disappeared, blocked |
| `sarif` | SARIF 2.1.0 with rules `discovery.endpoint`, `discovery.exposed_without_auth` and `discovery.disappeared` |

`--report-dir DIR` also writes `discovery.json`, `discovery.sarif` and
`telemetry.ndjson`, the request log the `req#N` citations point into.

Discovery results are not check findings: they do not appear in
[the check reference](checks.md) and are not scored. The score belongs
to `--validate`, which runs the ordinary check.

## Exit status

| Code | Meaning |
|---|---|
| 0 | discovery ran and no endpoint is exposed without authentication |
| 1 | discovery could not run: a bad flag, an unreadable source, a range in a targets file |
| 2 | at least one endpoint is exposed without authentication |
