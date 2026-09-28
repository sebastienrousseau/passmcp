---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  How to follow a passmcp finding back to the exact request that produced it, using the wire log, the HAR export and the recorded timings.
---

# Reading the evidence

Every finding passmcp reports cites the request that produced it. This page is
about following that citation — opening the wire log, finding the exchange,
and reading what actually crossed the network.

It matters more than it sounds. An independent audit in 2026 put false
positives from pattern-matching MCP scanners at roughly four in five. The
answer to "is this finding real?" should not be "the tool said so".

## What a run writes

Point `--report-dir` at a directory and a run leaves seven files:

```sh
passmcp check https://mcp.example.com/mcp --report-dir ./passmcp-report
```

| File | What it is |
|---|---|
| `report.json` | The verdict, machine-readable. Findings, scores, phases, counts. |
| `report.txt` | The same thing for a terminal. |
| `report.md` | The same thing for a pull request comment or a ticket. |
| `report.html` | The document you print to PDF and hand to somebody. |
| `index.html` | The report again, as the directory's landing page. |
| `telemetry.ndjson` | One JSON object per request, in order. |
| `telemetry.har` | The same exchanges in HAR 1.2, for a tool that speaks it. |

The two telemetry files are the evidence. The reports are the argument.

## Following a finding to its request

A finding in `report.json` carries the sequence numbers of the requests
behind it:

```json
{
  "id": "protocol.unknown_tool",
  "status": "fail",
  "title": "Unknown tool is reported",
  "detail": "calling a non-existent tool returned success",
  "requests": [31]
}
```

`31` is the `seq` field in the NDJSON stream. One line, one request:

```sh
jq 'select(.seq == 31)' passmcp-report/telemetry.ndjson
```

```json
{
  "seq": 31,
  "phase": "protocol",
  "label": "unknown tool",
  "method": "POST",
  "url": "https://mcp.example.com/mcp",
  "status": 200,
  "rpc": { "method": "tools/call", "id": 31 },
  "timings": { "dns": 0, "connect": 1200000, "tls": 8100000, "ttfb": 21400000, "total": 21900000 },
  "request_headers": { "Authorization": "Bearer ***", "Content-Type": "application/json" },
  "response_headers": { "Content-Type": "application/json" },
  "request_bytes": 118,
  "response_bytes": 64,
  "trace_id": "fdc8741d05c3ed6a703ac9c5a124d086"
}
```

That is the whole basis of the finding: a `tools/call` for a tool that does
not exist, answered `200` with a result rather than `-32602`. You can
disagree with the verdict, but not with the exchange.

### Timings are nanoseconds in NDJSON

`timings` values are `time.Duration`, so nanoseconds. The `_ms` fields in
`report.json` are milliseconds. They are different units on purpose: the
stream is machine-facing, the report is not.

## Reading the HAR

`telemetry.har` is HAR 1.2, which means Chrome DevTools, Firefox, Charles,
Insomnia and Postman will all open it. Drag it onto the Network panel with
"Preserve log" on.

The structure is the standard one:

```text
log
├── version    "1.2"
├── creator    { name: "passmcp", version: … }
└── entries[]
    ├── startedDateTime
    ├── time              total, milliseconds
    ├── request           method, url, headers, postData
    ├── response          status, headers, content
    ├── serverIPAddress
    ├── timings           blocked, dns, connect, ssl, send, wait, receive
    └── comment           the phase and label, so an entry says why it happened
```

The `comment` field is worth knowing about: HAR has nowhere to record *why*
a request was made, so passmcp puts the phase and the check's label there. In
DevTools it shows on the entry; with `jq` it is one field:

```sh
jq -r '.log.entries[] | "\(.comment)\t\(.response.status)\t\(.time)ms"' \
  passmcp-report/telemetry.har
```

### What the timings mean

| Field | What it measures |
|---|---|
| `blocked` | Time in the connection queue. |
| `dns` | Name resolution. `0` on a reused connection or an IP literal. |
| `connect` | TCP. `0` on a reused connection. |
| `ssl` | TLS handshake. Included inside `connect`, per the HAR spec. |
| `send` | Writing the request. |
| `wait` | Time to first byte — usually the server thinking. |
| `receive` | Reading the body. |

A `wait` that dwarfs everything else is the server being slow. A `connect`
that does is the network. Distinguishing them is the reason both are there.

## What is not in the evidence

Secrets. They are removed structurally at the recorder, not by a pattern
match on the way out:

- Headers whose names are credential-bearing — `Authorization`,
  `Cookie`, `Set-Cookie`, `X-Api-Key` and the rest — are masked by name.
- Values the operator supplied are masked wherever they appear, including
  in a body.
- Tokens the *server* issued during the run are registered as they arrive
  and masked from that point on, so a refresh token minted at request 12
  is masked at request 13.

This is why the files are safe to attach to a ticket. It is also why a
finding about a credential shows `Bearer ***` rather than nothing at all:
the shape is preserved so you can see a credential was sent.

See [the security model](security-model.md) for the threat model behind
that choice.

## Bounded, and honest about it

A server can answer with a gigabyte. Response bodies are capped, the
recorder keeps a ring buffer, and the summary counts what it dropped rather
than pretending the cap did not happen. If a run was truncated, the report
says so.
