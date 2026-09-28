---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp findings and fleet changes as OCSF 1.3.0 events, for Security Lake, Splunk, Sentinel and any other SIEM that reads the Open Cybersecurity Schema Framework.
---

# OCSF

`--output ocsf` writes a run's failing and warning findings as a JSON array
of [OCSF](https://schema.ocsf.io/1.3.0/) events, pinned to schema version
**1.3.0**. Passing, skipped and informational findings are not events: a
SIEM wants what needs attention.

```sh
passmcp check https://mcp.example/mcp --output ocsf > events.json
```

## Classes

| Finding | OCSF class |
|---|---|
| a weakness in the server: transport, discovery, auth, egress, filesystem, supply chain, stdio, prompt-injection text, confusable names, toxic tool combinations, origin checks, output injection, dishonest annotations | Vulnerability Finding (`2002`) |
| everything else — a departure from the MCP specification | Compliance Finding (`2003`), with `compliance.standards` naming the passmcp rubric version |

| passmcp | `severity_id` |
|---|---|
| fail, critical | 5 Critical |
| fail, major | 4 High |
| fail, other | 3 Medium |
| warn, critical | 3 Medium |
| warn, other | 2 Low |

Each event's `finding_info.uid` is a digest of the run's trace id, the check
id and the finding's position, so a re-sent event deduplicates. What OCSF
has no field for — the check id, the `req#N` evidence, the advice, the
trace id and the documentation link — is under `unmapped.passmcp`.

## Fleet changes

`passmcp fleet run --output ocsf` writes one event per [fleet](fleet.md)
change instead. The event carries the change's kind, the tool, the before
and after values, and the digests of both attestations under
`unmapped.passmcp`, so the SIEM holds the evidence for the alert, not only the
alert.

## Sending events

`--ocsf-endpoint URL` posts the array to a collector over HTTPS;
`--ocsf-header "Name: value"` is repeatable, for the collector's key. The
destination is written to stderr before anything is sent, and nothing is
sent without the flag. As with `--otlp-endpoint`, a collector that refuses
the post is a warning, not a change to the verdict or the exit status.

## Redaction

Server text in an event — a tool description in a finding's detail, an
error string — passes through the same redactor as the report, and is capped
at 2,000 characters. A credential passmcp was given does not appear in an
event, even when the server reflects it back.

## Schema

The event shape is checked in the test suite against the OCSF 1.3.0 class
and object definitions, vendored under `internal/ocsf/testdata/ocsf-1.3.0/`
(Apache-2.0): required attributes present, no attribute the class does not
define, enumerations in range. A golden file pins the rest.
