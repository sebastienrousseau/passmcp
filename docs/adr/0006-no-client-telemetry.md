---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp sends nothing home, why that is a product guarantee rather than a current fact, and what replaces the numbers telemetry would have produced.
---

# 0006 — passmcp never phones home

**Status:** Accepted · **Date:** 2026-09-19

## Context

passmcp's front page says *0 bytes uploaded* and *nothing here is uploaded*.
Today that is simply a description of the code: there is no client-side
callback anywhere in the binary, because nobody has written one.

A proposal was put forward to add one. Opt-out, anonymous, no personal
data: operating system, architecture, whether the run was in CI, how long
it took, the final score, and which phase failed. The reasoning is sound
and conventional — a developer tool with no usage data is a tool whose
maintainers are guessing, and an investor asking about adoption deserves a
number rather than an anecdote.

Three things make it the wrong trade for this particular tool.

**The tool is pointed at production.** An operator runs `passmcp check`
against a server holding their customers' data, with a credential that
works. The endpoint is often internal and its hostname is itself
sensitive. Even a payload that carries none of that has to be *audited* to
establish that it carries none of that, and the audit is a cost paid by
every security team that evaluates passmcp, forever.

**The guidance now runs the other way.** In May 2026 the NSA's Artificial
Intelligence Security Center published *Model Context Protocol (MCP):
Security Design Considerations for AI-Driven Automation*. Among its
recommendations: for sensitive data, prefer local MCP server instances
with **no vendor access or telemetry**. passmcp is not an MCP server, but
it is the tool an operator points at one, and the reasoning transfers
exactly. An enterprise reading that document and then finding a callback
in the diagnostic has been handed a reason to stop reading.

**The nearest competitor has just made the opposite choice.** The most
widely adopted MCP security scanner now requires an account and an API
token before it will scan anything. That is a gift, and it is only a gift
while passmcp needs neither.

## Decision

**passmcp contains no client-side telemetry, and will not.** No callback, no
ping, no opt-out beacon, no crash reporter.

*0 bytes uploaded* is promoted from a description of the current code to a
**product guarantee**, recorded in the stability-guarantees section of the
README. Adding a callback is therefore a breaking change under this
project's own rules, not a feature.

The guarantee is bounded and the bound is stated rather than implied: passmcp
makes requests to the server under test, to the authorization server that
server names, and to an OTLP collector or a report directory the operator
configures explicitly. Those are the run. (A fourth and a fifth, each asked
for by flag, were added on 2026-09-22 and 2026-09-23; see the amendments
below.) Nothing else leaves the machine,
and nothing at all goes to anywhere passmcp's authors control.

`satellion.com` is a website and carries ordinary website analytics. A
website is not the tool.

## Consequences

The numbers have to come from somewhere else, and they do — from
deliberate publication rather than silent collection, which is a better
source and not merely an acceptable one:

| Signal | Why it is stronger than telemetry |
|---|---|
| Published attestations in a transparency log | Every entry is an operator choosing to publish. Attributable, countable, and auditable by a third party directly rather than on our word |
| GitHub Action usage count | Computed and published by GitHub, not by us |
| Badge impressions | The operator opted in by embedding it |
| Package and release download counts | Already collected by four distribution channels |
| Citations of the rubric | The only signal that measures whether passmcp is becoming a standard rather than a popular tool |

What is genuinely lost is the diagnostic feedback loop: we cannot see
which phase developers fail on most, or which checks confuse them. That
has to be bought with research instead — the census, issue triage, an
opt-in survey, and the coverage of the guidance catalogue. Slower, less
precise, and it does not require asking every user to trust us with a
callback they did not want.

## What would make this wrong

If the ecosystem's norms shift so far that a local-first posture stops
being a differentiator and becomes an obstacle — if operators start
*expecting* a diagnostic to report to a fleet service and treat one that
does not as unmanageable — then the answer is still not a callback in the
binary. It is a separate, explicitly configured exporter the operator
points at **their own** collector, which `--otlp-endpoint` already is.

The line that must not move: passmcp never sends anything to an endpoint
passmcp's authors control.

## Amendment — 2026-09-22: vulnerability lookup

`passmcp sbom --osv` asks OSV which advisories affect the packages in a bill
of materials. That is a destination the bound above did not list, so it is
recorded here rather than added quietly.

It stays inside the decision for the same reason `--otlp-endpoint` does:
the operator asks for it explicitly, by flag, on the run where it happens.
It is off by default, and nothing else in passmcp makes the request. It is
announced on stderr before anything is sent, and it is recorded in the
document it produced. What is sent is package URLs and nothing else: no
hashes, no paths, no project name, nothing about the server under test.
Components that did not come from a public registry are never sent, because
their names may be internal and no public database could match them.
`--osv-url` points the lookup at a mirror for an operator who cannot send
even public package names outside their network.

The OSV API is run by Google, not by passmcp's authors, so the line above
does not move. The bound now reads: the server under test, the
authorization server it names, an OTLP collector or report directory the
operator configures, and a vulnerability database the operator asks for by
flag.

## Amendment — 2026-09-23: explanations from a model

`passmcp explain report.json --model NAME` sends a saved report's failures
and warnings to a language model and prints its explanations beside
passmcp's own guidance. That is a destination the bound did not list, so it
is recorded here.

It is held to the vulnerability lookup's terms. It is asked for by
`--model` on the command where it happens; an API key that is merely
present in the environment sends nothing, because a key exported for
other tools is not a request. It is announced on stderr, naming the
destination, before anything is sent. What is sent is each finding's id,
title, status, severity and detail as the saved report records them, and
the remediation text passmcp ships — not the evidence, the telemetry, the
authentication summary or the rest of the report. It is sent only over
TLS, or plain HTTP to this machine, and `--api-url` points it at a proxy
or gateway an organisation already runs for model traffic. Without
`--model`, `passmcp explain` is offline and still complete.

The model's answer is untrusted in the same way the server's text is:
bounded, attributed to the model by name, and unable to change a status,
a severity or a check id, which are copied from the report.

The bound now reads: the server under test, the authorization server it
names, an OTLP collector or report directory the operator configures, a
vulnerability database the operator asks for by flag, and a model the
operator asks for by flag.

## Amendment — 2026-09-28: findings to a security event collector

`--output ocsf --ocsf-endpoint URL`, on `passmcp check` and `passmcp fleet run`,
posts failing and warning findings, and a fleet run's changes, as OCSF
events to a collector the operator runs. That is a destination the bound did
not list, so it is recorded here.

It is the same kind of thing as `--otlp-endpoint`: an exporter pointed at the
operator's own infrastructure, held to the vulnerability lookup's terms.
Nothing is sent without the flag, whatever else is configured. The
destination is announced on stderr before anything is sent. What is sent is
the finding's id, status, severity and detail, the `req#N` it cites, and for
a fleet change the before and after values and both attestation digests;
the recorder's redaction applies, as in every other format. It is sent only
over TLS, or plain HTTP to this machine, and a redirect is refused: the
events go to the endpoint named and nowhere else.

The bound now reads: the server under test, the authorization server it
names, an OTLP collector, OCSF collector or report directory the operator
configures, a vulnerability database the operator asks for by flag, and a
model the operator asks for by flag.
