---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp measures MCP servers instead of sitting between agents and them, and why that is a positioning decision rather than a scoping one.
---

# 0007 — passmcp is an instrument, not a gateway

**Status:** Accepted · **Date:** 2026-09-19

## Context

The obvious commercial shape for a tool that understands MCP deeply is a
gateway: sit between the agent and the server, broker credentials, block
the tool call that should not happen, and charge for the control plane.
The proposal was specific — centralised token orchestration, blast-radius
controls on unannotated tools, interception of a mutating call an agent
attempted by mistake.

Two facts argue against it.

**That market is not merely competitive, it is settled.** As of mid-2026
there are published fourteen-vendor buyer's guides for MCP gateways. The
entrants include Kong, Solo.io's Agent Gateway, Obot, IBM ContextForge,
Amazon Bedrock AgentCore, Tyk, MintMCP, Lunar.dev, Arcade, TrueFoundry and
Docker's own MCP Gateway. Two of them are free and open source. One of them
is AWS. Entering it means competing on deployment surface, enterprise
integrations and brand — the three axes on which a single-maintainer Go
project is weakest — and abandoning evidence, protocol depth and
trustworthiness, which are the three on which it is strongest.

**A gateway is a production dependency.** The reason an operator is willing
to point passmcp at a live server is that passmcp touches nothing: it makes
requests, records what came back, and exits. A proxy has to be trusted with
traffic, kept available, patched on somebody else's schedule, and blamed
when latency moves. That is a different product with a different risk
profile sold to a different buyer, and it would cost the one property that
makes the current product easy to adopt.

There is also an asymmetry worth naming. Every one of those fourteen
gateways has to make an admission decision — route to this server, or do
not — and none of them has a defensible basis for it. They ship policy
engines with no measurement. passmcp is measurement with no policy engine.

## Decision

**passmcp is never in the data path.** It does not proxy, broker credentials,
or intercept a call between an agent and a server. There is no
`passmcp-gateway`, and the family manifest records it as considered and
rejected with this reasoning attached.

What passmcp sells instead is the input those gateways lack: a signed,
portable [attestation](../reports.md) that states what was measured, what
it was judged against, and what the evidence was — verifiable offline, so a
gateway never has to call passmcp to trust it.

The corollary is a policy and not just a scope boundary: **passmcp never
becomes a runtime dependency of anyone's production traffic.** It is
written down here so that it does not get re-litigated by the first
enterprise that asks for a proxy.

## Consequences

The commercial model rests on fleet, history and evidence rather than on
interception: policy gating in CI, drift between two attestations, the
inventory a security team is required to keep, retention for an audit, and
licensing the evaluation engine to the gateways themselves.

That last one is the point. A gateway integration is a partnership rather
than a competition, and it reaches distribution passmcp could not buy. The
first two should be pull requests into the two open-source gateways, where
there is no procurement and a merged change is the case study.

The cost is real. Interception is where the obvious money is, and declining
it means the revenue depends on an attestation format being adopted by
people who are under no obligation to adopt it. If nobody verifies it, the
strategy has no second act.

## Update — 2026-09-24: where the line is

"Never in the data path" needed a line drawn once the first integrations
existed, because two of them sit close to it. The decision is unchanged;
this says what it means.

**The line.** passmcp is in the data path when either of these is true, and
must never be:

1. **An agent request fails, or slows, when something passmcp operates is
   down.** Nothing passmcp runs is consulted synchronously while a request
   is in flight.
2. **An agent request's bytes pass through code passmcp operates.** passmcp
   never terminates, forwards, rewrites or holds a request or a response
   between an agent and a server.

**Inside the line, and allowed:**

- *Code the gateway operator runs.* The verifier in passmcp-reporting, and
  the agentgateway `ExtMcp` processor built on it, run in the operator's
  own infrastructure. The gateway calls the processor for every request,
  so the operator's path depends on it, but that is the operator's
  component deciding from statements it loaded in advance; it never calls
  passmcp, and passmcp never sees the traffic. This is what "the evaluation
  engine inside somebody else's gateway" means.
- *Admission at registration time.* Obot's gate reads a statement when a
  catalog entry changes and when a server is created. No request waits on
  it.
- *A revocation or re-evaluation feed pushed to a gateway's control plane.*
  Asynchronous, and the gateway keeps its last decisions when the feed is
  unreachable: stale, not stopped. This is the shape the commercial live
  service may take.

**Outside the line, and never built:** a proxy, a credential broker, an
inline policy decision point passmcp hosts, or any hosted endpoint a gateway
must call before it can route a request.

The test for anything new is the first rule, stated as an operator would
experience it: if every passmcp-operated service went away at once, would any
agent request on any customer's network fail or wait? If yes, it is a
gateway feature, and it is not built.

## What would make this wrong

If the attestation is not adopted — if twelve months after it is signed no
gateway, registry or auditor verifies one — then measurement alone is not a
business and the decision needs revisiting. The response is still not to
build a gateway from scratch; it is to be the evaluation engine inside
somebody else's, which is a licensing conversation rather than a product
rewrite.

The other thing that would make it wrong is a gateway shipping its own
behavioural evaluator of comparable depth. That is the risk the census and
the public rubric exist to make expensive: a competitor can copy the checks
in a quarter and cannot copy a longitudinal dataset that everyone cites.
