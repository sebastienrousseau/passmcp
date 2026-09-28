---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Why passmcp has no paid tier yet: every feature on the roadmap is built in the open, and the open-core line is drawn only when there is adoption to draw it against.
---

# 0012 — Everything stays open for now

**Status:** Accepted · **Date:** 2026-09-27

## Context

The 2027 research put three candidates for a paid tier on the roadmap:

- **Hosted, continuous runs:** scheduled checking of registered servers,
  with history, alerts and trends, run as a managed service.
- **The organisation-wide Security Graph:** the map of agents, MCP
  servers and identities in #4, with a multi-user interface.
- **Enterprise controls:** SSO and SAML, RBAC, audit logs, policy packs,
  and evidence export for SOC 2 and ISO 27001 auditors.

Drawing that line now would decide which of the next issues are built
in the open and which are not: the graph in issue #4, discovery in
issue #5, fleet validation in issue #8 and the evidence mappings in
issues #1–#3. Nothing yet says where the line belongs:

- No gateway, registry or auditor consumes the attestation in production
  yet. Obot's admission gate (obot-platform/obot#8013) is awaiting review,
  and the agentgateway processor is published but not linked from
  upstream.
- No customer has asked for any of the three.
- There is one maintainer. A hosted tier is an operational commitment
  (availability, a data processing agreement, SOC 2 for the service
  itself), and that is a second product.

A paid feature designed without a buyer is priced, scoped and packaged by
guesswork, and walling off a feature before anyone uses it costs the
adoption the open project exists to earn.

## Decision

**There is no paid tier yet. Every feature on the roadmap is built in the
open**, under the licences that already apply:

- **The engine and the CLI:** GPL-3.0.
- **The attestation format, the rubric and the control mappings:**
  Apache-2.0 ([ADR 0011](0011-attestation-format-is-apache.md)).

Concretely:

- **Built open, for anyone to run:** the Security Graph (#4), discovery
  (#5), continuous fleet validation (#8) and the SOC 2, ISO 27001 and
  GDPR evidence mappings (#1–#3). They run on the operator's side, as
  everything passmcp does ([ADR 0007](0007-not-a-gateway.md)).
- **Not created:** the `passmcp-enterprise` repository proposed in the
  roadmap.
- **Not offered:** a hosted service. SOC 2 and ISO 27001 certification
  are not pursued, because they only apply to a service that exists.
- **Not gated:** no feature is withheld from the open build and no
  licence key exists. Nothing in the tree anticipates one, so no dormant
  seams have to be maintained.
- **Income:** support and sponsorship only, for now.

The decisions that protect a future commercial product stay as they are.
No client telemetry ([ADR 0006](0006-no-client-telemetry.md)) and never
in the data path ([ADR 0007](0007-not-a-gateway.md)) apply to any tier
that is ever built, so this record does not weaken them.

## What would reopen it

This record is superseded, not edited, when one of these happens:

- An organisation asks to pay for one of the three candidates, or for
  something else passmcp does not do.
- The attestation is consumed in production by a gateway, registry or
  auditor. That makes the evidence itself the thing worth paying to
  keep current.
- A second maintainer joins, which makes an operated service something
  that can be staffed.

The superseding record draws the open-core line against that evidence:
which of the three, the pricing unit (per server, per agent or per
identity), and how the paid part is licensed.

## What would make it wrong

If a well-funded competitor packages passmcp's open work as a hosted service
before passmcp does, the open build has funded someone else's product. The
mitigations are the ones already in place: the GPL licence on the engine,
a public rubric whose authority stays with this project, and a census
dataset that is expensive to copy. If those prove too weak, that is a
reason to reopen this record early.
