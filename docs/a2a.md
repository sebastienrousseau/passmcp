---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Check an Agent2Agent (A2A) agent from its Agent Card: transport, schema, signature and authentication, with an offline-verifiable attestation.
---

# A2A agents

`passmcp a2a check` verifies an agent that speaks the
[Agent2Agent (A2A) protocol](https://a2a-protocol.org/) from its Agent
Card. It uses the same rules as an MCP run: every verdict cites the
requests behind it, passmcp only reads, and the result can be written as an
in-toto attestation that a registry or gateway verifies offline.

```sh
passmcp a2a check https://agent.example.com
passmcp a2a check https://agent.example.com --output json
passmcp a2a check https://agent.example.com --output attestation > a2a.intoto.json
```

The command exits with 0 when nothing failed, 2 when a check failed, and 1
when the URL cannot be checked at all.

## What it checks against

The specification is **A2A v1.0**, read at commit
[`72b3761`](https://github.com/a2aproject/A2A/tree/72b3761bd84c59291da694dcd97cdfc2c010df39)
of `a2aproject/A2A` (Apache-2.0):

- **Where the card is:** section 8.2 puts the Agent Card at
  `/.well-known/agent-card.json` at the root of the agent's domain. passmcp
  fetches it from there whatever path the URL you give names.
- **What a card is:** the `AgentCard` message in
  [`specification/a2a.proto`](https://github.com/a2aproject/A2A/blob/72b3761bd84c59291da694dcd97cdfc2c010df39/specification/a2a.proto)
  is the normative definition, rendered as JSON with proto3 JSON field
  names. A2A v1 publishes no JSON Schema for the card, so passmcp vendors
  none. The validator in `internal/a2a/schema.go` transcribes the proto
  message by message, including its required fields, its `oneof` groups
  and its enumerations.
- **How a card is signed:** section 8.4 defines the signature. A signer
  removes default values, excludes the `signatures` member, canonicalises
  the rest with [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785) (JCS),
  and signs the result as the payload of a JWS
  ([RFC 7515](https://www.rfc-editor.org/rfc/rfc7515)). Each
  `AgentCardSignature` carries the protected header and the signature.

## The checks

| Check | Passes when | Fails when |
|---|---|---|
| `a2a.transport` | the card was served over HTTPS | the card is served over plain http from a host that is not loopback (loopback is recorded as info, as `net.scheme` records it for MCP) |
| `a2a.card_schema` | the card is a valid A2A v1 `AgentCard` | the card cannot be fetched, is not a JSON object, or departs from the schema. Every error names its JSON path, such as `$.skills[0].tags: must be an array` |
| `a2a.card_signature` | a signature verifies against the key its `jku` names | no signature verifies: the card was altered, the key set cannot be fetched, or it has no key with the `kid` |
| `a2a.unauthenticated` | the card declares a scheme and the agent refuses a request with no credentials | the agent answers a request that carries no credentials, whether or not the card declares a scheme |

Each check also has the outcomes that are neither pass nor fail:

- **An unsigned card** is `info`. Signing is optional in A2A v1, so an
  unsigned card breaks no rule. The finding records that nothing binds
  the card to its publisher.
- **A signature that verifies only against a `jwk` embedded in its own
  protected header** is `warn`. It shows the card was not altered after
  signing, but not who signed it, because anyone can sign with a key they
  carry themselves.
- **A card whose signature names neither a `jku` nor a `jwk`** fails.
  passmcp keeps no trusted key store, so it has no way to resolve that key.
- **The unprotected `header`** of a signature is never used to find a
  key. Nothing in it is signed.
- **An agent that refuses a request while its card declares no scheme** is
  `warn`. The agent is protected, but a client cannot learn from the card
  how to authenticate.

### Signature verification

passmcp implements JCS and JWS with the Go standard library alone, with no
dependency added for them. It accepts these algorithms:

- `EdDSA` (Ed25519);
- `ES256`, `ES384` and `ES512`;
- `RS256`, `RS384` and `RS512`;
- `PS256`, `PS384` and `PS512`.

It refuses RSA keys under 2048 bits and EC points that are not on their
curve. The canonicaliser is tested against the RFC 8785 examples.

A `jku` is fetched only when the URL policy allows it: HTTPS to a public
host, or loopback. A card that names a key set inside your network is
refused unless you pass `--insecure-allow-private-hosts`, because a card
that could make passmcp fetch any URL it names would turn passmcp into a
probe of your network.

### The one request that shows authentication

Showing whether the agent serves requests without credentials needs one
request. passmcp picks the least invasive method A2A has, `ListTasks` with
a page size of one, and sends it with no credentials to the first JSON-RPC
or HTTP+JSON interface the card declares:

- JSON-RPC: `POST <url>` with
  `{"jsonrpc":"2.0","id":"passmcp-a2a-1","method":"ListTasks","params":{"pageSize":1}}`
- HTTP+JSON: `GET <url>/tasks?pageSize=1`

Both carry the `A2A-Version` header of the interface. The request reads,
creates and changes nothing. passmcp never sends a message and never
invokes a skill ([ADR-0004](adr/0004-read-only-by-default.md)). How the
answer counts:

- **Served:** a 2xx answer with a task list, or with a JSON-RPC `result`.
- **Refused:** 401 or 403.
- **Neither:** anything else, such as a JSON-RPC error, a 404 or a
  redirect. The finding is `info`, because it shows nothing either way.

passmcp skips the check, and says why, when the card declares only gRPC or
names an interface the URL policy refuses.

## The attestation

`--output attestation` writes an in-toto Statement v1 whose predicate is
passmcp-reporting's A2A evaluation (`a2a` package). The statement holds:

- the card's URL;
- the SHA-256 of its JCS form;
- whether the card was signed, and which key verified it;
- every verdict with its evidence, and the verdict counts.

The statement carries no score, because A2A has no rubric yet. A number
with no rubric behind it could not be compared with anything.

A consumer verifies it offline:

```go
st, err := a2a.Parse(b) // satellion.com/passmcp-reporting/a2a
if err != nil || !st.Covers("https://agent.example.com") {
    // reject
}
```

`--output json` writes the full result, including every schema error.
The text output lists the schema errors in full when there are more than
the five the finding summarises.
