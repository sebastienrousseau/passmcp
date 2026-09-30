<!-- SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com> -->
<!-- SPDX-License-Identifier: GPL-3.0-only -->

# Roadmap

What passmcp intends to do over the next twelve months, October 2026 to
September 2027, and what it will not do.

**This is the maintainer's current intent, not a commitment.** passmcp has
one maintainer ([MAINTAINERS.md](MAINTAINERS.md)) and no funded schedule,
so nothing below carries a date. Every line is drawn from a document in
this repository, linked beside it; a plan that is not written down there
is not on this page. The page changes the way any substantial decision
does ([GOVERNANCE.md](GOVERNANCE.md)): an issue, at least a week of
comment, then a pull request.

## What passmcp intends to do

### Keep the release cadence and the family in lockstep

- Release in small steps, moving the patch digit every time, and reach
  `0.1.0` only after `0.0.999` ([CHANGELOG.md](CHANGELOG.md)).
- Release every repository in the family at the same version, so a
  reader never has to ask which version of which piece they are looking
  at ([docs/ecosystem.md](docs/ecosystem.md)).
- Keep each release built, signed and published by the release workflow,
  with SLSA provenance, a CycloneDX SBOM and keyless cosign signatures,
  and nothing published by hand ([DEVELOPMENT.md](DEVELOPMENT.md#release-model)).

### Follow the MCP specification

- Keep diagnosing every revision passmcp grades today, 2024-11-05
  through the stateless 2026-07-28, and add checks as the specification
  moves. 0.0.4 added seven, with 138 in all
  ([CHANGELOG.md](CHANGELOG.md), [docs/checks.md](docs/checks.md)).
- The gaps passmcp names in
  [When not to use passmcp](README.md#when-not-to-use-passmcp) are where
  new checks would come from: the MCP Apps extension, `pattern` and
  `format` in JSON Schema, and a `$ref` into another document. Naming a
  gap is not a promise to close it.

### Make the attestation useful to the tools that decide admission

- Get the signed attestation consumed by the gateways and registries
  that have to decide whether to admit a server. The first two
  integrations are pull requests into the two open-source gateways
  ([ADR 0007](docs/adr/0007-not-a-gateway.md)); Obot's admission gate is
  awaiting review, and the agentgateway processor is published
  ([ADR 0012](docs/adr/0012-everything-stays-open.md)).
- Keep the attestation format, the rubric and the control mappings under
  Apache-2.0, so anyone can implement them without passmcp's engine
  ([ADR 0011](docs/adr/0011-attestation-format-is-apache.md)).

### Keep building everything in the open

- The Security Graph, discovery, continuous fleet validation, and the
  SOC 2, ISO/IEC 27001 and GDPR evidence mappings stay in the open
  build, for anyone to run on their own side
  ([ADR 0012](docs/adr/0012-everything-stays-open.md)).
- ADR 0012 names what would reopen that decision: an organisation asking
  to pay, the attestation consumed in production, or a second
  maintainer. Until one of those happens, there is no paid tier and no
  licence key.

### Keep the project's assurance current

- Re-review the [security model](docs/security-model.md) on every
  release that touches the areas it lists.
- Meet the OpenSSF Best Practices criteria that can be met from the
  repository ([project 15080](https://www.bestpractices.dev/projects/15080)).
- Offer passmcp to nixpkgs: the flake exists and has not been submitted
  ([pkg/nix/README.md](pkg/nix/README.md)).

## What passmcp will not do

Each of these is a recorded decision, not an omission. Reversing one
takes a new decision record that supersedes the old one.

| passmcp will not | Why | Record |
|---|---|---|
| Sit in the data path: proxy, broker credentials, or intercept a call between an agent and a server | A gateway is a production dependency, and the market is settled | [ADR 0007](docs/adr/0007-not-a-gateway.md) |
| Ship an adversarial or exploit mode, behind a flag, a verb or a separate repository | The read-only posture is what lets a security team approve passmcp | [ADR 0008](docs/adr/0008-no-adversarial-mode.md) |
| Send anything home: no telemetry, no crash reporter, no opt-out beacon | *0 bytes uploaded* is a product guarantee | [ADR 0006](docs/adr/0006-no-client-telemetry.md) |
| Invoke a tool that does not declare `readOnlyHint: true` unless the operator says so | An unannotated tool is destructive under the specification's default | [ADR 0004](docs/adr/0004-read-only-by-default.md) |
| Accept credentials in the hosted diagnostic | Handing a working token to someone else's server is what passmcp warns against | [ADR 0005](docs/adr/0005-public-mode-is-the-same-binary.md) |
| Offer a hosted service or a paid tier, for now | Nobody has asked, and a hosted service is a second product | [ADR 0012](docs/adr/0012-everything-stays-open.md) |
| Embed a tokenizer vocabulary | Token counts are named estimates | [ADR 0009](docs/adr/0009-token-counts-are-estimates.md) |
| Become a load-testing tool | The parallel burst is bounded and the default throttle is two requests a second, on purpose | [When not to use passmcp](README.md#when-not-to-use-passmcp) |

The family's rejected repositories, `passmcp-gateway`, `passmcp-proxy`,
`passmcp-fuzz` and `passmcp-wasm`, are listed with their reasons in
[docs/ecosystem.md](docs/ecosystem.md#considered-and-rejected).

## Suggesting a change

Open an issue that says what you need and why. A request that runs into
one of the decisions above is still worth filing: each record says what
would make it wrong, and evidence of that is how a decision changes.
