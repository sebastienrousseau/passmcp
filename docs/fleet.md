---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  passmcp fleet run: check a set of MCP servers on a schedule, attest each, and fail on the changes that matter even when the score does not move.
---

# Fleets

`passmcp check` answers "is this server safe to connect to?" once. A platform
team that runs twenty servers needs the same answer every six hours, and
needs to know what changed since the answer was last yes. `passmcp fleet run`
is that loop.

```sh
passmcp fleet run fleet.yaml --state /data/passmcp
```

## The fleet file

```yaml
version: 1
state: fleet-state          # relative to this file; --state overrides it
pacing:
  rps: 2                    # per server; 0 means unpaced
  samples: 3
  call_timeout: 20s
servers:
  - name: docs
    endpoint: https://docs.example/mcp
    credential:
      token_env: DOCS_MCP_TOKEN
    policy: policies/docs.json
  - name: billing
    endpoint: https://billing.example/mcp
    credential:
      mode: client-credentials
      client_id: passmcp-fleet
      client_secret_env: BILLING_CLIENT_SECRET
      token_url: https://auth.example/oauth/token
      scope: mcp.read
  - name: local-git
    command: ["npx", "-y", "@acme/mcp-git@1.2.3"]
```

- **Credentials are named, never written.** A credential block names the
  environment variable that holds the token or client secret. A key passmcp
  does not know — `token:` included — is refused, so a secret pasted into a
  committed file fails the run instead of being quietly ignored.
- **Each server has its own policy**, loaded exactly as `--policy` would be.
- **A name is a directory.** Names are letters, digits, `.`, `_` and `-`,
  unique within the file.

## What a run does

For each server, in order: a full `passmcp check` under the server's policy,
the report directory written to `<state>/<name>/runs/<UTC time>/` with its
attestation, and a comparison with the server's previous recorded run.
`<state>/summary.json` holds the result for the whole fleet; stdout carries
it as a table, `--output json`, or `--output ocsf`.

| Change | Severity |
|---|---|
| a tool's `readOnlyHint` changes, in either direction | critical |
| a description gains text aimed at the model | critical |
| any other annotation change (other than `destructiveHint`) | critical |
| a tool added or removed, a schema changed | from the [baseline](reports.md#watching-for-drift) ladder |
| a check that passed now fails | serious |
| any other verdict that got worse | notable |
| the score dropped | notable |

**A critical change fails the fleet even at an unchanged score.** A tool
that stops claiming to be read-only is exactly the change a score averages
away.

## Exit status

| Code | Meaning |
|---|---|
| 0 | every server was reached, passed its gate and changed nothing critically |
| 1 | a server was unreachable |
| 2 | a server failed its gate or changed critically |

**Unreachable is its own status.** A server passmcp could not complete an MCP
handshake with is reported as `unreachable` with the error, never as a pass
and never as unchanged — and its previous run stays the one the next run is
compared with.

## Secrets

The values of every `token_env` and `client_secret_env` variable are
registered with the redactor before the first request. They are masked in
the reports, the catalogue snapshots, the diffs, the summary and the
diagnostics — including when a server reflects a token back into a tool
description.

## Running it on a schedule

[`examples/kubernetes/fleet-cronjob.yaml`](https://github.com/sebastienrousseau/passmcp/blob/main/examples/kubernetes/fleet-cronjob.yaml)
runs the fleet every six hours as a Kubernetes CronJob: the fleet file from
a ConfigMap mounted read-only, secrets from a Secret by `secretKeyRef`, state
on a PersistentVolumeClaim so each run has the last one to compare with, and
a non-root, read-only-root-filesystem container with every capability
dropped.

To send the fleet's changes to a SIEM, add `--output ocsf` or
`--ocsf-endpoint`; see [OCSF](ocsf.md).

Three things to know when you adapt it:

- **An internal CA** is trusted by setting `SSL_CERT_FILE` to a mounted
  bundle; the image carries only the public roots.
- **The image ships no MCP servers.** A `command:` entry needs its server
  inside the pod: carry the binary in from an init container onto an
  `emptyDir`, or build an image on top of passmcp's. It runs as the same
  non-root user under the same restrictions, and receives none of the pod's
  credentials.
- **Read `summary.json` from the volume, not the pod log.** The container
  log holds stdout and stderr together and the runtime may interleave their
  lines, so a JSON summary read back with `kubectl logs` can arrive with a
  diagnostic line inside it.

### Tested on a real cluster

`make e2e-kind` runs the example in a [kind](https://kind.sigs.k8s.io/)
cluster, applied unchanged apart from the image, the fleet file, the CA
and a one-minute schedule, against two TLS servers and a stdio server, with
[Ory Hydra](https://www.ory.sh/hydra/) issuing the client-credentials
tokens. Three scheduled runs: a baseline, a `readOnlyHint` withdrawn
(critical, exit 2), and a server scaled to zero (unreachable, exit 1). It
judges the result from outside passmcp: the namespace enforces the
`restricted` Pod Security profile, containerd's runtime spec shows what was
actually applied, the volume is read back through the claim, every log and
event is searched for the seeded secrets and every token the servers saw,
and a packet capture of the node shows every destination the passmcp pods
sent to. The verdict is `build/e2e-kind/matrix.md`; any failed row fails
the target. `PASSMCP_IMAGE=ghcr.io/sebastienrousseau/passmcp@sha256:…` runs the
same test against a published image.
