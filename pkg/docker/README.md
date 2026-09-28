<!--
SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
SPDX-License-Identifier: GPL-3.0-only
-->

# Container image

**Recipe:** [`Dockerfile`](../../Dockerfile) at the repository root,
built and pushed by the release workflow. Not duplicated here; see
[`../README.md`](../README.md) for why.

## Run

```bash
docker run --rm ghcr.io/sebastienrousseau/passmcp:latest check https://mcp.example.com/mcp
```

Pass credentials through the environment rather than on the command line,
so they do not land in the shell history or `docker inspect`:

```bash
docker run --rm -e PASSMCP_TOKEN ghcr.io/sebastienrousseau/passmcp:latest \
  check https://mcp.example.com/mcp
```

To keep a report directory, mount a volume and point `--report-dir` at
it. The image runs as uid 65532, so the mounted directory must be
writable by that user.

```bash
docker run --rm -e PASSMCP_TOKEN -v "$PWD/out:/out" \
  ghcr.io/sebastienrousseau/passmcp:latest check https://mcp.example.com/mcp --report-dir /out
```

The image has no shell and no package manager. `passmcp login` does not
work inside it: the loopback redirect the browser flow needs is not
reachable from the host. Log in with a native binary and mount
`~/.config/passmcp` read-only if you need the stored token in a container.

## Base image

`gcr.io/distroless/static-debian12:nonroot`, pinned by digest, which
OpenSSF Scorecard checks. The digest in the `Dockerfile` is a
placeholder until the first release; `release-config` in `ci.yml`
refuses to pass while it is. Resolve it with:

```bash
docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
```

Dependabot keeps it current afterwards.

## Verify

```bash
cosign verify ghcr.io/sebastienrousseau/passmcp:<version> \
  --certificate-identity-regexp '^https://github\.com/sebastienrousseau/passmcp/' \
  --certificate-oidc-issuer 'https://token.actions.githubusercontent.com'
```
