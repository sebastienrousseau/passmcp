---
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
description: >-
  Signing passmcp attestations: sign the statement file with cosign, verify the signature and then the contents, and why passmcp itself does neither.
---

# Signing attestations

A statement from `passmcp check --output attestation` is a claim about a
server, made to be handed to a gateway, a registry or an auditor that was
not there when the run happened. Two questions have to be answered before
anyone acts on it, and they are answered by different tools:

| Question | Answered by |
|---|---|
| Who made this statement, and has it changed since? | the signature: `cosign verify-blob` |
| What does it say, and is that acceptable? | the contents: `passmcp verify` |

passmcp does not sign and does not check signatures
([ADR 0010](adr/0010-provenance-is-reported-not-verified.md)). A Sigstore
verifier is a certificate chain, a transparency log with inclusion proofs
and a timestamp authority; written by hand it would be the largest and least
reviewed part of the binary, and every gateway that would verify a passmcp
statement already runs cosign. The statement is a file, so it is signed as
one.

## In GitHub Actions, without a key

The signing identity is the workflow itself. Nothing is stored and nothing
expires.

```yaml
permissions:
  contents: read
  id-token: write   # the OIDC token cosign exchanges for a certificate

jobs:
  attest:
    runs-on: ubuntu-latest
    steps:
      - uses: sigstore/cosign-installer@v3
      - run: |
          passmcp check https://mcp.example.com/mcp --token-env MCP_TOKEN \
            --output attestation > attestation.json || test $? -eq 2
          cosign sign-blob --yes --bundle attestation.sigstore.json attestation.json
        env:
          MCP_TOKEN: ${{ secrets.MCP_TOKEN }}
```

`|| test $? -eq 2` keeps a run that found failures: a statement that says
"this server fails two checks" is exactly as worth signing as one that says
it passes. Exit 1 — the run could not be made — still stops the job.

Keyless signing writes an entry to Sigstore's public transparency log. The
entry holds the certificate, which names the repository and workflow, and
the SHA-256 of the statement file. It does not hold the statement, so the
endpoint and the verdicts stay wherever you put `attestation.json`.

To keep credentials and signing apart, run the diagnostic in one job and
sign in another that never sees the server — the split
[Reports](reports.md#producing-one-in-a-later-job) describes.

## Verifying

Signature first, then contents. The second step is only worth running on a
statement that passed the first.

```sh
cosign verify-blob attestation.json \
  --bundle attestation.sigstore.json \
  --certificate-identity-regexp '^https://github.com/ORG/REPO/\.github/workflows/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

passmcp verify attestation.json --endpoint https://mcp.example.com/mcp --max-fail 0
```

Pin the identity as tightly as your process allows: a workflow file and a
ref (`…/attest.yml@refs/heads/main`) rather than the whole repository, if
only that workflow should be able to vouch for a server.

A statement changed after signing fails the first command. A statement
signed by the right workflow and about the wrong server fails the second,
through `--endpoint`, which recomputes the subject digest rather than
comparing names.

## With a key, offline

Where there is no OIDC identity, or nothing may leave the network, sign
with a key and no transparency log. cosign 3 takes the services it uses
from a signing configuration, so one that lists none is how to be sure
nothing is uploaded:

```sh
cat > local-signing-config.json <<'EOF'
{"mediaType":"application/vnd.dev.sigstore.signingconfig.v0.2+json",
 "caUrls":[],"oidcUrls":[],"rekorTlogUrls":[],"tsaUrls":[],
 "rekorTlogConfig":{"selector":"ANY"},"tsaConfig":{"selector":"ANY"}}
EOF

cosign sign-blob --yes --key cosign.key \
  --signing-config local-signing-config.json \
  --bundle attestation.sigstore.json attestation.json

cosign verify-blob attestation.json --key cosign.pub \
  --bundle attestation.sigstore.json --insecure-ignore-tlog
```

`--insecure-ignore-tlog` is what it says: without a log, nobody but the key
holder can see that a signature was made, and a compromised key signs
silently. It is the right trade inside a closed network, and the wrong one
for a statement published outside it.

## Not `cosign attest-blob`, not `gh attestation`

Both wrap a predicate in a new in-toto statement whose subject is a file's
digest. A passmcp statement is already a complete in-toto statement, and its
subject is the server — a digest of the transport and endpoint — not a
file. Wrapping it would nest one statement inside another and replace the
server with the digest of a JSON file, and `gh attestation verify`, which
recomputes the subject from a file or an image, has nothing to recompute it
from. Sign the statement as a blob.
