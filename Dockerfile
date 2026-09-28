# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only

# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e
#
# Runtime image for passmcp.
#
# The binary is expected to already be built by goreleaser. Do NOT compile
# from source here: the image must ship the same artefact the tarball does,
# or `docker pull` and a downloaded release are not the same program.
#
# dockers_v2 lays the build context out by platform — linux/amd64/passmcp,
# linux/arm64/passmcp — and buildx sets TARGETPLATFORM per architecture as it
# builds the manifest. The old dockers: section dropped one binary at the
# context root, which is why this used to copy plain `passmcp`.
#
# The base is distroless/static: passmcp is a static binary with CGO off, and
# needs nothing from the image but CA certificates and a non-root user,
# both of which distroless ships. It is pinned by digest, which OpenSSF
# Scorecard checks and which release-config in ci.yml refuses to release
# without. Dependabot keeps the digest fresh. To resolve it by hand:
#   docker buildx imagetools inspect gcr.io/distroless/static-debian12:nonroot
FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab

ARG TARGETPLATFORM
COPY ${TARGETPLATFORM}/passmcp /usr/local/bin/passmcp

LABEL org.opencontainers.image.source="https://github.com/sebastienrousseau/passmcp" \
      org.opencontainers.image.description="passmcp: onboard, test and diagnose remote MCP servers end to end" \
      org.opencontainers.image.licenses="GPL-3.0-only" \
      org.opencontainers.image.title="passmcp" \
      org.opencontainers.image.vendor="Sebastien Rousseau"

# distroless nonroot is uid/gid 65532. Numeric, so Kubernetes runAsNonRoot
# can verify it.
USER 65532:65532
WORKDIR /home/nonroot

ENTRYPOINT ["/usr/local/bin/passmcp"]
CMD ["--help"]
