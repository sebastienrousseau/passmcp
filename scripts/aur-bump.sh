#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Move the family's three AUR packages to a released version.
#
#   scripts/aur-bump.sh v0.0.1           # prepare and test; push nothing
#   scripts/aur-bump.sh v0.0.1 --push    # then commit, push and read back
#
# The AUR repositories are the source of truth for the recipes
# (pkg/aur/README.md). This script changes only pkgver, pkgrel and the
# checksums, recomputed from what the release published. Before anything
# is pushed, every package is built, installed and linted with makepkg and
# namcap in a native Arch Linux container, which also regenerates
# .SRCINFO. Needs: git, curl, python3, docker; --push also needs an SSH
# key the AUR account holds.
set -euo pipefail

tag="${1:-}"
push="${2:-}"
[[ "${tag}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || { echo "usage: $0 vX.Y.Z [--push]" >&2; exit 2; }
[[ -z "${push}" || "${push}" == --push ]] || { echo "usage: $0 vX.Y.Z [--push]" >&2; exit 2; }
ver="${tag#v}"
owner=sebastienrousseau
# arm64 natively: the x86_64 image under emulation crashes the Go runtime.
image="${AUR_IMAGE:-lopsided/archlinux:latest}"
platform="${AUR_PLATFORM:-linux/arm64}"

work=$(mktemp -d)
container="aur-bump-$$"
trap 'docker rm -f "${container}" >/dev/null 2>&1 || true; rm -rf "${work}"' EXIT

sha256_of() { # URL -> sha256 of the downloaded bytes
  curl -q -fsSL "$1" -o "${work}/download" || { echo "aur-bump: cannot fetch $1" >&2; exit 1; }
  python3 -c 'import hashlib,sys; print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "${work}/download"
}

# Rewrites assignments in a PKGBUILD: set KEY 'value' pairs, quoting the
# checksum arrays as makepkg writes them.
set_vars() { # file key=value...
  python3 - "$@" <<'PY'
import re, sys
path, pairs = sys.argv[1], sys.argv[2:]
text = open(path).read()
for pair in pairs:
    key, value = pair.split("=", 1)
    new = f"{key}=('{value}')" if key.startswith("sha256sums") else f"{key}={value}"
    text, n = re.subn(rf"(?m)^{re.escape(key)}=.*$", new, text)
    if n != 1:
        sys.exit(f"aur-bump: {path}: expected one {key}= line, found {n}")
open(path, "w").write(text)
PY
}

echo "=== checksums for ${tag}"
passmcp_src=$(sha256_of "https://github.com/${owner}/passmcp/archive/refs/tags/${tag}.tar.gz")
reporting_src=$(sha256_of "https://github.com/${owner}/passmcp-reporting/archive/refs/tags/${tag}.tar.gz")
curl -q -fsSL "https://github.com/${owner}/passmcp-server/releases/download/${tag}/checksums.txt" -o "${work}/mcp-checksums.txt" \
  || { echo "aur-bump: passmcp-server ${tag} has no checksums.txt; is it released?" >&2; exit 1; }
mcp_x86=$(awk '$2 == "passmcp-server_Linux_x86_64.tar.gz" { print $1 }' "${work}/mcp-checksums.txt")
mcp_arm=$(awk '$2 == "passmcp-server_Linux_arm64.tar.gz" { print $1 }' "${work}/mcp-checksums.txt")
[[ -n "${mcp_x86}" && -n "${mcp_arm}" ]] || { echo "aur-bump: passmcp-server's checksums.txt lacks a Linux archive" >&2; exit 1; }
printf '    passmcp %s\n    passmcp-reporting %s\n    passmcp-server x86_64 %s, aarch64 %s\n' "${passmcp_src}" "${reporting_src}" "${mcp_x86}" "${mcp_arm}"

packages=(passmcp passmcp-server-bin passmcp-agentgateway-extmcp)
echo "=== cloning and editing"
for p in "${packages[@]}"; do
  git clone -q "ssh://aur@aur.archlinux.org/${p}.git" "${work}/${p}"
done
set_vars "${work}/passmcp/PKGBUILD" "pkgver=${ver}" "pkgrel=1" "sha256sums=${passmcp_src}"
set_vars "${work}/passmcp-server-bin/PKGBUILD" "pkgver=${ver}" "pkgrel=1" "sha256sums_x86_64=${mcp_x86}" "sha256sums_aarch64=${mcp_arm}"
set_vars "${work}/passmcp-agentgateway-extmcp/PKGBUILD" "pkgver=${ver}" "pkgrel=1" "sha256sums=${reporting_src}"

echo "=== build, install and lint in Arch Linux (${platform})"
docker run -d --name "${container}" --platform "${platform}" "${image}" sleep 3600 >/dev/null
docker exec "${container}" bash -c '
  set -euo pipefail
  pacman-key --init >/dev/null 2>&1; pacman-key --populate >/dev/null 2>&1
  pacman -Syu --noconfirm --needed base-devel go namcap git >/tmp/pacman.log 2>&1 || { tail -5 /tmp/pacman.log; exit 1; }
  useradd -m builder && echo "builder ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/builder'
for p in "${packages[@]}"; do
  docker cp "${work}/${p}" "${container}:/home/builder/${p}"
done
docker exec "${container}" chown -R builder:builder /home/builder
# In dependency order: passmcp-server-bin depends on passmcp.
for p in "${packages[@]}"; do
  docker exec -u builder -w "/home/builder/${p}" "${container}" bash -c '
    set -euo pipefail
    makepkg -s --noconfirm > /tmp/build.log 2>&1 || { tail -20 /tmp/build.log; exit 1; }
    pkg=$(ls ./*.pkg.tar.* | head -n1)
    sudo pacman -U --noconfirm "${pkg}" >/dev/null
    namcap PKGBUILD
    makepkg --printsrcinfo > .SRCINFO' \
    || { echo "aur-bump: ${p} did not build, install or lint" >&2; exit 1; }
  docker cp "${container}:/home/builder/${p}/.SRCINFO" "${work}/${p}/.SRCINFO"
  echo "    ${p} ${ver}-1 built, installed and linted"
done
docker exec "${container}" bash -c 'passmcp version && passmcp-server --version && agentgateway-extmcp -h 2>&1 | head -1'

for p in "${packages[@]}"; do
  echo "=== ${p}"
  git -C "${work}/${p}" --no-pager diff --stat
done

if [[ "${push}" != --push ]]; then
  echo "tested; nothing pushed. Re-run with --push to publish ${ver}-1."
  exit 0
fi

echo "=== publishing"
for p in "${packages[@]}"; do
  git -C "${work}/${p}" add PKGBUILD .SRCINFO
  # Re-runnable: a package whose repository already holds this version has
  # nothing to commit, and is only read back.
  if git -C "${work}/${p}" diff --cached --quiet; then
    echo "    ${p} already at ${ver}-1 in its repository"
  else
    git -C "${work}/${p}" commit -q -S -m "Update to ${ver}-1"
    git -C "${work}/${p}" push -q origin HEAD:master
    [[ "$(git -C "${work}/${p}" ls-remote origin refs/heads/master | cut -f1)" == "$(git -C "${work}/${p}" rev-parse HEAD)" ]] \
      || { echo "aur-bump: ${p} did not land on the AUR" >&2; exit 1; }
  fi
  # The package page lags the push by some seconds; poll for up to a minute.
  shown=""
  for _ in $(seq 12); do
    page=$(curl -q -fsSL "https://aur.archlinux.org/packages/${p}" || true)
    if grep -q "Package Details: ${p} ${ver}-1" <<<"${page}"; then shown=yes; break; fi
    sleep 5
  done
  [[ -n "${shown}" ]] || { echo "aur-bump: after a minute the ${p} page still does not show ${ver}-1" >&2; exit 1; }
  echo "    ${p} ${ver}-1 published"
done
