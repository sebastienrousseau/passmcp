#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Fail unless CHANGELOG.md has a heading for the version being released and
# the install snippets in README.md do not pin a stale version.
#
#   scripts/verify-release-versions.sh v0.0.1
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag="${1:-${GITHUB_REF_NAME:-}}"
[ -n "$tag" ] || { echo "usage: $0 vX.Y.Z" >&2; exit 2; }
ver="${tag#v}"
grep -Eq "^## \[$ver\]" CHANGELOG.md || { echo "CHANGELOG.md has no '## [$ver]' heading" >&2; exit 1; }
# Every install snippet pins the release: @latest resolves to whatever the
# module proxy thinks is highest, which is not always the current release.
pinned=(README.md docs/*.md)
if grep -Eo 'passmcp/cmd/passmcp@(v[0-9]+\.[0-9]+\.[0-9]+|latest)' "${pinned[@]}" | grep -v "passmcp@v$ver" ; then
  echo "an install snippet pins something other than v$ver" >&2; exit 1
fi
echo "release versions agree on $ver"
