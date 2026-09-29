#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Fail unless every place that states the release version agrees on it:
# the CHANGELOG heading, the install snippets in README.md and docs/, the
# family sentence in the README's ecosystem section, and the release notes
# in docs/releases/.
#
# With a tag (the release workflow passes GITHUB_REF_NAME), the tag is the
# version under test. Without one (CI on every push), the version is the
# newest '## [x.y.z]' heading in CHANGELOG.md, the one place it is authored.
#
#   scripts/verify-release-versions.sh [vX.Y.Z]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
tag="${1:-${GITHUB_REF_NAME:-}}"
case "${tag}" in
  v[0-9]*) ver="${tag#v}" ;;
  *) ver=$(sed -n 's/^## \[\([0-9][0-9.]*\)\].*/\1/p' CHANGELOG.md | head -1) ;;
esac
[ -n "${ver}" ] || { echo "verify-release-versions: CHANGELOG.md has no '## [x.y.z]' heading" >&2; exit 1; }
fail=0
grep -Eq "^## \[${ver}\]" CHANGELOG.md || { echo "CHANGELOG.md has no '## [${ver}]' heading" >&2; fail=1; }
# Every install snippet pins the release: @latest resolves to whatever the
# module proxy thinks is highest, which is not always the current release.
pinned=(README.md docs/*.md)
if grep -Eo 'passmcp/cmd/passmcp@(v[0-9]+\.[0-9]+\.[0-9]+|latest)' "${pinned[@]}" | grep -v "passmcp@v${ver}"; then
  echo "an install snippet pins something other than v${ver}" >&2; fail=1
fi
# The family sentence every README in the family carries names the version.
stated=$(sed -n 's/^Every component is released at \*\*\([0-9.]*\)\*\*.*/\1/p' README.md)
[ "${stated}" = "${ver}" ] || { echo "README.md's ecosystem section says '${stated}', not ${ver}; run make ecosystem" >&2; fail=1; }
notes="docs/releases/v${ver}.md"
grep -q '^## Highlights ⭐️' "${notes}" 2>/dev/null || { echo "${notes} is missing or has no '## Highlights ⭐️'" >&2; fail=1; }
[ "${fail}" -eq 0 ] || exit 1
echo "release versions agree on ${ver}"
