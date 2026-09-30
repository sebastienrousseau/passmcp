#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Fail unless SBOM.md's Core Dependencies table lists exactly the direct
# requirements in go.mod, each at the version go.mod pins. The table is
# hand-written because its Purpose and License columns cannot be derived;
# this is what keeps its first two columns from drifting.
#
#   scripts/sbom-check.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

want=$(go mod edit -json | jq -r '.Require[] | select(.Indirect | not) | "\(.Path) \(.Version)"' | sort)
tick='`' # the table's code spans, kept out of a quoted pattern
have=$(sed -n "s/^| ${tick}\([^${tick}]*\)${tick} | \(v[^ |]*\) |.*/\1 \2/p" SBOM.md | sort)

if [ "${want}" != "${have}" ]; then
  echo "sbom-check: SBOM.md's Core Dependencies differ from go.mod's direct requirements:" >&2
  diff <(echo "${want}") <(echo "${have}") | sed -n 's/^</  go.mod only: /p; s/^>/  SBOM.md only:/p' >&2
  exit 1
fi
echo "sbom-check: SBOM.md lists the $(wc -l <<<"${want}" | tr -d ' ') direct requirements in go.mod"
