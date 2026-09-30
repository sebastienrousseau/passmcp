#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Run every fuzz target for a fixed time. The committed corpus under each
# package's testdata/fuzz/ replays first, so a fixed bug stays fixed.
#
#   scripts/fuzz.sh            # 20s per target
#   FUZZTIME=5m scripts/fuzz.sh
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
FUZZTIME="${FUZZTIME:-20s}"
targets=(
  "./auth FuzzParseWWWAuthenticate"
  "./transport FuzzReadSSE"
  "./transport FuzzHeaderValue"
  "./diagnostics FuzzValidate"
  "./diagnostics FuzzArguments"
  "./internal/clientconf FuzzParse"
  "./internal/probe FuzzSchemaValid"
  "./internal/termsafe FuzzString"
)
for t in "${targets[@]}"; do
  set -- $t
  echo "== $1 $2 ($FUZZTIME)"
  go test "$1" -run '^$' -fuzz "^$2\$" -fuzztime "$FUZZTIME"
done
