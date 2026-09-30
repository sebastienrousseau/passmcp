#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Condition and branch coverage with gobco (BSD-2-Clause, FLOSS), for the
# OpenSSF test_branch_coverage80 criterion. gobco type-checks every .go
# file in a directory and ignores build constraints, so it panics with
# "redeclared in this block" on packages with per-OS files. The script
# therefore works on a copy of the tracked tree with the files that the
# host build context ignores removed; the repository is never modified.
set -euo pipefail

GOBCO_VERSION="${GOBCO_VERSION:-v1.3.4}"
MODE="${MODE:-cond}"            # cond: each && / || operand both ways; branch: -branch
MIN="${BRANCH_MIN:-80}"
JOBS="${JOBS:-6}"
root="$(git rev-parse --show-toplevel)"
out="${DIST:-build}/branchcover-${MODE}"
out="$root/$out"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

GOBIN="$work/bin" go install "github.com/rillig/gobco@${GOBCO_VERSION}"

cd "$root"
mkdir -p "$work/src"
git ls-files -z | tar --null -cf - -T - | tar -xf - -C "$work/src"
cd "$work/src"
go list -f '{{$d:=.Dir}}{{range .IgnoredGoFiles}}{{$d}}/{{.}}{{"\n"}}{{end}}' ./... |
  xargs rm -f
rm -rf "$out" && mkdir -p "$out"

flag=""
[ "$MODE" = branch ] && flag="-branch"
go list -f '{{.Dir}}' ./... | sed "s|^$PWD|.|" |
  xargs -P "$JOBS" -I{} sh -c \
    'n=$(printf %s "{}" | tr "/." "__"); "$0/bin/gobco" $1 "{}" >"$2/$n.txt" 2>&1 || { echo "gobco failed: {}" >&2; exit 255; }' \
    "$work" "$flag" "$out"

cat "$out"/*.txt | awk -v min="$MIN" '
  /^(Condition|Branch) coverage: / { split($3, a, "/"); c += a[1]; t += a[2] }
  END {
    pct = t ? 100 * c / t : 100
    printf "gobco %s coverage: %d/%d = %.2f%% (min %s%%)\n", "'"$MODE"'", c, t, pct, min
    exit pct + 0 < min + 0
  }'
