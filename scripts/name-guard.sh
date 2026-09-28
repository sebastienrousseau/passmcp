#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# name-guard: fail when a retired product name appears in a tracked file.
# The retired name may not appear anywhere in this repository.
set -euo pipefail
cd "$(git rev-parse --show-toplevel)"

old='sc''out'   # split so this file does not match itself

hits=$(git grep -nIi -e "${old}" -- . ':(exclude)*.sum' || true)
if [ -n "${hits}" ]; then
  echo "name-guard: a retired name appears in the tree:" >&2
  printf '%s\n' "${hits}" | head -50 >&2
  echo "name-guard: $(printf '%s\n' "${hits}" | wc -l | tr -d ' ') occurrence(s)" >&2
  exit 1
fi
echo "name-guard: clean"
