#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
#
# Fail unless README.md follows the portfolio README template (AGENTS.md
# §7.3): a centred plain-text h1, the template's second-level headings in
# the template's order, and no unresolved {{UPPER_SNAKE_CASE}} variable
# outside code. The heading list is the template's; update both together.
#
#   scripts/readme-check.sh [README.md]
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
readme="${1:-README.md}"
[ -f "${readme}" ] || { echo "readme-check: ${readme} not found" >&2; exit 1; }

project=$(sed -n 's|^<h1 align="center">\([^<]*\)</h1>$|\1|p' "${readme}" | head -1)
[ -n "${project}" ] || { echo "readme-check: no centred plain-text <h1 align=\"center\">name</h1>" >&2; exit 1; }

expected=$(cat <<LIST
Contents
Install
Requirements
Quick Start
The ${project} ecosystem
Capabilities at a glance
Ecosystem comparison
Benchmarks
Features
Configuration
Examples
When not to use ${project}
Development
Security
Documentation
Stability guarantees
License
LIST
)

# Second-level headings and template tokens, both outside fenced code.
outside_code=$(awk '/^[[:space:]]*(```|~~~)/ { fence = !fence; next } !fence' "${readme}")
actual=$(sed -n 's/^## //p' <<<"${outside_code}")
if [ "${actual}" != "${expected}" ]; then
  echo "readme-check: second-level headings differ from the template:" >&2
  diff <(echo "${expected}") <(echo "${actual}") >&2 || true
  exit 1
fi

# Inline code is content too: strip it before looking for variables.
# shellcheck disable=SC2001,SC2016 # a regex substitution with literal backticks
tokens=$(sed 's/`[^`]*`//g' <<<"${outside_code}" | grep -oE '\{\{ *[A-Z][A-Z0-9_]* *\}\}' || true)
[ -z "${tokens}" ] || { echo "readme-check: unresolved template variables: ${tokens}" >&2; exit 1; }

echo "readme-check: ${readme} follows the template (${project})"
