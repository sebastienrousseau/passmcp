#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Sebastien Rousseau <sebastian.rousseau@gmail.com>
# SPDX-License-Identifier: GPL-3.0-only
# Build passmcp and run the full diagnostic against corralctl's HTTP mode.
#
#   ./scripts/demo-corral.sh                       # text report on stdout
#   ./scripts/demo-corral.sh --output md           # any passmcp check flags
#   REPORT_DIR=./out ./scripts/demo-corral.sh      # also write all files
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

PORT="${PORT:-7777}"
ENDPOINT="http://127.0.0.1:${PORT}/mcp"
REPORT_DIR="${REPORT_DIR:-}"
LOG="$(mktemp -t corral-mcp.XXXXXX)"

command -v corralctl >/dev/null || { echo "corralctl not found" >&2; exit 1; }

# --- 1. build ---------------------------------------------------------------
make -s build

# --- 2. start the server; stop it whatever happens --------------------------
corralctl mcp --http "127.0.0.1:${PORT}" --log-level warn >"$LOG" 2>&1 &
SERVER_PID=$!
trap 'kill "$SERVER_PID" 2>/dev/null || true; rm -f "$LOG"' EXIT
for _ in $(seq 1 50); do
  curl -fsS -o /dev/null -X POST -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    -d '{"jsonrpc":"2.0","id":0,"method":"ping"}' "$ENDPOINT" 2>/dev/null && break
  sleep 0.1
done
kill -0 "$SERVER_PID" 2>/dev/null || { echo "corralctl failed to start:" >&2; cat "$LOG" >&2; exit 1; }

# --- 3. diagnose ------------------------------------------------------------
# --rps 0: your own local server, no need to throttle.
# --arg: give the lookup tools a real repository name instead of a probe.
extra=()
[ -n "$REPORT_DIR" ] && extra+=(--report-dir "$REPORT_DIR")
set +e
./build/passmcp check "$ENDPOINT" --rps 0 \
  --arg corral_find_repo.query=corralctl \
  --arg corral_get_repo_metadata.query=corralctl \
  --arg corral_repo_overview.query=corralctl \
  --arg corral_find_symbol.name=runClone \
  --arg corral_search_code.query=preflightSummary \
  "${extra[@]}" "$@"
status=$?
set -e
echo "passmcp exit status: $status (0 clean, 2 findings failed)" >&2
exit "$status"
