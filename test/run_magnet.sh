#!/bin/sh
# Live magnet smoke test (RFC roadmap H.2 helper). Requires network + magnet URL.
set -eu
MAG="${1:-}"
DUR="${2:-120}"
if [ -z "$MAG" ]; then
    echo "usage: $0 'magnet:?xt=...' [seconds]"
    exit 2
fi
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
make -s ntx
LOG=".live.log"
./ntx --compat-peers --dht --verbose "$MAG" >"$LOG" 2>&1 &
PID=$!
trap 'kill "$PID" 2>/dev/null || true' EXIT INT TERM
sleep "$DUR"
kill "$PID" 2>/dev/null || true
wait "$PID" 2>/dev/null || true
grep -E 'pe_out ok=|unchoked=|100%' "$LOG" || true
echo "smoke done (${DUR}s) log=$LOG"
