#!/bin/sh
# Smoke / loopback-ish network check for `make test-net`.
# Verifies: binary runs, listen port is in --port-lo/--port-hi, JSON has "port".
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
cd "$ROOT"
test -x ./ntx

MAG='magnet:?xt=urn:btih:0000000000000000000000000000000000000000&dn=loopback-smoke'
OUT=$(mktemp)
ERR=$(mktemp)
trap 'rm -f "$OUT" "$ERR"' EXIT

# 2s is enough for a few JSON lines; timeout 124 is success for us
set +e
timeout 2 ./ntx --port-lo=6881 --port-hi=6891 --stats-json "$MAG" >"$OUT" 2>"$ERR"
rc=$?
set -e
# 124 = timeout killed; 0 = clean quit (unlikely); other = fail
if [ "$rc" -ne 124 ] && [ "$rc" -ne 0 ]; then
  echo "test-net: ntx exited $rc" >&2
  cat "$ERR" >&2
  exit 1
fi

grep -q 'ntx: build' "$ERR" || { echo "test-net: missing build banner" >&2; exit 1; }

# hello-first (JSON API §7): line 1 is the contract hello, not the stats snapshot —
# locate the JSON line that actually carries the port field instead of assuming
# it is line 1. Empty result (no such line) still trips the "no JSON port" guard.
line=$(grep '"port"' "$OUT" | head -n 1)
echo "$line" | grep -q '"port"' || { echo "test-net: no JSON port" >&2; exit 1; }

# Extract port number and check range 6881–6891
port=$(printf '%s' "$line" | sed -n 's/.*"port":\([0-9][0-9]*\).*/\1/p')
test -n "$port"
if [ "$port" -lt 6881 ] || [ "$port" -gt 6891 ]; then
  echo "test-net: port $port outside 6881-6891" >&2
  exit 1
fi

echo "net_loopback OK (port=$port)"
