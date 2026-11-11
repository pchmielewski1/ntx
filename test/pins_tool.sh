#!/usr/bin/env bash
# Offline gate for scripts/pins/pins.py (Task C4, design §6.2). Replays recorded
# openssl results from test/vectors/pins/<case>; no network, no real keys.
# Expected codes come from the §6.2 gate table: OK/warning-only = 0, every
# blocking row = 1. Run from `make test-cli`.
set -u
cd "$(dirname "$0")/.." || exit 1
VEC=test/vectors/pins
fails=0

# case: expected exit code, plus one row that must appear in the report
run() { # run <case> <want-rc> <want-row>
  local out rc
  out=$(python3 scripts/pins/pins.py check --offline-fixture "$VEC/$1" 2>&1); rc=$?
  if [ "$rc" -ne "$2" ]; then
    echo "FAIL pins_$1: rc=$rc want=$2" >&2; printf '%s\n' "$out" | sed 's/^/    | /' >&2
    fails=$((fails + 1)); return
  fi
  if ! printf '%s\n' "$out" | grep -qE "^$3"; then
    echo "FAIL pins_$1: missing row /^$3/" >&2; printf '%s\n' "$out" | sed 's/^/    | /' >&2
    fails=$((fails + 1)); return
  fi
  echo "PASS pins_$1"
}

[ -d "$VEC/ok" ] || { echo "SKIP pins_tool (missing $VEC)"; exit 0; }
command -v python3 >/dev/null 2>&1 || { echo "SKIP pins_tool (no python3)"; exit 0; }
command -v openssl  >/dev/null 2>&1 || { echo "SKIP pins_tool (no openssl)"; exit 0; }

run ok          0 'a\.test OK '
run new-key     1 'c\.test NEW-KEY '
run webpki      1 'a\.test WEBPKI-FAIL '
run full-scrape 1 'a\.test FULL-SCRAPE '
run unreachable 0 'a\.test UNREACHABLE '
run few-hosts   1 'pins: QUALIFIED 1 minimum 2'

# update must never touch the committed table: it runs here against a scratch
# copy of ntx_share_trackers.c, which is also how the report's diff is produced.
TMP=$(mktemp -d)
cp src/proto/ntx_share_trackers.c "$TMP/trk.c"
: > "$TMP/pins.txt"
out=$(python3 scripts/pins/pins.py update --offline-fixture "$VEC/new-key" \
      --trackers "$TMP/trk.c" --pins-txt "$TMP/pins.txt" 2>&1); rc=$?
if [ "$rc" -eq 0 ] && printf '%s\n' "$out" | grep -q '^--- ' \
   && grep -q '"c.test"' "$TMP/trk.c" && [ "$(wc -l < "$TMP/pins.txt")" -ge 3 ]; then
  echo "PASS pins_update_offline"
else
  echo "FAIL pins_update_offline: rc=$rc" >&2; printf '%s\n' "$out" | sed 's/^/    | /' >&2
  fails=$((fails + 1))
fi
rm -rf "$TMP"

if [ "$fails" -ne 0 ]; then echo "FAIL pins_tool: $fails"; exit 1; fi
echo PASS
