#!/bin/sh
# Manual live-network smoke test: run ntx against a REAL swarm for N seconds and
# check that peers were reached and data flowed. Not part of `make test` (needs the
# internet and a magnet/torrent you are allowed to download).
#
#   test/run_magnet_120.sh 'magnet:?xt=urn:btih:…' [seconds]
#   test/run_magnet_120.sh path/to/file.torrent    [seconds]
#   test/run_magnet_120.sh link.txt                [seconds]   (file with one magnet line)
#
# A freely redistributable torrent works well, e.g. the official one of a Linux
# distribution. link.txt in this repo is a FICTIONAL demo and will (correctly) fail.
set -eu
cd "$(dirname "$0")/.."
src="${1:-}"
timeout="${2:-120}"
if [ -z "$src" ]; then
    echo "usage: $0 <magnet|link.txt|.torrent> [seconds]" >&2
    exit 2
fi
log=".test.magnet.log"
store="$(mktemp -d)"
trap 'rm -rf "$store"' EXIT

make -s ntx
./ntx --verbose --store-dir="$store" "$src" >"$log" 2>&1 &
pid=$!
sleep "$timeout"
kill "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null || true

ok=0
grep -E 'peer drop|hs timeout batch|peer buf full|status peers|req timeout|trk boost' "$log" | tail -25 || true
echo "--- last status lines ---"
grep -E '@dl|@wait|@choked|meta-wait|pe[0-9]+/' "$log" | tail -8 || true

pe_ok_max=$(grep -oE 'pe[0-9]+/[0-9]+/[0-9]+u[0-9]+' "$log" | sed -E 's/pe[0-9]+\/[0-9]+\/([0-9]+)u.*/\1/' | sort -n | tail -1)
pe_ok_max=${pe_ok_max:-0}

if [ "$pe_ok_max" -ge 2 ] 2>/dev/null; then
    echo "PASS magnet sustained peers_ok max=$pe_ok_max"
    ok=1
fi
if grep -qE '@dl' "$log" && tail -60 "$log" | grep -qE '@dl'; then
    echo "PASS magnet still downloading at end"
    ok=1
fi
if grep -qE '@dl' "$log"; then
    last_dl=$(grep -oE '[0-9]+K/s|[0-9]+M/s|[0-9]+B/s' "$log" | tail -20 | grep -v '0B/s' | tail -1 || true)
    if [ -n "$last_dl" ]; then
        echo "PASS magnet had non-zero speed ($last_dl)"
        ok=1
    fi
fi
if [ "$ok" -eq 0 ]; then
    echo "FAIL magnet ${timeout}s (need @dl + peers_ok>=2 sustained; see $log)"
    tail -40 "$log"
    exit 1
fi
exit 0
