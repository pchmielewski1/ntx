#!/bin/sh
# Private-share end-to-end (plan Task I1 step 1-2, design §12).
#
#   flock /tmp/ntx-maketest.lock ./test/interop/share/share_e2e.sh   # make test-share
#
# What it proves, in one run of a build whose share-tracker table is pinned to a
# throwaway local HTTPS tracker:
#   1. `--share` of a 5 MiB random file reaches ready and prints its magnet on
#      stdout (docs/cli.md "Private shares" step 5);
#   2. a second ntx leeches that magnet through the pinned HTTPS tracker to
#      completion and the bytes match byte for byte;
#   3. the tracker saw two distinct peers for the hash and never a /scrape
#      without info_hash;
#   4. neither the share nor the leech produced any dht/pex diagnostic — BEP 27;
#   5. the .torrent written into store-dir A is mode 0600 and the shared file's
#      mtime is untouched (the share is read-only, §5.1/§5.4);
#   6. an inbound plaintext handshake for the shared hash is torn down with zero
#      bytes sent back (§7.1 strict MSE), observed against the seed's own listen
#      port with test/interop/v2/hs_capture.py's own helpers (imported only).
#
# Rules obeyed: POSIX sh only (this box runs dash — no <<<, no arrays, no
# bashisms). Ports are always OS-assigned (bind port 0; the tracker prints
# PORT=<n>) because other suites own 6975-6995. Every wait carries an explicit
# `timeout`, the trap kills only the PIDs this script recorded, and the whole
# run stays well under 180 s.
#
# Evidence lives under test/.scratch/share-e2e/ (git-ignored). It is deleted on
# success; a FAIL keeps it and names the assertion that broke. KEEP_EVIDENCE=1
# keeps it on success too.
set -eu

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" || exit 1

WORK="$ROOT/test/.scratch/share-e2e"
BIN=".sharetest_e2e.tmp"
SRC="$WORK/src"
A="$WORK/storeA"
B="$WORK/storeB"
CERTS="$WORK/certs"
NAME=share_e2e_payload.bin
TRK_PY="$ROOT/test/interop/share/tracker_https.py"
TPL="$ROOT/test/interop/share/trackers.inc.in"
HS_DIR="$ROOT/test/interop/v2"

SECS_START=$(date +%s)
PIDS=""

# --------------------------------------------------------------- plumbing ---
say() { printf 'share_e2e: %s\n' "$*"; }

# fail <assertion-name> [evidence-file...] — names the assertion, tails the evidence.
fail() {
    why=$1
    shift
    printf 'FAIL share_e2e: %s\n' "$why"
    for f in "$@"; do
        [ -f "$f" ] || continue
        printf -- '--- tail %s ---\n' "$f"
        tail -n 12 "$f" 2>/dev/null || true
    done
    exit 1
}

kill_pids() {
    for p in $PIDS; do
        kill "$p" 2>/dev/null || true
    done
    # Every child is a `timeout -k 5 N ...` wrapper, so TERM is enough; the sleep
    # gives the wrapper its kill-after deadline and ntx its best-effort `stopped`
    # announce. Then a bounded KILL for anything wedged.
    sleep 1
    for p in $PIDS; do
        kill -9 "$p" 2>/dev/null || true
    done
    PIDS=""
}

cleanup() {
    rc=$?
    kill_pids
    rm -f "$ROOT/$BIN" 2>/dev/null || true
    if [ "$rc" -eq 0 ] && [ "${KEEP_EVIDENCE:-0}" != 1 ]; then
        rm -rf "$WORK" 2>/dev/null || true
    fi
    return $rc
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

spawn() { PIDS="$PIDS $!"; } # record the pid of the most recent `... &`

count() { # count FILE PATTERN -> number of matching lines
    c=$(grep -c "$2" "$1" 2>/dev/null || true)
    printf '%s\n' "${c:-0}"
}

# poll <secs> <file> <basic-regex> -> 0 seen / 1 timeout
poll() {
    _s=$1 _f=$2 _pat=$3 _i=0
    while [ "$_i" -lt "$_s" ]; do
        if [ -f "$_f" ] && grep -q "$_pat" "$_f" 2>/dev/null; then return 0; fi
        sleep 1
        _i=$((_i + 1))
    done
    return 1
}

# count_distinct_peer_ids <tracker.log> <ih> -> distinct peer_id values announced
peer_ids() {
    grep "^ANN $2 " "$1" 2>/dev/null \
        | sed -n 's/.* peer_id=\([0-9a-f]*\).*/\1/p' | sort -u | grep -c . || true
}

# ---------------------------------------------------------------- preflight --
for f in "$TRK_PY" "$TPL" "$HS_DIR/hs_capture.py"; do
    [ -f "$f" ] || fail "missing $f"
done
for t in openssl python3 timeout stat find grep sed awk dd; do
    command -v "$t" >/dev/null 2>&1 || fail "missing tool $t"
done
[ -d src ] || fail "must run from the repo root (no src/ here)"

rm -rf "$WORK" 2>/dev/null || true
mkdir -p "$SRC" "$A" "$B" "$CERTS" || fail "cannot create $WORK"

# Build flags mirror the ntx-sharetest recipe, so the only difference from
# `make ntx-sharetest` is the rendered tracker table and the output name.
CC_BIN=${CC:-cc}
CFLAGS=${CFLAGS:--O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections}
HARDEN_CFLAGS=${HARDEN_CFLAGS:--fstack-protector-strong -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=2 -fPIE}
LDFLAGS=${LDFLAGS:--Wl,--gc-sections}
HARDEN_LDFLAGS=${HARDEN_LDFLAGS:--pie -Wl,-z,relro,-z,now,-z,noexecstack}
LDLIBS=${LDLIBS:--lm}

# ------------------------------------------------------- payload + cert ------
# The two pinned hosts are loopback aliases, not 127.0.0.1/localhost: the
# built-in dev pin for 127.0.0.1 is consulted BEFORE the share table
# (ntx_https_pin_lookup), so a generated leaf can never pin-match there, and
# localhost would need a DNS reply (DoH is unreachable in this sandbox).
# Aliases keep both hosts literal IPv4, so no resolver is involved at all.
IP_A=127.0.0.2
IP_B=127.0.0.3

say "payload: 5 MiB random"
dd if=/dev/urandom of="$SRC/$NAME" bs=1048576 count=5 >/dev/null 2>&1 || fail "dd payload"
[ "$(stat -c%s "$SRC/$NAME")" -eq 5242880 ] || fail "payload size is not 5 MiB"
MT0=$(stat -c '%Y.%y' "$SRC/$NAME")

say "cert: P-256 self-signed (openssl)"
CERT="$CERTS/tracker-cert.pem"
KEY="$CERTS/tracker-key.pem"
timeout 30 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -pkeyopt ec_param_enc:named_curve -sha256 -days 2 -nodes \
    -keyout "$KEY" -out "$CERT" -subj "/CN=$IP_A" \
    -addext "subjectAltName=IP:$IP_A,IP:$IP_B" >"$WORK/openssl.log" 2>&1 \
    || fail "openssl req (cert generation)" "$WORK/openssl.log"
[ -s "$CERT" ] && [ -s "$KEY" ] || fail "certificate or key not written" "$WORK/openssl.log"

# The pin is SHA-256 over the leaf's SubjectPublicKeyInfo, 64 lowercase hex —
# the exact form strk_raw wants (strk_hex32 in src/proto/ntx_share_trackers.c).
# The cert generated here is the one handed to the tracker below, so the pin and
# the served certificate cannot drift apart.
SPKI=$(timeout 30 sh -c 'openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256' _ "$CERT" | awk '{print $NF}')
case $SPKI in
    *[!0-9a-f]*) fail "SPKI pin is not lowercase hex: '$SPKI'" ;;
esac
[ "${#SPKI}" -eq 64 ] || fail "SPKI pin is not 64 hex chars: '$SPKI'"
say "pin: SPKI $SPKI"

# ---------------------------------------------------------------- tracker ----
say "tracker: HTTPS on an ephemeral port, $IP_A + $IP_B"
timeout -k 5 300 python3 "$TRK_PY" "$WORK/tracker.log" "$CERT" "$KEY" "$IP_A,$IP_B" \
    >"$WORK/port.txt" 2>"$WORK/tracker.err" &
spawn
poll 20 "$WORK/port.txt" '^PORT=[0-9][0-9]*$' || fail "tracker never bound in 20s" "$WORK/port.txt" "$WORK/tracker.err"
PORT=$(sed -n 's/^PORT=\([0-9][0-9]*\)$/\1/p' "$WORK/port.txt" | head -n 1)
[ -n "$PORT" ] || fail "tracker printed no PORT= line" "$WORK/port.txt"
say "tracker: $IP_A:$PORT and $IP_B:$PORT"

# ---------------------------------------------------------------- build -------
say "build: render trackers.inc, compile $BIN"
timeout 30 sed -e "s/@PORT@/$PORT/g" -e "s/@SPKI@/$SPKI/g" \
    -e "s/@IP_A@/$IP_A/g" -e "s/@IP_B@/$IP_B/g" "$TPL" >"$WORK/trackers.inc" \
    || fail "rendering trackers.inc"
if grep -q '@[A-Z_]*@' "$WORK/trackers.inc"; then
    fail "placeholders left in the rendered trackers.inc" "$WORK/trackers.inc"
fi
INC="$WORK/trackers.inc"
SRCS=$(find src -name '*.c')
# shellcheck disable=SC2086
timeout -k 5 180 "$CC_BIN" $CFLAGS $HARDEN_CFLAGS -DNTX_SHARE_TRACKERS_INC="\"$INC\"" \
    -o "$BIN" $SRCS $LDFLAGS $HARDEN_LDFLAGS $LDLIBS >"$WORK/build.log" 2>&1 \
    || fail "compiling the share-test binary" "$WORK/build.log"
[ -x "$ROOT/$BIN" ] || fail "the share-test binary was not produced" "$WORK/build.log"

# ---------------------------------------------------------------- seed -------
say "seed: --share $NAME (store A)"
timeout -k 5 150 "$ROOT/$BIN" --share="$SRC/$NAME" --allow-local-peers \
    --store-dir="$A" --no-port-map --port-lo=0 --port-hi=0 \
    --verbose --log="$WORK/seed.diag.log" </dev/null \
    >"$WORK/magnet.txt" 2>"$WORK/seed.err" &
spawn
SEED_PID=$!
# docs/cli.md: the magnet goes to stdout once a share tracker answered; this is
# the same line `ntx --share=f > link.txt` is documented to produce.
poll 60 "$WORK/magnet.txt" '^magnet:?xt=urn:btih:' \
    || fail "magnet not emitted within 60s" "$WORK/seed.err" "$WORK/seed.diag.log" "$WORK/tracker.log" "$WORK/tracker.err"
MAG=$(grep '^magnet:?xt=urn:btih:' "$WORK/magnet.txt" | head -n 1)
IH=$(printf '%s' "$MAG" | sed -n 's/.*urn:btih:\([0-9a-f]\{40\}\).*/\1/p')
[ "${#IH}" -eq 40 ] || fail "magnet carries no 40-hex urn:btih" "$WORK/magnet.txt"
if ! grep -q "tr=https%3A%2F%2F$IP_A%3A$PORT%2Fannounce" "$WORK/magnet.txt"; then
    fail "magnet has no tr= for the pinned tracker" "$WORK/magnet.txt"
fi
say "seed: ready, ih=$IH"

# ---------------------------------------------------------------- leech ------
say "leech: magnet -> store B"
timeout -k 5 150 "$ROOT/$BIN" --allow-local-peers --store-dir="$B" --no-port-map \
    --port-lo=0 --port-hi=0 --stats-json --verbose --log="$WORK/leech.diag.log" \
    "$WORK/magnet.txt" </dev/null >"$WORK/leech.ndjson" 2>"$WORK/leech.err" &
spawn
LEECH_PID=$!
poll 60 "$WORK/leech.ndjson" '"pct":100' || fail "leech did not complete within 60s" "$WORK/leech.ndjson" "$WORK/leech.err" "$WORK/leech.diag.log"
poll 15 "$B/$NAME" '.' >/dev/null 2>&1 || true
[ -f "$B/$NAME" ] || fail "downloaded file absent from store B" "$WORK/leech.err"

# ------------------------------------------------------------ assertions -----
# 1 — bytes
cmp "$SRC/$NAME" "$B/$NAME" || fail "cmp: downloaded bytes differ from the source" "$WORK/leech.err"

# 2 — tracker log: two distinct peers for this hash, zero /scrape without hash
PEERS=$(peer_ids "$WORK/tracker.log" "$IH")
[ "$PEERS" -ge 2 ] || fail "tracker log shows $PEERS distinct peer(s) for $IH, want >= 2" "$WORK/tracker.log"
SCRAPES=$(count "$WORK/tracker.log" '^SCRAPE_NOHASH')
[ "$SCRAPES" -eq 0 ] || fail "tracker log has $SCRAPES /scrape-without-info_hash hit(s)" "$WORK/tracker.log"
say "tracker: $PEERS distinct peers for $IH, $SCRAPES scrape-without-hash"

# 3 — no dht / pex diagnostics anywhere in either run (BEP 27 for a private share).
# The only legitimate source of the word is netx's fail-soft note when the shared
# UDP owner cannot bind the listen port ("dht standalone, utp off"), which says
# there is no UDP at all rather than that DHT ran; it is excluded by name, and the
# pattern still catches every real DHT/PEX diagnostic in src/.
for log in seed.err seed.diag.log leech.err leech.diag.log; do
    N=$(grep -inE 'dht|pex' "$WORK/$log" 2>/dev/null \
        | grep -vcE 'shared udp[6]? :.*dht standalone|shared udp[6]? :.*v6 utp off' || true)
    N=${N:-0}
    [ "$N" -eq 0 ] || { printf 'FAIL share_e2e: %s contains dht/pex line(s)\n' "$log"; grep -inE 'dht|pex' "$WORK/$log" | head -n 5; exit 1; }
done

# 4 — the .torrent written by the share is 0600
TR_COUNT=$(find "$A" -maxdepth 1 -type f -name '*.torrent' | wc -l)
[ "$TR_COUNT" -eq 1 ] || fail "expected exactly 1 .torrent in store A, found $TR_COUNT"
TORRENT=$(find "$A" -maxdepth 1 -type f -name '*.torrent' | head -n 1)
MODE=$(stat -c '%a' "$TORRENT")
[ "$MODE" = "600" ] || fail "$TORRENT has mode $MODE, want 600"

# 5 — the shared file was never written
MT1=$(stat -c '%Y.%y' "$SRC/$NAME")
[ "$MT0" = "$MT1" ] || fail "source mtime changed: '$MT0' -> '$MT1'"

# 6 — inbound plaintext for the shared hash is dropped without a reply (§7.1)
SEED_PORT=$(grep "^ANN $IH " "$WORK/tracker.log" | sed -n 's/^ANN [0-9a-f]* [0-9.]* \([0-9]*\) started .*/\1/p' | head -n 1)
[ -n "$SEED_PORT" ] || fail "tracker log has no started announce for $IH" "$WORK/tracker.log"
BEFORE=$(count "$WORK/seed.err" 'plaintext_strict_share')
say "probe: inbound plaintext -> seed 127.0.0.1:$SEED_PORT"

timeout -k 5 25 python3 - "$SEED_PORT" "$IH" "$HS_DIR" <<'PY' >"$WORK/probe.out" 2>"$WORK/probe.err"
# Inbound-plaintext probe for §7.1, built on test/interop/v2/hs_capture.py's own
# helpers (imported, never edited): a second seeder greeting the share with a
# clear BitTorrent handshake must be dropped before ntx sends a single byte.
import os
import socket
import sys
import time

hs_dir = sys.argv[3]
sys.path.insert(0, hs_dir)
import hs_capture as hc  # noqa: E402

port, ih = int(sys.argv[1]), bytes.fromhex(sys.argv[2])
if len(ih) != 20:
    print("PROBE_ERR bad-infohash")
    sys.exit(2)
hs = bytes([19]) + hc.MAGIC + b"\x00" * 8 + ih + b"-SE0001-" + os.urandom(12)
if len(hs) != hc.HANDSHAKE_LEN:
    print("PROBE_ERR bad-handshake-length")
    sys.exit(2)
s = None
last = None
for _ in range(10):  # the listen socket is up for the seed's whole life; a bare
    try:            # ECONNREFUSED here is the loopback port allocator racing us
        s = socket.create_connection(("127.0.0.1", port), 2)
        break
    except OSError as e:
        last = e
        time.sleep(0.5)
if s is None:
    print("PROBE_ERR connect=%s" % last)
    sys.exit(2)
s.settimeout(3)
try:
    s.sendall(hs)
except OSError as e:
    print("PROBE_ERR send=%s" % e)
    sys.exit(2)
got = b""
try:
    got = s.recv(4096)
except OSError:
    pass
closed = got == b""
try:
    closed = s.recv(1) == b""
except OSError:
    closed = True
s.close()
print("PROBE bytes=%d plain=%d closed=%d" % (len(got), int(hc.is_plaintext(got)), int(closed)))
PY
[ -s "$WORK/probe.out" ] || fail "plaintext probe printed nothing" "$WORK/probe.err"
say "probe: $(cat "$WORK/probe.out")"
grep -q '^PROBE bytes=0 plain=0' "$WORK/probe.out" || fail "plaintext probe received a reply" "$WORK/probe.out" "$WORK/probe.err"
poll 10 "$WORK/seed.err" 'plaintext_strict_share' || fail "seed never logged plaintext_strict_share" "$WORK/seed.err"
AFTER=$(count "$WORK/seed.err" 'plaintext_strict_share')
[ "$AFTER" -gt "$BEFORE" ] || fail "plaintext drop not newly observed ($BEFORE -> $AFTER)" "$WORK/seed.err"

# --------------------------------------------------------------- wrap-up -----
kill "$SEED_PID" 2>/dev/null || true
kill "$LEECH_PID" 2>/dev/null || true
say "all assertions ok in $(( $(date +%s) - SECS_START ))s"
printf 'PASS share_e2e\n'
