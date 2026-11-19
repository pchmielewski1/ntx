#!/usr/bin/env bash
# JSON Control API e2e gate (§12): pipe instead of TTY, python3 as parser.
#
# Variant A (binding): the EOF assertion runs as a SEPARATE eof_probe process
# BEFORE the main pass; the main pass keeps its command channel open until the
# quit (seq=8), which is the LAST command — so the quit ack is the last line of
# the stream (§8: "graceful; exit code 0; the last line is the ack").
#
# Mechanism note: the worktree lives on an sshfs mount that refuses mkfifo
# ("Operation not permitted"), so the parent-controlled command channel is a
# real pipe via bash coproc (pipe(2)) instead of a FIFO file. Semantics are the
# same as a fifo design: the driver holds the write end open across
# the pass, and closing it is the EOF event the probe asserts on (§3.9).
#
# Scratch: repo-local test/.scratch/9/interop-ipc/ only (house convention,
# cf. test/interop/v2/interop_v2.sh; never /tmp). Every spawned pid is tracked
# and reaped through the EXIT/INT/TERM traps.
set -uo pipefail

# ------------------------------------------------------------- watchdog ------
# Mirror of the v2 gate: re-exec under a hard timeout so a wedged pipe can
# never hang the caller. The guard env var stops the child from re-arming.
if [ "${NTX_IPC_WATCHDOG:-0}" != "1" ]; then
    export NTX_IPC_WATCHDOG=1
    exec timeout -k 5 300 bash "$0" "$@"
fi

here=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
ROOT=$(CDPATH= cd -- "$here/../../.." && pwd)
cd "$ROOT" || exit 1

WORK="$ROOT/test/.scratch/9/interop-ipc"
PIDS=""
MAIN_OUT=""
MAIN_ERR=""

log()  { printf 'interop-ipc: %s\n' "$*"; }
die() {
    log "FAIL: $*"
    [ -n "$MAIN_OUT" ] && tail -n 5 "$MAIN_OUT" >&2 2>/dev/null || true
    [ -n "$MAIN_ERR" ] && tail -n 5 "$MAIN_ERR" >&2 2>/dev/null || true
    exit 1
}

# ---------------------------------------------------------------- reaping ----
kill_pids() {
    local p
    for p in ${PIDS:-}; do kill "$p" 2>/dev/null || true; done
    sleep 0.3
    for p in ${PIDS:-}; do kill -9 "$p" 2>/dev/null || true; done
    wait 2>/dev/null || true
    PIDS=""
}
cleanup() { kill_pids; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

fresh_dir() { # reset scratch (v2 pattern); hard-guarded to the one WORK root
    local d=$1
    case "$d" in
        */interop-ipc) ;;
        *) log "internal: refusing fresh_dir($d)"; exit 1 ;;
    esac
    rm -rf "$d" 2>/dev/null || { sleep 1; rm -rf "$d" 2>/dev/null; } || true
    mkdir -p "$d"
}

[ -x ./ntx ] || make ntx || die "build failed"
fresh_dir "$WORK"

# wait_for substr timeout_s file label — grep on raw substrings (§10 style)
wait_for() {
    local needle=$1 tmo=$2 file=$3 label=$4
    local end=$(( $(date +%s) + tmo ))
    until grep -q -- "$needle" "$file" 2>/dev/null; do
        kill -0 "$pid" 2>/dev/null || die "$label died waiting for: $needle"
        [ "$(date +%s)" -le "$end" ] || die "timeout waiting for: $needle"
        sleep 0.05
    done
}

# ============================================================ A1: eof_probe ===
# §3.9: EOF on stdin closes the COMMAND CHANNEL only — the daemon keeps serving.
log "eof_probe: starting a separate ntx for the §3.9 EOF assertion"
E_OUT="$WORK/out2.ndjson"
E_ERR="$WORK/err2.log"
rm -f "$E_OUT" "$E_ERR"
coproc eofp { exec ./ntx --stats-json --store-dir="$WORK/dl2" >"$E_OUT" 2>"$E_ERR"; }
pid=$eofp_PID
EFD=${eofp[1]}                 # keep the write fd in a scalar: bash unsets the
PIDS="$PIDS $eofp_PID"         # coproc array once the child is reaped
wait_for '"type":"hello"' 5 "$E_OUT" eof_probe
printf '{"cmd":"ping","seq":1}\n' >&"$EFD"
exec {EFD}>&-                  # EOF: closes the channel, NOT the session (§3.9)
sleep 0.4                   # brief-sanctioned settle for the last snapshots
kill -0 "$pid" 2>/dev/null || die "§3.9: session died on EOF"
grep -q '"type":"stats"' "$E_OUT" || die "§3.9: no stats after EOF"
kill -TERM "$pid" 2>/dev/null || true
wait "$pid" 2>/dev/null; rc2=$?
[ "$rc2" -eq 0 ] || die "§3.9: EOF+SIGTERM rc=$rc2 (want 0)"
log "eof_probe: alive after EOF, stats flowed, SIGTERM rc=0"

# ============================================================== A2: main pass =
log "main pass: scripted vector seq=1..8, quit last, channel open throughout"
MAIN_OUT="$WORK/out.ndjson"
MAIN_ERR="$WORK/err.log"
rm -f "$MAIN_OUT" "$MAIN_ERR"
coproc main { exec ./ntx --stats-json --store-dir="$WORK/dl" >"$MAIN_OUT" 2>"$MAIN_ERR"; }
pid=$main_PID
MFD=${main[1]}                 # scalar fd handle (coproc array dies with the job)
PIDS="$PIDS $main_PID"
say() { printf '%s\n' "$1" >&"$MFD"; }

wait_for '"type":"hello"' 5 "$MAIN_OUT" main      # §7: first line, once
MAG="magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=IpcTest"

say '{"cmd":"ping","seq":1}'
wait_for '"seq":1,"cmd":"ping"' 3 "$MAIN_OUT" main
say "{\"cmd\":\"add\",\"seq\":2,\"magnet\":\"$MAG\"}"
wait_for '"seq":2,"cmd":"add"' 3 "$MAIN_OUT" main
wait_for '"i":0' 3 "$MAIN_OUT" main
say '{"cmd":"pause","seq":3,"i":0}'
wait_for '"seq":3,"cmd":"pause","i":0,"ok":1,"state":3' 3 "$MAIN_OUT" main
say '{"cmd":"pause","seq":4,"i":0}'               # idempotent (§6.2)
wait_for '"seq":4,"cmd":"pause"' 3 "$MAIN_OUT" main
say '{"cmd":"resume","seq":5,"i":0}'
wait_for '"seq":5,"cmd":"resume","i":0,"ok":1,"state":0' 3 "$MAIN_OUT" main  # paused_from = META
# R8: a second torrent whose dn is 60 × U+00E9 (120 bytes of 2-byte characters).
# The stats `name` field is 48 bytes, so the name MUST be cut on a character
# boundary and every emitted line must stay decodable — assert_ipc.py parses the
# whole stream with a strict decoder, which is exactly what R8 broke.
DNR=""
for _r8 in $(seq 1 60); do DNR="${DNR}%C3%A9"; done
say "{\"cmd\":\"add\",\"seq\":11,\"magnet\":\"magnet:?xt=urn:btih:1123456789abcdef0123456789abcdef01234567&dn=$DNR\"}"
wait_for '"seq":11,"cmd":"add"' 3 "$MAIN_OUT" main
say '{"cmd":"status"}'                            # §6.2: a snapshot outside the 100 ms tick
wait_for '"type":"stats"' 1 "$MAIN_OUT" main      # immediately — 100 ms margin
say 'junk-no-braces'                              # §6.4: gate before any mutation
wait_for '"code":"bad_json"' 2 "$MAIN_OUT" main
say '{"cmd":"remove","seq":6,"i":0}'
wait_for '"seq":6,"cmd":"remove","i":0,"ok":1,"state":5' 3 "$MAIN_OUT" main
say '{"cmd":"remove","seq":7,"i":0}'              # repeat → no_slot
wait_for '"seq":7,"cmd":"remove","i":0,"ok":0,"code":"no_slot"' 3 "$MAIN_OUT" main

# §11 share: synchronous errors only, both io. A missing path fails the open,
# a directory fails S_ISREG — both before any hashing, and a build whose share
# tracker list is unusable answers no_trackers instead (§6.4), so the wait
# accepts either and assert_ipc.py pins the accepted set.
mkdir -p "$WORK/adir"
say "{\"cmd\":\"share\",\"seq\":9,\"path\":\"$WORK/nope.bin\"}"
wait_for '"seq":9,"cmd":"share","ok":0,"code":"' 3 "$MAIN_OUT" main
grep -q '"seq":9,"cmd":"share","ok":0,"code":"io"' "$MAIN_OUT" ||
    grep -q '"seq":9,"cmd":"share","ok":0,"code":"no_trackers"' "$MAIN_OUT" ||
    die "share of a missing file is neither io nor no_trackers"
say "{\"cmd\":\"share\",\"seq\":10,\"path\":\"$WORK/adir\"}"
wait_for '"seq":10,"cmd":"share","ok":0,"code":"' 3 "$MAIN_OUT" main
grep -q '"seq":10,"cmd":"share","ok":0,"code":"io"' "$MAIN_OUT" ||
    grep -q '"seq":10,"cmd":"share","ok":0,"code":"no_trackers"' "$MAIN_OUT" ||
    die "share of a directory is neither io nor no_trackers"

# R30: a decoded \u0000 must not silently cut the path — pre-fix this shared the
# file "a" below with ack ok:1. The whole document is bad_json instead.
printf 'R30FILE\n' > "$WORK/a"
say "{\"cmd\":\"share\",\"seq\":12,\"path\":\"$WORK/a\\u0000b\"}"
wait_for '"seq":12,"cmd":"share","ok":0,"code":"bad_json"' 3 "$MAIN_OUT" main

# ---------------------------------------------------------------------------
# V04 (d): the asynchronous half of §11 over the REAL pipe.
#
# Everything above ends at an ack. The two share probes (seq 9, 10) are refused
# synchronously, so nothing that ever left this process was a "share" event: the
# ordering docs/json-api.md pins ("per tick: ack, then share, then stats") and
# the identity of a `share` that carries `torrent` were only ever seen inside
# t_ipc_ctrl.c, where g_share_evt is a buffer the test itself holds and
# ipc_share_events is called by hand. This leg is a second, real ntx on a real
# pipe (coproc, same as the main pass) whose share actually reaches READY, so
# every byte asserted here was written by the shipped emitter to a real stdout.
#
# Reaching READY needs a reachable pinned tracker (§5.5: one `started` answer),
# so this leg builds its own client the way test/interop/share/share_e2e.sh
# does — the ephemeral HTTPS tracker and the rendered trackers.inc, over the two
# loopback aliases the pin pool leaves free. It is a different binary from the
# ./ntx above, which is exactly why it gets its own process, its own store dir
# and its own assert_ipc.py call: the gate under test here is the JSON share
# stream, not the release tracker table.
# ---------------------------------------------------------------------------
# Evidence for this leg only: die() would tail the MAIN pass stream instead.
vdie() {
    log "FAIL: $*"
    [ -f "$V4_OUT" ] && { printf -- '--- tail v04.ndjson ---\n'; tail -n 6 "$V4_OUT" >&2; }
    [ -f "$V4_ERR" ] && { printf -- '--- tail v04.err ---\n'; tail -n 6 "$V4_ERR" >&2; }
    exit 1
}

V4="$WORK/v04"
V4BIN="$WORK/ntx-v04"
V4_OUT="$WORK/v04.ndjson"
V4_ERR="$WORK/v04.err"
rm -rf "$V4" "$V4BIN"
mkdir -p "$V4/store"
for f in "$ROOT/test/interop/share/tracker_https.py" \
         "$ROOT/test/interop/share/trackers.inc.in" \
         "$ROOT/test/vectors/share/one_piece_16k/data.bin" \
         "$ROOT/test/vectors/share/one_piece_16k/meta.torrent" \
         "$ROOT/test/vectors/share/one_piece_16k/manifest.txt"; do
    [ -f "$f" ] || vdie "V04 leg: missing $f"
done

# --- the fixture, and its identity taken from the manifest, not from ntx -----
cp "$ROOT/test/vectors/share/one_piece_16k/data.bin" "$V4/one_piece_16k.bin"
cp "$ROOT/test/vectors/share/one_piece_16k/meta.torrent" "$V4/meta.torrent"
MT0=$(md5sum < "$V4/meta.torrent")
IH_EXP=$(awk '/^ih_sha1:/{print $2}' "$ROOT/test/vectors/share/one_piece_16k/manifest.txt")
IH2_EXP=$(awk '/^ih_sha256:/{print $2}' "$ROOT/test/vectors/share/one_piece_16k/manifest.txt")
case ${IH_EXP:-x} in
    *[!0-9a-f]*|"") vdie "V04 leg: no ih_sha1 in the fixture manifest" ;;
esac
[ "${#IH_EXP}" -eq 40 ] || vdie "V04 leg: ih_sha1 is not 40 hex: '$IH_EXP'"
[ "${#IH2_EXP}" -eq 64 ] || vdie "V04 leg: ih_sha256 is not 64 hex: '$IH2_EXP'"

# --- the pinned HTTPS tracker, one process, two loopback aliases -------------
# Same two addresses as share_e2e.sh and for the same reason: the built-in pin
# pool owns 127.0.0.1 for the dev leaf and is consulted before the share table,
# so a generated leaf can never pin-match there; and the hosts stay literal
# IPv4, so no resolver is involved.
IP_A=127.0.0.2
IP_B=127.0.0.3
mkdir -p "$V4/certs"
timeout -k 5 60 openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
    -pkeyopt ec_param_enc:named_curve -sha256 -days 2 -nodes \
    -keyout "$V4/tracker-key.pem" -out "$V4/tracker-cert.pem" -subj "/CN=$IP_A" \
    -addext "subjectAltName=IP:$IP_A,IP:$IP_B" >"$V4/openssl.log" 2>&1 \
    || vdie "V04 leg: openssl req failed: $(tail -3 "$V4/openssl.log")"
SPKI=$(timeout 60 sh -c 'openssl x509 -in "$1" -pubkey -noout | openssl pkey -pubin -outform DER | openssl dgst -sha256' _ "$V4/tracker-cert.pem" | awk '{print $NF}')
[ "${#SPKI}" -eq 64 ] || vdie "V04 leg: SPKI pin is not 64 hex: '$SPKI'"

timeout -k 5 300 python3 "$ROOT/test/interop/share/tracker_https.py" \
    "$V4/tracker.log" "$V4/tracker-cert.pem" "$V4/tracker-key.pem" "$IP_A,$IP_B" \
    >"$V4/port.txt" 2>"$V4/tracker.err" &
PIDS="$PIDS $!"
for i in $(seq 1 40); do
    grep -q '^PORT=[0-9][0-9]*$' "$V4/port.txt" 2>/dev/null && break
    sleep 0.25
done
PORT=$(sed -n 's/^PORT=\([0-9][0-9]*\)$/\1/p' "$V4/port.txt" | head -n 1)
[ -n "$PORT" ] || vdie "V04 leg: tracker never bound: $(cat "$V4/port.txt" "$V4/tracker.err" 2>/dev/null)"

# --- the client: production source, test tracker table ----------------------
timeout -k 5 60 sed -e "s/@PORT@/$PORT/g" -e "s/@SPKI@/$SPKI/g" \
    -e "s/@IP_A@/$IP_A/g" -e "s/@IP_B@/$IP_B/g" \
    "$ROOT/test/interop/share/trackers.inc.in" > "$V4/trackers.inc" \
    || vdie "V04 leg: rendering trackers.inc"
grep -q '@[A-Z_]*@' "$V4/trackers.inc" && vdie "V04 leg: placeholders left in trackers.inc"
: > "$V4_OUT"
if ! timeout -k 5 240 ${CC:-cc} ${CFLAGS:--O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections} \
        -DNTX_SHARE_TRACKERS_INC="\"$V4/trackers.inc\"" -o "$V4BIN" \
        $(find src -name '*.c') ${LDFLAGS:--Wl,--gc-sections} ${LDLIBS:--lm} \
        >"$V4/build.log" 2>&1; then
    vdie "V04 leg: client build failed: $(tail -5 "$V4/build.log")"
fi
# The table is test-only, and the .inc says so on stderr at start; a client that
# did not print it is not the client this leg was written against.
"$V4BIN" --help >"$V4/help.out" 2>"$V4/help.err" || true
grep -q 'NTX-TEST-TRACKERS' "$V4/help.err" \
    || vdie "V04 leg: the client was not built with the test tracker table"

# The per-tick order of the three emitters, pinned where it is actually decided.
#
# docs/json-api.md promises "per event-loop tick: ack, then share, then stats",
# and that order is a property of main()'s for(;;) loop — src/ntx_main.c calls
# ipc_pump_tick (acks + the status snapshot), then ipc_share_events, then the
# 100 ms snapshot. No stream observation can pin it: a share needs seconds to
# hash, so by the time the event lands the loop has emitted a hundred cadence
# snapshots on both sides of it and the relative position of ONE snapshot says
# nothing (moving the drain below the snapshot block leaves this leg green).
# t_ipc_ctrl.c pins the contract per tick, but it calls the three functions
# itself, so it too would stay green if the loop reordered them. This is the
# assertion that is not vacuous against that change, and it is the same style of
# structural check the seam grep above is.
V4SRC="$ROOT/src/ntx_main.c"
n_pump=$(grep -n 'ipc_pump_tick(s);' "$V4SRC" | head -1 | cut -d: -f1)
n_evq=$(grep -n 'ipc_share_events(s);' "$V4SRC" | head -1 | cut -d: -f1)
n_snap=$(grep -n 'ntx_stats_to_json(&st, g_js' "$V4SRC" | sed -n '2p' | cut -d: -f1)
[ -n "$n_pump" ] && [ -n "$n_evq" ] && [ -n "$n_snap" ] \
    || vdie "V04 leg: an emitter call vanished from $V4SRC (pump=$n_pump evq=$n_evq snap=$n_snap)"
[ "$(grep -c 'ipc_pump_tick(s);' "$V4SRC")" = "1" ] \
    && [ "$(grep -c 'ipc_share_events(s);' "$V4SRC")" = "1" ] \
    || vdie "V04 leg: an emitter is called from two places — the tick order is no longer one place to read"
{ [ "$n_pump" -lt "$n_evq" ] && [ "$n_evq" -lt "$n_snap" ]; } \
    || vdie "V04 leg: the tick emits out of order — pump@$n_pump share@$n_evq snapshot@$n_snap (docs/json-api.md wants ack, share, stats)"
log "V04 leg: tick order pinned in source — pump@$n_pump < share@$n_evq < snapshot@$n_snap"

# --- the run: real pipe, --stats-json, quit last ----------------------------
log "V04 leg: scripted share (from a .torrent) to READY over a real pipe"
# The braces keep bash's "coproc [main] still exists" notice off the gate's own
# stderr — the child's stderr still goes to its own file inside the body.
{ coproc v04 { exec "$V4BIN" --stats-json --allow-local-peers --no-port-map \
                   --port-lo=0 --port-hi=0 --store-dir="$V4/store" \
                   >"$V4_OUT" 2>"$V4_ERR"; }; } 2>/dev/null
vpid=${v04_PID}
VFD=${v04[1]}
PIDS="$PIDS $vpid"
vsay() { printf '%s\n' "$1" >&"$VFD"; }
pid=$vpid                     # wait_for's liveness handle
wait_for '"type":"hello"' 10 "$V4_OUT" v04

# Three commands in ONE write, so ipc_pump_tick dispatches all of them inside
# a single event-loop tick — the unit of the ordering contract. `status` has no
# ack (§6.2), its only footprint is the snapshot ipc_on_line emits itself: that
# is the stats line that must sit BEFORE the ack, and the cadence snapshot of a
# later tick is the one that must sit AFTER the event.
vsay "{\"cmd\":\"status\",\"seq\":13}"
vsay "{\"cmd\":\"share\",\"seq\":14,\"path\":\"$V4/one_piece_16k.bin\",\"torrent\":\"$V4/meta.torrent\"}"
vsay "{\"cmd\":\"status\",\"seq\":15}"

ack_ok=""
for i in $(seq 1 60); do
    grep -q '"seq":14,"cmd":"share","i":0,"ok":1,"state":' "$V4_OUT" 2>/dev/null && ack_ok=1 && break
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.25
done
[ -n "$ack_ok" ] || vdie "V04 leg: share ack never arrived: $(tail -5 "$V4_OUT") $(tail -3 "$V4_ERR")"
kill -0 "$vpid" 2>/dev/null || vdie "V04 leg: the client died on a share command: $(cat "$V4_ERR")"

ev=""
for i in $(seq 1 240); do
    grep -q '"type":"share"' "$V4_OUT" 2>/dev/null && ev=1 && break
    kill -0 "$vpid" 2>/dev/null || vdie "V04 leg: died before the share event: $(tail -5 "$V4_OUT") $(tail -3 "$V4_ERR")"
    sleep 0.25
done
[ -n "$ev" ] || vdie "V04 leg: no share event within 60s: $(tail -5 "$V4_OUT") $(tail -3 "$V4_ERR")"

# One event, ever: §11 answers every queued share exactly once. Let a further
# second pass so a duplicate emitted on a later tick cannot hide behind speed.
sleep 1

# Quit first, then assert. Everything this leg checks — the event, the tracker
# request that produced it, the bytes of the .torrent — is already on disk or on
# the wire by the time the event is out, so ending the session here both keeps
# §8's "the quit ack is the last line" true for assert_ipc.py and means every
# later check reports the failure of ITS OWN assertion instead of a timeout.
vsay '{"cmd":"quit","seq":16}'
for i in $(seq 1 40); do
    kill -0 "$vpid" 2>/dev/null || break
    sleep 0.25
done
kill -0 "$vpid" 2>/dev/null && vdie "V04 leg: quit did not end the session"
exec {VFD}>&-
wait "$vpid" 2>/dev/null; vrc=$?
[ "$vrc" -eq 0 ] || vdie "V04 leg: quit rc=$vrc (want 0)"

# The field values, the exact counts and the ordering are asserted by the
# parser, not by grep: the stream is strict-decoded line by line and the
# expected values come from the fixture's own manifest.
python3 "$here/assert_ipc.py" "$V4_OUT" \
    --want 14=share --want 16=quit \
    --share-ok 1 \
    --ih "$IH_EXP" --ih2 "$IH2_EXP" \
    --name one_piece_16k.bin --torrent "$V4/meta.torrent" \
    --tracker "tr=https%3A%2F%2F$IP_A%3A$PORT%2Fannounce" \
    --ordering 14 --stats-min 3 \
    || die "assert_ipc.py rejected the V04 share stream"

# The `started` that made it READY really left the process (§5.5) — without it
# the event could only be a line the code produced without ever reaching a
# pinned tracker, and the leg would be asserting nothing.
for i in $(seq 1 20); do
    grep -Eq "^ANN $IH_EXP [0-9.]+ [0-9]+ started " "$V4/tracker.log" 2>/dev/null && break
    sleep 0.25
done
grep -Eq "^ANN $IH_EXP [0-9.]+ [0-9]+ started " "$V4/tracker.log" \
    || vdie "V04 leg: tracker never saw a started for $IH_EXP: $(cat "$V4/tracker.log")"

# §5.6: the operator's .torrent is never rewritten, and a from-torrent share
# writes no metainfo of its own into the store.
MT1=$(md5sum < "$V4/meta.torrent")
[ "$MT0" = "$MT1" ] || vdie "V04 leg: the client rewrote $V4/meta.torrent"
[ -z "$(find "$V4/store" -name '*.torrent' -print -quit 2>/dev/null)" ] \
    || vdie "V04 leg: a from-torrent share wrote a .torrent into $V4/store: $(find "$V4/store" -type f)"

log "V04 leg: stats -> ack -> share -> stats over a real pipe, from-torrent identity, rc=0"
pid=$main_PID                    # wait_for's liveness handle goes back to the main pass

# Variant A: quit is the LAST command; fd stays open until the ack lands.
say '{"cmd":"quit","seq":8}'
wait_for '"seq":8,"cmd":"quit","ok":1' 3 "$MAIN_OUT" main
exec {MFD}>&-
wait "$pid" 2>/dev/null; rc=$?
[ "$rc" -eq 0 ] || die "quit rc=$rc (want 0)"

python3 "$here/assert_ipc.py" "$MAIN_OUT" || die "assert_ipc.py rejected the stream"
log "stream validated by assert_ipc.py"
echo "interop_ipc PASS"
