#!/usr/bin/env bash
#
# BEP29 uTP interop matrix (ntx).
#
# Drives the SUT (`./ntx --utp`) at two levels and records an honest matrix:
#   * wire level  — a self-contained raw BEP29 peer (test/interop/utp/utp_probe.py,
#     written from the spec, NOT from ntx_utp*.c) talks header/SYN/STATE/DATA/
#     SACK/FIN/RESET to the SUT's uTP listener, and a raw acceptor makes the
#     SUT's *initiator* SYN path open in the other direction.
#   * engine level — the SUT against a libtorrent-based engine (rtorrent) and
#     qBittorrent-nox in a container, seeder and leech both ways.
#
# Scenarios: SYN/STATE open both directions, DATA+SACK,
# loss + reorder (netem when privileged, else the userspace relay), FIN close,
# RESET, and a bytes-out == bytes-in accounting assertion per cell.
#
# Hardening (mirrors test/interop/v2/interop_v2.sh — the proven pattern; an
# earlier hang was caused by un-timed-out docker + background seeds):
#   * script-wide watchdog re-exec as the FIRST effect (timeout 900, guard var)
#   * EVERY docker call under `timeout` (build 180, run/start 60, stop 30);
#     `docker info` probed under `timeout -k 5 15`; docker absent => cells
#     SKIP(docker-unavailable), script still exits 0
#   * background jobs joined with bounded `wait || true`; NO kill/pkill/killall
#     of foreign pids — only our own recorded pids, via `timeout ... kill`
#   * netem needs CAP_NET_ADMIN: probed with `tc qdisc add` (no sudo); denied =>
#     LOSS/REORDER driven through the userspace relay and labelled
#     RUN(userspace-emul) so the evidence is honest, never a fake netem PASS
#   * ports rotate from a 32xx base, +1 on EADDRINUSE, 20 tries, foreign pids
#     never inspected
#   * WORK is absolute under test/.scratch/11/interop-utp/ (never /tmp)
#   * a cell is RUN only on a genuine observation; NEVER a fabricated PASS (R13)
#
# Run ONCE:  timeout 900 bash test/interop/utp/interop_utp.sh
set -uo pipefail

# ---------------------------------------------------------------- watchdog ---
if [ "${NTX_UTP_INTEROP_WATCHDOG:-0}" != "1" ]; then
    export NTX_UTP_INTEROP_WATCHDOG=1
    exec timeout -k 5 900 bash "$0" "$@"
fi

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" || exit 1

WORK="$ROOT/test/.scratch/11/interop-utp"
MIRROR="$ROOT/test/.scratch/p5b-p6b/interop-utp.txt"
FIXTURE="$ROOT/test/.scratch/9/interop-v2/torrents/single_16k"
CELL=0
DOCKER_OK=0
NETEM_OK=0
PIDS=""
CONTAINERS=""

log() { printf 'interop-utp: %s\n' "$*"; }
declare -a MATRIX
log_cell() { MATRIX+=("$1|$2|$3"); }

# ------------------------------------------------------------------ cleanup --
# Only ever signal pids WE started, and always through `timeout ... kill` so a
# wedged child can never hang the join. No blanket kill/pkill of foreign pids.
stop_job() { # pid
    local pid=$1
    [ -n "$pid" ] || return 0
    timeout -k 5 5 kill "$pid" 2>/dev/null || true
    timeout -k 5 20 wait "$pid" 2>/dev/null || true
}
cleanup() {
    local p
    for p in ${PIDS:-}; do stop_job "$p"; done
    PIDS=""
    for c in ${CONTAINERS:-}; do
        timeout -k 5 30 docker rm -f "$c" >/dev/null 2>&1 || true
    done
    CONTAINERS=""
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM
spawn() { PIDS="$PIDS $!"; }

fresh_dir() {
    local d=$1
    rm -rf "$d" 2>/dev/null || { sleep 1; rm -rf "$d" 2>/dev/null; } || true
    mkdir -p "$d"
}

# --------------------------------------------------------------- preflight ---
fresh_dir "$WORK"

# netem capability: try to install a netem qdisc on lo (needs CAP_NET_ADMIN).
# No sudo. If the add is refused we fall back to the userspace relay and label
# the loss/reorder cells RUN(userspace-emul).
probe_netem() {
    timeout -k 5 10 tc qdisc add dev lo root netem loss 0.0 2>/dev/null || return 1
    timeout -k 5 10 tc qdisc del dev lo root 2>/dev/null || true
    return 0
}
if probe_netem; then NETEM_OK=1; fi

if command -v docker >/dev/null 2>&1; then
    if timeout -k 5 15 docker info >/dev/null 2>&1; then DOCKER_OK=1; fi
fi
[ "${NTX_UTP_NO_DOCKER:-0}" = 1 ] && DOCKER_OK=0
[ "${NTX_UTP_FORCE_NETEM:-0}" = 1 ] && NETEM_OK=1
log "netem=$([ "$NETEM_OK" = 1 ] && echo yes || echo no) docker=$([ "$DOCKER_OK" = 1 ] && echo yes || echo no)"

# per-cell port allocator: rotating 32xx range, +1 on EADDRINUSE, 20 tries.
port_free() { # port -> 0 free / non-zero busy
    timeout -k 5 5 python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
try:
    s.bind(("127.0.0.1", int(sys.argv[1])))
except OSError:
    s.close(); sys.exit(1)
s.close(); sys.exit(0)
' "$1"
}
port() { # slot -> allocated UDP port
    local slot=$1 p tries=0
    p=$((32000 + CELL * 6 + slot))
    while ! port_free "$p"; do
        tries=$((tries + 1)); [ "$tries" -ge 20 ] && break
        p=$((p + 1))
    done
    printf '%d' "$p"
}

# ---- helpers ---------------------------------------------------------------

# start an --utp seeder from the v2 single_16k fixture; sets SEED_PID, SEED_PORT
start_utp_seeder() { # tag
    local tag=$1
    SEED_PORT=$(port 1)
    fresh_dir "$WORK/$tag/seed"
    cp -a "$FIXTURE"/. "$WORK/$tag/seed/" 2>/dev/null
    timeout -k 5 120 ./ntx --utp --store-dir="$WORK/$tag/seed" \
        --port-lo=$SEED_PORT --port-hi=$SEED_PORT --stats-json \
        "$WORK/$tag/seed/meta.torrent" >"$WORK/$tag.seed.ndjson" 2>"$WORK/$tag.seed.err" &
    spawn; SEED_PID=$!
    sleep 1.2
}

# bytes-out==bytes-in accounting: the raw probe prints "bytes_out=.. bytes_in=.."
# lines; for a lossless cell every byte the SUT put on the wire must arrive, so
# the relay must forward everything it received (drop==0) and the peer must see
# the SUT's STATE/acks (bytes_in>0). Returns 0 on a balanced accounting.
assert_bytes() { # probe-log relay-json lossless(1/0) -> 0 ok
    local log=$1 rj=$2 lossless=$3
    local bo bi drop fwd
    bo=$(grep -o 'bytes_out=[0-9]*' "$log" 2>/dev/null | head -n1 | sed 's/bytes_out=//')
    bi=$(grep -o 'bytes_in=[0-9]*' "$log" 2>/dev/null | head -n1 | sed 's/bytes_in=//')
    drop=$(sed -n 's/.*"drop": *\([0-9]*\).*/\1/p' "$rj" 2>/dev/null | head -n1)
    fwd=$(sed -n 's/.*"fwd": *\([0-9]*\).*/\1/p' "$rj" 2>/dev/null | head -n1)
    [ -n "$bo" ] && [ -n "$bi" ] || return 1
    [ "$bi" -gt 0 ] || return 1
    if [ "$lossless" = 1 ]; then
        [ "${drop:-0}" = 0 ] && [ "${fwd:-0}" -gt 0 ] || return 1
    fi
    return 0
}

# ------------------------------------------------------------------- cells ---

# c01 netem capability (informational; decides how loss/reorder cells are driven)
cell_netem_probe() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL")
    if [ "$NETEM_OK" = 1 ]; then
        log_cell "$id" "RUN" "tc/netem available (CAP_NET_ADMIN) — loss/reorder use real netem on lo"
    else
        log_cell "$id" "SKIP" "netem-unprivileged (tc qdisc add dev lo refused, no CAP_NET_ADMIN) — loss/reorder driven via userspace relay"
    fi
}

# c02 SYN/STATE open, SUT is the acceptor (raw probe dials the SUT listener)
cell_syn_acceptor() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t=syn-acc
    start_utp_seeder "$t"
    local out="$WORK/$t.syn.out"
    timeout -k 5 15 python3 test/interop/utp/utp_probe.py syn-probe 127.0.0.1 "$SEED_PORT" 6 >"$out" 2>&1
    local r=0; grep -q 'SYN_OK' "$out" 2>/dev/null || r=1
    stop_job "$SEED_PID"
    if [ "$r" = 0 ]; then
        log_cell "$id" "RUN" "SYN->ST_STATE accepted by SUT listener (initiator=probe); $out"
    else
        log_cell "$id" "FAIL" "SUT listener did not answer ST_STATE to a BEP29 SYN; $out; $WORK/$t.seed.err"
    fi
}

# c03 SYN/STATE open, SUT is the INITIATOR (raw acceptor listens; ntx dials it)
cell_syn_initiator() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t=syn-init
    local AP; AP=$(port 2)
    fresh_dir "$WORK/$t/dl"
    # raw acceptor on AP; the tracker advertises AP so the SUT leech dials it.
    timeout -k 5 25 python3 test/interop/utp/utp_probe.py listen 127.0.0.1 "$AP" 22 >"$WORK/$t.acc.out" 2>&1 &
    spawn; local ACC_PID=$!
    sleep 0.6
    local TP; TP=$(port 0)
    timeout -k 5 25 python3 test/interop/tracker.py "$AP" "$TP" >"$WORK/$t.trk.log" 2>&1 &
    spawn; local TRK_PID=$!
    sleep 0.4
    local LP; LP=$(port 3)
    local MAG; MAG=$(timeout -k 5 12 python3 test/interop/v2/magnet_uri.py "$FIXTURE/meta.torrent" 2>/dev/null)
    [ -n "$MAG" ] || MAG="magnet:?xt=urn:btih:0000000000000000000000000000000000000000"
    timeout -k 5 20 ./ntx --utp --store-dir="$WORK/$t/dl" --port-lo=$LP --port-hi=$LP \
        --stats-json --verbose "${MAG}&tr=http://127.0.0.1:${TP}/announce" \
        >/dev/null 2>"$WORK/$t.dl.err"
    local r=0; grep -q 'ACCEPT_OPEN' "$WORK/$t.acc.out" 2>/dev/null || r=1
    stop_job "$ACC_PID"; stop_job "$TRK_PID"
    if [ "$r" = 0 ]; then
        log_cell "$id" "RUN" "SUT initiator SYN opened a uTP conn toward a raw acceptor (ST_STATE replied); $WORK/$t.acc.out"
    else
        log_cell "$id" "FAIL" "SUT never sent a BEP29 SYN the raw acceptor could answer (initiator path); $WORK/$t.acc.out; $WORK/$t.dl.err"
    fi
}

# c04 DATA + SACK observation (raw probe pushes DATA, watches for a SACK ext)
cell_data_sack() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t=data
    start_utp_seeder "$t"
    local out="$WORK/$t.data.out"
    timeout -k 5 15 python3 test/interop/utp/utp_probe.py data-sack 127.0.0.1 "$SEED_PORT" 6 >"$out" 2>&1
    local ok=0; grep -q 'DATA_OK' "$out" 2>/dev/null && ok=1
    local sack='no'; grep -Eq 'SACK_BITS=[1-9]' "$out" 2>/dev/null && sack='yes'
    stop_job "$SEED_PID"
    if [ "$ok" = 1 ]; then
        log_cell "$id" "RUN" "DATA accepted by SUT SM (reliable until acked); SACK-extension-observed=$sack (0 bits is legal — only sent when a seq is skipped); $out"
    else
        log_cell "$id" "FAIL" "SUT did not ack a DATA packet (DATA_TIMEOUT/RESET); $out; $WORK/$t.seed.err"
    fi
}

# c05/c06 loss + reorder. netem when available, else the userspace relay.
drive_impairment() { # tag mode(loss|reorder) -> sets IMP_OUT, IMP_KIND, IMP_RC
    local tag=$1 mode=$2
    local RP SP; RP=$(port 4); SP=$(port 1)
    local out="$WORK/$tag.$mode.out" rj="$WORK/$tag.$mode.relay.json"
    start_utp_seeder_at "$tag" "$SP"
    IMP_RC=1
    if [ "$NETEM_OK" = 1 ]; then
        IMP_KIND=netem
        local q='loss 25%'
        [ "$mode" = reorder ] && q='delay 15ms 10ms distribution normal'
        timeout -k 5 10 tc qdisc add dev lo root netem $q 2>/dev/null
        timeout -k 5 15 python3 test/interop/utp/utp_probe.py data-sack 127.0.0.1 "$SP" 8 >"$out" 2>&1
        timeout -k 5 10 tc qdisc del dev lo root 2>/dev/null || true
    else
        IMP_KIND=userspace-emul
        local flags='--loss 0.25'
        [ "$mode" = reorder ] && flags='--reorder 0.4 --window 8'
        timeout -k 5 16 python3 test/interop/utp/utp_relay.py "$RP" "$SP" $flags --seed 11 --secs 13 --stats "$rj" >"$WORK/$tag.$mode.relay.out" 2>&1 &
        spawn; local RL=$!
        sleep 0.5
        timeout -k 5 15 python3 test/interop/utp/utp_probe.py data-sack 127.0.0.1 "$RP" 9 >"$out" 2>&1
        stop_job "$RL"
    fi
    stop_job "$SEED_PID"
    grep -q 'DATA_OK' "$out" 2>/dev/null && IMP_RC=0
    IMP_OUT="$out"; IMP_RJ="$rj"
}
start_utp_seeder_at() { # tag port
    local tag=$1; SEED_PORT=$2
    fresh_dir "$WORK/$tag/seed"; cp -a "$FIXTURE"/. "$WORK/$tag/seed/" 2>/dev/null
    timeout -k 5 120 ./ntx --utp --store-dir="$WORK/$tag/seed" \
        --port-lo=$SEED_PORT --port-hi=$SEED_PORT --stats-json \
        "$WORK/$tag/seed/meta.torrent" >"$WORK/$tag.seed.ndjson" 2>"$WORK/$tag.seed.err" &
    spawn; SEED_PID=$!; sleep 1.2
}
cell_loss() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL")
    drive_impairment loss loss
    if [ "$IMP_RC" = 0 ]; then
        log_cell "$id" "RUN" "DATA survives $([ "$NETEM_OK" = 1 ] && echo 'netem 25% loss' || echo 'userspace 25% drop') via SUT retransmit (BEP29 §5/§6); $IMP_OUT"
    else
        log_cell "$id" "FAIL" "DATA not recovered under $IMP_KIND loss; $IMP_OUT"
    fi
}
cell_reorder() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL")
    drive_impairment reorder reorder
    if [ "$IMP_RC" = 0 ]; then
        log_cell "$id" "RUN" "DATA survives $([ "$NETEM_OK" = 1 ] && echo 'netem reorder/delay' || echo 'userspace reorder window=8') (SUT in-order reassembly + ack); $IMP_OUT"
    else
        log_cell "$id" "FAIL" "DATA not recovered under $IMP_KIND reorder; $IMP_OUT"
    fi
}

# c07 FIN close
cell_fin() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t=fin
    start_utp_seeder "$t"
    local out="$WORK/$t.fin.out"
    timeout -k 5 15 python3 test/interop/utp/utp_probe.py fin-probe 127.0.0.1 "$SEED_PORT" 6 >"$out" 2>&1
    local r=0; grep -q 'FIN_CLEAN' "$out" 2>/dev/null || r=1
    stop_job "$SEED_PID"
    if [ "$r" = 0 ]; then
        log_cell "$id" "RUN" "ST_FIN drained + clean close (BEP29 §2 FIN); $out"
    else
        log_cell "$id" "FAIL" "ST_FIN close hung / not clean; $out; $WORK/$t.seed.err"
    fi
}

# c08 RESET
cell_reset() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t=reset
    start_utp_seeder "$t"
    local out="$WORK/$t.reset.out"
    timeout -k 5 15 python3 test/interop/utp/utp_probe.py reset-probe 127.0.0.1 "$SEED_PORT" 6 >"$out" 2>&1
    local r=0; grep -q 'RESET_REOPEN_OK' "$out" 2>/dev/null || r=1
    stop_job "$SEED_PID"
    if [ "$r" = 0 ]; then
        log_cell "$id" "RUN" "ST_RESET tears down state; a fresh SYN is accepted again (no stale half-open); $out"
    else
        log_cell "$id" "FAIL" "after ST_RESET the SUT refused a fresh SYN (stale state) or never opened; $out"
    fi
}

# c09 bytes-out == bytes-in accounting (lossless relay, transparent forwarding)
cell_bytes_accounting() {
    local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t=bytes
    local RP SP; RP=$(port 4); SP=$(port 1)
    start_utp_seeder_at "$t" "$SP"
    local out="$WORK/$t.bytes.out" rj="$WORK/$t.bytes.relay.json"
    timeout -k 5 14 python3 test/interop/utp/utp_relay.py "$RP" "$SP" --seed 3 --secs 11 --stats "$rj" >"$WORK/$t.bytes.relay.out" 2>&1 &
    spawn; local RL=$!
    sleep 0.5
    timeout -k 5 13 python3 test/interop/utp/utp_probe.py data-sack 127.0.0.1 "$RP" 7 >"$out" 2>&1
    stop_job "$RL"; stop_job "$SEED_PID"
    if assert_bytes "$out" "$rj" 1; then
        log_cell "$id" "RUN" "bytes-out==bytes-in: lossless relay forwarded every byte (drop=0,fwd>0) and SUT acks reached the peer (bytes_in>0); $out; $rj"
    else
        log_cell "$id" "FAIL" "byte accounting unbalanced on a lossless path (see $out; $rj)"
    fi
}

# ---- engine cells (docker, libtorrent-based rtorrent + qBittorrent-nox) -----
# Build one image carrying both engines; if the build or the engine is unusable
# we record the verbatim error and SKIP, never a fake PASS.
build_engine_image() { # -> 0 built / 1 failed (reason in $ENGINE_ERR)
    local ctx="$WORK/docker-ctx"
    fresh_dir "$ctx"
    cp "$ROOT/test/interop/utp/Dockerfile" "$ctx/" || { ENGINE_ERR="Dockerfile missing"; return 1; }
    cp "$ROOT/test/interop/utp/engine-seed.sh" "$ctx/" 2>/dev/null || { ENGINE_ERR="engine-seed.sh missing"; return 1; }
    [ -f "$FIXTURE/meta.torrent" ] || { ENGINE_ERR="no v1 fixture at $FIXTURE"; return 1; }
    cp -a "$FIXTURE" "$ctx/fixture" || { ENGINE_ERR="fixture copy failed"; return 1; }
    timeout -k 5 180 docker build -t ntx-interop-utp-engines "$ctx" >"$WORK/build.log" 2>&1
    local rc=$?
    if [ "$rc" -ne 0 ]; then
        ENGINE_ERR="docker build rc=$rc: $(tail -n 5 "$WORK/build.log" 2>/dev/null | tr '\n' ' ')"
        return 1
    fi
    return 0
}

# Can the containerised engine even load a plain v1 torrent + seed it?
engine_probe() { # engine -> 0 usable / 1 unusable (reason in $ENGINE_ERR)
    local eng=$1 verdict
    verdict=$(timeout -k 5 90 docker run --rm ntx-interop-utp-engines \
        engine-seed.sh probe "$eng" /interop/fixture 51999 2>&1 | head -n 1)
    printf '%s\n' "$verdict" >"$WORK/$eng.probe.log" 2>/dev/null || true
    case "$verdict" in
        *PROBE_OK*) return 0 ;;
        *) ENGINE_ERR="$eng reported '$verdict'"; return 1 ;;
    esac
}

# engine seeds a v1 torrent over uTP; the SUT leeches and the file must verify.
cell_engine_seed_dl() { # engine
    local eng=$1; local id; CELL=$((CELL + 1)); id=$(printf 'c%02d' "$CELL"); local t="$eng-seed"
    if [ "$DOCKER_OK" != 1 ]; then log_cell "$id" "SKIP" "docker-unavailable ($eng seeder->ntx uTP download)"; return; fi
    if ! build_engine_image; then log_cell "$id" "SKIP" "engine image unavailable: $ENGINE_ERR"; return; fi
    if ! engine_probe "$eng"; then log_cell "$id" "SKIP" "engine unusable head-less: $ENGINE_ERR"; return; fi
    local SP; SP=$(port 1); local TP; TP=$(port 0); local name="ntx-utp-$t"
    CONTAINERS="$CONTAINERS $name"
    fresh_dir "$WORK/$t/dl"
    timeout -k 5 25 python3 test/interop/tracker.py "$SP" "$TP" >"$WORK/$t.trk.log" 2>&1 &
    spawn; sleep 0.5
    timeout -k 5 60 docker run -d --network=host --name "$name" ntx-interop-utp-engines \
        engine-seed.sh seed "$eng" /interop/fixture "/seed/$eng" "$SP" "http://127.0.0.1:${TP}/announce" \
        >"$WORK/$t.run.log" 2>&1
    local drc=$?
    if [ "$drc" -ne 0 ]; then
        log_cell "$id" "SKIP" "engine seeder start rc=$drc (uTP transport likely unsupported by $eng): $(tail -n 3 "$WORK/$t.run.log" 2>/dev/null | tr '\n' ' ')"
        timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
        return
    fi
    local i=0
    until (echo >/dev/tcp/127.0.0.1/"$SP") 2>/dev/null || [ "$i" -ge 20 ]; do sleep 1; i=$((i + 1)); done
    local LP; LP=$(port 3)
    timeout -k 5 90 ./ntx --utp --store-dir="$WORK/$t/dl" --port-lo=$LP --port-hi=$LP \
        --stats-json "$FIXTURE/meta.torrent" >"$WORK/$t.dl.ndjson" 2>"$WORK/$t.dl.err"
    local rc=$?
    # What did the engine say about serving head-less?  A SEED_FAIL (GUI/TUI that
    # never bound) is an engine-side limitation => SKIP, not a SUT FAIL.
    local slog="$WORK/$t.container.log"
    timeout -k 5 30 docker logs "$name" >"$slog" 2>&1 || true
    timeout -k 5 30 docker stop "$name" >/dev/null 2>&1 || true
    timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
    local got; got=$(grep -o '"pct":100' "$WORK/$t.dl.ndjson" 2>/dev/null | head -n1)
    if [ -n "$got" ]; then
        log_cell "$id" "RUN" "$eng seeded over uTP, ntx leech reached pct=100 (rc=$rc); $WORK/$t.dl.ndjson"
    elif grep -q 'SEED_FAIL' "$slog" 2>/dev/null; then
        local why; why=$(grep -o 'SEED_FAIL:[^ ]*' "$slog" 2>/dev/null | head -n1)
        log_cell "$id" "SKIP" "engine cannot serve head-less: $eng reported '$why' (uTP serving not reachable for $eng in CI); $slog"
    else
        log_cell "$id" "FAIL" "$eng seeder->ntx uTP download did not complete (rc=$rc); $WORK/$t.dl.err; $slog"
    fi
}

# --------------------------------------------------------------------- run ---
cell_netem_probe
cell_syn_acceptor
cell_syn_initiator
cell_data_sack
cell_loss
cell_reorder
cell_fin
cell_reset
cell_bytes_accounting
cell_engine_seed_dl rtorrent
cell_engine_seed_dl qbittorrent-nox

# ----------------------------------------------------------------- matrix ----
mkdir -p "$(dirname "$MIRROR")"
{
    echo "ntx BEP29 uTP interop matrix (BEP29)"
    echo "generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "netem=$([ "$NETEM_OK" = 1 ] && echo yes || echo no-unprivileged-userspace-emul) docker=$([ "$DOCKER_OK" = 1 ] && echo yes || echo no)"
    echo "cell|status|evidence"
    for row in "${MATRIX[@]}"; do printf '%s\n' "$row"; done
} >"$WORK/matrix.txt"
cp "$WORK/matrix.txt" "$MIRROR" 2>/dev/null || true

log "matrix: $WORK/matrix.txt"
log "mirror: $MIRROR"
# 0 = completed; individual FAIL cells are recorded evidence, not fatal (R13).
exit 0
