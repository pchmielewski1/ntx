#!/usr/bin/env bash
#
# BEP52 v2 / hybrid interop matrix (ntx).
#
# Runs ntx (the SUT) against: (a) itself over loopback (ntx<->ntx seeder->leech
# for pure-v2 + hybrid fixtures), (b) qBittorrent-nox / libtorrent in a
# container as both seeder and leecher. Every cell is recorded as
# RUN / SKIP / FAIL with an evidence path; a FAIL keeps the ndjson / stderr /
# capture log next to it. We never fabricate a PASS: a cell is RUN only when
# the download actually verified (sha256) or the observable was actually seen.
#
# Hardening (the previous attempt HUNG on un-timed-out docker + background
# seeds):
#   * script-wide watchdog re-exec as the FIRST effect (timeout 900, guard var)
#   * EVERY docker call wrapped in `timeout ... docker ...`; a docker timeout
#     is a FAIL(docker-timeout), never a hang
#   * docker info probed under `timeout 15`; non-zero => all docker cells
#     SKIP(docker-unavailable), local cells still run, script exits 0
#   * background seed jobs joined with `timeout N wait || kill -9`
#   * WORK paths are ABSOLUTE under test/.scratch/9/interop-v2/
#   * EXIT/INT/TERM trap kills every recorded pid (bounded wait)
#
# Run ONCE:   timeout 900 bash test/interop/v2/interop_v2.sh
# Scratch is the repo-local test/.scratch/9/ tree only (never /tmp).
set -uo pipefail

# ---------------------------------------------------------------- watchdog ---
# Re-exec ourselves under a hard timeout so a wedged docker/wait can never hang
# the caller. The guard env var stops the re-exec'd child from re-arming it.
if [ "${NTX_INTEROP_WATCHDOG:-0}" != "1" ]; then
    export NTX_INTEROP_WATCHDOG=1
    exec timeout -k 5 900 bash "$0" "$@"
fi

ROOT=$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)
cd "$ROOT" || exit 1

WORK="$ROOT/test/.scratch/9/interop-v2"
MIRROR="$ROOT/test/.scratch/p5b-p6b/interop-v2.txt"
FIXTURES="$WORK/torrents"
GEN="$WORK/gen.log"
CELL=0
DOCKER_OK=0
PIDS=""
CONTAINERS=""
: >"$WORK/.keep" 2>/dev/null || true

log() { printf 'interop-v2: %s\n' "$*"; }

# matrix rows: cell|status|evidence
declare -a MATRIX
log_cell() { MATRIX+=("$1|$2|$3"); }
next_cell() { CELL=$((CELL + 1)); printf 'c%02d' "$CELL"; }

# Opt-in cell filter for iterating on ONE cell without paying for the matrix.
# Unset (the default) => run_cell always returns 0 and nothing changes at all.
# Set => run <name> ... runs, everything else is skipped, but CELL still ticks
# so the surviving rows keep their usual cNN ids (NTX_V2_ONLY=qbt_share_leech
# must still report as c20). Space-separated list of cell names.
ONLY="${NTX_V2_ONLY:-}"
run_cell() {
    [ -z "$ONLY" ] && return 0
    case " $ONLY " in *" $1 "*) return 0;; esac
    CELL=$((CELL + 1))   # keep the numbering of the cells that do run
    return 1
}

# ------------------------------------------------------------------ cleanup --
kill_pids() {
    local p
    for p in ${PIDS:-}; do
        timeout -k 5 5 kill "$p" 2>/dev/null || true
    done
    for p in ${PIDS:-}; do
        timeout -k 5 5 wait "$p" 2>/dev/null || true
    done
    for p in ${PIDS:-}; do
        kill -9 "$p" 2>/dev/null || true
    done
    PIDS=""
}
cleanup() {
    kill_pids
    local c
    for c in ${CONTAINERS:-}; do
        timeout -k 5 30 docker rm -f "$c" >/dev/null 2>&1 || true
    done
    CONTAINERS=""
}
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM

spawn() { PIDS="$PIDS $!"; }   # record the pid of the most recent `... &`

# Bounded join of a background job: signal it, wait a little, then SIGKILL.
# The jobs are `timeout N ./ntx ...` wrappers, so a plain TERM makes the
# wrapper forward the signal and the child exit promptly; the -k backstop and
# the final kill -9 cover a wedged child so a wait can never hang the cell.
stop_job() { # pid
    local pid=$1
    [ -n "$pid" ] || return 0
    kill "$pid" 2>/dev/null || true
    timeout -k 5 20 wait "$pid" 2>/dev/null || kill -9 "$pid" 2>/dev/null || true
}

fresh_dir() { # rm -rf that tolerates FUSE ".fuse_hidden*" leftovers from a wedged run
    local d=$1
    rm -rf "$d" 2>/dev/null || { sleep 1; rm -rf "$d" 2>/dev/null; } || true
    mkdir -p "$d"
}

# --------------------------------------------------------------- preflight ---
fresh_dir "$WORK"
mkdir -p "$FIXTURES"

if command -v docker >/dev/null 2>&1; then
    if timeout -k 5 15 docker info >/dev/null 2>&1; then
        DOCKER_OK=1
    fi
fi
# CI / air-gapped escape hatch: force the docker cells to SKIP(docker-unavailable)
# without probing, so the local matrix still runs and the script exits 0.
[ "${NTX_V2_NO_DOCKER:-0}" = 1 ] && DOCKER_OK=0
log "docker=$([ "$DOCKER_OK" = 1 ] && echo yes || echo no)"

# per-cell port allocator: 4 ports per cell, well clear of the 9router :20128
# and the usual dev-server range. Each candidate is probed with a bounded bind
# test; on EADDRINUSE we rotate +4 (keeping the per-cell layout disjoint) up to
# 20 tries. Foreign PIDs are never inspected or signalled — a busy port is
# simply stepped over.
port_free() { # port [host] -> 0 free / non-zero busy
    # The host matters: a listener on 127.0.0.2 does NOT make a 127.0.0.1 bind
    # fail, so a cell that binds a specific loopback literal has to probe that
    # literal or it will be handed a port something already owns. With no host
    # given the probe stays exactly as it was (127.0.0.1) so the other cells'
    # port selection is untouched.
    local p=$1 h=${2:-127.0.0.1}
    timeout -k 5 5 python3 -c '
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.bind((sys.argv[2], int(sys.argv[1])))
except OSError:
    s.close()
    sys.exit(1)
s.close()
sys.exit(0)
' "$p" "$h"
}

port() { # slot [host] -> allocated TCP port
    local slot=$1 p tries=0 host=${2:-127.0.0.1}
    p=$((53000 + CELL * 4 + slot))
    while ! port_free "$p" "$host"; do
        tries=$((tries + 1))
        [ "$tries" -ge 20 ] && break
        p=$((p + 4))
    done
    printf '%d' "$p"
}

# magnet line (dual: btih + 1220-prefixed btmh) straight from a fixture manifest
manifest_magnet() { # fixture -> magnet uri (with tr= appended by caller)
    local fixture=$1
    awk '/^magnet:.* dual$/{getline; print; exit}' "$FIXTURES/$fixture/manifest.txt"
}

# Magnet for dialling: derived from the fixture's OWN info dict so the xt pair
# is exactly what ntx's hash gate will check it against.  The manifest's
# "dual" line is a generator golden kept for the ut_metadata cells, which test
# that ntx accepts the spec's truncated-SHA-256 btih for a pure-v2 torrent.
fixture_magnet() { # fixture -> magnet uri (with tr= appended by caller)
    timeout -k 5 15 python3 test/interop/v2/magnet_uri.py \
        "$FIXTURES/$1/meta.torrent" 2>/dev/null
}

# verify every non-metadata file of a fixture matches between seed and download
# NOTE: shell exit status is 0=success, so the boolean is INVERTED on purpose
# (ok=1 => return 1 => the `if verify_fixture` branch is false). Getting this
# backwards turns an empty download dir into a false PASS.
verify_fixture() { # fixture dl_dir -> 0 ok / 1 bad (>=1 data file must match)
    local fixture=$1 dl=$2 fx="$FIXTURES/$1" ok=1 rel s d n=0
    [ -d "$dl" ] || return 1
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        [ -f "$dl/$rel" ] || { ok=0; break; }
        s=$(sha256sum "$fx/$rel" 2>/dev/null | cut -d' ' -f1)
        d=$(sha256sum "$dl/$rel" 2>/dev/null | cut -d' ' -f1)
        [ -n "$s" ] && [ "$s" = "$d" ] || { ok=0; break; }
        n=$((n + 1))
    done < <(cd "$fx" && find . -type f ! -name meta.torrent ! -name manifest.txt ! -name README.txt | sed 's|^./||')
    [ "$n" -ge 1 ] || ok=0
    [ "$ok" = 1 ] && return 0
    return 1
}

# ------------------------------------------------------------------- cells ---

# L1 fixture generation (golden generator via gen_torrents.py)
cell_gen() {
    CELL=$((CELL + 1)); local id; id=$(printf "c%02d" "$CELL")
    if timeout -k 5 60 python3 test/interop/v2/gen_torrents.py "$FIXTURES" >"$GEN" 2>&1 \
        && [ -f "$FIXTURES/single_16k/meta.torrent" ] \
        && [ -f "$FIXTURES/multi_v2/meta.torrent" ] \
        && [ -f "$FIXTURES/hybrid_ok/meta.torrent" ]; then
        log_cell "$id" "RUN" "fixtures generated via bep52_gen (single_16k, multi_v2, hybrid_ok); $GEN"
    else
        log_cell "$id" "FAIL" "fixture generation failed; $GEN"
    fi
}

# L2 BEP52 hash-exchange wire vectors (21/22/23) via the golden generator
cell_vectors() {
    CELL=$((CELL + 1)); local id; id=$(printf "c%02d" "$CELL") vdir="$ROOT/test/vectors/bep52" vlog="$WORK/vectors.log"
    if timeout -k 5 60 python3 test/scripts/bep52_hash_msgs.py >"$vlog" 2>&1 \
        && [ -f "$vdir/hash_request_leaf.bin" ] \
        && [ -f "$vdir/hash_request_piece_layer.bin" ] \
        && [ -f "$vdir/hash_reject.bin" ] \
        && [ -f "$vdir/hashes_omitted_proof_layers.bin" ]; then
        log_cell "$id" "RUN" "BEP52 21/22/23 vectors self-check OK; $vlog"
    else
        log_cell "$id" "FAIL" "hash vector generation/self-check failed; $vlog"
    fi
}

# start a loopback seeder from a fixture .torrent; returns via globals
# $SEED_PID / $TRK_PID / $TRK_PORT / $SEED_PORT. Caller must kill_pids or wait.
start_seeder() { # fixture tag -> sets TRK_PORT SEED_PORT TRK_PID SEED_PID
    local fixture=$1 tag=$2
    TRK_PORT=$(port 0); SEED_PORT=$(port 1)
    fresh_dir "$WORK/seed/$tag"
    cp -a "$FIXTURES/$fixture"/. "$WORK/seed/$tag"/
    python3 test/interop/tracker.py "$SEED_PORT" "$TRK_PORT" >"$WORK/$tag.trk.log" 2>&1 &
    spawn; TRK_PID=$!
    sleep 0.4
    # The seeder's backstop must outlast every cell that dials it: cell bodies give
    # the leecher up to two minutes, and a seeder that self-reaps mid-pump shows up
    # as a connect_fail on the leech side, i.e. as a download that never verifies.
    timeout -k 5 240 ./ntx --store-dir="$WORK/seed/$tag" --port-lo=$SEED_PORT --port-hi=$SEED_PORT \
        --stats-json "$FIXTURES/$fixture/meta.torrent" >"$WORK/$tag.seed.ndjson" 2>&1 &
    spawn; SEED_PID=$!
}

# L3-L5 seeder reaches the seeding state (pct 100, phase seed) for each fixture
cell_seed_verify() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="seed-$fixture"; local i reached=0
    start_seeder "$fixture" "$t"
    for i in $(seq 1 25); do
        if grep -q '"phase":"seed"' "$WORK/$t.seed.ndjson" 2>/dev/null \
            && grep -Eq '"pct":100' "$WORK/$t.seed.ndjson" 2>/dev/null; then
            reached=1; break
        fi
        sleep 1
    done
    stop_job "$SEED_PID"
    stop_job "$TRK_PID"
    if [ "$reached" = 1 ]; then
        log_cell "$id" "RUN" "ntx seeder reached seed state for $fixture (pct100); $WORK/$t.seed.ndjson"
    else
        log_cell "$id" "FAIL" "ntx seeder never reached seed state for $fixture; $WORK/$t.seed.ndjson"
    fi
}

# L6 reserved-bit: dialer (hybrid/v2 magnet) connects to a capture listener;
# we read the initiator's outgoing handshake and check the BEP52 v2 bit (m[27]
# & 0x10). Genuine observation of the reserved-bit signal.
cell_hs_reserved() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="hs-$fixture"
    local CAP_PORT=$(port 2) TRK_PORT=$(port 0) out="$WORK/$t.hs"
    local MAG; MAG=$(fixture_magnet "$fixture")
    # The capture checks the captured handshake's 20-byte info hash against this,
    # so it must be the very xt the dialler will put on the wire: the magnet's
    # btih, not a value we invent.
    local IH; IH=$(printf '%s' "$MAG" | sed -n 's/.*urn:btih:\([0-9a-f]*\).*/\1/p')
    fresh_dir "$WORK/dl/$t"
    python3 test/interop/tracker.py "$CAP_PORT" "$TRK_PORT" >"$WORK/$t.trk.log" 2>&1 &
    spawn; local TRK_PID=$!
    sleep 0.4
    timeout -k 5 30 python3 test/interop/v2/hs_capture.py "$CAP_PORT" "$IH" 20 >"$out" 2>&1 &
    spawn; local CAP_PID=$!
    if [ -z "$MAG" ] || [ ${#IH} -ne 40 ]; then
        stop_job "$CAP_PID"
        stop_job "$TRK_PID"
        log_cell "$id" "SKIP" "no magnet derivable from $fixture (reserved-bit)"
        return
    fi
    # Ports are allocated BEFORE the `&`: a $(...) inside a background command is
    # expanded only once the job has been spawned, so leaving it inline would run
    # the port allocator after `wait` had already reaped (and we had killed) the
    # tracker, and the dialler would come up with no tracker to ask.
    local DL_PORT; DL_PORT=$(port 3)
    # Let the capture reach accept() before anyone dials it: the tracker hands out
    # the capture's port, so a dial that lands before the listener is up is lost
    # and the cell would time out on an empty log.
    sleep 1
    # The dialler runs in the FOREGROUND (backgrounded commands in this harness have
    # had a habit of never reaching exec), and the capture is polled through to its
    # own exit: it prints HS_OK/HS_ERR and returns as soon as it has the handshake.
    timeout -k 5 40 ./ntx --store-dir="$WORK/dl/$t" --port-lo=$DL_PORT --port-hi=$DL_PORT \
        --stats-json --verbose "${MAG}&tr=http://127.0.0.1:${TRK_PORT}/announce" \
        >/dev/null 2>"$WORK/$t.dl.err"
    local i=0
    while [ ! -s "$out" ] && [ "$i" -lt 15 ]; do sleep 1; i=$((i + 1)); done
    stop_job "$CAP_PID"
    stop_job "$TRK_PID"
    local m27
    m27=$(sed -n 's/.* m27=\([0-9a-f][0-9a-f]\).*/\1/p' "$out" | head -n1)
    if [ -n "$m27" ] && [ $((0x$m27 & 0x10)) -eq 16 ]; then
        log_cell "$id" "RUN" "reserved-bit v2 signal seen (m27&0x10) dialing $fixture; $out"
    else
        log_cell "$id" "FAIL" "reserved-bit v2 signal not observed dialing $fixture; $out"
    fi
}

# L7-L8 ut_metadata pump round-trip vs a LOCAL ntx seeder. The seeder is loaded
# from a .torrent, so this cell exercises the serving path that BEP9 opens to any
# peer holding the info dict (ntx_session_data_send_metainfo gates on have_meta,
# not on the fetch state). The leech dials with the manifest's spec 'dual' magnet,
# whose btih is the truncated SHA-256 for a pure-v2 torrent, so a RUN here also
# proves the assemble path hash-gates that form of xt correctly. A request that
# comes back with no DATA is recorded as a FAIL with the log as evidence, never
# as a fake PASS.
cell_meta_exchange() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="meta-$fixture"; local err="$WORK/$t.dl.err"
    start_seeder "$fixture" "$t"
    local MAG; MAG=$(manifest_magnet "$fixture")
    if [ -z "$MAG" ]; then
        stop_job "$SEED_PID"
        stop_job "$TRK_PID"
        log_cell "$id" "SKIP" "no dual magnet in manifest for $fixture (metadata exchange)"
        return
    fi
    local DL_PORT; DL_PORT=$(port 2)      # allocated before the dialler starts
    # Foreground, like the other leech cells: the request/response loop finishes
    # well inside the timeout, and a backgrounded wrapper would be reaped by the
    # cell's own bookkeeping before the log has anything in it.
    timeout -k 5 25 ./ntx --store-dir="$WORK/dl/$t" --port-lo=$DL_PORT --port-hi=$DL_PORT \
        --stats-json --verbose "${MAG}&tr=http://127.0.0.1:${TRK_PORT}/announce" \
        >/dev/null 2>"$err"
    stop_job "$SEED_PID"
    stop_job "$TRK_PID"
    if grep -q 'meta req' "$err" 2>/dev/null && grep -E -q 'meta rx .* type=1 ' "$err" 2>/dev/null; then
        log_cell "$id" "RUN" "ut_metadata request/response round-trip vs local seeder ($fixture); $err"
    else
        log_cell "$id" "FAIL" "no ut_metadata DATA round-trip vs local seeder for $fixture (no type=1 DATA in the leech log); $err"
    fi
}

# D0: the REAL BEP9 ut_metadata assemble path — ntx leeches a MAGNET (no
# .torrent on the leech side, so the info dict can only arrive over BEP9) from
# the reference-client seeder. Gate: the dialer emits `meta req`, the seeder
# answers with `meta rx ... type=1` DATA, the info dict assembles (hash-gated
# against the magnet xt), and the download then verifies byte-for-byte. For a
# hybrid torrent that assemble is followed by the ordinary piece pump; for the
# pure-v2 fixtures the reference client (transmission, a v1-only engine) cannot
# even load the .torrent, so those cells record the ecosystem gap as evidence
# rather than a fake PASS.
cell_qbt_meta_dl() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="qmeta-$fixture"
    if [ "$DOCKER_OK" != 1 ]; then log_cell "$id" "SKIP" "docker-unavailable ($fixture reference-client metadata fetch)"; return; fi
    local verdict; verdict=$(probe_reference "$fixture" "$WORK/$t.probe.log")
    case "$verdict" in
        *"100%"*|*Success*|*"Add succeeded"*|*"added"*) ;;
        *) log_cell "$id" "FAIL" "$fixture: reference engine cannot load the BEP52 fixture — transmission reported '$verdict' (v1-only engine, no BEP52 support), so no ut_metadata DATA is obtainable from it; $WORK/$t.probe.log"; return ;;
    esac
    local SEED_PORT=$(port 1) TRK_PORT=$(port 0) name="ntx-v2-$t"
    CONTAINERS="$CONTAINERS $name"
    fresh_dir "$WORK/dl/$t"
    # magnet with a v2 btmh xt, computed from the fixture's own info dict
    local MAG
    MAG=$(timeout -k 5 15 python3 test/interop/v2/magnet_uri.py "$FIXTURES/$fixture/meta.torrent") || MAG=""
    if [ -z "$MAG" ]; then
        log_cell "$id" "FAIL" "could not derive a btmh magnet from $fixture meta.torrent"
        return
    fi
    python3 test/interop/tracker.py "$SEED_PORT" "$TRK_PORT" >"$WORK/$t.trk.log" 2>&1 &
    spawn
    sleep 0.4
    timeout -k 5 60 docker run --rm -d --network=host --name "$name" ntx-interop-v2-qbt \
        qbt-seed.sh transmission-seed "/interop/torrents/$fixture" "/seed/$fixture" "$SEED_PORT" \
        "http://127.0.0.1:${TRK_PORT}/announce" \
        >"$WORK/$t.td.log" 2>&1
    local drc=$?
    if [ "$drc" -ne 0 ]; then
        log_cell "$id" "FAIL" "docker-timeout/failed starting reference seeder rc=$drc (pure-v2 fixtures are outside a v1-only engine's reach — recorded, not faked); $WORK/$t.td.log"
        timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
        return
    fi
    local i=0
    until (echo >/dev/tcp/127.0.0.1/"$SEED_PORT") 2>/dev/null || [ "$i" -ge 20 ]; do sleep 1; i=$((i + 1)); done
    timeout -k 5 90 ./ntx --store-dir="$WORK/dl/$t" --port-lo=$(port 3) --port-hi=$(port 3) \
        --stats-json --verbose "${MAG}&tr=http://127.0.0.1:${TRK_PORT}/announce" \
        >"$WORK/$t.dl.ndjson" 2>"$WORK/$t.dl.err"
    local rc=$?
    timeout -k 5 30 docker stop "$name" >/dev/null 2>&1 || true
    timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
    local err="$WORK/$t.dl.err" got_req=0 got_data=0
    grep -q 'meta req' "$err" 2>/dev/null && got_req=1
    grep -E -q 'meta rx .* type=1 ' "$err" 2>/dev/null && got_data=1
    if [ "$got_req" = 1 ] && [ "$got_data" = 1 ] && verify_fixture "$fixture" "$WORK/dl/$t"; then
        log_cell "$id" "RUN" "$fixture: ut_metadata DATA from reference seeder, info assembled, download sha256-verified (rc=$rc); $err"
    else
        log_cell "$id" "FAIL" "$fixture: metadata fetch from reference seeder incomplete (req=$got_req data=$got_data verified=no, rc=$rc); $err"
    fi
}

# L9-L11 full loopback magnet download must verify by sha256. ntx accepts a
# magnet whose xt matches an already-loaded .torrent and downloads over the
# standard piece pipeline; the seeder (started from the same fixture) serves
# the pieces. PASS only on a byte-for-byte sha256 match of every data file.
cell_magnet_verify() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="dlv-$fixture"; local err="$WORK/$t.dl.err"
    start_seeder "$fixture" "$t"
    fresh_dir "$WORK/dl/$t"
    local MAG; MAG=$(fixture_magnet "$fixture")
    if [ -z "$MAG" ]; then
        stop_job "$SEED_PID"
        stop_job "$TRK_PID"
        log_cell "$id" "SKIP" "no magnet derivable from $fixture (download verify)"
        return
    fi
    local DL_PORT; DL_PORT=$(port 2)      # allocated before the dialler starts
    # The leech runs in the FOREGROUND under `timeout`: it exits by itself once the
    # torrent verifies, and a backgrounded wrapper whose redirections are set up in
    # the subshell is not something this cell should be debugging while it judges
    # the SUT.  The seeder and tracker stay alive underneath it until it finishes.
    timeout -k 5 120 ./ntx --store-dir="$WORK/dl/$t" --port-lo=$DL_PORT --port-hi=$DL_PORT \
        --stats-json --verbose "${MAG}&tr=http://127.0.0.1:${TRK_PORT}/announce" \
        >"$WORK/$t.dl.ndjson" 2>"$WORK/$t.dl.err"
    stop_job "$SEED_PID"
    stop_job "$TRK_PID"
    if verify_fixture "$fixture" "$WORK/dl/$t"; then
        log_cell "$id" "RUN" "$fixture magnet loopback download sha256-verified; $WORK/$t.dl.ndjson"
    else
        log_cell "$id" "FAIL" "$fixture magnet loopback did not verify (no byte-identical data file landed in $WORK/dl/$t); $err"
    fi
}

# ------------------------------------------------------------------ docker ---
build_image() { # -> 0 built / 1 failed
    local ctx="$WORK/docker-ctx"
    fresh_dir "$ctx"
    cp test/interop/v2/Dockerfile test/interop/v2/qbt-seed.sh "$ctx/" || return 1
    cp -a "$FIXTURES" "$ctx/torrents" || return 1
    timeout -k 5 120 docker build -t ntx-interop-v2-qbt "$ctx" >"$WORK/build.log" 2>&1
}

# Can the containerised reference engine load this BEP52 fixture at all?
# Prints the engine's own verdict on stdout. This is the honest gate in front
# of every reference-client cell: transmission is a v1-only engine and refuses
# BEP52 files, qBittorrent-nox is a GUI binary that never binds a socket
# head-less. Either answer is recorded as the cell's reason, never hidden.
probe_reference() { # fixture logfile -> verdict on stdout (also tee'd to logfile)
    local out
    out=$(timeout -k 5 90 docker run --rm ntx-interop-v2-qbt \
        qbt-seed.sh probe "/interop/torrents/$1" /tmp/probe 51999 2>&1 | head -n 1)
    printf '%s\n' "$out" >"$2" 2>/dev/null || true
    printf '%s\n' "$out"
}

# D: reference client seeds; ntx leeches over loopback and the download must
# verify byte-for-byte. Gated on the reference engine actually loading the
# fixture (see probe_reference).
cell_qbt_seed_dl() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="qseed-$fixture"
    if [ "$DOCKER_OK" != 1 ]; then log_cell "$id" "SKIP" "docker-unavailable ($fixture reference-client seed)"; return; fi
    local verdict; verdict=$(probe_reference "$fixture" "$WORK/$t.probe.log")
    case "$verdict" in
        *"100%"*|*Success*|*"Add succeeded"*|*"added"*) ;;
        *) log_cell "$id" "FAIL" "$fixture: reference engine cannot load the BEP52 fixture — transmission reported '$verdict' (v1-only engine, no BEP52 support); $WORK/$t.probe.log"; return ;;
    esac
    local SEED_PORT=$(port 1) DL_PORT=$(port 3) TRK_PORT=$(port 0) name="ntx-v2-$t"
    CONTAINERS="$CONTAINERS $name"
    fresh_dir "$WORK/dl/$t"
    python3 test/interop/tracker.py "$SEED_PORT" "$TRK_PORT" >"$WORK/$t.trk.log" 2>&1 &
    spawn
    sleep 0.4
    timeout -k 5 60 docker run --rm -d --network=host --name "$name" ntx-interop-v2-qbt \
        qbt-seed.sh transmission-seed "/interop/torrents/$fixture" "/seed/$fixture" "$SEED_PORT" \
        "http://127.0.0.1:${TRK_PORT}/announce" \
        >"$WORK/$t.td.log" 2>&1
    local drc=$?
    if [ "$drc" -ne 0 ]; then
        log_cell "$id" "FAIL" "docker-timeout/failed starting reference seeder rc=$drc; $WORK/$t.td.log"
        timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
        return
    fi
    local i=0
    until (echo >/dev/tcp/127.0.0.1/"$SEED_PORT") 2>/dev/null || [ "$i" -ge 20 ]; do sleep 1; i=$((i + 1)); done
    local MAG; MAG=$(manifest_magnet "$fixture")
    local target="$FIXTURES/$fixture/meta.torrent"
    [ -n "$MAG" ] && target="${MAG}&tr=http://127.0.0.1:${TRK_PORT}/announce"
    timeout -k 5 90 ./ntx --store-dir="$WORK/dl/$t" --port-lo=$DL_PORT --port-hi=$DL_PORT \
        --stats-json "$target" >"$WORK/$t.dl.ndjson" 2>"$WORK/$t.dl.err"
    local rc=$?
    timeout -k 5 30 docker stop "$name" >/dev/null 2>&1 || true
    timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
    local note=""
    [ "$rc" = 124 ] && note=" client killed by its timeout after the bytes verified (ntx run-loop is signal-driven, no self-exit)"
    if verify_fixture "$fixture" "$WORK/dl/$t"; then
        log_cell "$id" "RUN" "$fixture sha256-verified from reference seeder (rc=$rc$note); $WORK/$t.dl.ndjson"
    else
        log_cell "$id" "FAIL" "$fixture from reference seeder did not verify (rc=$rc); $WORK/$t.dl.err"
    fi
}

# D: ntx seeds; the containerised reference client leeches from it and we copy
# the result out and verify by sha256.
cell_qbt_leech() { # fixture
    local fixture=$1; local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL"); local t="qleech-$fixture"
    if [ "$DOCKER_OK" != 1 ]; then log_cell "$id" "SKIP" "docker-unavailable ($fixture reference-client leech)"; return; fi
    local verdict; verdict=$(probe_reference "$fixture" "$WORK/$t.probe.log")
    case "$verdict" in
        *"100%"*|*Success*|*"Add succeeded"*|*"added"*) ;;
        *) log_cell "$id" "FAIL" "$fixture: reference engine cannot load the BEP52 fixture — transmission reported '$verdict' (v1-only engine, no BEP52 support), so it cannot leech from ntx either; $WORK/$t.probe.log"; return ;;
    esac
    local SEED_PORT=$(port 1) TD_PORT=$(port 2) name="ntx-v2-$t"
    CONTAINERS="$CONTAINERS $name"
    start_seeder "$fixture" "$t"
    # transmission reads the announce baked into the fixture meta.torrent
    # (http://127.0.0.1:6969/announce), so answer that exact announce with
    # the ntx seeder's port. Bounded like every other child.
    timeout -k 5 120 python3 test/interop/tracker.py "$SEED_PORT" 6969 \
        >"$WORK/$t.trk6969.log" 2>&1 &
    spawn; local TRK6969_PID=$!
    sleep 2
    local MAG; MAG=$(manifest_magnet "$fixture")
    [ -n "$MAG" ] || MAG="magnet:?xt=urn:btih:0000000000000000000000000000000000000000"
    timeout -k 5 60 docker run --rm --network=host --name "$name" ntx-interop-v2-qbt \
        qbt-seed.sh transmission-leech "/interop/torrents/$fixture" "/dl/$fixture" "$TD_PORT" \
        "http://127.0.0.1:6969/announce" "$MAG" \
        >"$WORK/$t.td.log" 2>&1
    local rc=$?
    stop_job "$TRK6969_PID"
    fresh_dir "$WORK/dl/$t"
    timeout -k 5 60 docker cp "$name:/dl/$fixture/." "$WORK/dl/$t/" >"$WORK/$t.cp.log" 2>&1 || true
    timeout -k 5 60 docker rm -f "$name" >/dev/null 2>&1 || true
    stop_job "$SEED_PID"
    stop_job "$TRK_PID"
    if verify_fixture "$fixture" "$WORK/dl/$t"; then
        log_cell "$id" "RUN" "$fixture sha256-verified leeching from ntx seeder via reference client (rc=$rc); $WORK/$t.td.log"
    else
        log_cell "$id" "FAIL" "$fixture reference-client leech did not verify (rc=$rc); $WORK/$t.td.log"
    fi
}

# E: the private-share cell (plan Task I1 step 3). Seed A is `ntx --share`, the
# seeder of design §5; qBittorrent-nox with the peer-socket encryption the plan
# specifies (Session\Encryption=1 — qbt's enum being 0=plaintext 1=allow
# 2=require) leeches the share's own .torrent and the bytes must be
# byte-identical to the source.
#
# MSE is forced by ntx, not by qbt's enum: a share is MSE-only, so a plaintext
# handshake on one is dropped with plaintext_strict_share
# (src/core/ntx_session_bt_hs.c, src/core/ntx_session_pe.c), and the cell proves
# it seed-side (`peer_ok ... plain=0 ... via=pe_promote`). 2 was measured A/B
# against this seed and is unusable: libtorrent 2.0.8 forms no peer in either
# direction against ntx (outbound ntx dies `hs pe_fail st=RECV_DH role=0 inn=0`;
# qbt inbound falls back to plaintext and is then dropped with
# plaintext_strict_share). See the README's "Why `1`, when qbt calls `2`
# require" for the full measured A/B.
#
# Nothing here is simulated: `ntx --share` publishes a private (BEP 27) hybrid
# (BEP 52) single-file metainfo and announces it ONLY to the HTTPS share list
# compiled into the binary (§6), so the cell
#   * mints a tracker certificate + the matching SPKI pins (share_cert.py) and
#     builds the seeder with -DNTX_SHARE_TRACKERS_INC pointing at them — the
#     checked-in scripts/pins/sharetest_trackers.inc carries all-zero pins and
#     would fail closed, and the Makefile that owns that target is not ours to
#     touch, so the cell passes its own SHARETEST_INC to the existing recipe;
#   * serves the announce over pinned HTTPS on two rows (§6.3 needs
#     NTX_SHARE_MIN_TRACKERS=2) with share_registry_tracker.py, so the two peers
#     are DISCOVERED rather than assumed — BEP 27 forbids every other source, so
#     "qbt contacted seed A only" is only observable if a tracker told it to;
#   * installs the tracker cert as a CA inside the container: ntx pins, plain
#     libtorrent does not, so without a trusted cert qbt never reaches the
#     tracker and would sit idle forever.
#
# Evidence the cell asserts, each from the side that produced it:
#   seed A      phase=seed, priv=1 share=1 enc_strict=1, trk_pin_fail=0, and an
#               MSE-only peer log — a plaintext handshake on a share is dropped
#               (src/core/ntx_session_bt_hs.c: plaintext_strict_share)
#   tracker     every announce arrived over https, both rows, never a scrape
#   qbt         progress==1, and dht_nodes==0 in sync/maindata (BEP 27 held)
#   bytes       cmp of the downloaded file against the source, not a hash echo
cell_qbt_share_leech() {
    local id; CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL")
    local t=share-leech
    # Per-run scratch. The script is documented as "run ONCE", but two matrix
    # runs in flight (another stream) share $WORK, and a concurrent fresh_dir
    # of this directory deletes the tracker log and peer state out from under
    # the live cell — which then reports a bare "did not complete" for a
    # collision that has nothing to do with ntx.
    local S="$WORK/$t.$$"
    local t_start=$SECONDS
    if [ "$DOCKER_OK" != 1 ]; then log_cell "$id" "SKIP" "docker-unavailable (private-share qbt leech)"; return; fi
    # The harness owes one check before it is trusted to judge anything: the
    # announce decode has to stay byte-exact, or one swarm splits in two and the
    # cell fails for a reason that has nothing to do with ntx.
    if ! timeout -k 5 30 python3 test/interop/v2/share_registry_tracker.py --self-check \
            >"$S.self-check.log" 2>&1; then
        log_cell "$id" "FAIL" "share tracker self-check failed; $S.self-check.log"; return
    fi
    fresh_dir "$S"; mkdir -p "$S/A"

    # The tracker hosts are loopback LITERALS other than 127.0.0.1: that address
    # has a hard-coded pin in ntx's built-in dev pool (src/proto/ntx_https_pin.c)
    # which is consulted BEFORE the share table and would reject our certificate.
    # TP1/TP2 must be probed on the address they are actually bound to — see
    # port_free. AP is the seeder (INADDR_ANY), QP/WP live inside the container
    # on the host netns.
    local TP1=$(port 0 127.0.0.2) TP2=$(port 1 127.0.0.3) AP=$(port 2) QP=$(port 3) WP=$(port 4)
    head -c 1048576 /dev/urandom >"$S/sharefile.bin" || {
        log_cell "$id" "FAIL" "could not create the share source; $S"; return; }

    timeout -k 5 60 python3 test/interop/v2/share_cert.py --out "$S/cert" \
        --https-port "$TP1" --https-port2 "$TP2" >"$S/cert.log" 2>&1
    if [ $? -ne 0 ] || [ ! -f "$S/cert/sharetest.inc" ]; then
        log_cell "$id" "FAIL" "tracker cert/pin generation failed; $S/cert.log"; return
    fi

    # Host build of the pinned seeder, bind-mounted into the container exactly
    # like the ctx copies src/: no scripts/ has to join the docker context.
    #
    # The artifact is moved OUT of the repo root afterwards. ntx-sharetest is
    # gitignored but it is a `make` target keyed on its .inc prerequisite, so
    # leaving our binary there would make a later default `make ntx-sharetest`
    # (the sibling stream's test-share) read "up to date" and silently reuse a
    # seeder pinned to THIS cell's throwaway tracker.
    local SB="$S/ntx-sharetest" saved=""
    [ -x ./ntx-sharetest ] && { saved="$S/ntx-sharetest.prev"; mv ./ntx-sharetest "$saved"; }
    # -B, not a bare make: with a second matrix run in flight the shared
    # ./ntx-sharetest can be re-created by the OTHER cell after the mv above and
    # before make runs. make then sees a binary newer than this cell's .inc,
    # calls it up to date, and the seeder comes up pinned to the other cell's
    # tracker ports — every announce gets "trk http connect fail" and the cell
    # fails for a collision that has nothing to do with ntx.
    timeout -k 5 180 make -B ntx-sharetest SHARETEST_INC="$S/cert/sharetest.inc" \
        >"$S/build.log" 2>&1
    local brc=$?
    [ "$brc" = 0 ] && [ -x ./ntx-sharetest ] && mv ./ntx-sharetest "$SB"
    [ -n "$saved" ] && mv "$saved" ./ntx-sharetest
    if [ "$brc" -ne 0 ] || [ ! -x "$SB" ]; then
        log_cell "$id" "FAIL" "ntx-sharetest build failed rc=$brc; $S/build.log"; return
    fi

    # The cell runs TWO passes, one per handshake direction, and the tracker
    # forces the direction with --blind: it answers the peer whose peer_id starts
    # with the given prefix with an EMPTY compact list, so that peer can only be
    # REACHED, never reach anybody. DHT/PeX/LSD are off and the .torrent names no
    # peers, so the tracker list is the only way either side can learn the other's
    # port — blinding one side therefore isolates one dial direction completely.
    #
    # Why two passes and not one run: the seed and qbt both announce `started`
    # within milliseconds of each other, so unblinded they dial SIMULTANEOUSLY and
    # only the winner of that race is observable in the seed's log. One pass can
    # then only ever prove one of ntx's two MSE roles. Passes:
    #   seed-dials  blind -qB4520-  -> ntx is the MSE INITIATOR  (peer_ok out=1)
    #   qbt-dials   blind -NT0100-  -> ntx is the MSE RESPONDER  (peer_ok out=0)
    # Each pass has its own 1 MiB source, store, logs, tracker state and a
    # byte-identical cmp of its own download, so neither can borrow the other's
    # bytes and neither depends on which side wins a race.
    #
    # "<tag>:<blinded peer_id prefix>:<peer_ok out=>:<pe_ok role=>:<ntx role word>"
    # out= is ntx's own view (1 = we dialled) and role= is NTX_PE_INITIATOR(0) /
    # NTX_PE_RESPONDER(1), so the pair is (1,0) when the seed dials and (0,1)
    # when qbt dials. Both are asserted, so a log line cannot be relabelled.
    local passes="seed-dials:-qB4520-:1:0:initiator qbt-dials:-NT0100-:0:1:responder"
    local pass tag blind pout prole role PS TOR name qrc seed_alive trk_alive
    local oom0 oom1 reason="" envnote=""
    oom0=$(awk '/^oom_kill /{print $2}' /proc/vmstat 2>/dev/null)

    for pass in $passes; do
        IFS=: read -r tag blind pout prole role <<<"$pass"
        PS="$S/$tag"
        fresh_dir "$PS"; mkdir -p "$PS/A"
        head -c 1048576 /dev/urandom >"$PS/sharefile.bin" || {
            reason="pass $tag: could not create the share source; $PS"; break; }

        timeout -k 5 240 python3 test/interop/v2/share_registry_tracker.py \
            --bind 127.0.0.2 --bind2 127.0.0.3 --https-port "$TP1" --https-port2 "$TP2" \
            --cert "$S/cert/cert.pem" --key "$S/cert/key.pem" \
            --harness-pid $$ --blind="$blind" \
            --log "$PS/trk.log" --state "$PS/trk.state.json" >"$PS/trk.out" 2>&1 &
        spawn; local TRKP=$!
        sleep 1
        if grep -qi "Address already in use" "$PS/trk.out" 2>/dev/null; then
            stop_job "$TRKP"
            reason="pass $tag: share tracker could not bind 127.0.0.2:$TP1 / 127.0.0.3:$TP2 (stale listener?); $PS/trk.out"
            break
        fi

        # Run the binary THIS cell just built, at $SB — not ./ntx-sharetest, which
        # was just restored to whatever the sibling stream's build left there. A
        # stale seeder carries a stale compiled-in tracker list (the tracker URLs
        # are baked in at build time), and then announces to some other run's ports.
        timeout -k 5 240 "$SB" --share="$PS/sharefile.bin" --store-dir="$PS/A" \
            --port-lo=$AP --port-hi=$AP --allow-local-peers --no-port-map \
            --verbose --log="$PS/seed.log" --stats-json >"$PS/seed.ndjson" 2>"$PS/seed.err" &
        spawn; local SEEDP=$!

        TOR=""; local i=0
        until TOR=$(ls "$PS"/A/*.torrent 2>/dev/null | head -1) && [ -n "$TOR" ] || [ "$i" -ge 30 ]
        do sleep 1; i=$((i + 1)); done
        if [ -z "$TOR" ]; then
            stop_job "$SEEDP"; stop_job "$TRKP"
            reason="pass $tag: seed A published no .torrent in 30 s; $PS/seed.err"
            break
        fi
        chmod 644 "$TOR" 2>/dev/null || true

        # Gate the pass on the metainfo really being the private single-file hybrid
        # --share is supposed to publish, so it cannot pass by accident.
        timeout -k 5 60 python3 test/interop/v2/share_cert.py --out "$PS/verify" \
            --https-port "$TP1" --https-port2 "$TP2" --verify-torrent "$TOR" \
            >"$PS/verify.log" 2>&1
        if [ $? -ne 0 ]; then
            stop_job "$SEEDP"; stop_job "$TRKP"
            reason="pass $tag: share metainfo is not private/single-file/hybrid: $(tr '\n' ';' <"$PS/verify.log"); $PS/verify.log"
            break
        fi

        # /share is THIS pass's directory, but the tracker certificate is shared by
        # both passes and lives one level up at $S/cert. Mount it in as well, or the
        # "/share/cert/cert.pem" argument below names a file that does not exist in
        # the container: qbt-seed.sh then silently skips update-ca-certificates (its
        # `[ -f "$CA_PEM" ]` guard is false), libtorrent cannot verify the pinned
        # tracker cert, qbt never announces, and the pass dies as "stalledDL /
        # total_peer_connections=0" with a tracker log that only ever saw ntx.
        name="ntx-v2-$t-$tag"; CONTAINERS="$CONTAINERS $name"
        timeout -k 5 150 docker run --rm --network=host --name "$name" \
            -v "$PS:/share:rw" -v "$S/cert:/share/cert:ro" ntx-interop-v2-qbt \
            qbt-seed.sh qbt-share-leech "/share/A/$(basename "$TOR")" "/share/dl" \
            "$QP" "https://127.0.0.2:$TP1/announce" "$WP" 90 "/share/cert/cert.pem" 1 \
            >"$PS/qbt.log" 2>&1
        qrc=$?
        timeout -k 5 30 docker rm -f "$name" >/dev/null 2>&1 || true

        # Liveness, sampled BEFORE the jobs are stopped: a seed or tracker reaped
        # by host OOM mid-cell is an environment failure, not a wire failure, and
        # this is the only moment that can still tell them apart.
        seed_alive=1; trk_alive=1
        kill -0 "$SEEDP" 2>/dev/null || seed_alive=0
        kill -0 "$TRKP" 2>/dev/null || trk_alive=0
        # Passes share ports; the next one must not inherit this one's peer.
        stop_job "$SEEDP"; stop_job "$TRKP"
        sleep 1

        # --- asserts, this pass only -------------------------------------------------
        # Environment first, and it never excuses a wire assert: these only add a
        # cause to the FAIL, they cannot turn a FAIL into a RUN.
        envnote=""
        case "$qrc" in
            124) envnote=" qbt hit the outer docker timeout (rc=124, a hang)";;
            137) envnote=" qbt was SIGKILLed (rc=137)";;
        esac
        [ "$seed_alive" = 0 ] && envnote="$envnote seed A was gone before qbt finished"
        [ "$trk_alive" = 0 ] && envnote="$envnote share tracker was gone before qbt finished"
        oom1=$(awk '/^oom_kill /{print $2}' /proc/vmstat 2>/dev/null)
        [ -n "$oom0" ] && [ -n "$oom1" ] && [ "$oom1" != "$oom0" ] \
            && envnote="$envnote host OOM kills +$((oom1 - oom0)) since cell start"

        # The tracker writes its state every 2 s and atomically, so a tracker that
        # died still says what it saw; requests=0 really means nothing announced.
        if [ ! -s "$PS/trk.state.json" ] || ! grep -q '"requests": [1-9]' "$PS/trk.state.json" 2>/dev/null; then
            local tw="state file absent, so the tracker never even wrote its first dump"
            [ -s "$PS/trk.state.json" ] && tw='state says requests=0, so the tracker was healthy and nothing announced'
            reason="pass $tag: ENVIRONMENT-or-wire: share tracker saw no announces ($tw;$envnote); $PS/trk.state.json $PS/trk.out $PS/seed.err $PS/qbt.log"
            break
        fi
        if [ "$qrc" -ne 0 ]; then
            reason="pass $tag: qbt exited rc=$qrc without completing;$envnote $PS/qbt.log"; break
        fi
        if ! cmp -s "$PS/sharefile.bin" "$PS/dl/sharefile.bin" 2>/dev/null; then
            reason="pass $tag: downloaded file is not byte-identical (or absent);$envnote $PS/qbt.log"; break
        fi
        if ! grep -aq '"phase":"seed"' "$PS/seed.ndjson" 2>/dev/null \
            || ! grep -aq '"priv":1,"share":1,"enc_strict":1' "$PS/seed.ndjson" 2>/dev/null; then
            reason="pass $tag: seed A never reached phase=seed with priv/share/enc_strict set;$envnote $PS/seed.ndjson"; break
        fi
        if ! grep -aq '"trk_pin_fail":0' "$PS/seed.ndjson" 2>/dev/null; then
            reason="pass $tag: seed A's pinned announce failed (trk_pin_fail!=0);$envnote $PS/seed.ndjson"; break
        fi
        if ! grep -aq 'QBT-PREFS encryption=1' "$PS/qbt.log" 2>/dev/null; then
            # Read back from qbt's own /api/v2/app/preferences, not from our conf, so
            # a key this version ignores cannot pass for one it honours. 1 is the
            # value the plan specifies and, by the measurement recorded in
            # qbt-seed.sh, the only one under which qbt opens with MSE at all.
            reason="pass $tag: qbt did not report the encryption policy the plan sets (encryption=1);$envnote $PS/qbt.log"; break
        fi
        if ! grep -aq 'QBT-SESSION dht_nodes=0' "$PS/qbt.log" 2>/dev/null; then
            reason="pass $tag: qbt reported DHT activity on a private torrent (BEP 27 broken);$envnote $PS/qbt.log"; break
        fi
        if ! grep -aq 'scheme=https' "$PS/trk.log" 2>/dev/null \
            || grep -q 'scheme=http ' "$PS/trk.log" 2>/dev/null; then
            reason="pass $tag: not every announce reached the share tracker over https;$envnote $PS/trk.log"; break
        fi
        if ! grep -aq '"scrape_no_hash": 0' "$PS/trk.state.json" 2>/dev/null; then
            reason="pass $tag: share tracker saw a scrape, which §6.3 forbids;$envnote $PS/trk.state.json"; break
        fi
        # Both sides really used this tracker, and only this one: the blinded peer
        # still announced (it just got an empty list), so the swarm was formed by
        # discovery in the one direction the pass allows.
        if ! grep -aq 'peer_id=2d4e54303130302d' "$PS/trk.log" \
            || ! grep -aq 'peer_id=2d7142' "$PS/trk.log"; then
            reason="pass $tag: the share tracker did not see both peers announce (ntx -NT0100- and qBittorrent -qB4520-);$envnote $PS/trk.log"; break
        fi
        # The MSE proof, per direction. Positive, not an absence: the peer that
        # reached PH_OK got there through the MSE state machine (sp_pe_finish ->
        # sp_promote_peer_ok prints via=pe_promote, which the plaintext path can
        # never print — it goes through via=bths) on a socket the seed recorded as
        # non-plaintext (sp_vlog_peer prints plain=0 only when the peer is not
        # plaintext). out= is the direction this pass forced.
        if ! grep -Eq "hs pe_ok .*role=$prole( |\$)" "$PS/seed.log" 2>/dev/null; then
            reason="pass $tag: no MSE handshake completed as ntx $role (no pe_ok role=$prole);$envnote $PS/seed.log"; break
        fi
        if ! grep -Eq "hs peer_ok .*out=$pout plain=0 .*via=pe_promote" "$PS/seed.log" 2>/dev/null; then
            reason="pass $tag: seed A's peer was not MSE-promoted in this direction (no peer_ok out=$pout plain=0 via=pe_promote);$envnote $PS/seed.log"; break
        fi
        # A plaintext peer could only ever arrive via bths. Rejecting that path
        # outright is what makes "byte-identical" impossible to earn unencrypted,
        # whatever any future enum says.
        if grep -aq 'via=bths' "$PS/seed.log" 2>/dev/null; then
            reason="pass $tag: seed A accepted a peer through the plaintext handshake (via=bths);$envnote $PS/seed.log"; break
        fi
        # Isolation, so the label on the direction above is not a guess.
        if [ "$(grep -ac 'hs peer_ok' "$PS/seed.log")" != "1" ]; then
            reason="pass $tag: expected exactly one promoted peer in a blinded pass, saw $(grep -ac 'hs peer_ok' "$PS/seed.log");$envnote $PS/seed.log"; break
        fi
    done

    if [ -n "$reason" ]; then
        log_cell "$id" "FAIL" "$reason"
        return
    fi
    # Independent re-check of the bytes after both passes, each against the source
    # that pass generated for itself, so neither pass can borrow the other's file
    # and the matrix line cannot claim a cmp that is not on disk right now.
    for pass in $passes; do
        IFS=: read -r tag _ _ _ <<<"$pass"
        if ! cmp -s "$S/$tag/sharefile.bin" "$S/$tag/dl/sharefile.bin" 2>/dev/null; then
            log_cell "$id" "FAIL" "final cmp: pass $tag is not byte-identical; $S/$tag/qbt.log"
            return
        fi
    done
    log_cell "$id" "RUN" "private share (BEP27 hybrid single-file) from ntx --share: qbt-nox leeches the share's own .torrent byte-identical (cmp) in TWO forced passes -- seed-dials proves ntx's MSE INITIATOR (peer_ok out=1 plain=0 via=pe_promote), qbt-dials proves ntx's MSE RESPONDER (peer_ok out=0 plain=0 via=pe_promote) -- with Session\\Encryption=1 read back from qbt's own API, discovery only via pinned-https announces on both rows, scrape_no_hash=0, dht_nodes=0, and no via=bths plaintext peer; $((SECONDS - t_start))s; $S/seed-dials/seed.log $S/qbt-dials/seed.log"
}

# --------------------------------------------------------------------- run ---
# cell_gen stays ungated: it is cheap and build_image() copies $FIXTURES into the
# docker context, so a filtered run must still be able to (re)build the image.
cell_gen
run_cell vectors && cell_vectors
for f in single_16k multi_v2 hybrid_ok; do run_cell seed_verify && cell_seed_verify "$f"; done
for f in single_16k hybrid_ok; do run_cell hs_reserved && cell_hs_reserved "$f"; done
for f in single_16k hybrid_ok; do run_cell meta_exchange && cell_meta_exchange "$f"; done
for f in single_16k multi_v2 hybrid_ok; do run_cell magnet_verify && cell_magnet_verify "$f"; done

if [ "$DOCKER_OK" = 1 ]; then
    CELL=$((CELL + 1)); id=$(printf "c%02d" "$CELL")
    if [ -n "$ONLY" ] && timeout -k 5 20 docker image inspect ntx-interop-v2-qbt >/dev/null 2>&1; then
        # Filtered run and the image is already there: do not pay for a rebuild.
        log_cell "$id" "RUN" "reference-client image (transmission + qbt-nox) present, not rebuilt (NTX_V2_ONLY set)"
    elif build_image; then
        log_cell "$id" "RUN" "reference-client image (transmission + qbt-nox) built; $WORK/build.log"
        DOCKER_OK=1
    else
        log_cell "$id" "SKIP" "reference-client image build failed; $WORK/build.log"
        DOCKER_OK=0
    fi
fi
for f in single_16k hybrid_ok; do run_cell qbt_seed_dl && cell_qbt_seed_dl "$f"; done
for f in hybrid_ok; do run_cell qbt_leech && cell_qbt_leech "$f"; done
for f in single_16k multi_v2 hybrid_ok; do run_cell qbt_meta_dl && cell_qbt_meta_dl "$f"; done
run_cell qbt_share_leech && cell_qbt_share_leech

# ----------------------------------------------------------------- matrix ----
mkdir -p "$(dirname "$MIRROR")"
{
    echo "ntx BEP52 v2/hybrid interop matrix (BEP52)"
    echo "generated=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "docker=$([ "$DOCKER_OK" = 1 ] && echo yes || echo no)"
    echo "cell|status|evidence"
    for row in "${MATRIX[@]}"; do printf '%s\n' "$row"; done
} >"$WORK/matrix.txt"
cp "$WORK/matrix.txt" "$MIRROR" 2>/dev/null || true

log "matrix: $WORK/matrix.txt"
log "mirror: $MIRROR"
# 0 = completed (individual FAIL cells are recorded, not fatal to the run)
exit 0
