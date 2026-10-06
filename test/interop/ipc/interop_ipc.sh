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
say '{"cmd":"status"}'                            # §6.2: a snapshot outside the 100 ms tick
wait_for '"type":"stats"' 1 "$MAIN_OUT" main      # immediately — 100 ms margin
say 'junk-no-braces'                              # §6.4: gate before any mutation
wait_for '"code":"bad_json"' 2 "$MAIN_OUT" main
say '{"cmd":"remove","seq":6,"i":0}'
wait_for '"seq":6,"cmd":"remove","i":0,"ok":1,"state":5' 3 "$MAIN_OUT" main
say '{"cmd":"remove","seq":7,"i":0}'              # repeat → no_slot
wait_for '"seq":7,"cmd":"remove","i":0,"ok":0,"code":"no_slot"' 3 "$MAIN_OUT" main

# Variant A: quit is the LAST command; fd stays open until the ack lands.
say '{"cmd":"quit","seq":8}'
wait_for '"seq":8,"cmd":"quit","ok":1' 3 "$MAIN_OUT" main
exec {MFD}>&-
wait "$pid" 2>/dev/null; rc=$?
[ "$rc" -eq 0 ] || die "quit rc=$rc (want 0)"

python3 "$here/assert_ipc.py" "$MAIN_OUT" || die "assert_ipc.py rejected the stream"
log "stream validated by assert_ipc.py"
echo "interop_ipc PASS"
