#!/usr/bin/env bash
# D5 interop CI: ntx (under test) vs transmission-daemon (reference seeder).
# Runs INSIDE the ntx-interop container (see Dockerfile). Scratch = /work.
#
# The host repo is baked into the image at /repo (COPY; the sshfs host mount can't
# be bind-mounted by the docker daemon). We build a COPY in /work so the host ./ntx
# (aarch64) is never touched. This exercises, against a real reference implementation
# (transmission-daemon): wire handshake, PE/MSE (BEP3/15), request/response (piece
# download) and tracker announce.
set -euo pipefail

WORK=/work
REPO_SRC=/repo            # bind-mounted host repo (read-only)
BUILD="$WORK/repo"        # build copy of the repo (x86_64, container-local)
SEED="$WORK/seed.bin"
TORRENT="$WORK/seed.torrent"
SEED_DIR="$WORK/dl"       # transmission download dir (data present -> seeds)
DL2="$WORK/dl2"           # ntx store dir
RPC="http://127.0.0.1:9091/transmission/rpc"
PEER_PORT=51413           # transmission's peer port (fixed, so the tracker can name it)
TRK_PORT=6969             # standalone tracker port
# transmission 3.00 has no usable built-in announce endpoint (its web server
# 409s every request without the RPC session-id), so a minimal tracker stands in.
TRACKER="http://127.0.0.1:$TRK_PORT/announce"
DL_SECS=180
TRK_PID=""

log() { printf 'interop: %s\n' "$*"; }
cleanup() { kill "$TPID" 2>/dev/null || true; [ -n "$TRK_PID" ] && kill "$TRK_PID" 2>/dev/null || true; }
die() { log "FAIL: $*"; tail -n 40 "$WORK/transmission.log" >&2 2>/dev/null || true; cleanup; exit 1; }

# --- scratch cleanup ---
rm -rf "$BUILD" "$SEED_DIR" "$DL2" "$WORK/tconf" \
       "$SEED" "$TORRENT" "$WORK/ntx.ndjson" "$WORK/ntx.err" "$WORK/transmission.log" "$WORK/tracker.log"

# --- a. build ntx from the bind-mounted repo (x86_64, in-container) ---
log "building ntx in $BUILD (x86_64, container-local)"
mkdir -p "$BUILD"
cp -a "$REPO_SRC/Makefile" "$BUILD/"
cp -a "$REPO_SRC/src" "$BUILD/src"
cd "$BUILD"
make -s ntx
test -x ./ntx
log "built ntx ($(stat -c%s ./ntx) bytes)"

# --- b. seed data + single-file v1 torrent, capture info-hash ---
# Debian's aria2 build compiles out 'make-torrent' (no MakeTorrent in the binary),
# so generate the torrent with python3 (self-contained bencode + SHA-1). 16 KiB
# pieces -> 64 pieces for the 1 MiB seed, a realistic multi-piece download.
head -c 1048576 /dev/urandom > "$SEED"
INFO_HASH=$(python3 - "$SEED" "$TORRENT" <<'PY'
import hashlib, sys
def b(o):
    if isinstance(o, int): return b'i' + str(o).encode() + b'e'
    if isinstance(o, str): o = o.encode()
    if isinstance(o, bytes): return str(len(o)).encode() + b':' + o
    if isinstance(o, dict):
        r = b'd'
        for k in sorted(o): r += b(k) + b(o[k])
        return r + b'e'
    raise TypeError
seed, torrent = sys.argv[1], sys.argv[2]
data = open(seed, 'rb').read()
PL = 16384
pieces = b''.join(hashlib.sha1(data[i:i + PL]).digest() for i in range(0, len(data), PL))
info = {'length': len(data), 'name': 'seed.bin', 'piece length': PL, 'pieces': pieces}
open(torrent, 'wb').write(b({'info': info}))
print(hashlib.sha1(b(info)).hexdigest())
PY
)
[ -n "$INFO_HASH" ] || { log "FAIL: no info-hash from torrent generator"; exit 1; }
log "info-hash=$INFO_HASH (64 pieces x 16 KiB)"

# --- c. transmission-daemon as the reference SEEDER ---
mkdir -p "$SEED_DIR" "$DL2"
cp -a "$SEED" "$SEED_DIR/seed.bin"   # data present -> transmission verifies + seeds
# transmission-daemon flags (see `transmission-daemon --help`): RPC is always on,
# the RPC port is --port (not --rpc-port). DHT/portmap off to keep the swarm on
# the standalone-tracker path only. --foreground keeps TPID = the real process.
nohup transmission-daemon \
    --config-dir="$WORK/tconf" \
    --port=9091 --rpc-bind-address=127.0.0.1 \
    --peerport="$PEER_PORT" \
    --download-dir="$SEED_DIR" \
    --no-dht --no-portmap --foreground \
    > "$WORK/transmission.log" 2>&1 &
TPID=$!
log "transmission-daemon pid=$TPID (peer port $PEER_PORT)"

# prime the RPC session id (first POST -> 409 + X-Transmission-Session-Id header)
SID=""
for _ in $(seq 1 30); do
    SID=$(curl -s -D - -o /dev/null -X POST "$RPC" \
            -H 'Content-Type: application/json' -d '{"method":"session-get"}' \
            | tr -d '\r' | grep -i '^x-transmission-session-id:' | head -n1 | cut -d' ' -f2 || true)
    [ -n "$SID" ] && break
    sleep 1
done
[ -n "$SID" ] || die "transmission RPC not ready on 127.0.0.1:9091"
log "rpc session ok"

rpc() {
    curl -s -X POST "$RPC" -H 'Content-Type: application/json' \
        -H "X-Transmission-Session-Id: $SID" \
        -d "$(printf '{"method":"%s","arguments":%s}' "$1" "$2")"
}

# add the torrent (its data already lives in the download dir)
ADDRESP=$(rpc torrent-add "{\"filename\":\"$TORRENT\",\"download_dir\":\"$SEED_DIR\",\"start\":true}") || die "torrent-add RPC failed"
log "torrent-add: $ADDRESP"

# poll until transmission is a seeder: status 6, or 100% done with nothing left.
# (transmission reports status 6 before it sets isSeed, so don't rely on isSeed.)
seeded=0
for i in $(seq 1 90); do
    ST=$(rpc torrent-get '{"fields":["status","isSeed","percentDone","leftDone"]}' \
        | python3 -c 'import sys,json
try:
    t=json.load(sys.stdin)["arguments"]["torrents"][0]
    print(t.get("status"), t.get("percentDone"), t.get("leftDone"))
except Exception:
    print("ERR 0 0")' || echo "ERR 0 0")
    log "poll $i: status/pct/left = $ST"
    seeded=$(printf '%s\n' "$ST" | python3 -c 'import sys
p=sys.stdin.read().split()
try:
    st=int(p[0]); pd=p[1]; ld=p[2]
    print(1 if (st==6 or (pd in ("1","1.0") and ld=="0")) else 0)
except Exception:
    print(0)')
    [ "$seeded" = "1" ] && break
    sleep 1
done
if [ "$seeded" != "1" ]; then
    log "diagnose: seed dir:"; ls -la "$SEED_DIR" || true
    die "transmission not seeding after 90s"
fi
log "transmission is seeding"

# start the standalone tracker: answers every announce with transmission's address
python3 "$REPO_SRC/test/interop/tracker.py" "$PEER_PORT" "$TRK_PORT" \
    > "$WORK/tracker.log" 2>&1 &
TRK_PID=$!
log "tracker pid=$TRK_PID on 127.0.0.1:$TRK_PORT -> seeder 127.0.0.1:$PEER_PORT"

# --- d. run ntx against the reference seeder ---
MAG="magnet:?xt=urn:btih:$INFO_HASH&tr=$TRACKER"
log "running ntx: $MAG"
set +e
timeout "$DL_SECS" ./ntx --store-dir="$DL2" --stats-json "$MAG" > "$WORK/ntx.ndjson" 2> "$WORK/ntx.err"
NTX_RC=$?
set -e
log "ntx rc=$NTX_RC (124=timeout after download, expected)"

# --- e. verify: ground truth is sha256, plus the ntx-side completed state ---
SEED_SHA=$(sha256sum "$SEED" | cut -d' ' -f1)
DL_FILE="$DL2/seed.bin"
DL_SHA=$(sha256sum "$DL_FILE" 2>/dev/null | cut -d' ' -f1 || true)
if [ -z "$DL_SHA" ] || [ "$SEED_SHA" != "$DL_SHA" ]; then
    log "FAIL: sha256 mismatch (seed=$SEED_SHA dl=${DL_SHA:-<missing>})"
    tail -n 20 "$WORK/ntx.ndjson" >&2 || true
    cleanup
    exit 1
fi
log "sha256 match: $DL_SHA"

pct100=$(grep -c '"pct":100' "$WORK/ntx.ndjson" || true)
peers_ok=$(grep -oE '"peers_ok":[0-9]+' "$WORK/ntx.ndjson" | grep -oE '[0-9]+' | sort -n | tail -1 || true)
peers_ok=${peers_ok:-0}

if [ "${pct100:-0}" -ge 1 ] && [ "$peers_ok" -ge 1 ]; then
    log "ntx side: pct100_lines=$pct100 max_peers_ok=$peers_ok"
    echo "INTEROP PASS (sha256=$DL_SHA, peers_ok=$peers_ok, pct100=$pct100)"
    cleanup
    exit 0
else
    log "FAIL: ntx did not reach completed state (pct100=${pct100:-0}, peers_ok=$peers_ok)"
    tail -n 20 "$WORK/ntx.ndjson" >&2 || true
    cleanup
    exit 1
fi
