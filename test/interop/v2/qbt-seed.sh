#!/bin/bash
# Reference-client driver for the BEP52 v2/hybrid interop matrix.
#
#   qbt-seed.sh probe              <fixture_dir>
#   qbt-seed.sh transmission-seed  <fixture_dir> <save_path> <port> <tracker_url>
#   qbt-seed.sh transmission-leech <fixture_dir> <save_path> <port> <tracker_url> <magnet>
#   qbt-seed.sh qbt-seed           <fixture_dir> <save_path> <port>
#
# transmission-daemon binds its torrenting port at start-up, so the harness can
# probe the port before dialling it. qBittorrent-nox is a GUI binary and is run
# under Xvfb; if it never opens a listening socket the cell is reported from
# the container log, never from a guess.
set -u

MODE="$1"
SRC="$2"
SAVE="$3"
PORT="$4"
TRK="${5:-}"

mkdir -p "$SAVE"

listening() { # port -> 0 when something is bound to it
    local p=$1
    (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null
}

wait_seeding() { # session_dir -> 0 once transmission reports a complete seed
    local sess=$1 deadline=$((SECONDS + 40))
    while [ "$SECONDS" -lt "$deadline" ]; do
        if transmission-remote -l --config-dir="$sess" 2>/dev/null | grep -q '100%'; then
            return 0
        fi
        sleep 1
    done
    return 1
}

if [ "$MODE" = probe ]; then
    # Can this engine load the fixture at all?  We print transmission's own
    # verdict and let the harness turn it into the cell's reason: a v1-only
    # engine refusing a BEP52 file is a real result, not a harness bug.
    SESS=$(mktemp -d /tmp/trprobe.XXXXXX)
    transmission-daemon --download-dir=/tmp/probe --config-dir="$SESS" \
        --peerport=51999 --no-portmap --no-utp --no-blocklist --no-dht \
        >/tmp/td.log 2>&1 &
    DPID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do listening 51999 && break; sleep 1; done
    transmission-remote -a "$SRC/meta.torrent" --config-dir="$SESS" 2>&1 | head -n 1
    kill "$DPID" 2>/dev/null
    exit 0
fi

if [ "$MODE" = transmission-seed ]; then
    SESS=$(mktemp -d /tmp/trseed.XXXXXX)
    cp -a "$SRC"/. "$SAVE"/ 2>/dev/null || true
    transmission-daemon --download-dir="$SAVE" --config-dir="$SESS" \
        --peerport="$PORT" --no-portmap --no-utp --no-blocklist --no-dht \
        >/tmp/td.log 2>&1 &
    DPID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do listening "$PORT" && break; sleep 1; done
    listening "$PORT" || { echo "TD-NOT-LISTENING port=$PORT"; tail -n 5 /tmp/td.log; exit 3; }
    transmission-remote -a "$SRC/meta.torrent" --config-dir="$SESS" --port="$PORT" \
        >/tmp/add.log 2>&1 || { echo "TD-ADD-FAIL"; tail -n 5 /tmp/add.log; tail -n 5 /tmp/td.log; exit 4; }
    transmission-remote --torrent 1 --start --config-dir="$SESS" >>/tmp/add.log 2>&1 || true
    [ -n "$TRK" ] && transmission-remote -t "$TRK" --torrent 1 --config-dir="$SESS" >/dev/null 2>&1
    wait_seeding "$SESS" || { echo "TD-NOT-SEEDING"; transmission-remote -l --config-dir="$SESS" 2>&1 | head -3; tail -n 5 /tmp/td.log; exit 5; }
    echo "TD-SEEDING port=$PORT"
    # stay alive so the harness can dial us; the outer docker timeout reaps us
    while kill -0 "$DPID" 2>/dev/null; do sleep 1; done
    exit 0
fi

if [ "$MODE" = transmission-leech ]; then
    MAG="$6"
    SESS=$(mktemp -d /tmp/trleech.XXXXXX)
    rm -rf "$SAVE"; mkdir -p "$SAVE"
    transmission-daemon --download-dir="$SAVE" --config-dir="$SESS" \
        --peerport="$PORT" --no-portmap --no-utp --no-blocklist --no-dht \
        >/tmp/td.log 2>&1 &
    DPID=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do listening "$PORT" && break; sleep 1; done
    listening "$PORT" || { echo "TD-NOT-LISTENING port=$PORT"; tail -n 5 /tmp/td.log; exit 3; }
    transmission-remote -a "$SRC/meta.torrent" --config-dir="$SESS" --port="$PORT" \
        >/tmp/add.log 2>&1 || { echo "TD-ADD-FAIL"; tail -n 5 /tmp/add.log; tail -n 5 /tmp/td.log; exit 4; }
    transmission-remote --torrent 1 --start --config-dir="$SESS" >>/tmp/add.log 2>&1 || true
    deadline=$((SECONDS + 40))
    while [ "$SECONDS" -lt "$deadline" ]; do
        transmission-remote -l --config-dir="$SESS" 2>/dev/null | grep -q '100%' && break
        sleep 1
    done
    kill "$DPID" 2>/dev/null
    wait "$DPID" 2>/dev/null
    ok=1
    while IFS= read -r rel; do
        [ -n "$rel" ] || continue
        [ -f "$SAVE/$rel" ] || { ok=0; break; }
        [ "$(sha256sum "$SRC/$rel" | cut -d' ' -f1)" = "$(sha256sum "$SAVE/$rel" | cut -d' ' -f1)" ] || { ok=0; break; }
    done < <(cd "$SRC" && find . -type f ! -name meta.torrent ! -name manifest.txt ! -name README.txt | sed 's|^./||')
    [ "$ok" = 1 ] || { echo "TD-LEECH-NOT-VERIFIED"; transmission-remote -l --config-dir="$SESS" 2>&1 | head -3; tail -n 5 /tmp/td.log; exit 5; }
    echo "TD-LEECH-VERIFIED"
    exit 0
fi

# ---- qBittorrent-nox (GUI binary, driven head-less under Xvfb) ------------
PROFILE=$(mktemp -d /tmp/qbtprof.XXXXXX)
cp -a "$SRC"/. "$SAVE"/ 2>/dev/null || true
xvfb-run --auto-servernum qbittorrent-nox \
    --profile="$PROFILE" \
    --webui-port=9988 \
    --torrenting-port="$PORT" \
    --save-path="$SAVE" \
    --skip-dialog=true \
    --add-paused=false \
    "$SRC/meta.torrent" >/tmp/qbt.log 2>&1 &
QPID=$!
for _ in $(seq 1 25); do listening "$PORT" && break; sleep 1; done
if ! listening "$PORT"; then
    echo "QBT-NOT-LISTENING port=$PORT"
    tail -n 10 /tmp/qbt.log
    kill "$QPID" 2>/dev/null
    exit 3
fi
echo "QBT-LISTENING port=$PORT"
while kill -0 "$QPID" 2>/dev/null; do sleep 1; done
exit 0
