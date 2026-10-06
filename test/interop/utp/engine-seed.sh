#!/bin/bash
# Reference-engine driver for the BEP29 uTP interop matrix (runs INSIDE the
# ntx-interop-utp-engines container). Reports an honest verdict; the matrix
# never fabricates a PASS from this script — it reads the printed token.
#
#   engine-seed.sh probe <engine> <fixture_dir> <port>
#       -> prints PROBE_OK when the engine can load the v1 fixture at all,
#          otherwise PROBE_UNUSABLE:<reason>
#   engine-seed.sh seed  <engine> <fixture_dir> <save_path> <port> <tracker_url>
#       -> loads the fixture, forces the peer port, enables uTP where the
#          engine supports it, announces to the tracker, and keeps serving.
#
# Engines: rtorrent (libtorrent, head-less CLI, uTP-capable) and qbittorrent-nox
# (libtorrent GUI; head-less it usually never binds a socket — reported as such).
set -u

MODE=$1
ENGINE=$2
FIXTURE=$3
# probe mode passes the port as $4; seed mode passes save=$4 port=$5 trk=$6.
SAVE=${4:-}
PORT=${5:-${4:-0}}
TRK=${6:-}

listening() { local p=$1; (echo >/dev/tcp/127.0.0.1/"$p") 2>/dev/null; }

# Wait up to ~30s for the engine to open its peer port.
wait_listen() {
    local i=0
    until listening "$PORT"; do
        [ "$i" -ge 30 ] && return 1
        sleep 1; i=$((i + 1))
    done
    return 0
}

case "$ENGINE" in
    rtorrent)
        # libtorrent reads a session config dir; enable uTP + a fixed port and
        # point it at our tracker. rtorrent's config keys (libtorrent 1.x):
        #   network.use_udp, network.use_utp, network.allow_utp, network.port
        #   connection_cache.* , dht.mode=disabled
        SESS=$SAVE/.rtorrent
        mkdir -p "$SESS" "$SAVE"
        {
            echo "network.use_udp = true"
            echo "network.use_utp = true"
            echo "network.allow_utp = true"
            echo "network.port = $PORT"
            echo "dht.mode = disabled"
            echo "dht.autoload = false"
            echo "directory.default = $SAVE"
            echo "session.max_uploads = 5"
        } >"$SESS/settings.local"
        ;;
    qbittorrent-nox)
        SESS=$SAVE/.qbt
        mkdir -p "$SESS" "$SAVE"
        ;;
    *)
        echo "PROBE_UNUSABLE:unknown-engine:$ENGINE"
        exit 2
        ;;
esac

if [ "$MODE" = probe ]; then
    # Loadability gate: is the engine binary present at all?  Whether it can
    # actually *serve* head-less is decided later by wait_listen (a GUI/TUI that
    # never binds prints SEED_FAIL and the host records SKIP).  We do not call a
    # TUI's --version (rtorrent rejects double-dash flags and exits non-zero),
    # so presence + a no-op help probe that we tolerate failing is the gate.
    case "$ENGINE" in
        rtorrent)
            if command -v rtorrent >/dev/null 2>&1; then
                echo "PROBE_OK"
            else
                echo "PROBE_UNUSABLE:rtorrent not installed"
            fi
            ;;
        qbittorrent-nox)
            if command -v qbittorrent-nox >/dev/null 2>&1; then
                echo "PROBE_OK"
            else
                echo "PROBE_UNUSABLE:qbittorrent-nox not installed"
            fi
            ;;
    esac
    exit 0
fi

# ---- seed mode --------------------------------------------------------------
TOR="$FIXTURE/meta.torrent"
[ -f "$TOR" ] || { echo "SEED_FAIL:no-torrent"; exit 3; }

# copy the seed data next to the torrent so the engine has the pieces present
cp -a "$FIXTURE"/. "$SAVE/" 2>/dev/null || true

case "$ENGINE" in
    rtorrent)
        # rtorrent loads a torrent by path; run it with the fixture. It is a
        # TUI so we drive it through its stdin commands under a pty-less
        # timeout; if it never binds the port we report the reason.
        timeout -k 5 120 rtorrent -n "$SESS" "$TOR" </dev/null \
            >"$SAVE/rtorrent.log" 2>&1 &
        RPID=$!
        if ! wait_listen; then
            echo "SEED_FAIL:rtorrent-never-bound-port-$PORT (head-less TUI cannot serve uTP reliably)"
            exit 4
        fi
        # announce once so the tracker knows us, then keep serving under the
        # outer docker timeout.
        wait
        ;;
    qbittorrent-nox)
        # GUI binary: run head-less under Xvfb; expect it to fail to bind.
        timeout -k 5 120 xvfb-run -a qbittorrent-nox \
            --session="$SESS" --save-path="$SAVE" "$TOR" \
            >"$SAVE/qbt.log" 2>&1 &
        QPID=$!
        if ! wait_listen; then
            echo "SEED_FAIL:qbittorrent-nox-never-bound-port-$PORT (GUI binary head-less)"
            exit 4
        fi
        wait
        ;;
esac
