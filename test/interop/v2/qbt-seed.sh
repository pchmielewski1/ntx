#!/bin/bash
# Reference-client driver for the BEP52 v2/hybrid interop matrix.
#
#   qbt-seed.sh probe              <fixture_dir>
#   qbt-seed.sh transmission-seed  <fixture_dir> <save_path> <port> <tracker_url>
#   qbt-seed.sh transmission-leech <fixture_dir> <save_path> <port> <tracker_url> <magnet>
#   qbt-seed.sh qbt-seed           <fixture_dir> <save_path> <port>
#   qbt-seed.sh qbt-share-leech    <torrent_file> <save_path> <port> <tracker_url> <webui_port> [secs] [ca_pem] [encryption]
#
# qbt-share-leech is the private-share cell's engine: it adds ONE .torrent
# through the WebAPI and polls it to completion with [BitTorrent]
# Session\Encryption set from argv[9] (default 1 — qbt's enum is 0=plaintext
# 1=allow 2=require; the cell runs 1, which is what the plan specifies, because
# 2 never forms a peer against ntx — see the block below and the README's
# "Why `1`, when qbt calls `2` require"). DHT/PeX/LSD and port-forwarding are
# off in the same conf. qbittorrent-nox binds its peer socket head-less without
# Xvfb, so the WebAPI is the control channel.
# [ca_pem], when given, is installed as a system CA first: the share's announce
# is pinned HTTPS and libtorrent validates it through the normal trust store.
# The encryption evidence is NOT read from qbt — this build answers 400 on
# torrents/properties|files|trackers and its peer flags are not comparable
# across engines. The cell asserts MSE from the SEED's own handshake log
# (peer_ok with plain=0 via=pe_promote), and reads QBT-PREFS back from
# /api/v2/app/preferences so a conf key this version ignores cannot pass.
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

# ---- qBittorrent-nox as the private-share leech (MSE, enum 1) ----------------
# qbittorrent-nox needs no Xvfb: it binds its peer socket head-less within a
# couple of seconds, so the WebAPI (no auth needed with LocalHostAuth=false +
# a loopback/bridge AuthSubnetWhitelist) is the control channel.
#
# The conf keys are the ones qbt itself writes back, verified against
# /api/v2/app/preferences on this very package (qbittorrent-nox 4.5.2 /
# libtorrent 2.0.8): [BitTorrent] Session\Encryption, Session\DHTEnabled,
# Session\PeXEnabled, Session\LSDEnabled. The [Preferences] BitTorrent\*
# spellings are ignored by this version — they read back as the defaults.
# Session\Encryption is the value the plan calls for (`encryption=1`). What
# decides the cell is not qbt's label for the enum but what the seed's MSE state
# machine observes on the wire, asserted by the cell from ntx's own log: the
# peer is promoted through the encrypted handshake on a non-plaintext socket
# (`peer_ok ... plain=0 ... via=pe_promote`).
#
# That comment also got the ENUM wrong: 0=plaintext / 1=allow / 2=require is
# libtorrent's own peer_encryption_t, and qbt's Session\Encryption preference is
# NOT that enum (the value is mapped before it reaches libtorrent, and this
# image ships no WebUI strings to read the labels from). So the values were
# measured, not named — A/B against this seed, one direction at a time (the
# share tracker answers the other peer with an empty peer list, so exactly one
# side can dial), `cmp` of the 1 MiB share as the verdict:
#
#   ENC  qbt dials (seed blinded)                  seed dials (qbt blinded)
#    0   first bytes 13 42 69 74 54.. = plaintext   full MSE: SEND_DH->..->DONE,
#       BT handshake, dropped plaintext_strict_share  byte-identical
#    1   first bytes opaque (MSE DHKey offer),      full MSE: same walk,
#       seed accepts MSE, byte-identical            byte-identical
#    2   plaintext BT handshake, dropped            closes the socket right
#                                                    after ntx's DHKey:
#                                                    pe_fail st=RECV_DH inn=0
#
# Read the table by what it measures, not by anybody's enum name: 1 is the only
# value that opens with MSE in both directions, 0 accepts MSE but opens in
# plaintext, 2 speaks plaintext one way and refuses MSE the other. That is
# consistent with qbt 4.5.2's own ordering (0=allow, 1=require, 2=plaintext),
# which is NOT libtorrent's peer_encryption_t — the 0/1/2 = plaintext/allow/
# require mapping this file used to document is libtorrent's, and applying it
# here put "require" and "plaintext" on swapped values.
#
# Hence: ENC=1 is kept (the plan's value, and by measurement the MSE-only one),
# and the cell proves the handshake in BOTH directions separately using the
# tracker's --blind knob, because in the unblinded run the two sides dial each
# other simultaneously and only the winner is observable. The old failure trace
# (`pe_fail st=RECV_DH inn=0` + `plaintext_strict_share`) is the trace of ENC=2,
# i.e. of a client with encryption turned off — it was never evidence about
# ntx's MSE initiator or responder, and ntx behaved correctly in both of its
# places in that trace (it offered MSE, and it refused plaintext on a share).
if [ "$MODE" = qbt-share-leech ]; then
    TOR="$SRC"                     # single .torrent, not a fixture dir
    WEBUI="${6:-8080}"
    SECS="${7:-120}"
    CA_PEM="${8:-}"
    ENC="${9:-1}"                  # libtorrent peer-socket encryption enum (1 = plan's value)
    # The share's announce is HTTPS and pinned by ntx, but libtorrent has no
    # pinning — it validates the tracker cert through the ordinary trust store.
    # Installing the harness CA is the honest equivalent of a real share host's
    # publicly trusted certificate; without it qbt simply never reaches the
    # tracker and the peer never learns the seeder's address.
    if [ -n "$CA_PEM" ] && [ -f "$CA_PEM" ]; then
        cp "$CA_PEM" /usr/local/share/ca-certificates/ntx-sharetest-tracker.crt 2>/dev/null \
            && update-ca-certificates >/tmp/ca.log 2>&1 \
            || echo "CA-INSTALL-DEFERRED (no root?); see /tmp/ca.log"
    fi
    rm -rf "$SAVE"; mkdir -p "$SAVE"
    PROFILE=$(mktemp -d /tmp/qbtprof.XXXXXX)
    mkdir -p "$PROFILE/qBittorrent/config"
    cat > "$PROFILE/qBittorrent/config/qBittorrent.conf" <<CONF
[BitTorrent]
Session\Port=$PORT
Session\Encryption=$ENC
Session\DHTEnabled=false
Session\PeXEnabled=false
Session\LSDEnabled=false
Session\PortForwardingEnabled=false
Session\QueueingSystemEnabled=false
# 4.5.2 ignores the save_path form field of torrents/add and writes to the
# session default instead, so the destination has to be set here or the harness
# cannot read the file back. Verified against /api/v2/app/preferences: this is
# the key that makes save_path read back as the path below.
Session\DefaultSavePath=$SAVE

[LegalNotice]
Accepted=true

[Preferences]
WebUI\Port=$WEBUI
WebUI\LocalHostAuth=false
WebUI\AuthSubnetWhitelistEnabled=true
WebUI\AuthSubnetWhitelist=127.0.0.1/32, 172.16.0.0/12
CONF
    qbittorrent-nox --profile="$PROFILE" >/tmp/qbt.log 2>&1 &
    QPID=$!
    for _ in $(seq 1 25); do listening "$WEBUI" && break; sleep 1; done
    if ! listening "$WEBUI"; then
        echo "QBT-WEBUI-NOT-LISTENING port=$WEBUI"
        tail -n 10 /tmp/qbt.log
        kill "$QPID" 2>/dev/null
        exit 3
    fi
    python3 - "$TOR" "$SAVE" "$WEBUI" "$SECS" <<'PY'
import json, sys, time, urllib.error, urllib.parse, urllib.request

torrent, save, webui, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]), int(sys.argv[4])
BASE = "http://127.0.0.1:%d" % webui


def call(path, fields=None, files=None):
    data, hdr = None, {}
    if files:
        B = "ntxb"
        body = b""
        for k, v in (fields or {}).items():
            body += ('--%s\r\nContent-Disposition: form-data; name="%s"\r\n\r\n%s\r\n'
                     % (B, k, v)).encode()
        for k, (fn, blob) in files.items():
            body += ('--%s\r\nContent-Disposition: form-data; name="%s"; filename="%s"\r\n'
                     'Content-Type: application/x-bittorrent\r\n\r\n' % (B, k, fn)).encode()
            body += blob + b"\r\n"
        body += ("--%s--\r\n" % B).encode()
        data = body
        hdr["Content-Type"] = "multipart/form-data; boundary=" + B
    elif fields is not None:
        data = urllib.parse.urlencode(fields).encode()
        hdr["Content-Type"] = "application/x-www-form-urlencoded"
    return urllib.request.urlopen(urllib.request.Request(BASE + path, data=data, headers=hdr),
                                  timeout=15).read().decode()

def get(path, **qs):
    url = BASE + path
    if qs:
        url += "?" + urllib.parse.urlencode(qs)
    return urllib.request.urlopen(urllib.request.Request(url), timeout=15).read().decode()


for _ in range(30):  # the WebUI binds a moment after the process starts
    try:
        call("/api/v2/app/version")
        break
    except Exception:
        time.sleep(1)

try:
    p = json.loads(call("/api/v2/app/preferences"))
    print("QBT-PREFS encryption=%s dht=%s pex=%s lsd=%s port=%s"
          % (p.get("encryption"), p.get("dht"), p.get("pex"), p.get("lsd"), p.get("listen_port")))
except Exception as e:
    print("QBT-PREFS-ERR %s" % e)

def report_evidence(t):
    """What the cell prints as evidence. torrents/properties|files|trackers all
    answer 400 on this build for every hash spelling (v1, v2, `all`), so the
    observable channel is sync/maindata plus the torrents/info row: infohash_v1
    is the id the ntx seed announced, content_path is where the bytes landed,
    and maindata's dht_nodes must stay 0 under BEP 27."""
    print("QBT-EVIDENCE hash=%s infohash_v1=%s save_path=%r content_path=%r "
          "downloaded=%s size=%s state=%s progress=%s tracker=%r trackers=%s"
          % (t.get("hash"), t.get("infohash_v1"), t.get("save_path"), t.get("content_path"),
             t.get("downloaded"), t.get("size"), t.get("state"), t.get("progress"),
             t.get("tracker"), t.get("trackers_count")))
    try:
        md = json.loads(get("/api/v2/sync/maindata"))
        ss = md.get("server_state") or {}
        print("QBT-SESSION dht_nodes=%s total_peer_connections=%s connection_status=%s"
              % (ss.get("dht_nodes"), ss.get("total_peer_connections"),
                 ss.get("connection_status")))
    except Exception as e:
        print("QBT-SESSION-ERR %s" % e)

name = torrent.rsplit("/", 1)[-1]
try:
    print("QBT-ADD", call("/api/v2/torrents/add",
                          {"save_path": save, "paused": "false", "category": "",
                           "skip_hash_check": "false", "auto_tmm": "false"},
                          {"torrents": (name, open(torrent, "rb").read())}))
except urllib.error.HTTPError as e:
    print("QBT-ADD-FAIL http=%s %s" % (e.code, e.read()[:200]))
    sys.exit(4)

deadline, last, seen = time.time() + secs, "no-info", False
while time.time() < deadline:
    try:
        info = json.loads(call("/api/v2/torrents/info"))
    except Exception as e:
        info = []
        last = "info-error %s" % e
    if info:
        if not seen:
            for x in info:
                print("QBT-TORRENT hash=%s name=%r progress=%s state=%s"
                      % (x.get("hash"), x.get("name"), x.get("progress"), x.get("state")))
            seen = True
    if info:
        t = info[0]
        last = ("progress=%s state=%s seeds=%s peers=%s size=%s done=%s ratio=%s error=%r"
                % (t.get("progress"), t.get("state"), t.get("num_seeds"), t.get("num_peers"),
                   t.get("size"), t.get("done"), t.get("ratio"), t.get("error")))
        if t.get("progress") == 1.0 and t.get("state") in (
                "uploading", "stalledUP", "forcedUP", "pausedUP", "checkingUP"):
            print("QBT-DONE", last)
            report_evidence(t)
            sys.exit(0)
    time.sleep(1)
print("QBT-INCOMPLETE", last)
try:
    report_evidence(json.loads(call("/api/v2/torrents/info"))[0])
except Exception as e:
    print("QBT-EVIDENCE-ERR %s" % e)
sys.exit(5)
PY
    rc=$?
    kill -TERM "$QPID" 2>/dev/null
    timeout -k 5 10 wait "$QPID" 2>/dev/null || kill -9 "$QPID" 2>/dev/null
    echo "--- /tmp/qbt.log ---"
    tail -n 12 /tmp/qbt.log
    exit $rc
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
