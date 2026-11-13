#!/usr/bin/env python3
"""Pinned HTTPS announce registry for the private-share interop cell.

`ntx --share` announces ONLY to the HTTPS share list compiled into the binary
(design §6), so the plain one-address tracker the other v2 cells use cannot
stand in: the seeder's announce has to arrive over pinned HTTPS or the share
never reaches READY, and the two peers of a private swarm have to be DISCOVERED
rather than assumed (BEP 27 forbids every other source). This is the qualified
share tracker of §6.3, faked:

  * HTTPS via http.server + ssl with the P-256 certificate share_cert.py just
    minted, on two bind endpoints because the share list needs
    NTX_SHARE_MIN_TRACKERS=2 rows and ntx announces to all of them;
  * peers remembered per info_hash, answered `compact=1`, `left=0` counted as
    complete — that is the §5.5 seed claim the cell asserts;
  * the address handed out for a peer is the address the tracker OBSERVED it
    at, so host and container peers find each other whatever topology the cell
    runs them in;
  * `/scrape` without `info_hash` answers 400 (§6.3);
  * every request line is appended to the evidence log and a JSON summary lands
    in --state on SIGTERM: the cell reads both to show the swarm talked to this
    tracker only, saw exactly the expected peers, and never scraped.

The query is decoded as BYTES: info_hash and peer_id are raw 20-byte values,
and parse_qs would hand back str and mangle every non-ASCII octet, which splits
one swarm into several. `--self-check` asserts that decode.

Harness, not the SUT — deliberately independent of ntx's own code so it cannot
talk itself into a PASS.
"""
import argparse
import http.server
import json
import os
import signal
import socket
import ssl
import struct
import threading
import time

LOCK = threading.Lock()
PEERS = {}  # info_hash hex -> {peer_id hex: {"ip","port","left","events","scheme"}}
STATS = {"requests": 0, "scrape_no_hash": 0, "other_paths": 0}
# --blind: peer_id prefixes that get an EMPTY peer list (see --blind's help).
# Discovery is still real — the blinded peer simply is not told where the other
# one lives — so the cell can force exactly ONE direction of the MSE handshake
# to be the one that happens, and prove both of them rather than trusting
# whichever won the simultaneous-open race.
BLIND = []


def benc(n):
    return b"i" + str(n).encode() + b"e"


def bstr(b):
    if isinstance(b, str):
        b = b.encode()
    return str(len(b)).encode() + b":" + b


def unquote(b):
    out, i = bytearray(), 0
    while i < len(b):
        c = b[i:i + 1]
        if c == b"%":
            out += bytes.fromhex(b[i + 1:i + 3].decode("ascii"))
            i += 3
        elif c == b"+":
            out += b" "
            i += 1
        else:
            out += c
            i += 1
    return bytes(out)


def parse_query_bytes(query):
    q = {}
    for pair in query.split(b"&"):
        if not pair:
            continue
        k, _, v = pair.partition(b"=")
        q.setdefault(unquote(k), []).append(unquote(v))
    return q


def compact(entries):
    out = b""
    for ip, port in entries:
        out += socket.inet_aton(ip) + struct.pack(">H", port)
    return out

def blinded(peer_id):
    """True if this announcer must be answered an empty peer list."""
    return any(peer_id.startswith(p.encode("latin1")) for p in BLIND)


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.0"  # close after response -> ntx reads to EOF

    def reply(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        path, _, query = self.path.partition("?")
        q = parse_query_bytes(query.encode("latin1"))
        with LOCK:
            STATS["requests"] += 1
            if path == "/scrape":
                if b"info_hash" not in q:
                    STATS["scrape_no_hash"] += 1
                    self.reply(400, b"d15:failure reason14:no info_hash sete")
                    return
                self.reply(200, b"d5:filesde")
                return
            if path != "/announce":
                STATS["other_paths"] += 1
                self.reply(404, b"d15:failure reason8:no path e")
                return
            ih = (q.get(b"info_hash") or [b""])[0]
            pid = (q.get(b"peer_id") or [b""])[0]
            ip = self.client_address[0]
            try:
                port = int((q.get(b"port") or [b"0"])[0])
            except ValueError:
                port = 0
            left = (q.get(b"left") or [b"?"])[0].decode("latin1")
            event = (q.get(b"event") or [b"none"])[0].decode("latin1")
            scheme = "https" if getattr(self.server, "is_tls", False) else "http"
            with open(self.server.log_path, "a") as f:
                f.write("announce scheme=%s src=%s:%d hash=%s peer_id=%s left=%s event=%s\n"
                        % (scheme, ip, port, ih.hex(), pid.hex(), left, event))
                f.flush()
            table = PEERS.setdefault(ih.hex(), {})
            if event == "stopped":
                table.pop(pid.hex(), None)
            elif port:
                ent = table.setdefault(pid.hex(), {"ip": ip, "port": port, "left": left,
                                                   "events": [], "scheme": scheme})
                ent.update(ip=ip, port=port, left=left, scheme=scheme)
                ent["events"].append(event)
            others = [v for k, v in table.items() if k != pid.hex()]
            if blinded(pid):
                others = []
            body = (b"d"
                    + bstr("complete") + benc(sum(1 for v in others if v["left"] == "0"))
                    + bstr("incomplete") + benc(len([v for v in others if v["left"] != "0"]))
                    + bstr("interval") + benc(30)
                    + bstr("peers") + bstr(compact([(v["ip"], v["port"]) for v in others]))
                    + b"e")
            self.reply(200, body)

    def log_message(self, fmt, *args):
        pass


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(bind, port, log, cert=None, key=None):
    # Bind BEFORE anything else and refuse to start otherwise. A stale
    # orphan already on this port must be a loud, immediate failure — not a
    # half-started tracker that lets the cell run against the wrong certificate.
    srv = Server((bind, port), Handler)
    srv.log_path = log
    srv.is_tls = bool(cert)
    if cert:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(cert, key)
        srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def alive(pid):
    """Is pid still a running process? A zombie does not count: it is dead, just
    not reaped yet, and holding a port does not need a reaped parent."""
    try:
        with open("/proc/%d/stat" % pid, "rb") as f:
            return f.read().rsplit(b")", 1)[1].split()[0] not in (b"Z", b"X", b"x")
    except FileNotFoundError:
        return False
    except OSError:
        return True  # unreadable but present: assume alive, never kill ourselves


def watch_harness(pid):
    """Quit when whoever started us goes away.

    A matrix run killed by a signal never reaches the harness's stop_job, and an
    orphaned tracker sitting on its ports with a STALE certificate poisons the
    next run: the seeder then pins against a cert no tracker answers with, and
    the cell fails with a pin mismatch that looks like a product bug.

    Two conditions, because there are two relevant parents: our DIRECT parent is
    the `timeout` wrapper (reparenting = it died; this is also what
    PR_SET_PDEATHSIG would only half-cover, since it would watch the wrapper and
    not the script), and the harness script itself is the process whose job list
    is supposed to stop us.
    """
    ppid = os.getppid()
    while True:
        time.sleep(1)
        if os.getppid() != ppid:
            os._exit(0)
        if pid and not alive(pid):
            os._exit(0)


def self_check():
    """The one check this harness owes: the query decode must stay byte-exact."""
    q = parse_query_bytes(b"info_hash=%00%FF%00A&peer_id=-qB0000%2B%25%00x&port=6881&left=0")
    assert q[b"info_hash"] == [b"\x00\xff\x00A"], q
    assert q[b"peer_id"] == [b"-qB0000+%\x00x"], q
    assert q[b"port"] == [b"6881"] and q[b"left"] == [b"0"]
    assert compact([("127.0.0.2", 6881)]) == socket.inet_aton("127.0.0.2") + b"\x1a\xe1"
    assert benc(1) == b"i1e" and bstr("ab") == b"2:ab"
    print("share_registry_tracker self-check OK")
    return 0


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--self-check", action="store_true")
    ap.add_argument("--bind", default="127.0.0.2", help="bind host of the first HTTPS row")
    ap.add_argument("--bind2", default="127.0.0.3", help="bind host of the second HTTPS row")
    ap.add_argument("--https-port", type=int)
    ap.add_argument("--https-port2", type=int)
    ap.add_argument("--http-port", type=int, default=0, help="optional plain endpoint (0 = off)")
    ap.add_argument("--http-bind", default="127.0.0.1")
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--log")
    ap.add_argument("--state")
    ap.add_argument("--harness-pid", type=int, default=0,
                    help="exit when this pid (the matrix script) goes away; 0 disables the guard")
    ap.add_argument("--blind", default="",
                    help="comma-separated peer_id prefixes that are answered an EMPTY peer list, so "
                         "the swarm can only be discovered in one direction. Lets the cell force "
                         "which side dials and prove each MSE direction on its own.")
    a = ap.parse_args()

    if a.self_check:
        return self_check()
    global BLIND
    BLIND = [x for x in a.blind.split(",") if x]
    missing = [o for o, v in (("--https-port", a.https_port), ("--https-port2", a.https_port2),
                              ("--cert", a.cert), ("--key", a.key), ("--log", a.log),
                              ("--state", a.state)) if not v]
    if missing:
        ap.error("missing required argument(s): " + ", ".join(missing))

    open(a.log, "a").close()  # so the cell can tell "no requests" from "no log"

    def dump():
        with LOCK:
            blob = json.dumps({"requests": STATS["requests"],
                               "scrape_no_hash": STATS["scrape_no_hash"],
                               "other_paths": STATS["other_paths"], "peers": PEERS},
                              sort_keys=True)
        # Atomic replace, so a dump in flight can never leave half a file for the
        # cell to read as "no announces".
        tmp = a.state + ".tmp"
        with open(tmp, "w") as f:
            f.write(blob)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, a.state)

    def on_term(_sig, _frm):
        dump()
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, on_term)
    signal.signal(signal.SIGINT, on_term)

    serve(a.bind, a.https_port, a.log, a.cert, a.key)
    serve(a.bind2, a.https_port2, a.log, a.cert, a.key)
    if a.http_port:
        serve(a.http_bind, a.http_port, a.log)
    if a.harness_pid:
        threading.Thread(target=watch_harness, args=(a.harness_pid,), daemon=True).start()

    # Keep the state file live, not just SIGTERM-fresh. The cell reads it to prove
    # the announces happened; if it were only written by the signal handler, a
    # tracker reaped by host OOM (this box runs ~95/121 GB) would take the whole
    # run's evidence with it and the cell could not tell "the tracker died" apart
    # from "nobody announced". Dumping every 2 s costs nothing and the asserts
    # below are unchanged -- they read the same numbers.
    def keep_state():
        while True:
            time.sleep(2)
            try:
                dump()
            except OSError:
                pass

    threading.Thread(target=keep_state, daemon=True).start()
    threading.Event().wait()  # daemon threads; SIGTERM is the stop button


if __name__ == "__main__":
    main()
