#!/usr/bin/env python3
"""Local HTTPS announce tracker for the private-share end-to-end test.

Test harness only (never shipped), so it is deliberately simple: stdlib
`http.server` wrapped in `ssl`, no third-party dependency.

  usage: tracker_https.py LOGFILE [CERT.pem KEY.pem] [BIND_IPS]

BIND_IPS (argv[4]) is a comma-separated list of loopback addresses to listen
on, default 127.0.0.1.  All of them share one OS-assigned port, printed once as
PORT=<n>; the share e2e passes two, because the built-in HTTPS pin pool
(src/proto/ntx_https_pin.c) owns 127.0.0.1 for the dev leaf and is consulted
before the share-tracker table, so a test-pinned tracker must live on other
loopback addresses.

* Binds 127.0.0.1 on an OS-assigned ephemeral port (never a fixed one — other
  suites own 6975-6995) and prints `PORT=<n>` on stdout once bound, so the
  caller can build the announce URL, the SPKI pin and the rendered
  trackers.inc.  `PORT=ERR <reason>` + exit 1 when it cannot come up.
* The P-256 self-signed certificate is generated at start (openssl CLI, which
  the plan guarantees) into a work dir under the log file's directory and is
  removed again on exit — the caller reads it before `PORT=` is printed.
  Pass CERT KEY as argv[2..3] to serve a certificate the caller made itself
  (the shell harness uses this so the SPKI pin and the served cert cannot
  drift apart, and so no openssl child is left behind on teardown).
* Per BEP 3 it answers `GET /announce?info_hash=..&peer_id=..&port=..` with a
  compact peer list, remembering every (info_hash, ip, port) it has seen and
  never returning the announcing peer itself, so two `ntx` processes on
  127.0.0.1 actually find each other.
* `/scrape` without `info_hash` answers 400 (BEP 3 requires the hash there);
  every other unknown path answers 404.  Both counts are assertions in
  share_e2e.sh, which greps the log file.
* Every request line is appended to LOGFILE as one line per request:
    ANN <ih> <ip> <port> <event> peer_id=<hex>
    ANN_BAD <ih> <reason>
    SCRAPE_NOHASH <query>
    OTHER <method> <path> <status>
  flush-per-line, so the harness can poll it while the peers still run.
"""
import http.server
import os
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse

PEER_LEN = 6  # BEP 3 compact: 4-byte IPv4 + 2-byte port


def bint(n):
    return b"i" + str(int(n)).encode() + b"e"


def bstr(s):
    if isinstance(s, str):
        s = s.encode()
    return str(len(s)).encode() + b":" + s


def bdict(pairs):
    """BEP 3 bencoded dict: d (k1 v1)(k2 v2)… e — keys pre-encoded by caller."""
    return b"d" + b"".join(k + v for k, v in pairs) + b"e"


def compact(pairs):
    out = b""
    for ip, port in pairs:
        out += socket.inet_aton(ip) + struct.pack(">H", port)
    return out


class Tracker(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"  # keep-alive: ntx announces more than once
    server_version = "ntx-sharetest"

    # --- logging -------------------------------------------------------
    def log(self, line):
        self.server.logf.write(line + "\n")
        self.server.logf.flush()

    def log_message(self, fmt, *args):
        pass  # stderr chatter would only confuse the harness

    # --- bencoded replies ----------------------------------------------
    def reply(self, code, body=b"", ctype="text/plain"):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        if body:
            self.wfile.write(body)

    def reply_fail(self, reason):
        self.reply(200, bdict([(bstr("failure reason"), bstr(reason))]))

    # --- HTTP entry points ---------------------------------------------
    def do_GET(self):
        try:
            self.route_GET()
        except Exception as e:  # never let one request take the harness down
            try:
                self.log("HANDLER_ERR %s: %s" % (type(e).__name__, e))
                self.reply(500, b"tracker error\n")
            except Exception:
                self.close_connection = True

    def route_GET(self):
        path, _, query = self.path.partition("?")
        # encoding='latin-1' so the %XX escapes of the binary info_hash / peer_id
        # come back as 20 single-byte code points; the default utf-8 decoding
        # would fold them into U+FFFD and destroy the hash.
        q = urllib.parse.parse_qs(query, keep_blank_values=True, encoding="latin-1")
        if path == "/announce":
            self.do_announce(q)
        elif path == "/scrape":
            if q.get("info_hash"):
                self.reply(200, bdict([(bstr("files"), bdict([]))]))
            else:
                self.log("SCRAPE_NOHASH %s" % (query or "-"))
                self.reply(400, b"scrape needs info_hash\n")
        elif path == "/":
            self.log("OTHER GET / 200")
            self.reply(200, b"ntx-sharetest tracker\n")
        else:
            self.log("OTHER GET %s 404" % path)
            self.reply(404, b"not found\n")

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        if length:
            self.rfile.read(length)
        path = self.path.partition("?")[0]
        self.log("OTHER POST %s 404" % path)
        self.reply(404, b"not found\n")

    # --- BEP 3 announce -------------------------------------------------
    def do_announce(self, q):
        peer_ip = self.client_address[0]
        raw_ih = q.get("info_hash", [""])[0]
        if len(raw_ih) != 20:
            self.log("ANN_BAD %s bad-info-hash-len=%d" % (raw_ih.encode("latin1").hex(), len(raw_ih)))
            return self.reply_fail("bad info_hash")
        ih = raw_ih.encode("latin1").hex()
        raw_pid = q.get("peer_id", [""])[0]
        pid = raw_pid.encode("latin1")
        if len(pid) != 20:
            self.log("ANN_BAD %s bad-peer-id-len=%d" % (ih, len(pid)))
            return self.reply_fail("bad peer_id")
        try:
            port = int(q.get("port", ["0"])[0])
            left = int(q.get("left", ["0"])[0])
            uploaded = int(q.get("uploaded", ["0"])[0])
        except ValueError:
            self.log("ANN_BAD %s bad-numbers" % ih)
            return self.reply_fail("bad numbers")
        if not 1 <= port <= 65535:
            self.log("ANN_BAD %s bad-port=%d" % (ih, port))
            return self.reply_fail("bad port")
        if q.get("compact", ["1"])[0] != "1":
            self.log("ANN_BAD %s compact-not-1" % ih)
            return self.reply_fail("this tracker only speaks compact=1")
        event = q.get("event", ["none"])[0]

        swarm = self.server.peers.setdefault(ih, {})
        key = (peer_ip, port)
        if event == "stopped":
            swarm.pop(key, None)
        else:
            swarm[key] = {"pid": pid.hex(), "seed": left == 0, "up": uploaded}
        others = [k for k in swarm if k != key]
        self.log("ANN %s %s %d %s peer_id=%s seed=%d n=%d"
                 % (ih, peer_ip, port, event, pid.hex(), int(left == 0), len(others)))
        body = bdict([
            (bstr("interval"), bint(30)),
            (bstr("complete"), bint(sum(1 for v in swarm.values() if v["seed"]))),
            (bstr("incomplete"), bint(sum(1 for v in swarm.values() if not v["seed"]))),
            (bstr("peers"), bstr(compact(others))),
        ])
        self.reply(200, body, "text/plain")


class Server(http.server.ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def gen_cert(workdir):
    """P-256 self-signed cert, CN/SAN 127.0.0.1, via the openssl CLI."""
    key = os.path.join(workdir, "tracker-key.pem")
    crt = os.path.join(workdir, "tracker-cert.pem")
    cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-pkeyopt", "ec_param_enc:named_curve", "-sha256", "-days", "2", "-nodes",
           "-keyout", key, "-out", crt, "-subj", "/CN=127.0.0.1",
           "-addext", "subjectAltName=IP:127.0.0.1"]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if r.returncode != 0:
        die("openssl failed: %s" % r.stderr.decode("utf8", "replace").strip()[-200:])
    return crt, key


def die(msg):
    print("PORT=ERR %s" % msg)
    sys.stdout.flush()
    sys.exit(1)


def main():
    if len(sys.argv) < 2:
        die("usage: tracker_https.py LOGFILE [CERT KEY]")
    logpath = sys.argv[1]
    tmpdir = None
    if len(sys.argv) >= 4:
        crt, key = sys.argv[2], sys.argv[3]
    else:
        root = os.path.dirname(os.path.abspath(logpath)) or "."
        tmpdir = tempfile.mkdtemp(prefix="cert.", dir=root)
        crt, key = gen_cert(tmpdir)
    ips = [i for i in (sys.argv[4] if len(sys.argv) >= 5 else "127.0.0.1").split(",") if i]
    if not ips:
        die("empty BIND_IPS")

    logf = open(logpath, "a", buffering=1)
    peers = {}
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        ctx.options |= ssl.OP_NO_COMPRESSION
    try:  # TLS 1.3 x25519 + ecdsa_secp256r1_sha256 is what ntx's client offers
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass

    # One port, one listener per address: every address in the pin table has to
    # answer, and a peer list split across listeners would not find the seed.
    servers = []
    port = 0
    try:
        for ip in ips:
            srv = Server((ip, port), Tracker)
            if port == 0:
                port = srv.server_address[1]
            elif srv.server_address[1] != port:
                die("cannot reuse port %d on %s" % (port, ip))
            srv.logf = logf
            srv.peers = peers
            srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
            servers.append(srv)
    except OSError as e:
        for s in servers:
            s.server_close()
        die("bind %s: %s" % (",".join(ips), e))

    print("PORT=%d" % port)
    sys.stdout.flush()
    threads = [threading.Thread(target=s.serve_forever, kwargs={"poll_interval": 0.2}, daemon=True)
               for s in servers]
    for t in threads:
        t.start()
    try:
        while any(t.is_alive() for t in threads):
            time.sleep(0.2)
    except KeyboardInterrupt:
        pass
    finally:
        for s in servers:
            s.shutdown()
            s.server_close()
        logf.close()
        if tmpdir:
            for f in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
