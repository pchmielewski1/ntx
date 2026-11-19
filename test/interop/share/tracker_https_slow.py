#!/usr/bin/env python3
"""Slow HTTPS announce tracker for test/t_session_trk_http_slow.c.

Test harness only (never shipped). Like test/interop/share/tracker_https.py it is
stdlib + `openssl` only; the difference is that it answers **slowly on purpose**, so
the test can put a healthy-but-late tracker on either side of NTX_TRK_HTTP_BUDGET_MS.
Four wall-clock sleeps, one per phase of the fetch, all in milliseconds:

    --accept-ms     after accept(), before the TLS handshake is served
    --handshake-ms  after the TLS handshake, before the request is read
    --request-ms    after the request is read, before the reply is built
    --response-ms   after the reply is built, before its bytes are written

The client cannot tell these apart from the outside — every one of them is the
budget being spent on a live server — which is exactly what the test needs.

stdout, once bound (the caller reads these two lines):

    PORT=<n>
    SPKI=<64 hex>      SHA-256 of the leaf's SubjectPublicKeyInfo — the pin the
                       caller installs in the test pin pool (never hand-typed)

Log lines, one per event, flushed:

    SLEEP <accept>/<handshake>/<request>/<response>   (once, at start)
    ANN <ih-hex> <port> <event>                        (one per announce)
    OTHER <request line>                               (anything not /announce)
    HANDLER_ERR <type>: <msg>

  usage: tracker_https_slow.py --log F --ip 127.0.0.2 [--cert C --key K]
                               --accept-ms N --handshake-ms N --request-ms N
                               --response-ms N
"""
import argparse
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

PEER_PORT = 40001  # default compact peer this tracker hands back (override: --peer-port)


def bint(n):
    return b"i" + str(int(n)).encode() + b"e"


def bstr(s):
    if isinstance(s, str):
        s = s.encode()
    return str(len(s)).encode() + b":" + s


def bdict(pairs):
    return b"d" + b"".join(k + v for k, v in pairs) + b"e"


def compact(pairs):
    out = b""
    for ip, port in pairs:
        out += socket.inet_aton(ip) + struct.pack(">H", port)
    return out


def sleep_ms(ms):
    if ms > 0:
        time.sleep(ms / 1000.0)


def gen_cert(workdir, ip):
    key = os.path.join(workdir, "slow-key.pem")
    crt = os.path.join(workdir, "slow-cert.pem")
    cmd = ["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1",
           "-pkeyopt", "ec_param_enc:named_curve", "-sha256", "-days", "2", "-nodes",
           "-keyout", key, "-out", crt, "-subj", "/CN=%s" % ip,
           "-addext", "subjectAltName=IP:%s" % ip]
    r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    if r.returncode != 0:
        die("openssl req: %s" % r.stderr.decode("utf8", "replace").strip()[-200:])
    return crt, key


def spki_pin(crt):
    """SHA-256 over the leaf's DER SubjectPublicKeyInfo, 64 lowercase hex."""
    p1 = subprocess.Popen(["openssl", "x509", "-in", crt, "-pubkey", "-noout"],
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    p2 = subprocess.Popen(["openssl", "pkey", "-pubin", "-outform", "DER"],
                          stdin=p1.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    p3 = subprocess.Popen(["openssl", "dgst", "-sha256", "-r"],
                          stdin=p2.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    out = p3.communicate()[0].decode("ascii", "replace").strip()
    pin = out.split()[0].lower() if out else ""
    if len(pin) != 64 or any(c not in "0123456789abcdef" for c in pin):
        die("cannot read the SPKI pin from openssl: %r" % out)
    return pin


def die(msg):
    print("PORT=ERR %s" % msg)
    sys.stdout.flush()
    sys.exit(1)


class Session(threading.Thread):
    """One announce: sleep, handshake, sleep, read, sleep, answer, sleep, write."""

    daemon = True

    def __init__(self, srv, conn):
        super().__init__()
        self.srv, self.conn = srv, conn

    def read_request(self, tls):
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = tls.recv(4096)
            if not chunk:
                return None
            buf += chunk
            if len(buf) > 65536:
                return None
        return buf.decode("latin-1")

    def run(self):
        srv = self.srv
        tls = None
        try:
            sleep_ms(srv.cfg["accept_ms"])          # 1. connect / accept
            tls = srv.ctx.wrap_socket(self.conn, server_side=True)
            sleep_ms(srv.cfg["handshake_ms"])       # 2. after the handshake
            req = self.read_request(tls)
            sleep_ms(srv.cfg["request_ms"])         # 3. after the request
            if req is None:
                return
            status, body = srv.reply(req)
            resp = ("HTTP/1.1 %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\n"
                    "Connection: close\r\n\r\n" % (status, len(body))).encode("latin-1") + body
            sleep_ms(srv.cfg["response_ms"])        # 4. before the bytes go out
            tls.sendall(resp)
        except Exception as e:  # never let one connection take the harness down
            srv.log("HANDLER_ERR %s: %s" % (type(e).__name__, e))
        finally:
            try:
                if tls is not None:
                    tls.close()
                else:
                    self.conn.close()
            except OSError:
                pass


class Server(threading.Thread):
    daemon = True

    def __init__(self, ip, ctx, cfg, logf):
        super().__init__()
        self.cfg, self.ctx, self.logf = cfg, ctx, logf
        self.stop = False
        self.lfd = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.lfd.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.lfd.bind((ip, 0))
        self.lfd.listen(16)
        self.port = self.lfd.getsockname()[1]

    def log(self, line):
        self.logf.write(line + "\n")
        self.logf.flush()

    def reply(self, req):
        try:
            line = req.split("\r\n", 1)[0]
            method, path, _ = line.split(" ", 2)
        except ValueError:
            self.log("OTHER %r" % req[:80])
            return "400 Bad Request", b"bad request line\n"
        if method != "GET" or not path.startswith("/announce"):
            self.log("OTHER %s" % line)
            return "404 Not Found", b"not found\n"
        _, _, query = path.partition("?")
        q = urllib.parse.parse_qs(query, keep_blank_values=True, encoding="latin-1")
        ih = q.get("info_hash", [""])[0].encode("latin-1")
        if len(ih) != 20:
            self.log("ANN_BAD bad-info-hash-len=%d" % len(ih))
            return "200 OK", bdict([(bstr("failure reason"), bstr("bad info_hash"))])
        try:
            port = int(q.get("port", ["0"])[0] or 0)
        except ValueError:
            port = 0
        event = q.get("event", ["none"])[0]
        self.log("ANN %s %d %s" % (ih.hex(), port, event))
        body = bdict([
            (bstr("interval"), bint(1800)),
            (bstr("complete"), bint(1)),
            (bstr("incomplete"), bint(0)),
            (bstr("peers"), bstr(compact([("127.0.0.1", self.cfg["peer_port"])]))),
        ])
        return "200 OK", body

    def run(self):
        while not self.stop:
            try:
                conn, _addr = self.lfd.accept()
            except OSError:
                return
            Session(self, conn).start()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--log", required=True)
    ap.add_argument("--ip", default="127.0.0.2")
    ap.add_argument("--peer-port", type=int, default=PEER_PORT)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--accept-ms", type=int, default=0)
    ap.add_argument("--handshake-ms", type=int, default=0)
    ap.add_argument("--request-ms", type=int, default=0)
    ap.add_argument("--response-ms", type=int, default=0)
    a = ap.parse_args()

    tmpdir = None
    if a.cert and a.key:
        crt, key = a.cert, a.key
    else:
        root = os.path.dirname(os.path.abspath(a.log)) or "."
        tmpdir = tempfile.mkdtemp(prefix="cert.", dir=root)
        crt, key = gen_cert(tmpdir, a.ip)
    pin = spki_pin(crt)

    cfg = {"accept_ms": a.accept_ms, "handshake_ms": a.handshake_ms,
           "request_ms": a.request_ms, "response_ms": a.response_ms,
           "peer_port": a.peer_port}
    logf = open(a.log, "a", buffering=1)
    logf.write("SLEEP %d/%d/%d/%d peer_port=%d\n" % (cfg["accept_ms"], cfg["handshake_ms"],
                                                     cfg["request_ms"], cfg["response_ms"],
                                                     cfg["peer_port"]))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(crt, key)
    if hasattr(ssl, "OP_NO_COMPRESSION"):
        ctx.options |= ssl.OP_NO_COMPRESSION
    try:  # TLS 1.3 x25519 + ecdsa_secp256r1_sha256 is what ntx's client offers
        ctx.set_alpn_protocols(["http/1.1"])
    except NotImplementedError:
        pass
    try:
        srv = Server(a.ip, ctx, cfg, logf)
    except OSError as e:
        die("bind %s: %s" % (a.ip, e))
    srv.start()
    print("PORT=%d" % srv.port)
    print("SPKI=%s" % pin)
    sys.stdout.flush()
    try:
        while srv.is_alive():
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        srv.stop = True
        try:
            srv.lfd.close()
        except OSError:
            pass
        logf.close()
        if tmpdir:
            for f in os.listdir(tmpdir):
                os.unlink(os.path.join(tmpdir, f))
            os.rmdir(tmpdir)
    return 0


if __name__ == "__main__":
    sys.exit(main())
