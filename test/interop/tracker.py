#!/usr/bin/env python3
# Minimal BitTorrent HTTP tracker for interop testing (test harness, not SUT).
# transmission 3.00's web server enforces the RPC session-id on every request and
# has no usable built-in announce endpoint, so this tiny tracker stands in: it
# answers every GET with a bencoded dict whose "peers" (compact) is the fixed
# seeder address (transmission's peer port). ntx's tracker client (ntx_tracker.c)
# parses exactly this shape.
import http.server
import socket
import struct
import sys

SEED_PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 51413
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 6969


def bint(n):
    return b'i' + str(n).encode() + b'e'


def bstr(s):
    if isinstance(s, str):
        s = s.encode()
    return str(len(s)).encode() + b':' + s


PEERS = socket.inet_aton('127.0.0.1') + struct.pack('>H', SEED_PORT)
RESP = (b'd'
        + bstr('complete') + bint(1)
        + bstr('incomplete') + bint(0)
        + bstr('interval') + bint(300)
        + bstr('peers') + bstr(PEERS)
        + b'e')


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.0'  # close after response -> ntx reads to EOF

    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-Type', 'text/plain')
        self.send_header('Content-Length', str(len(RESP)))
        self.end_headers()
        self.wfile.write(RESP)

    def log_message(self, format, *args):
        pass


if __name__ == '__main__':
    http.server.HTTPServer(('127.0.0.1', PORT), Handler).serve_forever()
