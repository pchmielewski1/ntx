#!/usr/bin/env python3
"""Generate test/vectors/ipc/*.jsonl for the JSON Control API (§11.1, §12).
Schema escape_bad_name.jsonl: one vector per line, hex-encoded to dodge
JSON-escaping inception: in=<hex raw name bytes> out=<hex expected escaped>.
Regenerate: python3 test/scripts/ipc_vectors.py"""
import os

HERE = os.path.join(os.path.dirname(__file__), "..", "vectors", "ipc")
os.makedirs(HERE, exist_ok=True)

def esc(s: bytes) -> bytes:
    o = bytearray()
    for b in s:
        if b == 0x22:
            o += b'\\"'
        elif b == 0x5C:
            o += b'\\\\'
        elif b == 0x0A:
            o += b'\\n'
        elif b == 0x0D:
            o += b'\\r'
        elif b == 0x09:
            o += b'\\t'
        elif b < 0x20:
            o += ("\\u%04x" % b).encode()
        else:
            o += bytes([b])
    return bytes(o)

# ntx_json_escape is a C-string escaper (§11.1): it consumes a NUL-
# terminated char[], exactly like the char name[48] field it is fed from.
# A raw 0x00 is therefore outside the escaper's domain (it terminates the
# input), so the witness control-byte vector uses a NUL-free control pair
# (\u0001\u001f) to keep the reference oracle in lock-step with the C contract.
VECT = [b'a"b\\c\td\ne', b'plain', b"", b"\x01\x1f", b"\xff\xfe",
        b'"' * 47, b"\\" * 47]
with open(os.path.join(HERE, "escape_bad_name.jsonl"), "wb") as f:
    for v in VECT:
        f.write(b'in=' + v.hex().encode() + b' out=' + esc(v).hex().encode() + b'\n')
print("wrote test/vectors/ipc/escape_bad_name.jsonl (%d vectors)" % len(VECT))

# cmds_ok.jsonl / cmds_err.jsonl (§6.1, §6.4): each line carries the
# request line (hex), the expected verdict, and optional field expectations.
OKV = [
    (b'{"cmd":"ping","seq":7}', b'ok', b'cmd=ping seq=7'),
    (b'{"cmd":"pause","i":0,"seq":7}', b'ok', b'cmd=pause i=0 seq=7'),
    (b'{"cmd":"resume","i":15}', b'ok', b'cmd=resume i=15'),
    (b'{"cmd":"remove","i":3,"seq":-2}', b'ok', b'cmd=remove i=3 seq=-2'),
    (b'{"cmd":"quit"}', b'ok', b'cmd=quit'),
    (b'{"cmd":"ping","note":{"nested":1}}', b'bad_json', b''),   # v1 rejects nesting
    (b'{"cmd":"add","magnet":"magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"}',
     b'ok', b'cmd=add'),
    (b'{"cmd":"ping","x":1,"y":2}', b'ok', b'cmd=ping'),          # unknown keys skipped
    (b'{ }', b'bad_json', b''),
    (b'{"cmd":"pause","i":16}', b'bad_i', b''),
    (b'{"cmd":"pause","i":-1}', b'bad_i', b''),
    (b'{"cmd":"pause"}', b'bad_i', b''),
    (b'{"cmd":"nope"}', b'unknown_cmd', b''),
    (b'{"cmd":1}', b'bad_json', b''),
    (b'ping', b'bad_json', b''),
    (b'{"cmd":"add","magnet":"m:1","path":"a.torrent"}', b'bad_arg', b''),
    (b'{"cmd":"add","magnet":""}', b'bad_arg', b''),
    (b'{"cmd":"add","path":"' + b'A' * 512 + b'"}', b'io', b''),  # >511 B (§6.4)
    (b'{"cmd":"seqq","seq":7}', b'unknown_cmd', b''),
    (b'{"cmd":"ping","i":7}', b'ok', b'cmd=ping'),                # i ignored for ping
    (b'{"seq":5,"cmd":"hello"}', b'ok', b'cmd=hello seq=5'),      # any key order
]
def w(name, rows):
    with open(os.path.join(HERE, name), "wb") as f:
        for line, want, fields in rows:
            f.write(b'line=' + line.hex().encode() + b' want=' + want +
                    (b' ' + fields if fields else b'') + b'\n')
        print("wrote test/vectors/ipc/" + name + " (%d)" % len(rows))
w("cmds_ok.jsonl", [r for r in OKV if r[1] == b'ok'])
w("cmds_err.jsonl", [r for r in OKV if r[1] != b'ok'])
