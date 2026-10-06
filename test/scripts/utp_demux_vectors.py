#!/usr/bin/env python3
"""Golden vectors for the shared-demux first-byte classifier
(ntx_udp_classify in src/net/ntx_netx.c).

Normative: BEP 29 / BEP 5 first-byte rules.
  'd' | 'l' | 'i'                      -> bencode -> DHT (BEP5)
  high nibble type 0..4, low nibble 1  -> uTP header start (BEP29)
  otherwise (incl. empty)              -> drop (demux_unknown class)
Note: 0x64 as uTP would be type=6, ver=4 — never a legal uTP v1 byte.

Deterministic, self-checking. Writes:
  test/vectors/utp/demux_classify.bin       - concatenated datagram bytes
  test/vectors/utp/demux_classify.meta.json - per-case offsets + expected kind
"""
import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VEC = os.path.join(ROOT, "test", "vectors", "utp")


def utp_hdr(type_, conn):
    """20-B BEP29 header, ver=1 (mirrors test/scripts/utp_header.py)."""
    assert 0 <= type_ <= 4
    return struct.pack(">BBHIIIHH", (type_ << 4) | 1, 0, conn,
                       0x000ABCDE, 0, 0x00100000, 1, 0)


def dht_ping(tid):
    """BEP5-style ping request prefix (starts with 'd')."""
    return (b"d" b"1:ad" b"2:ii5ee" b"3:id6:nodeid0" b"2:q4:ping"
             b"1:t" + bytes([4, tid & 0xFF]) + b"1:y1:qe")


def py_classify(b):
    """Mirror of ntx_udp_classify — normative table above."""
    if len(b) == 0:
        return "drop"
    b0 = b[0]
    if b0 in (0x64, 0x6C, 0x69):
        return "dht"
    if (b0 >> 4) <= 4 and (b0 & 0x0F) == 1:
        return "utp"
    return "drop"


def cases():
    out = []

    def add(name, payload, expected):
        assert py_classify(payload) == expected, (name, payload.hex())
        out.append({"name": name, "hex": payload.hex(),
                    "len": len(payload), "expected": expected})

    # --- DHT: bencode first bytes -------------------------------------
    add("dht_ping_d", dht_ping(1), "dht")
    add("dht_list_l", b"l" b"de" b"4:namei42ee" b"e", "dht")
    add("dht_int_i", b"i1234e", "dht")
    add("dht_one_byte_d", b"d", "dht")
    add("dht_one_byte_l", b"l", "dht")
    add("dht_one_byte_i", b"i", "dht")
    # 0x64/0x6c/0x69 as raw UDP: must classify DHT, never uTP
    # (0x64 would be type=6 ver=4, 0x6c type=6 ver=12, 0x69 type=6 ver=9)
    add("udp_64_is_dht", bytes([0x64, 0x00, 0x11, 0x22]), "dht")
    add("udp_6c_is_dht", bytes([0x6C, 0xAA, 0xBB]), "dht")
    add("udp_69_is_dht", bytes([0x69, 0xCC]), "dht")

    # --- uTP: every legal type/ver combo, conns present ---------------
    for t in range(5):
        add("utp_type%d_ver1" % t, utp_hdr(t, 0xBEEF + t), "utp")
        add("utp_one_byte_type%d" % t, bytes([(t << 4) | 1]), "utp")
    add("utp_syn", utp_hdr(4, 0x1234), "utp")
    add("utp_syn_one_byte", bytes([0x41]), "utp")

    # --- near-miss nibbles: ver wrong or type out of range ------------
    add("near_ver0_type0", bytes([0x00]) + b"\x00" * 19, "drop")
    for v in (2, 3, 4, 5, 6, 7):
        add("near_type0_ver%d" % v, bytes([0x00 | v]) + b"\x00" * 19, "drop")
    for t in range(5, 16):
        add("near_type%d_ver1" % t, bytes([(t << 4) | 1]) + b"\x00" * 19, "drop")
    add("near_61_type6_ver1", bytes([0x61]) + b"\x00" * 19, "drop")
    add("near_01_type0_ver1_ok", bytes([0x01]) + b"\x00" * 19, "utp")

    # --- edges ---------------------------------------------------------
    add("empty", b"", "drop")
    add("one_byte_garbage", bytes([0x80]), "drop")
    add("two_byte_garbage", bytes([0x00, 0x00]), "drop")
    add("two_byte_utp_start", bytes([0x21, 0x00]), "utp")

    return out


def main():
    cs = cases()
    blob = b"".join(bytes.fromhex(c["hex"]) for c in cs)
    off = 0
    for c in cs:
        c["off"] = off
        off += c["len"]
    assert off == len(blob)
    digest = hashlib.sha256(blob).hexdigest()

    os.makedirs(VEC, exist_ok=True)
    with open(os.path.join(VEC, "demux_classify.bin"), "wb") as fp:
        fp.write(blob)
    meta = {
        "vectors": "demux_classify",
        "task": "p6b-13-demux-classify",
        "normative": "BEP 29",
        "bin": "test/vectors/utp/demux_classify.bin",
        "bin_sha256": digest,
        "count": len(cs),
        "cases": cs,
    }
    with open(os.path.join(VEC, "demux_classify.meta.json"), "w") as fp:
        json.dump(meta, fp, indent=1, sort_keys=True)
        fp.write("\n")
    print("demux vectors: %d cases, bin %d B, sha256 %s"
          % (len(cs), len(blob), digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
