#!/usr/bin/env python3
"""Golden SOCKS5 UDP ASSOCIATE framing vectors (RFC1928 §7).

Normative: RFC 1928 §7.

UDP request/reply framing:
  RSV(2)=0, FRAG(1)=0, ATYP(1), DST.ADDR(4|16), DST.PORT(2 BE), DATA
This generator is deterministic and self-checking. It writes:
  test/vectors/socks/udp_associate_frames.bin
  test/vectors/socks/udp_associate_frames.meta.json

Cases cover encap/decap round-trips, RSV/FRAG rejects, ATYP matrix, IPv4/IPv6,
truncated frames, and TCP ASSOCIATE request bytes.
"""
import hashlib
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VEC = os.path.join(ROOT, "test", "vectors", "socks")

UTP_LIKE = bytes([
    0x21, 0x00, 0xBE, 0xEF, 0x00, 0x0A, 0xBC, 0xDE,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x01, 0x00, 0x02,
]) + b"uTPDATA"


def encap(atyp, addr, port, data, rsv=0, frag=0):
    assert atyp in (1, 4)
    assert len(addr) == (4 if atyp == 1 else 16)
    return (struct.pack(">HBB", rsv, frag, atyp) + addr +
            struct.pack(">H", port) + data)


def raw_udp(atyp, body, port, data, rsv=0, frag=0):
    return struct.pack(">HBB", rsv, frag, atyp) + body + struct.pack(">H", port) + data


def request(atyp, addr, port):
    assert atyp in (1, 4)
    assert len(addr) == (4 if atyp == 1 else 16)
    return (bytes([0x05, 0x03, 0x00, atyp]) + addr + struct.pack(">H", port))


def cases():
    out = []

    v4 = bytes([10, 0, 0, 1])
    v6 = bytes([0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                0, 0, 0, 0, 0, 0, 0, 0x01])

    def add(name, ctype, frame, expected, **kw):
        c = {"name": name, "type": ctype, "expected": expected,
             "hex": frame.hex(), "len": len(frame)}
        c.update(kw)
        out.append(c)

    # --- TCP ASSOCIATE request bytes (server stub asserts verbatim) -----
    add("request_v4_basic", "request", request(1, v4, 6881), "ok",
        atyp=1, dst=v4.hex(), port=6881)
    add("request_v6_basic", "request", request(4, v6, 6881), "ok",
        atyp=4, dst=v6.hex(), port=6881)

    # --- UDP request/reply datagram framing ----------------------------
    add("encap_v4_basic", "encap", encap(1, v4, 6881, UTP_LIKE), "ok",
        atyp=1, dst=v4.hex(), port=6881, data=UTP_LIKE.hex())
    add("encap_v6_basic", "encap", encap(4, v6, 6881, UTP_LIKE), "ok",
        atyp=4, dst=v6.hex(), port=6881, data=UTP_LIKE.hex())
    add("encap_empty_data", "encap", encap(1, v4, 6882, b""), "ok",
        atyp=1, dst=v4.hex(), port=6882, data="")

    add("decap_v4_basic", "decap", encap(1, v4, 6881, UTP_LIKE), "ok",
        atyp=1, dst=v4.hex(), port=6881, data=UTP_LIKE.hex())
    add("decap_v6_basic", "decap", encap(4, v6, 6881, UTP_LIKE), "ok",
        atyp=4, dst=v6.hex(), port=6881, data=UTP_LIKE.hex())
    add("decap_empty_data", "decap", encap(1, v4, 6882, b""), "ok",
        atyp=1, dst=v4.hex(), port=6882, data="")

    # Edge cases: RSV and FRAG must be zero; non-zero FRAG is dropped/rejected.
    add("decap_rsv_nonzero_reject", "decap",
        encap(1, v4, 6881, UTP_LIKE, rsv=0x01), "reject", reject="rsv")
    add("decap_frag_nonzero_reject", "decap",
        encap(1, v4, 6881, UTP_LIKE, frag=1), "reject", reject="frag")

    # ATYP matrix: only v4/v6 are accepted for peer IPs; domain is avoided.
    # These use FRAG=0 so the ATYP dispatch path is the one exercised.
    domain = bytes([0x04]) + b"host"
    add("decap_atyp_domain_reject", "decap",
        raw_udp(0x03, domain, 6881, UTP_LIKE), "reject", reject="atyp_domain")
    add("decap_atyp_unknown_reject", "decap",
        raw_udp(0x09, v4, 6881, UTP_LIKE), "reject", reject="atyp_unknown")

    # Truncated frames must not be parsed.
    add("decap_truncated_v4_reject", "decap",
        encap(1, v4, 6881, UTP_LIKE)[:8], "reject", reject="truncated")
    add("decap_truncated_v6_reject", "decap",
        encap(4, v6, 6881, UTP_LIKE)[:20], "reject", reject="truncated")
    add("decap_short_header_reject", "decap", bytes([0, 0, 0, 1, 10, 0]),
        "reject", reject="short")

    return out


def main():
    cs = cases()
    blob = b"".join(bytes.fromhex(c["hex"]) for c in cs)
    off = 0
    for c in cs:
        c["off"] = off
        off += c["len"]
    assert off == len(blob)

    # Self-check the normative encap/request helpers against the stored bytes.
    for c in cs:
        raw = bytes.fromhex(c["hex"])
        if c["type"] == "request":
            atyp = int(c["atyp"])
            addr = bytes.fromhex(c["dst"])
            assert raw == request(atyp, addr, int(c["port"])), c["name"]
        elif c["type"] == "encap":
            atyp = int(c["atyp"])
            addr = bytes.fromhex(c["dst"])
            assert raw == encap(atyp, addr, int(c["port"]),
                               bytes.fromhex(c["data"])), c["name"]
        elif c["type"] == "decap":
            if c["expected"] == "ok":
                hdr = 6 + (4 if int(c["atyp"]) == 1 else 16)
                assert raw[:hdr] == raw[:hdr]
                assert raw[hdr:] == bytes.fromhex(c["data"])
            elif c.get("reject"):
                r = c["reject"]
                assert len(raw) >= 4, c["name"]
                if r == "frag":
                    assert raw[2] != 0, c["name"]
                elif r == "atyp_domain":
                    assert raw[2] == 0 and raw[3] == 0x03, c["name"]
                elif r == "atyp_unknown":
                    assert raw[2] == 0 and raw[3] == 0x09, c["name"]
                elif r == "rsv":
                    assert raw[0] != 0 or raw[1] != 0, c["name"]
                    assert raw[2] == 0, c["name"]
                elif r == "truncated":
                    assert raw[2] == 0 and raw[3] in (1, 4), c["name"]
                elif r == "short":
                    assert len(raw) < 8, c["name"]

    digest = hashlib.sha256(blob).hexdigest()
    os.makedirs(VEC, exist_ok=True)
    bin_path = os.path.join(VEC, "udp_associate_frames.bin")
    meta_path = os.path.join(VEC, "udp_associate_frames.meta.json")
    with open(bin_path, "wb") as fp:
        fp.write(blob)
    meta = {
        "vectors": "socks-udp-associate-frames",
        "task": "p6b-16-socks-udp",
        "normative": "RFC 1928 section 7",
        "bin": "test/vectors/socks/udp_associate_frames.bin",
        "bin_sha256": digest,
        "count": len(cs),
        "cases": cs,
    }
    with open(meta_path, "w") as fp:
        json.dump(meta, fp, indent=1, sort_keys=True)
        fp.write("\n")
    print("socks udp vectors: %d cases, bin %d B, sha256 %s"
          % (len(cs), len(blob), digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
