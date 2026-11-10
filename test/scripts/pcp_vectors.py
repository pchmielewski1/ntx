#!/usr/bin/env python3
"""Golden vectors for the PCP / NAT-PMP codecs in src/proto/ntx_pcp.c (design §8).

Normative: RFC 6887 §7.1 (request header), §7.2 (response header), §7.4 (result
codes), §11.1 (MAP opcode); RFC 6886 §3.2 (external address), §3.3 (mapping).
Packed with struct only — deliberately independent of the C code, so the C
builder cannot validate itself.

Deterministic, self-checking. Writes:
  test/vectors/pcp/pcp.bin       - concatenated message bytes
  test/vectors/pcp/pcp.meta.json - per-case offsets, fields and expected verdicts

Verdicts the C test asserts (the contract of ntx_pcp.c):
  pcp_build_map / natpmp_build_addr / natpmp_build_map -> bytes == "hex"
  pcp_parse_map     -> 0 ok | -1 short/garbage | -2 nonce/proto/port mismatch
                       | 1 UNSUPP_VERSION (NAT-PMP fallback)
  natpmp_parse_addr -> 0 ok | -1 anything else
  natpmp_parse_map  -> 0 ok | -1 anything else
"""
import hashlib
import ipaddress
import json
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VEC = os.path.join(ROOT, "test", "vectors", "pcp")

# Fixed parameters, shared by the builder cases and the parser cases.
NONCE = bytes.fromhex("0102030405060708090a0b0c")
BAD_NONCE = bytes.fromhex("ff02030405060708090a0b0c")        # differs in byte 0
BAD_NONCE_TAIL = bytes.fromhex("0102030405060708090a0bff")   # differs in byte 11
CLIENT_IP16 = ipaddress.IPv6Address("::ffff:192.168.1.10").packed
INT_PORT = 6881
SUGG_PORT = 6881
EXT_PORT = 40123
LIFETIME = 7200
EPOCH = 86400
EXT_IP16 = ipaddress.IPv6Address("::ffff:203.0.113.9").packed
EXT_IP4 = bytes([203, 0, 113, 9])
EXT_IP6_16 = bytes.fromhex("20010db800000000000000000000002a")

NATPMP_INT_PORT = 6881
NATPMP_SUGG_PORT = 6881
NATPMP_EXT_PORT = 40123
NATPMP_LIFETIME = 7200
NATPMP_EPOCH = 86400

OPCODE_MAP = 1


def be32(b4):
    """Wire-order 32-bit field (the RFCs have no host byte order)."""
    return struct.unpack(">I", b4)[0]


def pcp_req(lifetime, client_ip16, opcode_data):
    """RFC 6887 §7.1 request header (24 B) + opcode-specific data."""
    hdr = struct.pack(">BBHI", 2, OPCODE_MAP, 0, lifetime) + client_ip16
    assert len(hdr) == 24, len(hdr)
    msg = hdr + opcode_data
    assert len(msg) % 4 == 0
    return msg


def pcp_map_req_data(nonce, proto, int_port, sugg_port):
    """RFC 6887 §11.1 fig. 9 MAP opcode request data (36 B)."""
    # Protocol, then 24 reserved bits, then the two 16-bit ports.
    data = nonce + bytes([proto, 0, 0, 0]) + struct.pack(">HH", int_port, sugg_port) + bytes(16)
    assert len(data) == 36, len(data)
    return data


def pcp_resp(result, lifetime, epoch_b4, opcode_data, version=2):
    """RFC 6887 §7.2 response header (24 B): R bit set, 12 B reserved zero,
    16-bit Result Code. Epoch Time is opaque to this codec, so the caller
    passes the 4 wire bytes and the expectation is the same bytes as u32."""
    # §7.2: octet 2 is 8 reserved bits, octet 3 is the Result Code.
    hdr = struct.pack(">BBBB", version, 0x80 | OPCODE_MAP, 0, result)
    hdr += struct.pack(">I", lifetime) + epoch_b4 + bytes(12)
    assert len(hdr) == 24, len(hdr)
    msg = hdr + opcode_data
    assert len(msg) % 4 == 0
    return msg


def pcp_map_resp_data(nonce, proto, int_port, ext_port, ext_ip16):
    """RFC 6887 §11.1 fig. 10 MAP opcode response data (36 B)."""
    data = nonce + bytes([proto, 0, 0, 0]) + struct.pack(">HH", int_port, ext_port) + ext_ip16
    assert len(data) == 36, len(data)
    return data


def cases():
    out = []

    def add(name, kind, msg, note, **fields):
        assert isinstance(msg, (bytes, bytearray))
        out.append(dict([("name", name), ("kind", kind), ("note", note),
                         ("hex", bytes(msg).hex()), ("len", len(msg))]
                        + sorted(fields.items())))

    EPOCHW = struct.pack(">I", EPOCH)
    good = pcp_resp(0, LIFETIME, EPOCHW,
                    pcp_map_resp_data(NONCE, 6, INT_PORT, EXT_PORT, EXT_IP16))
    assert len(good) == 60

    # --- PCP MAP requests (builder cases; byte-exact vs. the RFC layout) --
    def req(name, proto, int_port, sugg_port, lifetime, note):
        add(name, "build_pcp_map",
            pcp_req(lifetime, CLIENT_IP16,
                    pcp_map_req_data(NONCE, proto, int_port, sugg_port)),
            note, client_ip=CLIENT_IP16.hex(), nonce=NONCE.hex(), proto=proto,
            int_port=int_port, sugg_port=sugg_port, lifetime=lifetime, expect=60)

    req("map_req_tcp", 6, INT_PORT, SUGG_PORT, LIFETIME,
        "RFC 6887 §7.1+§11.1 MAP request, TCP, 60 B")
    req("map_req_udp_zero_sugg", 17, INT_PORT, 0, LIFETIME,
        "MAP request, UDP, suggested external port 0 (RFC 6887 §11.1)")
    req("map_req_delete", 6, INT_PORT, EXT_PORT, 0,
        "lifetime 0 = delete, renewal-style suggested external port")

    # --- PCP MAP responses ----------------------------------------------
    ok = dict(nonce=NONCE.hex(), proto=6, int_port=INT_PORT, ext_port=EXT_PORT,
              ext_ip=EXT_IP16.hex(), lifetime=LIFETIME, epoch=be32(EPOCHW),
              result=0, expect=0)
    add("map_resp_ok", "parse_pcp_map", good,
        "success; assigned external port differs from the internal port", **ok)
    add("map_resp_options_pad", "parse_pcp_map", good + bytes(1040),
        "success with 1040 B of trailing options data (n = 1100 ceiling)", **ok)
    add("map_resp_v6_ext", "parse_pcp_map",
        pcp_resp(0, LIFETIME, EPOCHW,
                 pcp_map_resp_data(NONCE, 6, INT_PORT, EXT_PORT, EXT_IP6_16)),
        "success with a native IPv6 external address",
        nonce=NONCE.hex(), proto=6, int_port=INT_PORT, ext_port=EXT_PORT,
        ext_ip=EXT_IP6_16.hex(), lifetime=LIFETIME, epoch=be32(EPOCHW),
        result=0, expect=0)

    def mismatch(name, msg, note):
        add(name, "parse_pcp_map", msg, note,
            nonce=NONCE.hex(), proto=6, int_port=INT_PORT, ext_port=-1,
            ext_ip="", lifetime=-1, epoch=-1, result=-1, expect=-2)

    mismatch("map_resp_wrong_nonce",
             pcp_resp(0, LIFETIME, EPOCHW,
                      pcp_map_resp_data(BAD_NONCE, 6, INT_PORT, EXT_PORT, EXT_IP16)),
             "nonce differs from the request in byte 0")
    mismatch("map_resp_wrong_nonce_tail",
             pcp_resp(0, LIFETIME, EPOCHW,
                      pcp_map_resp_data(BAD_NONCE_TAIL, 6, INT_PORT, EXT_PORT, EXT_IP16)),
             "nonce differs from the request only in its last byte")
    mismatch("map_resp_wrong_proto",
             pcp_resp(0, LIFETIME, EPOCHW,
                      pcp_map_resp_data(NONCE, 17, INT_PORT, EXT_PORT, EXT_IP16)),
             "response says UDP while the request asked for TCP")
    mismatch("map_resp_wrong_int_port",
             pcp_resp(0, LIFETIME, EPOCHW,
                      pcp_map_resp_data(NONCE, 6, 6882, EXT_PORT, EXT_IP16)),
             "internal port is not the one we asked about")

    def garbage(name, msg, note, result=-1):
        add(name, "parse_pcp_map", msg, note,
            nonce=NONCE.hex(), proto=6, int_port=INT_PORT, ext_port=-1,
            ext_ip="", lifetime=-1, epoch=-1, result=result, expect=-1)

    garbage("map_resp_truncated_59", good[:59],
            "truncated to 59 B: the parser must not read past n")
    garbage("map_resp_too_short", b"\x02\x81\x00\x00" + bytes(20),
            "24 B response carrying no MAP opcode data")
    garbage("map_resp_rbit_clear", good[:1] + bytes([OPCODE_MAP]) + good[2:],
            "R bit clear — a request, not a response")
    garbage("map_resp_bad_opcode", good[:1] + bytes([0x82]) + good[2:],
            "R set but opcode 2 (PEER), not MAP")
    garbage("map_resp_bad_result",
            pcp_resp(7, 30, EPOCHW,
                     pcp_map_resp_data(NONCE, 6, INT_PORT, SUGG_PORT, bytes(16))),
            "result 7 NETWORK_FAILURE is not a mapping — only 0 and 1 are accepted", 7)
    garbage("map_resp_too_long", good + bytes(1044),
            "1104 B > the 1100 B PCP ceiling (RFC 6887 §7)")
    garbage("map_resp_not_mult4", good + b"\x00" * 1039,
            "1099 B: not a multiple of 4 (RFC 6887 §8.3)")
    garbage("map_resp_empty", b"", "empty datagram")
    garbage("map_resp_garbage", bytes(range(60)),
            "60 B of garbage (version 0, opcode 1, R clear)")

    unsupp = pcp_resp(1, 1800, EPOCHW,
                      pcp_map_resp_data(NONCE, 6, INT_PORT, SUGG_PORT, bytes(16)),
                      version=0)
    add("map_resp_unsupp_version", "parse_pcp_map", unsupp,
        "NAT-PMP server answering a PCP request: version 0, result 1 (RFC 6887 §9, App. A)",
        nonce=NONCE.hex(), proto=6, int_port=INT_PORT, ext_port=-1, ext_ip="",
        lifetime=-1, epoch=-1, result=1, expect=1)
    add("map_resp_unsupp_version_natpmp_shaped", "parse_pcp_map",
        struct.pack(">BBH", 0, 128, 1) + struct.pack(">I", 0) + bytes(4),
        "NAT-PMP UNSUPP_VERSION reply (RFC 6886 §3.5): 12 B, first octet 0, "
        "16-bit result 1 — still the fallback verdict",
        nonce=NONCE.hex(), proto=6, int_port=INT_PORT, ext_port=-1, ext_ip="",
        lifetime=-1, epoch=-1, result=1, expect=1)

    # --- NAT-PMP (RFC 6886 §3.2, §3.3) ---------------------------------
    add("natpmp_addr_req", "build_natpmp_addr", struct.pack(">BB", 0, 0),
        "Determining the External Address request (2 B)", expect=2)

    def addr_resp(name, result, ext_ip4, note, expect, vers=0, op=128):
        msg = struct.pack(">BBH", vers, op, result) + struct.pack(">I", NATPMP_EPOCH) + ext_ip4
        assert len(msg) == 12
        add(name, "parse_natpmp_addr", msg, note, result=result,
            ext_ip=ext_ip4.hex(), epoch=NATPMP_EPOCH, expect=expect)

    addr_resp("natpmp_addr_resp_ok", 0, EXT_IP4,
              "address response, result 0, external 203.0.113.9", 0)
    addr_resp("natpmp_addr_resp_error", 2, bytes(4),
              "result 2 NOT_AUTHORIZED: external address is undefined", -1)
    addr_resp("natpmp_addr_resp_bad_vers", 0, EXT_IP4,
              "version 1: only version 0 exists (RFC 6886 §3.2)", -1, vers=1)
    msg = struct.pack(">BBH", 0, 129, 0) + struct.pack(">I", NATPMP_EPOCH) + EXT_IP4
    add("natpmp_addr_resp_bad_op", "parse_natpmp_addr", msg,
        "OP 129 is a mapping response, not an address response",
        result=0, ext_ip=EXT_IP4.hex(), epoch=NATPMP_EPOCH, expect=-1)
    msg = struct.pack(">BBH", 0, 128, 0) + struct.pack(">I", NATPMP_EPOCH) + EXT_IP4
    add("natpmp_addr_resp_short", "parse_natpmp_addr", msg[:11],
        "11 B: truncated", result=0, ext_ip="00000000", epoch=-1, expect=-1)

    for op, tag in ((1, "udp"), (2, "tcp")):
        add("natpmp_map_req_" + tag, "build_natpmp_map",
            struct.pack(">BBHHHI", 0, op, 0, NATPMP_INT_PORT,
                        NATPMP_SUGG_PORT, NATPMP_LIFETIME),
            "Map %s request (12 B)" % tag.upper(),
            op=op, int_port=NATPMP_INT_PORT, sugg_port=NATPMP_SUGG_PORT,
            lifetime=NATPMP_LIFETIME, expect=12)

        # resp_op/msg_int_port are what the gateway sends; op/int_port are what
        # the client asked, i.e. what the parser is called with.
        def map_resp(name, resp_op, result, msg_int_port, ext_port, lifetime,
                     note, expect, vers=0):
            m = struct.pack(">BBH", vers, resp_op, result)
            m += struct.pack(">I", NATPMP_EPOCH)
            m += struct.pack(">HHI", msg_int_port, ext_port, lifetime)
            assert len(m) == 16
            add(name, "parse_natpmp_map", m, note, op=op, int_port=NATPMP_INT_PORT,
                result=result, ext_port=ext_port if expect == 0 else -1,
                lifetime=lifetime if expect == 0 else -1, epoch=NATPMP_EPOCH,
                expect=expect)

        map_resp("natpmp_map_resp_" + tag, 128 + op, 0, NATPMP_INT_PORT,
                 NATPMP_EXT_PORT, NATPMP_LIFETIME,
                 "mapping response, result 0, external port 40123", 0)
        map_resp("natpmp_map_resp_" + tag + "_wrong_op", 128 if op == 1 else 129,
                 0, NATPMP_INT_PORT, NATPMP_EXT_PORT, NATPMP_LIFETIME,
                 "OP does not match the request", -1)
        map_resp("natpmp_map_resp_" + tag + "_bad_vers", 128 + op, 0,
                 NATPMP_INT_PORT, NATPMP_EXT_PORT, NATPMP_LIFETIME,
                 "version 1: only version 0 exists (RFC 6886 §3)", -1, vers=1)
        map_resp("natpmp_map_resp_" + tag + "_wrong_port", 128 + op, 0,
                 NATPMP_INT_PORT + 1, NATPMP_EXT_PORT, NATPMP_LIFETIME,
                 "internal port in the response is not the one requested", -1)
        map_resp("natpmp_map_resp_" + tag + "_error", 128 + op, 4,
                 NATPMP_INT_PORT, 0, 30,
                 "result 4 NOT_AUTHORIZED (RFC 6886 §3.3)", -1)
        map_resp("natpmp_map_resp_" + tag + "_delete", 128 + op, 0,
                 NATPMP_INT_PORT, 0, 0,
                 "deletion ack: result 0, external port 0, lifetime 0 (RFC 6886 §3.4)", 0)

    # Out-of-contract op: the contract pins op to 1 (udp) / 2 (tcp). A parser
    # that only compares b[1] against 128 + op would accept OP 131 for op 3.
    m = struct.pack(">BBH", 0, 131, 0) + struct.pack(">I", NATPMP_EPOCH)
    m += struct.pack(">HHI", NATPMP_INT_PORT, NATPMP_EXT_PORT, NATPMP_LIFETIME)
    add("natpmp_map_resp_op3", "parse_natpmp_map", m,
        "op 3 is outside the contract (1 udp / 2 tcp), even with a matching OP 131",
        op=3, int_port=NATPMP_INT_PORT, result=0, ext_port=-1, lifetime=-1,
        epoch=NATPMP_EPOCH, expect=-1)
    m = struct.pack(">BBH", 0, 128, 0) + struct.pack(">I", NATPMP_EPOCH)
    m += struct.pack(">HHI", NATPMP_INT_PORT, NATPMP_EXT_PORT, NATPMP_LIFETIME)
    add("natpmp_map_resp_op0", "parse_natpmp_map", m,
        "op 0 is the address opcode, not a mapping (RFC 6886 §3.3)",
        op=0, int_port=NATPMP_INT_PORT, result=0, ext_port=-1, lifetime=-1,
        epoch=NATPMP_EPOCH, expect=-1)

    # --- CGNAT / private classifier on the 16-byte form -----------------
    for addr, expect in (
            ("::ffff:100.64.0.1", 1), ("::ffff:100.127.255.255", 1),
            ("::ffff:100.128.0.1", 0), ("::ffff:100.63.255.255", 0),
            ("::ffff:10.0.0.1", 1), ("::ffff:10.255.255.255", 1),
            ("::ffff:11.0.0.1", 0), ("::ffff:172.16.0.1", 1),
            ("::ffff:172.31.255.255", 1), ("::ffff:172.15.255.255", 0),
            ("::ffff:172.32.0.1", 0), ("::ffff:192.168.0.1", 1),
            ("::ffff:192.167.255.255", 0), ("::ffff:193.168.0.1", 0),
            ("::ffff:8.8.8.8", 0), ("::ffff:0.0.0.0", 0),
            ("::ffff:255.255.255.255", 0), ("fc00::1", 1), ("fdff::1", 1),
            ("fe00::1", 0), ("::1", 0), ("2001:db8::1", 0), ("::", 0),
            ("::ffff:169.254.1.1", 0), ("::10.0.0.1", 0),
            ("2001:db8::ff:ffff", 0), ("fd00::ffff:ffff", 1),
            # Native IPv6 whose octets 10-11 are ff ff, so a classifier that
            # tests only those two octets reads the tail as an IPv4 address.
            # Both failure directions must stay correct: the four below are
            # public/native and must not be called private, and the fd/fc ones
            # are ULA and must not be called public.
            ("2002:a00:1::ffff:10.0.0.1", 0),      # 6to4, tail = 10/8
            ("2001:db8::ffff:100.64.0.1", 0),      # doc prefix, tail = CGNAT
            ("fe80::ffff:10.0.0.1", 0),             # link-local, tail = 10/8
            ("64:ff9b::ffff:10.0.0.1", 0),          # NAT64 well-known, tail = 10/8
            ("fd00::ffff:ffff:1", 1),                # ULA misread as 255.255.0.1
            ("fc00::ffff:8.8.8.8", 1),               # ULA misread as 8.8.8.8
            ("fdff::ffff:ffff:ffff", 1),             # top of fc00::/7, v4-shaped tail
            ("fc00::", 1), ("fe80::", 0), ("2002::", 0),
            # Ten leading zero octets but only ONE of octets 10/11 is 0xff: a
            # malformed "mapped" address. Testing octet 11 alone takes the v4
            # branch on the first two and calls them private; testing octet 10
            # alone takes it on the third.
            ("::ff:10.0.0.1", 0), ("::ff:100.64.0.1", 0),
            ("::ff00:10.0.0.1", 0),
            # Octet 9 is the last one that has to be zero: a native address
            # with 01 there and a private-looking tail must not take the v4
            # branch, so a 9-byte (not 10-byte) prefix check is caught too.
            ("::1:ffff:a00:1", 0), ("::1:ffff:6440:1", 0)):
        add("cgnat_" + addr.replace(":", "_").replace(".", "-"), "cgnat",
            ipaddress.IPv6Address(addr).packed,
            "pcp_ip_is_cgnat_or_private(%s)" % addr, addr=addr, expect=expect)

    return out


def main():
    cs = cases()
    names = [c["name"] for c in cs]
    dupes = sorted({n for n in names if names.count(n) > 1})
    assert not dupes, "duplicate case names: %s" % dupes
    blob = b"".join(bytes.fromhex(c["hex"]) for c in cs)
    off = 0
    for c in cs:
        c["off"] = off
        off += len(c["hex"]) // 2
    assert off == len(blob)
    assert len(blob) <= 65536
    digest = hashlib.sha256(blob).hexdigest()

    os.makedirs(VEC, exist_ok=True)
    with open(os.path.join(VEC, "pcp.bin"), "wb") as fp:
        fp.write(blob)
    meta = {
        "vectors": "pcp",
        "task": "B4-pcp-natpmp-codec",
        "normative": "RFC 6887 §7.1/§7.2/§7.4/§11.1, RFC 6886 §3.2/§3.3",
        "bin": "test/vectors/pcp/pcp.bin",
        "bin_sha256": digest,
        "count": len(cs),
        "cases": cs,
    }
    with open(os.path.join(VEC, "pcp.meta.json"), "w") as fp:
        json.dump(meta, fp, indent=1, sort_keys=True)
        fp.write("\n")
    print("pcp vectors: %d cases, bin %d B, sha256 %s"
          % (len(cs), len(blob), digest))
    return 0


if __name__ == "__main__":
    sys.exit(main())
