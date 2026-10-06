#!/usr/bin/env python3
"""gen_fixtures_announce_dht_pe.py — A5 golden wire fixtures: announce / DHT / PE.

Synthesizes realistic, privacy-scrubbed wire fixtures OFFLINE (no network,
no clock, fixed constants) and freezes them under:

  test/fixtures/announce/  <name>.bin + <name>.meta.json
  test/fixtures/dht/       <name>.bin + <name>.meta.json
  test/fixtures/pe/        <name>.bin + <name>.meta.json

meta.json keys: name, source, date, scrub_notes, expected {...}.

Wire formats: docs/protocol.md (tracker HTTP announce, DHT BEP5/BEP32,
peer-wire handshake + BEP3/BEP10).

Deterministic: re-running produces byte-identical files.
Run:  python3 test/scripts/gen_fixtures_announce_dht_pe.py
"""
import hashlib
import ipaddress
import json
import os

ROOT = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
FX = os.path.join(ROOT, "test", "fixtures")
DATE = "2026-09-03"

SCRUB = (
    "Privacy-scrubbed synthetic fixture: no real peers, trackers or DHT nodes. "
    "All IPv4 addresses from RFC 5737 documentation space 192.0.2.0/24, "
    "all IPv6 from 2001:db8::/48. IDs, tokens, counters and ports are fixed "
    "synthetic constants. Generated offline by test/scripts/gen_fixtures_announce_dht_pe.py; "
    "no clock dependence in output."
)


# ---------------- bencode (dict keys sorted by (len, bytes) per spec) --------

def be_int(v):
    return b"i%de" % v


def be_str(v):
    if isinstance(v, str):
        v = v.encode("ascii")
    return b"%d:%s" % (len(v), v)


def be(x):
    if isinstance(x, bool):
        raise TypeError("bool is not valid bencode")
    if isinstance(x, int):
        return be_int(x)
    if isinstance(x, (bytes, str)):
        return be_str(x)
    if isinstance(x, list):
        return b"l" + b"".join(be(i) for i in x) + b"e"
    if isinstance(x, dict):
        return b"d" + b"".join(be_str(k) + be(x[k]) for k in sorted(x, key=lambda k: (len(k), k))) + b"e"
    raise TypeError(type(x))


# ---------------- compact encodings -----------------------------------------

def v4(ip):
    return ipaddress.IPv4Address(ip).packed


def v6(ip):
    return ipaddress.IPv6Address(ip).packed


def compact4(peers):
    return b"".join(v4(ip) + port.to_bytes(2, "big") for ip, port in peers)


def compact6(peers):
    return b"".join(v6(ip) + port.to_bytes(2, "big") for ip, port in peers)


def nodes4(recs):
    """recs: (id20, ip, port) -> 26 B records (id + ip4 + port BE)."""
    return b"".join(i + v4(ip) + port.to_bytes(2, "big") for i, ip, port in recs)


def nodes6(recs):
    """recs: (id20, ip, port) -> 38 B records (id + ip6 + port BE)."""
    return b"".join(i + v6(ip) + port.to_bytes(2, "big") for i, ip, port in recs)


# ---------------- announce fixtures -----------------------------------------

def announce_list():
    """Realistic HTTP announce response: bencoded dict with full `peers` array
    (list of {ip, port}) + compact `peers6` (BEP32)."""
    peers = [
        {"ip": "192.0.2.10", "port": 6881},
        {"ip": "192.0.2.11", "port": 6882},
        {"ip": "192.0.2.12", "port": 6883},
        {"ip": "192.0.2.13", "port": 6884},
    ]
    peers6 = [
        ("2001:db8::5", 6999),
        ("2001:db8::11", 6998),
        ("2001:db8:0:0:0:0:0:100", 6997),
    ]
    resp = {
        "complete": 42,
        "incomplete": 17,
        "interval": 1800,
        "peers": peers,
        "peers6": compact6(peers6),
        "trackerid": bytes(range(0, 8)),
    }
    meta = {
        "name": "http_announce_list",
        "source": "synthesized from docs/protocol.md (trackers: HTTP, compact 6 B/peer; BEP32 peers6 18 B/peer)",
        "date": DATE,
        "scrub_notes": SCRUB,
        "expected": {
            "interval": 1800,
            "seeders": 42,
            "leechers": 17,
            "peers4": [[p["ip"], p["port"]] for p in peers],
            "peers6": [list(p) for p in peers6],
        },
    }
    return be(resp), meta


def announce_compact():
    """HTTP announce response with compact `peers` string (classic trackers)."""
    peers = [
        ("192.0.2.21", 6881),
        ("192.0.2.22", 6882),
        ("192.0.2.23", 6883),
        ("192.0.2.24", 6884),
    ]
    resp = {
        "complete": 5,
        "incomplete": 3,
        "interval": 1200,
        "peers": compact4(peers),
        "trackerid": bytes(range(8, 16)),
    }
    meta = {
        "name": "http_announce_compact",
        "source": "synthesized from docs/protocol.md (trackers: HTTP, compact 6 B/peer)",
        "date": DATE,
        "scrub_notes": SCRUB,
        "expected": {
            "interval": 1200,
            "seeders": 5,
            "leechers": 3,
            "peers4": [list(p) for p in peers],
        },
    }
    return be(resp), meta


# ---------------- DHT fixtures ----------------------------------------------

def dht_get_peers():
    """DHT get_peers response (BEP5): r{ id, token, values, values6, nodes, nodes6 }."""
    rid = bytes(range(0x40, 0x54))
    tid = bytes([0xC0, 0xFF])
    token = bytes(range(0x50, 0x58))
    values = [
        ("192.0.2.31", 6881),
        ("192.0.2.32", 6882),
    ]
    values6 = [
        ("2001:db8::21", 6881),
        ("2001:db8::22", 6882),
    ]
    nid1 = bytes(range(0x60, 0x74))
    nid2 = bytes(range(0x74, 0x88))
    n1 = ("192.0.2.41", 6881)
    n2 = ("192.0.2.42", 6882)
    nid3 = bytes(range(0x88, 0x9C))
    nid4 = bytes(range(0x9C, 0xB0))
    n3 = ("2001:db8::41", 6881)
    n4 = ("2001:db8::42", 6882)
    msg = {
        "r": {
            "id": rid,
            "token": token,
            "values": compact4(values),
            "values6": compact6(values6),
            "nodes": nodes4([(nid1, n1[0], n1[1]), (nid2, n2[0], n2[1])]),
            "nodes6": nodes6([(nid3, n3[0], n3[1]), (nid4, n4[0], n4[1])]),
        },
        "t": tid,
        "y": "r",
    }
    meta = {
        "name": "get_peers_response",
        "source": "synthesized from docs/protocol.md (DHT BEP5 + BEP32; compact nodes 26 B, values 6 B, v6 38/18 B)",
        "date": DATE,
        "scrub_notes": SCRUB,
        "expected": {
            "y": "r",
            "tid": tid.hex(),
            "id": rid.hex(),
            "token": token.hex(),
            "values": [list(p) for p in values],
            "values6": [list(p) for p in values6],
            "nodes": [[nid1.hex(), n1[0], n1[1]], [nid2.hex(), n2[0], n2[1]]],
            "nodes6": [[nid3.hex(), n3[0], n3[1]], [nid4.hex(), n4[0], n4[1]]],
        },
    }
    return be(msg), meta


def dht_find_node():
    """DHT find_node response (BEP5): r{ id, nodes, nodes6 } — no values/token."""
    rid = bytes(range(0xA0, 0xB4))
    tid = bytes([0x11, 0x22])
    recs4 = []
    for i in range(3):
        rid_i = bytes([0xC0 + i] * 20)
        recs4.append((rid_i, "192.0.2.%d" % (51 + i), 7000 + i))
    recs6 = []
    for i in range(2):
        rid_i = bytes([0xD0 + i] * 20)
        recs6.append((rid_i, "2001:db8::%x" % (0x51 + i), 7100 + i))
    msg = {
        "r": {
            "id": rid,
            "nodes": nodes4(recs4),
            "nodes6": nodes6(recs6),
        },
        "t": tid,
        "y": "r",
    }
    meta = {
        "name": "find_node_response",
        "source": "synthesized from docs/protocol.md (DHT BEP5 find_node response, dual-stack)",
        "date": DATE,
        "scrub_notes": SCRUB,
        "expected": {
            "y": "r",
            "tid": tid.hex(),
            "id": rid.hex(),
            "nodes": [[i.hex(), ip, port] for i, ip, port in recs4],
            "nodes6": [[i.hex(), ip, port] for i, ip, port in recs6],
        },
    }
    return be(msg), meta


# ---------------- PE fixture -------------------------------------------------

INFO_HASH = bytes(range(0x5A, 0x6E))
PEER_ID = b"-ntx-golden000000001"  # 20 B


def bt_msg(msg_id, payload=b"", padded=False):
    """BEP3 message; padded = BEP10/MSE convention (0x10000000 bit in length field)."""
    ln = (1 + len(payload)) | (0x10000000 if padded else 0)
    return ln.to_bytes(4, "big") + bytes([msg_id]) + payload


def pe_exchange():
    """Peer-wire stream: BT handshake (68 B) + keepalive + interested +
    bitfield + choke + one BEP10-padded have. Plaintext (client supports
    --compat-peers plaintext fallback, docs/protocol.md §MSE/PE)."""
    reserved = bytearray(8)
    reserved[5] = 0x10  # BEP10 (extension protocol)
    hs = bytes([0x13]) + b"BitTorrent protocol" + bytes(reserved) + INFO_HASH + PEER_ID
    stream = hs
    stream += b"\x00\x00\x00\x00"                    # keepalive
    stream += bt_msg(2)                              # interested
    stream += bt_msg(5, b"\xd0\x00\x00")             # bitfield: pieces 0,1,3 (MSB-first: 0xD0)
    stream += bt_msg(0)                              # choke
    stream += bt_msg(4, (7).to_bytes(4, "big"), padded=True)  # padded have(7)
    meta = {
        "name": "bt_exchange",
        "source": "synthesized from docs/protocol.md (handshake 68 B table; BEP3 ids; BEP10 padding bit)",
        "date": DATE,
        "scrub_notes": SCRUB + " Peer IDs and info hash are synthetic constants, not real torrents.",
        "expected": {
            "handshake": {
                "info_hash": INFO_HASH.hex(),
                "peer_id": PEER_ID.decode("ascii"),
                "bep10": True,
            },
            "messages": [
                {"type": "keepalive"},
                {"type": "interested"},
                {"type": "bitfield", "nbytes": 3, "pieces": [0, 1, 3]},
                {"type": "choke"},
                {"type": "have", "index": 7, "padded": True},
            ],
        },
    }
    return stream, meta


# ---------------- writer -----------------------------------------------------

def wfile(path, data):
    d = os.path.dirname(path)
    if not os.path.isdir(d):
        os.makedirs(d)
    with open(path, "wb") as f:
        f.write(data)


def wmeta(path, meta):
    with open(path, "w") as f:
        f.write(json.dumps(meta, indent=2, sort_keys=True) + "\n")


def main():
    fixtures = [
        ("announce/http_announce_list", announce_list),
        ("announce/http_announce_compact", announce_compact),
        ("dht/get_peers_response", dht_get_peers),
        ("dht/find_node_response", dht_find_node),
        ("pe/bt_exchange", pe_exchange),
    ]
    for rel, fn in fixtures:
        raw, meta = fn()
        assert meta["name"] == rel.rsplit("/", 1)[1]
        wfile(os.path.join(FX, rel + ".bin"), raw)
        wmeta(os.path.join(FX, rel + ".meta.json"), meta)
        print("%-32s %4d B  sha256=%s" % (rel + ".bin", len(raw),
                                          hashlib.sha256(raw).hexdigest()[:16]))
    print("OK: %d fixtures frozen under test/fixtures/" % len(fixtures))


if __name__ == "__main__":
    main()
