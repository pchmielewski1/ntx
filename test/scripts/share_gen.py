#!/usr/bin/env python3
"""--share metainfo fixtures (golden source for test/t_share_meta.c).

Independent of the C sources: hashlib, handwritten bencode and a BEP 52 merkle
tree (16 KiB SHA-256 leaves, zero-filled to the next power of two). Emits
test/vectors/share/<fixture>/ :

  data.bin       the shared file bytes
  salt.txt       the 32 hex chars of info["ntx salt"] (no newline)
  trackers.txt   one announce URL per line, in share-list order
  info.bin       the exact bencoded info dict
  meta.torrent   the exact full .torrent
  manifest.txt   ps, np, ih_sha1, ih_sha256, has_layers + the extra keys below

Fixtures cover design §5.2/§5.3 and Review Focus 3: 1 B, exactly one piece,
multiple + 1 B and an exact multiple of the piece length.

created by is "ntx/" + NTX_VERSION; the Makefile overrides NTX_VERSION with
-DNTX_VERSION, so the generator takes the same value from the environment
(NTX_VERSION, default 0.1.0 = src/core/ntx_config.h) and records it in
manifest.txt, where the test pins it against the C macro.

Run from the repo root:  python3 test/scripts/share_gen.py
"""
import hashlib
import math
import os
import sys

LEAF = 16384
PS_MIN = 16384
PS_MAX = 64 * 1024 * 1024
MAX_PIECES = 32768
SALT = "00112233445566778899aabbccddeeff"
CREATION_DATE = 1700000000
TRACKERS = ["https://tracker-one.test/announce",
            "https://tracker-two.test/announce"]
VERSION = os.environ.get("NTX_VERSION", "0.1.0")

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "vectors", "share"))


class Raw(bytes):
    """Already-bencoded bytes: spliced into the parent verbatim (used for the
    info dict, which the top level must carry byte for byte)."""


def bencode(obj):
    if isinstance(obj, Raw):
        return bytes(obj)
    if isinstance(obj, bool):
        raise TypeError("bool is not bencode")
    if isinstance(obj, int):
        return b"i%de" % obj
    if isinstance(obj, str):
        obj = obj.encode("utf-8")
    if isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        return str(len(b)).encode("ascii") + b":" + b
    if isinstance(obj, list):
        return b"l" + b"".join(bencode(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        out = b"d"
        for k in sorted(obj.keys(), key=lambda k: k if isinstance(k, bytes) else k.encode("utf-8")):
            out += bencode(k) + bencode(obj[k])
        return out + b"e"
    raise TypeError(type(obj))


def sha1(b):
    return hashlib.sha1(b).digest()


def sha256(b):
    return hashlib.sha256(b).digest()


def content(seed, size):
    """Deterministic bytes: tiled sha256("<seed>:<i>"), same scheme as bep52_gen.py."""
    out = bytearray()
    i = 0
    while len(out) < size:
        out += sha256(("%s:%d" % (seed, i)).encode("ascii"))
        i += 1
    return bytes(out[:size])


def next_pow2(n):
    p = 1
    while p < n:
        p <<= 1
    return p


def piece_len(size):
    """Smallest power of two in [16 KiB, 64 MiB] with <= 2048 pieces, else 64 MiB.
    None when even 64 MiB leaves more than 32768 pieces."""
    p = PS_MIN
    while p < PS_MAX and math.ceil(size / p) > 2048:
        p <<= 1
    if math.ceil(size / p) > MAX_PIECES:
        return None
    return p


def merkle_leaves(data):
    n_leaf = (len(data) + LEAF - 1) // LEAF
    leaves = [sha256(data[i * LEAF:(i + 1) * LEAF]) for i in range(n_leaf)]
    p = next_pow2(n_leaf) if n_leaf else 1
    while len(leaves) < p:
        leaves.append(bytes(32))
    return leaves


def fold(lev):
    lev = list(lev)
    while len(lev) > 1:
        lev = [sha256(lev[i] + lev[i + 1]) for i in range(0, len(lev), 2)]
    return lev[0]


def root_from_file(data):
    return fold(merkle_leaves(data))


def piece_layer(data, ps):
    """np hashes, each the subtree of exactly ps bytes (zero-filled to ps)."""
    T = ps // LEAF
    out = []
    for off in range(0, len(data), ps):
        chunk = data[off:off + ps]
        lev = [sha256(chunk[i * LEAF:(i + 1) * LEAF])
               for i in range((len(chunk) + LEAF - 1) // LEAF)]
        while len(lev) < T:
            lev.append(bytes(32))
        out.append(fold(lev))
    return b"".join(out)


def balance_hash(L):
    b = bytes(32)
    for _ in range(L):
        b = sha256(b + b)
    return b


def root_from_layer(layer, ps, file_len):
    """Recompute the pieces root from the piece layer (independent cross-check)."""
    L = (ps // LEAF).bit_length() - 1
    n_leaf = (file_len + LEAF - 1) // LEAF
    target = next_pow2(n_leaf) // (ps // LEAF)
    lev = [layer[i:i + 32] for i in range(0, len(layer), 32)]
    assert len(lev) <= target, "layer longer than file piece count"
    fill = balance_hash(L)
    while len(lev) < target:
        lev.append(fill)
    return fold(lev)


def v1_pieces(data, ps):
    return b"".join(sha1(data[off:off + ps]) for off in range(0, len(data), ps))


def gen_fixture(name, size):
    fname = name + ".bin"
    ps = piece_len(size)
    assert ps, "fixture too large"
    data = content(name, size)
    np = math.ceil(size / ps)
    root = root_from_file(data)
    pieces = v1_pieces(data, ps)
    layer = piece_layer(data, ps) if np > 1 else b""

    # Cross-checks: the layer must reproduce the root and the per-piece hashes.
    if np > 1:
        assert root_from_layer(layer, ps, size) == root, "root-from-layer mismatch"
        assert len(layer) == np * 32
        for i in range(np):
            chunk = data[i * ps:(i + 1) * ps]
            T = ps // LEAF
            lev = [sha256(chunk[j * LEAF:(j + 1) * LEAF])
                   for j in range((len(chunk) + LEAF - 1) // LEAF)]
            while len(lev) < T:
                lev.append(bytes(32))
            assert fold(lev) == layer[i * 32:(i + 1) * 32], "piece/layer mismatch"
    else:
        assert fold(merkle_leaves(data)) == root
    assert len(pieces) == np * 20

    info = bencode({
        "file tree": {fname: {b"": {"length": size, "pieces root": root}}},
        "length": size,
        "meta version": 2,
        "name": fname,
        "ntx salt": SALT,
        "piece length": ps,
        "pieces": pieces,
        "private": 1,
    })
    top = {
        "announce": TRACKERS[0],
        "announce-list": [[t] for t in TRACKERS],
        "created by": "ntx/" + VERSION,
        "creation date": CREATION_DATE,
        "info": Raw(info),  # spliced verbatim: top level must carry it byte for byte
    }
    if np > 1:
        top["piece layers"] = {root: layer}
    meta = bencode(top)
    # info.bin must be the exact substring the top level carries.
    assert meta.count(info) == 1, "info substring mismatch"

    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    write(os.path.join(d, "data.bin"), data)
    write(os.path.join(d, "salt.txt"), SALT.encode("ascii"))
    write(os.path.join(d, "trackers.txt"), "\n".join(TRACKERS).encode("ascii") + b"\n")
    write(os.path.join(d, "info.bin"), info)
    write(os.path.join(d, "meta.torrent"), meta)
    lines = [
        "# ntx --share metainfo fixture (test/scripts/share_gen.py)",
        "fixture: %s" % name,
        "name: %s" % fname,
        "size: %d" % size,
        "ps: %d" % ps,
        "np: %d" % np,
        "has_layers: %d" % (1 if np > 1 else 0),
        "salt: %s" % SALT,
        "creation_date: %d" % CREATION_DATE,
        "created_by: ntx/%s" % VERSION,
        "ih_sha1: %s" % sha1(info).hex(),
        "ih_sha256: %s" % sha256(info).hex(),
        "root: %s" % root.hex(),
        "pieces_sha1: %s" % pieces.hex(),
    ]
    if np > 1:
        lines.append("layer: %s" % layer.hex())
    write(os.path.join(d, "manifest.txt"), ("\n".join(lines) + "\n").encode("ascii"))
    print("wrote %s/ (size %d, ps %d, np %d, layers %d, info %d B, meta %d B)"
          % (name, size, ps, np, len(layer), len(info), len(meta)))


def write(path, data):
    with open(path, "wb") as f:
        f.write(data)


def main():
    os.makedirs(OUT, exist_ok=True)
    gen_fixture("tiny_1b", 1)
    gen_fixture("one_piece_16k", 16384)
    gen_fixture("multi_tail", 3 * 16384 + 100)
    gen_fixture("exact_multi", 4 * 16384)
    print("all fixtures OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
