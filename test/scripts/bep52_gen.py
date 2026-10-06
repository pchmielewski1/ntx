#!/usr/bin/env python3
"""BEP52 fixture generator (golden source for C tests).

Emits fixtures under test/vectors/bep52/ :
  single_16k/        pure v2 single file,  piece len 16KiB
  multi_v2/          pure v2 multi file (rootless + subdir), piece len 128KiB
  hybrid_ok/         hybrid single file (v1 + v2 in one info dict), 16KiB
  hybrid_bad_order/  hybrid multi file; v1 files order != v2 tree order (must reject)

Each fixture dir contains:
  meta.torrent   full bencoded .torrent (announce + info [+ piece layers])
  <file bytes>   on disk under the fixture dir at the tree-relative path
  manifest.txt   line-based expected values (see README.txt)

Deterministic content: block(i) = sha256(b"<seed>:<i>") tiled.
Self-checks before writing:
  - root recomputed from the piece layer == root computed from file bytes
  - per-piece sha256 matches the layer entry
  - v1 pieces match the (padded) v1 address space layout
Run:  python3 test/scripts/bep52_gen.py
"""
import hashlib
import os
import sys

LEAF = 16384
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "vectors", "bep52"))


def bencode(obj):
    if isinstance(obj, bool):
        raise TypeError("bool is not bencode")
    if isinstance(obj, int):
        return b"i%de" % obj
    if isinstance(obj, str):
        b = obj.encode("utf-8")
        return str(len(b)).encode("ascii") + b":" + b
    if isinstance(obj, (bytes, bytearray)):
        b = bytes(obj)
        return str(len(b)).encode("ascii") + b":" + b
    if isinstance(obj, list):
        return b"l" + b"".join(bencode(x) for x in obj) + b"e"
    if isinstance(obj, dict):
        out = b"d"

        def ksort(k):
            return k.encode("utf-8") if isinstance(k, str) else k

        for k in sorted(obj.keys(), key=ksort):
            out += bencode(k) + bencode(obj[k])
        return out + b"e"
    raise TypeError(type(obj))


def sha1(b):
    return hashlib.sha1(b).digest()


def sha256(b):
    return hashlib.sha256(b).digest()


def hexd(b):
    return b.hex()


def content(seed, size):
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


def merkle_leaves(data):
    """16KiB block hashes; last block may be shorter; zero-fill (32 zero bytes
    as the leaf hash value) up to a power of two. Empty file -> single zero leaf."""
    n_leaf = (len(data) + LEAF - 1) // LEAF if data else 0
    leaves = [sha256(data[i * LEAF:(i + 1) * LEAF]) for i in range(n_leaf)]
    p = next_pow2(n_leaf) if n_leaf else 1
    while len(leaves) < p:
        leaves.append(bytes(32))
    return leaves


def fold(levels):
    while len(levels) > 1:
        levels = [sha256(levels[i] + levels[i + 1]) for i in range(0, len(levels), 2)]
    return levels[0]


def root_from_file(data):
    return fold(merkle_leaves(data))


def file_layer(data, ps):
    """Concatenated hashes of the layer where one hash covers exactly ps bytes.
    Balance-only hashes (past EOF) are omitted. Empty file -> b''."""
    if not data:
        return b""
    n_leaf = (len(data) + LEAF - 1) // LEAF
    lev = merkle_leaves(data)
    for _ in range((ps // LEAF).bit_length() - 1):
        lev = [sha256(lev[i] + lev[i + 1]) for i in range(0, len(lev), 2)]
    np = (len(data) + ps - 1) // ps
    return b"".join(lev[:np])


def balance_hash(L):
    """Value of a layer-L hash whose 2^L leaves are all past-EOF zeros:
    L folds of the 32-byte zero leaf value."""
    b = bytes(32)
    for _ in range(L):
        b = sha256(b + b)
    return b


def root_from_layer(layer, ps, file_len):
    """Recompute the file merkle root from a piece-layer string (T6 check).
    Layer hashes cover exactly ps bytes each; balance-only (past-EOF) hashes
    are filled with their merkle value (L folds of zero leaves), then the
    layer is folded up to the root."""
    if file_len == 0:
        return bytes(32)
    L = (ps // LEAF).bit_length() - 1
    n_leaf = (file_len + LEAF - 1) // LEAF
    target = next_pow2(n_leaf) // (ps // LEAF)
    lev = [layer[i:i + 32] for i in range(0, len(layer), 32)]
    assert len(lev) <= target, "layer longer than file piece count"
    fill = balance_hash(L)
    while len(lev) < target:
        lev.append(fill)
    for _ in range(target.bit_length() - 1):
        lev = [sha256(lev[i] + lev[i + 1]) for i in range(0, len(lev), 2)]
    return lev[0]


def v2_piece_hashes(data, ps):
    """Piece hash of each logical piece.

    len > ps:  the merkle subtree root where the subtree covers exactly ps
               bytes (2^L 16KiB leaves, zero-filled to balance; for ps ==
               16KiB this is just sha256 of the piece bytes).
    len <= ps: the file has a single piece and the tree has no piece-layer
               level, so the piece hash is the pieces root itself."""
    if not data:
        return []
    if len(data) <= ps:
        return [root_from_file(data)]
    out = []
    L = (ps // LEAF).bit_length() - 1
    target = 1 << L
    for off in range(0, len(data), ps):
        chunk = data[off:off + ps]
        leaves = [sha256(chunk[i * LEAF:(i + 1) * LEAF])
                  for i in range((len(chunk) + LEAF - 1) // LEAF)]
        while len(leaves) < target:
            leaves.append(bytes(32))
        for _ in range(L):
            leaves = [sha256(leaves[i] + leaves[i + 1])
                      for i in range(0, len(leaves), 2)]
        out.append(leaves[0])
    return out


def v1_pieces(blobs, ps):
    """sha1 pieces over a contiguous v1 address space (blobs in v1 order,
    padding blobs included as zeros)."""
    cat = b"".join(blobs)
    return [sha1(cat[i:i + ps]) for i in range(0, len(cat), ps)]


def write_fixture(name, meta, files, manifest_lines):
    d = os.path.join(OUT, name)
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, "meta.torrent"), "wb") as f:
        f.write(meta)
    for rel, data in files.items():
        p = os.path.join(d, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True) if os.path.dirname(p) else None
        with open(p, "wb") as f:
            f.write(data)
    with open(os.path.join(d, "manifest.txt"), "w") as f:
        for ln in manifest_lines:
            f.write(ln + "\n")
    print("wrote %s/ (%d files, meta %d B)" % (name, len(files), len(meta)))


def manifest_header(name, kind, ps, np_total, addr_end, data_size,
                    ih_full, ih_trunc, ih_sha1):
    return [
        "# bep52 fixture manifest",
        "fixture: %s" % name,
        "kind: %s" % kind,
        "piece_len: %d" % ps,
        "np_total: %d" % np_total,
        "addr_end: %d" % addr_end,
        "data_size: %d" % data_size,
        "ih_full: %s" % hexd(ih_full),
        "ih_trunc: %s" % hexd(ih_trunc),
        "ih_sha1: %s" % hexd(ih_sha1),
    ]


# ---------------------------------------------------------------------------
# 1. single_16k : pure v2, single file, ps = 16KiB
# ---------------------------------------------------------------------------
def gen_single():
    name = "single_16k"
    ps = 16384
    fsize = 40000
    data = content(name, fsize)
    root = root_from_file(data)
    layer = file_layer(data, ps)
    pieces = v2_piece_hashes(data, ps)
    for i, ph in enumerate(pieces):
        assert ph == layer[i * 32:(i + 1) * 32], "piece/layer mismatch"
    assert root_from_layer(layer, ps, fsize) == root, "root-from-layer mismatch"

    np_total = len(pieces)
    addr_end = (np_total - 1) * ps + (fsize - (np_total - 1) * ps)
    info = {
        "name": name,
        "piece length": ps,
        "meta version": 2,
        "file tree": {name: {b"": {"length": fsize, "pieces root": root}}},
    }
    meta = bencode({"announce": "http://127.0.0.1:6969/announce",
                    "info": info,
                    "piece layers": {root: layer}})
    ih_full = sha256(bencode(info))
    ih_trunc = ih_full[:20]
    ih_sha1 = sha1(bencode(info))

    lines = manifest_header(name, "single_v2", ps, np_total, addr_end, fsize,
                            ih_full, ih_trunc, ih_sha1)
    lines.append("file: idx=0 fp=0 np=%d len=%d root=%s path=%s"
                 % (np_total, fsize, hexd(root), name))
    lines.append("layer: idx=0 %s" % hexd(layer))
    for i, ph in enumerate(pieces):
        lines.append("piece: idx=%d v2=%s" % (i, hexd(ph)))
    lines += [
        "# magnet fixtures (line starts with 'magnet:')",
        "magnet: %s btmh_only" % name,
        "magnet:?xt=urn:btmh:1220%s&dn=bep52+single" % hexd(ih_full),
        "magnet: %s dual" % name,
        "magnet:?xt=urn:btih:%s&xt=urn:btmh:1220%s&dn=bep52+single"
        % (hexd(ih_trunc), hexd(ih_full)),
    ]
    write_fixture(name, meta, {name: data}, lines)


# ---------------------------------------------------------------------------
# 2. multi_v2 : pure v2, rootless tree + subdir, ps = 128KiB
#    a.txt 50000 B  (< ps, single piece, root only, no layer entry)
#    dir/b.dat 300000 B (3 pieces, 19 leaves, layer of 3 hashes, 1 omitted)
#    dir/c.bin 1000 B   (< ps, single piece, root only, no layer entry)
# ---------------------------------------------------------------------------
def gen_multi():
    name = "multi_v2"
    ps = 131072
    files = {
        "a.txt": content(name + ":a", 50000),
        "dir/b.dat": content(name + ":b", 300000),
        "dir/c.bin": content(name + ":c", 1000),
    }
    order = ["a.txt", "dir/b.dat", "dir/c.bin"]  # tree (sorted DFS) order
    tree = {"a.txt": None, "dir": {"b.dat": None, "c.bin": None}}

    entries = []
    layers = {}
    fp = 0
    for rel in order:
        data = files[rel]
        root = root_from_file(data)
        np = (len(data) + ps - 1) // ps if data else 0
        entries.append((rel, data, root, np, fp))
        if len(data) > ps:
            lay = file_layer(data, ps)
            layers[root] = lay
            assert root_from_layer(lay, ps, len(data)) == root, "root-from-layer"
            for i in range(np):
                assert v2_piece_hashes(data, ps)[i] == lay[i * 32:(i + 1) * 32]
        fp += np

    tree = {}
    for rel, data, root, np, f0 in entries:
        parts = rel.split("/")
        node = tree
        for p in parts[:-1]:
            node = node.setdefault(p, {})
        node[parts[-1]] = {b"": {"length": len(data), "pieces root": root}}

    info = {
        "name": name,
        "piece length": ps,
        "meta version": 2,
        "file tree": tree,
    }
    meta = bencode({"announce": "http://127.0.0.1:6969/announce",
                    "info": info,
                    "piece layers": layers})
    ih_full = sha256(bencode(info))
    ih_trunc = ih_full[:20]
    ih_sha1 = sha1(bencode(info))

    np_total = entries[-1][4] + entries[-1][3]
    addr_end = entries[-1][4] * ps + len(entries[-1][1])
    data_size = sum(len(d) for d in files.values())
    lines = manifest_header(name, "multi_v2", ps, np_total, addr_end, data_size,
                            ih_full, ih_trunc, ih_sha1)
    for i, (rel, data, root, np, f0) in enumerate(entries):
        lines.append("file: idx=%d fp=%d np=%d len=%d root=%s path=%s"
                     % (i, f0, np, len(data), hexd(root), rel))
        if len(data) > ps:
            lines.append("layer: idx=%d %s" % (i, hexd(layers[root])))
    gi = 0
    for rel, data, root, np, f0 in entries:
        for ph in v2_piece_hashes(data, ps):
            lines.append("piece: idx=%d v2=%s" % (gi, hexd(ph)))
            gi += 1
    write_fixture(name, meta, files, lines)


# ---------------------------------------------------------------------------
# 3. hybrid_ok : hybrid single file, v1 ps == v2 ps == 16KiB
# ---------------------------------------------------------------------------
def gen_hybrid_ok():
    name = "hybrid_ok"
    fname = "hello.txt"
    ps = 16384
    fsize = 50000
    data = content(name, fsize)
    root = root_from_file(data)
    layer = file_layer(data, ps)
    assert root_from_layer(layer, ps, fsize) == root

    v1pc = v1_pieces([data], ps)
    for i, ph in enumerate(v2_piece_hashes(data, ps)):
        assert ph == layer[i * 32:(i + 1) * 32]

    info = {
        "name": fname,
        "piece length": ps,
        "pieces": b"".join(v1pc),
        "length": fsize,
        "meta version": 2,
        "file tree": {fname: {b"": {"length": fsize, "pieces root": root}}},
    }
    meta = bencode({"announce": "http://127.0.0.1:6969/announce",
                    "info": info,
                    "piece layers": {root: layer}})
    ib = bencode(info)
    ih_full = sha256(ib)
    ih_trunc = ih_full[:20]
    ih_sha1 = sha1(ib)  # v1 swarm infohash (hybrid joins v1 swarm with this)

    np_total = len(v1pc)
    lines = manifest_header(name, "hybrid_ok", ps, np_total, fsize, fsize,
                            ih_full, ih_trunc, ih_sha1)
    lines.append("file: idx=0 fp=0 np=%d len=%d root=%s path=%s"
                 % (np_total, fsize, hexd(root), fname))
    lines.append("layer: idx=0 %s" % hexd(layer))
    for i, ph in enumerate(v2_piece_hashes(data, ps)):
        lines.append("piece: idx=%d v2=%s v1=%s" % (i, hexd(ph), hexd(v1pc[i])))
    lines += [
        "magnet: %s dual" % name,
        "magnet:?xt=urn:btih:%s&xt=urn:btmh:1220%s&dn=bep52+hybrid"
        % (hexd(ih_sha1), hexd(ih_full)),
    ]
    write_fixture(name, meta, {fname: data}, lines)


# ---------------------------------------------------------------------------
# 4. hybrid_bad_order : hybrid multi file; v1 files order [b, pad, a] but v2
#    tree order [a, b] -> layout validation MUST reject.
# ---------------------------------------------------------------------------
def gen_hybrid_bad_order():
    name = "hybrid_bad_order"
    ps = 16384
    a = content(name + ":a", 20000)
    b = content(name + ":b", 40000)
    pa = ps - (len(a) % ps)  # 12768
    pb = ps - (len(b) % ps)  # 9152
    ra = root_from_file(a)
    rb = root_from_file(b)
    la = file_layer(a, ps)
    lb = file_layer(b, ps)
    assert root_from_layer(la, ps, len(a)) == ra
    assert root_from_layer(lb, ps, len(b)) == rb

    tree = {
        "a.bin": {b"": {"length": len(a), "pieces root": ra}},
        "b.bin": {b"": {"length": len(b), "pieces root": rb}},
    }
    # v1 layout: b first (order mismatch), then pad, then a
    v1_order = [b, b"\x00" * pb, a, b"\x00" * pa]
    v1pc = v1_pieces(v1_order, ps)
    v1_files = [
        {"length": len(b), "path": ["b.bin"]},
        {"length": pb, "path": [".pad", str(pb)], "attr": "p"},
        {"length": len(a), "path": ["a.bin"]},
        {"length": pa, "path": [".pad", str(pa)], "attr": "p"},
    ]
    info = {
        "name": name,
        "piece length": ps,
        "pieces": b"".join(v1pc),
        "files": v1_files,
        "meta version": 2,
        "file tree": tree,
    }
    meta = bencode({"announce": "http://127.0.0.1:6969/announce",
                    "info": info,
                    "piece layers": {ra: la, rb: lb}})
    ib = bencode(info)
    ih_full = sha256(ib)
    ih_trunc = ih_full[:20]
    ih_sha1 = sha1(ib)

    # v2 mapping (tree order a,b): a fp=0 np=2, b fp=2 np=3
    np_total = (len(a) + ps - 1) // ps + (len(b) + ps - 1) // ps
    addr_end = ((len(a) + ps - 1) // ps) * ps + len(b)
    data_size = len(a) + len(b)
    lines = manifest_header(name, "hybrid_bad_order", ps, np_total, addr_end,
                            data_size, ih_full, ih_trunc, ih_sha1)
    lines.append("file: idx=0 fp=0 np=%d len=%d root=%s path=a.bin"
                 % ((len(a) + ps - 1) // ps, len(a), hexd(ra)))
    lines.append("file: idx=1 fp=%d np=%d len=%d root=%s path=b.bin"
                 % ((len(a) + ps - 1) // ps, (len(b) + ps - 1) // ps, len(b), hexd(rb)))
    lines.append("layer: idx=0 %s" % hexd(la))
    lines.append("layer: idx=1 %s" % hexd(lb))
    write_fixture(name, meta, {"a.bin": a, "b.bin": b}, lines)


def main():
    os.makedirs(OUT, exist_ok=True)
    with open(os.path.join(OUT, "README.txt"), "w") as f:
        f.write(
            "BEP52 P5a golden fixtures. Generated by test/scripts/bep52_gen.py "
            "(deterministic; re-run to regenerate). C tests read meta.torrent, "
            "the file bytes and manifest.txt; never hardcode these values.\n\n"
            "manifest.txt keys:\n"
            "  fixture / kind / piece_len / np_total / addr_end / data_size\n"
            "  ih_full  32 B sha256(info) hex\n"
            "  ih_trunc first 20 B hex (tracker/HS for pure v2)\n"
            "  ih_sha1  20 B sha1(info) hex (v1 swarm for hybrid)\n"
            "  file: idx= fp= np= len= root= path=   (tree order)\n"
            "  layer: idx= <hex>   (only files with len > piece_len)\n"
            "  piece: idx= v2=<hex> [v1=<hex>]  (global piece index)\n"
            "  magnet: <fixture> <btmh_only|dual>\n"
            "  magnet:?xt=...  (the magnet URL for the line above)\n"
        )
    gen_single()
    gen_multi()
    gen_hybrid_ok()
    gen_hybrid_bad_order()
    print("all fixtures OK")


if __name__ == "__main__":
    sys.exit(main())
