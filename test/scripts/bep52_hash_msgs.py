#!/usr/bin/env python3
"""BEP52 hash-message golden vector generator.

Emits wire-exact vectors under test/vectors/bep52/ :
  hash_request_leaf.bin            id 21  leaf layer (base_layer=0) request
  hash_request_piece_layer.bin     id 21  piece layer (base_layer=3) request
  hash_reject.bin                  id 23  byte-identical payload to leaf request
  hashes_omitted_proof_layers.bin  id 22  proof-layer omission per BEP52
  hash_request_illegal_length.bin  id 21  length=3 (not power of two)
  hash_request_illegal_index.bin   id 21  index=3, length=2 (index % length)

Normative: BEP 52
(BEP52: "All later integers ... four bytes big-endian"; hash request payload
= pieces root 32 B + base layer + index + length + proof layers; hashes adds
concat hashes; hash reject has the same payload as hash request).

Wire layout of each .bin (BT framing included, parser can be fed the file
bytes directly):
  [0:4]   BE uint32 length prefix = 1 + payload bytes
  [4]     msg id (21/22/23)
  [5:37]  pieces root (32 B)
  [37:41] base layer  BE uint32
  [41:45] index       BE uint32
  [45:49] length      BE uint32
  [49:53] proof layers BE uint32
  [53:]   hashes (id 22 only): concat 32 B SHA2-256 digests

All vectors share one deterministic synthetic file (seed "bep52-hash-msgs",
262144 B = 16 x 16KiB leaves, no padding needed; tree height 4). Merkle
rules identical to src/core/ntx_merkle.c and bep52_gen.py: leaf = 16 KiB
block SHA2-256, BF=2, balance leaves past EOF = 32 zero bytes as leaf value.

Omission rule demonstrated by hashes_omitted_proof_layers (BEP52 §hashes):
request base_layer=0 index=0 length=4 proof_layers=3 -> the requested 4
leaves already contain the first log2(4)-1 = 1 proof layer (layer 1), so
layer 1 is omitted from the wire hashes but still counted in proof_layers;
layers 2 and 3 contribute one uncle hash each. Wire hashes = 4 leaves +
2 uncles = 6 x 32 B. Self-check: folding those 6 hashes reproduces the
pieces root.

Deterministic: no RNG, no clock; content(i) = sha256("<seed>:<i>") tiled.
Re-run:  python3 test/scripts/bep52_hash_msgs.py   (byte-identical output)
"""
import hashlib
import json
import os
import struct
import sys

LEAF = 16384
PIECE_LEN = 131072            # 128 KiB -> piece layer = log2(128K/16K) = 3
PIECE_LAYER = (PIECE_LEN // LEAF).bit_length() - 1   # == 3
FILE_SIZE = 16 * LEAF         # 262144 B = exactly 16 leaves, tree height 4
SEED = "bep52-hash-msgs"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.normpath(os.path.join(HERE, "..", "vectors", "bep52"))

ID_REQUEST = 21
ID_HASHES = 22
ID_REJECT = 23


def sha256(b):
    return hashlib.sha256(b).digest()


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


def log2(n):
    assert n > 0 and (n & (n - 1)) == 0, "not a power of two: %r" % n
    return n.bit_length() - 1


def merkle_layers(data):
    """List of layers: layers[0] = 16KiB leaf hashes, ..., layers[h] = [root].
    Trailing leaves past EOF = 32 zero bytes, padded to a power of two
    (identical to ntx_merkle.c ntx_leaves/ntx_fold_once)."""
    n_leaf = (len(data) + LEAF - 1) // LEAF if data else 0
    lev = [sha256(data[i * LEAF:(i + 1) * LEAF]) for i in range(n_leaf)]
    p = next_pow2(n_leaf) if n_leaf else 1
    while len(lev) < p:
        lev.append(bytes(32))
    layers = [lev]
    while len(lev) > 1:
        lev = [sha256(lev[i] + lev[i + 1]) for i in range(0, len(lev), 2)]
        layers.append(lev)
    return layers


def payload(root, base_layer, index, length, proof_layers, hashes=b""):
    return (root
            + struct.pack(">IIII", base_layer, index, length, proof_layers)
            + hashes)


def wire(msg_id, pay):
    frame = struct.pack(">I", 1 + len(pay)) + bytes([msg_id]) + pay
    assert len(frame) == 4 + 1 + len(pay)
    return frame


def base_hashes(layers, base_layer, index, length):
    lay = layers[base_layer]
    return b"".join(lay[index + i] for i in range(length))


def uncle_hashes(layers, base_layer, index, length, proof_layers):
    """One uncle per non-omitted proof layer, bottom to top.
    Omitted: the first log2(length)-1 proof layers (contained in the
    requested span); still counted towards proof_layers (BEP52 §hashes)."""
    h = len(layers) - 1                      # tree height
    om = log2(length) - 1
    assert proof_layers >= om, "proof_layers below omission floor"
    assert base_layer + proof_layers <= h - 1, "proof layers exceed tree"
    sub_layer = base_layer + log2(length)   # layer of the requested subtree root
    sub_node = index >> log2(length)        # aligned: index % length == 0
    out = []
    for i in range(om + 1, proof_layers + 1):
        layer = base_layer + i
        node = sub_node >> (layer - sub_layer)
        uncle = layers[layer][node ^ 1]
        out.append(uncle)
    return b"".join(out)


def fold_up(root, base_layer, index, length, proof_layers, hashes):
    """Recompute root from (base hashes ++ uncles); True iff == root."""
    base = [hashes[i * 32:(i + 1) * 32] for i in range(length)]
    uncles = [hashes[i * 32:(i + 1) * 32]
              for i in range(length, length + proof_layers - (log2(length) - 1))]
    lev = list(base)
    while len(lev) > 1:
        lev = [sha256(lev[i] + lev[i + 1]) for i in range(0, len(lev), 2)]
    node = lev[0]
    sub_layer = base_layer + log2(length)
    sub_node = index >> log2(length)
    for i, uncle in enumerate(uncles):
        path = sub_node >> i
        node = sha256(node + uncle) if (path & 1) == 0 else sha256(uncle + node)
    return node == root


def write_vector(stem, msg_id, fields, blob, extra=None):
    pay_len = len(blob) - 5
    meta = {
        "generator": "test/scripts/bep52_hash_msgs.py",
        "bep": "BEP52 hash exchange",
        "msg": {"name": fields["msg_name"], "id": msg_id},
        "framing": {
            "length_prefix": "BE uint32 = 1 + payload_bytes",
            "msg_id_bytes": 1,
            "payload_bytes": pay_len,
            "total_bytes": len(blob),
        },
        "fields": {
            "pieces_root": fields["root"].hex(),
            "base_layer": fields["base_layer"],
            "index": fields["index"],
            "length": fields["length"],
            "proof_layers": fields["proof_layers"],
        },
        "legality": fields["legality"],
        "source": {
            "seed": SEED,
            "file_size": FILE_SIZE,
            "leaf_size": LEAF,
            "piece_length": PIECE_LEN,
            "piece_layer": PIECE_LAYER,
            "note": "pieces_root = SHA2-256 merkle root (BF=2, 16KiB leaves) "
                   "of the deterministic file content(seed,i) tiled to file_size",
        },
    }
    if fields.get("hashes") is not None:
        meta["fields"]["hashes"] = {
            "count": len(fields["hashes"]) // 32,
            "bytes": len(fields["hashes"]),
            "hex": fields["hashes"].hex(),
        }
    if extra:
        meta.update(extra)
    binp = os.path.join(OUT, stem + ".bin")
    metap = os.path.join(OUT, stem + ".meta.json")
    with open(binp, "wb") as f:
        f.write(blob)
    with open(metap, "w") as f:
        f.write(json.dumps(meta, indent=2, sort_keys=False) + "\n")
    print("wrote %s (%d B, id %d, %s)" % (stem, len(blob), msg_id,
                                          fields["legality"]))


def req_fields(root, base_layer, index, length, proof_layers, msg_name, legality):
    return {"root": root, "base_layer": base_layer, "index": index,
            "length": length, "proof_layers": proof_layers,
            "msg_name": msg_name, "legality": legality, "hashes": None}


def main():
    os.makedirs(OUT, exist_ok=True)
    data = content(SEED, FILE_SIZE)
    layers = merkle_layers(data)
    height = len(layers) - 1
    root = layers[height][0]
    assert height == 4, "fixture expects tree height 4, got %d" % height
    assert len(layers[0]) == 16 and len(layers[PIECE_LAYER]) == 2
    # piece layer (128KiB per hash) folds the first 8 leaves to hash 0
    lev = list(layers[0][0:8])
    while len(lev) > 1:
        lev = [sha256(lev[i] + lev[i + 1]) for i in range(0, len(lev), 2)]
    assert layers[PIECE_LAYER][0] == lev[0]

    vectors = []

    # 1. legal leaf-layer request: 4 leaf hashes from index 0
    f1 = req_fields(root, 0, 0, 4, 0, "hash request", "legal")
    vectors.append(("hash_request_leaf", ID_REQUEST, f1, None))

    # 2. legal piece-layer request (ps=128KiB -> base_layer=3), both hashes
    f2 = req_fields(root, PIECE_LAYER, 0, 2, 0, "hash request", "legal")
    vectors.append(("hash_request_piece_layer", ID_REQUEST, f2, None))

    # 3. hash reject: byte-identical payload of vector 1 (BEP52)
    f3 = req_fields(root, 0, 0, 4, 0, "hash reject", "legal")
    vectors.append(("hash_reject", ID_REJECT, f3, None))

    # 4. hashes with proof-layer omission: length=4 -> layer 1 omitted
    #    (log2(4)-1 = 1), layers 2..3 uncles on the wire, proof_layers=3
    f4 = req_fields(root, 0, 0, 4, 3, "hashes", "legal")
    hs = base_hashes(layers, 0, 0, 4) + uncle_hashes(layers, 0, 0, 4, 3)
    assert len(hs) == (4 + 3 - (log2(4) - 1)) * 32 == 192
    assert fold_up(root, 0, 0, 4, 3, hs), "hashes vector must fold to root"
    f4["hashes"] = hs
    vectors.append(("hashes_omitted_proof_layers", ID_HASHES, f4, {
        "omission": {
            "rule": "BEP52: first log2(length)-1 proof layers are omitted "
                    "from hashes when the requested span contains them; "
                    "they still count towards proof_layers",
            "log2_length_minus_1": log2(4) - 1,
            "requested_proof_layers": 3,
            "omitted_layers": [1],
            "included_uncle_layers": [2, 3],
            "wire_hash_count": 6,
        },
        "correlates_with": {
            "pieces_root": root.hex(), "base_layer": 0, "index": 0,
            "length": 4, "proof_layers": 3,
        },
        "expected": "hashes must fold to pieces_root (see fold in meta)",
    }))

    # 5. illegal: length=3 (not a power of two; also length>=2 ok but pow2 fails)
    f5 = req_fields(root, 0, 0, 3, 0, "hash request", "illegal")
    vectors.append(("hash_request_illegal_length", ID_REQUEST, f5, {
        "violations": ["length-must-be-power-of-two (BEP52: length >= 2 "
                       "and power of two)"],
        "expected": "well-formed framing; validation MUST reject",
    }))

    # 6. illegal: index=3, length=2 -> index % length = 1 != 0
    f6 = req_fields(root, 0, 3, 2, 0, "hash request", "illegal")
    vectors.append(("hash_request_illegal_index", ID_REQUEST, f6, {
        "violations": ["index-must-be-multiple-of-length (BEP52: index % "
                       "length == 0)"],
        "expected": "well-formed framing; validation MUST reject",
    }))

    # cross-checks before writing anything
    reject_pay = payload(**{k: f3[k] for k in
                            ("root", "base_layer", "index", "length",
                             "proof_layers")})
    leaf_pay = payload(**{k: f1[k] for k in
                          ("root", "base_layer", "index", "length",
                           "proof_layers")})
    assert reject_pay == leaf_pay, "reject payload must equal request payload"
    for stem, mid, f, _extra in vectors:
        pay = payload(f["root"], f["base_layer"], f["index"], f["length"],
                      f["proof_layers"], f["hashes"] or b"")
        blob = wire(mid, pay)
        want = 245 if mid == ID_HASHES else 53
        assert len(blob) == want, "%s: %d != %d" % (stem, len(blob), want)
        # every legal request must be answerable: index aligned, pow2 length
        if f["legality"] == "legal":
            assert f["length"] >= 2 and (f["length"] & (f["length"] - 1)) == 0
            assert f["index"] % f["length"] == 0
        assert f["root"] == root
        write_vector(stem, mid, f, blob, _extra)
    print("all %d vectors OK (pieces_root=%s)" % (len(vectors), root.hex()))


if __name__ == "__main__":
    sys.exit(main())
