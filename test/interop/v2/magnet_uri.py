#!/usr/bin/env python3
"""Derive a magnet URI (btih + BEP52 btmh) from a .torrent's own info dict.

Used by the v2 interop matrix for the pure-v2 ut_metadata cell: the ntx leech
must be started from a magnet (no .torrent on disk) so the info dict can only
arrive over BEP9. The hashes are computed from the raw bencoded info dict of
the fixture itself (golden rule: derive, never hardcode).

  * v1 / hybrid xt  urn:btih:<sha1(info) hex>
  * v2 xt           urn:btmh:1220<sha256(info) hex>   (BEP52 1220 prefix)

Prints "magnet:?xt=...&xt=...&dn=<name>" on stdout, exits non-zero on failure.
"""
import hashlib
import re
import sys


def value_len(raw, p):
    """Number of bytes of the bencoded value starting at p (validated)."""
    start = p
    c = raw[p:p + 1]
    if c == b"i":
        p = raw.index(b"e", p) + 1
    elif c == b"l":
        p += 1
        while raw[p:p + 1] != b"e":
            p += value_len(raw, p)
        p += 1
    elif c == b"d":
        p += 1
        while raw[p:p + 1] != b"e":
            p += value_len(raw, p)  # key
            p += value_len(raw, p)  # value
        p += 1
    elif c.isdigit():
        col = raw.index(b":", p)
        n = int(raw[p:col])
        p = col + 1 + n
    else:
        raise ValueError("bad bencode tag %r at %d" % (c, p))
    return p - start


def extract_info(raw):
    """Return the exact bencoded bytes of the top-level "info" value."""
    i = raw.find(b"4:info")
    if i < 0:
        raise ValueError("no info key")
    p = i + len(b"4:info")
    return raw[p:p + value_len(raw, p)]


def top_keys(info):
    """Names of the keys of a bencoded dict, in the order they appear."""
    out, p = [], info.index(b"d") + 1
    while info[p:p + 1] != b"e":
        col = info.index(b":", p)
        n = int(info[p:col])
        out.append(info[col + 1:col + 1 + n])
        p = col + 1 + n + value_len(info, col + 1 + n)
    return out


def info_name(info):
    m = re.search(rb"4:name(\d+):", info)
    if not m:
        return "interop"
    n = int(m.group(1))
    off = m.end()
    return info[off:off + n].decode("latin1")


def main():
    if len(sys.argv) != 2:
        sys.stderr.write("usage: magnet_uri.py META.TORRENT\n")
        return 2
    with open(sys.argv[1], "rb") as f:
        raw = f.read()
    info = extract_info(raw)
    # The btih xt is ALWAYS SHA-1 of the bencoded info dict and the btmh xt is
    # ALWAYS the BEP52 1220-prefixed SHA-256 of the same byes, whatever the
    # torrent's v1/v2/hybrid flavour: a magnet may carry both, and ntx matches
    # either.  Emitting the truncated SHA-256 as the btih is simply wrong and
    # makes every info-dict assembled from the magnet fail its xt check.
    sha1 = hashlib.sha1(info).hexdigest()
    sha256 = hashlib.sha256(info).hexdigest()
    # BEP52: a pure-v2 info dict has no "pieces" key, and its v1-compatible
    # btih is the TRUNCATED SHA-256, not SHA-1.  v1 and hybrid torrents carry
    # "piece layers" alongside "pieces" and keep the classic SHA-1 btih.
    # Substring probes are useless here: a hash value can encode to the very
    # bytes we look for.  Walk the info dict and test its keys instead.
    keys = top_keys(info)
    has_pieces = b"pieces" in keys
    has_layers = (b"piece layers" in keys or b"file tree" in keys)
    dn = info_name(info).replace(" ", "+")
    if not has_layers:
        # A v1-only torrent has no piece layers, hence no v2 root: advertising a
        # btmh xt would invite peers to run BEP52 verification against a torrent
        # that cannot satisfy it, and would make ntx flag the swarm as
        # v2-capable.  Emit the classic SHA-1 btih alone.
        print("magnet:?xt=urn:btih:%s&dn=%s" % (sha1, dn))
    elif has_pieces:
        # Hybrid: it joins the v1 swarm, so the btih xt is the real SHA-1(info)
        # and the btmh xt carries the v2 root (manifest "dual" golden).
        print("magnet:?xt=urn:btih:%s&xt=urn:btmh:1220%s&dn=%s"
              % (sha1, sha256, dn))
    else:
        # Pure v2: no "pieces" key, and the v1-compatible btih is the TRUNCATED
        # SHA-256, not SHA-1 (BEP52 / manifest "dual" golden).
        print("magnet:?xt=urn:btih:%s&xt=urn:btmh:1220%s&dn=%s"
              % (sha256[:40], sha256, dn))
    return 0


if __name__ == "__main__":
    sys.exit(main())
