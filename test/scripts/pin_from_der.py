#!/usr/bin/env python3
"""pin_from_der.py FILE.der — SHA-256(DER SubjectPublicKeyInfo) → 64-char hex lower.

X.509 (RFC 5280):
  Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
  SubjectPublicKeyInfo lives in TBSCertificate (the SEQUENCE field after subject).
If the file is a bare SPKI (SEQUENCE { AlgorithmIdentifier, BIT STRING }),
the whole file is hashed.
"""
import hashlib
import sys


def read_tlv(data: bytes, off: int):
    """Returns (tag, value_start, value_len)."""
    if off >= len(data):
        raise ValueError("truncated: tag")
    tag = data[off]
    off += 1
    if tag & 0x1F == 0x1F:  # multi-byte tag
        while True:
            if off >= len(data):
                raise ValueError("truncated: tag number")
            b = data[off]
            off += 1
            if not (b & 0x80):
                break
    if off >= len(data):
        raise ValueError("truncated: length")
    lb = data[off]
    off += 1
    if lb < 0x80:
        length = lb
    elif lb == 0x80:
        raise ValueError("indefinite length not supported")
    else:
        n = lb & 0x7F
        if off + n > len(data):
            raise ValueError("truncated: long-form length")
        length = int.from_bytes(data[off : off + n], "big")
        off += n
    if off + length > len(data):
        raise ValueError("truncated: value")
    return tag, off, length


def parse_children(data: bytes, vstart: int, vlen: int):
    """Lista (tag, start_tlv, value_start, value_len) dzieci."""
    out = []
    off = vstart
    end = vstart + vlen
    while off < end:
        tag_start = off
        tag, vstart2, vlen2 = read_tlv(data, off)
        out.append((tag, tag_start, vstart2, vlen2))
        off = vstart2 + vlen2
    return out


def raw_tlv(data: bytes, child) -> bytes:
    tag, tag_start, vstart, vlen = child
    return data[tag_start : vstart + vlen]


def looks_like_spki(data: bytes, child) -> bool:
    tag, _tag_start, vstart, vlen = child
    if tag != 0x30:
        return False
    inner = parse_children(data, vstart, vlen)
    return len(inner) >= 2 and inner[0][0] == 0x30 and inner[1][0] == 0x03


def spki_from_cert(data: bytes):
    """SPKI from an X.509 certificate; None if the structure does not match."""
    tag, vstart, vlen = read_tlv(data, 0)
    if tag != 0x30:
        return None
    children = parse_children(data, vstart, vlen)
    if len(children) != 3:
        return None
    tbs_tag, _tbs_ts, tbs_vstart, tbs_vlen = children[0]
    sig_tag, _sig_ts, _sig_vs, _sig_vl = children[1]
    sigval_tag, _sv_ts, _sv_vs, _sv_vl = children[2]
    if tbs_tag != 0x30 or sig_tag != 0x30 or sigval_tag != 0x03:
        return None
    tbs = parse_children(data, tbs_vstart, tbs_vlen)
    idx = 1 if tbs and tbs[0][0] == 0xA0 else 0  # [0] EXPLICIT version
    # serial INTEGER, sigAlg SEQUENCE, issuer, validity SEQUENCE, subject, SPKI
    if len(tbs) - idx < 6:
        return None
    want = [0x02, 0x30, None, 0x30, None, 0x30]
    for k, w in enumerate(want):
        if w is not None and tbs[idx + k][0] != w:
            return None
    spki = tbs[idx + 5]
    if looks_like_spki(data, spki):
        return raw_tlv(data, spki)
    # fallback: the last SEQUENCE in TBS (SPKI is the last v3 field)
    seqs = [c for c in tbs if c[0] == 0x30]
    for c in reversed(seqs):
        if looks_like_spki(data, c):
            return raw_tlv(data, c)
    return None


def extract_spki(data: bytes) -> bytes:
    spki = spki_from_cert(data)
    if spki is not None:
        return spki
    # the file is the bare SPKI: SEQUENCE { SEQUENCE (AlgorithmIdentifier), BIT STRING }
    tag, vstart, vlen = read_tlv(data, 0)
    if tag == 0x30:
        children = parse_children(data, vstart, vlen)
        if len(children) == 2 and children[0][0] == 0x30 and children[1][0] == 0x03:
            return data[0 : vstart + vlen]
    raise ValueError("not a certificate and not a bare SubjectPublicKeyInfo")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: pin_from_der.py FILE.der", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], "rb") as f:
            data = f.read()
    except OSError as e:
        print(f"ERROR: cannot read {sys.argv[1]}: {e}", file=sys.stderr)
        return 1
    try:
        spki = extract_spki(data)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1
    sys.stdout.write(hashlib.sha256(spki).hexdigest() + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
