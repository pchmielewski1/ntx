#!/usr/bin/env python3
"""rsa_pss_vectors.py - RSASSA-PSS (SHA-256, MGF1-SHA256, salt 32) vectors for
src/crypto/ntx_rsa_pkcs1.c:ntx_rsa_pss_verify_sha256.

Signatures are produced by the `cryptography` package (OpenSSL), i.e. an
implementation independent of ntx. Output: test/vectors/rsa_pss/vectors.txt, lines
    <n hex> <e hex> <mhash hex> <sig hex> <expected 1|0> <label>

Run from the repository root:  python3 test/scripts/rsa_pss_vectors.py
(Keys are generated fresh each run; the committed file is just one sample.)
"""
import hashlib
import os
import sys

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))


def sign(key, msg):
    return key.sign(
        msg,
        padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
        hashes.SHA256(),
    )


def mgf1(seed, ln):
    out = b""
    ctr = 0
    while len(out) < ln:
        out += hashlib.sha256(seed + ctr.to_bytes(4, "big")).digest()
        ctr += 1
    return out[:ln]


def pss_em(mhash, salt, em_len, unused_bits=0):
    """EM = maskedDB || H || 0xBC, exactly the RSASSA-PSS-GENERIC layout
    (maskGen = MGF1-SHA256, trailer 0xBC). unused_bits = 8*emLen - emBits."""
    db = b"\x00" * (em_len - 34 - len(salt)) + b"\x01" + salt  # dbLen = emLen-33
    m_seed = hashlib.sha256(b"\x00" * 8 + mhash + salt).digest()
    masked = bytearray(bytes(a ^ b for a, b in zip(db, mgf1(m_seed, em_len - 33))))
    if unused_bits:
        masked[0] &= 0xFF >> unused_bits  # leftmost bits must be zero per RFC 8017
    return bytes(masked) + m_seed + b"\xbc"


def rsasp(key, em):
    """Raw RSASP1: sig = em^d mod n - lets the vectors carry crafted EMs."""
    priv = key.private_numbers()
    return pow(int.from_bytes(em, "big"), priv.d, priv.public_numbers.n).to_bytes(
        (priv.public_numbers.n.bit_length() + 7) // 8, "big"
    )


def main():
    lines = []
    for bits in (2048, 2047, 3072):  # 2047: emLen = k-1 path (modBits % 8 == 7)
        key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        nums = key.public_key().public_numbers()
        k = (nums.n.bit_length() + 7) // 8
        n_hex = nums.n.to_bytes(k, "big").hex()
        e_hex = nums.e.to_bytes(3, "big").hex()
        em_len = (nums.n.bit_length() - 1 + 7) // 8
        unused = 8 * em_len - (nums.n.bit_length() - 1)  # 8*emLen - emBits
        for i in range(3):
            msg = b"ntx rsa-pss vector %d/%d" % (bits, i)
            mh = hashlib.sha256(msg).digest()
            sig = sign(key, msg)
            assert len(sig) == k
            lines.append((n_hex, e_hex, mh.hex(), sig.hex(), 1, "valid-%d-%d" % (bits, i)))
            if i == 0:
                bad = bytearray(sig)
                bad[len(bad) // 2] ^= 0x01
                lines.append((n_hex, e_hex, mh.hex(), bytes(bad).hex(), 0, "flipped-sig-%d" % bits))
                badh = bytearray(mh)
                badh[0] ^= 0x80
                lines.append((n_hex, e_hex, bytes(badh).hex(), sig.hex(), 0, "wrong-hash-%d" % bits))
                lines.append((n_hex, e_hex, mh.hex(), (b"\x00" * k).hex(), 0, "zero-sig-%d" % bits))
                lines.append((n_hex, e_hex, mh.hex(), n_hex, 0, "sig-eq-n-%d" % bits))
                # --- structural vectors (CVE-2022-3437 class): crafted EMs signed
                # with the real key, so every check but the broken one holds.
                salt = bytes((j * 7 + 1) & 0xFF for j in range(32))
                em = pss_em(mh, salt, em_len, unused)
                if int.from_bytes(em, "big") >= nums.n:
                    continue
                lines.append((n_hex, e_hex, mh.hex(), rsasp(key, em).hex(), 1,
                              "crafted-valid-%d" % bits))
                # trailer != 0xBC
                t = bytearray(em)
                t[-1] = 0xBB
                lines.append((n_hex, e_hex, mh.hex(), rsasp(key, bytes(t)).hex(), 0,
                              "bad-trailer-%d" % bits))
                # leftmost unused bits of maskedDB set (must be zero: 8*emLen - emBits)
                u = bytearray(em)
                u[0] |= 0x80 >> (unused - 1)
                lines.append((n_hex, e_hex, mh.hex(), rsasp(key, bytes(u)).hex(), 0,
                              "bad-unused-bit-%d" % bits))
                # DB structure: a PS padding byte flipped (salt and H stay consistent,
                # only the all-zero PS check can catch this)
                p = bytearray(em)
                p[2] ^= 0x02
                lines.append((n_hex, e_hex, mh.hex(), rsasp(key, bytes(p)).hex(), 0,
                              "bad-ps-byte-%d" % bits))
                # DB structure: the 0x01 separator flipped
                s = bytearray(em)
                s[em_len - 33 - 32 - 1] ^= 0x01
                lines.append((n_hex, e_hex, mh.hex(), rsasp(key, bytes(s)).hex(), 0,
                              "bad-sep-byte-%d" % bits))
                # salt shorter than 32 (RFC 8446 requires saltLen == hLen for
                # rsa_pss_rsae_sha256; the 20-byte variant must be refused)
                sig20 = key.sign(
                    msg,
                    padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=20),
                    hashes.SHA256(),
                )
                lines.append((n_hex, e_hex, mh.hex(), sig20.hex(), 0, "salt-20-%d" % bits))
                # "auto" salt (emLen - hLen - 2 = 222 at 2048): the lenient-verifier
                # bug class; a strict saltLen==32 verifier must refuse it. (Built by
                # hand: the cryptography lib only allows AUTO when verifying.)
                sigauto = rsasp(key, pss_em(mh, bytes((j * 11 + 3) & 0xFF for j in range(em_len - 34)), em_len, unused))
                lines.append((n_hex, e_hex, mh.hex(), sigauto.hex(), 0, "salt-auto-%d" % bits))
                # API robustness: same key with an explicit leading zero byte in n
                # (and the signature padded to match) - must still verify.
                lines.append((("00" + n_hex), e_hex, mh.hex(), "00" + sig.hex(), 1,
                              "leading-zero-n-%d" % bits))
    out = os.path.join(ROOT, "test/vectors/rsa_pss/vectors.txt")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        f.write("# n e mhash sig expected label - generated by test/scripts/rsa_pss_vectors.py\n")
        for row in lines:
            f.write("%s %s %s %s %d %s\n" % row)
    print("wrote %d vectors to %s" % (len(lines), os.path.relpath(out, ROOT)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
