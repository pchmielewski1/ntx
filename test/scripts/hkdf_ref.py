#!/usr/bin/env python3
"""hkdf_ref.py — reference HKDF (RFC 5869, HMAC-SHA256).

(TLS 1.3 key schedule / Hkdf-Expand-Label: test/scripts/tls13_ref.py.)

Subcommands:
  --case 1 --extract            RFC 5869 test case 1 → PRK (asserted against the RFC)
  --case 1 --expand             RFC 5869 test case 1 → OKM (asserted against the RFC)
  --hkdf5869 --ikm HEX --salt HEX --info HEX --len N
                                generic extract+expand → OKM hex

Exit: 0 ok; 1 bad data; 2 usage error / vector assert.
"""
import argparse
import hashlib
import hmac
import sys

# RFC 5869 test case 1 vectors (SHA-256) — Appendix A.1.
# source: RFC 5869 A.1 (rfc-editor.org, verified 2026-08-29).
# NOTE: the vectors below are the genuine RFC 5869 A.1 ones; some secondary
# write-ups carry mangled PRK/OKM values (an OKM of 64 B instead of 42 B,
# not matching RFC 5869), so this script asserts against RFC 5869 A.1 itself.
TC1_IKM = "0b" * 22  # 22 octets 0x0b (RFC 5869 A.1)
TC1_SALT = "000102030405060708090a0b0c"
TC1_INFO = "f0f1f2f3f4f5f6f7f8f9"
TC1_L = 42
TC1_PRK = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
TC1_OKM = (
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)

def unhex(s: str, what: str) -> bytes:
    try:
        return bytes.fromhex(s)
    except ValueError:
        print(f"ERROR: bad hex for {what}: {s!r}", file=sys.stderr)
        sys.exit(1)


def hkdf_extract(salt: bytes, ikm: bytes) -> bytes:
    if not salt:
        salt = b"\x00" * 32
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    hash_len = 32
    if length < 0 or length > 255 * hash_len:
        raise ValueError("expand length out of range")
    if not prk:
        raise ValueError("PRK empty")
    t = b""
    prev = b""
    counter = 1
    while len(t) < length:
        prev = hmac.new(prk, prev + info + bytes([counter]), hashlib.sha256).digest()
        t += prev
        counter += 1
    return t[:length]


def die_assert(got: str, want: str, what: str) -> None:
    print(f"ASSERT FAIL ({what}): computed {got} != vector {want}", file=sys.stderr)
    sys.exit(2)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--case", choices=["1"], help="RFC 5869 test case")
    p.add_argument("--extract", action="store_true", help="with --case 1: print the PRK")
    p.add_argument("--expand", action="store_true", help="with --case 1: print the OKM")
    p.add_argument("--hkdf5869", action="store_true", help="generic extract+expand")
    p.add_argument("--ikm", help="hex IKM (--hkdf5869)")
    p.add_argument("--salt", default="", help="hex salt (--hkdf5869; empty = zeros)")
    p.add_argument("--info", default="", help="hex info (--hkdf5869)")
    p.add_argument("--len", dest="outlen", type=int, help="OKM length in bytes (--hkdf5869)")
    args = p.parse_args()

    if args.case == "1":
        if args.extract == args.expand:
            print("usage: --case 1 requires exactly one of: --extract / --expand", file=sys.stderr)
            return 2
        prk = hkdf_extract(unhex(TC1_SALT, "salt"), unhex(TC1_IKM, "ikm"))
        if args.extract:
            if prk.hex() != TC1_PRK:
                die_assert(prk.hex(), TC1_PRK, "RFC5869 TC1 PRK")
            sys.stdout.write(prk.hex() + "\n")
            return 0
        okm = hkdf_expand(prk, unhex(TC1_INFO, "info"), TC1_L)
        if okm.hex() != TC1_OKM:
            die_assert(okm.hex(), TC1_OKM, "RFC5869 TC1 OKM")
        sys.stdout.write(okm.hex() + "\n")
        return 0

    if args.hkdf5869:
        if not args.ikm or args.outlen is None:
            print("usage: --hkdf5869 --ikm HEX --salt HEX --info HEX --len N", file=sys.stderr)
            return 2
        prk = hkdf_extract(unhex(args.salt, "salt"), unhex(args.ikm, "ikm"))
        okm = hkdf_expand(prk, unhex(args.info, "info"), args.outlen)
        sys.stdout.write(okm.hex() + "\n")
        return 0

    p.print_usage(sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main())
