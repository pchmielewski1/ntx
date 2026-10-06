#!/usr/bin/env python3
"""hex_cmp.py A B — compare two hex sources (a file or a hex string argument).

Usage:
  hex_cmp.py A B
    A, B: path to a hex file OR a raw hex string
stdout: HEX MATCH (exit 0) / HEX MISMATCH (A vs B) (exit 1)
"""
import os
import re
import sys


def normalize(raw: str) -> str:
    return re.sub(r"[\s,]+", "", raw.lower())


def read_hex(arg: str) -> str:
    if os.path.isfile(arg):
        with open(arg, "r") as f:
            return normalize(f.read())
    return normalize(arg)


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: hex_cmp.py A B", file=sys.stderr)
        return 2
    a = read_hex(sys.argv[1])
    b = read_hex(sys.argv[2])
    if not re.fullmatch(r"[0-9a-f]*", a) or not re.fullmatch(r"[0-9a-f]*", b):
        print("ERROR: input contains non-hex characters", file=sys.stderr)
        return 1
    if a == b:
        print("HEX MATCH")
        return 0
    print("HEX MISMATCH (A vs B)")
    print(f"  A: {len(a)} hex chars ({len(a) // 2} bytes)", file=sys.stderr)
    print(f"  B: {len(b)} hex chars ({len(b) // 2} bytes)", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
