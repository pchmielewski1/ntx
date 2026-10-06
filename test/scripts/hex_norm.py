#!/usr/bin/env python3
"""hex_norm.py — hex normalisation: strip whitespace/commas, lowercase.

Usage:
  hex_norm.py [--expect N] [FILE]
    --expect N   expected length in BYTES; exit 1 otherwise
    FILE         input file (default: stdin)
stdout: plain hex (lowercase, no whitespace)
"""
import re
import sys


def normalize(raw: str) -> str:
    return re.sub(r"[\s,]+", "", raw.lower())


def main() -> int:
    args = sys.argv[1:]
    expect = None
    src = None
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--expect":
            if i + 1 >= len(args):
                print("ERROR: --expect requires a value", file=sys.stderr)
                return 2
            try:
                expect = int(args[i + 1])
            except ValueError:
                print(f"ERROR: --expect value not an int: {args[i + 1]}", file=sys.stderr)
                return 2
            i += 2
        elif a.startswith("--expect="):
            try:
                expect = int(a.split("=", 1)[1])
            except ValueError:
                print(f"ERROR: --expect value not an int: {a}", file=sys.stderr)
                return 2
            i += 1
        elif src is None:
            src = a
            i += 1
        else:
            print(f"ERROR: unexpected argument: {a}", file=sys.stderr)
            return 2

    if src is not None:
        try:
            with open(src, "r") as f:
                raw = f.read()
        except OSError as e:
            print(f"ERROR: cannot read {src}: {e}", file=sys.stderr)
            return 1
    else:
        raw = sys.stdin.read()

    hexstr = normalize(raw)
    if not re.fullmatch(r"[0-9a-f]*", hexstr):
        print("ERROR: input contains non-hex characters", file=sys.stderr)
        return 1
    if expect is not None and len(hexstr) != 2 * expect:
        print(
            f"ERROR: expected {expect} bytes ({2 * expect} hex chars), "
            f"got {len(hexstr)} hex chars ({len(hexstr) // 2} bytes)",
            file=sys.stderr,
        )
        return 1
    sys.stdout.write(hexstr + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
