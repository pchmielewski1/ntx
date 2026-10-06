#!/usr/bin/env python3
"""Generate BEP52 interop fixtures from the golden generator."""
import os
import sys

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", ".."))
sys.path.insert(0, os.path.join(ROOT, "test", "scripts"))

import bep52_gen

def main():
    out = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "test/.scratch/9/fixtures")
    os.makedirs(out, exist_ok=True)
    bep52_gen.OUT = out
    bep52_gen.gen_single()
    bep52_gen.gen_multi()
    bep52_gen.gen_hybrid_ok()
    print("fixtures=" + out)

if __name__ == "__main__":
    main()
