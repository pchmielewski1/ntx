#!/usr/bin/env python3
"""Mint the HTTPS share-tracker key material for the private-share interop cell.

Writes into --out:

  key.pem cert.pem   P-256 self-signed certificate for the tracker endpoints
  pub.pem            its public key (the audit trail of the pin below)
  sharetest.inc      the -DNTX_SHARE_TRACKERS_INC payload for the seeder build:
                     two tracker rows whose SPKI pin is that of the certificate
                     minted right here

The pin is SHA-256 over the DER SubjectPublicKeyInfo — the same quantity
scripts/pins/pins.py records for a real share host — so the seeder build passes
ntx_share_available() AND its announce really pin-matches the server it dials.
The checked-in scripts/pins/sharetest_trackers.inc carries all-zero pins and
fails closed by design (§6.2); with it the share would announce to nothing and
the cell would have no seeder to talk to.

Two rows because NTX_SHARE_MIN_TRACKERS is 2. Both hosts are loopback LITERALS
so the seeder needs no DNS/DoH to reach them, and neither is 127.0.0.1: that
address has a hard-coded pin in ntx's built-in dev pool (ntx_https_pin.c),
which is consulted BEFORE the share table and would reject our certificate.

openssl here is harness tooling only — the shipped binary stays libc+libm.
"""
import argparse
import hashlib
import os
import subprocess
import sys


def run(cmd):
    p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if p.returncode != 0:
        sys.stderr.write(p.stderr.decode("utf-8", "replace"))
        raise SystemExit("command failed: " + " ".join(cmd))
    return p.stdout


def is_ip(h):
    parts = h.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)

def bdecode(data, i=0):
    """Minimal bencode reader (no deps) — enough to inspect a share metainfo."""
    if data[i:i + 1] == b"d":
        i += 1; out = {}
        while data[i:i + 1] != b"e":
            k, i = bdecode(data, i)
            v, i = bdecode(data, i)
            out[k] = v
        return out, i + 1
    if data[i:i + 1] == b"l":
        i += 1; out = []
        while data[i:i + 1] != b"e":
            v, i = bdecode(data, i)
            out.append(v)
        return out, i + 1
    if data[i:i + 1] == b"i":
        j = data.index(b"e", i)
        return int(data[i + 1:j]), j + 1
    j = data.index(b":", i)
    n = int(data[i:j])
    return data[j + 1:j + 1 + n], j + 1 + n

def verify_share_torrent(path):
    """Assert the metainfo is what `ntx --share` publishes: private=1, one file,
    and hybrid (BEP 52 v2 root alongside the v1 pieces), so the cell really
    exercises the private-share path and not some accidental public fixture."""
    with open(path, "rb") as f:
        meta, _ = bdecode(f.read(), 0)
    info = meta.get(b"info") or {}
    problems = []
    if info.get(b"private") != 1:
        problems.append("info.private != 1 (got %r)" % info.get(b"private"))
    if info.get(b"meta version") != 2:
        problems.append("info['meta version'] != 2 (got %r)" % info.get(b"meta version"))
    if not info.get(b"pieces"):
        problems.append("no v1 'pieces' — not a hybrid metainfo")
    files = info.get(b"files")
    length = info.get(b"length")
    if files is not None:
        problems.append("multi-file info — --share publishes single-file")
    if not isinstance(length, int) or length <= 0:
        problems.append("missing/invalid single-file info.length (got %r)" % length)
    ft = info.get(b"file tree")
    if not isinstance(ft, dict) or not ft:
        problems.append("empty info['file tree']")
    else:
        def has_root(node):
            if isinstance(node, dict):
                if b"pieces root" in node:
                    return True
                return any(has_root(v) for v in node.values())
            return False
        if not has_root(ft):
            problems.append("no v2 'pieces root' in info['file tree']")
    return (not problems), problems


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--host", default="127.0.0.2",
                    help="loopback literal of the first tracker row; never 127.0.0.1, whose "
                         "pin is hard-coded in ntx's built-in dev pool and outranks this table")
    ap.add_argument("--host2", default="127.0.0.3", help="loopback literal of the second row")
    ap.add_argument("--https-port", type=int, required=True)
    ap.add_argument("--https-port2", type=int, required=True,
                    help="second loopback port backing the second required tracker row")
    ap.add_argument("--days", type=int, default=2)
    ap.add_argument("--verify-torrent", default=None,
                    help="also assert the metainfo is private=1, single-file and hybrid "
                         "(BEP 52), i.e. what `ntx --share` publishes; non-zero exit if not")
    a = ap.parse_args()

    rows = [(a.host, a.https_port), (a.host2, a.https_port2)]
    bad = [h for h, _ in rows if not is_ip(h)]
    if bad:
        raise SystemExit("tracker hosts must be IPv4 literals (no DoH on the announce "
                         "path): " + ", ".join(bad))
    if any(h == "127.0.0.1" for h, _ in rows):
        raise SystemExit("127.0.0.1 is pinned in ntx's built-in dev pool; pick another "
                         "loopback literal")

    os.makedirs(a.out, exist_ok=True)
    key = os.path.join(a.out, "key.pem")
    cert = os.path.join(a.out, "cert.pem")
    pub = os.path.join(a.out, "pub.pem")
    inc = os.path.join(a.out, "sharetest.inc")
    for f in (key, cert, pub, inc):
        if os.path.exists(f):
            os.unlink(f)

    sans = ",".join("IP:%s" % h for h, _ in rows)
    run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
         "-pkeyopt", "ec_param_enc:named_curve", "-sha256", "-days", str(a.days), "-nodes",
         "-keyout", key, "-out", cert, "-subj", "/CN=%s" % a.host,
         "-addext", "subjectAltName=" + sans])

    with open(pub, "wb") as f:
        f.write(run(["openssl", "x509", "-in", cert, "-pubkey", "-noout"]))
    der = run(["openssl", "pkey", "-pubin", "-in", pub, "-outform", "DER"])
    spki = hashlib.sha256(der).hexdigest()
    if len(spki) != 64:
        raise SystemExit("unexpected SPKI digest length: %d" % len(spki))

    urls = [("https://%s:%d/announce" % (h, p), h) for h, p in rows]
    with open(inc, "w") as f:
        f.write("/* Generated by test/interop/v2/share_cert.py — private-share interop "
                "cell only. */\n")
        f.write("static const strk_raw strk_raw_tab[] = {\n")
        for url, host in urls:
            f.write('    {"%s", "%s",\n     {"%s", 0, 0, 0}},\n' % (url, host, spki))
        f.write("};\n")
        # <stdio.h> belongs to the included file: ntx_share_trackers.c does not
        # pull it in and the banner below needs fputs/stderr, exactly like
        # scripts/pins/sharetest_trackers.inc.
        f.write("#include <stdio.h>\n")
        f.write("__attribute__((constructor)) static void strk_test_banner(void) {\n")
        f.write('    fputs("NTX-TEST-TRACKERS: private-share interop build\\n", stderr);\n')
        f.write("}\n")

    print("cert=%s" % cert)
    print("key=%s" % key)
    print("inc=%s" % inc)
    print("urls=%s" % ",".join(u for u, _ in urls))
    print("spki=%s" % spki)

    if a.verify_torrent:
        ok, problems = verify_share_torrent(a.verify_torrent)
        for p in problems:
            print("VERIFY-FAIL %s" % p)
        print("verify_torrent=%s %s" % ("ok" if ok else "fail", a.verify_torrent))
        if not ok:
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
