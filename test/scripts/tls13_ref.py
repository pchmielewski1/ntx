#!/usr/bin/env python3
"""tls13_ref.py - independent TLS 1.3 (RFC 8446) reference for the ntx client.

Written separately from src/net/ntx_tls13.c (different language, different
structure, the `cryptography` package for X25519 / AES-GCM / ECDSA / RSA-PSS)
so that the two cannot share a bug. It produces:

  test/vectors/tls13/kat.txt        key=hex lines: key schedule, Expand-Label,
                                    record protection, handshake messages
                                    (consumed by test/t_tls13.c)
  test/fixtures/tls/<name>.bin      the byte stream a server sends
  test/fixtures/tls/<name>.meta.json   expected client behaviour
                                    (consumed by test/t_tls_golden.c)

Run from anywhere:  python3 test/scripts/tls13_ref.py
Requires: python3, `cryptography` (generator only; the tests need nothing).
The self-checks at the start pin the key schedule to values from RFC 8448.
"""
import hashlib
import hmac
import json
import os
import struct

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography import x509

ROOT = os.path.normpath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
VEC = os.path.join(ROOT, "test", "vectors", "tls13")
FIX = os.path.join(ROOT, "test", "fixtures", "tls")


def sha256(b):
    return hashlib.sha256(b).digest()


def hmac256(k, m):
    return hmac.new(k, m, hashlib.sha256).digest()


# ---- HKDF (RFC 5869) and the TLS 1.3 key schedule (RFC 8446 7.1) ------------

def hkdf_extract(salt, ikm):
    return hmac256(salt if salt else b"\x00" * 32, ikm)


def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac256(prk, t + info + bytes([i]))
        out += t
        i += 1
    return out[:n]


def expand_label(secret, label, ctx, n):
    full = b"tls13 " + label.encode()
    info = struct.pack(">H", n) + bytes([len(full)]) + full + bytes([len(ctx)]) + ctx
    return hkdf_expand(secret, info, n)


def derive_secret(secret, label, th):
    return expand_label(secret, label, th, 32)


def traffic_keys(secret):
    return expand_label(secret, "key", b"", 16), expand_label(secret, "iv", b"", 12)


EMPTY = sha256(b"")
ZEROS = b"\x00" * 32


def selfcheck():
    """Anchor the schedule to RFC 8448 (section 3, simple 1-RTT handshake)."""
    early = hkdf_extract(b"", ZEROS)
    assert early.hex() == "33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a", early.hex()
    derived = derive_secret(early, "derived", EMPTY)
    assert derived.hex() == "6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba", derived.hex()


# ---- record protection (RFC 8446 5.2) ----------------------------------------

class Dir:
    def __init__(self, secret):
        self.secret = secret
        self.key, self.iv = traffic_keys(secret)
        self.seq = 0

    def nonce(self):
        s = self.seq.to_bytes(12, "big")
        return bytes(a ^ b for a, b in zip(self.iv, s))

    def seal(self, inner_type, content, pad=0):
        inner = content + bytes([inner_type]) + b"\x00" * pad
        hdr = bytes([23, 3, 3]) + struct.pack(">H", len(inner) + 16)
        ct = AESGCM(self.key).encrypt(self.nonce(), inner, hdr)
        self.seq += 1
        return hdr + ct

    def update(self):
        self.__init__(expand_label(self.secret, "traffic upd", b"", 32))


def plain_record(typ, body):
    return bytes([typ, 3, 3]) + struct.pack(">H", len(body)) + body


# ---- handshake messages -------------------------------------------------------

def hs(typ, body):
    return bytes([typ]) + len(body).to_bytes(3, "big") + body


def ext(typ, data):
    return struct.pack(">HH", typ, len(data)) + data


def client_hello(sni, cr, sid, pub, alpn):
    exts = b""
    if sni:
        name = sni.encode()
        exts += ext(0, struct.pack(">HBH", len(name) + 3, 0, len(name)) + name)
    exts += ext(10, struct.pack(">HH", 2, 0x001D))
    exts += ext(13, struct.pack(">HHH", 4, 0x0403, 0x0804))
    exts += ext(43, bytes([2]) + struct.pack(">H", 0x0304))
    exts += ext(51, struct.pack(">HHH", 36, 0x001D, 32) + pub)
    if alpn:
        names = b"".join(bytes([len(a)]) + a.encode() for a in alpn)
        exts += ext(16, struct.pack(">H", len(names)) + names)
    body = (struct.pack(">H", 0x0303) + cr + bytes([32]) + sid + struct.pack(">HH", 2, 0x1301)
            + bytes([1, 0]) + struct.pack(">H", len(exts)) + exts)
    return hs(1, body)


def server_hello(srandom, sid, pub, cipher=0x1301, ks_group=0x001D):
    exts = ext(43, struct.pack(">H", 0x0304)) + ext(51, struct.pack(">HH", ks_group, 32) + pub)
    body = (struct.pack(">H", 0x0303) + srandom + bytes([len(sid)]) + sid + struct.pack(">H", cipher)
            + bytes([0]) + struct.pack(">H", len(exts)) + exts)
    return hs(2, body)


def encrypted_extensions(alpn):
    exts = b""
    if alpn:
        exts += ext(16, struct.pack(">HB", len(alpn) + 1, len(alpn)) + alpn.encode())
    return hs(8, struct.pack(">H", len(exts)) + exts)


def certificate(der, ctx=b"", extra_ext=b""):
    entry = len(der).to_bytes(3, "big") + der + struct.pack(">H", len(extra_ext)) + extra_ext
    lst = len(entry).to_bytes(3, "big") + entry
    return hs(11, bytes([len(ctx)]) + ctx + lst)


def cv_content(th):
    return b"\x20" * 64 + b"TLS 1.3, server CertificateVerify" + b"\x00" + th


def certificate_verify(key, th, sigalg=None):
    if isinstance(key, ec.EllipticCurvePrivateKey):
        sig = key.sign(cv_content(th), ec.ECDSA(hashes.SHA256()))
        alg = 0x0403
    else:
        sig = key.sign(cv_content(th), padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32),
                       hashes.SHA256())
        alg = 0x0804
    if sigalg is not None:
        alg = sigalg
    return hs(15, struct.pack(">HH", alg, len(sig)) + sig)


def finished(base_secret, th):
    fk = expand_label(base_secret, "finished", b"", 32)
    return hs(20, hmac256(fk, th))


# ---- one complete handshake ---------------------------------------------------

def load_keys():
    ek = serialization.load_pem_private_key(open(os.path.join(VEC, "key_p256.pem"), "rb").read(), None)
    rk = serialization.load_pem_private_key(open(os.path.join(VEC, "key_rsa.pem"), "rb").read(), None)
    ed = open(os.path.join(VEC, "leaf_p256.der"), "rb").read()
    rd = open(os.path.join(VEC, "leaf_rsa.der"), "rb").read()
    return ek, ed, rk, rd


def spki_pin(der):
    cert = x509.load_der_x509_certificate(der)
    spki = cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return sha256(spki)


CLIENT_PRIV = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")  # RFC 7748 alice
SERVER_PRIV = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")  # RFC 7748 bob
CR = bytes(range(1, 33))
SNI = "tls13-mock"


def x25519_pub(priv):
    return X25519PrivateKey.from_private_bytes(priv).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def x25519_shared(priv, peer_pub):
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
    return X25519PrivateKey.from_private_bytes(priv).exchange(X25519PublicKey.from_public_bytes(peer_pub))


class Session:
    """Builds the server side of one handshake plus everything the tests need."""

    def __init__(self, key, der, alpn_server="http/1.1", alpn_client="http/1.1"):
        self.key, self.der = key, der
        self.sid = sha256(CR)
        self.cpub = x25519_pub(CLIENT_PRIV)
        self.spub = x25519_pub(SERVER_PRIV)
        self.ch = client_hello(SNI, CR, self.sid, self.cpub, [alpn_client] if alpn_client else [])
        self.sh = server_hello(bytes([0xA0 + i for i in range(32)]), self.sid, self.spub)
        self.shared = x25519_shared(SERVER_PRIV, self.cpub)
        assert self.shared == x25519_shared(CLIENT_PRIV, self.spub)
        self.alpn_server = alpn_server
        self.finish_schedule()

    def finish_schedule(self):
        self.h_sh = sha256(self.ch + self.sh)
        self.early = hkdf_extract(b"", ZEROS)
        self.derived1 = derive_secret(self.early, "derived", EMPTY)
        self.hs_secret = hkdf_extract(self.derived1, self.shared)
        self.c_hs = derive_secret(self.hs_secret, "c hs traffic", self.h_sh)
        self.s_hs = derive_secret(self.hs_secret, "s hs traffic", self.h_sh)

    def flight(self, cert_ctx=b"", sigalg=None, ee=None, extra=b"", corrupt_cv=False, corrupt_fin=False):
        """Return list of server handshake messages and the transcript pieces."""
        ee = ee if ee is not None else encrypted_extensions(self.alpn_server)
        msgs = [ee]
        if extra:
            msgs.append(extra)
        cert = certificate(self.der, ctx=cert_ctx)
        msgs.append(cert)
        t = self.ch + self.sh + b"".join(msgs)
        cv = bytearray(certificate_verify(self.key, sha256(t), sigalg))
        if corrupt_cv:
            cv[-1] ^= 1
        cv = bytes(cv)
        msgs.append(cv)
        t += cv
        fin = bytearray(finished(self.s_hs, sha256(t)))
        if corrupt_fin:
            fin[-1] ^= 1
        fin = bytes(fin)
        msgs.append(fin)
        t += fin
        self.h_sfin = sha256(t)
        # application secrets use the transcript through the (uncorrupted) server Finished
        self.derived2 = derive_secret(self.hs_secret, "derived", EMPTY)
        self.master = hkdf_extract(self.derived2, ZEROS)
        self.c_ap = derive_secret(self.master, "c ap traffic", self.h_sfin)
        self.s_ap = derive_secret(self.master, "s ap traffic", self.h_sfin)
        return msgs

    def client_finished_flight(self):
        """CCS + protected client Finished exactly as the client must send them."""
        cfin = finished(self.c_hs, self.h_sfin)
        rec = Dir(self.c_hs).seal(22, cfin)
        return bytes([20, 3, 3, 0, 1, 1]) + rec, cfin


def build_fixture(name, s, mode="ok", pin=None, coalesce=False, fragment=0, padding_bytes=0):
    """mode: ok | bad_finished | bad_cv | bad_tag | cert_request | ctx | sigalg | pin_fail."""
    kw = {}
    if mode == "bad_finished":
        kw["corrupt_fin"] = True
    if mode == "bad_cv":
        kw["corrupt_cv"] = True
    if mode == "ctx":
        kw["cert_ctx"] = b"\x01"
    if mode == "sigalg":
        kw["sigalg"] = 0x0806  # rsa_pkcs1_sha256: never offered
    if mode == "cert_request":
        kw["extra"] = hs(13, b"\x00" + struct.pack(">H", 0))
    msgs = s.flight(**kw)
    stream = plain_record(22, s.sh) + bytes([20, 3, 3, 0, 1, 1])
    d = Dir(s.s_hs)
    if coalesce:
        stream += d.seal(22, b"".join(msgs))
    elif fragment:
        blob = b"".join(msgs)
        for i in range(0, len(blob), fragment):
            stream += d.seal(22, blob[i:i + fragment])
    else:
        for i, m in enumerate(msgs):
            r = d.seal(22, m)
            if mode == "bad_tag" and i == 0:
                r = r[:-1] + bytes([r[-1] ^ 1])
            stream += r
    # post-handshake traffic: NewSessionTicket, KeyUpdate(not requested), then data under new keys
    app = Dir(s.s_ap)
    nst = hs(4, struct.pack(">IIB", 7200, 0x01020304, 4) + b"nonc" + struct.pack(">H", 8) + b"ticket!!" + struct.pack(">H", 0))
    stream += app.seal(22, nst)
    stream += app.seal(22, hs(24, b"\x00"))
    app.update()
    payload = b"NTX13-APP-OK-PADDED!"
    stream += app.seal(23, payload, pad=padding_bytes)
    # alert close_notify at the end
    stream += app.seal(21, bytes([1, 0]))

    cflight, cfin = s.client_finished_flight()
    pins_ok = spki_pin(s.der)
    expected = {"outcome": {"ok": "ok", "pin_fail": "pin-fail"}.get(mode, "fail")}
    if mode in ("ok", "pin_fail"):
        expected.update({
            "tls_version": 13,
            "alpn": s.alpn_server or "",
            "spki_sha256_hex": (pins_ok if mode == "ok" else sha256(b"wrong pin")).hex(),
            "c_ap_secret_hex": s.c_ap.hex(),
            "s_ap_secret_hex": s.s_ap.hex(),
            "client_flight_hex": cflight.hex(),
            "app_data_hex": payload.hex(),
        })
        if mode == "pin_fail":
            expected.pop("c_ap_secret_hex"), expected.pop("s_ap_secret_hex")
            expected.pop("client_flight_hex"), expected.pop("app_data_hex")
    meta = {
        "name": name,
        "source": "test/scripts/tls13_ref.py (independent Python reference; RFC 8446)",
        "date": "2026-10-05",
        "scrub_notes": "No PII: synthetic SNI 'tls13-mock', RFC 7748 test keys, self-signed fixture cert.",
        "client": {
            "sni": SNI,
            "alpn": "http/1.1" if s.alpn_server is not None else "",
            "client_priv_hex": CLIENT_PRIV.hex(),
            "client_random_hex": CR.hex(),
            "ch_sha256_hex": sha256(s.ch).hex(),
        },
        "expected": expected,
    }
    open(os.path.join(FIX, name + ".bin"), "wb").write(stream)
    with open(os.path.join(FIX, name + ".meta.json"), "w") as f:
        json.dump(meta, f, indent=2)
        f.write("\n")


def kat(lines, name, val):
    if isinstance(val, bytes):
        val = val.hex()
    lines.append(f"{name}={val}")


def write_kat():
    ek, ed, rk, rd = load_keys()
    s = Session(ek, ed)
    msgs = s.flight()
    L = []
    L.append("# generated by test/scripts/tls13_ref.py - do not edit")
    # key schedule
    kat(L, "ecdhe", s.shared)
    kat(L, "h_ch_sh", s.h_sh)
    kat(L, "early_secret", s.early)
    kat(L, "derived1", s.derived1)
    kat(L, "hs_secret", s.hs_secret)
    kat(L, "c_hs", s.c_hs)
    kat(L, "s_hs", s.s_hs)
    k, iv = traffic_keys(s.c_hs)
    kat(L, "c_hs_key", k), kat(L, "c_hs_iv", iv)
    k, iv = traffic_keys(s.s_hs)
    kat(L, "s_hs_key", k), kat(L, "s_hs_iv", iv)
    kat(L, "h_sfin", s.h_sfin)
    kat(L, "derived2", s.derived2)
    kat(L, "master", s.master)
    kat(L, "c_ap", s.c_ap)
    kat(L, "s_ap", s.s_ap)
    k, iv = traffic_keys(s.s_ap)
    kat(L, "s_ap_key", k), kat(L, "s_ap_iv", iv)
    d = Dir(s.s_ap)
    d.update()
    kat(L, "s_ap_next", d.secret)
    # Hkdf-Expand-Label with assorted lengths / contexts
    sec = sha256(b"expand-label-secret")
    for i, (lab, ctx, n) in enumerate([("key", b"", 16), ("iv", b"", 12), ("finished", b"", 32),
                                       ("test", b"\x01\x02\x03", 7), ("longer label for test", sha256(b"c"), 48)]):
        kat(L, f"el{i}_label", lab)
        kat(L, f"el{i}_ctx", ctx)
        kat(L, f"el{i}_len", str(n))
        kat(L, f"el{i}_out", expand_label(sec, lab, ctx, n))
    kat(L, "el_secret", sec)
    # Finished
    th = sha256(b"finished-transcript")
    kat(L, "fin_base", s.s_hs), kat(L, "fin_th", th), kat(L, "fin_msg", finished(s.s_hs, th))
    # handshake messages
    kat(L, "sid", s.sid), kat(L, "cr", CR), kat(L, "cpub", s.cpub), kat(L, "spub", s.spub)
    kat(L, "ch_alpn", s.ch)
    kat(L, "ch_noalpn", client_hello(SNI, CR, s.sid, s.cpub, []))
    kat(L, "ch_nosni", client_hello(None, CR, s.sid, s.cpub, ["h2", "http/1.1"]))
    kat(L, "sh", s.sh)
    kat(L, "ee_alpn", msgs[0]), kat(L, "ee_none", encrypted_extensions(None))
    kat(L, "cert_ec", msgs[1])
    kat(L, "cv_ec", msgs[2])
    kat(L, "fin_srv", msgs[3])
    kat(L, "th_cert_ec", sha256(s.ch + s.sh + msgs[0] + msgs[1]))
    kat(L, "leaf_ec_der", ed)
    kat(L, "leaf_ec_pin", spki_pin(ed))
    sr = Session(rk, rd)
    mr = sr.flight()
    kat(L, "cert_rsa", mr[1])
    kat(L, "cv_rsa", mr[2])
    kat(L, "th_cert_rsa", sha256(sr.ch + sr.sh + mr[0] + mr[1]))
    kat(L, "leaf_rsa_der", rd)
    kat(L, "leaf_rsa_pin", spki_pin(rd))
    # records: seal vectors with explicit sequence numbers and padding
    sec = sha256(b"record-secret")
    kat(L, "rec_secret", sec)
    for i, (typ, pt, pad, seq) in enumerate([(23, b"hello", 0, 0), (22, b"\x00" * 40, 0, 1), (23, b"x" * 300, 0, 0x0102030405),
                                              (21, bytes([1, 0]), 0, 7), (23, b"padded", 9, 3), (23, b"", 0, 2)]):
        dd = Dir(sec)
        dd.seq = seq
        kat(L, f"rec{i}_type", str(typ)), kat(L, f"rec{i}_pt", pt), kat(L, f"rec{i}_pad", str(pad))
        kat(L, f"rec{i}_seq", str(seq)), kat(L, f"rec{i}_out", dd.seal(typ, pt, pad))
    open(os.path.join(VEC, "kat.txt"), "w").write("\n".join(L) + "\n")


def main():
    selfcheck()
    os.makedirs(FIX, exist_ok=True)
    for f in os.listdir(FIX):
        os.remove(os.path.join(FIX, f))
    ek, ed, rk, rd = load_keys()
    write_kat()
    build_fixture("tls13_ecdsa_ok", Session(ek, ed))
    build_fixture("tls13_rsa_pss_ok", Session(rk, rd), padding_bytes=11)
    build_fixture("tls13_ecdsa_coalesced", Session(ek, ed), coalesce=True)
    build_fixture("tls13_rsa_fragmented", Session(rk, rd), fragment=97)
    build_fixture("tls13_no_alpn", Session(ek, ed, alpn_server=None, alpn_client=None))
    build_fixture("tls13_pin_mismatch", Session(ek, ed), mode="pin_fail")
    build_fixture("tls13_bad_finished", Session(ek, ed), mode="bad_finished")
    build_fixture("tls13_bad_certverify", Session(rk, rd), mode="bad_cv")
    build_fixture("tls13_bad_record_tag", Session(ek, ed), mode="bad_tag")
    build_fixture("tls13_certificate_request", Session(ek, ed), mode="cert_request")
    build_fixture("tls13_cert_context", Session(ek, ed), mode="ctx")
    build_fixture("tls13_unoffered_sigalg", Session(rk, rd), mode="sigalg")
    print("OK: kat.txt + %d fixtures" % (len(os.listdir(FIX)) // 2))


if __name__ == "__main__":
    main()
