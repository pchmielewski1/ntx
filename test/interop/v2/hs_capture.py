"""Capture the first BitTorrent handshake a dialing ntx peer sends us.

The interop harness points its throwaway HTTP tracker at this listener so the
ntx downloader (dialing a hybrid / pure-v2 magnet) connects here instead of a
real seeder. ntx speaks the PE/MSE extension (src/proto/ntx_pe.c) as initiator,
so a passive accept-and-read only ever sees ciphertext: the initiator sends its
96-byte DH public key + pad, waits for ours, then sends syncHash(20) +
skeyObf(20) + RC4(VC|crypto|padlen|pad|IAlen) and the RC4-encrypted 68-byte BT
handshake (ntx_pe.c:214-245). The reserved bits we care about live inside that
encrypted block, so the capture has to be a real MSE responder, not a sniffer.

This script therefore implements the responder side of MSE with the same
primitives ntx uses:
  * DH over the 768-bit prime, Ya = 2^xa mod P, S = Yb^xa mod P  (ntx_dh.c)
  * keystreams = SHA1("keyA"|S|IH) / SHA1("keyB"|S|IH), BEP9 1024-byte discard
                                               (src/crypto/ntx_rc4.c:41-43)
  * syncHash = SHA1("req1"|S)                  (src/proto/ntx_pe_vc.c:112-119)
Answering the DH exchange correctly is what keeps ntx's state machine alive
long enough to emit the handshake.

Locating the handshake: the initiator's first message carries a 0-511 byte DH
pad that is plaintext and does NOT consume keystream, and TCP can split that
message across reads, so the buffer offsets of VC and handshake are not
derivable from the frame layout. Rather than parse VC/padlen/IA (whose offsets
are exactly what the coalescing makes unstable), we scan: the first keystream
offset D and buffer offset V where data[V:V+20] decodes to pstrlen 19 +
"BitTorrent protocol" pins the 68-byte handshake uniquely. That is the same
"try every offset" strategy pe_find_vc_initiator (ntx_pe.c:130-178) uses, just
anchored on the BT magic instead of the 8-byte VC.

If ntx instead takes its compat plaintext path (pe_plaintext_peer, ntx_pe.c:86)
we just read the clear 68 B.

BEP52 sets the 4th-most-significant bit (0x10) of the LAST reserved byte
(m[27]) when the torrent is hybrid or v2, so the
handshake bytes are the observable for the reserved-bit cell.

Prints one line:
  HS_OK pstrlen=19 proto=BitTorrent protocol reserved=<16 hex of m[20:28]> m27=<hex> infohash=<40 hex> peerid=<40 hex>
exits 0 on a well-formed handshake, non-zero otherwise.

Usage: hs_capture.py PORT INFOHASH_HEX [timeout_seconds]
"""
import hashlib
import os
import socket
import sys
import time

MAGIC = b"BitTorrent protocol"
DH_P = 1552518092300708935130918131258481755631334049434514313202351194902966239949102107258669453876591642442910007680288864229150803718918046342632727613031282983744380820890196288509170691316593175367469551763119843371637221007211169123
DH_BYTES = 96
HANDSHAKE_LEN = 68
PAD_LEN = 64
GRACE = 6.0
DISCARD = 1024


def sha1(*chunks):
    h = hashlib.sha1()
    for c in chunks:
        h.update(c)
    return h.digest()


class Rc4:
    """RC4 with BEP9's lazy 1024-byte discard (ntx_rc4.c:28-43)."""

    def __init__(self, key):
        self.s = list(range(256))
        j = 0
        for i in range(256):
            j = (j + self.s[i] + key[i % len(key)]) & 0xff
            self.s[i], self.s[j] = self.s[j], self.s[i]
        self.i = self.j = 0
        self.dropped = False
        self.raw = b""

    def byte(self):
        self.i = (self.i + 1) & 0xff
        self.j = (self.j + self.s[self.i]) & 0xff
        self.s[self.i], self.s[self.j] = self.s[self.j], self.s[self.i]
        return self.s[(self.s[self.i] + self.s[self.j]) & 0xff]

    def keystream(self, n):
        if not self.dropped:
            for _ in range(DISCARD):
                self.byte()
            self.dropped = True
        return bytes(self.byte() for _ in range(n))

    def at(self, off, n):
        """Raw (pre-discard) keystream slice; offsets are stable and cached."""
        while len(self.raw) < off + n:
            self.raw += bytes(self.byte() for _ in range(max(256, off + n - len(self.raw))))
        return self.raw[off:off + n]


class Buf:
    """Stream buffer with a deadline-bounded fill."""

    def __init__(self, conn, deadline):
        self.conn = conn
        self.deadline = deadline
        self.data = b""

    def need(self, n, grace=None):
        """Fill to n byes.  `grace` overrides the overall deadline for this call.

        The MSE exchange legitimately stalls while the initiator waits for our DH
        reply and then for our VC, so a single global deadline would expire
        mid-handshake; callers that are waiting on a peer reaction pass a grace
        period instead."""
        stop = time.monotonic() + grace if grace is not None else self.deadline
        while len(self.data) < n:
            left = stop - time.monotonic()
            if left <= 0:
                return False
            self.conn.settimeout(left)
            try:
                chunk = self.conn.recv(65536)
            except OSError:
                return False
            if not chunk:
                return False
            self.data += chunk
        return True

    def drain(self, quiet=0.25):
        """Pull until the peer goes silent for `quiet` seconds or we time out.

        The initiator writes its first message (Ya + pad) and then blocks for
        our DH reply, and writes PE3 + the BT handshake together and then blocks
        for our VC.  A quiet period therefore marks a message boundary, which is
        the only reliable way to know a burst is complete when TCP coalesces our
        own outbound reply into the same recv() as the peer's next message."""
        while True:
            left = self.deadline - time.monotonic()
            if left <= 0:
                return
            self.conn.settimeout(min(quiet, left))
            try:
                chunk = self.conn.recv(65536)
            except OSError:
                return
            if not chunk:
                return
            self.data += chunk

    def take(self, n):
        out, self.data = self.data[:n], self.data[n:]
        return out


def is_plaintext(buf):
    """ntx_pe.c:86-92 pe_plaintext_peer, both the full and the 10-byte form."""
    if len(buf) < 4 or buf[0] != 19:
        return False
    if len(buf) >= HANDSHAKE_LEN:
        return buf[1:20] == MAGIC
    return buf[1:11] == MAGIC[:10]


def find_handshake(buf, ks):
    """Locate the encrypted BT handshake; return (bytes_to_consume, offset).

    The initiator's stream in front of the handshake is
        <DH pad of message one, plaintext, 0-511 B>
        syncHash(20) skeyObf(20)            plaintext
        RC4(VC[8] | crypto[4] | padlen[2] | pad | IAlen[2])
    and only the last group consumes keystream.  Neither the pad length nor the
    PE3 pad length is knowable up front, and TCP coalescing makes buffer offsets
    unstable, so we solve for the shift instead of parsing: for a candidate pad
    length P, a handshake at buffer offset v was keystreamed from byte (v - P)
    after BEP9's discard, and the 19 + "BitTorrent protocol" prefix pins P and v
    uniquely.  bytes_to_consume is then v - P, i.e. the run of byes that did not
    touch the cipher."""
    want = bytes([19]) + MAGIC
    hi = min(len(buf), 1600)
    for P in range(hi):
        for v in range(P, len(buf) - HANDSHAKE_LEN + 1):
            k = ks.at(v - P + DISCARD, 20)
            if buf[v] ^ k[0] != 19:
                continue
            if bytes(a ^ b for a, b in zip(buf[v:v + 20], k)) != want:
                continue
            find_handshake.keystream_off = v - P + DISCARD
            return v - P, v
    return None


def main():
    if len(sys.argv) < 3:
        return fail("usage: hs_capture.py PORT INFOHASH_HEX [timeout]")
    port = int(sys.argv[1])
    try:
        infohash = bytes.fromhex(sys.argv[2])
    except ValueError:
        return fail("bad-infohash %r" % sys.argv[2])
    if len(infohash) != 20:
        return fail("bad-infohash len=%d" % len(infohash))
    timeout = float(sys.argv[3]) if len(sys.argv) > 3 else 30.0

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(1)
    srv.settimeout(timeout)
    try:
        conn, _ = srv.accept()
    except (socket.timeout, OSError):
        return fail("accept-timeout")
    buf = Buf(conn, time.monotonic() + timeout)
    try:
        return run(conn, buf, infohash)
    finally:
        conn.close()
        srv.close()


def run(conn, buf, infohash):
    # --- message one: initiator DH public key + 0-511 B of pad ----------
    if not buf.need(DH_BYTES):
        if is_plaintext(buf.data):
            if not buf.need(HANDSHAKE_LEN, GRACE):
                return fail("short-plaintext-handshake")
            return emit(buf.take(HANDSHAKE_LEN))
        return fail("no-initiator-bytes")
    ya = buf.take(DH_BYTES)
    buf.need(DH_BYTES + 512, GRACE)         # message one is Ya + <=511 B pad

    # --- our keypair, shared secret, initiator's send keystream ----------
    xa = int.from_bytes(os.urandom(20), "big") % (DH_P - 3) + 2
    yb = pow(2, xa, DH_P)
    secret = pow(int.from_bytes(ya, "big"), xa, DH_P)
    if secret < 2 or secret > DH_P - 2:
        return fail("bad-secret")
    s = secret.to_bytes(DH_BYTES, "big")
    ks = Rc4(sha1(b"keyA", s, infohash))

    # --- our reply: Yb + a spec-sized pad.  We never receive what we send, so
    # the buffer holds only the peer's byes and nothing has to be filtered out.
    conn.sendall(yb.to_bytes(DH_BYTES, "big") + os.urandom(PAD_LEN))
    buf.drain()                             # message two lands whole

    # --- message two: syncHash + skeyObf + RC4(PE3) + RC4(handshake) ----
    want = sha1(b"req1", s)
    for _ in range(60):
        if buf.data.find(want) >= 0:
            break
        if not buf.need(len(buf.data) + 128, GRACE):
            break
    else:
        return fail("sync-hash-missing")
    if buf.data.find(want) < 0:
        if is_plaintext(buf.data):
            if not buf.need(HANDSHAKE_LEN, GRACE):
                return fail("short-plaintext-handshake")
            return emit(buf.take(HANDSHAKE_LEN))
        return fail("sync-hash-missing")
    buf.drain()                             # PE3 and the handshake are one burst

    for _ in range(80):
        hit = find_handshake(buf.data, ks)
        if hit is not None:
            off = hit[1]
            if len(buf.data) < off + HANDSHAKE_LEN:
                if not buf.need(off + HANDSHAKE_LEN, GRACE):
                    return fail("incomplete-handshake")
            enc = buf.data[off:off + HANDSHAKE_LEN]
            plain = bytes(a ^ b for a, b in
                          zip(enc, ks.at(find_handshake.keystream_off,
                                        HANDSHAKE_LEN)))
            return emit(plain)
        if not buf.need(len(buf.data) + 512, GRACE):
            break
    return fail("handshake-not-found")


def emit(hs):
    if len(hs) != HANDSHAKE_LEN:
        return fail("short-read got=%d" % len(hs))
    if hs[0] != 19 or hs[1:20] != MAGIC:
        return fail("bad-magic pstrlen=%d proto=%r"
                    % (hs[0], hs[1:20].decode("latin1")))
    reserved = hs[20:28]
    print("HS_OK pstrlen=%d proto=%s reserved=%s m27=%02x infohash=%s peerid=%s"
          % (hs[0], "BitTorrent protocol", reserved.hex(), reserved[7],
             hs[28:48].hex(), hs[48:68].hex()))
    return 0


def fail(why):
    print("HS_ERR %s" % why)
    return 3


if __name__ == "__main__":
    sys.exit(main())
