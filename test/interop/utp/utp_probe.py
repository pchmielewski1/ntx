#!/usr/bin/env python3
"""Raw BEP29 uTP packet-level probe (test harness, NOT the SUT).

Self-contained uTP v1 implementation (header / types / SACK / SYN / FIN / RESET)
written from BEP 29 only.
It is deliberately independent of ntx_utp*.c so that a wire-level disagreement
between this probe and the SUT is evidence, not a shared bug.

Modes (first argv):
  syn-probe   <ip> <port> <secs>   send ST_SYN, wait for the ST_STATE reply.
                                   prints SYN_OK / SYN_TIMEOUT + hex of the reply.
  reset-probe <ip> <port> <secs>   open a conn (SYN/STATE), then send ST_RESET,
                                   then re-SYN: a healthy acceptor must answer
                                   the second SYN too (no stale half-state).
  data-sack   <ip> <port> <secs>   open a conn, push DATA, read the stream back;
                                   if the peer sends a SACK extension we record
                                   it. Prints DATA_OK/DATA_TIMEOUT + byte counts.
  fin-probe   <ip> <port> <secs>   open, send DATA then ST_FIN; observe the peer
                                   draining then its own ST_FIN (clean close).

Every mode prints a `bytes_out=<n> bytes_in=<n>` line so the shell harness can
assert bytes-out == bytes-in for the lossless cells.
"""
import os
import random
import signal
import socket
import struct
import sys
import time

# ---- BEP29 header (20 B, network byte order; type high nibble, ver low) ----
HDR_LEN = 20
VER = 1
ST_DATA, ST_FIN, ST_STATE, ST_RESET, ST_SYN = 0, 1, 2, 3, 4
EXT_SACK = 1


def pack_hdr(type_, ext, conn_id, ts_us, ts_diff_us, wnd, seq, ack):
    return struct.pack('>BBHIIIHH', (type_ << 4) | VER, ext, conn_id & 0xFFFF,
                        ts_us & 0xFFFFFFFF, ts_diff_us & 0xFFFFFFFF,
                        wnd & 0xFFFFFFFF, seq & 0xFFFF, ack & 0xFFFF)


def unpack_hdr(b):
    if len(b) < HDR_LEN:
        return None
    b0, ext, conn, ts, tsd, wnd, seq, ack = struct.unpack('>BBHIIIHH', b[:HDR_LEN])
    return dict(type=b0 >> 4, ver=b0 & 0xF, ext=ext, conn_id=conn, ts_us=ts,
                ts_diff_us=tsd, wnd=wnd, seq=seq, ack=ack, raw=b)


def parse_sack(payload, ack_nr):
    """Return list of acked seqs encoded in the SACK mask (first bit = ack+2)."""
    if len(payload) < 2:
        return []
    ext, ln = payload[0], payload[1]
    if ext != EXT_SACK or ln == 0 or 2 + ln > len(payload):
        return []
    mask = list(payload[2:2 + ln])
    out = []
    for i, byte in enumerate(mask):
        for bit in range(8):  # LSB = lower seq within each byte
            if byte & (1 << bit):
                out.append((ack_nr + 2 + i * 8 + bit) & 0xFFFF)
    return out


class Peer:
    def __init__(self, ip, port, seed_seq=None):
        self.ip, self.port = ip, port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.settimeout(0.25)
        self.conn_recv = random.randrange(1, 0xFFFF)
        self.conn_send = (self.conn_recv + 1) & 0xFFFF
        self.seq = seed_seq if seed_seq is not None else 1
        self.ack = 0
        self.rx = bytearray()
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.sack_seen = []
        self.rtt_us = 0

    def send(self, pkt):
        self.tx_bytes += self.s.sendto(pkt, (self.ip, self.port))

    def now_us(self):
        return int(time.monotonic() * 1e6) & 0xFFFFFFFF

    def recv_one(self):
        try:
            data, _ = self.s.recvfrom(65535)
        except socket.timeout:
            return None
        self.rx_bytes += len(data)
        return unpack_hdr(data)

    def handshake(self, secs=3.0):
        """Initiator: SYN (retransmitted per BEP29 §6 initial 1000ms, here 250ms
        so loss cells converge) -> expect ST_STATE. 0 ok / 1 timeout."""
        deadline = time.monotonic() + secs
        last_syn = 0.0
        while time.monotonic() < deadline:
            if time.monotonic() - last_syn >= 0.25:
                syn = pack_hdr(ST_SYN, 0, self.conn_recv, self.now_us(), 0,
                               0, self.seq, 0)
                self.send(syn)
                last_syn = time.monotonic()
            h = self.recv_one()
            if not h or h['ver'] != VER:
                continue
            if h['type'] == ST_STATE:
                self.ack = h['seq']
                self.seq = (self.seq + 1) & 0xFFFF  # SYN consumed seq_nr=1
                return 0
            if h['type'] == ST_RESET:
                return 2
        return 1

    def state(self):
        self.send(pack_hdr(ST_STATE, 0, self.conn_send, self.now_us(), 0,
                           0x10000, 0, self.ack))

    def data(self, payload):
        self.send(pack_hdr(ST_DATA, 0, self.conn_send, self.now_us(), 0,
                           0x10000, self.seq, self.ack) + payload)
        self.seq = (self.seq + 1) & 0xFFFF

    def reliable_data(self, payload, secs=3.0):
        """Send DATA, retransmitting (same seq, BEP29 §5) until the peer acks it
        (ST_STATE with ack == our seq). 0 acked / 1 timeout."""
        seq = self.seq
        deadline = time.monotonic() + secs
        last = 0.0
        while time.monotonic() < deadline:
            if time.monotonic() - last >= 0.25:
                self.send(pack_hdr(ST_DATA, 0, self.conn_send, self.now_us(), 0,
                                   0x10000, seq, self.ack) + payload)
                last = time.monotonic()
            h = self.recv_one()
            if not h or h['ver'] != VER:
                continue
            if h['type'] == ST_STATE and h['ack'] == seq:
                self.ack = seq
                self.seq = (seq + 1) & 0xFFFF
                return 0
            if h['type'] == ST_RESET:
                return 2
        self.seq = (seq + 1) & 0xFFFF
        return 1

    def fin(self):
        self.send(pack_hdr(ST_FIN, 0, self.conn_send, self.now_us(), 0,
                           0, self.seq, self.ack))
        self.seq = (self.seq + 1) & 0xFFFF

    def reset(self):
        self.send(pack_hdr(ST_RESET, 0, self.conn_send, self.now_us(), 0,
                           0, self.seq, self.ack))

    def pump(self, secs, want=0):
        """Read DATA until `want` bytes or timeout; ack each DATA."""
        deadline = time.monotonic() + secs
        while time.monotonic() < deadline and len(self.rx) < want:
            h = self.recv_one()
            if not h or h['ver'] != VER:
                continue
            if h['type'] == ST_DATA:
                body = bytes(h['raw'])[HDR_LEN:]
                if h['ext']:
                    # skip extension chain to the payload (BEP29 §3)
                    p = body
                    while len(p) >= 2:
                        et, el = p[0], p[1]
                        if et == 0:
                            p = p[2:]
                            break
                        if et == EXT_SACK:
                            self.sack_seen += parse_sack(p, h['ack'])
                        if 2 + el > len(p):
                            p = b''
                            break
                        p = p[2 + el:]
                    body = p
                if h['seq'] == (self.ack + 1) & 0xFFFF:
                    self.rx += body
                self.ack = h['seq']
                self.state()
            elif h['type'] == ST_FIN:
                self.ack = h['seq']
                self.state()
                return 0
            elif h['type'] == ST_RESET:
                return 2
        return 0

    def report(self, tag):
        print(f'{tag} bytes_out={self.tx_bytes} bytes_in={self.rx_bytes}')


class Acceptor:
    """Raw uTP acceptor: bind a UDP port, answer one inbound ST_SYN with the
    ST_STATE, then keep the stream open (ack each DATA) so the SUT's initiator
    path (SYN -> STATE -> first ST_DATA carrying the BT handshake) is exercised
    at wire level. This is the 'open both directions' half of the SYN/STATE cell."""

    def __init__(self, bind_port):
        self.s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(('127.0.0.1', bind_port))
        self.s.settimeout(0.25)
        self.peer = None
        self.conn_send = 0
        self.conn_recv = 0
        self.ack = 0
        self.rx = bytearray()
        self.tx_bytes = 0
        self.rx_bytes = 0
        self.opened = False

    def now_us(self):
        return int(time.monotonic() * 1e6) & 0xFFFFFFFF

    def _send(self, pkt):
        if self.peer:
            self.tx_bytes += self.s.sendto(pkt, self.peer)

    def _state(self):
        self._send(pack_hdr(ST_STATE, 0, self.conn_send, self.now_us(), 0,
                           0x10000, 0, self.ack))

    def run(self, secs):
        stop = [False]

        def _stop(*_):
            stop[0] = True

        signal.signal(signal.SIGTERM, _stop)
        signal.signal(signal.SIGINT, _stop)
        deadline = time.monotonic() + secs
        while not stop[0] and time.monotonic() < deadline:
            try:
                data, src = self.s.recvfrom(65535)
            except socket.timeout:
                continue
            self.rx_bytes += len(data)
            h = unpack_hdr(data)
            if not h or h['ver'] != VER:
                continue
            if h['type'] == ST_SYN and not self.opened:
                # BEP29 §4 acceptor: recv id = syn.conn_id+1, send id = syn.conn_id
                self.peer = src
                self.conn_recv = (h['conn_id'] + 1) & 0xFFFF
                self.conn_send = h['conn_id'] & 0xFFFF
                self.ack = h['seq']
                self._send(pack_hdr(ST_STATE, 0, self.conn_send, self.now_us(),
                                   0, 0x10000, 0, self.ack))
                self.opened = True
                print('ACCEPT_OPEN', flush=True)
            elif h['type'] == ST_DATA and self.opened:
                body = bytes(h['raw'])[HDR_LEN:]
                if h['seq'] == (self.ack + 1) & 0xFFFF:
                    self.rx += body
                self.ack = h['seq']
                self._state()
            elif h['type'] == ST_FIN and self.opened:
                self.ack = h['seq']
                self._state()
                return 0
            elif h['type'] == ST_RESET:
                return 2
        return 0 if self.opened else 1

    def report(self, tag):
        print(f'{tag} bytes_out={self.tx_bytes} bytes_in={self.rx_bytes} '
              f'rx_payload={len(self.rx)}')


def main():
    mode, ip, port, secs = sys.argv[1], sys.argv[2], int(sys.argv[3]), float(sys.argv[4])
    random.seed(0xBEEF)
    if mode == 'syn-probe':
        p = Peer(ip, port)
        r = p.handshake(secs)
        if r == 0:
            p.state()
            print('SYN_OK')
        else:
            print('SYN_TIMEOUT')
        p.report('syn')
    elif mode == 'reset-probe':
        p = Peer(ip, port)
        if p.handshake(secs) != 0:
            print('RESET_NO_OPEN')
            p.report('reset')
            return
        p.reset()
        time.sleep(0.2)
        p2 = Peer(ip, port)  # fresh conn: a healthy acceptor answers again
        r2 = p2.handshake(secs)
        print('RESET_REOPEN_OK' if r2 == 0 else 'RESET_REOPEN_FAIL')
        p.report('reset')
        p2.report('reset2')
    elif mode == 'data-sack':
        p = Peer(ip, port)
        if p.handshake(secs) != 0:
            print('DATA_NO_OPEN')
            p.report('data')
            return
        msg = b'ntx-utp-harness-data-' + os.urandom(64)
        r = p.reliable_data(msg, secs)
        p.pump(secs, 0)
        tag = 'DATA_OK' if r == 0 else ('DATA_RESET' if r == 2 else 'DATA_TIMEOUT')
        print(f'DATA_SENT={len(msg)} SACK_BITS={len(p.sack_seen)} {tag}')
        p.report('data')
    elif mode == 'fin-probe':
        p = Peer(ip, port)
        if p.handshake(secs) != 0:
            print('FIN_NO_OPEN')
            p.report('fin')
            return
        p.data(b'bye')
        p.fin()
        r = p.pump(secs, 3)
        print('FIN_CLEAN' if r == 0 else 'FIN_HANG')
        p.report('fin')
    elif mode == 'listen':
        # argv[3] is the bind port (ip arg is ignored for a server bind)
        a = Acceptor(int(sys.argv[3]))
        r = a.run(secs)
        if r == 0:
            print('ACCEPT_OK')
        elif r == 2:
            print('ACCEPT_RESET')
        else:
            print('ACCEPT_TIMEOUT')
        a.report('listen')
    else:
        print(f'unknown mode {mode}')
        sys.exit(2)


if __name__ == '__main__':
    main()
