#!/usr/bin/env python3
"""Userspace UDP relay + impairment injector for the uTP interop matrix.

When `tc`/netem is unavailable (unprivileged CI: no CAP_NET_ADMIN) the harness
still has to drive loss and reordering through the SUT's own BEP29 retransmit /
SACK paths. This relay is that substitute: it is the single UDP endpoint both
peers dial, and it forwards every datagram to the *other* real peer, optionally
dropping, reordering (within a window), or duplicating datagrams. Because the
peers only ever talk to the relay, the relay can count bytes per direction and
the harness asserts bytes-out == bytes-in for the lossless cells.

Usage:
  utp_relay.py <relay_port> <fixed_peer_port> [--loss F] [--reorder F] [--dup F]
                [--window N] [--seed S] [--secs N] [--stats FILE]

The relay binds 127.0.0.1:relay_port; both peers dial that one port. One peer
(the SUT server) has the known <fixed_peer_port>; the other (a raw probe or a
leech, possibly on an ephemeral source port) is learned from its first
datagram. Every datagram from the fixed port is forwarded to the learned peer,
and every datagram from any other source is forwarded to the fixed port (which
also records that source as the learned peer). Forwarding uses the relay's own
socket, so each peer sees its counterpart at relay_port. Byte counters
(client->fixed = a_to_b, fixed->client = b_to_a, plus dropped/reordered/
duplicated counts) are written as JSON to --stats (and stdout) on exit.
"""
import json
import random
import signal
import socket
import sys
import time


def main():
    relay_port = int(sys.argv[1])
    fixed_port = int(sys.argv[2])
    argv = sys.argv[3:]

    def flag(name, default):
        if name in argv:
            return float(argv[argv.index(name) + 1])
        return default

    def iflag(name, default):
        if name in argv:
            return int(argv[argv.index(name) + 1])
        return default

    loss = flag('--loss', 0.0)
    reorder = flag('--reorder', 0.0)
    dup = flag('--dup', 0.0)
    window = iflag('--window', 8)
    seed = iflag('--seed', 0)
    secs = flag('--secs', 60.0)
    stats = None
    if '--stats' in argv:
        stats = argv[argv.index('--stats') + 1]

    random.seed(seed)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(0.2)
    # Bind the single endpoint both peers dial. Forwarding uses this same
    # socket, so each peer observes its counterpart at relay_port.
    s.bind(('127.0.0.1', relay_port))
    my_port = s.getsockname()[1]

    st = dict(a_to_b=0, b_to_a=0, drop=0, reorder=0, dup=0, fwd=0,
              my_port=my_port, loss=loss, reorder_pct=reorder, dup_pct=dup)

    def emit():
        txt = json.dumps(st)
        if stats:
            with open(stats, 'w') as f:
                f.write(txt + '\n')
        print(txt, flush=True)

    fixed = ('127.0.0.1', fixed_port)
    learned = [None]  # the client peer, learned from its first datagram
    stop = [False]

    def _on_sig(signum, frame):
        stop[0] = True

    signal.signal(signal.SIGTERM, _on_sig)
    signal.signal(signal.SIGINT, _on_sig)

    def forward(dst, data, key):
        st[key] = st.get(key, 0) + len(data)
        if dst is None:
            st['drop'] += 1
            return
        if loss and random.random() < loss:
            st['drop'] += 1
            return
        if dup and random.random() < dup:
            s.sendto(data, dst)
            st['dup'] += 1
        if reorder and random.random() < reorder and window > 1:
            st['reorder'] += 1
            # hold a moment so the next datagram can overtake it
            time.sleep(random.random() * 0.004)
        s.sendto(data, dst)
        st['fwd'] += 1

    deadline = time.monotonic() + secs
    try:
        while not stop[0] and time.monotonic() < deadline:
            try:
                data, src = s.recvfrom(65535)
            except socket.timeout:
                continue
            if src[1] == fixed_port:
                forward(learned[0], data, 'b_to_a')
            else:
                learned[0] = src  # (re)learn the client peer on every packet
                forward(fixed, data, 'a_to_b')
    finally:
        emit()
        s.close()


if __name__ == '__main__':
    main()
