#!/usr/bin/env python3
"""BEP29 uTP golden vectors.

Deterministic, self-checking. Writes:
  test/vectors/utp/header/vectors.txt  - 20-byte header pack/unpack cases
  test/vectors/utp/header/sack.txt     - SACK bitmask cases
  test/vectors/utp/header/ext.txt      - extension chain skip cases
  test/vectors/utp/cc_constants.txt   - frozen CC constants (verified 2026-09-04)
  test/vectors/utp/cc.txt             - CC update golden sequences

C semantics mirrored exactly (Q16 fixed point, truncating division):
  base_delay = min over sliding ring (120 samples) of ts_diff (0 until first)
  our_delay  = ts_diff - base_delay            (us)
  off_target = CCONTROL_TARGET - our_delay     (us)
  delay_factor   = Q16(off_target / TARGET)
  window_factor  = Q16(outstanding / max_window)  (0 if max_window == 0)
  scaled_gain    = (MAX_CWND_INCREASE_PACKETS_PER_RTT * delay_factor * window_factor) >> 32
  new_max_window = max_window + scaled_gain, clamped to >= 0
"""
import os
import struct
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
VEC = os.path.join(ROOT, "test", "vectors", "utp")

# frozen constants (BEP29 + uTP reference; libtorrent 1.0 do_ledbat Q16 variant)
CCONTROL_TARGET_US = 100000          # 100 ms
MAX_CWND_INCREASE = 3                # packets/RTT (uTP reference)
CC_HISTORY = 120                     # 2-minute sliding window
MIN_PACKET_SIZE = 150
INIT_TIMEOUT_MS = 1000
MIN_TIMEOUT_MS = 500
DUP_ACK_LIMIT = 3


def pack_hdr(type_, ver, ext, conn, ts, tsdiff, wnd, seq, ack):
    assert 0 <= type_ <= 4 and ver == 1
    # 20-byte BEP29 header: byte0 = type (high nibble) | ver (low nibble)
    return struct.pack(">BBHIIIHH", (type_ << 4) | ver, ext, conn, ts, tsdiff, wnd, seq, ack)


HDRS = [
    # name, type, ver, ext, conn, ts, tsdiff, wnd, seq, ack, ext_bytes(hex|None)
    ("data_plain", 0, 1, 0, 0x1234, 0x00000001, 0, 0x00100000, 5, 4, None),
    ("syn_init", 4, 1, 0, 0xBEEF, 0x000ABCDE, 0, 0, 1, 0, None),
    ("state_ack", 2, 1, 0, 0x0001, 0xDEADBEEF, 0, 2048, 2, 0x000A, None),
    ("fin_eof", 1, 1, 0, 0x0002, 0x00000010, 0, 0, 9, 8, None),
    ("reset_rst", 3, 1, 0, 0x0003, 0x00000020, 0, 0, 0, 0, None),
    ("data_sack", 0, 1, 1, 0x0004, 0x00000030, 0x000186A0, 61440, 7, 0x000A, "01040000000F"),
    ("data_unknown_ext", 0, 1, 7, 0x0005, 0x00000040, 0, 8192, 3, 2, "770361626300"),
]


def w_vectors():
    lines = []
    for (name, t, v, e, conn, ts, tsd, wnd, seq, ack, ext) in HDRS:
        hdr = pack_hdr(t, v, e, conn, ts, tsd, wnd, seq, ack)
        assert len(hdr) == 20, name
        blob = hdr + (bytes.fromhex(ext) if ext else b"")
        # self-check: roundtrip
        f = struct.unpack(">BBHIIIHH", hdr)
        assert f == ((t << 4) | v, e, conn, ts, tsd, wnd, seq, ack), name
        lines.append(
            "hdr %s %d %d %d 0x%x 0x%x 0x%x 0x%x %d %d %s"
            % (name, t, v, e, conn, ts, tsd, wnd, seq, ack, blob.hex())
        )
    with open(os.path.join(VEC, "header", "vectors.txt"), "w") as fp:
        fp.write("\n".join(lines) + "\n")
    return len(lines)


def sack_case(name, ack_nr, offsets, nbytes):
    """offsets: bit positions (relative to ack_nr+2) that are set."""
    mask = bytearray(nbytes)
    for o in offsets:
        assert 0 <= o < nbytes * 8, name
        mask[o // 8] |= 1 << (o % 8)  # LSB = lower seq (BEP29 reversed byte order)
    return "sack %s %d %s %s" % (name, ack_nr, ",".join(str(x) for x in offsets), mask.hex())


def w_sack():
    cases = [
        # first bit = ack_nr+2; byte0 bits 0..7 -> ack_nr+2..ack_nr+9
        ("two", 10, [0, 1, 3], 4),            # acks 12,13,15
        ("full_byte", 100, list(range(8)), 4),  # acks 102..109
        ("cross_byte", 5, [7, 8, 9], 4),      # bit7 of byte0 + byte1 bits 0,1 -> 12,13,14
        ("sixty_four", 0, [0, 31, 32, 63], 8),  # 64-bit mask, all four corners
        ("tail_only", 0xFFFF, [63], 8),       # wraps 16-bit seq: ack 0x0002
    ]
    lines = [sack_case(*c) for c in cases]
    # self-check: known-good vector: ack_nr=10, bits {12,13,15} -> byte0 = 0b00001011
    assert bytes.fromhex(lines[0].split()[-1]) == b"\x0b\x00\x00\x00"
    with open(os.path.join(VEC, "header", "sack.txt"), "w") as fp:
        fp.write("\n".join(lines) + "\n")
    return len(lines)


def w_ext():
    cases = [
        # name, chain_hex, expected_first_type, expected_payload_hex (after chain), n_blocks
        # every chain ends with the (0,0) terminator; payload follows it
        ("sack_only", "01040000000F0000", 1, "", 2),
        ("sack_then_unknown", "01040000000F77036162630000", 1, "", 3),
        ("unknown_only", "77036162630000", 7, "", 2),
        ("empty_chain", "", 0, "", 0),
        ("with_payload", "01040000000F0000DEADBEEF", 1, "DEADBEEF", 2),
    ]
    lines = []
    for (name, chain, first, payload, nb) in cases:
        blob = bytes.fromhex(chain)
        off, blocks, ok = 0, 0, True
        first_t = blob[0] if blob else 0
        while off < len(blob):
            t, ln = blob[off], blob[off + 1]
            if ln == 0 and t != 0:
                ok = False
                break
            off += 2 + ln
            if t == 0:
                blocks += 1
                break
            blocks += 1
        assert ok, name
        assert payload.lower() == blob[off:].hex(), name
        lines.append("ext %s %s %d %s %d" % (name, chain, first_t, payload, blocks))
    with open(os.path.join(VEC, "header", "ext.txt"), "w") as fp:
        fp.write("\n".join(lines) + "\n")
    return len(lines)


def w_cc_constants():
    lines = [
        "# uTP P6a CC constants - frozen 2026-09-04",
        "# Sources: BEP29 (Accepted, 2012-10-20 update: loss factor 0.5, SACK layout)",
        "#   https://www.bittorrent.org/beps/bep_0029.html",
        "#   MAX_CWND_INCREASE_PACKETS_PER_RTT: uTP reference implementation value",
        "#   (modern libtorrent 1.0+ uses the Q16 variant of the same BEP formula,",
        "#   see src/utp_stream.cpp do_ledbat; dup_ack_limit=3 confirmed)",
        "CCONTROL_TARGET_US=%d" % CCONTROL_TARGET_US,
        "MAX_CWND_INCREASE_PACKETS_PER_RTT=%d" % MAX_CWND_INCREASE,
        "CC_HISTORY=%d" % CC_HISTORY,
        "MIN_PACKET_SIZE=%d" % MIN_PACKET_SIZE,
        "INIT_TIMEOUT_MS=%d" % INIT_TIMEOUT_MS,
        "MIN_TIMEOUT_MS=%d" % MIN_TIMEOUT_MS,
        "DUP_ACK_LIMIT=%d" % DUP_ACK_LIMIT,
        "LOSS_FACTOR=%s" % "0.5",
    ]
    with open(os.path.join(VEC, "cc_constants.txt"), "w") as fp:
        fp.write("\n".join(lines) + "\n")


def q16_div(num, den):
    if den == 0:
        return 0
    return (num << 16) // den


def cc_update_state(hist, hist_n, hist_idx, ts_diff, outstanding, cwnd):
    # add sample to ring (skip 0 = no delay sample)
    if ts_diff > 0:
        if hist_n < CC_HISTORY:
            hist[hist_idx] = ts_diff
            hist_idx = (hist_idx + 1) % CC_HISTORY
            hist_n += 1
        else:
            hist[hist_idx] = ts_diff
            hist_idx = (hist_idx + 1) % CC_HISTORY
    base = min(hist[:hist_n]) if hist_n else 0
    if base == 0:
        return cwnd  # no delay samples yet: do not adjust
    our_delay = ts_diff - base
    off_target = CCONTROL_TARGET_US - our_delay
    delay_factor = q16_div(off_target, CCONTROL_TARGET_US)
    window_factor = q16_div(outstanding, cwnd)
    scaled = (MAX_CWND_INCREASE * delay_factor * window_factor) >> 32
    new_cwnd = cwnd + scaled
    return max(new_cwnd, 0)


def w_cc():
    # golden scenario: warm-up (no samples), steady below target, spike above target
    seq = [
        # (ts_diff_us, outstanding, cwnd_in)
        (100000, 1400, 4096),    # sample 1: base=100000, our=0 -> full gain
        (100000, 1400, 0),       # cwnd 0 -> window_factor 0, no change
        (110000, 1400, 8192),    # base=100000, our=10000, off=90000 -> shrink-ish
        (130000, 1400, 8192),    # our=30000, off=70000
        (250000, 1400, 8192),    # our=150000 > target -> off negative -> shrink
        (100000, 0, 8192),       # outstanding 0 -> window_factor 0
        (100000, 1400, 1),       # tiny cwnd
    ]
    lines = ["# cc golden: ts_diff_us outstanding cwnd_in cwnd_out"]
    hist = [0] * CC_HISTORY
    hist_n, hist_idx, cwnd = 0, 0, 4096
    for (ts, out, c_in) in seq:
        c_out = cc_update_state(hist, hist_n, hist_idx, ts, out, c_in)
        if ts > 0:
            if hist_n < CC_HISTORY:
                hist[hist_idx] = ts
                hist_idx = (hist_idx + 1) % CC_HISTORY
                hist_n += 1
            else:
                hist[hist_idx] = ts
                hist_idx = (hist_idx + 1) % CC_HISTORY
        cwnd = c_out
        lines.append("%d %d %d %d" % (ts, out, c_in, c_out))
    with open(os.path.join(VEC, "cc.txt"), "w") as fp:
        fp.write("\n".join(lines) + "\n")
    return len(lines) - 1


def main():
    os.makedirs(os.path.join(VEC, "header"), exist_ok=True)
    n1 = w_vectors()
    n2 = w_sack()
    n3 = w_ext()
    w_cc_constants()
    n4 = w_cc()
    print("vectors: %d hdr, %d sack, %d ext, %d cc" % (n1, n2, n3, n4))
    return 0


if __name__ == "__main__":
    sys.exit(main())
