#include "ntx_utp.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

/* uTP v1 (BEP29) connection state machine.
 * See BEP 29.
 * Packets are injected via ntx_utp_conn_input; wire
 * send goes through ops->tx.
 *
 * Documented deviations from the BEP text:
 *  D1  Acceptor seq_nr is deterministic, not random:
 *      (uint16)(syn_seq * 0x9E3779B9 ^ 0x85EBCA6B), 0 -> 1.
 *  D2  Initial max_window = 4096 bytes (BEP leaves the initial cwnd open);
 *      advertised wnd == max_window.
 *  D3  Initial DATA chunk size = 1200 bytes. On timeout packet_size AND
 *      max_window are SET to NTX_UTP_MIN_PKT (150) per BEP29; the
 *      x0.5 halving applies to the loss path only.
 *  D4  In-flight tracking ring is capped at 128 packets.
 *  D5  Send queue is capped at 1<<20 bytes.
 *  D6  Out-of-order payload buffer. OOO DATA is
 *      stored in a bounded reorder window and drained in order to ops->rx
 *      once the gap fills, so reordering no longer forces a retransmit
 *      storm (BEP29 "wait out-of-order"). Acceptance policy:
 *      in-order -> deliver; distance d in [1, OOO_CAP-1] with a free slot
 *      and plen <= OOO_SLOT -> buffer + SACK; anything else (d >= OOO_CAP,
 *      buffer full, oversize payload) -> REJECT (not stored) but still
 *      SACKed, so the sender's loss path recovers it. The 128-bit received
 *      mask (D7) is kept in lockstep with the buffer via oo_delivered on
 *      every expected_seq advance.
 *  D7  SACK mask is 16 bytes (128 bits); bit i (LSB-first within a byte)
 *      = ack_nr+2+i, matching ntx_utp_parse_sack (BEP29); the first
 *      missing packet (ack_nr+1) is implicit and not in the mask.
 *  D8  Outgoing ts_diff_us is always 0 (one-way
 *      delay is not measured); incoming ts_diff_us drives the CC update.
 *  D9  After both FINs are exchanged the SM enters CS_DESTROYING so that
 *      further input() returns -1.
 *  D10 RTT update: delta = rtt - rtt_smoothed (pre-update, BEP 6 order);
 *      rtt/rtt_var are updated only for packets sent once (retrans flag).
 *  D11 close() flushes the entire queue ignoring the window gate.
 *  D12 write() returns 0 without queueing when the gate
 *      (min(max_window, peer_wnd)) is full (frozen API: 0..n).
 *  D13 input() drops ST_SYN with -1 (SYN collision, BEP 4).
 *  D14 Acceptor transitions SYN_RECV -> CONNECTED on the first in-order
 *      DATA (the frozen API keeps CS_SYN_RECV right after accept()).
 *  D15 Single pending timer; on_timer reschedules doubled (cap 8000 ms)
 *      unless CS_DESTROYING. The frozen API has no timer-cancel op, so a
 *      timer that fires with nothing to retransmit simply reschedules.
 *  D16 close() before CONNECTED just transitions to CS_DESTROYING (no
 *      FIN is emitted).
 *  D17 CS_FIN_SENT is an internal state value 5 (not in the frozen public
 *      enum); ntx_utp_conn_state() may return 5 for a half-closed conn.
 *      test-only ntx_utp_sm_int.h exposes it as SM_CS_FIN_SENT.
 *  D18 packet_size recovery: BEP29 says sizes are dynamic 150..large
 *      "based on rate" but gives no growth rule. Minimal choice: chunks stay
 *      at the timeout floor (150) until the CC path has raised
 *      max_window back to the initial chunk cap (1200); the restore then
 *      rides the same CC-gated ACK branch (ts_diff_us != 0). max_window
 *      recovery itself is pure congestion control: probe/ACK samples let ntx_utp_cc_update
 *      raise it from the 150 floor again.
 *  D19 sm_flush() tracks an explicit sent watermark (q_sent): the queue
 *      offset of the next unsent byte. The previous formula (unsent =
 *      q_write - q_free - cur_window) assumed every past chunk was
 *      full-size; when the window gate truncated a chunk, bytes beyond the
 *      sent watermark became invisible and the queue stalled until the next
 *      full-size round. Latent for a long time; exposed by the 150 ms
 *      timeout (a 150-byte gate frequently truncates mid-chunk).
 *  D20 FIN-after-OOO: an ST_FIN whose
 *      seq_nr is ahead of expected_seq records eof_pkt (its seq) as pending
 *      and does not finalise the close until the gap ahead of it is filled
 *      and drained (expected_seq reaches eof_pkt), per BEP29 "record
 *      eof_pkt; wait out-of-order". A FIN that arrives in order behaves as
 *      before (D9). This is the read-side complement of the D6 buffer: with
 *      OOO data buffered, closing on the FIN alone would drop it.
 */

#define NTX_UTP_SM_QUEUE_CAP (1u << 20)
#define NTX_UTP_SM_FL_CAP 128
#define NTX_UTP_SM_SACK_BYTES 16
#define NTX_UTP_SM_SACK_BITS (NTX_UTP_SM_SACK_BYTES * 8u)
#define NTX_UTP_SM_INIT_PKT 1200u
#define NTX_UTP_SM_INIT_WND 4096u
#define NTX_UTP_SM_MAX_TIMEOUT_MS 8000u
#define NTX_UTP_SM_FIN_SENT 5 /* D17 */
/* D6 reorder window: matches the 128-bit SACK mask width (D7) — a packet
 * further ahead than the mask can represent cannot be SACK-acked, so it is
 * rejected instead of buffered. One fixed slot per window position keeps the
 * buffer bounded at OOO_CAP * OOO_SLOT bytes with no allocator. */
#define NTX_UTP_SM_OOO_CAP 128u
#define NTX_UTP_SM_OOO_SLOT NTX_UTP_SM_INIT_PKT /* 1200 B — the DATA cap */

struct ntx_utp_ooo_slot {
    uint16_t seq; /* seq_nr held here (valid when the slot is non-empty) */
    uint32_t len; /* payload bytes; 0 == empty slot (ST_DATA always has
                   * payload, BEP29, so a stored slot never has len 0) */
};

struct ntx_utp_fl {
    uint16_t seq;
    uint64_t q_off; /* absolute offset in qbuf */
    uint32_t len;
    uint32_t ts; /* 32-bit us send time */
    int retrans; /* 1 once sent more than once */
};

struct ntx_utp_conn {
    int state;
    uint16_t conn_id_recv;
    uint16_t conn_id_send;
    uint16_t seq_nr; /* next seq for our DATA/SYN/FIN */
    uint16_t expected_seq; /* next seq expected from the peer */
    uint16_t send_acked; /* SEND space: highest of our seqs cumulatively acked.
                            The receive frontier is NOT stored: it is always
                            expected_seq - 1 (the two spaces are unrelated
                            numbers; one field poisoned the other — D21). */
    int64_t max_window; /* congestion window, bytes (D2) */
    uint32_t cur_window; /* in-flight bytes */
    uint32_t peer_wnd; /* peer advertised receive window (last STATE) */
    uint32_t packet_size; /* DATA chunk size (D3) */
    uint32_t rtt_smoothed; /* us, 0 = no sample */
    uint32_t rtt_var; /* us */
    int dup_acks;
    int consecutive_timeouts;
    int timer_pending;
    uint32_t last_timeout_ms;
    int peer_eof;
    ntx_utp_cc cc;
    uint8_t *qbuf;
    uint64_t q_write; /* total bytes written (monotonic) */
    uint64_t q_sent; /* absolute offset of the next unsent byte (sent watermark) */
    uint64_t q_free; /* absolute offset up to which bytes are acked/freed */
    struct ntx_utp_fl fl[NTX_UTP_SM_FL_CAP];
    int fl_n;
    int fl_head; /* index of the oldest entry */
    uint8_t ooo_mask[NTX_UTP_SM_SACK_BYTES]; /* bit i (LSB-first) = seq
                                                expected_seq+i received (D6) */
    struct ntx_utp_ooo_slot ooo[NTX_UTP_SM_OOO_CAP]; /* D6 reorder buffer */
    uint8_t *ooo_pool; /* D6 payload pool: OOO_CAP * OOO_SLOT bytes */
    int ooo_n; /* number of non-empty ooo slots (D6) */
    int eof_pending; /* D20: ST_FIN seen ahead of expected_seq */
    uint16_t eof_seq; /* D20: seq_nr of the pending eof_pkt */
    const ntx_utp_conn_ops *ops;
};

static uint32_t now_us32(const ntx_utp_conn *c) {
    return (uint32_t)c->ops->clock(c->ops->ctx);
}

/* Emit one packet (20-byte header + optional payload) via ops->tx. */
static void sm_emit(ntx_utp_conn *c, uint16_t conn_id, uint8_t type,
                    uint8_t ext, uint16_t seq, uint16_t ack, uint32_t wnd,
                    uint32_t ts, const uint8_t *payload, size_t plen) {
    ntx_utp_hdr h;
    memset(&h, 0, sizeof h);
    h.type = type;
    h.ver = NTX_UTP_VER;
    h.extension = ext;
    h.conn_id = conn_id;
    h.ts_us = ts;
    h.ts_diff_us = 0; /* D8 */
    h.wnd_size = wnd;
    h.seq_nr = seq;
    h.ack_nr = ack;
    uint8_t buf[NTX_UTP_HDR_LEN + NTX_UTP_SM_INIT_PKT + 64];
    ntx_utp_hdr_write(buf, sizeof buf, &h);
    if (payload != NULL && plen > 0) memcpy(buf + NTX_UTP_HDR_LEN, payload, plen);
    c->ops->tx(buf, NTX_UTP_HDR_LEN + plen, c->ops->ctx);
}

/* ooo_mask: bit i = seq expected_seq+i received. When expected_seq advances
 * by 1, bit i becomes bit i-1 (right shift across the 128-bit mask). */
static void ooo_delivered(ntx_utp_conn *c) {
    uint8_t carry = 0;
    for (int i = NTX_UTP_SM_SACK_BYTES - 1; i >= 0; i--) {
        uint8_t v = c->ooo_mask[i];
        c->ooo_mask[i] = (uint8_t)((v >> 1) | carry);
        carry = (uint8_t)(v << 7);
    }
}

static void ooo_mark(ntx_utp_conn *c, int d) {
    if (d < 1 || d >= (int)NTX_UTP_SM_SACK_BITS) return;
    c->ooo_mask[d / 8] |= (uint8_t)(1u << (unsigned)(d % 8));
}

/* D6: index of the buffer slot holding `seq`, or -1. Wrap-safe compare. */
static int ooo_find(const ntx_utp_conn *c, uint16_t seq) {
    for (int i = 0; i < (int)NTX_UTP_SM_OOO_CAP; i++)
        if (c->ooo[i].len != 0 && (int16_t)(c->ooo[i].seq - seq) == 0)
            return i;
    return -1;
}

/* D6: store payload for `seq` into a free slot. Returns 0 on accept, -1 on
 * reject (window full). Caller has already bounded d and plen. */
static int ooo_put(ntx_utp_conn *c, uint16_t seq, const uint8_t *payload,
                   size_t plen) {
    int slot = -1;
    for (int i = 0; i < (int)NTX_UTP_SM_OOO_CAP; i++)
        if (c->ooo[i].len == 0) {
            slot = i;
            break;
        }
    if (slot < 0) return -1; /* reorder window full: reject, sender recovers */
    memcpy(c->ooo_pool + (size_t)slot * NTX_UTP_SM_OOO_SLOT, payload, plen);
    c->ooo[slot].seq = seq;
    c->ooo[slot].len = (uint32_t)plen;
    c->ooo_n++;
    return 0;
}

/* D6: after the current gap is filled, deliver every buffered successor in
 * sequence to ops->rx and keep the SACK mask (D7) in lockstep. Advances
 * expected_seq and refreshes the receive-side ack frontier. */
static void ooo_drain(ntx_utp_conn *c) {
    for (;;) {
        int i = ooo_find(c, c->expected_seq);
        if (i < 0) break;
        uint32_t len = c->ooo[i].len;
        const uint8_t *pl = c->ooo_pool + (size_t)i * NTX_UTP_SM_OOO_SLOT;
        c->ooo[i].len = 0;
        c->ooo_n--;
        if (c->ops->rx) c->ops->rx(pl, len, c->ops->ctx);
        c->expected_seq = (uint16_t)(c->expected_seq + 1u);
        ooo_delivered(c);
    }
}

/* SACK STATE (D7): ack_nr = expected_seq-1; mask bit i = ack_nr+2+i, i.e.
 * the ooo_mask shifted right by 1. Ext block: (1, 16, mask[16], 0, 0). */
static void sm_send_sack(ntx_utp_conn *c) {
    uint8_t mask[NTX_UTP_SM_SACK_BYTES];
    uint8_t carry = 0;
    for (int i = NTX_UTP_SM_SACK_BYTES - 1; i >= 0; i--) {
        uint8_t v = c->ooo_mask[i];
        mask[i] = (uint8_t)((v >> 1) | carry);
        carry = (uint8_t)(v << 7);
    }
    uint8_t buf[NTX_UTP_HDR_LEN + 2 + NTX_UTP_SM_SACK_BYTES + 2];
    ntx_utp_hdr h;
    memset(&h, 0, sizeof h);
    h.type = NTX_UTP_ST_STATE;
    h.ver = NTX_UTP_VER;
    h.extension = NTX_UTP_EXT_SACK;
    h.conn_id = c->conn_id_send;
    h.ts_us = now_us32(c);
    h.ts_diff_us = 0;
    h.wnd_size = (uint32_t)c->max_window;
    h.seq_nr = c->seq_nr;
    h.ack_nr = (uint16_t)(c->expected_seq - 1u);
    ntx_utp_hdr_write(buf, sizeof buf, &h);
    buf[NTX_UTP_HDR_LEN] = NTX_UTP_EXT_SACK;
    buf[NTX_UTP_HDR_LEN + 1] = (uint8_t)NTX_UTP_SM_SACK_BYTES;
    memcpy(buf + NTX_UTP_HDR_LEN + 2, mask, sizeof mask);
    buf[NTX_UTP_HDR_LEN + 2 + sizeof mask] = 0;
    buf[NTX_UTP_HDR_LEN + 3 + sizeof mask] = 0;
    c->ops->tx(buf, sizeof buf, c->ops->ctx);
}

/* Pure ST_STATE (D21): the cumulative ACK for freshly delivered data when
 * there is nothing to piggyback. Mirrors sm_send_sack minus the ext block;
 * ST_STATE consumes no seq_nr (BEP29), so seq_nr rides unadvanced. */
static void sm_send_ack(ntx_utp_conn *c) {
    uint8_t buf[NTX_UTP_HDR_LEN];
    ntx_utp_hdr h;
    memset(&h, 0, sizeof h);
    h.type = NTX_UTP_ST_STATE;
    h.ver = NTX_UTP_VER;
    h.extension = 0;
    h.conn_id = c->conn_id_send;
    h.ts_us = now_us32(c);
    h.ts_diff_us = 0;
    h.wnd_size = (uint32_t)c->max_window;
    h.seq_nr = c->seq_nr;
    h.ack_nr = (uint16_t)(c->expected_seq - 1u);
    ntx_utp_hdr_write(buf, sizeof buf, &h);
    c->ops->tx(buf, sizeof buf, c->ops->ctx);
}

/* Send pending queue as ST_DATA while the gate allows (BEP 2 window rule:
 * cur_window + pkt <= min(max_window, peer_wnd)). ignore_gate: close(). */
static void sm_flush(ntx_utp_conn *c, int ignore_gate) {
    if (c->state != NTX_UTP_CS_CONNECTED) return;
    int64_t gate64 =
        c->max_window < (int64_t)c->peer_wnd ? c->max_window : (int64_t)c->peer_wnd;
    if (gate64 < 0) gate64 = 0;
    if (gate64 > (int64_t)UINT32_MAX) gate64 = (int64_t)UINT32_MAX;
    uint32_t gate = (uint32_t)gate64;
    int emitted = 0;
    for (;;) {
        uint64_t unsent = c->q_write - c->q_sent;
        if (unsent == 0 || c->fl_n >= NTX_UTP_SM_FL_CAP) break;
        uint32_t chunk =
            (uint32_t)(unsent < (uint64_t)c->packet_size ? unsent : c->packet_size);
        if (!ignore_gate &&
            (uint64_t)c->cur_window + (uint64_t)chunk > (uint64_t)gate) {
            if (c->cur_window >= gate) break;
            chunk = gate - c->cur_window;
            if (chunk == 0) break;
        }
        uint64_t off = c->q_sent;
        uint32_t ts = now_us32(c);
        sm_emit(c, c->conn_id_send, NTX_UTP_ST_DATA, 0, c->seq_nr,
                (uint16_t)(c->expected_seq - 1u), (uint32_t)c->max_window, ts,
                c->qbuf + (size_t)(off % NTX_UTP_SM_QUEUE_CAP), chunk);
        struct ntx_utp_fl *e = &c->fl[(c->fl_head + c->fl_n) % NTX_UTP_SM_FL_CAP];
        e->seq = c->seq_nr;
        e->q_off = off;
        e->len = chunk;
        e->ts = ts;
        e->retrans = 0;
        c->fl_n++;
        c->q_sent += chunk;
        c->cur_window += chunk;
        c->seq_nr = (uint16_t)(c->seq_nr + 1u);
        emitted = 1;
    }
    if (emitted && !c->timer_pending) {
        c->timer_pending = 1;
        if (c->rtt_smoothed != 0 || c->rtt_var != 0) {
            uint32_t ms = (uint32_t)(((uint64_t)c->rtt_smoothed +
                                      4u * (uint64_t)c->rtt_var) /
                                     1000u);
            if (ms < NTX_UTP_MIN_TIMEOUT_MS) ms = NTX_UTP_MIN_TIMEOUT_MS;
            c->last_timeout_ms = ms;
        } else {
            c->last_timeout_ms = NTX_UTP_INIT_TIMEOUT_MS; /* first: 1000 ms */
        }
        c->ops->timer(c->last_timeout_ms, c->ops->ctx);
    }
}

/* 3 dup-acks: the oldest in-flight packet (seq == send_acked+1) is lost.
 * Retransmit the same seq/payload (cannot repackage, BEP 5); halve cwnd. */
static void sm_loss_event(ntx_utp_conn *c) {
    struct ntx_utp_fl *e = &c->fl[c->fl_head];
    sm_emit(c, c->conn_id_send, NTX_UTP_ST_DATA, 0, e->seq,
            (uint16_t)(c->expected_seq - 1u),
            (uint32_t)c->max_window, now_us32(c),
            c->qbuf + (size_t)(e->q_off % NTX_UTP_SM_QUEUE_CAP), e->len);
    e->retrans = 1;
    c->max_window = c->max_window / 2;
    if (c->max_window < 1) c->max_window = 1;
}

static int sm_input_state(ntx_utp_conn *c, const ntx_utp_hdr *h) {
    c->peer_wnd = h->wnd_size;
    if (c->state == NTX_UTP_CS_SYN_SENT && h->ack_nr == 1) {
        c->state = NTX_UTP_CS_CONNECTED;
        c->timer_pending = 0; /* handshake done; SYN retransmission is moot */
        c->expected_seq = h->seq_nr; /* acceptor seq_nr; STATE consumes none */
    }
    int16_t d = (int16_t)(h->ack_nr - c->send_acked);
    if (d > 0) {
        uint32_t outstanding_before = c->cur_window;
        struct ntx_utp_fl oldest = {0}; /* silences a false -Wmaybe-uninitialized on older gcc */
        int have_oldest = 0;
        while (c->fl_n > 0 &&
               (int16_t)(c->fl[c->fl_head].seq - h->ack_nr) <= 0) {
            struct ntx_utp_fl e = c->fl[c->fl_head];
            c->fl_head = (c->fl_head + 1) % NTX_UTP_SM_FL_CAP;
            c->fl_n--;
            if (!have_oldest) {
                oldest = e;
                have_oldest = 1;
            }
            c->q_free = e.q_off + (uint64_t)e.len; /* seq order == q_off order */
            c->cur_window -= e.len;
        }
        if (have_oldest && !oldest.retrans) { /* D10 */
            uint32_t rtt = now_us32(c) - oldest.ts; /* wrap-safe 32-bit us */
            int64_t delta = (int64_t)rtt - (int64_t)c->rtt_smoothed;
            if (delta < 0) delta = -delta;
            c->rtt_var =
                (uint32_t)((3u * (uint32_t)c->rtt_var + (uint32_t)delta) / 4u);
            c->rtt_smoothed =
                (uint32_t)((7u * (uint32_t)c->rtt_smoothed + (uint32_t)rtt) / 8u);
        }
        c->send_acked = h->ack_nr;
        c->dup_acks = 0;
        /* BEP29 backoff is per-stall, not per-life: real forward
         * progress re-arms the ladder (RTT-based once sampled, else the
         * 1000 ms initial). Pre-fix last_timeout_ms only ever doubled toward
         * the 8 s cap, so a conn that recovered once stalled re-stalled at
         * 8 s granularity and blew the pump budget. */
        c->consecutive_timeouts = 0;
        if (c->rtt_smoothed != 0 || c->rtt_var != 0) {
            uint32_t ms = (uint32_t)(((uint64_t)c->rtt_smoothed +
                                      4u * (uint64_t)c->rtt_var) /
                                     1000u);
            if (ms < NTX_UTP_MIN_TIMEOUT_MS) ms = NTX_UTP_MIN_TIMEOUT_MS;
            c->last_timeout_ms = ms;
        } else {
            c->last_timeout_ms = NTX_UTP_INIT_TIMEOUT_MS;
        }
        if (h->ts_diff_us != 0) {
            c->max_window = ntx_utp_cc_update(&c->cc, h->ts_diff_us,
                                              outstanding_before, c->max_window);
            /* D18: BEP29 leaves packet-size growth unspecified; once the
             * sec.8 CC path has raised the window back to the initial chunk
             * cap, the timeout shrink is undone. */
            if (c->max_window >= NTX_UTP_SM_INIT_PKT)
                c->packet_size = NTX_UTP_SM_INIT_PKT;
        }
        sm_flush(c, 0);
    } else if (d == 0 && c->fl_n > 0) {
        c->dup_acks++;
        if (c->dup_acks >= NTX_UTP_DUP_ACK_LIMIT) {
            sm_loss_event(c);
            c->dup_acks = 0;
        }
    }
    return 0;
}

static int sm_input_data(ntx_utp_conn *c, const ntx_utp_hdr *h,
                         const uint8_t *payload, size_t plen) {
    int16_t d = (int16_t)(h->seq_nr - c->expected_seq);
    if (d == 0) {
        if (c->state == NTX_UTP_CS_SYN_RECV)
            c->state = NTX_UTP_CS_CONNECTED; /* D14 */
        c->expected_seq = (uint16_t)(c->expected_seq + 1u);
        if (plen > 0 && c->ops->rx) c->ops->rx(payload, plen, c->ops->ctx);
        ooo_delivered(c);
        /* D6: the gap is gone — deliver any buffered successors in order. */
        ooo_drain(c);
        /* D20: a FIN that arrived ahead of this gap is now satisfied. */
        if (c->eof_pending && (int16_t)(c->expected_seq - c->eof_seq) >= 0) {
            c->eof_pending = 0;
            c->peer_eof = 1;
            if (c->state == NTX_UTP_SM_FIN_SENT) {
                c->state = NTX_UTP_CS_DESTROYING; /* D9 */
                if (c->ops->closed) c->ops->closed(c->ops->ctx);
            }
        }
        /* D21 (BEP29): received data must be acknowledged. A payload-
         * less ST_STATE carries the cumulative receive frontier when there is
         * nothing to piggyback; DATA piggybacks live in sm_flush. Without
         * this an idle receiver never opens the sender's window and the
         * sender stalls behind the retransmit ladder (a gap since D14). */
        sm_send_ack(c);
        return 0;
    }
    if (d > 0) {
        /* D6 accept policy: buffer inside the reorder window (bounded
         * distance, fitting payload, not already held). The SACK mask is
         * advanced only for packets we actually stored, so it never
         * acknowledges data we rejected — the sender's loss path recovers
         * those (beyond-window / oversize / buffer-full). */
        if (d < (int16_t)NTX_UTP_SM_OOO_CAP && plen <= NTX_UTP_SM_OOO_SLOT &&
            ooo_find(c, h->seq_nr) < 0 &&
            ooo_put(c, h->seq_nr, payload, plen) == 0)
            ooo_mark(c, (int)d);
    }
    sm_send_sack(c); /* duplicate (d<0) or gap (d>0): do not deliver yet */
    return 0;
}

ntx_utp_conn *ntx_utp_conn_initiate(uint16_t conn_id_recv,
                                    const ntx_utp_conn_ops *ops) {
    if (ops == NULL || ops->tx == NULL || ops->clock == NULL ||
        ops->timer == NULL)
        return NULL;
    ntx_utp_conn *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    c->qbuf = malloc(NTX_UTP_SM_QUEUE_CAP);
    if (c->qbuf == NULL) {
        free(c);
        return NULL;
    }
    c->ooo_pool = malloc((size_t)NTX_UTP_SM_OOO_CAP * NTX_UTP_SM_OOO_SLOT);
    if (c->ooo_pool == NULL) {
        free(c->qbuf);
        free(c);
        return NULL;
    }
    c->ops = ops;
    c->state = NTX_UTP_CS_SYN_SENT;
    c->conn_id_recv = conn_id_recv;
    c->conn_id_send = (uint16_t)(conn_id_recv + 1u);
    c->seq_nr = 1;
    c->max_window = NTX_UTP_SM_INIT_WND; /* D2 */
    c->peer_wnd = NTX_UTP_SM_INIT_WND;
    c->packet_size = NTX_UTP_SM_INIT_PKT; /* D3 */
    ntx_utp_cc_init(&c->cc);
    /* ST_SYN: conn_id = conn_id_recv (BEP 4), seq 1, ack 0, wnd 0. */
    sm_emit(c, conn_id_recv, NTX_UTP_ST_SYN, 0, 1, 0, 0, now_us32(c), NULL, 0);
    c->seq_nr = 2;
    c->send_acked = 1; /* the SYN itself (consumed seq 1 in our space) */
    c->timer_pending = 1;
    c->last_timeout_ms = NTX_UTP_INIT_TIMEOUT_MS;
    ops->timer(NTX_UTP_INIT_TIMEOUT_MS, ops->ctx);
    return c;
}

ntx_utp_conn *ntx_utp_conn_accept(uint16_t syn_conn_id, uint16_t syn_seq_nr,
                                  uint32_t syn_ts_us,
                                  const ntx_utp_conn_ops *ops) {
    (void)syn_ts_us; /* D8: one-way delay is not measured */
    if (ops == NULL || ops->tx == NULL || ops->clock == NULL ||
        ops->timer == NULL)
        return NULL;
    ntx_utp_conn *c = calloc(1, sizeof *c);
    if (c == NULL) return NULL;
    c->qbuf = malloc(NTX_UTP_SM_QUEUE_CAP);
    if (c->qbuf == NULL) {
        free(c);
        return NULL;
    }
    c->ooo_pool = malloc((size_t)NTX_UTP_SM_OOO_CAP * NTX_UTP_SM_OOO_SLOT);
    if (c->ooo_pool == NULL) {
        free(c->qbuf);
        free(c);
        return NULL;
    }
    c->ops = ops;
    c->state = NTX_UTP_CS_SYN_RECV;
    c->conn_id_recv = (uint16_t)(syn_conn_id + 1u);
    c->conn_id_send = syn_conn_id;
    c->expected_seq = (uint16_t)(syn_seq_nr + 1u);
    c->seq_nr = (uint16_t)(((uint32_t)syn_seq_nr * 0x9E3779B9u) ^ 0x85EBCA6Bu);
    if (c->seq_nr == 0) c->seq_nr = 1; /* D1 */
    c->send_acked = (uint16_t)(c->seq_nr - 1u); /* send base: the first DATA
                                                    (seq_nr) acks with d == 1 */
    c->max_window = NTX_UTP_SM_INIT_WND; /* D2 */
    c->peer_wnd = NTX_UTP_SM_INIT_WND;
    c->packet_size = NTX_UTP_SM_INIT_PKT; /* D3 */
    ntx_utp_cc_init(&c->cc);
    /* ACK-only ST_STATE reply (BEP 4); does not consume a seq_nr. */
    sm_emit(c, c->conn_id_send, NTX_UTP_ST_STATE, 0, c->seq_nr, syn_seq_nr,
            (uint32_t)c->max_window, now_us32(c), NULL, 0);
    return c;
}

int ntx_utp_conn_input(ntx_utp_conn *c, const uint8_t *pkt, size_t n) {
    if (c == NULL || n < NTX_UTP_HDR_LEN) return -1;
    if (c->state == NTX_UTP_CS_DESTROYING) return -1;
    ntx_utp_hdr h;
    if (ntx_utp_hdr_parse(pkt, n, &h) != 0) return -1;
    const uint8_t *payload = pkt + NTX_UTP_HDR_LEN;
    size_t plen = n - NTX_UTP_HDR_LEN;
    if (h.extension != 0) {
        if (plen == 0) return -1;
        int first = 0;
        if (ntx_utp_ext_skip(payload, plen, &first, &payload) != 0) return -1;
        plen = (size_t)(pkt + n - payload);
    }
    switch (h.type) {
    case NTX_UTP_ST_SYN:
        /* BEP29 handshake robustness. The glue closes the slot on -1,
         * so refusing a benign retransmit strands the pair forever (the
         * ASan-timing e2e stall). Two legitimate cases, both answered with the
         * ACK-only STATE (which consumes no seq_nr, BEP29):
         * 1. SYN_RECV and this is the very SYN we await (same seq): the peer
         *    never got our reply — replay it.
         * 2. CONNECTED and the seq sits at/below the receive frontier: the
         *    retransmit of the handshake SYN raced our D14 promotion — answer
         *    with the cumulative STATE so the peer's ladder stops.
         * Anything else is a foreign SYN on a live tuple: collision (D13). */
        if ((int16_t)(h.seq_nr - (uint16_t)(c->expected_seq - 1u)) <= 0) {
            sm_emit(c, c->conn_id_send, NTX_UTP_ST_STATE, 0, c->seq_nr,
                    (uint16_t)(c->expected_seq - 1u),
                    (uint32_t)c->max_window, now_us32(c), NULL, 0);
            return 0;
        }
        return -1; /* D13: SYN to an existing conn = collision (BEP 4) */
    case NTX_UTP_ST_STATE:
        return sm_input_state(c, &h);
    case NTX_UTP_ST_DATA:
        return sm_input_data(c, &h, payload, plen);
    case NTX_UTP_ST_FIN: {
        int16_t fd = (int16_t)(h.seq_nr - c->expected_seq);
        if (fd < 0) return 0; /* old/duplicate FIN: already recorded */
        if (fd == 0) {
            c->peer_eof = 1;
            c->eof_pending = 0;
            if (c->state == NTX_UTP_SM_FIN_SENT) {
                c->state = NTX_UTP_CS_DESTROYING; /* D9 */
                if (c->ops->closed) c->ops->closed(c->ops->ctx);
            }
            return 0;
        }
        /* D20: FIN ahead of the gap — record eof_pkt, wait out-of-order. */
        c->eof_pending = 1;
        c->eof_seq = h.seq_nr;
        sm_send_sack(c);
        return 0;
    }
    case NTX_UTP_ST_RESET:
        for (int i = 0; i < (int)NTX_UTP_SM_OOO_CAP; i++) /* D6: drop buffer */
            c->ooo[i].len = 0;
        c->ooo_n = 0;
        c->eof_pending = 0;
        c->state = NTX_UTP_CS_DESTROYING;
        if (c->ops->closed) c->ops->closed(c->ops->ctx);
        return 0;
    default:
        return -1;
    }
}

size_t ntx_utp_conn_write(ntx_utp_conn *c, const uint8_t *data, size_t n) {
    if (c == NULL || data == NULL || n == 0) return 0;
    if (c->state != NTX_UTP_CS_CONNECTED && c->state != NTX_UTP_CS_SYN_SENT)
        return 0;
    int64_t gate64 =
        c->max_window < (int64_t)c->peer_wnd ? c->max_window : (int64_t)c->peer_wnd;
    if (gate64 < 0) gate64 = 0;
    uint32_t gate =
        gate64 > (int64_t)UINT32_MAX ? UINT32_MAX : (uint32_t)gate64;
    if (c->cur_window >= gate) return 0; /* D12 */
    uint64_t avail =
        (uint64_t)NTX_UTP_SM_QUEUE_CAP - (c->q_write - c->q_free);
    size_t m = n < (size_t)avail ? n : (size_t)avail;
    if (m == 0) return 0;
    uint64_t off = c->q_write;
    size_t first = (size_t)(NTX_UTP_SM_QUEUE_CAP - (off % NTX_UTP_SM_QUEUE_CAP));
    if (m > first) {
        memcpy(c->qbuf + (size_t)(off % NTX_UTP_SM_QUEUE_CAP), data, first);
        memcpy(c->qbuf, data + first, m - first);
    } else {
        memcpy(c->qbuf + (size_t)(off % NTX_UTP_SM_QUEUE_CAP), data, m);
    }
    c->q_write += m;
    sm_flush(c, 0);
    return m;
}

void ntx_utp_conn_on_timer(ntx_utp_conn *c) {
    if (c == NULL || c->state == NTX_UTP_CS_DESTROYING) return;
    if (c->fl_n > 0) {
        /* BEP29: on timeout set packet_size AND max_window to the
         * smallest packet size (150) and allow one probe packet (SET, not
         * halve; the x0.5 shrink belongs to the loss path only). */
        c->packet_size = NTX_UTP_MIN_PKT;
        c->max_window = NTX_UTP_MIN_PKT;
        struct ntx_utp_fl *e = &c->fl[c->fl_head];
        sm_emit(c, c->conn_id_send, NTX_UTP_ST_DATA, 0, e->seq,
                (uint16_t)(c->expected_seq - 1u), (uint32_t)c->max_window,
                now_us32(c),
                c->qbuf + (size_t)(e->q_off % NTX_UTP_SM_QUEUE_CAP), e->len);
        e->retrans = 1;
    } else if (c->state == NTX_UTP_CS_SYN_SENT) {
        /* SYN still unacked: retransmit with the same fields, fresh ts. */
        sm_emit(c, c->conn_id_recv, NTX_UTP_ST_SYN, 0, 1, 0, 0, now_us32(c),
                NULL, 0);
    }
    c->consecutive_timeouts++;
    uint32_t next = c->last_timeout_ms * 2u;
    if (next == 0 || next > NTX_UTP_SM_MAX_TIMEOUT_MS)
        next = NTX_UTP_SM_MAX_TIMEOUT_MS;
    c->last_timeout_ms = next;
    c->timer_pending = 1;
    c->ops->timer(next, c->ops->ctx);
}

void ntx_utp_conn_close(ntx_utp_conn *c) {
    if (c == NULL) return;
    if (c->state == NTX_UTP_CS_CONNECTED) {
        sm_flush(c, 1); /* D11: flush the entire queue, ignore the gate */
    } else if (c->state != NTX_UTP_SM_FIN_SENT) {
        c->state = NTX_UTP_CS_DESTROYING; /* D16 */
        return;
    }
    /* ST_FIN: seq = seq_nr (not consumed, "eof"), wnd 0, ack = recv frontier. */
    sm_emit(c, c->conn_id_send, NTX_UTP_ST_FIN, 0, c->seq_nr,
            (uint16_t)(c->expected_seq - 1u), 0, now_us32(c), NULL, 0);
    c->state = NTX_UTP_SM_FIN_SENT;
    if (c->peer_eof) {
        c->state = NTX_UTP_CS_DESTROYING; /* D9 */
        if (c->ops->closed) c->ops->closed(c->ops->ctx);
    }
}

void ntx_utp_conn_free(ntx_utp_conn *c) {
    if (c == NULL) return;
    if (c->state != NTX_UTP_CS_DESTROYING && c->state != NTX_UTP_CS_SYN_SENT &&
        c->ops->tx) {
        sm_emit(c, c->conn_id_send, NTX_UTP_ST_RESET, 0, 0, 0, 0, now_us32(c),
                NULL, 0);
        c->state = NTX_UTP_CS_DESTROYING;
    }
    free(c->qbuf);
    free(c->ooo_pool);
    free(c);
}

int ntx_utp_conn_state(const ntx_utp_conn *c) {
    return c != NULL ? c->state : NTX_UTP_CS_UNINITIALIZED;
}

int ntx_utp_conn_connected(const ntx_utp_conn *c) {
    return c != NULL && c->state == NTX_UTP_CS_CONNECTED;
}

uint16_t ntx_utp_conn_recv_id(const ntx_utp_conn *c) {
    return c != NULL ? c->conn_id_recv : 0;
}
