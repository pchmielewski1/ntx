#ifndef NTX_UTP_SM_INT_H
#define NTX_UTP_SM_INT_H

/* Test-only introspection for the uTP SM internals. Only test/t_utp_sm.c
 * may include this header, and only AFTER including src/net/ntx_utp_sm.c
 * (the full struct definition must be in scope). */

#include "ntx_utp.h"

/* D17: internal half-closed state value (not in the frozen public enum). */
#define SM_CS_FIN_SENT 5

static inline int64_t sm_int_max_window(const ntx_utp_conn *c) {
    return c->max_window;
}
static inline void sm_int_set_max_window(ntx_utp_conn *c, int64_t v) {
    c->max_window = v;
}
static inline int sm_int_dup_acks(const ntx_utp_conn *c) { return c->dup_acks; }
static inline int sm_int_timer_pending(const ntx_utp_conn *c) {
    return c->timer_pending;
}
static inline uint32_t sm_int_last_timeout_ms(const ntx_utp_conn *c) {
    return c->last_timeout_ms;
}
static inline int sm_int_in_flight(const ntx_utp_conn *c) { return c->fl_n; }
/* SEND space: highest of our seqs cumulatively acked (D21 split). */
static inline uint16_t sm_int_acked_frontier(const ntx_utp_conn *c) {
    return c->send_acked;
}
/* RECEIVE space: the cumulative ack field we emit is always this derived
 * value; there is no stored field any more. */
static inline uint16_t sm_int_recv_acked(const ntx_utp_conn *c) {
    return (uint16_t)(c->expected_seq - 1u);
}
static inline uint16_t sm_int_expected_seq(const ntx_utp_conn *c) {
    return c->expected_seq;
}
static inline uint16_t sm_int_conn_id_send(const ntx_utp_conn *c) {
    return c->conn_id_send;
}
static inline uint32_t sm_int_peer_wnd(const ntx_utp_conn *c) {
    return c->peer_wnd;
}
static inline uint32_t sm_int_cur_window(const ntx_utp_conn *c) {
    return c->cur_window;
}
static inline size_t sm_int_q_len(const ntx_utp_conn *c) {
    return (size_t)(c->q_write - c->q_free);
}
static inline uint32_t sm_int_rtt(const ntx_utp_conn *c) {
    return c->rtt_smoothed;
}
static inline uint32_t sm_int_rtt_var(const ntx_utp_conn *c) {
    return c->rtt_var;
}
static inline uint32_t sm_int_packet_size(const ntx_utp_conn *c) {
    return c->packet_size;
}
/* D6 reorder-buffer introspection (test-only). */
static inline int sm_int_ooo_count(const ntx_utp_conn *c) { return c->ooo_n; }
static inline int sm_int_ooo_has(const ntx_utp_conn *c, uint16_t seq) {
    return ooo_find(c, seq) >= 0;
}
/* D20 FIN-after-OOO introspection (test-only). */
static inline int sm_int_peer_eof(const ntx_utp_conn *c) { return c->peer_eof; }
static inline int sm_int_eof_pending(const ntx_utp_conn *c) {
    return c->eof_pending;
}
static inline uint16_t sm_int_eof_seq(const ntx_utp_conn *c) {
    return c->eof_seq;
}
/* Test-only seed for the sm_flush() rtt-based timer schedule path
 * (delay = max((rtt + 4*rtt_var)/1000, NTX_UTP_MIN_TIMEOUT_MS)). Via the
 * public API timer_pending is already 1 by the time the first RTT sample
 * exists, so that branch is otherwise unreachable from tests. */
static inline void sm_int_set_rtt(ntx_utp_conn *c, uint32_t rtt_us,
                                  uint32_t var_us) {
    c->rtt_smoothed = rtt_us;
    c->rtt_var = var_us;
}

#endif
