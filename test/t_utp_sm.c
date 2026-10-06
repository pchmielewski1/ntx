#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/net/ntx_utp_sm.c"
#include "../src/net/ntx_utp_hdr.c"
#include "../src/net/ntx_utp_cc.c"
#include "../src/net/ntx_utp_sm_int.h"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

/* ---------------- harness ---------------- */

static uint64_t now_us = 1000000;

static uint64_t h_clock(void *ctx) { (void)ctx; return now_us; }

#define CAP_CAP 512
typedef struct { uint8_t data[1600]; size_t n; } cap_pkt; /* 20 + 1200 + margin */
static cap_pkt cap[CAP_CAP];
static int cap_n;

static void h_tx(const uint8_t *pkt, size_t n, void *ctx) {
    (void)ctx;
    if (cap_n >= CAP_CAP || n > sizeof cap[0].data) return;
    memcpy(cap[cap_n].data, pkt, n);
    cap[cap_n].n = n;
    cap_n++;
}

static uint32_t timer_delays[64];
static int timer_n;
static int timer_pending_h;

static void h_timer(uint32_t delay_ms, void *ctx) {
    (void)ctx;
    if (timer_n < (int)(sizeof timer_delays / sizeof timer_delays[0]))
        timer_delays[timer_n++] = delay_ms;
    timer_pending_h = 1;
}

typedef struct { uint8_t buf[1 << 20]; size_t n; int closed; } h_conn;

static void h_rx(const uint8_t *data, size_t n, void *ctx) {
    h_conn *hc = (h_conn *)ctx;
    if (hc->n + n <= sizeof hc->buf) {
        memcpy(hc->buf + hc->n, data, n);
        hc->n += n;
    }
}

static void h_closed(void *ctx) { ((h_conn *)ctx)->closed = 1; }

static void reset_caps(void) { cap_n = 0; timer_n = 0; timer_pending_h = 0; }

static ntx_utp_conn_ops make_ops(h_conn *hc) {
    ntx_utp_conn_ops ops;
    memset(&ops, 0, sizeof ops);
    ops.tx = h_tx;
    ops.rx = h_rx;
    ops.timer = h_timer;
    ops.closed = h_closed;
    ops.clock = h_clock;
    ops.ctx = hc;
    return ops;
}

static size_t craft(uint8_t *buf, size_t capsz, uint8_t type, uint8_t ext,
                    uint16_t conn, uint32_t ts, uint32_t tsdiff, uint32_t wnd,
                    uint16_t seq, uint16_t ack, const uint8_t *pl, size_t pln) {
    ntx_utp_hdr h;
    memset(&h, 0, sizeof h);
    h.type = type;
    h.ver = NTX_UTP_VER;
    h.extension = ext;
    h.conn_id = conn;
    h.ts_us = ts;
    h.ts_diff_us = tsdiff;
    h.wnd_size = wnd;
    h.seq_nr = seq;
    h.ack_nr = ack;
    if (ntx_utp_hdr_write(buf, capsz, &h) != 0) return 0;
    if (pl != NULL && pln > 0) memcpy(buf + NTX_UTP_HDR_LEN, pl, pln);
    return NTX_UTP_HDR_LEN + pln;
}

static int cap_parse(const cap_pkt *p, ntx_utp_hdr *h, const uint8_t **pl,
                     size_t *pln) {
    if (ntx_utp_hdr_parse(p->data, p->n, h) != 0) return -1;
    *pl = p->data + NTX_UTP_HDR_LEN;
    *pln = p->n - NTX_UTP_HDR_LEN;
    if (h->extension != 0) {
        int first = 0;
        if (ntx_utp_ext_skip(p->data + NTX_UTP_HDR_LEN, *pln, &first, pl) != 0)
            return -1;
        *pln = (size_t)(p->data + p->n - *pl);
    }
    return 0;
}

/* Must mirror the D1 deterministic-seq formula in ntx_utp_sm.c. */
static uint16_t det_seq(uint16_t syn_seq) {
    uint16_t s = (uint16_t)(((uint32_t)syn_seq * 0x9E3779B9u) ^ 0x85EBCA6Bu);
    return s == 0 ? 1 : s;
}

/* ---------------- 1. initiate ---------------- */

static void test_initiate(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 1000000;
    ntx_utp_conn_ops ops = make_ops(&hc);
    ntx_utp_conn *a = ntx_utp_conn_initiate(0x1234, &ops);
    check(a != NULL, "initiate: conn allocated");
    check(cap_n == 1, "initiate: exactly one packet emitted");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    int ok = cap_n >= 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0;
    check(ok, "initiate: capture parses");
    if (!ok) { ntx_utp_conn_free(a); return; }
    check(h.type == NTX_UTP_ST_SYN && h.ver == NTX_UTP_VER && h.extension == 0,
          "initiate: ST_SYN ver=1 ext=0");
    check(h.conn_id == 0x1234, "initiate: conn_id == conn_id_recv");
    check(h.seq_nr == 1 && h.ack_nr == 0, "initiate: seq=1 ack=0");
    check(h.ts_us == 1000000u && h.ts_diff_us == 0 && h.wnd_size == 0,
          "initiate: ts=now tsdiff=0 wnd=0");
    check(pln == 0, "initiate: no payload");
    check(ntx_utp_conn_state(a) == NTX_UTP_CS_SYN_SENT, "initiate: state CS_SYN_SENT");
    check(timer_n == 1 && timer_delays[0] == NTX_UTP_INIT_TIMEOUT_MS,
          "initiate: retransmission timer 1000 ms");
    check(sm_int_timer_pending(a) == 1, "initiate: timer_pending set");
    ntx_utp_conn_free(a);
}

/* ---------------- 2-4. accept + handshake + conn ids ---------------- */

static ntx_utp_conn *g_a, *g_b;
static h_conn g_hca, g_hcb;
static ntx_utp_conn_ops g_ops_a, g_ops_b; /* static: outlive the test fn */
static uint16_t g_det;

static void test_accept_handshake(void) {
    reset_caps();
    now_us = 1000000;
    g_det = det_seq(1);
    g_ops_b = make_ops(&g_hcb);
    g_b = ntx_utp_conn_accept(0x1234, 1, 1000000, &g_ops_b);
    check(g_b != NULL, "accept: conn allocated");
    check(cap_n == 1, "accept: exactly one packet emitted");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n >= 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0, "accept: capture parses");
    check(h.type == NTX_UTP_ST_STATE && h.extension == 0, "accept: ST_STATE no ext");
    check(h.conn_id == 0x1234, "accept: conn_id == syn conn id (send id)");
    check(h.ack_nr == 1, "accept: ack == syn seq");
    check(h.seq_nr == g_det, "accept: deterministic seq_nr (D1)");
    check(h.wnd_size == 4096, "accept: advertised wnd == initial max_window 4096");
    check(h.ts_us == 1000000u && h.ts_diff_us == 0, "accept: ts=now tsdiff=0");
    check(ntx_utp_conn_state(g_b) == NTX_UTP_CS_SYN_RECV,
          "accept: state CS_SYN_RECV (frozen API)");

    uint8_t state_pkt[20];
    size_t state_n = cap[0].n;
    memcpy(state_pkt, cap[0].data, state_n);
    g_ops_a = make_ops(&g_hca);
    g_a = ntx_utp_conn_initiate(0x1234, &g_ops_a);
    reset_caps();
    check(ntx_utp_conn_input(g_a, state_pkt, state_n) == 0, "handshake: A consumes STATE");
    check(ntx_utp_conn_state(g_a) == NTX_UTP_CS_CONNECTED, "handshake: A -> CS_CONNECTED");
    check(ntx_utp_conn_connected(g_a) == 1, "handshake: A connected()");
    check(sm_int_timer_pending(g_a) == 0, "handshake: A timer cleared");
    check(ntx_utp_conn_recv_id(g_a) == 0x1234, "handshake: recv_id");
    check(sm_int_conn_id_send(g_a) == 0x1235, "connids: A send id 0x1235");
    check(sm_int_conn_id_send(g_b) == 0x1234, "connids: B send id 0x1234");
}

/* ---------------- 5. data flow ---------------- */

static void test_data_flow(void) {
    reset_caps();
    now_us = 2000000;
    uint8_t data[5000];
    for (int i = 0; i < 5000; i++) data[i] = (uint8_t)(i * 31 + 7);
    size_t queued = ntx_utp_conn_write(g_a, data, 5000);
    check(queued == 5000, "data: write accepts all 5000 bytes");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n >= 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0,
          "data: first packet captured");
    check(h.type == NTX_UTP_ST_DATA && h.conn_id == 0x1235,
          "data: first DATA conn_id 0x1235 (send id)");
    check(h.seq_nr == 2, "data: first DATA seq == 2");
    check(pln > 0 && pln <= 1200, "data: chunk <= 1200");
    check(h.ack_nr == (uint16_t)(g_det - 1u),
          "data: DATA ack carries the receive frontier (expected_seq-1)");
    check(h.wnd_size == 4096, "data: DATA advertises max_window");

    /* Drive to completion: feed A's DATA to B; the crafted ST_STATE acks
     * advance A's send frontier. B additionally emits its own pure ST_STATE
     * acks on every in-order delivery (D21) — captured, not needed here. */
    int fed = 0;
    int rounds = 0;
    uint8_t st[20];
    while ((sm_int_in_flight(g_a) > 0 || sm_int_q_len(g_a) > 0) && rounds < 12) {
        for (int i = fed; i < cap_n; i++) {
            ntx_utp_hdr dh;
            const uint8_t *dpl;
            size_t dpln;
            if (cap_parse(&cap[i], &dh, &dpl, &dpln) != 0) continue;
            if (dh.type == NTX_UTP_ST_DATA && dh.conn_id == 0x1235)
                (void)ntx_utp_conn_input(g_b, cap[i].data, cap[i].n);
        }
        fed = cap_n;
        uint16_t ack = (uint16_t)(sm_int_expected_seq(g_b) - 1u);
        size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x1234, (uint32_t)now_us,
                         0, 4096, g_det, ack, NULL, 0);
        (void)ntx_utp_conn_input(g_a, st, n);
        rounds++;
    }
    check(sm_int_in_flight(g_a) == 0, "data: A in-flight drained");
    check(sm_int_q_len(g_a) == 0, "data: A queue empty");
    check(sm_int_acked_frontier(g_a) == 6, "data: A frontier advanced to 6");
    check(g_hcb.n == 5000 && memcmp(g_hcb.buf, data, 5000) == 0,
          "data: B rx == exact 5000 bytes");
    size_t total = 0;
    int all_ok = 1;
    for (int i = 0; i < cap_n; i++) {
        ntx_utp_hdr dh;
        const uint8_t *dpl;
        size_t dpln;
        if (cap_parse(&cap[i], &dh, &dpl, &dpln) != 0) { all_ok = 0; break; }
        if (dh.type != NTX_UTP_ST_DATA) continue; /* D21 pure acks ride STATE */
        if (dh.conn_id != 0x1235 || dpln > 1200) all_ok = 0;
        total += dpln;
    }
    check(all_ok, "data: all captured DATA use conn 0x1235, chunks <= 1200");
    check(total == 5000, "data: total DATA payload == 5000");
    check(cap_n >= 2, "data: window gate split the 5000 into rounds");
}

/* ---------------- 6. SACK / loss ---------------- */

static ntx_utp_conn *g_a2, *g_b2;
static h_conn g_hca2, g_hcb2;
static ntx_utp_conn_ops g_ops_a2, g_ops_b2; /* static: used by test_fin too */

static void test_sack_loss(void) {
    reset_caps();
    now_us = 3000000;
    g_ops_a2 = make_ops(&g_hca2);
    g_a2 = ntx_utp_conn_initiate(0x5678, &g_ops_a2);
    g_ops_b2 = make_ops(&g_hcb2);
    g_b2 = ntx_utp_conn_accept(0x5678, 1, (uint32_t)now_us, &g_ops_b2);
    uint8_t state_pkt[20];
    size_t state_n = cap[cap_n - 1].n; /* B2's STATE (last emitted) */
    memcpy(state_pkt, cap[cap_n - 1].data, state_n);
    check(ntx_utp_conn_input(g_a2, state_pkt, state_n) == 0, "sack: handshake ok");
    check(ntx_utp_conn_state(g_a2) == NTX_UTP_CS_CONNECTED, "sack: A2 connected");
    reset_caps();

    uint8_t p[5][300];
    for (int k = 0; k < 5; k++)
        for (int i = 0; i < 300; i++) p[k][i] = (uint8_t)(k * 61 + i);
    int w_ok = 1;
    for (int k = 0; k < 5; k++)
        if (ntx_utp_conn_write(g_a2, p[k], 300) != 300) w_ok = 0;
    check(w_ok, "sack: 5x write 300B accepted");
    check(cap_n == 5, "sack: 5 DATA packets emitted");
    int seqs_ok = 1;
    for (int i = 0; i < 5; i++) {
        ntx_utp_hdr h;
        const uint8_t *pl;
        size_t pln;
        if (cap_parse(&cap[i], &h, &pl, &pln) != 0 || h.type != NTX_UTP_ST_DATA ||
            h.seq_nr != (uint16_t)(2 + i) || pln != 300 || memcmp(pl, p[i], 300) != 0)
            seqs_ok = 0;
    }
    check(seqs_ok, "sack: p1..p5 seq 2..6, 300B each, exact payloads");

    /* Feed p1,p3,p4,p5 to B2 (skip p2) */
    (void)ntx_utp_conn_input(g_b2, cap[0].data, cap[0].n);
    (void)ntx_utp_conn_input(g_b2, cap[2].data, cap[2].n);
    (void)ntx_utp_conn_input(g_b2, cap[3].data, cap[3].n);
    (void)ntx_utp_conn_input(g_b2, cap[4].data, cap[4].n);
    check(g_hcb2.n == 300 && memcmp(g_hcb2.buf, p[0], 300) == 0, "sack: B2 rx only p1");
    /* D6: the OOO p3,p4,p5 are buffered (not dropped) pending the p2 gap. */
    check(sm_int_ooo_count(g_b2) == 3, "sack: B2 OOO buffer holds 3 (p3,p4,p5)");
    check(sm_int_ooo_has(g_b2, 4) && sm_int_ooo_has(g_b2, 5) &&
              sm_int_ooo_has(g_b2, 6),
          "sack: B2 OOO buffer holds seqs 4,5,6");
    int si = cap_n - 1;
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    int sack_ok = si >= 0 && cap_parse(&cap[si], &h, &pl, &pln) == 0;
    check(sack_ok, "sack: SACK STATE parses");
    if (sack_ok) {
        check(h.type == NTX_UTP_ST_STATE && h.extension == NTX_UTP_EXT_SACK,
              "sack: ST_STATE ext=SACK");
        check(h.conn_id == 0x5678 && h.ack_nr == 2,
              "sack: SACK conn/ack_nr (ack_nr == expected_seq-1)");
        check(cap[si].n == 20 + 2 + 16 + 2, "sack: SACK packet size 40B");
        check(cap[si].data[20] == 1 && cap[si].data[21] == 16,
              "sack: ext block type=1 len=16");
        check(cap[si].data[38] == 0 && cap[si].data[39] == 0,
              "sack: (0,0) terminator");
        /* D7: bit i = ack_nr+2+i; p3,p4,p5 set; p2 (ack_nr+1) implicit missing */
        const uint8_t *m = cap[si].data + 22;
        int mask_ok = m[0] == 0x07;
        for (int i = 1; i < 16; i++)
            if (m[i] != 0) mask_ok = 0;
        check(mask_ok, "sack: mask 0x07 (p3,p4,p5 bits; p2 implicit)");
    }

    int64_t mw_before = sm_int_max_window(g_a2);
    check(mw_before == 4096, "sack: max_window 4096 before loss");
    /* 1st SACK: progress (acks p1). 2nd-4th: no progress -> 3 dup-acks -> loss. */
    (void)ntx_utp_conn_input(g_a2, cap[si].data, cap[si].n);
    check(sm_int_acked_frontier(g_a2) == 2, "sack: first SACK acks p1 (frontier 2)");
    (void)ntx_utp_conn_input(g_a2, cap[si].data, cap[si].n);
    (void)ntx_utp_conn_input(g_a2, cap[si].data, cap[si].n);
    (void)ntx_utp_conn_input(g_a2, cap[si].data, cap[si].n);
    check(sm_int_max_window(g_a2) == mw_before / 2,
          "sack: max_window halved exactly once");
    check(sm_int_dup_acks(g_a2) == 0, "sack: dup_acks reset after loss");
    int ri = -1;
    for (int i = si + 1; i < cap_n; i++) {
        ntx_utp_hdr rh;
        const uint8_t *rpl;
        size_t rpln;
        if (cap_parse(&cap[i], &rh, &rpl, &rpln) == 0 && rh.type == NTX_UTP_ST_DATA &&
            rh.seq_nr == 3 && rpln == 300 && memcmp(rpl, p[1], 300) == 0)
            ri = i;
    }
    check(ri >= 0, "sack: p2 retransmitted (same seq, same payload)");
    if (ri >= 0) {
        (void)ntx_utp_conn_input(g_b2, cap[ri].data, cap[ri].n);
        /* D6: delivering the p2 gap drains the buffered p3,p4,p5 in order to
         * the reader at once — no retransmit storm, no BEP 6 timeout wait. */
        check(g_hcb2.n == 1500, "sack: D6 gap fill delivers full 1500B at once");
        int ord = 1;
        for (int k = 0; k < 5; k++)
            if (memcmp(g_hcb2.buf + 300 * (size_t)k, p[k], 300) != 0) ord = 0;
        check(ord, "sack: D6 B2 rx == full 5x300 in order after gap fill");
        check(sm_int_ooo_count(g_b2) == 0, "sack: D6 OOO buffer drained empty");
        /* D21: delivering the p2 gap already made B2 emit a pure cumulative
         * ack that drains A2's p2..p5; the crafted cumulative STATE ack is
         * then a harmless duplicate on the send-frontier gate. */
        uint8_t st[20];
        size_t sn = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x5678,
                          (uint32_t)now_us, 0, 4096, g_det, 6, NULL, 0);
        (void)ntx_utp_conn_input(g_a2, st, sn);
        check(sm_int_in_flight(g_a2) == 0, "sack: A2 in-flight drained by ack");
    }
}

/* ---------------- 7. FIN ---------------- */

static void test_fin(void) {
    uint8_t st[20];
    for (int r = 0; r < 4 && sm_int_in_flight(g_a2) > 0; r++) {
        uint16_t ack = (uint16_t)(sm_int_expected_seq(g_b2) - 1u);
        size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x5678, (uint32_t)now_us,
                         0, 4096, g_det, ack, NULL, 0);
        (void)ntx_utp_conn_input(g_a2, st, n);
    }
    check(sm_int_in_flight(g_a2) == 0, "fin: A2 in-flight drained");
    check(sm_int_acked_frontier(g_a2) == 6, "fin: A2 frontier 6 (all 5 DATA acked)");

    reset_caps();
    ntx_utp_conn_close(g_a2);
    check(cap_n == 1, "fin: A2 close emits exactly ST_FIN");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n >= 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0, "fin: FIN parses");
    check(h.type == NTX_UTP_ST_FIN && h.conn_id == 0x5679, "fin: ST_FIN conn 0x5679");
    check(h.seq_nr == 7, "fin: FIN seq == next seq (7, not consumed)");
    check(h.wnd_size == 0 && h.ack_nr == (uint16_t)(g_det - 1u) && pln == 0,
          "fin: FIN wnd=0 ack=receive frontier (g_det-1) no payload");
    check(ntx_utp_conn_state(g_a2) == SM_CS_FIN_SENT, "fin: A2 CS_FIN_SENT (internal)");

    (void)ntx_utp_conn_input(g_b2, cap[0].data, cap[0].n);
    check(ntx_utp_conn_state(g_b2) == NTX_UTP_CS_CONNECTED,
          "fin: B2 still connected (peer_eof remembered)");
    ntx_utp_conn_close(g_b2);
    int fi = cap_n - 1;
    check(fi >= 0 && cap_parse(&cap[fi], &h, &pl, &pln) == 0 && h.type == NTX_UTP_ST_FIN,
          "fin: B2 ST_FIN");
    check(h.conn_id == 0x5678 && h.seq_nr == g_det && h.ack_nr == 6,
          "fin: B2 FIN fields (seq == its seq_nr, ack 6)");
    (void)ntx_utp_conn_input(g_a2, cap[fi].data, cap[fi].n);
    check(g_hca2.closed == 1, "fin: A2 closed fired");
    check(ntx_utp_conn_state(g_a2) == NTX_UTP_CS_DESTROYING,
          "fin: A2 -> CS_DESTROYING (D9)");
    uint8_t junk[20];
    size_t rn = craft(junk, sizeof junk, NTX_UTP_ST_STATE, 0, 0x5678, (uint32_t)now_us,
                      0, 4096, g_det, 6, NULL, 0);
    check(ntx_utp_conn_input(g_a2, junk, rn) == -1, "fin: input after closed -> -1");
    ntx_utp_conn_free(g_a2);
    ntx_utp_conn_free(g_b2);
    g_a2 = NULL;
    g_b2 = NULL;
}

/* ---------------- 8. RESET ---------------- */

static void test_reset(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 4000000;
    ntx_utp_conn_ops ops_c = make_ops(&hc);
    ntx_utp_conn *c = ntx_utp_conn_initiate(0x9ABC, &ops_c);
    check(c != NULL, "reset: conn allocated");
    uint8_t rst[20];
    size_t n = craft(rst, sizeof rst, NTX_UTP_ST_RESET, 0, 0x9ABC, (uint32_t)now_us, 0,
                     0, 0, 0, NULL, 0);
    check(ntx_utp_conn_input(c, rst, n) == 0, "reset: ST_RESET consumed");
    check(ntx_utp_conn_state(c) == NTX_UTP_CS_DESTROYING, "reset: state CS_DESTROYING");
    check(hc.closed == 1, "reset: closed fired");
    check(ntx_utp_conn_input(c, rst, n) == -1, "reset: further input -> -1");
    ntx_utp_conn_free(c);
    check(cap_n == 1, "reset: free in DESTROYING emits nothing");
}

/* ---------------- 9. timeout / doubling ---------------- */

static void test_timeout(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 1000000;
    ntx_utp_conn_ops ops_d = make_ops(&hc);
    ntx_utp_conn *d = ntx_utp_conn_initiate(0x7777, &ops_d);
    check(timer_n == 1 && timer_delays[0] == 1000, "timeout: initial timer 1000");
    now_us += 1000000;
    ntx_utp_conn_on_timer(d);
    check(cap_n == 2, "timeout: SYN retransmitted (2nd ST_SYN)");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n >= 2 && cap_parse(&cap[1], &h, &pl, &pln) == 0 &&
              h.type == NTX_UTP_ST_SYN,
          "timeout: 2nd packet is ST_SYN");
    check(h.ts_us == 2000000u && h.seq_nr == 1 && h.conn_id == 0x7777,
          "timeout: SYN retrans fields (ts updated)");
    check(timer_n == 2 && timer_delays[1] == 2000, "timeout: rescheduled 2000");
    now_us += 2000000;
    ntx_utp_conn_on_timer(d);
    check(cap_n == 3 && cap_parse(&cap[2], &h, &pl, &pln) == 0 &&
              h.type == NTX_UTP_ST_SYN,
          "timeout: 3rd ST_SYN");
    check(h.ts_us == 4000000u, "timeout: 3rd SYN ts updated");
    check(timer_n == 3 && timer_delays[2] == 4000, "timeout: rescheduled 4000");
    ntx_utp_conn_free(d);
}

/* ---------------- 10. window 0 ---------------- */

static void test_window_zero(void) {
    h_conn hca, hcb;
    memset(&hca, 0, sizeof hca);
    memset(&hcb, 0, sizeof hcb);
    reset_caps();
    now_us = 5000000;
    ntx_utp_conn_ops ops_e = make_ops(&hca);
    ntx_utp_conn *e = ntx_utp_conn_initiate(0x4321, &ops_e);
    uint8_t state_pkt[20];
    size_t state_n;
    ntx_utp_conn_ops ops_f = make_ops(&hcb);
    ntx_utp_conn *f = ntx_utp_conn_accept(0x4321, 1, (uint32_t)now_us, &ops_f);
    memcpy(state_pkt, cap[cap_n - 1].data, cap[cap_n - 1].n); /* f's STATE */
    state_n = cap[cap_n - 1].n;
    check(ntx_utp_conn_input(e, state_pkt, state_n) == 0, "wnd0: handshake ok");
    reset_caps();

    uint8_t data[300];
    for (int i = 0; i < 300; i++) data[i] = (uint8_t)i;
    sm_int_set_max_window(f, 0);
    uint8_t st[20];
    size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x4321, (uint32_t)now_us, 0,
                     0, g_det, 1, NULL, 0);
    (void)ntx_utp_conn_input(e, st, n);
    check(sm_int_peer_wnd(e) == 0, "wnd0: peer_wnd from STATE wnd=0");
    check(ntx_utp_conn_write(e, data, 300) == 0, "wnd0: write returns 0 (window full)");
    check(cap_n == 0, "wnd0: no DATA emitted");

    sm_int_set_max_window(f, 4096);
    n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x4321, (uint32_t)now_us, 0, 4096,
              g_det, 1, NULL, 0);
    (void)ntx_utp_conn_input(e, st, n);
    check(ntx_utp_conn_write(e, data, 300) == 300, "wnd0: write accepted after restore");
    check(cap_n == 1, "wnd0: A emits DATA after window restored");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n >= 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0 &&
              h.type == NTX_UTP_ST_DATA && pln == 300,
          "wnd0: DATA 300B");
    ntx_utp_conn_free(e);
    ntx_utp_conn_free(f);
}

/* ---------------- 11. ts_diff / CC ---------------- */

static void test_ts_diff_cc(void) {
    h_conn hca, hcb;
    memset(&hca, 0, sizeof hca);
    memset(&hcb, 0, sizeof hcb);
    reset_caps();
    now_us = 6000000;
    ntx_utp_conn_ops ops_e = make_ops(&hca);
    ntx_utp_conn *e = ntx_utp_conn_initiate(0x2222, &ops_e);
    uint8_t state_pkt[20];
    size_t state_n;
    ntx_utp_conn_ops ops_f = make_ops(&hcb);
    ntx_utp_conn *f = ntx_utp_conn_accept(0x2222, 1, (uint32_t)now_us, &ops_f);
    memcpy(state_pkt, cap[cap_n - 1].data, cap[cap_n - 1].n); /* f's STATE */
    state_n = cap[cap_n - 1].n;
    check(ntx_utp_conn_input(e, state_pkt, state_n) == 0, "cc: handshake ok");
    reset_caps();

    uint8_t data[4096];
    for (int i = 0; i < 4096; i++) data[i] = (uint8_t)(i ^ 0x5A);
    check(ntx_utp_conn_write(e, data, 4096) == 4096, "cc: write 4096");
    check(sm_int_in_flight(e) == 4, "cc: 4 DATA in flight (1200+1200+1200+496)");

    int64_t mw = sm_int_max_window(e);
    uint8_t st[20];
    size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x2222, (uint32_t)now_us, 0,
                     4096, g_det, 1, NULL, 0);
    (void)ntx_utp_conn_input(e, st, n);
    check(sm_int_max_window(e) == mw, "cc: ts_diff=0 leaves max_window unchanged");

    n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0x2222, (uint32_t)now_us, 100000,
              4096, g_det, 5, NULL, 0);
    (void)ntx_utp_conn_input(e, st, n);
    check(sm_int_max_window(e) == mw + 3,
          "cc: ts_diff=100ms outstanding=4096 -> +3 (BEP29 sec.8)");
    check(sm_int_in_flight(e) == 0, "cc: ack drained in-flight");
    check(sm_int_acked_frontier(e) == 5, "cc: frontier advanced to 5");
    ntx_utp_conn_free(e);
    ntx_utp_conn_free(f);
}

/* ---------------- 12-14. timeout / RTT coverage (BEP29) -------- */

/* Drive an initiator to CONNECTED with a crafted ACK-only ST_STATE
 * (sm_input_state accepts ack_nr == 1 while CS_SYN_SENT, D14/frozen API). */
static void connect_via_state(ntx_utp_conn *c, uint16_t peer_seq) {
    uint8_t st[20];
    size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0, (uint32_t)now_us, 0,
                     4096, peer_seq, 1, NULL, 0);
    (void)ntx_utp_conn_input(c, st, n);
}

static void ack_state(ntx_utp_conn *c, uint16_t ack_nr) {
    uint8_t st[20];
    size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0, (uint32_t)now_us, 0,
                     4096, 100, ack_nr, NULL, 0);
    (void)ntx_utp_conn_input(c, st, n);
}

/* 12. timeout on unacked DATA: single probe, packet_size AND max_window SET
 * to 150 (BEP29 sec.6), doubling, cap 8000 (D15), probe-ACK must not pollute
 * the RTT estimator (D10), recovery via the 150 floor + sec.8 CC growth (D18).
 * Virtual clock starts at an arbitrary origin to prove nothing depends on the
 * wall clock. */
static void test_timeout_probe(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 0x123456789abcULL; /* arbitrary virtual clock origin */
    ntx_utp_conn_ops ops_p = make_ops(&hc);
    ntx_utp_conn *p = ntx_utp_conn_initiate(0x8888, &ops_p);
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n == 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0 &&
              h.ts_us == (uint32_t)0x123456789abcULL,
          "probe: SYN ts comes from clock_fn at arbitrary origin (no wall clock)");
    connect_via_state(p, 100);
    check(ntx_utp_conn_state(p) == NTX_UTP_CS_CONNECTED, "probe: connected via STATE");
    uint8_t data[6000];
    for (int i = 0; i < 6000; i++) data[i] = (uint8_t)(i * 17 + 3);
    check(ntx_utp_conn_write(p, data, 6000) == 6000, "probe: write 6000 queued");
    check(sm_int_in_flight(p) == 4, "probe: 4 DATA in flight (window gate)");
    check(timer_n == 2 && timer_delays[1] == NTX_UTP_INIT_TIMEOUT_MS &&
              sm_int_last_timeout_ms(p) == NTX_UTP_INIT_TIMEOUT_MS &&
              sm_int_rtt(p) == 0,
          "probe: first unacked DATA schedules 1000 ms before any RTT sample");
    now_us += 1500000;
    int before = cap_n;
    ntx_utp_conn_on_timer(p);
    check(cap_n == before + 1, "probe: timer fires exactly one probe packet");
    int pi = cap_n - 1;
    check(cap_parse(&cap[pi], &h, &pl, &pln) == 0 && h.type == NTX_UTP_ST_DATA &&
              h.seq_nr == 2 && pln == 1200 && memcmp(pl, data, 1200) == 0 &&
              h.ts_us == (uint32_t)now_us,
          "probe: single probe = oldest unacked (seq 2, same 1200 B, fresh ts)");
    check(sm_int_packet_size(p) == NTX_UTP_MIN_PKT,
          "probe: packet_size drops to 150 on timeout");
    check(sm_int_max_window(p) == NTX_UTP_MIN_PKT,
          "probe: max_window SET to 150 on timeout per BEP29 sec.6 (not halved)");
    check(timer_n == 3 && timer_delays[2] == 2000,
          "probe: DATA timeout reschedules doubled (2000 ms)");
    now_us += 2000000;
    before = cap_n;
    ntx_utp_conn_on_timer(p);
    check(cap_n == before + 1 && timer_n == 4 && timer_delays[3] == 4000,
          "probe: consecutive DATA timeout doubles again (4000 ms), one probe");
    now_us += 4000000;
    ntx_utp_conn_on_timer(p);
    now_us += 8000000;
    ntx_utp_conn_on_timer(p);
    check(timer_n == 6 && timer_delays[4] == 8000 && timer_delays[5] == 8000 &&
              sm_int_last_timeout_ms(p) == 8000,
          "probe: doubling caps at 8000 ms (D15)");
    /* Spec sec.8 recovery while data is still in flight: a delay-sampled
     * advancing ACK lets ntx_utp_cc_update lift max_window above the 150
     * timeout floor; packet_size stays pinned at the floor until the window
     * reaches the 1200 cap (D18 — pinned fully in test 15). */
    uint8_t cst[20];
    size_t csn = craft(cst, sizeof cst, NTX_UTP_ST_STATE, 0, 0, (uint32_t)now_us,
                       100000, 4096, 100, 3, NULL, 0);
    (void)ntx_utp_conn_input(p, cst, csn);
    check(sm_int_max_window(p) > NTX_UTP_MIN_PKT,
          "probe: CC ACK (ts_diff=100ms) lifts max_window above the 150 floor (sec.8)");
    check(sm_int_packet_size(p) == NTX_UTP_MIN_PKT,
          "probe: packet_size stays at 150 while the window is below the 1200 cap (D18)");
    /* ACK the probe only: the retrans=1 entry must not feed the estimator. */
    ack_state(p, 2);
    check(sm_int_rtt(p) == 0 && sm_int_rtt_var(p) == 0,
          "probe: ACK of retransmitted probe leaves rtt/rtt_var untouched (D10)");
    /* ACK seqs 3..5: window opens; recovery must use the 150 B chunk size. */
    before = cap_n;
    ack_state(p, 5);
    int rec_ok = cap_n > before;
    for (int i = before; i < cap_n; i++) {
        ntx_utp_hdr rh;
        const uint8_t *rpl;
        size_t rpln;
        if (cap_parse(&cap[i], &rh, &rpl, &rpln) != 0 ||
            rh.type != NTX_UTP_ST_DATA || rpln == 0 || rpln > NTX_UTP_MIN_PKT)
            rec_ok = 0;
    }
    check(rec_ok, "probe: recovery path sends remaining data in <=150 B chunks (D3)");
    /* Drain: the timeout SET max_window to 150 (sec.6) and these ACKs carry
     * no delay samples, so the gate admits one 150 B chunk per ACK round. */
    for (int r = 0; r < 64 && (sm_int_in_flight(p) > 0 || sm_int_q_len(p) > 0); r++) {
        uint16_t top = 5;
        for (int i = before; i < cap_n; i++) {
            ntx_utp_hdr rh;
            const uint8_t *rpl;
            size_t rpln;
            if (cap_parse(&cap[i], &rh, &rpl, &rpln) == 0 &&
                rh.type == NTX_UTP_ST_DATA &&
                (int16_t)(rh.seq_nr - top) > 0)
                top = rh.seq_nr;
        }
        ack_state(p, top);
    }
    check(sm_int_in_flight(p) == 0 && sm_int_q_len(p) == 0,
          "probe: full ACK drains in-flight and queue after recovery");
    ntx_utp_conn_free(p);
}

/* 13. RTT/RTT-var estimator: exact integer BEP29 sec.6 formulas
 * (rtt += (sample - rtt)/8; rtt_var += (|sample - rtt| - rtt_var)/4,
 * truncating, var uses the pre-update rtt per D10). */
static void test_rtt_formula(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 200000000;
    ntx_utp_conn_ops ops_r = make_ops(&hc);
    ntx_utp_conn *r = ntx_utp_conn_initiate(0x9999, &ops_r);
    connect_via_state(r, 100);
    check(ntx_utp_conn_state(r) == NTX_UTP_CS_CONNECTED, "rtt: connected");
    uint8_t d[500];
    for (int i = 0; i < 500; i++) d[i] = (uint8_t)(i + 1);
    /* sample 1: 12345 us */
    (void)ntx_utp_conn_write(r, d, 500);
    now_us += 12345;
    ack_state(r, 2);
    check(sm_int_rtt(r) == 1543u, "rtt: (7*0+12345)/8 = 1543 (integer BEP29 sec.6)");
    check(sm_int_rtt_var(r) == 3086u, "rtt: (3*0+12345)/4 = 3086 (integer BEP29 sec.6)");
    /* sample 2: 5000 us; delta uses pre-update rtt 1543 */
    (void)ntx_utp_conn_write(r, d, 500);
    now_us += 5000;
    ack_state(r, 3);
    check(sm_int_rtt(r) == 1975u, "rtt: (7*1543+5000)/8 = 1975");
    check(sm_int_rtt_var(r) == 3178u, "rtt: (3*3086+|5000-1543|)/4 = 3178");
    /* sample 3: equals rtt -> var decays 3/4, rtt stable */
    (void)ntx_utp_conn_write(r, d, 500);
    now_us += 1975;
    ack_state(r, 4);
    check(sm_int_rtt(r) == 1975u, "rtt: sample equal to rtt keeps rtt");
    check(sm_int_rtt_var(r) == 2383u, "rtt: (3*3178+0)/4 = 2383");
    ntx_utp_conn_free(r);
    /* sample across the 32-bit timestamp rollover: 0xFFFFFFF0 -> 0x10 == 32 us */
    h_conn hc2;
    memset(&hc2, 0, sizeof hc2);
    reset_caps();
    now_us = 0xFFFFFFF0ULL;
    ntx_utp_conn_ops ops_w = make_ops(&hc2);
    ntx_utp_conn *w = ntx_utp_conn_initiate(0x999A, &ops_w);
    connect_via_state(w, 100);
    (void)ntx_utp_conn_write(w, d, 300);
    now_us += 32; /* crosses 2^32 */
    ack_state(w, 2);
    check(sm_int_rtt(w) == 4u && sm_int_rtt_var(w) == 8u,
          "rtt: sample wrap-safe across 32-bit ts rollover (delta 32 us)");
    ntx_utp_conn_free(w);
}

/* 14. timeout floor: the sm_flush() rtt-based schedule path must clamp to
 * NTX_UTP_MIN_TIMEOUT_MS (500 ms). That branch needs rtt != 0 while
 * timer_pending == 0, which the public API never presents (the first timer
 * is armed before any sample exists), so seed the estimator via the
 * test-only setter. */
static void test_timeout_floor(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 300000000;
    ntx_utp_conn_ops ops_t = make_ops(&hc);
    uint8_t d[100];
    memset(d, 0xA5, sizeof d);
    ntx_utp_conn *t = ntx_utp_conn_initiate(0xBBBB, &ops_t);
    connect_via_state(t, 100);
    sm_int_set_rtt(t, 250u, 60u); /* (250 + 4*60)/1000 = 0 ms -> floor */
    (void)ntx_utp_conn_write(t, d, 100);
    check(timer_n == 2 && timer_delays[1] == NTX_UTP_MIN_TIMEOUT_MS &&
              sm_int_last_timeout_ms(t) == NTX_UTP_MIN_TIMEOUT_MS,
          "floor: tiny RTT never schedules below the 500 ms floor");
    ntx_utp_conn_free(t);
    memset(&hc, 0, sizeof hc);
    reset_caps();
    ntx_utp_conn *u2 = ntx_utp_conn_initiate(0xBBBB, &ops_t);
    connect_via_state(u2, 100);
    sm_int_set_rtt(u2, 600000u, 0u); /* 600 ms above the floor */
    (void)ntx_utp_conn_write(u2, d, 100);
    check(timer_n == 2 && timer_delays[1] == 600u,
          "floor: timer = (rtt + 4*var)/1000 above the floor (600 ms)");
    ntx_utp_conn_free(u2);
}
/* 15. D18 packet_size recovery: after the sec.6 timeout sets both fields to
 * 150, chunks stay at the floor until the sec.8 CC path has raised
 * max_window back to the 1200 initial cap; the restore then rides the same
 * CC-gated ACK branch and the next flush resumes full-size chunks.
 * (CC growth from the floor is pinned in test 12; here the recovered window
 * is seeded via the test-only setter. The write must exceed the initial
 * window so bytes are still UNSent when the timeout fires — D19: the
 * truncation watermark.) */
static void test_packet_size_recovery(void) {
    h_conn hc;
    memset(&hc, 0, sizeof hc);
    reset_caps();
    now_us = 400000000;
    ntx_utp_conn_ops ops_v = make_ops(&hc);
    ntx_utp_conn *v = ntx_utp_conn_initiate(0xC0DE, &ops_v);
    connect_via_state(v, 100);
    check(ntx_utp_conn_state(v) == NTX_UTP_CS_CONNECTED, "grow: connected");
    uint8_t data[6000];
    for (int i = 0; i < 6000; i++) data[i] = (uint8_t)(i * 29 + 11);
    check(ntx_utp_conn_write(v, data, 6000) == 6000, "grow: write 6000 queued");
    check(sm_int_in_flight(v) == 4 && sm_int_cur_window(v) == 4096,
          "grow: 4 DATA in flight at the 4096 gate, 1904 bytes still unsent");
    ntx_utp_conn_on_timer(v);
    check(sm_int_packet_size(v) == NTX_UTP_MIN_PKT &&
              sm_int_max_window(v) == NTX_UTP_MIN_PKT,
          "grow: timeout set packet_size=max_window=150 (sec.6)");
    /* Simulate the CC having recovered the window to >= the 1200 chunk cap,
     * then deliver a delay-sampled advancing ACK (ts_diff=100ms -> gain > 0)
     * that also drains in-flight bytes so the gate admits the unsent queue
     * again. */
    sm_int_set_max_window(v, 1200);
    uint8_t st[20];
    size_t n = craft(st, sizeof st, NTX_UTP_ST_STATE, 0, 0, (uint32_t)now_us,
                     100000, 4096, 100, 5, NULL, 0);
    int before = cap_n;
    (void)ntx_utp_conn_input(v, st, n);
    check(sm_int_packet_size(v) == NTX_UTP_SM_INIT_PKT,
          "grow: CC-gated ACK restores packet_size to the 1200 cap (D18)");
    check(sm_int_max_window(v) >= 1200,
          "grow: recovered window is kept by the CC update");
    int big_chunk = 0;
    for (int i = before; i < cap_n; i++) {
        ntx_utp_hdr dh;
        const uint8_t *dpl;
        size_t dpln;
        if (cap_parse(&cap[i], &dh, &dpl, &dpln) == 0 &&
            dh.type == NTX_UTP_ST_DATA && dpln > NTX_UTP_MIN_PKT)
            big_chunk = 1;
    }
    check(big_chunk, "grow: post-recovery flush emits chunks larger than 150");
    ntx_utp_conn_free(v);
}

/* ---------------- D6/D20 helpers + coverage ---------------- */

/* Build a CONNECTED initiator/acceptor pair on receive id `base`. The
 * acceptor's ST_STATE is fed back to the initiator so both reach CONNECTED;
 * the acceptor's expected_seq is syn_seq+1 (== 2) so DATA from the initiator
 * (first seq 2) lines up. Caller owns hca/hcb/opa/opb and frees both conns. */
static void mk_connected(ntx_utp_conn **a, ntx_utp_conn **b, h_conn *hca,
                         h_conn *hcb, ntx_utp_conn_ops *opa,
                         ntx_utp_conn_ops *opb, uint16_t base, uint64_t ts) {
    memset(hca, 0, sizeof *hca);
    memset(hcb, 0, sizeof *hcb);
    reset_caps();
    now_us = ts;
    *opa = make_ops(hca);
    *opb = make_ops(hcb);
    *a = ntx_utp_conn_initiate(base, opa);
    *b = ntx_utp_conn_accept(base, 1, (uint32_t)ts, opb);
    uint8_t st[20];
    size_t n = cap[cap_n - 1].n; /* acceptor's ST_STATE is the last emit */
    memcpy(st, cap[cap_n - 1].data, n);
    (void)ntx_utp_conn_input(*a, st, n); /* SYN_SENT -> CONNECTED */
}

/* Inject a crafted ST_DATA into `dst` (BEP29 DATA ignores the ack field). */
static void feed_data_to(ntx_utp_conn *dst, uint16_t conn_id, uint16_t seq,
                         const uint8_t *pl, size_t n) {
    uint8_t buf[NTX_UTP_HDR_LEN + 1500];
    size_t m = craft(buf, sizeof buf, NTX_UTP_ST_DATA, 0, conn_id,
                     (uint32_t)now_us, 0, 4096, seq, 0, pl, n);
    (void)ntx_utp_conn_input(dst, buf, m);
}

/* seq-tagged payload so in-order delivery can be verified byte-exactly. */
static void tag_payload(uint8_t *pl, size_t n, uint16_t seq) {
    for (size_t i = 0; i < n; i++)
        pl[i] = (uint8_t)(((unsigned)seq * 31u + (unsigned)i) & 0xffu);
}

/* 16. D6 reorder window: in-order delivery, bounded OOO buffering, and the
 * window-overflow reject policy (a packet too far ahead of expected_seq is
 * dropped, never buffered, never SACK-acknowledged, and only delivered once
 * it actually becomes the next in-order packet). */
static void test_ooo_window(void) {
    h_conn hca, hcb;
    ntx_utp_conn_ops opa, opb;
    ntx_utp_conn *a, *b;
    mk_connected(&a, &b, &hca, &hcb, &opa, &opb, 0x3300, 7000000);
    uint16_t sid = 0x3301; /* initiator send id */
    uint16_t base = sm_int_expected_seq(b);
    check(base == 2, "ooo: acceptor expected_seq == 2");
    uint8_t pl[64];
    tag_payload(pl, 64, base);
    feed_data_to(b, sid, base, pl, 64);
    check(hcb.n == 64 && memcmp(hcb.buf, pl, 64) == 0, "ooo: in-order p0 delivered");
    /* Window-edge packet (distance == OOO_CAP) is beyond the reorder window. */
    uint16_t far = (uint16_t)(base + NTX_UTP_SM_OOO_CAP + 1u);
    tag_payload(pl, 64, far);
    feed_data_to(b, sid, far, pl, 64);
    check(!sm_int_ooo_has(b, far), "ooo: beyond-window packet rejected (not buffered)");
    check(hcb.n == 64, "ooo: rejected far packet not delivered");
    /* Near OOO packets at distances 2..7 are buffered. */
    for (int d = 2; d <= 7; d++) {
        uint16_t s = (uint16_t)(base + d);
        tag_payload(pl, 64, s);
        feed_data_to(b, sid, s, pl, 64);
    }
    check(sm_int_ooo_count(b) == 6, "ooo: 6 near OOO packets buffered");
    int all = 1;
    for (int d = 2; d <= 7; d++)
        if (!sm_int_ooo_has(b, (uint16_t)(base + d))) all = 0;
    check(all, "ooo: every near OOO seq present in the buffer");
    /* The last SACK (from the base+7 feed) reports the buffered set: expected
     * is base+1, so ack_nr = base and sent bit i == seq base+2+i. Buffered
     * base+2..base+7 -> bits 0..5 -> byte0 0x3F; nothing beyond (far absent). */
    ntx_utp_hdr sh;
    const uint8_t *spl;
    size_t spln;
    int si = cap_n - 1;
    check(si >= 0 && cap_parse(&cap[si], &sh, &spl, &spln) == 0 &&
              sh.type == NTX_UTP_ST_STATE && sh.extension == NTX_UTP_EXT_SACK &&
              sh.ack_nr == base,
          "ooo: SACK emitted for the buffered run");
    if (si >= 0 && cap_parse(&cap[si], &sh, &spl, &spln) == 0) {
        const uint8_t *m = cap[si].data + 22; /* SACK mask start */
        check(m[0] == 0x3F, "ooo: SACK mask claims only the buffered run (0x3F)");
        int tail = 1;
        for (int i = 1; i < 16; i++)
            if (m[i] != 0) tail = 0;
        check(tail, "ooo: SACK mask does not claim the rejected far packet");
    }
    /* Fill the gap at base+1 -> the whole run base..base+7 delivers in order. */
    uint16_t gap = (uint16_t)(base + 1);
    tag_payload(pl, 64, gap);
    feed_data_to(b, sid, gap, pl, 64);
    check(hcb.n == 64 * 8, "ooo: gap fill delivers the buffered run in order");
    int ord = 1;
    for (int k = 0; k < 8; k++) {
        uint8_t exp[64];
        tag_payload(exp, 64, (uint16_t)(base + k));
        if (memcmp(hcb.buf + 64 * (size_t)k, exp, 64) != 0) ord = 0;
    }
    check(ord, "ooo: delivered run is in order base..base+7");
    check(sm_int_ooo_count(b) == 0, "ooo: buffer empty after the drain");
    check(!sm_int_ooo_has(b, far), "ooo: far packet still absent (was rejected)");
    /* A never-buffered packet is delivered the moment it becomes in order. */
    tag_payload(pl, 64, (uint16_t)(base + 8));
    feed_data_to(b, sid, (uint16_t)(base + 8), pl, 64);
    check(hcb.n == 64 * 9, "ooo: never-buffered packet delivered when in order");
    ntx_utp_conn_free(a);
    ntx_utp_conn_free(b);
}

/* 17. D20 FIN-after-OOO: an ST_FIN ahead of the gap records eof_pkt but does
 * not finalise the close until the gap ahead of it is filled and drained. */
static void test_fin_after_ooo(void) {
    h_conn hca, hcb;
    ntx_utp_conn_ops opa, opb;
    ntx_utp_conn *a, *b;
    mk_connected(&a, &b, &hca, &hcb, &opa, &opb, 0x4400, 8000000);
    uint16_t sid = 0x4401;
    uint16_t base = sm_int_expected_seq(b);
    uint8_t pl[64];
    tag_payload(pl, 64, base);
    feed_data_to(b, sid, base, pl, 64);
    tag_payload(pl, 64, (uint16_t)(base + 2));
    feed_data_to(b, sid, (uint16_t)(base + 2), pl, 64);
    check(sm_int_ooo_count(b) == 1 && sm_int_ooo_has(b, (uint16_t)(base + 2)),
          "fin-ooo: p2 buffered ahead of the gap");
    uint16_t fin_seq = (uint16_t)(base + 3); /* next seq after base,base+1,base+2 */
    uint8_t buf[20];
    size_t n = craft(buf, sizeof buf, NTX_UTP_ST_FIN, 0, sid, (uint32_t)now_us, 0, 0,
                     fin_seq, 0, NULL, 0);
    check(ntx_utp_conn_input(b, buf, n) == 0, "fin-ooo: ahead-FIN consumed");
    check(sm_int_eof_pending(b) == 1 && sm_int_eof_seq(b) == fin_seq,
          "fin-ooo: eof recorded pending, not applied");
    check(sm_int_peer_eof(b) == 0, "fin-ooo: peer_eof NOT set while a gap precedes the FIN");
    reset_caps();
    ntx_utp_conn_close(b);
    check(ntx_utp_conn_state(b) == SM_CS_FIN_SENT,
          "fin-ooo: close defers to FIN_SENT (waits for out-of-order)");
    check(hcb.closed == 0, "fin-ooo: closed not fired while OOO is pending");
    /* Fill the gap: drains base+2, expected reaches fin_seq -> finalise. */
    tag_payload(pl, 64, (uint16_t)(base + 1));
    feed_data_to(b, sid, (uint16_t)(base + 1), pl, 64);
    check(hcb.n == 64 * 3, "fin-ooo: gap fill delivers base..base+2 (192B)");
    check(sm_int_eof_pending(b) == 0 && sm_int_peer_eof(b) == 1,
          "fin-ooo: eof applied once the drain reached eof_seq");
    check(ntx_utp_conn_state(b) == NTX_UTP_CS_DESTROYING, "fin-ooo: finalises to DESTROYING");
    check(hcb.closed == 1, "fin-ooo: closed fired after the drain");
    ntx_utp_conn_free(b);
    ntx_utp_conn_free(a);
}

/* 18. RESET-mid-OOO: ST_RESET discards the reorder buffer; buffered data is
 * never delivered and post-reset input is ignored. */
static void test_reset_mid_ooo(void) {
    h_conn hca, hcb;
    ntx_utp_conn_ops opa, opb;
    ntx_utp_conn *a, *b;
    mk_connected(&a, &b, &hca, &hcb, &opa, &opb, 0x5500, 9000000);
    uint16_t sid = 0x5501;
    uint16_t base = sm_int_expected_seq(b);
    uint8_t pl[64];
    tag_payload(pl, 64, base);
    feed_data_to(b, sid, base, pl, 64);
    tag_payload(pl, 64, (uint16_t)(base + 2));
    feed_data_to(b, sid, (uint16_t)(base + 2), pl, 64);
    check(sm_int_ooo_count(b) == 1, "reset-ooo: OOO packet buffered pre-reset");
    uint8_t buf[20];
    size_t n = craft(buf, sizeof buf, NTX_UTP_ST_RESET, 0, sid, (uint32_t)now_us, 0, 0,
                     0, 0, NULL, 0);
    check(ntx_utp_conn_input(b, buf, n) == 0, "reset-ooo: RESET consumed");
    check(ntx_utp_conn_state(b) == NTX_UTP_CS_DESTROYING, "reset-ooo: -> DESTROYING");
    check(hcb.closed == 1, "reset-ooo: closed fired");
    check(sm_int_ooo_count(b) == 0, "reset-ooo: reorder buffer cleared");
    check(hcb.n == 64, "reset-ooo: only the in-order packet was delivered");
    tag_payload(pl, 64, (uint16_t)(base + 1));
    feed_data_to(b, sid, (uint16_t)(base + 1), pl, 64);
    check(hcb.n == 64, "reset-ooo: post-reset input ignored (buffered data never leaks)");
    ntx_utp_conn_free(b);
    ntx_utp_conn_free(a);
}

/* 19. Bidirectional simultaneous traffic: the send-side cumulative-ACK
 * frontier and the receive-side expected frontier are DIFFERENT seq spaces.
 * Regression: one shared acked_frontier field let the receive
 * path (in-order DATA at the acceptor's random base) overwrite the sender's
 * frontier, so the peer's next cumulative ACK computed d <= 0, was treated as
 * stale, and the window stayed shut until the retransmit ladder — the 50%
 * bidirectional flake behind t_utp_bt_handshake's e2f leg. */
static void test_bidirectional_frontiers(void) {
    h_conn hca, hcb;
    ntx_utp_conn_ops opa, opb;
    ntx_utp_conn *a, *b;
    mk_connected(&a, &b, &hca, &hcb, &opa, &opb, 0x6600, 10000000);
    reset_caps();
    uint8_t pa[6000], pb[400];
    for (int i = 0; i < 6000; i++) pa[i] = (uint8_t)(i * 3 + 1);
    for (int i = 0; i < 400; i++) pb[i] = (uint8_t)(255 - i);
    check(ntx_utp_conn_write(a, pa, 6000) == 6000, "bidi: A queues 6000B");
    /* Deliver A's DATA to B: in-order delivery promotes the acceptor to
     * CONNECTED (D14) and opens its write side. */
    for (int i = 0; i < cap_n; i++) {
        ntx_utp_hdr h;
        const uint8_t *pl;
        size_t pln;
        if (cap_parse(&cap[i], &h, &pl, &pln) == 0 &&
            h.type == NTX_UTP_ST_DATA && h.conn_id == 0x6601)
            (void)ntx_utp_conn_input(b, cap[i].data, cap[i].n);
    }
    check(ntx_utp_conn_write(b, pb, 400) == 400, "bidi: B queues 400B (CONNECTED via D14)");
    /* Cross-feed both directions every round. NO crafted STATE acks anywhere:
     * delivery alone must open both windows, riding the receivers' pure acks
     * (D21). Pre-fix the initiator's DATA poisons the acceptor's shared
     * frontier (af := ~7 while its own data sits at det_seq(1)=46034), so the
     * initiator's cumulative acks (ack_nr ~46034) compute d < 0 as int16 —
     * stale forever — and B's 400B never leaves in-flight. */
    for (int round = 0; round < 12; round++) {
        if (sm_int_in_flight(a) == 0 && sm_int_in_flight(b) == 0 &&
            sm_int_q_len(a) == 0 && sm_int_q_len(b) == 0) break;
        for (int i = 0; i < cap_n; i++) {
            ntx_utp_hdr h;
            const uint8_t *pl;
            size_t pln;
            if (cap_parse(&cap[i], &h, &pl, &pln) != 0) continue;
            if (h.conn_id == 0x6601) (void)ntx_utp_conn_input(b, cap[i].data, cap[i].n);
            else if (h.conn_id == 0x6600) (void)ntx_utp_conn_input(a, cap[i].data, cap[i].n);
        }
    }
    check(hcb.n == 6000 && memcmp(hcb.buf, pa, 6000) == 0,
          "bidi: B delivers A's full 6000B (window opened by B's pure acks alone)");
    check(hca.n == 400 && memcmp(hca.buf, pb, 400) == 0,
          "bidi: A delivers B's 400B (window opened by A's pure acks alone)");
    check(sm_int_in_flight(b) == 0,
          "bidi: B's in-flight drains with zero crafted acks (frontier split)");
    check(sm_int_in_flight(a) == 0 && sm_int_q_len(a) == 0 && sm_int_q_len(b) == 0,
          "bidi: both in-flight lists and queues drained");
    ntx_utp_conn_free(a);
    ntx_utp_conn_free(b);
}

/* 20. Pure ST_STATE ack on in-order DATA delivery (BEP29 sec.2: received
 * data must be acknowledged; a payload-less STATE carries it when there is
 * nothing to piggyback). Pre-fix an idle receiver emitted NOTHING and the
 * sender stalled behind the retransmit ladder. */
static void test_pure_ack_on_inorder(void) {
    h_conn hca, hcb;
    ntx_utp_conn_ops opa, opb;
    ntx_utp_conn *a, *b;
    mk_connected(&a, &b, &hca, &hcb, &opa, &opb, 0x7700, 11000000);
    uint16_t sid = 0x7701;
    uint16_t base = sm_int_expected_seq(b);
    reset_caps();
    uint8_t pl[64];
    tag_payload(pl, 64, base);
    feed_data_to(b, sid, base, pl, 64);
    ntx_utp_hdr h;
    const uint8_t *dpl;
    size_t dpln;
    check(cap_n == 1, "pure-ack: in-order delivery emits exactly one segment");
    check(cap_n == 1 && cap_parse(&cap[0], &h, &dpl, &dpln) == 0 &&
              h.type == NTX_UTP_ST_STATE && h.extension == 0 && dpln == 0,
          "pure-ack: the segment is a payload-less bare ST_STATE (no SACK ext)");
    check(cap_n == 1 && h.ack_nr == base,
          "pure-ack: ack_nr carries the cumulative receive frontier");
    check(cap_n == 1 && h.conn_id == 0x7700, "pure-ack: ST_STATE rides the acceptor send id");
    /* ST_STATE consumes no seq_nr (BEP29 sec.2): the next DATA still starts
     * at the acceptor's own deterministic base. */
    reset_caps();
    uint8_t out[10];
    memset(out, 0xA5, sizeof out);
    check(ntx_utp_conn_write(b, out, 10) == 10, "pure-ack: write accepted after the ack");
    check(cap_n == 1 && cap_parse(&cap[0], &h, &dpl, &dpln) == 0 &&
              h.type == NTX_UTP_ST_DATA && h.seq_nr == det_seq(1),
          "pure-ack: STATE did not consume the DATA seq (next DATA == base)");
    /* Out-of-order keeps the SACK cadence — the gap answer is an extended
     * STATE, not a second bare one. */
    reset_caps();
    tag_payload(pl, 64, (uint16_t)(base + 2));
    feed_data_to(b, sid, (uint16_t)(base + 2), pl, 64);
    check(cap_n == 1 && cap_parse(&cap[0], &h, &dpl, &dpln) == 0 &&
              h.type == NTX_UTP_ST_STATE && h.extension == NTX_UTP_EXT_SACK,
          "pure-ack: OOO keeps the SACK cadence (no bare STATE on gaps)");
    ntx_utp_conn_free(a);
    ntx_utp_conn_free(b);
}

/* 21. Lost SYN-ACK recovery (BEP29 sec.4): while SYN_RECV, a retransmitted
 * SYN (same seq — the one we are still waiting for) must re-trigger the
 * ACK-only STATE reply. Dropping it as a collision deadlocks the pair when
 * the original STATE datagram is lost: the initiator's SYN ladder retransmits
 * forever into a silent acceptor (the ASan-timing e2e flake). */
static void test_syn_retransmit_replies_state(void) {
    reset_caps();
    now_us = 12000000;
    h_conn hcb;
    memset(&hcb, 0, sizeof hcb);
    ntx_utp_conn_ops opb = make_ops(&hcb);
    ntx_utp_conn *b = ntx_utp_conn_accept(0x9900, 7, (uint32_t)now_us, &opb);
    check(b != NULL, "synr: accept ok");
    reset_caps();
    uint8_t buf[NTX_UTP_HDR_LEN];
    size_t m = craft(buf, sizeof buf, NTX_UTP_ST_SYN, 0, 0x9900,
                     (uint32_t)now_us, 0, 0, 7, 0, NULL, 0);
    check(ntx_utp_conn_input(b, buf, m) == 0,
          "synr: retransmitted same-seq SYN accepted in SYN_RECV");
    check(cap_n == 1, "synr: SYN retransmit re-emits the handshake STATE");
    ntx_utp_hdr h;
    const uint8_t *pl;
    size_t pln;
    check(cap_n == 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0 &&
              h.type == NTX_UTP_ST_STATE && h.extension == 0 &&
              h.conn_id == 0x9900 && h.ack_nr == 7 && h.seq_nr == det_seq(7),
          "synr: replayed STATE carries the accept reply's fields");
    /* A foreign-seq SYN is a real collision: still refused, silent (D13). */
    reset_caps();
    m = craft(buf, sizeof buf, NTX_UTP_ST_SYN, 0, 0x9900,
              (uint32_t)now_us, 0, 0, 42, 0, NULL, 0);
    check(ntx_utp_conn_input(b, buf, m) == -1,
          "synr: foreign-seq SYN stays a collision (D13)");
    check(cap_n == 0, "synr: collision emits nothing");
    ntx_utp_conn_free(b);

    /* CONNECTED race: the initiator's SYN retransmit overtakes the acceptor's
     * D14 promotion (STATE was delayed, not lost). The stale SYN (seq at/below
     * the receive frontier) must be answered with a STATE, not refused — the
     * glue closes the slot on -1 and the pair would strand forever (the
     * ASan-timing e2e stall). */
    reset_caps();
    now_us = 12100000;
    h_conn hca2, hcb2;
    memset(&hca2, 0, sizeof hca2);
    memset(&hcb2, 0, sizeof hcb2);
    ntx_utp_conn_ops opa2 = make_ops(&hca2);
    ntx_utp_conn_ops opb2 = make_ops(&hcb2);
    ntx_utp_conn *a2 = ntx_utp_conn_initiate(0x9910, &opa2);
    ntx_utp_conn *b2 = ntx_utp_conn_accept(0x9910, 3, (uint32_t)now_us, &opb2);
    (void)ntx_utp_conn_input(a2, cap[cap_n - 1].data, cap[cap_n - 1].n);
    reset_caps();
    uint8_t dbuf[NTX_UTP_HDR_LEN + 8];
    uint8_t dpl[8];
    for (int i = 0; i < 8; i++) dpl[i] = (uint8_t)i;
    size_t dn = craft(dbuf, sizeof dbuf, NTX_UTP_ST_DATA, 0, 0x9911,
                      (uint32_t)now_us, 0, 4096, 4, 0, dpl, 8);
    (void)ntx_utp_conn_input(b2, dbuf, dn); /* D14: b2 -> CONNECTED, frontier 4 */
    reset_caps();
    m = craft(buf, sizeof buf, NTX_UTP_ST_SYN, 0, 0x9910,
              (uint32_t)now_us, 0, 0, 3, 0, NULL, 0);
    check(ntx_utp_conn_input(b2, buf, m) == 0,
          "synr: stale handshake SYN in CONNECTED is answered, not refused");
    check(cap_n == 1 && cap_parse(&cap[0], &h, &pl, &pln) == 0 &&
              h.type == NTX_UTP_ST_STATE && h.ack_nr == 4 &&
              h.seq_nr == det_seq(3),
          "synr: the answer is the cumulative STATE (ack == frontier, seq unconsumed)");
    check(ntx_utp_conn_state(b2) == NTX_UTP_CS_CONNECTED,
          "synr: answering the stale SYN keeps the conn CONNECTED");
    ntx_utp_conn_free(a2);
    ntx_utp_conn_free(b2);
}

int main(void) {
    test_initiate();
    test_accept_handshake();
    test_data_flow();
    test_sack_loss();
    test_fin();
    test_reset();
    test_timeout();
    test_window_zero();
    test_ts_diff_cc();
    test_timeout_probe();
    test_rtt_formula();
    test_timeout_floor();
    test_packet_size_recovery();
    test_ooo_window();
    test_fin_after_ooo();
    test_reset_mid_ooo();
    test_bidirectional_frontiers();
    test_pure_ack_on_inorder();
    test_syn_retransmit_replies_state();
    printf("%s: %s\n", fails ? "FAIL" : "OK",
           fails ? "failures above" : "all checks passed");
    return fails ? 1 : 0;
}
