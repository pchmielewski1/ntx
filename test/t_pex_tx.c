#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "../src/net/ntx_addr.c"
#include "../src/core/ntx_pex_tx.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static ntx_addr v4addr(uint8_t o1, uint8_t o2, uint8_t o3, uint8_t o4) {
    ntx_addr a;
    uint8_t b[4] = { o1, o2, o3, o4 };
    uint32_t ip;
    memcpy(&ip, b, 4);
    ntx_addr_set_v4(&a, ip);
    return a;
}

static ntx_addr v6addr(uint8_t last) {
    ntx_addr a;
    uint8_t b[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, last };
    ntx_addr_set_v6(&a, b);
    return a;
}

typedef struct {
    uint32_t a4[50], d4[50];
    uint16_t ap4[50], dp4[50];
    uint8_t a6[50][16], d6[50][16];
    uint16_t ap6[50], dp6[50];
    int na4, na6, nd4, nd6;
} bufs_t;

static void bufs_reset(bufs_t *b) {
    b->na4 = b->na6 = b->nd4 = b->nd6 = 0;
}

static int drain_bufs(ntx_pex_tx *q, bufs_t *b) {
    return ntx_pex_tx_drain(q, b->a4, b->ap4, &b->na4, b->a6, b->ap6, &b->na6,
                            b->d4, b->dp4, &b->nd4, b->d6, b->dp6, &b->nd6, 50, 50);
}

static int peek_bufs(ntx_pex_tx *q, bufs_t *b) {
    return ntx_pex_tx_peek(q, b->a4, b->ap4, &b->na4, b->a6, b->ap6, &b->na6,
                           b->d4, b->dp4, &b->nd4, b->d6, b->dp6, &b->nd6, 50, 50);
}

static int lists_equal(const bufs_t *x, const bufs_t *y) {
    if (x->na4 != y->na4 || x->na6 != y->na6 || x->nd4 != y->nd4 || x->nd6 != y->nd6)
        return 0;
    for (int i = 0; i < x->na4; i++)
        if (x->a4[i] != y->a4[i] || x->ap4[i] != y->ap4[i]) return 0;
    for (int i = 0; i < x->na6; i++)
        if (memcmp(x->a6[i], y->a6[i], 16) != 0 || x->ap6[i] != y->ap6[i]) return 0;
    for (int i = 0; i < x->nd4; i++)
        if (x->d4[i] != y->d4[i] || x->dp4[i] != y->dp4[i]) return 0;
    for (int i = 0; i < x->nd6; i++)
        if (memcmp(x->d6[i], y->d6[i], 16) != 0 || x->dp6[i] != y->dp6[i]) return 0;
    return 1;
}

/* a1,a2,v6::10 advertised; 10.2.0.1 + v6::20 dropped; 10.1.0.3 + v6::11 pending add */
static void build_mixed_state(ntx_pex_tx *q) {
    ntx_pex_tx_init(q);
    ntx_addr a1 = v4addr(10, 1, 0, 1);
    ntx_addr a2 = v4addr(10, 1, 0, 2);
    ntx_addr a3 = v6addr(0x10);
    ntx_pex_tx_on_connected(q, &a1, 6881);
    ntx_pex_tx_on_connected(q, &a2, 6881);
    ntx_pex_tx_on_connected(q, &a3, 6881);
    ntx_addr d1 = v4addr(10, 2, 0, 1);
    ntx_addr d2 = v6addr(0x20);
    ntx_pex_tx_on_connected(q, &d1, 6881);
    ntx_pex_tx_on_connected(q, &d2, 6881);
    bufs_t b;
    bufs_reset(&b);
    (void)drain_bufs(q, &b); /* advertise a1,a2,a3,d1,d2 */
    ntx_pex_tx_on_disconnected(q, &d1, 6881); /* d1 -> pending_drop */
    ntx_pex_tx_on_disconnected(q, &d2, 6881); /* d2 -> pending_drop */
    ntx_addr a4 = v4addr(10, 1, 0, 3);
    ntx_addr a5 = v6addr(0x11);
    ntx_pex_tx_on_connected(q, &a4, 6881);
    ntx_pex_tx_on_connected(q, &a5, 6881);
}

static int test_connect_v4_drain(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    ntx_addr a = v4addr(10, 0, 0, 2);
    ntx_pex_tx_on_connected(&q, &a, 6881);
    bufs_t b;
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != 0) return fail("c1_drain_ret");
    if (b.na4 != 1 || b.nd4 != 0 || b.na6 != 0 || b.nd6 != 0) return fail("c1_counts");
    uint32_t exp;
    uint8_t eb[4] = { 10, 0, 0, 2 };
    memcpy(&exp, eb, 4);
    if (b.a4[0] != exp || b.ap4[0] != 6881) return fail("c1_vals");
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != -1) return fail("c1_drain2_ret");
    if (b.na4 || b.na6 || b.nd4 || b.nd6) return fail("c1_drain2_counts");
    return 0;
}

static int test_elision(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    ntx_addr a = v4addr(10, 0, 0, 3);
    ntx_pex_tx_on_connected(&q, &a, 6881);
    ntx_pex_tx_on_disconnected(&q, &a, 6881); /* before drain */
    bufs_t b;
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != -1) return fail("c2_ret");
    if (b.na4 || b.na6 || b.nd4 || b.nd6) return fail("c2_counts");
    return 0;
}

static int test_added_then_dropped(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    ntx_addr a = v4addr(10, 0, 0, 4);
    ntx_pex_tx_on_connected(&q, &a, 6881);
    bufs_t b;
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != 0) return fail("c3_added_ret");
    if (b.na4 != 1 || b.nd4 != 0) return fail("c3_added_counts");
    ntx_pex_tx_on_disconnected(&q, &a, 6881);
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != 0) return fail("c3_drop_ret");
    if (b.nd4 != 1 || b.na4 != 0) return fail("c3_drop_counts");
    uint32_t exp;
    uint8_t eb[4] = { 10, 0, 0, 4 };
    memcpy(&exp, eb, 4);
    if (b.d4[0] != exp || b.dp4[0] != 6881) return fail("c3_drop_vals");
    return 0;
}

static int test_dedup(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    ntx_addr a = v4addr(10, 0, 0, 5);
    ntx_pex_tx_on_connected(&q, &a, 6881);
    ntx_pex_tx_on_connected(&q, &a, 6881); /* same addr:port again */
    bufs_t b;
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != 0) return fail("c4_ret");
    if (b.na4 != 1) return fail("c4_dedup");
    return 0;
}

static int test_cap_70x(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    bufs_t b;
    for (int i = 1; i <= 70; i++) {
        ntx_addr a = v4addr(10, 0, 1, (uint8_t)i);
        ntx_pex_tx_on_connected(&q, &a, 6881);
        bufs_reset(&b);
        if (drain_bufs(&q, &b) != 0) return fail("c5_drain_ret");
        if (b.na4 > 50 || b.nd4 > 50) return fail("c5_cap");
        ntx_pex_tx_on_disconnected(&q, &a, 6881);
    }
    return 0;
}

static int test_v6_lifecycle(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    ntx_addr a = v6addr(0x07); /* 2001:db8::7 */
    ntx_pex_tx_on_connected(&q, &a, 6881);
    bufs_t b;
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != 0) return fail("c6_added_ret");
    if (b.na6 != 1 || b.na4 != 0 || b.nd6 != 0 || b.nd4 != 0) return fail("c6_added_counts");
    uint8_t exp[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07 };
    if (memcmp(b.a6[0], exp, 16) != 0 || b.ap6[0] != 6881) return fail("c6_added_vals");
    ntx_pex_tx_on_disconnected(&q, &a, 6881);
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != 0) return fail("c6_drop_ret");
    if (b.nd6 != 1 || b.na6 != 0 || b.nd4 != 0 || b.na4 != 0) return fail("c6_drop_counts");
    if (memcmp(b.d6[0], exp, 16) != 0 || b.dp6[0] != 6881) return fail("c6_drop_vals");
    return 0;
}

static int test_zero_ignored(void) {
    ntx_pex_tx q;
    ntx_pex_tx_init(&q);
    ntx_addr z;
    ntx_addr_clear(&z); /* family 0, all zero */
    ntx_pex_tx_on_connected(&q, &z, 6881);
    ntx_addr z4 = v4addr(0, 0, 0, 0); /* 0.0.0.0 */
    ntx_pex_tx_on_connected(&q, &z4, 6881);
    ntx_addr a = v4addr(10, 0, 0, 9);
    ntx_pex_tx_on_connected(&q, &a, 0); /* port 0 */
    bufs_t b;
    bufs_reset(&b);
    if (drain_bufs(&q, &b) != -1) return fail("c7_ret");
    if (b.na4 || b.na6 || b.nd4 || b.nd6) return fail("c7_counts");
    return 0;
}

static int test_peek_commit(void) {
    ntx_pex_tx q;
    build_mixed_state(&q);
    bufs_t p1, p2, p3;
    bufs_reset(&p1);
    if (peek_bufs(&q, &p1) != 0) return fail("c8_peek1_ret");
    if (p1.na4 != 1 || p1.na6 != 1 || p1.nd4 != 1 || p1.nd6 != 1) return fail("c8_peek1_counts");
    bufs_reset(&p2);
    if (peek_bufs(&q, &p2) != 0) return fail("c8_peek2_ret");
    if (!lists_equal(&p1, &p2)) return fail("c8_peek_stable");
    ntx_pex_tx_commit(&q, p1.na4, p1.na6, p1.nd4, p1.nd6);
    bufs_reset(&p3);
    if (peek_bufs(&q, &p3) != -1) return fail("c8_peek3_ret");
    if (p3.na4 || p3.na6 || p3.nd4 || p3.nd6) return fail("c8_peek3_counts");

    /* drain() == peek()+commit() on an identical mixed state */
    ntx_pex_tx q1, q2;
    build_mixed_state(&q1);
    build_mixed_state(&q2);
    bufs_t d1, k1;
    bufs_reset(&d1);
    if (drain_bufs(&q1, &d1) != 0) return fail("c8_drain_ret");
    bufs_reset(&k1);
    if (peek_bufs(&q2, &k1) != 0) return fail("c8_peek_ret");
    ntx_pex_tx_commit(&q2, k1.na4, k1.na6, k1.nd4, k1.nd6);
    if (!lists_equal(&d1, &k1)) return fail("c8_drain_eq_peek_commit");
    return 0;
}

int main(void) {
    if (test_connect_v4_drain() != 0) return 1;
    printf("PASS tx_connect_v4_drain\n");
    if (test_elision() != 0) return 1;
    printf("PASS tx_elision\n");
    if (test_added_then_dropped() != 0) return 1;
    printf("PASS tx_added_then_dropped\n");
    if (test_dedup() != 0) return 1;
    printf("PASS tx_dedup\n");
    if (test_cap_70x() != 0) return 1;
    printf("PASS tx_cap_70x\n");
    if (test_v6_lifecycle() != 0) return 1;
    printf("PASS tx_v6_lifecycle\n");
    if (test_zero_ignored() != 0) return 1;
    printf("PASS tx_zero_ignored\n");
    if (test_peek_commit() != 0) return 1;
    printf("PASS tx_peek_commit\n");
    return 0;
}
