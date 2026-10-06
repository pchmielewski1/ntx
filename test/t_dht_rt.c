#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "../src/proto/ntx_dht_rt.c"
#include "../src/net/ntx_addr.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static void fill20(uint8_t *buf, uint8_t v) {
    for (int i = 0; i < 20; i++) buf[i] = v;
}

static void mk_id(uint8_t id[20], uint8_t b0, uint8_t b1) {
    memset(id, 0, 20);
    id[0] = b0;
    id[1] = b1;
}

static ntx_dht_node mk_v4(uint8_t b0, uint8_t b1, uint32_t ip_host,
                          uint16_t port, uint64_t seen, uint8_t replied) {
    ntx_dht_node n;
    memset(&n, 0, sizeof n);
    mk_id(n.id, b0, b1);
    ntx_addr_set_v4(&n.addr, htonl(ip_host));
    n.port = port;
    n.last_seen_ms = seen;
    n.replied = replied;
    return n;
}

static int test_init_count_zero(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    memset(&rt, 0xA5, sizeof(rt));
    fill20(self, 0x11);
    ntx_dht_rt_init(&rt, self);
    if (ntx_dht_rt_count(&rt) != 0) return fail("init-count-zero");
    if (memcmp(rt.self_id, self, 20) != 0) return fail("init-self-id");
    return 0;
}

static int test_clear_count_zero(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x22);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_rt_clear(&rt);
    if (ntx_dht_rt_count(&rt) != 0) return fail("clear-count-zero");
    return 0;
}

static int test_clear_keeps_self(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x33);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_rt_clear(&rt);
    if (memcmp(rt.self_id, self, 20) != 0) return fail("clear-keeps-self");
    return 0;
}

static int test_add_reject_zero_addr(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n = mk_v4(0x01, 0x00, 0x01020304u, 6881, 1000, 0);
    ntx_addr_clear(&n.addr);
    if (ntx_dht_rt_add(&rt, &n) != -1) return fail("add-reject-zero-addr");
    if (ntx_dht_rt_count(&rt) != 0) return fail("add-reject-zero-addr-count");
    return 0;
}

static int test_add_reject_port0(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n = mk_v4(0x01, 0x00, 0x01020304u, 0, 1000, 0);
    if (ntx_dht_rt_add(&rt, &n) != -1) return fail("add-reject-port0");
    return 0;
}

static int test_add_reject_self_id(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x44);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n = mk_v4(0x01, 0x00, 0x01020304u, 6881, 1000, 0);
    memcpy(n.id, self, 20);
    if (ntx_dht_rt_add(&rt, &n) != -1) return fail("add-reject-self-id");
    return 0;
}

static int test_add_basic(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n = mk_v4(0x01, 0x00, 0x01020304u, 6881, 1000, 0);
    if (ntx_dht_rt_add(&rt, &n) != 0) return fail("add-basic");
    if (ntx_dht_rt_count(&rt) != 1) return fail("add-basic-count");
    return 0;
}

static int test_add_last_seen_auto(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n = mk_v4(0x01, 0x00, 0x01020304u, 6881, 0, 0);
    if (ntx_dht_rt_add(&rt, &n) != 0) return fail("add-last-seen-auto");
    if (rt.b[0].nodes[0].last_seen_ms == 0) return fail("add-last-seen-auto-val");
    return 0;
}

static int test_add_dedup(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x0A0B0C0Du, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x05, 0x00, 0x0A0B0C0Du, 6881, 2000, 1);
    if (ntx_dht_rt_add(&rt, &a) != 0) return fail("add-dedup-first");
    if (ntx_dht_rt_add(&rt, &b) != 0) return fail("add-dedup-second");
    if (ntx_dht_rt_count(&rt) != 1) return fail("add-dedup-count");
    if (memcmp(rt.b[0].nodes[0].id, a.id, 20) != 0) return fail("add-dedup-id");
    if (rt.b[0].nodes[0].last_seen_ms != 2000) return fail("add-dedup-seen");
    if (rt.b[0].nodes[0].replied != 1) return fail("add-dedup-replied");
    return 0;
}

static int test_add_dedup_cross_bucket(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x0A0B0C0Du, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x11, 0x00, 0x0A0B0C0Du, 6881, 2000, 0);
    if (ntx_dht_rt_add(&rt, &a) != 0) return fail("add-dedup-xb-first");
    if (ntx_dht_rt_add(&rt, &b) != 0) return fail("add-dedup-xb-second");
    if (ntx_dht_rt_count(&rt) != 1) return fail("add-dedup-xb-count");
    return 0;
}

static int test_closest_v4_order(void) {
    ntx_dht_rt rt;
    uint8_t self[20], target[20];
    ntx_dht_node out[8];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x01020304u, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x02, 0x00, 0x05060708u, 6881, 1000, 0);
    ntx_dht_node c = mk_v4(0x00, 0x01, 0x090A0B0Cu, 6881, 1000, 0);
    if (ntx_dht_rt_add(&rt, &a) != 0) return fail("closest-v4-add-a");
    if (ntx_dht_rt_add(&rt, &b) != 0) return fail("closest-v4-add-b");
    if (ntx_dht_rt_add(&rt, &c) != 0) return fail("closest-v4-add-c");
    fill20(target, 0x00);
    if (ntx_dht_rt_get_closest(&rt, target, out, 8) != 3) return fail("closest-v4-n");
    if (memcmp(out[0].id, c.id, 20) != 0) return fail("closest-v4-0");
    if (memcmp(out[1].id, a.id, 20) != 0) return fail("closest-v4-1");
    if (memcmp(out[2].id, b.id, 20) != 0) return fail("closest-v4-2");
    return 0;
}

static int test_closest_v4_cap2(void) {
    ntx_dht_rt rt;
    uint8_t self[20], target[20];
    ntx_dht_node out[8];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x01020304u, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x02, 0x00, 0x05060708u, 6881, 1000, 0);
    ntx_dht_node c = mk_v4(0x00, 0x01, 0x090A0B0Cu, 6881, 1000, 0);
    ntx_dht_rt_add(&rt, &a);
    ntx_dht_rt_add(&rt, &b);
    ntx_dht_rt_add(&rt, &c);
    fill20(target, 0x00);
    if (ntx_dht_rt_get_closest(&rt, target, out, 2) != 2) return fail("closest-v4-cap2-n");
    if (memcmp(out[0].id, c.id, 20) != 0) return fail("closest-v4-cap2-0");
    if (memcmp(out[1].id, a.id, 20) != 0) return fail("closest-v4-cap2-1");
    return 0;
}

static int test_closest_v6(void) {
    ntx_dht_rt rt;
    uint8_t self[20], target[20], v6[16];
    ntx_dht_node out[8], n;
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    memset(&n, 0, sizeof n);
    mk_id(n.id, 0x03, 0x00);
    memset(v6, 0, 16);
    v6[15] = 1; /* ::1 */
    ntx_addr_set_v6(&n.addr, v6);
    n.port = 1750;
    n.last_seen_ms = 1000;
    if (ntx_dht_rt_add(&rt, &n) != 0) return fail("closest-v6-add");
    fill20(target, 0x00);
    if (ntx_dht_rt_get_closest(&rt, target, out, 8) != 1) return fail("closest-v6-n");
    if (!ntx_addr_is_v6(&out[0].addr)) return fail("closest-v6-family");
    if (out[0].port != 1750) return fail("closest-v6-port");
    if (out[0].addr.u.v6[15] != 1) return fail("closest-v6-ip");
    return 0;
}

static int test_closest_empty(void) {
    ntx_dht_rt rt;
    uint8_t self[20], target[20];
    ntx_dht_node out[8];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    fill20(target, 0x00);
    if (ntx_dht_rt_get_closest(&rt, target, out, 8) != 0) return fail("closest-empty");
    return 0;
}

static int test_closest_cap0(void) {
    ntx_dht_rt rt;
    uint8_t self[20], target[20];
    ntx_dht_node out[8];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n = mk_v4(0x01, 0x00, 0x01020304u, 6881, 1000, 0);
    ntx_dht_rt_add(&rt, &n);
    fill20(target, 0x00);
    if (ntx_dht_rt_get_closest(&rt, target, out, 0) != 0) return fail("closest-cap0");
    return 0;
}

static void fill_bucket0(ntx_dht_rt *rt, uint8_t replied, uint64_t base_seen) {
    for (int i = 0; i < NTX_DHT_K; i++) {
        ntx_dht_node n = mk_v4((uint8_t)i, 0x00,
                               0x0A000000u | (uint32_t)(i + 1),
                               (uint16_t)(6881 + i), base_seen + 1000u * (uint64_t)(i + 1),
                               replied);
        (void)ntx_dht_rt_add(rt, &n); /* self=0 → bucket 0 */
    }
}

static int test_full_bucket_replied_evicts_oldest_nonreplied(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    self[0] = 0x08;
    ntx_dht_rt_init(&rt, self);
    fill_bucket0(&rt, 0, 0);
    ntx_dht_node n9 = mk_v4(0x08, 0x01, 0x0A0000FFu, 6890, 9000, 1);
    if (ntx_dht_rt_add(&rt, &n9) != 0) return fail("full-replied-add");
    if (ntx_dht_rt_count(&rt) != 8) return fail("full-replied-count");
    if (rt.b[0].n != 8) return fail("full-replied-bucket");
    int found_old = 0, found_new = 0;
    for (int i = 0; i < rt.b[0].n; i++) {
        if (rt.b[0].nodes[i].id[0] == 0x00) found_old = 1;
        if (rt.b[0].nodes[i].id[0] == 0x08) found_new = 1;
    }
    if (found_old) return fail("full-replied-old-still");
    if (!found_new) return fail("full-replied-new-missing");
    if (rt.n_repl != 1) return fail("full-replied-repl-n");
    if (rt.repl[0].id[0] != 0x00) return fail("full-replied-repl-id");
    if (rt.repl[0].last_seen_ms != 1000) return fail("full-replied-repl-seen");
    return 0;
}

static int test_full_bucket_all_replied_evicts_oldest(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    self[0] = 0x08;
    ntx_dht_rt_init(&rt, self);
    fill_bucket0(&rt, 1, 0);
    ntx_dht_node n9 = mk_v4(0x08, 0x01, 0x0A0000FFu, 6890, 9000, 1);
    if (ntx_dht_rt_add(&rt, &n9) != 0) return fail("full-allreplied-add");
    if (ntx_dht_rt_count(&rt) != 8) return fail("full-allreplied-count");
    int found_old = 0;
    for (int i = 0; i < rt.b[0].n; i++)
        if (rt.b[0].nodes[i].id[0] == 0x00) found_old = 1;
    if (found_old) return fail("full-allreplied-old-still");
    if (rt.n_repl != 1 || rt.repl[0].id[0] != 0x00) return fail("full-allreplied-repl");
    return 0;
}

static int test_full_bucket_nonreplied_to_repl(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    self[0] = 0x08;
    ntx_dht_rt_init(&rt, self);
    fill_bucket0(&rt, 0, 0);
    ntx_dht_node n9 = mk_v4(0x08, 0x01, 0x0A0000FFu, 6890, 9000, 0);
    if (ntx_dht_rt_add(&rt, &n9) != 0) return fail("full-nonreplied-add");
    if (ntx_dht_rt_count(&rt) != 8) return fail("full-nonreplied-count");
    int found_new = 0;
    for (int i = 0; i < rt.b[0].n; i++)
        if (rt.b[0].nodes[i].id[0] == 0x08) found_new = 1;
    if (found_new) return fail("full-nonreplied-in-bucket");
    if (rt.n_repl != 1) return fail("full-nonreplied-repl-n");
    if (rt.repl[0].id[0] != 0x08) return fail("full-nonreplied-repl-id");
    return 0;
}

static int test_repl_fifo_cap(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    fill_bucket0(&rt, 0, 0);
    for (int i = 0; i < 9; i++) {
        ntx_dht_node n = mk_v4((uint8_t)i, 0x01,
                               0x0B000000u | (uint32_t)(i + 1),
                               (uint16_t)(7000 + i), 9000u + 100u * (uint64_t)i, 0);
        /* id[0] = i → bucket 0 (full); replied=0 → each goes to repl */
        (void)ntx_dht_rt_add(&rt, &n);
    }
    if (rt.n_repl != NTX_DHT_RT_REPL) return fail("repl-fifo-cap-n");
    if (rt.repl[0].id[0] != 1) return fail("repl-fifo-cap-first");
    if (rt.repl[7].id[0] != 8) return fail("repl-fifo-cap-last");
    return 0;
}

static int test_expire(void) {
    ntx_dht_rt rt;
    uint8_t self[20];
    const uint64_t min_ms = 60u * 1000u;
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node old = mk_v4(0x01, 0x00, 0x01020304u, 6881, 4u * min_ms, 0);
    ntx_dht_node fresh = mk_v4(0x02, 0x00, 0x05060708u, 6881, 6u * min_ms, 0);
    ntx_dht_node exact = mk_v4(0x03, 0x00, 0x090A0B0Cu, 6881, 5u * min_ms, 0);
    ntx_dht_rt_add(&rt, &old);
    ntx_dht_rt_add(&rt, &fresh);
    ntx_dht_rt_add(&rt, &exact);
    rt.repl[0] = old;
    rt.n_repl = 1;
    uint64_t now = 20u * min_ms;
    if (ntx_dht_rt_expire(&rt, now) != 2) return fail("expire-removed");
    if (ntx_dht_rt_count(&rt) != 2) return fail("expire-count");
    if (rt.n_repl != 0) return fail("expire-repl");
    int found_fresh = 0, found_exact = 0;
    for (int i = 0; i < NTX_DHT_RT_BUCKETS; i++)
        for (int j = 0; j < rt.b[i].n; j++) {
            if (rt.b[i].nodes[j].id[0] == 0x02) found_fresh = 1;
            if (rt.b[i].nodes[j].id[0] == 0x03) found_exact = 1;
        }
    if (!found_fresh) return fail("expire-fresh-kept");
    if (!found_exact) return fail("expire-exact-kept");
    return 0;
}

int main(void) {
    if (test_init_count_zero() != 0) return 1;
    printf("PASS init-count-zero\n");
    if (test_clear_count_zero() != 0) return 1;
    printf("PASS clear-count-zero\n");
    if (test_clear_keeps_self() != 0) return 1;
    printf("PASS clear-keeps-self\n");
    if (test_add_reject_zero_addr() != 0) return 1;
    printf("PASS add-reject-zero-addr\n");
    if (test_add_reject_port0() != 0) return 1;
    printf("PASS add-reject-port0\n");
    if (test_add_reject_self_id() != 0) return 1;
    printf("PASS add-reject-self-id\n");
    if (test_add_basic() != 0) return 1;
    printf("PASS add-basic\n");
    if (test_add_last_seen_auto() != 0) return 1;
    printf("PASS add-last-seen-auto\n");
    if (test_add_dedup() != 0) return 1;
    printf("PASS add-dedup\n");
    if (test_add_dedup_cross_bucket() != 0) return 1;
    printf("PASS add-dedup-cross-bucket\n");
    if (test_closest_v4_order() != 0) return 1;
    printf("PASS closest-v4-order\n");
    if (test_closest_v4_cap2() != 0) return 1;
    printf("PASS closest-v4-cap2\n");
    if (test_closest_v6() != 0) return 1;
    printf("PASS closest-v6\n");
    if (test_closest_empty() != 0) return 1;
    printf("PASS closest-empty\n");
    if (test_closest_cap0() != 0) return 1;
    printf("PASS closest-cap0\n");
    if (test_full_bucket_replied_evicts_oldest_nonreplied() != 0) return 1;
    printf("PASS full-bucket-replied-evicts-oldest-nonreplied\n");
    if (test_full_bucket_all_replied_evicts_oldest() != 0) return 1;
    printf("PASS full-bucket-all-replied-evicts-oldest\n");
    if (test_full_bucket_nonreplied_to_repl() != 0) return 1;
    printf("PASS full-bucket-nonreplied-to-repl\n");
    if (test_repl_fifo_cap() != 0) return 1;
    printf("PASS repl-fifo-cap\n");
    if (test_expire() != 0) return 1;
    printf("PASS expire\n");
    return 0;
}
