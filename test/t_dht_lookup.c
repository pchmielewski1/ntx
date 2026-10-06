#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"

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

static int lk_find0(const ntx_dht_lookup *lk, uint8_t b0) {
    for (int i = 0; i < lk->n_known; i++)
        if (lk->known[i].id[0] == b0) return i;
    return -1;
}

static int test_init(void) {
    ntx_dht_lookup lk;
    uint8_t hash[20];
    fill20(hash, 0x7A);
    ntx_dht_lookup_init(&lk, hash, 1234);
    if (lk.done != 0) return fail("init-done");
    if (lk.n_known != 0) return fail("init-n-known");
    if (lk.n_inflight != 0) return fail("init-n-inflight");
    if (lk.start_ms != 1234) return fail("init-start");
    if (memcmp(lk.hash, hash, 20) != 0) return fail("init-hash");
    return 0;
}

static int test_seed_three_v4(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x0A000001u, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x02, 0x00, 0x0A000002u, 6881, 1000, 0);
    ntx_dht_node c = mk_v4(0x03, 0x00, 0x0A000003u, 6881, 1000, 0);
    ntx_dht_rt_add(&rt, &a);
    ntx_dht_rt_add(&rt, &b);
    ntx_dht_rt_add(&rt, &c);
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    int n = ntx_dht_lookup_seed(&lk, &rt);
    if (n != 3) return fail("seed3-n");
    if (lk.n_known != 3) return fail("seed3-n-known");
    if (lk.done != 0) return fail("seed3-done");
    if (lk.known[0].id[0] != 0x01) return fail("seed3-order0");
    if (lk.known[1].id[0] != 0x02) return fail("seed3-order1");
    if (lk.known[2].id[0] != 0x03) return fail("seed3-order2");
    return 0;
}

static int test_seed_empty(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    int n = ntx_dht_lookup_seed(&lk, &rt);
    if (n != 0) return fail("seed-empty-n");
    if (lk.n_known != 0) return fail("seed-empty-n-known");
    if (lk.done != 1) return fail("seed-empty-done");
    return 0;
}

static int test_seed_v6(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20], v6[16];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node n;
    memset(&n, 0, sizeof n);
    mk_id(n.id, 0x05, 0x00);
    memset(v6, 0, 16);
    v6[15] = 1;
    ntx_addr_set_v6(&n.addr, v6);
    n.port = 1750;
    n.last_seen_ms = 1000;
    ntx_dht_rt_add(&rt, &n);
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    int nseed = ntx_dht_lookup_seed(&lk, &rt);
    if (nseed != 1) return fail("seed-v6-n");
    if (!ntx_addr_is_v6(&lk.known[0].addr)) return fail("seed-v6-family");
    if (lk.known[0].port != 1750) return fail("seed-v6-port");
    return 0;
}

static int test_pick_alpha(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    ntx_dht_node out[NTX_DHT_LK_KNOWN];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    for (int i = 1; i <= 5; i++) {
        ntx_dht_node n = mk_v4((uint8_t)i, 0x00, 0x0A000000u + (uint32_t)i, 6881, 1000, 0);
        ntx_dht_rt_add(&rt, &n);
    }
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    int n1 = ntx_dht_lookup_pick(&lk, out, NTX_DHT_ALPHA);
    if (n1 != 3) return fail("pick1-n");
    if (out[0].id[0] != 0x01) return fail("pick1-0");
    if (out[1].id[0] != 0x02) return fail("pick1-1");
    if (out[2].id[0] != 0x03) return fail("pick1-2");
    if (lk.n_inflight != 3) return fail("pick1-inflight");
    if (lk.queried[0] != 1 || lk.inflight[0] != 1) return fail("pick1-flags");
    int n2 = ntx_dht_lookup_pick(&lk, out, NTX_DHT_ALPHA);
    if (n2 != 2) return fail("pick2-n");
    if (out[0].id[0] != 0x04) return fail("pick2-0");
    if (out[1].id[0] != 0x05) return fail("pick2-1");
    if (lk.n_inflight != 5) return fail("pick2-inflight");
    int n3 = ntx_dht_lookup_pick(&lk, out, NTX_DHT_ALPHA);
    if (n3 != 0) return fail("pick3-n");
    if (lk.done != 1) return fail("pick3-done");
    int n4 = ntx_dht_lookup_pick(&lk, out, NTX_DHT_ALPHA);
    if (n4 != 0) return fail("pick4-n");
    return 0;
}

static int test_pick_cap(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    ntx_dht_node out[NTX_DHT_LK_KNOWN];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    for (int i = 1; i <= 5; i++) {
        ntx_dht_node n = mk_v4((uint8_t)i, 0x00, 0x0A000000u + (uint32_t)i, 6881, 1000, 0);
        ntx_dht_rt_add(&rt, &n);
    }
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    int n1 = ntx_dht_lookup_pick(&lk, out, 2);
    if (n1 != 2) return fail("pickcap-n");
    if (out[0].id[0] != 0x01) return fail("pickcap-0");
    if (out[1].id[0] != 0x02) return fail("pickcap-1");
    if (lk.n_inflight != 2) return fail("pickcap-inflight");
    return 0;
}

static int test_two_rounds_finish(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    ntx_dht_node out[NTX_DHT_LK_KNOWN];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x0A000001u, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x02, 0x00, 0x0A000002u, 6881, 1000, 0);
    ntx_dht_node c = mk_v4(0x03, 0x00, 0x0A000003u, 6881, 1000, 0);
    ntx_dht_rt_add(&rt, &a);
    ntx_dht_rt_add(&rt, &b);
    ntx_dht_rt_add(&rt, &c);
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    if (lk.n_known != 3) return fail("2r-seed");
    if (ntx_dht_lookup_pick(&lk, out, NTX_DHT_ALPHA) != 3) return fail("2r-pick1");
    if (lk.n_inflight != 3) return fail("2r-pick1-inflight");
    ntx_dht_node d = mk_v4(0x04, 0x00, 0x0A000004u, 6881, 0, 0);
    ntx_dht_node e = mk_v4(0x05, 0x00, 0x0A000005u, 6881, 0, 0);
    ntx_dht_node f = mk_v4(0x06, 0x00, 0x0A000006u, 6881, 0, 0);
    ntx_dht_node r1[3] = { d, e, f };
    ntx_dht_lookup_on_response(&lk, a.id, r1, 3, 1000);
    int ai = lk_find0(&lk, 0x01);
    if (ai < 0 || lk.known[ai].replied != 1) return fail("2r-resp-replied");
    if (lk.n_known != 6) return fail("2r-n-known");
    int di = lk_find0(&lk, 0x04);
    if (di < 0 || lk.known[di].last_seen_ms != 1000) return fail("2r-new-seen");
    ntx_dht_lookup_inflight_done(&lk, 0);
    ntx_dht_lookup_inflight_done(&lk, 1);
    ntx_dht_lookup_inflight_done(&lk, 2);
    if (lk.n_inflight != 0) return fail("2r-inflight0");
    if (ntx_dht_lookup_pick(&lk, out, NTX_DHT_ALPHA) != 3) return fail("2r-pick2");
    if (out[0].id[0] != 0x04 || out[1].id[0] != 0x05 || out[2].id[0] != 0x06)
        return fail("2r-pick2-order");
    ntx_dht_lookup_on_response(&lk, d.id, &d, 1, 2000);
    int d2 = lk_find0(&lk, 0x04);
    if (d2 < 0 || lk.known[d2].replied != 1) return fail("2r-resp2-replied");
    if (lk.n_known != 6) return fail("2r-dedup-n");
    ntx_dht_lookup_inflight_done(&lk, 3);
    ntx_dht_lookup_inflight_done(&lk, 4);
    ntx_dht_lookup_inflight_done(&lk, 5);
    if (lk.n_inflight != 0) return fail("2r-inflight0b");
    ntx_dht_lookup_finish_check(&lk, 3000);
    if (lk.done != 1) return fail("2r-done");
    return 0;
}

static int test_timeout(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x0A000001u, 6881, 1000, 0);
    ntx_dht_rt_add(&rt, &a);
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    ntx_dht_lookup_finish_check(&lk, NTX_DHT_LOOKUP_MAX_MS);
    if (lk.done != 0) return fail("timeout-boundary");
    ntx_dht_lookup_finish_check(&lk, NTX_DHT_LOOKUP_MAX_MS + 1);
    if (lk.done != 1) return fail("timeout-done");
    return 0;
}

static int test_responder_added(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    ntx_dht_node a = mk_v4(0x01, 0x00, 0x0A000001u, 6881, 1000, 0);
    ntx_dht_node b = mk_v4(0x02, 0x00, 0x0A000002u, 6881, 1000, 0);
    ntx_dht_rt_add(&rt, &a);
    ntx_dht_rt_add(&rt, &b);
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    ntx_dht_node x = mk_v4(0x0F, 0x00, 0x0A00000Fu, 6881, 0, 0);
    ntx_dht_node d = mk_v4(0x07, 0x00, 0x0A000007u, 6881, 0, 0);
    ntx_dht_node nodes[2] = { x, d };
    ntx_dht_lookup_on_response(&lk, x.id, nodes, 2, 500);
    if (lk.n_known != 4) return fail("respadd-n");
    int xi = lk_find0(&lk, 0x0F);
    if (xi < 0 || lk.known[xi].replied != 1) return fail("respadd-x-replied");
    int di = lk_find0(&lk, 0x07);
    if (di < 0 || lk.known[di].replied != 0) return fail("respadd-d-replied");
    return 0;
}

static int test_replace_full(void) {
    ntx_dht_lookup lk;
    uint8_t hash[20];
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    for (int i = 1; i <= 16; i++) {
        ntx_dht_node n = mk_v4((uint8_t)i, 0x00, 0x0A000000u + (uint32_t)i,
                               (uint16_t)(6881 + i), 1000, 0);
        lk.known[i - 1] = n;
    }
    lk.n_known = 16;
    ntx_dht_node g = mk_v4(0x11, 0x00, 0x0A0000FFu, 6881, 0, 0);
    ntx_dht_node resp = lk.known[0];
    ntx_dht_lookup_on_response(&lk, resp.id, &g, 1, 500);
    if (lk.n_known != 16) return fail("repl-n");
    if (lk_find0(&lk, 0x10) != -1) return fail("repl-old-still");
    int gi = lk_find0(&lk, 0x11);
    if (gi < 0) return fail("repl-new-missing");
    if (lk.known[gi].replied != 0) return fail("repl-new-replied");
    if (lk.known[0].replied != 1) return fail("repl-resp-replied");
    return 0;
}

static int test_closest_12_cap8(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    ntx_dht_node out[NTX_DHT_LK_KNOWN];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    for (int i = 1; i <= 12; i++) {
        ntx_dht_node n = mk_v4((uint8_t)(0x10 * i), (uint8_t)i,
                               0x0A000000u + (uint32_t)i, 6881, 1000, 0);
        ntx_dht_rt_add(&rt, &n);
    }
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    if (lk.n_known != 12) return fail("close12-seed");
    int n = ntx_dht_lookup_closest(&lk, out, 8);
    if (n != 8) return fail("close12-n");
    for (int i = 0; i < 8; i++)
        if (out[i].id[0] != (uint8_t)(0x10 * (i + 1))) return fail("close12-order");
    return 0;
}

static int test_closest_replied_filter(void) {
    ntx_dht_rt rt;
    ntx_dht_lookup lk;
    uint8_t self[20], hash[20];
    ntx_dht_node out[NTX_DHT_LK_KNOWN];
    fill20(self, 0x00);
    ntx_dht_rt_init(&rt, self);
    for (int i = 1; i <= 12; i++) {
        ntx_dht_node n = mk_v4((uint8_t)(0x10 * i), (uint8_t)i,
                               0x0A000000u + (uint32_t)i, 6881, 1000, 0);
        ntx_dht_rt_add(&rt, &n);
    }
    fill20(hash, 0x00);
    ntx_dht_lookup_init(&lk, hash, 0);
    ntx_dht_lookup_seed(&lk, &rt);
    if (lk.n_known != 12) return fail("closefilter-seed");
    lk.known[0].replied = 1;
    lk.known[2].replied = 1;
    lk.known[4].replied = 1;
    lk.known[6].replied = 1;
    int n = ntx_dht_lookup_closest(&lk, out, 8);
    if (n != 8) return fail("closefilter-n");
    int targets = 0;
    for (int i = 0; i < n; i++)
        if (out[i].replied) targets++;
    if (targets != 4) return fail("closefilter-targets");
    return 0;
}

int main(void) {
    if (test_init() != 0) return 1;
    printf("PASS init\n");
    if (test_seed_three_v4() != 0) return 1;
    printf("PASS seed-three-v4\n");
    if (test_seed_empty() != 0) return 1;
    printf("PASS seed-empty\n");
    if (test_seed_v6() != 0) return 1;
    printf("PASS seed-v6\n");
    if (test_pick_alpha() != 0) return 1;
    printf("PASS pick-alpha\n");
    if (test_pick_cap() != 0) return 1;
    printf("PASS pick-cap\n");
    if (test_two_rounds_finish() != 0) return 1;
    printf("PASS two-rounds-finish\n");
    if (test_timeout() != 0) return 1;
    printf("PASS timeout\n");
    if (test_responder_added() != 0) return 1;
    printf("PASS responder-added\n");
    if (test_replace_full() != 0) return 1;
    printf("PASS replace-full\n");
    if (test_closest_12_cap8() != 0) return 1;
    printf("PASS closest-12-cap8\n");
    if (test_closest_replied_filter() != 0) return 1;
    printf("PASS closest-replied-filter\n");
    return 0;
}
