#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "../src/proto/ntx_dht_tid.c"
#include "../src/net/ntx_addr.c"
#include "../src/crypto/ntx_rng.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static ntx_addr mk_v4(uint32_t ip_host) {
    ntx_addr a;
    ntx_addr_set_v4(&a, htonl(ip_host));
    return a;
}

static ntx_addr mk_v6(const uint8_t b[16]) {
    ntx_addr a;
    ntx_addr_set_v6(&a, b);
    return a;
}

static ntx_addr mk_mapped_v4(uint32_t ip_host) {
    uint8_t b[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 0, 0, 0, 0 };
    uint32_t net = htonl(ip_host);
    b[12] = (uint8_t)(net >> 24);
    b[13] = (uint8_t)(net >> 16);
    b[14] = (uint8_t)(net >> 8);
    b[15] = (uint8_t)net;
    return mk_v6(b);
}

static int test_init_zero(void) {
    ntx_dht_tid_map m;
    memset(&m, 0x7E, sizeof m);
    ntx_dht_tid_init(&m);
    if (m.n != 0) return fail("init-n");
    return 0;
}

static int test_put_take_v4(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0xAB, 0xCD };
    ntx_addr a = mk_v4(0x01020304);
    if (ntx_dht_tid_put(&m, tid, &a, 1234, NTX_DHT_TK_FIND_NODE, 3, NTX_AF_INET) != 0)
        return fail("put-v4-rc");
    if (m.n != 1) return fail("put-v4-n");
    uint64_t stored_ms = m.e[0].sent_ms;
    ntx_dht_tid_ent out;
    memset(&out, 0, sizeof out);
    if (ntx_dht_tid_take(&m, tid, &a, 1234, &out) != 0) return fail("take-v4-rc");
    if (out.tid[0] != 0xAB || out.tid[1] != 0xCD) return fail("take-v4-tid");
    if (!ntx_addr_eq(&out.addr, &a)) return fail("take-v4-addr");
    if (out.port != 1234) return fail("take-v4-port");
    if (out.kind != NTX_DHT_TK_FIND_NODE) return fail("take-v4-kind");
    if (out.slot != 3) return fail("take-v4-slot");
    if (out.family != NTX_AF_INET) return fail("take-v4-family");
    if (out.sent_ms != stored_ms) return fail("take-v4-sent-ms");
    if (m.n != 0) return fail("take-v4-n-after");
    return 0;
}

static int test_put_take_v6(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x11, 0x22 };
    uint8_t b[16];
    memset(b, 0, sizeof b);
    b[0] = 0x20;
    b[1] = 0x01;
    b[15] = 0x01;
    ntx_addr a = mk_v6(b);
    if (ntx_dht_tid_put(&m, tid, &a, 6881, NTX_DHT_TK_ANNOUNCE, -1, NTX_AF_INET6) != 0)
        return fail("put-v6-rc");
    if (m.n != 1) return fail("put-v6-n");
    ntx_dht_tid_ent out;
    memset(&out, 0, sizeof out);
    if (ntx_dht_tid_take(&m, tid, &a, 6881, &out) != 0) return fail("take-v6-rc");
    if (out.tid[0] != 0x11 || out.tid[1] != 0x22) return fail("take-v6-tid");
    if (!ntx_addr_eq(&out.addr, &a)) return fail("take-v6-addr");
    if (out.port != 6881) return fail("take-v6-port");
    if (out.kind != NTX_DHT_TK_ANNOUNCE) return fail("take-v6-kind");
    if (out.slot != -1) return fail("take-v6-slot");
    if (out.family != NTX_AF_INET6) return fail("take-v6-family");
    if (m.n != 0) return fail("take-v6-n-after");
    return 0;
}

static int test_take_v4_mapped_source(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x5A, 0xA5 };
    ntx_addr v4 = mk_v4(0x01020304);
    if (ntx_dht_tid_put(&m, tid, &v4, 9999, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-mapped-rc");
    ntx_addr mapped = mk_mapped_v4(0x01020304);
    ntx_dht_tid_ent out;
    if (ntx_dht_tid_take(&m, tid, &mapped, 9999, &out) != 0)
        return fail("take-mapped-rc");
    if (m.n != 0) return fail("take-mapped-removed");
    if (!ntx_addr_eq(&out.addr, &v4)) return fail("take-mapped-stored-addr");
    if (out.port != 9999) return fail("take-mapped-port");
    return 0;
}

static int test_take_v4_source_of_mapped_put(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x33, 0x44 };
    ntx_addr mapped = mk_mapped_v4(0x0A0B0C0D);
    if (ntx_dht_tid_put(&m, tid, &mapped, 7777, NTX_DHT_TK_GET_PEERS, 2, NTX_AF_INET6) != 0)
        return fail("put-mapped2-rc");
    ntx_addr v4 = mk_v4(0x0A0B0C0D);
    ntx_dht_tid_ent out;
    if (ntx_dht_tid_take(&m, tid, &v4, 7777, &out) != 0)
        return fail("take-mapped2-rc");
    if (m.n != 0) return fail("take-mapped2-removed");
    if (!ntx_addr_eq(&out.addr, &mapped)) return fail("take-mapped2-stored-addr");
    return 0;
}

static int test_take_plain_v6_no_match_v4(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x99, 0x88 };
    ntx_addr v4 = mk_v4(0x01020304);
    if (ntx_dht_tid_put(&m, tid, &v4, 1234, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-v6no-rc");
    uint8_t b[16];
    memset(b, 0, sizeof b);
    b[0] = 0x20;
    b[1] = 0x01;
    b[15] = 0x04;
    ntx_addr plain6 = mk_v6(b);
    ntx_dht_tid_ent out;
    if (ntx_dht_tid_take(&m, tid, &plain6, 1234, &out) == 0)
        return fail("take-v6no-should-miss");
    if (m.n != 1) return fail("take-v6no-kept");
    return 0;
}

static int test_take_wrong_tid(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x01, 0x02 };
    uint8_t wrong[2] = { 0x01, 0x03 };
    ntx_addr a = mk_v4(0x01020304);
    if (ntx_dht_tid_put(&m, tid, &a, 1234, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-wtid-rc");
    ntx_dht_tid_ent out;
    if (ntx_dht_tid_take(&m, wrong, &a, 1234, &out) == 0)
        return fail("take-wtid-should-miss");
    if (m.n != 1) return fail("take-wtid-kept");
    return 0;
}

static int test_take_wrong_port(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x01, 0x02 };
    ntx_addr a = mk_v4(0x01020304);
    if (ntx_dht_tid_put(&m, tid, &a, 1234, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-wport-rc");
    ntx_dht_tid_ent out;
    if (ntx_dht_tid_take(&m, tid, &a, 1235, &out) == 0)
        return fail("take-wport-should-miss");
    if (m.n != 1) return fail("take-wport-kept");
    return 0;
}

static int test_put_full_map(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    ntx_addr a = mk_v4(0x0A000001);
    for (int i = 1; i <= NTX_DHT_TID_MAX; i++) {
        uint8_t tid[2] = { (uint8_t)(i >> 8), (uint8_t)i };
        if (ntx_dht_tid_put(&m, tid, &a, 1000, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
            return fail("put-fill-rc");
    }
    if (m.n != NTX_DHT_TID_MAX) return fail("full-n");
    uint8_t tid65[2] = { 0x00, (uint8_t)(NTX_DHT_TID_MAX + 1) };
    if (ntx_dht_tid_put(&m, tid65, &a, 1000, NTX_DHT_TK_PING, -1, NTX_AF_INET) == 0)
        return fail("put-full-should-fail");
    if (m.n != NTX_DHT_TID_MAX) return fail("full-n-after");
    uint8_t tid1[2] = { 0x00, 0x01 };
    if (ntx_dht_tid_put(&m, tid1, &a, 2000, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-overwrite-full");
    if (m.n != NTX_DHT_TID_MAX) return fail("full-n-after-overwrite");
    int found = 0;
    for (int i = 0; i < m.n; i++) {
        if (m.e[i].tid[0] == 0x00 && m.e[i].tid[1] == 0x01 && m.e[i].port == 2000)
            found = 1;
    }
    if (!found) return fail("overwrite-applied");
    return 0;
}

static int test_expire(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t tid[2] = { 0x77, 0x88 };
    ntx_addr a = mk_v4(0x0A000002);
    if (ntx_dht_tid_put(&m, tid, &a, 1234, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-exp-rc");
    m.e[0].sent_ms = 90000;
    if (ntx_dht_tid_expire(&m, 100000, 5000) != 1) return fail("expire-removed-count");
    if (m.n != 0) return fail("expire-n");
    if (ntx_dht_tid_put(&m, tid, &a, 1234, NTX_DHT_TK_PING, -1, NTX_AF_INET) != 0)
        return fail("put-exp2-rc");
    m.e[0].sent_ms = 90000;
    if (ntx_dht_tid_expire(&m, 100000, 30000) != 0) return fail("expire-kept-count");
    if (m.n != 1) return fail("expire-kept-n");
    return 0;
}

static int test_fresh_avoids_active_32(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    for (int i = 1; i <= 32; i++) {
        uint8_t tid[2] = { 0x00, (uint8_t)i };
        ntx_addr a = mk_v4(0x0B000000u | (uint32_t)i);
        if (ntx_dht_tid_put(&m, tid, &a, (uint16_t)(1000 + i), NTX_DHT_TK_PING, -1,
                            NTX_AF_INET) != 0)
            return fail("fresh32-seed-put");
    }
    uint8_t gen[32][2];
    for (int k = 0; k < 32; k++) {
        uint8_t tid[2];
        if (ntx_dht_tid_fresh(&m, tid) != 0) return fail("fresh32-rc");
        for (int i = 1; i <= 32; i++)
            if (tid[0] == 0x00 && tid[1] == (uint8_t)i)
                return fail("fresh32-clashes-active");
        for (int j = 0; j < k; j++)
            if (tid[0] == gen[j][0] && tid[1] == gen[j][1])
                return fail("fresh32-clashes-gen");
        gen[k][0] = tid[0];
        gen[k][1] = tid[1];
        ntx_addr a = mk_v4(0x0C000000u | (uint32_t)(k + 1));
        if (ntx_dht_tid_put(&m, tid, &a, (uint16_t)(2000 + k), NTX_DHT_TK_PING, -1,
                            NTX_AF_INET) != 0)
            return fail("fresh32-put");
    }
    if (m.n != NTX_DHT_TID_MAX) return fail("fresh32-map-full");
    uint8_t extra[2];
    if (ntx_dht_tid_fresh(&m, extra) != 0) return fail("fresh32-extra-rc");
    for (int i = 0; i < m.n; i++)
        if (m.e[i].tid[0] == extra[0] && m.e[i].tid[1] == extra[1])
            return fail("fresh32-extra-clash");
    return 0;
}

static int test_fresh_empty_map_200(void) {
    ntx_dht_tid_map m;
    ntx_dht_tid_init(&m);
    uint8_t sample[200][2];
    for (int i = 0; i < 200; i++) {
        ntx_dht_tid_expire(&m, (uint64_t)i, 63);
        uint8_t tid[2];
        if (ntx_dht_tid_fresh(&m, tid) != 0) return fail("fresh200-rc");
        for (int k = 0; k < m.n; k++)
            if (m.e[k].tid[0] == tid[0] && m.e[k].tid[1] == tid[1])
                return fail("fresh200-clashes-active");
        ntx_addr a = mk_v4(0x01000000u | (uint32_t)i);
        if (ntx_dht_tid_put(&m, tid, &a, (uint16_t)(1000 + i), NTX_DHT_TK_PING, -1,
                            NTX_AF_INET) != 0)
            return fail("fresh200-put");
        for (int k = 0; k < m.n; k++)
            if (m.e[k].tid[0] == tid[0] && m.e[k].tid[1] == tid[1])
                m.e[k].sent_ms = (uint64_t)i;
        sample[i][0] = tid[0];
        sample[i][1] = tid[1];
    }
    int lo = 200 - NTX_DHT_TID_MAX;
    for (int i = lo; i < 200; i++)
        for (int j = lo; j < i; j++)
            if (sample[i][0] == sample[j][0] && sample[i][1] == sample[j][1])
                return fail("fresh200-dup-in-window");
    return 0;
}

int main(void) {
    if (test_init_zero() != 0) return 1;
    printf("PASS init-zero\n");
    if (test_put_take_v4() != 0) return 1;
    printf("PASS put-take-v4\n");
    if (test_put_take_v6() != 0) return 1;
    printf("PASS put-take-v6\n");
    if (test_take_v4_mapped_source() != 0) return 1;
    printf("PASS take-v4-mapped-source\n");
    if (test_take_v4_source_of_mapped_put() != 0) return 1;
    printf("PASS take-v4-source-of-mapped-put\n");
    if (test_take_plain_v6_no_match_v4() != 0) return 1;
    printf("PASS take-plain-v6-no-match-v4\n");
    if (test_take_wrong_tid() != 0) return 1;
    printf("PASS take-wrong-tid\n");
    if (test_take_wrong_port() != 0) return 1;
    printf("PASS take-wrong-port\n");
    if (test_put_full_map() != 0) return 1;
    printf("PASS put-full-map\n");
    if (test_expire() != 0) return 1;
    printf("PASS expire\n");
    if (test_fresh_avoids_active_32() != 0) return 1;
    printf("PASS fresh-avoids-active-32\n");
    if (test_fresh_empty_map_200() != 0) return 1;
    printf("PASS fresh-empty-map-200\n");
    return 0;
}
