#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "../src/proto/ntx_bencode.c"
#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_msg.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static void fill20(uint8_t *buf, uint8_t v) {
    for (int i = 0; i < 20; i++) buf[i] = v;
}

static void put_ip4(uint8_t *p, uint32_t ip_host) {
    uint32_t net = htonl(ip_host);
    memcpy(p, &net, 4);
}

static int has_sub(const uint8_t *hay, size_t n, const char *needle) {
    size_t m = strlen(needle);
    if (m == 0 || n < m) return 0;
    for (size_t i = 0; i + m <= n; i++)
        if (memcmp(hay + i, needle, m) == 0) return 1;
    return 0;
}

static void put_port(uint8_t *p, uint16_t port_host) {
    uint16_t be = htons(port_host);
    memcpy(p, &be, 2);
}

static size_t be_key(uint8_t *b, size_t off, const char *k) {
    char h[24];
    int n = snprintf(h, sizeof h, "%zu:%s", strlen(k), k);
    memcpy(b + off, h, (size_t)n);
    return off + (size_t)n;
}

static size_t be_str(uint8_t *b, size_t off, const void *v, size_t n) {
    char h[16];
    int m = snprintf(h, sizeof h, "%zu:", n);
    memcpy(b + off, h, (size_t)m);
    off += (size_t)m;
    memcpy(b + off, v, n);
    return off + n;
}

/* 2 x record 26 B: id 0xAA.. / 1.2.3.4:6881 + id 0xBB.. / 5.6.7.8:6882 */
static void mk_nodes_v4(uint8_t *buf) {
    memset(buf, 0, 52);
    fill20(buf, 0xAA);
    put_ip4(buf + 20, 0x01020304u);
    put_port(buf + 24, 6881);
    fill20(buf + 26, 0xBB);
    put_ip4(buf + 46, 0x05060708u);
    put_port(buf + 50, 6882);
}

/* 2 x record 6 B: 1.2.3.4:6881 + 5.6.7.8:6882 */
static void mk_values_v4(uint8_t *buf) {
    memset(buf, 0, 12);
    put_ip4(buf, 0x01020304u);
    put_port(buf + 4, 6881);
    put_ip4(buf + 6, 0x05060708u);
    put_port(buf + 10, 6882);
}

static int test_parse_nodes_basic(void) {
    uint8_t buf[52];
    mk_nodes_v4(buf);
    ntx_dht_node out[4];
    memset(out, 0, sizeof out);
    int c = ntx_dht_msg_parse_nodes(buf, 52, out, 4, 1234);
    if (c != 2) return fail("parse-nodes-count");
    if (memcmp(out[0].id, buf, 20) != 0) return fail("parse-nodes-id0");
    if (!ntx_addr_is_v4(&out[0].addr)) return fail("parse-nodes-v4-0");
    if (out[0].addr.u.v4 != htonl(0x01020304u)) return fail("parse-nodes-ip0");
    if (out[0].port != 6881) return fail("parse-nodes-port0");
    if (out[0].last_seen_ms != 1234) return fail("parse-nodes-seen0");
    if (out[0].replied != 0) return fail("parse-nodes-replied0");
    if (memcmp(out[1].id, buf + 26, 20) != 0) return fail("parse-nodes-id1");
    if (out[1].addr.u.v4 != htonl(0x05060708u)) return fail("parse-nodes-ip1");
    if (out[1].port != 6882) return fail("parse-nodes-port1");
    if (out[1].last_seen_ms != 1234) return fail("parse-nodes-seen1");
    return 0;
}

static int test_parse_nodes_tail_ignored(void) {
    uint8_t buf[62];
    mk_nodes_v4(buf);
    for (int i = 52; i < 62; i++) buf[i] = (uint8_t)(i * 7 + 1);
    ntx_dht_node out[4];
    int c = ntx_dht_msg_parse_nodes(buf, 62, out, 4, 0);
    if (c != 2) return fail("parse-nodes-tail");
    if (out[0].port != 6881 || out[1].port != 6882) return fail("parse-nodes-tail-ports");
    return 0;
}

static int test_parse_nodes_cap1(void) {
    uint8_t buf[52];
    mk_nodes_v4(buf);
    ntx_dht_node out[4];
    memset(out, 0, sizeof out);
    int c = ntx_dht_msg_parse_nodes(buf, 52, out, 1, 42);
    if (c != 1) return fail("parse-nodes-cap1-count");
    if (out[0].port != 6881) return fail("parse-nodes-cap1-port");
    if (out[0].last_seen_ms != 42) return fail("parse-nodes-cap1-seen");
    return 0;
}

static int test_parse_nodes_null_empty(void) {
    uint8_t buf[52];
    mk_nodes_v4(buf);
    ntx_dht_node out[4];
    if (ntx_dht_msg_parse_nodes(buf, 0, out, 4, 0) != 0) return fail("parse-nodes-empty");
    if (ntx_dht_msg_parse_nodes(NULL, 52, out, 4, 0) != 0) return fail("parse-nodes-null-p");
    if (ntx_dht_msg_parse_nodes(buf, 52, NULL, 4, 0) != 0) return fail("parse-nodes-null-out");
    if (ntx_dht_msg_parse_nodes(buf, 52, out, 0, 0) != 0) return fail("parse-nodes-cap0");
    if (ntx_dht_msg_parse_nodes(buf, 52, out, -1, 0) != 0) return fail("parse-nodes-capneg");
    return 0;
}

static int test_parse_values_basic(void) {
    uint8_t buf[12];
    mk_values_v4(buf);
    ntx_dht_cpeer out[4];
    memset(out, 0, sizeof out);
    int c = ntx_dht_msg_parse_values(buf, 12, out, 4);
    if (c != 2) return fail("parse-values-count");
    if (!ntx_addr_is_v4(&out[0].addr)) return fail("parse-values-v4-0");
    if (out[0].addr.u.v4 != htonl(0x01020304u)) return fail("parse-values-ip0");
    if (out[0].port != 6881) return fail("parse-values-port0");
    if (out[1].addr.u.v4 != htonl(0x05060708u)) return fail("parse-values-ip1");
    if (out[1].port != 6882) return fail("parse-values-port1");
    return 0;
}

static int test_parse_values_tail_ignored(void) {
    uint8_t buf[16];
    mk_values_v4(buf);
    for (int i = 12; i < 16; i++) buf[i] = (uint8_t)(0xE0 + i);
    ntx_dht_cpeer out[4];
    int c = ntx_dht_msg_parse_values(buf, 16, out, 4);
    if (c != 2) return fail("parse-values-tail");
    if (out[0].port != 6881 || out[1].port != 6882) return fail("parse-values-tail-ports");
    return 0;
}

static int test_parse_values_null_empty(void) {
    uint8_t buf[12];
    mk_values_v4(buf);
    ntx_dht_cpeer out[4];
    if (ntx_dht_msg_parse_values(buf, 0, out, 4) != 0) return fail("parse-values-empty");
    if (ntx_dht_msg_parse_values(NULL, 12, out, 4) != 0) return fail("parse-values-null-p");
    if (ntx_dht_msg_parse_values(buf, 12, NULL, 4) != 0) return fail("parse-values-null-out");
    if (ntx_dht_msg_parse_values(buf, 12, out, 0) != 0) return fail("parse-values-cap0");
    return 0;
}

static int test_enc_ping_roundtrip(void) {
    uint8_t tid[2] = {0x12, 0x34};
    uint8_t id[20];
    fill20(id, 0x11);
    uint8_t pkt[128];
    size_t n = ntx_dht_msg_enc_ping(pkt, sizeof pkt, tid, id);
    if (n == 0) return fail("enc-ping-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, n, &v) != 0) return fail("enc-ping-parse");
    if (v.y == NULL || strcmp(v.y, "q") != 0) return fail("enc-ping-y");
    if (v.q == NULL || strcmp(v.q, "ping") != 0) return fail("enc-ping-q");
    if (v.tid_len != 2 || v.tid[0] != 0x12 || v.tid[1] != 0x34) return fail("enc-ping-tid");
    if (v.id_len != 20 || memcmp(v.id, id, 20) != 0) return fail("enc-ping-id");
    return 0;
}

static int test_enc_find_node_want(void) {
    uint8_t tid[2] = {0xAB, 0xCD};
    uint8_t id[20], n[20];
    fill20(id, 0x22);
    fill20(n, 0x33);
    uint8_t pkt[160];
    size_t pn = ntx_dht_msg_enc_find_node(pkt, sizeof pkt, tid, id, n, 1, 1);
    if (pn == 0) return fail("enc-fn-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, pn, &v) != 0) return fail("enc-fn-parse");
    if (v.q == NULL || strcmp(v.q, "find_node") != 0) return fail("enc-fn-q");
    if (v.target == NULL || v.target_len != 20 || memcmp(v.target, n, 20) != 0) return fail("enc-fn-n");
    if (v.want_n4 != 1 || v.want_n6 != 1) return fail("enc-fn-want");
    return 0;
}

static int test_enc_find_node_want_n4_only(void) {
    uint8_t tid[2] = {0x01, 0x02};
    uint8_t id[20], n[20];
    fill20(id, 0x22);
    fill20(n, 0x33);
    uint8_t pkt[160];
    size_t pn = ntx_dht_msg_enc_find_node(pkt, sizeof pkt, tid, id, n, 1, 0);
    if (pn == 0) return fail("enc-fn-n4-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, pn, &v) != 0) return fail("enc-fn-n4-parse");
    if (v.want_n4 != 1 || v.want_n6 != 0) return fail("enc-fn-n4-flags");
    return 0;
}

static int test_enc_find_node_no_want(void) {
    uint8_t tid[2] = {0x01, 0x02};
    uint8_t id[20], n[20];
    fill20(id, 0x22);
    fill20(n, 0x33);
    uint8_t pkt[160];
    size_t pn = ntx_dht_msg_enc_find_node(pkt, sizeof pkt, tid, id, n, 0, 0);
    if (pn == 0) return fail("enc-fn-nowant-size");
    if (has_sub(pkt, pn, "4:want")) return fail("enc-fn-nowant-raw");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, pn, &v) != 0) return fail("enc-fn-nowant-parse");
    if (v.want_n4 != 0 || v.want_n6 != 0) return fail("enc-fn-nowant-flags");
    if (v.target == NULL || v.target_len != 20 || memcmp(v.target, n, 20) != 0) return fail("enc-fn-nowant-n");
    return 0;
}

static int test_msg_find_node_target(void) {
    uint8_t tid[2] = {0xAB, 0xCD};
    uint8_t id[20], n[20];
    fill20(id, 0x22);
    fill20(n, 0x33);
    uint8_t pkt[160];
    size_t pn = ntx_dht_msg_enc_find_node(pkt, sizeof pkt, tid, id, n, 1, 0);
    if (pn == 0) return fail("fn-target-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, pn, &v) != 0) return fail("fn-target-parse");
    if (v.q == NULL || strcmp(v.q, "find_node") != 0) return fail("fn-target-q");
    if (v.id == NULL || v.id_len != 20 || memcmp(v.id, id, 20) != 0)
        return fail("fn-target-id");
    if (v.target == NULL || v.target_len != 20 || memcmp(v.target, n, 20) != 0)
        return fail("fn-target-val");
    /* variant a.target: d{ a:{id,target}, q:"find_node", t, y:"q" } */
    uint8_t pkt2[160];
    size_t e = 0;
    pkt2[e++] = 'd';
    e = be_key(pkt2, e, "a");
    pkt2[e++] = 'd';
    e = be_key(pkt2, e, "id");
    e = be_str(pkt2, e, id, 20);
    e = be_key(pkt2, e, "target");
    e = be_str(pkt2, e, n, 20);
    pkt2[e++] = 'e';
    e = be_key(pkt2, e, "q");
    e = be_str(pkt2, e, "find_node", 10);
    e = be_key(pkt2, e, "t");
    e = be_str(pkt2, e, tid, 2);
    e = be_key(pkt2, e, "y");
    e = be_str(pkt2, e, "q", 1);
    pkt2[e++] = 'e';
    ntx_dht_msg_view v2;
    if (ntx_dht_msg_parse(pkt2, e, &v2) != 0) return fail("fn-target2-parse");
    if (v2.q == NULL || strcmp(v2.q, "find_node") != 0) return fail("fn-target2-q");
    if (v2.target == NULL || v2.target_len != 20 || memcmp(v2.target, n, 20) != 0)
        return fail("fn-target2-val");
    return 0;
}

static int test_enc_get_peers(void) {
    uint8_t tid[2] = {0x5A, 0xA5};
    uint8_t id[20], ih[20];
    fill20(id, 0x44);
    fill20(ih, 0x55);
    uint8_t pkt[160];
    size_t pn = ntx_dht_msg_enc_get_peers(pkt, sizeof pkt, tid, id, ih, 1, 0);
    if (pn == 0) return fail("enc-gp-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, pn, &v) != 0) return fail("enc-gp-parse");
    if (v.q == NULL || strcmp(v.q, "get_peers") != 0) return fail("enc-gp-q");
    if (v.info_hash == NULL || memcmp(v.info_hash, ih, 20) != 0) return fail("enc-gp-ih");
    if (v.id_len != 20 || memcmp(v.id, id, 20) != 0) return fail("enc-gp-id");
    if (v.want_n4 != 1 || v.want_n6 != 0) return fail("enc-gp-want");
    return 0;
}

static int test_enc_announce_peer(void) {
    uint8_t tid[2] = {0xC3, 0x13};
    uint8_t id[20], ih[20], tok[8];
    fill20(id, 0x66);
    fill20(ih, 0x77);
    for (int i = 0; i < 8; i++) tok[i] = (uint8_t)(0xA0 + i);
    uint8_t pkt[200];
    size_t pn = ntx_dht_msg_enc_announce_peer(pkt, sizeof pkt, tid, id, ih, 6999, tok, 8);
    if (pn == 0) return fail("enc-ap-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, pn, &v) != 0) return fail("enc-ap-parse");
    if (v.y == NULL || strcmp(v.y, "q") != 0) return fail("enc-ap-y");
    if (v.q == NULL || strcmp(v.q, "announce_peer") != 0) return fail("enc-ap-q");
    if (v.id_len != 20 || memcmp(v.id, id, 20) != 0) return fail("enc-ap-id");
    if (v.info_hash == NULL || memcmp(v.info_hash, ih, 20) != 0) return fail("enc-ap-ih");
    if (v.port != 6999) return fail("enc-ap-port");
    if (v.token_len != 8 || memcmp(v.token, tok, 8) != 0) return fail("enc-ap-token");
    /* no token: field omitted */
    size_t pn2 = ntx_dht_msg_enc_announce_peer(pkt, sizeof pkt, tid, id, ih, 6999, NULL, 0);
    if (pn2 == 0) return fail("enc-ap-notok-size");
    ntx_dht_msg_view v2;
    if (ntx_dht_msg_parse(pkt, pn2, &v2) != 0) return fail("enc-ap-notok-parse");
    if (v2.token != NULL) return fail("enc-ap-notok-absent");
    return 0;
}

static int test_enc_r_ping(void) {
    uint8_t tid[2] = {0x77, 0x88};
    uint8_t id[20];
    fill20(id, 0x99);
    uint8_t pkt[128];
    size_t n = ntx_dht_msg_enc_r_ping(pkt, sizeof pkt, tid, id);
    if (n == 0) return fail("enc-r-ping-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, n, &v) != 0) return fail("enc-r-ping-parse");
    if (v.y == NULL || strcmp(v.y, "r") != 0) return fail("enc-r-ping-y");
    if (v.q != NULL) return fail("enc-r-ping-q-null");
    if (v.tid_len != 2 || v.tid[0] != 0x77 || v.tid[1] != 0x88) return fail("enc-r-ping-tid");
    if (v.id_len != 20 || memcmp(v.id, id, 20) != 0) return fail("enc-r-ping-id");
    return 0;
}

static int test_enc_r_find_node_nodes(void) {
    uint8_t tid[2] = {0x0A, 0x0B};
    uint8_t id[20];
    fill20(id, 0x11);
    uint8_t nodes[52];
    mk_nodes_v4(nodes);
    uint8_t pkt[256];
    size_t n = ntx_dht_msg_enc_r_find_node(pkt, sizeof pkt, tid, id, nodes, 52, NULL, 0);
    if (n == 0) return fail("enc-r-fn-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, n, &v) != 0) return fail("enc-r-fn-parse");
    if (v.y == NULL || strcmp(v.y, "r") != 0) return fail("enc-r-fn-y");
    if (v.nodes_len != 52 || memcmp(v.nodes, nodes, 52) != 0) return fail("enc-r-fn-nodes");
    if (v.nodes6 != NULL) return fail("enc-r-fn-nodes6-null");
    if (v.id_len != 20 || memcmp(v.id, id, 20) != 0) return fail("enc-r-fn-id");
    ntx_dht_node out[4];
    if (ntx_dht_msg_parse_nodes(v.nodes, v.nodes_len, out, 4, 1) != 2)
        return fail("enc-r-fn-nodes-parse");
    if (out[0].port != 6881 || out[1].port != 6882) return fail("enc-r-fn-nodes-ports");
    return 0;
}

static int test_enc_r_get_peers_values_token(void) {
    uint8_t tid[2] = {0xC0, 0xFF};
    uint8_t id[20];
    fill20(id, 0x2A);
    uint8_t token[8];
    for (int i = 0; i < 8; i++) token[i] = (uint8_t)(0x50 + i);
    uint8_t values[12];
    mk_values_v4(values);
    uint8_t pkt[256];
    size_t n = ntx_dht_msg_enc_r_get_peers(pkt, sizeof pkt, tid, id,
                                           token, 8, values, 12, NULL, 0, NULL, 0,
                                           NULL, 0);
    if (n == 0) return fail("enc-r-gp-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, n, &v) != 0) return fail("enc-r-gp-parse");
    if (v.y == NULL || strcmp(v.y, "r") != 0) return fail("enc-r-gp-y");
    if (v.token_len != 8 || memcmp(v.token, token, 8) != 0) return fail("enc-r-gp-token");
    if (v.values_len != 12 || memcmp(v.values, values, 12) != 0) return fail("enc-r-gp-values");
    if (v.values6 != NULL || v.nodes != NULL || v.nodes6 != NULL) return fail("enc-r-gp-nulls");
    if (v.id_len != 20 || memcmp(v.id, id, 20) != 0) return fail("enc-r-gp-id");
    ntx_dht_cpeer peers[4];
    if (ntx_dht_msg_parse_values(v.values, v.values_len, peers, 4) != 2)
        return fail("enc-r-gp-values-parse");
    if (peers[0].port != 6881 || peers[1].port != 6882) return fail("enc-r-gp-peers");
    return 0;
}

/* record 38 B: id 0xCC.. + ::1 + port 6881 */
static void mk_nodes6_one(uint8_t *buf) {
    memset(buf, 0, 38);
    fill20(buf, 0xCC);
    memset(buf + 20, 0, 16);
    buf[35] = 1;
    put_port(buf + 36, 6881);
}

/* record 18 B: ::1 + port 6881 */
static void mk_values6_one(uint8_t *buf) {
    memset(buf, 0, 18);
    buf[15] = 1;
    put_port(buf + 16, 6881);
}

static int test_parse_nodes6_basic(void) {
    uint8_t buf[38];
    mk_nodes6_one(buf);
    ntx_dht_node out[2];
    memset(out, 0, sizeof out);
    int c = ntx_dht_msg_parse_nodes6(buf, 38, out, 2, 555);
    if (c != 1) return fail("parse-nodes6-count");
    if (memcmp(out[0].id, buf, 20) != 0) return fail("parse-nodes6-id");
    if (!ntx_addr_is_v6(&out[0].addr)) return fail("parse-nodes6-v6");
    for (int i = 0; i < 15; i++)
        if (out[0].addr.u.v6[i] != 0) return fail("parse-nodes6-v6-zero");
    if (out[0].addr.u.v6[15] != 1) return fail("parse-nodes6-v6-one");
    if (out[0].port != 6881) return fail("parse-nodes6-port");
    if (out[0].last_seen_ms != 555) return fail("parse-nodes6-seen");
    return 0;
}

static int test_parse_nodes6_tail_null(void) {
    uint8_t buf[48];
    mk_nodes6_one(buf);
    for (int i = 38; i < 48; i++) buf[i] = (uint8_t)(0xC0 + i);
    ntx_dht_node out[2];
    if (ntx_dht_msg_parse_nodes6(buf, 48, out, 2, 0) != 1)
        return fail("parse-nodes6-tail");
    if (ntx_dht_msg_parse_nodes6(NULL, 38, out, 2, 0) != 0)
        return fail("parse-nodes6-null-p");
    if (ntx_dht_msg_parse_nodes6(buf, 38, NULL, 2, 0) != 0)
        return fail("parse-nodes6-null-out");
    if (ntx_dht_msg_parse_nodes6(buf, 38, out, 0, 0) != 0)
        return fail("parse-nodes6-cap0");
    return 0;
}

static int test_parse_values6_basic(void) {
    uint8_t buf[18];
    mk_values6_one(buf);
    ntx_dht_cpeer out[2];
    memset(out, 0, sizeof out);
    int c = ntx_dht_msg_parse_values6(buf, 18, out, 2);
    if (c != 1) return fail("parse-values6-count");
    if (!ntx_addr_is_v6(&out[0].addr)) return fail("parse-values6-v6");
    for (int i = 0; i < 15; i++)
        if (out[0].addr.u.v6[i] != 0) return fail("parse-values6-v6-zero");
    if (out[0].addr.u.v6[15] != 1) return fail("parse-values6-v6-one");
    if (out[0].port != 6881) return fail("parse-values6-port");
    return 0;
}

static int test_parse_values6_tail_null(void) {
    uint8_t buf[22];
    mk_values6_one(buf);
    for (int i = 18; i < 22; i++) buf[i] = (uint8_t)(0xD0 + i);
    ntx_dht_cpeer out[2];
    if (ntx_dht_msg_parse_values6(buf, 22, out, 2) != 1)
        return fail("parse-values6-tail");
    if (ntx_dht_msg_parse_values6(NULL, 18, out, 2) != 0)
        return fail("parse-values6-null-p");
    if (ntx_dht_msg_parse_values6(buf, 18, NULL, 2) != 0)
        return fail("parse-values6-null-out");
    if (ntx_dht_msg_parse_values6(buf, 18, out, 0) != 0)
        return fail("parse-values6-cap0");
    return 0;
}

static int test_enc_r_find_node_nodes6(void) {
    uint8_t tid[2] = {0x61, 0x62};
    uint8_t id[20];
    fill20(id, 0x3B);
    uint8_t nodes6[38];
    mk_nodes6_one(nodes6);
    uint8_t pkt[256];
    size_t n = ntx_dht_msg_enc_r_find_node(pkt, sizeof pkt, tid, id,
                                           NULL, 0, nodes6, 38);
    if (n == 0) return fail("enc-r-fn6-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, n, &v) != 0) return fail("enc-r-fn6-parse");
    if (v.nodes != NULL) return fail("enc-r-fn6-nodes-null");
    if (v.nodes6_len != 38 || memcmp(v.nodes6, nodes6, 38) != 0)
        return fail("enc-r-fn6-nodes6");
    ntx_dht_node out[2];
    if (ntx_dht_msg_parse_nodes6(v.nodes6, v.nodes6_len, out, 2, 9) != 1)
        return fail("enc-r-fn6-parse-nodes6");
    if (!ntx_addr_is_v6(&out[0].addr) || out[0].port != 6881)
        return fail("enc-r-fn6-node");
    return 0;
}

static int test_enc_r_get_peers_values6(void) {
    uint8_t tid[2] = {0x71, 0x72};
    uint8_t id[20];
    fill20(id, 0x4C);
    uint8_t values6[18];
    mk_values6_one(values6);
    uint8_t pkt[256];
    size_t n = ntx_dht_msg_enc_r_get_peers(pkt, sizeof pkt, tid, id,
                                           NULL, 0, NULL, 0, values6, 18,
                                           NULL, 0, NULL, 0);
    if (n == 0) return fail("enc-r-gp6-size");
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(pkt, n, &v) != 0) return fail("enc-r-gp6-parse");
    if (v.values6_len != 18 || memcmp(v.values6, values6, 18) != 0)
        return fail("enc-r-gp6-values6");
    if (v.values != NULL || v.nodes != NULL || v.nodes6 != NULL || v.token != NULL)
        return fail("enc-r-gp6-nulls");
    ntx_dht_cpeer peers[2];
    if (ntx_dht_msg_parse_values6(v.values6, v.values6_len, peers, 2) != 1)
        return fail("enc-r-gp6-parse-values6");
    if (!ntx_addr_is_v6(&peers[0].addr) || peers[0].port != 6881)
        return fail("enc-r-gp6-peer");
    return 0;
}

/* BEP10: query arguments live in dict `a`, not at top level */
static int test_query_a_dict(void) {
    uint8_t tid[2] = {0x11, 0x22};
    uint8_t id[20], tgt[20], ih[20], tok[8];
    fill20(id, 0x11);
    fill20(tgt, 0x22);
    fill20(ih, 0x33);
    for (int i = 0; i < 8; i++) tok[i] = (uint8_t)(0x40 + i);
    uint8_t pkt[256];
    size_t pn;
    ntx_be be;
    size_t consumed;

    pn = ntx_dht_msg_enc_find_node(pkt, sizeof pkt, tid, id, tgt, 1, 0);
    if (pn == 0) return fail("qad-fn-size");
    if (ntx_be_parse(pkt, pn, &be, &consumed, 32, 65536) != 0) return fail("qad-fn-parse");
    const ntx_be *a = ntx_be_dict_get(&be, "a");
    if (!a || a->t != NTX_BE_DICT) return fail("qad-fn-a");
    if (!ntx_be_dict_get(a, "id")) return fail("qad-fn-a-id");
    if (!ntx_be_dict_get(a, "target")) return fail("qad-fn-a-target");
    if (ntx_be_dict_get(&be, "target")) return fail("qad-fn-toplevel");
    ntx_be_free(&be);

    pn = ntx_dht_msg_enc_get_peers(pkt, sizeof pkt, tid, id, ih, 1, 1);
    if (pn == 0) return fail("qad-gp-size");
    if (ntx_be_parse(pkt, pn, &be, &consumed, 32, 65536) != 0) return fail("qad-gp-parse");
    a = ntx_be_dict_get(&be, "a");
    if (!a || a->t != NTX_BE_DICT) return fail("qad-gp-a");
    if (!ntx_be_dict_get(a, "id")) return fail("qad-gp-a-id");
    if (!ntx_be_dict_get(a, "info_hash")) return fail("qad-gp-a-ih");
    if (ntx_be_dict_get(&be, "info_hash")) return fail("qad-gp-toplevel");
    ntx_be_free(&be);

    pn = ntx_dht_msg_enc_announce_peer(pkt, sizeof pkt, tid, id, ih, 6999, tok, 8);
    if (pn == 0) return fail("qad-ap-size");
    if (ntx_be_parse(pkt, pn, &be, &consumed, 32, 65536) != 0) return fail("qad-ap-parse");
    a = ntx_be_dict_get(&be, "a");
    if (!a || a->t != NTX_BE_DICT) return fail("qad-ap-a");
    if (!ntx_be_dict_get(a, "id")) return fail("qad-ap-a-id");
    if (!ntx_be_dict_get(a, "info_hash")) return fail("qad-ap-a-ih");
    if (!ntx_be_dict_get(a, "port")) return fail("qad-ap-a-port");
    if (!ntx_be_dict_get(a, "token")) return fail("qad-ap-a-token");
    if (ntx_be_dict_get(&be, "port")) return fail("qad-ap-toplevel");
    if (ntx_be_dict_get(&be, "token")) return fail("qad-ap-toplevel-token");
    ntx_be_free(&be);
    return 0;
}

int main(void) {
    if (test_query_a_dict() != 0) return 1;
    printf("PASS query-a-dict\n");
    if (test_parse_nodes_basic() != 0) return 1;
    printf("PASS parse-nodes-basic\n");
    if (test_parse_nodes_tail_ignored() != 0) return 1;
    printf("PASS parse-nodes-tail-ignored\n");
    if (test_parse_nodes_cap1() != 0) return 1;
    printf("PASS parse-nodes-cap1\n");
    if (test_parse_nodes_null_empty() != 0) return 1;
    printf("PASS parse-nodes-null-empty\n");
    if (test_parse_values_basic() != 0) return 1;
    printf("PASS parse-values-basic\n");
    if (test_parse_values_tail_ignored() != 0) return 1;
    printf("PASS parse-values-tail-ignored\n");
    if (test_parse_values_null_empty() != 0) return 1;
    printf("PASS parse-values-null-empty\n");
    if (test_enc_ping_roundtrip() != 0) return 1;
    printf("PASS enc-ping-roundtrip\n");
    if (test_enc_find_node_want() != 0) return 1;
    printf("PASS enc-find-node-want\n");
    if (test_enc_find_node_want_n4_only() != 0) return 1;
    printf("PASS enc-find-node-want-n4-only\n");
    if (test_enc_find_node_no_want() != 0) return 1;
    printf("PASS enc-find-node-no-want\n");
    if (test_msg_find_node_target() != 0) return 1;
    printf("PASS msg_find_node_target\n");
    if (test_enc_get_peers() != 0) return 1;
    printf("PASS enc-get-peers\n");
    if (test_enc_announce_peer() != 0) return 1;
    printf("PASS enc-announce-peer\n");
    if (test_enc_r_ping() != 0) return 1;
    printf("PASS enc-r-ping\n");
    if (test_enc_r_find_node_nodes() != 0) return 1;
    printf("PASS enc-r-find-node-nodes\n");
    if (test_enc_r_get_peers_values_token() != 0) return 1;
    printf("PASS enc-r-get-peers-values-token\n");
    if (test_parse_nodes6_basic() != 0) return 1;
    printf("PASS parse-nodes6-basic\n");
    if (test_parse_nodes6_tail_null() != 0) return 1;
    printf("PASS parse-nodes6-tail-null\n");
    if (test_parse_values6_basic() != 0) return 1;
    printf("PASS parse-values6-basic\n");
    if (test_parse_values6_tail_null() != 0) return 1;
    printf("PASS parse-values6-tail-null\n");
    if (test_enc_r_find_node_nodes6() != 0) return 1;
    printf("PASS enc-r-find-node-nodes6\n");
    if (test_enc_r_get_peers_values6() != 0) return 1;
    printf("PASS enc-r-get-peers-values6\n");
    return 0;
}
