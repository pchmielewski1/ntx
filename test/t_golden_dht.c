/* A5 golden replay: DHT (BEP5/BEP32) response fixtures.
 *
 * Loads frozen fixtures from test/fixtures/dht/ (raw wire bytes +
 * .meta.json expectations) and drives the real parser path
 * ntx_dht_msg_parse + ntx_dht_msg_parse_{values,values6,nodes,nodes6}.
 * No network: fixture replay only. Deterministic.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "util.h"
#include "golden_meta.h"

#include "../src/proto/ntx_bencode.c"
#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_msg.c"

static int g_fail;

static void expect(const char *name, int ok) {
    if (ok) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); g_fail = 1; }
}

static int hex_to(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || v > 255) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* meta expected.values/values6 = [["192.0.2.31", 6881], ...] */
static int check_cpeers(const gm *exp, const char *key, const ntx_dht_cpeer *out, int n) {
    const gm *arr = gm_get(exp, key);
    if (!arr) return n == 0;
    if (arr->t != GM_ARR || (int64_t)arr->ne != n) return 0;
    for (size_t i = 0; i < arr->ne; i++) {
        const gm *e = arr->el[i];
        if (!e || e->t != GM_ARR || e->ne != 2) return 0;
        const char *ip;
        int64_t port;
        if (gm_str(e->el[0], &ip) != 0 || gm_num(e->el[1], &port) != 0) return 0;
        uint8_t a[16];
        int ok4 = inet_pton(AF_INET, ip, a) == 1;
        int ok6 = inet_pton(AF_INET6, ip, a) == 1;
        if (!ok4 && !ok6) return 0;
        if (ok4) {
            if (!ntx_addr_is_v4(&out[i].addr)) return 0;
            uint32_t net;
            memcpy(&net, a, 4);
            if (out[i].addr.u.v4 != net) return 0;
        } else {
            if (!ntx_addr_is_v6(&out[i].addr)) return 0;
            if (memcmp(out[i].addr.u.v6, a, 16) != 0) return 0;
        }
        if (out[i].port != (uint16_t)port) return 0;
    }
    return 1;
}

/* meta expected.nodes/nodes6 = [["<id hex20>", "ip", port], ...] */
static int check_nodes(const gm *exp, const char *key, const ntx_dht_node *out, int n) {
    const gm *arr = gm_get(exp, key);
    if (!arr) return n == 0;
    if (arr->t != GM_ARR || (int64_t)arr->ne != n) return 0;
    for (size_t i = 0; i < arr->ne; i++) {
        const gm *e = arr->el[i];
        if (!e || e->t != GM_ARR || e->ne != 3) return 0;
        const char *idhex, *ip;
        int64_t port;
        if (gm_str(e->el[0], &idhex) != 0 || gm_str(e->el[1], &ip) != 0 ||
            gm_num(e->el[2], &port) != 0)
            return 0;
        uint8_t id[20];
        if (!hex_to(idhex, id, 20)) return 0;
        if (memcmp(out[i].id, id, 20) != 0) return 0;
        uint8_t a[16];
        int ok4 = inet_pton(AF_INET, ip, a) == 1;
        int ok6 = inet_pton(AF_INET6, ip, a) == 1;
        if (!ok4 && !ok6) return 0;
        if (ok4) {
            if (!ntx_addr_is_v4(&out[i].addr)) return 0;
            uint32_t net;
            memcpy(&net, a, 4);
            if (out[i].addr.u.v4 != net) return 0;
        } else {
            if (!ntx_addr_is_v6(&out[i].addr)) return 0;
            if (memcmp(out[i].addr.u.v6, a, 16) != 0) return 0;
        }
        if (out[i].port != (uint16_t)port) return 0;
    }
    return 1;
}

static int replay_dht(const char *name) {
    char binpath[256], metapath[256];
    snprintf(binpath, sizeof binpath, "test/fixtures/dht/%s.bin", name);
    snprintf(metapath, sizeof metapath, "test/fixtures/dht/%s.meta.json", name);

    size_t n, mn;
    uint8_t *raw = read_file(binpath, &n);
    uint8_t *meta = read_file(metapath, &mn);

    gm root;
    char tag[256];
    snprintf(tag, sizeof tag, "%s:meta-parse", name);
    expect(tag, gm_parse((const char *)meta, mn, &root) == 0);
    if (g_fail) return 1;
    const gm *exp = gm_get(&root, "expected");
    expect("meta-expected", exp != NULL && exp->t == GM_OBJ);
    if (!exp) return 1;

    ntx_dht_msg_view v;
    char t1[256];
    snprintf(t1, sizeof t1, "%s:parse", name);
    expect(t1, ntx_dht_msg_parse(raw, n, &v) == 0);
    if (g_fail) return 1;

    const char *ey = NULL, *etid = NULL, *eid = NULL, *etok = NULL;
    gm_str(gm_get(exp, "y"), &ey);
    gm_str(gm_get(exp, "tid"), &etid);
    gm_str(gm_get(exp, "id"), &eid);
    gm_str(gm_get(exp, "token"), &etok);

    char t2[256], t3[256], t4[256], t5[256], t6[256], t7[256], t8[256], t9[256], t10[256];
    snprintf(t2, sizeof t2, "%s:y", name);
    snprintf(t3, sizeof t3, "%s:tid", name);
    snprintf(t4, sizeof t4, "%s:id", name);
    snprintf(t5, sizeof t5, "%s:token", name);
    snprintf(t6, sizeof t6, "%s:values", name);
    snprintf(t7, sizeof t7, "%s:values6", name);
    snprintf(t8, sizeof t8, "%s:nodes", name);
    snprintf(t9, sizeof t9, "%s:nodes6", name);
    snprintf(t10, sizeof t10, "%s:q-null", name);

    expect(t2, v.y != NULL && ey != NULL && strcmp(v.y, ey) == 0);
    expect(t3, v.tid != NULL && etid != NULL && v.tid_len == strlen(etid) / 2 &&
           hex_to(etid, (uint8_t *)v.tid, v.tid_len));
    expect(t4, v.id != NULL && eid != NULL && v.id_len == 20 &&
           hex_to(eid, (uint8_t *)v.id, 20));
    if (etok) {
        expect(t5, v.token != NULL && v.token_len == strlen(etok) / 2 &&
               hex_to(etok, (uint8_t *)v.token, v.token_len));
    } else {
        expect(t5, v.token == NULL);
    }
    expect(t10, v.q == NULL);

    ntx_dht_cpeer cp[16];
    memset(cp, 0, sizeof cp);
    int nv = v.values ? ntx_dht_msg_parse_values(v.values, v.values_len, cp, 16) : 0;
    expect(t6, check_cpeers(exp, "values", cp, nv));

    memset(cp, 0, sizeof cp);
    int nv6 = v.values6 ? ntx_dht_msg_parse_values6(v.values6, v.values6_len, cp, 16) : 0;
    expect(t7, check_cpeers(exp, "values6", cp, nv6));

    ntx_dht_node nd[16];
    memset(nd, 0, sizeof nd);
    int nn = v.nodes ? ntx_dht_msg_parse_nodes(v.nodes, v.nodes_len, nd, 16, 0) : 0;
    expect(t8, check_nodes(exp, "nodes", nd, nn));

    memset(nd, 0, sizeof nd);
    int nn6 = v.nodes6 ? ntx_dht_msg_parse_nodes6(v.nodes6, v.nodes6_len, nd, 16, 0) : 0;
    expect(t9, check_nodes(exp, "nodes6", nd, nn6));

    gm_free(&root);
    free(raw);
    free(meta);
    return 0;
}

int main(void) {
    if (replay_dht("get_peers_response")) return 1;
    if (replay_dht("find_node_response")) return 1;
    return g_fail ? 1 : 0;
}
