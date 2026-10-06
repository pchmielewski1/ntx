/* A5 golden replay: tracker announce (HTTP, bencoded) fixtures.
 *
 * Loads frozen fixtures from test/fixtures/announce/ (raw wire bytes +
 * .meta.json expectations) and drives the real parser path
 * ntx_tracker_http_parse_ex (ntx_tracker.c + ntx_http.c http_parse_dict_ex).
 * No network: fixture replay only. Deterministic.
 */
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#include "util.h"
#include "golden_meta.h"

#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_http.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/ui/ntx_diag.c"

static int g_fail;

static void expect(const char *name, int ok) {
    if (ok) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); g_fail = 1; }
}

/* meta expected.peers4 = [["192.0.2.10", 6881], ...]; ips in network order */
static int check_peers4(const gm *exp, uint8_t *ips, uint16_t *ports, int n) {
    const gm *arr = gm_get(exp, "peers4");
    if (!arr || arr->t != GM_ARR) return 0;
    if ((int64_t)arr->ne != n) return 0;
    for (size_t i = 0; i < arr->ne; i++) {
        const gm *e = arr->el[i];
        if (!e || e->t != GM_ARR || e->ne != 2) return 0;
        const char *ip;
        int64_t port;
        if (gm_str(e->el[0], &ip) != 0 || gm_num(e->el[1], &port) != 0) return 0;
        uint32_t a;
        if (inet_pton(AF_INET, ip, &a) != 1) return 0;
        if (memcmp(ips + (size_t)i * 4, &a, 4) != 0) return 0;
        if (ports[i] != (uint16_t)port) return 0;
    }
    return 1;
}

static int check_peers6(const gm *exp, uint8_t ips[][16], uint16_t *ports, int n) {
    const gm *arr = gm_get(exp, "peers6");
    if (!arr) return n == 0; /* key absent -> expect none */
    if (arr->t != GM_ARR) return 0;
    if ((int64_t)arr->ne != n) return 0;
    for (size_t i = 0; i < arr->ne; i++) {
        const gm *e = arr->el[i];
        if (!e || e->t != GM_ARR || e->ne != 2) return 0;
        const char *ip;
        int64_t port;
        if (gm_str(e->el[0], &ip) != 0 || gm_num(e->el[1], &port) != 0) return 0;
        uint8_t a[16];
        if (inet_pton(AF_INET6, ip, a) != 1) return 0;
        if (memcmp(ips[i], a, 16) != 0) return 0;
        if (ports[i] != (uint16_t)port) return 0;
    }
    return 1;
}

static int replay_announce(const char *name) {
    char binpath[256], metapath[256];
    snprintf(binpath, sizeof binpath, "test/fixtures/announce/%s.bin", name);
    snprintf(metapath, sizeof metapath, "test/fixtures/announce/%s.meta.json", name);

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

    uint32_t interval = 0, seeders = 0, leechers = 0;
    uint8_t ips4[50 * 4];
    uint16_t ports4[50];
    uint8_t ips6[50][16];
    uint16_t ports6[50];
    char err[128];
    memset(err, 0, sizeof err);
    int total = ntx_tracker_http_parse_ex(raw, n, NULL, &interval, &seeders, &leechers,
                                          ips4, ports4, 50, ips6, ports6, 50, err, sizeof err);

    int64_t e_interval = -1, e_seeders = -1, e_leechers = -1;
    gm_num(gm_get(exp, "interval"), &e_interval);
    gm_num(gm_get(exp, "seeders"), &e_seeders);
    gm_num(gm_get(exp, "leechers"), &e_leechers);

    const gm *p4 = gm_get(exp, "peers4");
    const gm *p6 = gm_get(exp, "peers6");
    int n4 = (p4 && p4->t == GM_ARR) ? (int)p4->ne : 0;
    int n6 = (p6 && p6->t == GM_ARR) ? (int)p6->ne : 0;

    char t1[256], t2[256], t3[256], t4[256], t5[256];
    snprintf(t1, sizeof t1, "%s:count", name);
    snprintf(t2, sizeof t2, "%s:counters", name);
    snprintf(t3, sizeof t3, "%s:peers4", name);
    snprintf(t4, sizeof t4, "%s:peers6", name);
    snprintf(t5, sizeof t5, "%s:total", name);
    expect(t1, total == n4 + n6);
    expect(t2, interval == (uint32_t)e_interval && seeders == (uint32_t)e_seeders &&
           leechers == (uint32_t)e_leechers);
    expect(t3, check_peers4(exp, ips4, ports4, n4));
    expect(t4, check_peers6(exp, ips6, ports6, n6));
    expect(t5, total >= 0 && err[0] == '\0');

    gm_free(&root);
    free(raw);
    free(meta);
    return 0;
}

int main(void) {
    if (replay_announce("http_announce_list")) return 1;
    if (replay_announce("http_announce_compact")) return 1;
    return g_fail ? 1 : 0;
}
