/* A3: PEX flood — parser/import limits + churn resistance.
 *
 * - Parser (ntx_pex_parse_ex): cap per list, bencode string size bound (65536),
 *   truncated compact records.
 * - Session import path (ntx_session_data_on_ext -> on_pex ->
 *   ntx_session_add_peer_from_tracker): import count <= min(parser cap 32+32,
 *   cfg->max_peers); duplicates not re-added on repeated imports (churn).
 * Deterministic: loopback only, no event loop, count-based assertions.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

#include "../src/core/ntx_session.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_peer.c"
#include "../src/core/ntx_store.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/proto/ntx_pe.c"
#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_holepunch.c"
#include "../src/proto/ntx_pex.c"
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
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_magnet.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/ui/ntx_diag.c"

#include "../src/core/ntx_session_stats.c"
#include "../src/core/ntx_pieceblk.c"
#include "../src/core/ntx_session_webseed.c"
#include "../src/core/ntx_session_pex.c"
#include "../src/core/ntx_session_meta.c"
#include "../src/core/ntx_session_vlog.c"
#include "../src/core/ntx_session_pe.c"
#include "../src/core/ntx_session_bt_hs.c"
#include "../src/proto/ntx_btmsg.c"
#include "../src/proto/ntx_utmeta.c"
#include "../src/proto/ntx_pe_vc.c"

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

/* ---------------- payload builders ---------------- */

static size_t be_len(uint8_t *p, size_t n) {
    char tmp[16];
    int m = snprintf(tmp, sizeof tmp, "%zu:", n);
    memcpy(p, tmp, (size_t)m);
    return (size_t)m;
}

/* d [5:added <v4 compact>] [6:added6 <v6 compact>] [7:dropped <v4>] [8:dropped6 <v6>] e */
static size_t build_pex(uint8_t *out, size_t cap,
                        const uint8_t *v4, size_t v4n,
                        const uint8_t *v6, size_t v6n,
                        const uint8_t *d4, size_t d4n,
                        const uint8_t *d6, size_t d6n) {
    (void)cap;
    uint8_t *p = out;
    *p++ = 'd';
    if (v4n) { memcpy(p, "5:added", 7); p += 7; p += be_len(p, v4n); memcpy(p, v4, v4n); p += v4n; }
    if (v6n) { memcpy(p, "6:added6", 8); p += 8; p += be_len(p, v6n); memcpy(p, v6, v6n); p += v6n; }
    if (d4n) { memcpy(p, "7:dropped", 9); p += 9; p += be_len(p, d4n); memcpy(p, d4, d4n); p += d4n; }
    if (d6n) { memcpy(p, "8:dropped6", 10); p += 10; p += be_len(p, d6n); memcpy(p, d6, d6n); p += d6n; }
    *p++ = 'e';
    return (size_t)(p - out);
}

/* n v4 compact peers: 10.0.0.i : port0+i (parser-only, never dialed) */
static void fill_v4(uint8_t *p, int n, uint16_t port0) {
    for (int i = 0; i < n; i++) {
        uint32_t ip = htonl(0x0a000000u + (uint32_t)i);
        uint16_t port = (uint16_t)(port0 + i);
        memcpy(p, &ip, 4);
        p[4] = (uint8_t)(port >> 8);
        p[5] = (uint8_t)(port & 0xff);
        p += 6;
    }
}

/* n v6 compact peers: 2001:db8::i : port0+i (parser-only) */
static void fill_v6(uint8_t *p, int n, uint16_t port0) {
    for (int i = 0; i < n; i++) {
        uint8_t ip[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        ip[14] = (uint8_t)(i >> 8);
        ip[15] = (uint8_t)(i & 0xff);
        uint16_t port = (uint16_t)(port0 + i);
        memcpy(p, ip, 16);
        p[16] = (uint8_t)(port >> 8);
        p[17] = (uint8_t)(port & 0xff);
        p += 18;
    }
}

/* loopback variants for the session import path */
static void fill_v4_lo(uint8_t *p, int n, uint16_t port0) {
    for (int i = 0; i < n; i++) {
        uint32_t ip = htonl(0x7f000001u); /* 127.0.0.1 */
        uint16_t port = (uint16_t)(port0 + i);
        memcpy(p, &ip, 4);
        p[4] = (uint8_t)(port >> 8);
        p[5] = (uint8_t)(port & 0xff);
        p += 6;
    }
}

static void fill_v6_lo(uint8_t *p, int n, uint16_t port0) {
    for (int i = 0; i < n; i++) {
        uint8_t ip[16] = {0};
        ip[15] = 1; /* ::1 */
        uint16_t port = (uint16_t)(port0 + i);
        memcpy(p, ip, 16);
        p[16] = (uint8_t)(port >> 8);
        p[17] = (uint8_t)(port & 0xff);
        p += 18;
    }
}

/* ---------------- session helpers ---------------- */

static const char *MAGNET =
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=PF&tr=udp://tracker.example.com:6969";

static ntx_session *mk(const ntx_config *cfg, ntx_netx **n) {
    *n = ntx_netx_init(cfg);
    if (!*n) fail("netx_init");
    ntx_session *s = ntx_session_init(*n, cfg);
    if (!s) fail("session_init");
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("add_magnet");
    if (s->n_tts != 1) fail("add_magnet_n");
    return s;
}

static void drop(ntx_session *s, ntx_netx *n) {
    ntx_session_free(s);
    ntx_netx_free(n);
}

static int count_all(const ntx_session *s) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd >= 0) c++;
    return c;
}

static int count_unique(const ntx_session *s) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peers[pi].fd < 0) continue;
        int dup = 0;
        for (int pj = pi + 1; pj < NTX_SESSION_MAX_PEERS; pj++) {
            if (s->peers[pj].fd < 0) continue;
            if (s->peers[pi].port == s->peers[pj].port &&
                ntx_addr_eq(&s->peers[pi].addr, &s->peers[pj].addr))
                dup = 1;
        }
        if (!dup) c++;
    }
    return c;
}

static int peer_present4(const ntx_session *s, uint32_t v4_net, uint16_t port) {
    ntx_addr a;
    ntx_addr_set_v4(&a, v4_net);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd >= 0 && s->peers[pi].port == port &&
            ntx_addr_eq(&s->peers[pi].addr, &a))
            return 1;
    return 0;
}

static int peer_present6(const ntx_session *s, const uint8_t ip6[16], uint16_t port) {
    ntx_addr a;
    ntx_addr_set_v6(&a, ip6);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd >= 0 && s->peers[pi].port == port &&
            ntx_addr_eq(&s->peers[pi].addr, &a))
            return 1;
    return 0;
}

static int find_pi(const ntx_session *s, uint16_t port) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd >= 0 && s->peers[pi].port == port) return pi;
    return -1;
}

static int v6_loopback_ok(void) {
    static const uint8_t lo[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ntx_addr a;
    ntx_addr_set_v6(&a, lo);
    int fd = ntx_sock_tcp6();
    if (fd < 0) return 0;
    int rc = ntx_sock_connect_addr(fd, &a, 6999);
    close(fd);
    return rc == 0;
}

/* ---------------- parser tests ---------------- */

static void test_parser_caps(void) {
    static uint8_t v4[200 * 6], v6[150 * 18], d4[50 * 6], d6[40 * 18];
    fill_v4(v4, 200, 10000);
    fill_v6(v6, 150, 11000);
    fill_v4(d4, 50, 12000);
    fill_v6(d6, 40, 13000);
    uint8_t buf[8192];
    size_t n = build_pex(buf, sizeof buf, v4, sizeof v4, v6, sizeof v6, d4, sizeof d4, d6, sizeof d6);

    /* caps below content: parser must stop exactly at cap (no overflow) */
    {
        static uint32_t aip[100], dip[100];
        static uint16_t apt[100], dport[100];
        static uint8_t a6ip[64][16], d6ip[64][16];
        static uint16_t a6port[64], d6port[64];
        int na = -1, nd = -1, na6 = -1, nd6 = -1;
        if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 100,
                             a6ip, a6port, &na6, d6ip, d6port, &nd6, 64) != 0)
            fail("cap_parse");
        if (na != 100 || na6 != 64 || nd != 50 || nd6 != 40) fail("cap_counts");
    }
    /* caps above content: every peer returned, bounded by payload */
    {
        static uint32_t aip[300], dip[60];
        static uint16_t apt[300], dport[60];
        static uint8_t a6ip[200][16], d6ip[50][16];
        static uint16_t a6port[200], d6port[50];
        int na = -1, nd = -1, na6 = -1, nd6 = -1;
        if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 300,
                             a6ip, a6port, &na6, d6ip, d6port, &nd6, 200) != 0)
            fail("full_parse");
        if (na != 200 || na6 != 150 || nd != 50 || nd6 != 40) fail("full_counts");
        uint32_t ip0, ipL;
        memcpy(&ip0, v4, 4);
        memcpy(&ipL, v4 + 199 * 6, 4);
        if (aip[0] != ip0 || apt[0] != 10000) fail("full_v4_first");
        if (aip[199] != ipL || apt[199] != 10199) fail("full_v4_last");
        if (memcmp(a6ip[149], v6 + 149 * 18, 16) != 0 || a6port[149] != 11149) fail("full_v6_last");
    }
    /* cap=1: exactly one peer per list */
    {
        uint32_t aip[1], dip[1];
        uint16_t apt[1], dport[1];
        int na = -1, nd = -1;
        uint8_t a6ip[1][16], d6ip[1][16];
        uint16_t a6port[1], d6port[1];
        int na6 = -1, nd6 = -1;
        if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 1,
                             a6ip, a6port, &na6, d6ip, d6port, &nd6, 1) != 0)
            fail("one_parse");
        if (na != 1 || na6 != 1 || nd != 1 || nd6 != 1) fail("one_counts");
        uint32_t ip0;
        memcpy(&ip0, v4, 4);
        if (aip[0] != ip0 || apt[0] != 10000) fail("one_v4");
    }
}

static void test_parser_size_bound(void) {
    uint8_t *buf = malloc(72000);
    if (!buf) fail("malloc");
    /* added string 65520 B (10920 peers): payload 65535 <= 65536 -> parse OK */
    {
        static uint8_t v4[10920 * 6];
        fill_v4(v4, 10920, 10000);
        size_t n = build_pex(buf, 72000, v4, sizeof v4, 0, 0, 0, 0, 0, 0);
        if (n != 65535) fail("size_ok_len");
        static uint32_t aip[10];
        static uint16_t apt[10];
        int na = -1, nd = -1;
        if (ntx_pex_parse_ex(buf, n, aip, apt, &na, 0, 0, &nd, 10,
                             0, 0, 0, 0, 0, 0, 0) != 0)
            fail("size_ok_parse");
        if (na != 10) fail("size_ok_count");
    }
    /* added string 69000 B (11500 peers): > 65536 -> parser must reject */
    {
        static uint8_t big[11500 * 6];
        fill_v4(big, 11500, 10000);
        size_t nb = build_pex(buf, 72000, big, sizeof big, 0, 0, 0, 0, 0, 0);
        if (nb <= 65536) fail("size_big_expected");
        uint32_t aip[10];
        uint16_t apt[10];
        int na = -1, nd = -1;
        if (ntx_pex_parse_ex(buf, nb, aip, apt, &na, 0, 0, &nd, 10,
                             0, 0, 0, 0, 0, 0, 0) == 0)
            fail("size_big_reject");
        if (ntx_pex_parse(buf, nb, aip, apt, &na, 0, 0, &nd, 10) == 0)
            fail("size_big_reject_legacy");
    }
    free(buf);
}

static void test_parser_trunc(void) {
    /* added = 3 full 6 B records + 3 trailing bytes -> exactly 3 peers */
    uint8_t v4[21];
    fill_v4(v4, 3, 10000);
    v4[18] = 0xff;
    v4[19] = 0xff;
    v4[20] = 0xff;
    uint8_t buf[64];
    size_t n = build_pex(buf, sizeof buf, v4, 21, 0, 0, 0, 0, 0, 0);
    uint32_t aip[8];
    uint16_t apt[8];
    int na = -1, nd = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, 0, 0, &nd, 8,
                         0, 0, 0, 0, 0, 0, 0) != 0)
        fail("trunc_parse");
    if (na != 3 || nd != 0) fail("trunc_count");
}

/* ---------------- session import tests ---------------- */

#define SRC_PORT 6999
#define V4_BASE 20000
#define V6_BASE 30000
#define N_V4 300
#define N_V6 100
#define PEX_V4_CAP 32 /* session parser cap (ntx_session_pex.c) */
#define PEX_V6_CAP 32

static void build_session_flood(uint8_t *out, size_t cap, size_t *outn) {
    static uint8_t v4[N_V4 * 6], v6[N_V6 * 18];
    fill_v4_lo(v4, N_V4, V4_BASE);
    fill_v6_lo(v6, N_V6, V6_BASE);
    *outn = build_pex(out, cap, v4, sizeof v4, v6, sizeof v6, 0, 0, 0, 0);
}

static void cfg_default(ntx_config *cfg, int max_peers) {
    memset(cfg, 0, sizeof *cfg);
    cfg->store_dir = "downloads";
    cfg->port_lo = 6881;
    cfg->port_hi = 6891;
    cfg->max_peers = max_peers;
    cfg->allow_local_peers = 1; /* these tests talk to 127.0.0.1 */
}

static void test_session_flood(int v6ok) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    ntx_addr src;
    ntx_addr_set_v4(&src, htonl(0x7f000001u));
    ntx_session_add_peer_from_tracker(s, 0, &src, SRC_PORT);
    if (count_all(s) != 1) fail("flood_src");
    int pi = find_pi(s, SRC_PORT);
    if (pi < 0) fail("flood_src_pi");

    uint8_t payload[4096];
    size_t pn = 0;
    build_session_flood(payload, sizeof payload, &pn);

    ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);

    int exp_v6 = v6ok ? (cfg.max_peers - 1 - PEX_V4_CAP) : 0; /* 17 */
    int exp_total = 1 + PEX_V4_CAP + exp_v6;                  /* 50 or 33 */
    int total = count_all(s);
    if (total != exp_total) fail("flood_total");
    if (total > cfg.max_peers) fail("flood_maxp");
    for (int i = 0; i < PEX_V4_CAP; i++)
        if (!peer_present4(s, htonl(0x7f000001u), (uint16_t)(V4_BASE + i)))
            fail("flood_v4");
    static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (v6ok) {
        for (int i = 0; i < exp_v6; i++)
            if (!peer_present6(s, lo6, (uint16_t)(V6_BASE + i))) fail("flood_v6");
        for (int i = exp_v6; i < PEX_V6_CAP; i++)
            if (peer_present6(s, lo6, (uint16_t)(V6_BASE + i))) fail("flood_v6_overflow");
    }
    /* no foreign peers: every live peer is in the expected set */
    for (int pj = 0; pj < NTX_SESSION_MAX_PEERS; pj++) {
        if (s->peers[pj].fd < 0) continue;
        uint16_t port = s->peers[pj].port;
        int known = 0;
        if (port == SRC_PORT) known = 1;
        else if (ntx_addr_is_v4(&s->peers[pj].addr) && port >= V4_BASE &&
                 port < V4_BASE + PEX_V4_CAP)
            known = 1;
        else if (v6ok && ntx_addr_is_v6(&s->peers[pj].addr) && port >= V6_BASE &&
                 port < V6_BASE + exp_v6)
            known = 1;
        if (!known) fail("flood_foreign");
    }

    /* churn: re-import the identical payload 200 more times (spam import).
     * Count must stay pinned at the limit; duplicates must not accumulate. */
    for (int t = 0; t < 200; t++) {
        ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);
        if (count_all(s) != exp_total) fail("churn_growth");
    }
    if (count_unique(s) != exp_total) fail("churn_dupes");

    drop(s, n);
}

static void test_maxp_gt_parser_cap(int v6ok) {
    ntx_config cfg;
    cfg_default(&cfg, 100);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    ntx_addr src;
    ntx_addr_set_v4(&src, htonl(0x7f000001u));
    ntx_session_add_peer_from_tracker(s, 0, &src, SRC_PORT);
    int pi = find_pi(s, SRC_PORT);
    if (pi < 0) fail("cap_src_pi");

    uint8_t payload[4096];
    size_t pn = 0;
    build_session_flood(payload, sizeof payload, &pn);
    ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);

    /* parser cap (32+32) is the binding limit here, not max_peers=100 */
    int exp_total = 1 + PEX_V4_CAP + (v6ok ? PEX_V6_CAP : 0);
    if (count_all(s) != exp_total) fail("cap_total");
    if (count_all(s) > cfg.max_peers) fail("cap_maxp");
    for (int i = 0; i < PEX_V4_CAP; i++)
        if (!peer_present4(s, htonl(0x7f000001u), (uint16_t)(V4_BASE + i)))
            fail("cap_v4");
    static const uint8_t lo6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    if (v6ok)
        for (int i = 0; i < PEX_V6_CAP; i++)
            if (!peer_present6(s, lo6, (uint16_t)(V6_BASE + i))) fail("cap_v6");

    drop(s, n);
}

static void test_dropped_not_imported(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    ntx_addr src;
    ntx_addr_set_v4(&src, htonl(0x7f000001u));
    ntx_session_add_peer_from_tracker(s, 0, &src, SRC_PORT);
    int pi = find_pi(s, SRC_PORT);
    if (pi < 0) fail("drop_src_pi");

    static uint8_t d4[10 * 6], d6[10 * 18];
    fill_v4(d4, 10, 40000);
    fill_v6(d6, 10, 41000);
    uint8_t payload[512];
    size_t pn = build_pex(payload, sizeof payload, 0, 0, 0, 0, d4, sizeof d4, d6, sizeof d6);

    /* parser sees dropped/dropped6 ... */
    {
        uint32_t aip[16], dip[16];
        uint16_t apt[16], dport[16];
        int na = -1, nd = -1;
        uint8_t d6ip[16][16];
        uint16_t d6port[16];
        int nd6 = -1;
        if (ntx_pex_parse_ex(payload, pn, aip, apt, &na, dip, dport, &nd, 16,
                             0, 0, 0, d6ip, d6port, &nd6, 16) != 0)
            fail("drop_parse");
        if (na != 0 || nd != 10 || nd6 != 10) fail("drop_counts");
    }
    /* ... but the import path must not add them (bounded, no churn source) */
    for (int t = 0; t < 50; t++)
        ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);
    if (count_all(s) != 1) fail("drop_imported");

    drop(s, n);
}

static void test_zero_entries_skipped(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    ntx_addr src;
    ntx_addr_set_v4(&src, htonl(0x7f000001u));
    ntx_session_add_peer_from_tracker(s, 0, &src, SRC_PORT);
    int pi = find_pi(s, SRC_PORT);
    if (pi < 0) fail("zero_src_pi");

    /* added: 0.0.0.0:50001 (zero IP), 127.0.0.1:50002 (valid), 127.0.0.1:0 (zero port) */
    uint8_t v4[18];
    uint32_t z = 0, lo = htonl(0x7f000001u);
    memcpy(v4, &z, 4);
    v4[4] = 50001 >> 8;
    v4[5] = 50001 & 0xff;
    memcpy(v4 + 6, &lo, 4);
    v4[10] = 50002 >> 8;
    v4[11] = 50002 & 0xff;
    memcpy(v4 + 12, &lo, 4);
    v4[16] = 0;
    v4[17] = 0;
    uint8_t payload[64];
    size_t pn = build_pex(payload, sizeof payload, v4, 18, 0, 0, 0, 0, 0, 0);

    {
        uint32_t aip[4];
        uint16_t apt[4];
        int na = -1, nd = -1;
        if (ntx_pex_parse_ex(payload, pn, aip, apt, &na, 0, 0, &nd, 4,
                             0, 0, 0, 0, 0, 0, 0) != 0)
            fail("zero_parse");
        if (na != 3) fail("zero_count");
    }
    ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);
    if (count_all(s) != 2) fail("zero_imported");
    if (!peer_present4(s, lo, 50002)) fail("zero_valid");
    if (peer_present4(s, lo, 50001)) fail("zero_ip_imported");

    drop(s, n);
}

static void test_oversized_via_session(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    ntx_addr src;
    ntx_addr_set_v4(&src, htonl(0x7f000001u));
    ntx_session_add_peer_from_tracker(s, 0, &src, SRC_PORT);
    int pi = find_pi(s, SRC_PORT);
    if (pi < 0) fail("over_src_pi");

    static uint8_t big[11500 * 6];
    fill_v4(big, 11500, 10000);
    uint8_t *payload = malloc(72000);
    if (!payload) fail("malloc");
    size_t pn = build_pex(payload, 72000, big, sizeof big, 0, 0, 0, 0, 0, 0);
    /* parse fails (string > 65536) -> import is a no-op, session intact */
    for (int t = 0; t < 10; t++)
        ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);
    if (count_all(s) != 1) fail("over_imported");
    free(payload);

    drop(s, n);
}

int main(void) {
    ntx_rng_init();

    test_parser_caps();
    printf("PASS parser_caps\n");
    test_parser_size_bound();
    printf("PASS parser_size_bound\n");
    test_parser_trunc();
    printf("PASS parser_trunc\n");

    int v6ok = v6_loopback_ok();
    if (!v6ok) printf("SKIP v6 loopback unavailable (no AF_INET6 ::1)\n");

    test_session_flood(v6ok);
    printf("PASS session_flood_churn\n");
    test_maxp_gt_parser_cap(v6ok);
    printf("PASS maxp_gt_parser_cap\n");
    test_dropped_not_imported();
    printf("PASS dropped_not_imported\n");
    test_zero_entries_skipped();
    printf("PASS zero_entries_skipped\n");
    test_oversized_via_session();
    printf("PASS oversized_via_session\n");

    return 0;
}
