#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdio.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/proto/ntx_pex.c"
#include "../src/ui/ntx_diag.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int test_pex_roundtrip(void) {
    uint8_t out[64];
    size_t n = 0;
    uint32_t ip = 0x0100007fu;
    uint16_t port = 6881;
    if (ntx_pex_build_added(out, sizeof out, &n, ip, port) != 0) return fail("pex_build");
    uint32_t aip[8];
    uint16_t apt[8];
    int na = 0, nd = 0;
    if (ntx_pex_parse(out, n, aip, apt, &na, 0, 0, &nd, 8) != 0) return fail("pex_parse");
    if (na != 1 || aip[0] != ip || apt[0] != port) return fail("pex_match");
    return 0;
}

static int test_dht_get_peers_encode(void) {
    ntx_netx *n = ntx_netx_init(NULL);
    if (!n) return fail("netx");
    if (ntx_dht_start(n) != 0) {
        ntx_netx_free(n);
        return fail("dht_start");
    }
    uint8_t ih[20];
    for (int i = 0; i < 20; i++) ih[i] = (uint8_t)(i * 7 + 3);
    int got = 0;
    ntx_dht_lookup_peers(ih, NULL, NULL);
    ntx_dht_stop();
    ntx_netx_free(n);
    (void)got;
    printf("PASS dht_get_peers_encode\n");
    return 0;
}

static int test_dht_peer_addr_type(void) {
    ntx_dht_peer p;
    memset(&p, 0, sizeof p);
    uint8_t v6[16];
    for (int i = 0; i < 16; i++) v6[i] = (uint8_t)(0x80 + i);
    ntx_addr_set_v6(&p.addr, v6);
    p.port = 6881;
    if (!ntx_addr_is_v6(&p.addr)) return fail("peer_addr_v6");
    if (ntx_addr_is_v4(&p.addr)) return fail("peer_addr_v4");
    return 0;
}

static int test_dht_dual_udp(void) {
    ntx_netx *n = ntx_netx_init(NULL);
    if (!n) return fail("netx");
    if (ntx_dht_start(n) != 0) {
        ntx_netx_free(n);
        return fail("dht_start");
    }
    if (ntx_dht_port4() == 0) {
        ntx_dht_stop();
        ntx_netx_free(n);
        return fail("dht_port4");
    }
    if (ntx_dht_port6() > 0) {
        if (ntx_dht_has_v6() != 1) {
            ntx_dht_stop();
            ntx_netx_free(n);
            return fail("dht_has_v6");
        }
        int tfd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        if (tfd >= 0) {
            int one = 1;
            setsockopt(tfd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
            struct sockaddr_in6 dst;
            memset(&dst, 0, sizeof dst);
            dst.sin6_family = AF_INET6;
            dst.sin6_addr = in6addr_loopback;
            dst.sin6_port = htons(ntx_dht_port6());
            const uint8_t pkt[] = "d1:q4:ping1:t2:XX1:y1:qe";
            sendto(tfd, pkt, sizeof pkt - 1, 0, (struct sockaddr *)&dst, sizeof dst);
            close(tfd);
        }
        ntx_netx_run_once(n, 200);
        ntx_dht_stop();
        ntx_netx_free(n);
        printf("PASS dht_dual_udp\n");
    } else {
        ntx_dht_stop();
        ntx_netx_free(n);
        printf("PASS dht_dual_udp (v6 unavailable — soft skip)\n");
    }
    return 0;
}

static int test_dht_inject_node(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    if (!netx) return fail("netx");
    if (ntx_dht_start(netx) != 0) {
        ntx_netx_free(netx);
        return fail("dht_start");
    }
    ntx_addr a;
    ntx_addr_set_v4(&a, inet_addr("127.0.0.2"));
    uint8_t id[20];
    memset(id, 0xA1, 20);
    if (ntx_dht_test_inject_node(id, &a, 6881) != 1) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("inject-node");
    }
    if (ntx_dht_node_count(0) != 1) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("inject-count");
    }
    ntx_dht_stop();
    ntx_netx_free(netx);
    printf("PASS dht_inject_node\n");
    return 0;
}

static int test_dht_tid_roundtrip(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    if (!netx) return fail("netx");
    if (ntx_dht_start(netx) != 0) {
        ntx_netx_free(netx);
        return fail("dht_start");
    }
    int s = ntx_sock_udp4();
    if (s < 0) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("udp4");
    }
    uint16_t P = ntx_sock_bind0(s);
    if (P == 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("bind0");
    }
    ntx_addr lo;
    ntx_addr_set_v4(&lo, inet_addr("127.0.0.1"));
    /* Known source = seed (not RT): if idB had the same addr:port as the
       injected RT node, dedup (addr+port) would block rt_add. */
    if (ntx_dht_test_inject_seed(&lo, P) != 1) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("inject-seed");
    }
    int before = ntx_dht_node_count(0);   /* 0 — RT empty */
    ntx_dht_tick();   /* RT empty → ping the first v4 seed = loopback */
    ntx_netx_run_once(netx, 300);
    uint8_t rbuf[512];
    struct sockaddr_in sin;
    socklen_t slen = sizeof sin;
    ssize_t rn = recvfrom(s, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
    if (rn <= 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("recv-ping");
    }
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("parse-ping");
    }
    if (!v.y || v.y[0] != 'q' || !v.q || strcmp(v.q, "ping") != 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("ping-q");
    }
    if (v.tid_len != NTX_DHT_TID_LEN) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("ping-tid-len");
    }
    uint8_t tid[2];
    memcpy(tid, v.tid, 2);

    uint8_t idB[20];
    memset(idB, 0x42, 20);
    uint8_t echo[128];
    int e = 0;
    const char *k1 = "d1:rd2:id20:";
    memcpy(echo, k1, 12);
    e = 12;
    memcpy(echo + e, idB, 20);
    e += 20;
    const char *k2 = "e1:t2:";
    memcpy(echo + e, k2, 6);
    e += 6;
    echo[e++] = tid[0];
    echo[e++] = tid[1];
    const char *k3 = "1:y1:re";
    memcpy(echo + e, k3, 7);
    e += 7;
    ntx_dht_msg_view ev;
    if (ntx_dht_msg_parse(echo, (size_t)e, &ev) != 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("echo-parse");
    }
    if (!ev.y || ev.y[0] != 'r' || ev.tid_len != 2 || memcmp(ev.tid, tid, 2) != 0 ||
        !ev.id || ev.id_len != 20) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("echo-fields");
    }

    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst.sin_port = htons(ntx_dht_port4());
    if (sendto(s, echo, (size_t)e, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("echo-send");
    }
    ntx_netx_run_once(netx, 300);
    int after = ntx_dht_node_count(0);
    if (after <= before) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("rt-add-matched");
    }

    uint8_t echo2[128];
    int e2 = 0;
    memcpy(echo2, k1, 12);
    e2 = 12;
    memcpy(echo2 + e2, idB, 20);
    e2 += 20;
    memcpy(echo2 + e2, k2, 6);
    e2 += 6;
    echo2[e2++] = 0x5A;
    echo2[e2++] = 0x77;
    memcpy(echo2 + e2, k3, 7);
    e2 += 7;
    if (sendto(s, echo2, (size_t)e2, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("neg-send");
    }
    ntx_netx_run_once(netx, 300);
    if (ntx_dht_node_count(0) != after) {
        close(s);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("rt-drop-unmatched");
    }

    ntx_dht_stop();
    close(s);
    ntx_netx_free(netx);
    printf("PASS dht_tid_roundtrip\n");
    return 0;
}

static uint64_t test_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static size_t be_raw(uint8_t *b, size_t off, const void *p, size_t n) {
    memcpy(b + off, p, n);
    return off + n;
}

static size_t be_key(uint8_t *b, size_t off, const char *k) {
    char h[24];
    int n = snprintf(h, sizeof h, "%zu:%s", strlen(k), k);
    return be_raw(b, off, h, (size_t)n);
}

static size_t be_str(uint8_t *b, size_t off, const void *v, size_t n) {
    char h[16];
    int m = snprintf(h, sizeof h, "%zu:", n);
    off = be_raw(b, off, h, (size_t)m);
    return be_raw(b, off, v, n);
}

static int lk_cb_calls;
static int lk_cb_peers;
static uint8_t lk_cb_hash[20];

static void lk_cb(const uint8_t hash[20], const ntx_dht_peer *p, int n, void *ud) {
    (void)p;
    (void)ud;
    lk_cb_calls++;
    lk_cb_peers += n;
    memcpy(lk_cb_hash, hash, 20);
}

static int test_dht_iterative_lookup(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    int s4 = -1, s6 = -1;
    if (!netx) return fail("netx");
    if (ntx_dht_start(netx) != 0) goto fail;
    s4 = ntx_sock_udp4();
    if (s4 < 0) goto fail;
    uint16_t P4 = ntx_sock_bind0(s4);
    if (P4 == 0) goto fail;
    int have_v6 = (ntx_dht_port6() > 0);
    if (have_v6) {
        s6 = ntx_sock_udp6();
        if (s6 < 0) goto fail;
        uint16_t P6 = ntx_sock_bind6(s6, 0);
        if (P6 == 0) goto fail;
        ntx_addr a6;
        ntx_addr_set_v6(&a6, (const uint8_t *)&in6addr_loopback);
        uint8_t idA6[20];
        memset(idA6, 0xB2, 20);
        if (ntx_dht_test_inject_node(idA6, &a6, P6) != 1) goto fail;
    }
    ntx_addr a4;
    ntx_addr_set_v4(&a4, inet_addr("127.0.0.1"));
    uint8_t idA[20];
    memset(idA, 0xB1, 20);
    if (ntx_dht_test_inject_node(idA, &a4, P4) != 1) goto fail;
    int rt4_before = ntx_dht_node_count(0);
    lk_cb_calls = 0;
    lk_cb_peers = 0;
    memset(lk_cb_hash, 0, sizeof lk_cb_hash);
    uint8_t h[20];
    memset(h, 0xC2, 20);
    ntx_dht_lookup_peers(h, lk_cb, NULL);
    if (ntx_dht_lookup_active() != 1) goto fail;
    ntx_netx_run_once(netx, 300);
    uint8_t rbuf[512];
    struct sockaddr_in sin;
    socklen_t slen = sizeof sin;
    ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
    if (rn <= 0) goto fail;
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
    if (!v.y || v.y[0] != 'q' || !v.q || strcmp(v.q, "get_peers") != 0) goto fail;
    if (!v.info_hash || memcmp(v.info_hash, h, 20) != 0) goto fail;
    if (!v.want_n4 || !v.want_n6) goto fail;
    if (v.tid_len != NTX_DHT_TID_LEN) goto fail;
    uint8_t tid4[2];
    memcpy(tid4, v.tid, 2);
    uint8_t idR[20];
    memset(idR, 0xD1, 20);
    uint8_t idN[20];
    memset(idN, 0xD3, 20);
    uint32_t ip4 = inet_addr("127.0.0.1");
    uint8_t nodes26[26];
    memcpy(nodes26, idN, 20);
    memcpy(nodes26 + 20, &ip4, 4);
    nodes26[24] = (uint8_t)(9999 >> 8);
    nodes26[25] = (uint8_t)(9999 & 0xFF);
    uint8_t vals12[12];
    memcpy(vals12, &ip4, 4);
    vals12[4] = (uint8_t)(5001 >> 8);
    vals12[5] = (uint8_t)(5001 & 0xFF);
    memcpy(vals12 + 6, &ip4, 4);
    vals12[10] = (uint8_t)(5002 >> 8);
    vals12[11] = (uint8_t)(5002 & 0xFF);
    uint8_t tok8[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    uint8_t echo[256];
    size_t e = 0;
    echo[e++] = 'd';
    e = be_key(echo, e, "r");
    echo[e++] = 'd';
    e = be_key(echo, e, "id");
    e = be_str(echo, e, idR, 20);
    e = be_key(echo, e, "nodes");
    e = be_str(echo, e, nodes26, 26);
    e = be_key(echo, e, "token");
    e = be_str(echo, e, tok8, 8);
    e = be_key(echo, e, "values");
    e = be_str(echo, e, vals12, 12);
    echo[e++] = 'e';
    e = be_key(echo, e, "t");
    e = be_str(echo, e, tid4, 2);
    e = be_key(echo, e, "y");
    e = be_str(echo, e, "r", 1);
    echo[e++] = 'e';
    ntx_dht_msg_view ev;
    if (ntx_dht_msg_parse(echo, e, &ev) != 0 || !ev.y || ev.y[0] != 'r' ||
        ev.tid_len != 2 || memcmp(ev.tid, tid4, 2) != 0 ||
        !ev.id || ev.id_len != 20 || ev.nodes_len != 26 || ev.values_len != 12 ||
        ev.token_len != 8)
        goto fail;
    struct sockaddr_in dst4;
    memset(&dst4, 0, sizeof dst4);
    dst4.sin_family = AF_INET;
    dst4.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst4.sin_port = htons(ntx_dht_port4());
    if (sendto(s4, echo, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
    ntx_netx_run_once(netx, 300);
    if (lk_cb_calls < 1 || lk_cb_peers < 2 || memcmp(lk_cb_hash, h, 20) != 0)
        goto fail;
    if (ntx_dht_node_count(0) <= rt4_before) goto fail;
    if (have_v6) {
        struct sockaddr_in6 sin6;
        socklen_t sl6 = sizeof sin6;
        ssize_t r6 = recvfrom(s6, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin6, &sl6);
        if (r6 <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)r6, &v) != 0 || !v.y || v.y[0] != 'q' ||
            !v.q || strcmp(v.q, "get_peers") != 0 ||
            !v.info_hash || memcmp(v.info_hash, h, 20) != 0 ||
            v.tid_len != NTX_DHT_TID_LEN)
            goto fail;
        uint8_t tid6[2];
        memcpy(tid6, v.tid, 2);
        uint8_t idR6[20];
        memset(idR6, 0xD2, 20);
        uint8_t idN6[20];
        memset(idN6, 0xD4, 20);
        uint8_t nodes38[38];
        memcpy(nodes38, idN6, 20);
        memcpy(nodes38 + 20, &in6addr_loopback, 16);
        nodes38[36] = (uint8_t)(9999 >> 8);
        nodes38[37] = (uint8_t)(9999 & 0xFF);
        uint8_t vals18[18];
        memcpy(vals18, &in6addr_loopback, 16);
        vals18[16] = (uint8_t)(5001 >> 8);
        vals18[17] = (uint8_t)(5001 & 0xFF);
        uint8_t echo6[256];
        size_t e6 = 0;
        echo6[e6++] = 'd';
        e6 = be_key(echo6, e6, "r");
        echo6[e6++] = 'd';
        e6 = be_key(echo6, e6, "id");
        e6 = be_str(echo6, e6, idR6, 20);
        e6 = be_key(echo6, e6, "nodes6");
        e6 = be_str(echo6, e6, nodes38, 38);
        e6 = be_key(echo6, e6, "token");
        e6 = be_str(echo6, e6, tok8, 8);
        e6 = be_key(echo6, e6, "values6");
        e6 = be_str(echo6, e6, vals18, 18);
        echo6[e6++] = 'e';
        e6 = be_key(echo6, e6, "t");
        e6 = be_str(echo6, e6, tid6, 2);
        e6 = be_key(echo6, e6, "y");
        e6 = be_str(echo6, e6, "r", 1);
        echo6[e6++] = 'e';
        if (ntx_dht_msg_parse(echo6, e6, &ev) != 0 || !ev.y || ev.y[0] != 'r' ||
            ev.tid_len != 2 || memcmp(ev.tid, tid6, 2) != 0 ||
            ev.values6_len != 18 || ev.nodes6_len != 38)
            goto fail;
        struct sockaddr_in6 dst6;
        memset(&dst6, 0, sizeof dst6);
        dst6.sin6_family = AF_INET6;
        dst6.sin6_addr = in6addr_loopback;
        dst6.sin6_port = htons(ntx_dht_port6());
        if (sendto(s6, echo6, e6, 0, (struct sockaddr *)&dst6, sizeof dst6) < 0)
            goto fail;
        ntx_netx_run_once(netx, 300);
        if (lk_cb_calls < 2 || lk_cb_peers < 3) goto fail;
    }
    uint64_t t0 = test_mono_ms();
    while (ntx_dht_lookup_active() && test_mono_ms() - t0 < 6000) {
        ntx_dht_tick();
        ntx_netx_run_once(netx, 200);
    }
    if (ntx_dht_lookup_active() != 0) goto fail;
    ntx_dht_stop();
    if (s6 >= 0) close(s6);
    close(s4);
    ntx_netx_free(netx);
    printf("PASS dht_iterative_lookup\n");
    return 0;
fail:
    printf("FAIL dht_iterative_lookup\n");
    ntx_dht_stop();
    if (s6 >= 0) close(s6);
    if (s4 >= 0) close(s4);
    ntx_netx_free(netx);
    return 1;
}

static int test_dht_rate_in(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    int s = -1;
    if (!netx) return fail("netx");
    if (ntx_dht_start(netx) != 0) {
        ntx_netx_free(netx);
        return fail("dht_start");
    }
    s = ntx_sock_udp4();
    if (s < 0) goto fail;
    if (ntx_sock_bind0(s) == 0) goto fail;
    int rx0, tx0, rd0, td0;
    ntx_dht_stats(&rx0, &tx0, &rd0, &td0);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst.sin_port = htons(ntx_dht_port4());
    for (int i = 0; i < 15; i++) {
        uint8_t tid[2] = {(uint8_t)(0x10 + i), (uint8_t)(0xA0 + i)};
        uint8_t id[20];
        memset(id, (uint8_t)(0x20 + i), 20);
        uint8_t pkt[128];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, id, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "ping", 4);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "ping") != 0 || pv.tid_len != NTX_DHT_TID_LEN)
            goto fail;
        if (sendto(s, pkt, e, 0, (struct sockaddr *)&dst, sizeof dst) < 0) goto fail;
    }
    ntx_netx_run_once(netx, 300);
    int rx, tx, rd, td;
    ntx_dht_stats(&rx, &tx, &rd, &td);
    if ((rx - rx0) + (rd - rd0) != 15) goto fail;
    if ((rx - rx0) > 10) goto fail;
    if ((rd - rd0) < 5) goto fail;
    ntx_dht_stop();
    close(s);
    ntx_netx_free(netx);
    printf("PASS dht_rate_in (rx=%d rd=%d)\n", rx - rx0, rd - rd0);
    return 0;
fail:
    ntx_dht_stop();
    if (s >= 0) close(s);
    ntx_netx_free(netx);
    return fail("dht_rate_in");
}

static int test_dht_inbound_queries(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    int s4 = -1, s6 = -1;
    if (!netx) return fail("inb-netx");
    if (ntx_dht_start(netx) != 0) goto fail;
    uint8_t myid[20];
    if (ntx_dht_node_id_get(myid) != 0) goto fail;
    ntx_addr a4;
    ntx_addr_set_v4(&a4, inet_addr("127.0.0.1"));
    uint8_t idn[20];
    for (int i = 0; i < 3; i++) {
        memset(idn, (uint8_t)(0xE1 + i), 20);
        if (ntx_dht_test_inject_node(idn, &a4, (uint16_t)(6001 + i)) != 1) goto fail;
    }
    int have_v6 = (ntx_dht_has_v6() == 1);
    if (have_v6) {
        ntx_addr a6;
        ntx_addr_set_v6(&a6, (const uint8_t *)&in6addr_loopback);
        for (int i = 0; i < 2; i++) {
            memset(idn, (uint8_t)(0xE4 + i), 20);
            if (ntx_dht_test_inject_node(idn, &a6, (uint16_t)(6004 + i)) != 1) goto fail;
        }
    }
    s4 = ntx_sock_udp4();
    if (s4 < 0) goto fail;
    if (ntx_sock_bind0(s4) == 0) goto fail;
    struct sockaddr_in dst4;
    memset(&dst4, 0, sizeof dst4);
    dst4.sin_family = AF_INET;
    dst4.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst4.sin_port = htons(ntx_dht_port4());
    uint8_t rbuf[512];
    struct sockaddr_in sin;
    socklen_t slen;
    ntx_dht_msg_view v;
    uint8_t idq[20];
    memset(idq, 0xF1, 20);
    /* PING: d{ a:{id}, q:"ping", t:"AB", y:"q" } */
    {
        uint8_t tid[2] = {'A', 'B'};
        uint8_t pkt[128];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "ping", 4);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "ping") != 0 || pv.tid_len != 2)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
        if (rn <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
        if (!v.y || v.y[0] != 'r') goto fail;
        if (!v.tid || v.tid_len != 2 || v.tid[0] != 'A' || v.tid[1] != 'B') goto fail;
        if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
    }
    /* FIND_NODE v4: d{ a:{id,target}, q:"find_node", t:"CD", y:"q" } */
    {
        uint8_t tid[2] = {'C', 'D'};
        uint8_t tgt[20];
        memset(tgt, 0xE9, 20);
        uint8_t pkt[160];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        e = be_key(pkt, e, "target");
        e = be_str(pkt, e, tgt, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "find_node", 10);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "find_node") != 0 ||
            !pv.target || pv.target_len != 20 || memcmp(pv.target, tgt, 20) != 0)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
        if (rn <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
        if (!v.y || v.y[0] != 'r') goto fail;
        if (!v.tid || v.tid_len != 2 || v.tid[0] != 'C' || v.tid[1] != 'D') goto fail;
        if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
        if (v.nodes_len != 3 * 26) goto fail;
        if (v.nodes6 != NULL) goto fail;
        ntx_dht_node nn[8];
        if (ntx_dht_msg_parse_nodes(v.nodes, v.nodes_len, nn, 8, 0) != 3) goto fail;
        uint16_t ports[3] = {nn[0].port, nn[1].port, nn[2].port};
        for (int i = 0; i < 3; i++)
            if (!ntx_addr_is_v4(&nn[i].addr) || nn[i].addr.u.v4 != inet_addr("127.0.0.1"))
                goto fail;
        for (int i = 0; i < 3; i++)
            for (int j = i + 1; j < 3; j++)
                if (ports[i] > ports[j]) {
                    uint16_t t = ports[i];
                    ports[i] = ports[j];
                    ports[j] = t;
                }
        for (int i = 0; i < 3; i++)
            if (ports[i] != (uint16_t)(6001 + i)) goto fail;
    }
    /* FIND_NODE v6 (soft skip when there is no ::1) */
    if (have_v6) {
        s6 = ntx_sock_udp6();
        if (s6 < 0) goto fail;
        int one = 1;
        setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        if (ntx_sock_bind6(s6, 0) == 0) goto fail;
        uint8_t tid[2] = {'E', 'F'};
        uint8_t tgt[20];
        memset(tgt, 0xE7, 20);
        uint8_t pkt[160];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        e = be_key(pkt, e, "target");
        e = be_str(pkt, e, tgt, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "find_node", 10);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "find_node") != 0 ||
            !pv.target || pv.target_len != 20 || memcmp(pv.target, tgt, 20) != 0)
            goto fail;
        struct sockaddr_in6 dst6;
        memset(&dst6, 0, sizeof dst6);
        dst6.sin6_family = AF_INET6;
        dst6.sin6_addr = in6addr_loopback;
        dst6.sin6_port = htons(ntx_dht_port6());
        if (sendto(s6, pkt, e, 0, (struct sockaddr *)&dst6, sizeof dst6) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        struct sockaddr_in6 sin6;
        socklen_t sl6 = sizeof sin6;
        ssize_t rn = recvfrom(s6, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin6, &sl6);
        if (rn <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
        if (!v.y || v.y[0] != 'r') goto fail;
        if (!v.tid || v.tid_len != 2 || v.tid[0] != 'E' || v.tid[1] != 'F') goto fail;
        if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
        if (v.nodes6_len != 2 * 38) goto fail;
        if (v.nodes != NULL) goto fail;
        ntx_dht_node nn[8];
        if (ntx_dht_msg_parse_nodes6(v.nodes6, v.nodes6_len, nn, 8, 0) != 2) goto fail;
        uint16_t ports[2] = {nn[0].port, nn[1].port};
        for (int i = 0; i < 2; i++) {
            if (!ntx_addr_is_v6(&nn[i].addr)) goto fail;
            for (int j = 0; j < 15; j++)
                if (nn[i].addr.u.v6[j] != 0) goto fail;
            if (nn[i].addr.u.v6[15] != 1) goto fail;
        }
        if (ports[0] > ports[1]) {
            uint16_t t = ports[0];
            ports[0] = ports[1];
            ports[1] = t;
        }
        if (ports[0] != 6004 || ports[1] != 6005) goto fail;
    }
    /* NEGATIVE: find_node without a target (a{id}) → zero datagrams from dht */
    {
        uint8_t tid[2] = {'G', 'H'};
        uint8_t pkt[128];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "find_node", 10);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "find_node") != 0 || pv.target != NULL)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 100);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, MSG_DONTWAIT,
                              (struct sockaddr *)&sin, &slen);
        if (rn != -1) goto fail;   /* EAGAIN expected */
    }
    ntx_dht_stop();
    if (s6 >= 0) close(s6);
    close(s4);
    ntx_netx_free(netx);
    printf("PASS dht_inbound_queries%s\n", have_v6 ? "" : " (v6 soft skip)");
    return 0;
fail:
    printf("FAIL dht_inbound_queries\n");
    ntx_dht_stop();
    if (s6 >= 0) close(s6);
    if (s4 >= 0) close(s4);
    ntx_netx_free(netx);
    return 1;
}

/* inbound get_peers (token + values + nodes by source family) and
   announce_peer (verify token → store + r_ping; bad token → drop). */
static int test_dht_inbound_announce(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    int s4 = -1, s6 = -1;
    if (!netx) return fail("ann-netx");
    if (ntx_dht_start(netx) != 0) goto fail;
    uint8_t myid[20];
    if (ntx_dht_node_id_get(myid) != 0) goto fail;
    uint8_t h[20];
    memset(h, 0x5A, 20);
    ntx_addr a4;
    ntx_addr_set_v4(&a4, inet_addr("127.0.0.1"));
    uint8_t idn[20];
    for (int i = 0; i < 2; i++) {
        memset(idn, (uint8_t)(0xD1 + i), 20);
        if (ntx_dht_test_inject_node(idn, &a4, (uint16_t)(7001 + i)) != 1) goto fail;
    }
    s4 = ntx_sock_udp4();
    if (s4 < 0) goto fail;
    if (ntx_sock_bind0(s4) == 0) goto fail;
    struct sockaddr_in dst4;
    memset(&dst4, 0, sizeof dst4);
    dst4.sin_family = AF_INET;
    dst4.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst4.sin_port = htons(ntx_dht_port4());
    uint8_t rbuf[512];
    struct sockaddr_in sin;
    socklen_t slen;
    ntx_dht_msg_view v;
    uint8_t idq[20];
    memset(idq, 0xF2, 20);
    int have_v6 = (ntx_dht_has_v6() == 1);
    /* 1) GET_PEERS v4 (want n4) → r: id, token(8), no values, nodes = 2×26 from rt4 */
    uint8_t tok4[8];
    {
        uint8_t tid[2] = {'I', 'A'};
        uint8_t pkt[256];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        e = be_key(pkt, e, "info_hash");
        e = be_str(pkt, e, h, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "get_peers", 9);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "want");
        pkt[e++] = 'l';
        e = be_str(pkt, e, "n4", 2);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "get_peers") != 0 ||
            !pv.info_hash || memcmp(pv.info_hash, h, 20) != 0 || !pv.want_n4)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
        if (rn <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
        if (!v.y || v.y[0] != 'r') goto fail;
        if (!v.tid || v.tid_len != 2 || v.tid[0] != 'I' || v.tid[1] != 'A') goto fail;
        if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
        if (!v.token || v.token_len != 8) goto fail;
        memcpy(tok4, v.token, 8);
        if (v.values != NULL || v.values6 != NULL) goto fail;   /* store empty */
        if (v.nodes_len != 2 * 26) goto fail;
        ntx_dht_node nn[8];
        if (ntx_dht_msg_parse_nodes(v.nodes, v.nodes_len, nn, 8, 0) != 2) goto fail;
        for (int i = 0; i < 2; i++)
            if (!ntx_addr_is_v4(&nn[i].addr) ||
                nn[i].addr.u.v4 != inet_addr("127.0.0.1"))
                goto fail;
        uint16_t ports[2] = {nn[0].port, nn[1].port};
        if (ports[0] > ports[1]) {
            uint16_t t = ports[0]; ports[0] = ports[1]; ports[1] = t;
        }
        if (ports[0] != 7001 || ports[1] != 7002) goto fail;
        ntx_addr ta;
        ntx_addr_set_v4(&ta, inet_addr("127.0.0.1"));
        if (ntx_dht_token_check(&ta, tok4) != 0) goto fail;
    }
    /* 2) ANNOUNCE_PEER v4 (port 5000, token from step 1) → r_ping (y=r, id) */
    {
        uint8_t tid[2] = {'I', 'B'};
        uint8_t pkt[256];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        e = be_key(pkt, e, "info_hash");
        e = be_str(pkt, e, h, 20);
        e = be_key(pkt, e, "port");
        char ip[16];
        int m = snprintf(ip, sizeof ip, "i%ue", (unsigned)5000);
        e = be_raw(pkt, e, ip, (size_t)m);
        e = be_key(pkt, e, "token");
        e = be_str(pkt, e, tok4, 8);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "announce_peer", 13);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'q' ||
            !pv.q || strcmp(pv.q, "announce_peer") != 0 ||
            !pv.info_hash || memcmp(pv.info_hash, h, 20) != 0 ||
            pv.port != 5000 || !pv.token || pv.token_len != 8)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
        if (rn <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
        if (!v.y || v.y[0] != 'r') goto fail;
        if (!v.tid || v.tid_len != 2 || v.tid[0] != 'I' || v.tid[1] != 'B') goto fail;
        if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
    }
    /* 3) GET_PEERS v4 → values: 1 peer 127.0.0.1:5000 */
    {
        uint8_t tid[2] = {'I', 'C'};
        uint8_t pkt[256];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        e = be_key(pkt, e, "info_hash");
        e = be_str(pkt, e, h, 20);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "get_peers", 9);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "want");
        pkt[e++] = 'l';
        e = be_str(pkt, e, "n4", 2);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.q ||
            strcmp(pv.q, "get_peers") != 0)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
        if (rn <= 0) goto fail;
        if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
        if (!v.y || v.y[0] != 'r') goto fail;
        if (!v.values || v.values_len != 6) goto fail;
        ntx_dht_peer pr[4];
        if (ntx_dht_msg_parse_values(v.values, v.values_len, pr, 4) != 1) goto fail;
        if (!ntx_addr_is_v4(&pr[0].addr) ||
            pr[0].addr.u.v4 != inet_addr("127.0.0.1") || pr[0].port != 5000)
            goto fail;
    }
    /* 4) NEGATIVE: announce with a RANDOM token (8×0xFF) → no reply */
    {
        uint8_t tid[2] = {'I', 'D'};
        uint8_t bad[8];
        memset(bad, 0xFF, 8);
        uint8_t pkt[256];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "a");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idq, 20);
        e = be_key(pkt, e, "info_hash");
        e = be_str(pkt, e, h, 20);
        e = be_key(pkt, e, "port");
        char ip[16];
        int m = snprintf(ip, sizeof ip, "i%ue", (unsigned)5000);
        e = be_raw(pkt, e, ip, (size_t)m);
        e = be_key(pkt, e, "token");
        e = be_str(pkt, e, bad, 8);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "q");
        e = be_str(pkt, e, "announce_peer", 13);
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "q", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.q ||
            strcmp(pv.q, "announce_peer") != 0 || pv.token_len != 8)
            goto fail;
        if (sendto(s4, pkt, e, 0, (struct sockaddr *)&dst4, sizeof dst4) < 0) goto fail;
        ntx_netx_run_once(netx, 150);
        slen = sizeof sin;
        ssize_t rn = recvfrom(s4, rbuf, sizeof rbuf, MSG_DONTWAIT,
                              (struct sockaddr *)&sin, &slen);
        if (rn != -1) goto fail;   /* EAGAIN expected — drop without reply */
    }
    /* 5) v6 (soft): get_peers → token v6; announce ::1:5001 → r_ping;
       get_peers → values6: 1 peer ::1:5001 */
    if (have_v6) {
        s6 = ntx_sock_udp6();
        if (s6 < 0) goto fail;
        int one = 1;
        setsockopt(s6, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        if (ntx_sock_bind6(s6, 0) == 0) goto fail;
        struct sockaddr_in6 dst6;
        memset(&dst6, 0, sizeof dst6);
        dst6.sin6_family = AF_INET6;
        dst6.sin6_addr = in6addr_loopback;
        dst6.sin6_port = htons(ntx_dht_port6());
        struct sockaddr_in6 sin6;
        ntx_addr ta6;
        ntx_addr_set_v6(&ta6, (const uint8_t *)&in6addr_loopback);
        uint8_t tok6[8];
        {   /* get_peers z v6 (want n6) */
            uint8_t tid[2] = {'I', 'E'};
            uint8_t pkt[256];
            size_t e = 0;
            pkt[e++] = 'd';
            e = be_key(pkt, e, "a");
            pkt[e++] = 'd';
            e = be_key(pkt, e, "id");
            e = be_str(pkt, e, idq, 20);
            e = be_key(pkt, e, "info_hash");
            e = be_str(pkt, e, h, 20);
            pkt[e++] = 'e';
            e = be_key(pkt, e, "q");
            e = be_str(pkt, e, "get_peers", 9);
            e = be_key(pkt, e, "t");
            e = be_str(pkt, e, tid, 2);
            e = be_key(pkt, e, "want");
            pkt[e++] = 'l';
            e = be_str(pkt, e, "n6", 2);
            pkt[e++] = 'e';
            e = be_key(pkt, e, "y");
            e = be_str(pkt, e, "q", 1);
            pkt[e++] = 'e';
            ntx_dht_msg_view pv;
            if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.q ||
                strcmp(pv.q, "get_peers") != 0 || !pv.want_n6)
                goto fail;
            if (sendto(s6, pkt, e, 0, (struct sockaddr *)&dst6, sizeof dst6) < 0) goto fail;
            ntx_netx_run_once(netx, 300);
            socklen_t sl6 = sizeof sin6;
            ssize_t rn = recvfrom(s6, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin6, &sl6);
            if (rn <= 0) goto fail;
            if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
            if (!v.y || v.y[0] != 'r') goto fail;
            if (!v.tid || v.tid_len != 2 || v.tid[0] != 'I' || v.tid[1] != 'E') goto fail;
            if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
            if (!v.token || v.token_len != 8) goto fail;
            memcpy(tok6, v.token, 8);
            if (v.values != NULL || v.values6 != NULL) goto fail;   /* v6 store empty */
            if (v.nodes != NULL || v.nodes6 != NULL) goto fail;    /* rt6 empty */
            if (ntx_dht_token_check(&ta6, tok6) != 0) goto fail;
        }
        {   /* announce v6: ::1:5001 with a token → r_ping */
            uint8_t tid[2] = {'I', 'F'};
            uint8_t pkt[256];
            size_t e = 0;
            pkt[e++] = 'd';
            e = be_key(pkt, e, "a");
            pkt[e++] = 'd';
            e = be_key(pkt, e, "id");
            e = be_str(pkt, e, idq, 20);
            e = be_key(pkt, e, "info_hash");
            e = be_str(pkt, e, h, 20);
            e = be_key(pkt, e, "port");
            char ip[16];
            int m = snprintf(ip, sizeof ip, "i%ue", (unsigned)5001);
            e = be_raw(pkt, e, ip, (size_t)m);
            e = be_key(pkt, e, "token");
            e = be_str(pkt, e, tok6, 8);
            pkt[e++] = 'e';
            e = be_key(pkt, e, "q");
            e = be_str(pkt, e, "announce_peer", 13);
            e = be_key(pkt, e, "t");
            e = be_str(pkt, e, tid, 2);
            e = be_key(pkt, e, "y");
            e = be_str(pkt, e, "q", 1);
            pkt[e++] = 'e';
            ntx_dht_msg_view pv;
            if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.q ||
                strcmp(pv.q, "announce_peer") != 0 || pv.port != 5001 || pv.token_len != 8)
                goto fail;
            if (sendto(s6, pkt, e, 0, (struct sockaddr *)&dst6, sizeof dst6) < 0) goto fail;
            ntx_netx_run_once(netx, 300);
            socklen_t sl6 = sizeof sin6;
            ssize_t rn = recvfrom(s6, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin6, &sl6);
            if (rn <= 0) goto fail;
            if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
            if (!v.y || v.y[0] != 'r') goto fail;
            if (!v.tid || v.tid_len != 2 || v.tid[0] != 'I' || v.tid[1] != 'F') goto fail;
            if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
        }
        {   /* get_peers z v6 → values6: 1 peer ::1:5001 */
            uint8_t tid[2] = {'I', 'G'};
            uint8_t pkt[256];
            size_t e = 0;
            pkt[e++] = 'd';
            e = be_key(pkt, e, "a");
            pkt[e++] = 'd';
            e = be_key(pkt, e, "id");
            e = be_str(pkt, e, idq, 20);
            e = be_key(pkt, e, "info_hash");
            e = be_str(pkt, e, h, 20);
            pkt[e++] = 'e';
            e = be_key(pkt, e, "q");
            e = be_str(pkt, e, "get_peers", 9);
            e = be_key(pkt, e, "t");
            e = be_str(pkt, e, tid, 2);
            e = be_key(pkt, e, "want");
            pkt[e++] = 'l';
            e = be_str(pkt, e, "n6", 2);
            pkt[e++] = 'e';
            e = be_key(pkt, e, "y");
            e = be_str(pkt, e, "q", 1);
            pkt[e++] = 'e';
            ntx_dht_msg_view pv;
            if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.q ||
                strcmp(pv.q, "get_peers") != 0)
                goto fail;
            if (sendto(s6, pkt, e, 0, (struct sockaddr *)&dst6, sizeof dst6) < 0) goto fail;
            ntx_netx_run_once(netx, 300);
            socklen_t sl6 = sizeof sin6;
            ssize_t rn = recvfrom(s6, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin6, &sl6);
            if (rn <= 0) goto fail;
            if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
            if (!v.y || v.y[0] != 'r') goto fail;
            if (!v.values6 || v.values6_len != 18) goto fail;
            ntx_dht_peer pr[4];
            if (ntx_dht_msg_parse_values6(v.values6, v.values6_len, pr, 4) != 1) goto fail;
            if (!ntx_addr_is_v6(&pr[0].addr) || pr[0].port != 5001) goto fail;
            for (int j = 0; j < 15; j++)
                if (pr[0].addr.u.v6[j] != 0) goto fail;
            if (pr[0].addr.u.v6[15] != 1) goto fail;
        }
    }
    ntx_dht_stop();
    if (s6 >= 0) close(s6);
    close(s4);
    ntx_netx_free(netx);
    printf("PASS dht_inbound_announce%s\n", have_v6 ? "" : " (v6 soft skip)");
    return 0;
fail:
    printf("FAIL dht_inbound_announce\n");
    ntx_dht_stop();
    if (s6 >= 0) close(s6);
    if (s4 >= 0) close(s4);
    ntx_netx_free(netx);
    return 1;
}

static int test_dht_bootstrap_findnode(void) {
    ntx_netx *netx = ntx_netx_init(NULL);
    int s = -1;
    if (!netx) return fail("boot-netx");
    if (ntx_dht_start(netx) != 0) goto fail;
    uint8_t myid[20];
    if (ntx_dht_node_id_get(myid) != 0) goto fail;
    s = ntx_sock_udp4();
    if (s < 0) goto fail;
    if (ntx_sock_bind0(s) == 0) goto fail;
    uint16_t P = ntx_sock_local_port(s);
    ntx_addr lo;
    ntx_addr_set_v4(&lo, inet_addr("127.0.0.1"));
    if (ntx_dht_test_inject_seed(&lo, P) != 1) goto fail;
    int before = ntx_dht_node_count(0);
    ntx_dht_bootstrap();
    ntx_netx_run_once(netx, 300);
    uint8_t rbuf[512];
    struct sockaddr_in sin;
    socklen_t slen = sizeof sin;
    ssize_t rn = recvfrom(s, rbuf, sizeof rbuf, 0, (struct sockaddr *)&sin, &slen);
    if (rn <= 0) goto fail;
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(rbuf, (size_t)rn, &v) != 0) goto fail;
    if (!v.y || v.y[0] != 'q') goto fail;
    if (!v.q || strcmp(v.q, "find_node") != 0) goto fail;
    if (!v.id || v.id_len != 20 || memcmp(v.id, myid, 20) != 0) goto fail;
    if (!v.target || v.target_len != 20 || memcmp(v.target, myid, 20) != 0) goto fail;
    if (!v.want_n4 || !v.want_n6) goto fail;
    /* ECHO: r_find_node { r:{id 0xF1×20, nodes: 2×26B}, t, y:"r" } */
    {
        uint8_t idr[20], id4a[20], id4b[20];
        memset(idr, 0xF1, 20);
        memset(id4a, 0xF4, 20);
        memset(id4b, 0xF5, 20);
        uint32_t ip1 = inet_addr("127.0.0.1");
        uint16_t p1 = htons(8001), p2 = htons(8002);
        uint8_t nodes[52];
        memcpy(nodes, id4a, 20);
        memcpy(nodes + 20, &ip1, 4);
        memcpy(nodes + 24, &p1, 2);
        memcpy(nodes + 26, id4b, 20);
        memcpy(nodes + 46, &ip1, 4);
        memcpy(nodes + 50, &p2, 2);
        uint8_t tid[2];
        memcpy(tid, v.tid, 2);
        uint8_t pkt[256];
        size_t e = 0;
        pkt[e++] = 'd';
        e = be_key(pkt, e, "r");
        pkt[e++] = 'd';
        e = be_key(pkt, e, "id");
        e = be_str(pkt, e, idr, 20);
        e = be_key(pkt, e, "nodes");
        e = be_str(pkt, e, nodes, 52);
        pkt[e++] = 'e';
        e = be_key(pkt, e, "t");
        e = be_str(pkt, e, tid, 2);
        e = be_key(pkt, e, "y");
        e = be_str(pkt, e, "r", 1);
        pkt[e++] = 'e';
        ntx_dht_msg_view pv;
        if (ntx_dht_msg_parse(pkt, e, &pv) != 0 || !pv.y || pv.y[0] != 'r' ||
            !pv.id || pv.id_len != 20 || !pv.nodes || pv.nodes_len != 52)
            goto fail;
        struct sockaddr_in dst;
        memset(&dst, 0, sizeof dst);
        dst.sin_family = AF_INET;
        dst.sin_addr.s_addr = inet_addr("127.0.0.1");
        dst.sin_port = htons(ntx_dht_port4());
        if (sendto(s, pkt, e, 0, (struct sockaddr *)&dst, sizeof dst) < 0) goto fail;
        ntx_netx_run_once(netx, 300);
        int after = ntx_dht_node_count(0);
        if (after < before + 3) goto fail;   /* 2 nodes from nodes + the seed (r.id, known source) */
    }
    ntx_dht_stop();
    close(s);
    ntx_netx_free(netx);
    printf("PASS dht_bootstrap_findnode\n");
    return 0;
fail:
    printf("FAIL dht_bootstrap_findnode\n");
    ntx_dht_stop();
    if (s >= 0) close(s);
    ntx_netx_free(netx);
    return 1;
}

/* dual announce — per-source token; announce_peer goes out on the right
   socket (v4→fd4, v6→fd6) with the token received from that source.
   S4/S6 = test "nodes" (node + seed): get_peers → r_get_peers(token),
   announce_peer → r_ping. */
struct ann_node {
    uint8_t last[1024];
    size_t last_n;
    uint8_t tok[8];
    int v6;
    uint16_t dht_port;
    int announced;   /* the handler confirmed announce_peer with r_ping */
};

static void ann_node_on_udp(int fd, void *ctx) {
    struct ann_node *an = (struct ann_node *)ctx;
    for (;;) {
        uint8_t buf[1024];
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        ssize_t r = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&ss, &sl);
        if (r <= 0) return;
        ntx_dht_msg_view v;
        if (ntx_dht_msg_parse(buf, (size_t)r, &v) != 0) continue;
        if (!v.y || v.y[0] != 'q' || !v.q || v.tid_len != NTX_DHT_TID_LEN) continue;
        memcpy(an->last, buf, (size_t)r);
        an->last_n = (size_t)r;
        uint8_t pkt[256];
        size_t n = 0;
        if (strcmp(v.q, "get_peers") == 0) {
            uint8_t idr[20];
            memset(idr, 0xE7, 20);
            n = ntx_dht_msg_enc_r_get_peers(pkt, sizeof pkt, v.tid, idr, an->tok, 8,
                                            NULL, 0, NULL, 0, NULL, 0, NULL, 0);
        } else if (strcmp(v.q, "announce_peer") == 0) {
            an->announced = 1;
            uint8_t idr[20];
            ntx_dht_node_id_get(idr);
            n = ntx_dht_msg_enc_r_ping(pkt, sizeof pkt, v.tid, idr);
        }
        if (n == 0) continue;
        if (an->v6) {
            struct sockaddr_in6 d6;
            memset(&d6, 0, sizeof d6);
            d6.sin6_family = AF_INET6;
            d6.sin6_addr = in6addr_loopback;
            d6.sin6_port = htons(an->dht_port);
            if (sendto(fd, pkt, n, 0, (struct sockaddr *)&d6, sizeof d6) < 0) return;
        } else {
            struct sockaddr_in d4;
            memset(&d4, 0, sizeof d4);
            d4.sin_family = AF_INET;
            d4.sin_addr.s_addr = inet_addr("127.0.0.1");
            d4.sin_port = htons(an->dht_port);
            if (sendto(fd, pkt, n, 0, (struct sockaddr *)&d4, sizeof d4) < 0) return;
        }
    }
}

/* Single-family phase: a fresh DHT instance + S on loopback (node + seed);
   announce → cold-start get_peers to S → r_get_peers(token) →
   announce_peer to S with the token on the right socket. */
static int ann_dual_phase(int v6, const uint8_t hash[20], uint16_t port,
                          uint8_t tok_fill, uint8_t id_fill) {
    ntx_netx *netx = ntx_netx_init(NULL);
    int s = -1;
    if (!netx) return 1;
    if (ntx_dht_start(netx) != 0) goto fail;
    struct ann_node an;
    memset(&an, 0, sizeof an);
    memset(an.tok, tok_fill, 8);
    an.v6 = v6;
    if (v6) {
        if (ntx_dht_port6() == 0) goto ok;   /* soft skip */
        s = ntx_sock_udp6();
        if (s < 0) goto fail;
        int one = 1;
        setsockopt(s, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        if (ntx_sock_bind6(s, 0) == 0) goto fail;
        an.dht_port = ntx_dht_port6();
    } else {
        s = ntx_sock_udp4();
        if (s < 0) goto fail;
        if (ntx_sock_bind0(s) == 0) goto fail;
        an.dht_port = ntx_dht_port4();
    }
    ntx_cbs cbs = {ann_node_on_udp, NULL, NULL};
    ntx_netx_add(netx, s, EPOLLIN, &an, &cbs);
    ntx_addr a;
    uint16_t P;
    if (v6) {
        ntx_addr_set_v6(&a, (const uint8_t *)&in6addr_loopback);
        P = ntx_sock_local_port6(s);
    } else {
        ntx_addr_set_v4(&a, inet_addr("127.0.0.1"));
        P = ntx_sock_local_port(s);
    }
    uint8_t id[20];
    memset(id, id_fill, 20);
    if (ntx_dht_test_inject_node(id, &a, P) != 1) goto fail;
    if (ntx_dht_test_inject_seed(&a, P) != 1) goto fail;
    ntx_dht_announce(hash, port);
    for (int i = 0; i < 15; i++) {
        ntx_netx_run_once(netx, 200);
        if (an.last_n > 0) {
            ntx_dht_msg_view pv;
            if (ntx_dht_msg_parse(an.last, an.last_n, &pv) == 0 &&
                pv.y && pv.y[0] == 'q' && pv.q &&
                strcmp(pv.q, "announce_peer") == 0)
                break;
        }
    }
    {
        ntx_dht_msg_view v;
        if (an.last_n == 0 || ntx_dht_msg_parse(an.last, an.last_n, &v) != 0)
            goto fail;
        if (!v.y || v.y[0] != 'q' || !v.q || strcmp(v.q, "announce_peer") != 0)
            goto fail;
        if (!v.info_hash || memcmp(v.info_hash, hash, 20) != 0) goto fail;
        if (v.port != port) goto fail;
        if (!v.token || v.token_len != 8) goto fail;
        for (int i = 0; i < 8; i++)
            if (v.token[i] != tok_fill) goto fail;
        if (an.announced != 1) goto fail;   /* S confirmed with r_ping */
    }
ok:
    ntx_dht_stop();
    if (s >= 0) close(s);
    ntx_netx_free(netx);
    return 0;
fail:
    ntx_dht_stop();
    if (s >= 0) close(s);
    ntx_netx_free(netx);
    return 1;
}

static int test_dht_announce_dual(void) {
    uint8_t hash[20], hash2[20];
    memset(hash, 0xA5, 20);
    memset(hash2, 0xB5, 20);
    if (ann_dual_phase(0, hash, 5000, 0xAA, 0xC1) != 0)
        return fail("dht_announce_dual v4");
    if (ann_dual_phase(1, hash2, 6000, 0xBB, 0xC2) != 0)
        return fail("dht_announce_dual v6");
    printf("PASS dht_announce_dual\n");
    return 0;
}

int main(void) {
    ntx_rng_init();
    if (test_pex_roundtrip() != 0) return 1;
    printf("PASS pex_roundtrip\n");
    if (test_dht_get_peers_encode() != 0) return 1;
    if (test_dht_peer_addr_type() != 0) return 1;
    printf("PASS dht_peer_addr_type\n");
    if (test_dht_dual_udp() != 0) return 1;
    if (test_dht_inject_node() != 0) return 1;
    if (test_dht_tid_roundtrip() != 0) return 1;
    if (test_dht_iterative_lookup() != 0) return 1;
    if (test_dht_rate_in() != 0) return 1;
    if (test_dht_inbound_queries() != 0) return 1;
    if (test_dht_inbound_announce() != 0) return 1;
    if (test_dht_bootstrap_findnode() != 0) return 1;
    if (test_dht_announce_dual() != 0) return 1;
    return 0;
}
