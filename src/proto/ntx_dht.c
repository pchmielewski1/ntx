#include "ntx_dht.h"
#include "ntx_dht_tid.h"
#include "ntx_dht_token.h"
#include "ntx_dht_lookup.h"
#include "../net/ntx_sock.h"
#include "../crypto/ntx_rng.h"
#include "../core/ntx_time.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <time.h>

#define DHT_PEERS_MAX 100
#define DHT_SEEDS_MAX 8
#define DHT_NODES_CAP 32
#define DHT_RATE_OUT_PPS 40   /* outbound: total of all sends (1 s window) */
#define DHT_RATE_IN_PPS  10   /* inbound: per ntx_addr (1 s window) */

struct dht_inlim {
    ntx_addr addr;
    uint32_t count;
    uint64_t win_ms;
};

struct dht_lkup {
    ntx_dht_lookup lk;
    uint64_t sent_ms[NTX_DHT_LK_KNOWN];   /* per idx known[]; timeout 2 s (glue) */
    int active;
};

/* Peer store: max 100 peers per info_hash and family,
   16 info_hashes, lazy allocation, LRU by last_used_ms / seen_ms. */
#define DHT_HASHES_MAX 16
#define DHT_PEERS_PER_HASH 100

struct dht_stored_peer {
    ntx_dht_peer p;
    uint64_t seen_ms;
};

struct dht_hash {
    uint8_t hash[20];
    struct dht_stored_peer peers4[DHT_PEERS_PER_HASH];
    int n4;
    struct dht_stored_peer peers6[DHT_PEERS_PER_HASH];
    int n6;
    uint64_t last_used_ms;
};

/* Per-source tokens (from get_peers replies); announce_peer goes to the
   node on the same socket the token came from. */
#define DHT_ANN_MAX 16

struct dht_ann_tok {
    ntx_addr addr;
    uint16_t port;
    uint8_t tok[20];
    uint8_t len;     /* 0 = empty slot */
    uint8_t sent;    /* announce_peer sent to this source (for the current hash) */
    uint8_t _pad;
};

static struct {
    int fd4;
    int fd6;
    int shared4;   /* fd4 is the netx-owned shared listen-port socket (do not close) */
    ntx_netx *netx;
    uint8_t node_id[20];
    ntx_dht_rt rt4, rt6;
    struct { ntx_addr addr; uint16_t port; } seeds[DHT_SEEDS_MAX];
    int n_seeds;
    struct { uint8_t hash[20]; ntx_dht_cb cb; void *ud; } pending;
    uint8_t announce_hash[20];
    uint16_t announce_port;
    struct dht_ann_tok ann_toks[DHT_ANN_MAX];
    int ann_toks_rr;
    int ann_active;
    uint64_t ann_since_ms;
    int running;
    uint64_t last_tick_ms;
    ntx_dht_tid_map tid;
    ntx_dht_token_ctx tok;
    struct dht_hash hashes[DHT_HASHES_MAX];
    int n_hashes;
    struct dht_lkup lk4, lk6;             /* lk4↔rt4, lk6↔rt6 */
    uint64_t out_win_ms;
    uint32_t out_cnt;
    struct dht_inlim inlim[16];
    uint32_t rx, tx, rx_dropped, tx_dropped;
} g_dht;

/* Node-ID persistence: 20 B file; static (outside g_dht), survives stop/start */
static const char *g_state_path;

void ntx_dht_set_state_path(const char *p) { g_state_path = p; }

static int dht_state_load(uint8_t id[20]) {
    if (!g_state_path) return -1;
    FILE *f = fopen(g_state_path, "rb");
    if (!f) return -1;
    uint8_t b[20];
    size_t n = fread(b, 1, sizeof b, f);
    fclose(f);
    if (n != sizeof b) return -1;
    int zero = 1;
    for (size_t i = 0; i < sizeof b; i++) if (b[i]) zero = 0;
    if (zero) return -1;
    memcpy(id, b, sizeof b);
    return 0;
}

static void dht_state_save(const uint8_t id[20]) {
    if (!g_state_path) return;
    FILE *f = fopen(g_state_path, "wb");
    if (!f) return;
    fwrite(id, 1, 20, f);
    fclose(f);
}

static void dht_send_to(const ntx_addr *addr, uint16_t port, const uint8_t *pkt, size_t n);

static void dht_send_bootstrap(void) {
    /* to EVERY seed (v4 and v6): find_node(target = own node_id) */
    for (int i = 0; i < g_dht.n_seeds; i++) {
        uint8_t tid[2];
        if (ntx_dht_tid_fresh(&g_dht.tid, tid) != 0) continue;
        uint8_t pkt[256];
        size_t n = ntx_dht_msg_enc_find_node(pkt, sizeof pkt, tid, g_dht.node_id,
                                             g_dht.node_id, 1, 1);
        if (n == 0) continue;
        if (ntx_dht_tid_put(&g_dht.tid, tid, &g_dht.seeds[i].addr, g_dht.seeds[i].port,
                            NTX_DHT_TK_FIND_NODE, -1,
                            ntx_addr_is_v6(&g_dht.seeds[i].addr) ? NTX_AF_INET6 : NTX_AF_INET) != 0)
            continue;
        dht_send_to(&g_dht.seeds[i].addr, g_dht.seeds[i].port, pkt, n);
    }
}

static void dht_bootstrap(void) {
    static const struct {
        const char *host;
        uint16_t port;
    } seeds[] = {{"router.bittorrent.com", 6881}, {"router.utorrent.com", 6881},
                 {"dht.transmissionbt.com", 6881}};
    for (size_t i = 0; i < sizeof seeds / sizeof seeds[0]; i++) {
        ntx_addr a;
        if (ntx_sock_resolve(seeds[i].host, &a) != 0) continue;
        if (ntx_addr_is_zero(&a)) continue;
        int dup = 0;
        for (int j = 0; j < g_dht.n_seeds; j++)
            if (g_dht.seeds[j].port == seeds[i].port &&
                ntx_addr_eq(&g_dht.seeds[j].addr, &a)) { dup = 1; break; }
        if (dup || g_dht.n_seeds >= DHT_SEEDS_MAX) continue;
        g_dht.seeds[g_dht.n_seeds].addr = a;
        g_dht.seeds[g_dht.n_seeds].port = seeds[i].port;
        g_dht.n_seeds++;
    }
    dht_send_bootstrap();
}

static void dht_send_to(const ntx_addr *addr, uint16_t port, const uint8_t *pkt, size_t n) {
    if (port == 0 || ntx_addr_is_zero(addr)) return;
    uint64_t now = ntx_mono_ms();
    if (now - g_dht.out_win_ms >= 1000) {
        g_dht.out_win_ms = now;
        g_dht.out_cnt = 0;
    }
    if (g_dht.out_cnt >= DHT_RATE_OUT_PPS) {
        g_dht.tx_dropped++;
        return;
    }
    g_dht.out_cnt++;
    g_dht.tx++;
    if (ntx_addr_is_v4(addr)) {
        if (g_dht.fd4 < 0) return;
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = addr->u.v4;
        sa.sin_port = htons(port);
        sendto(g_dht.fd4, pkt, n, 0, (struct sockaddr *)&sa, sizeof sa);
    } else if (ntx_addr_is_v6(addr)) {
        if (g_dht.fd6 < 0) return;
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof sa6);
        sa6.sin6_family = AF_INET6;
        memcpy(&sa6.sin6_addr, addr->u.v6, 16);
        sa6.sin6_port = htons(port);
        sendto(g_dht.fd6, pkt, n, 0, (struct sockaddr *)&sa6, sizeof sa6);
    }
}

static void dht_send_tid(const uint8_t tid[2], const ntx_addr *addr, uint16_t port,
                         ntx_dht_tid_kind kind, const uint8_t *pkt, size_t n) {
    if (ntx_dht_tid_put(&g_dht.tid, tid, addr, port, kind, -1,
                        ntx_addr_is_v6(addr) ? NTX_AF_INET6 : NTX_AF_INET) != 0)
        return;
    dht_send_to(addr, port, pkt, n);
}

static int dht_ann_tok_find(const ntx_addr *a, uint16_t p) {
    for (int i = 0; i < DHT_ANN_MAX; i++)
        if (g_dht.ann_toks[i].len > 0 &&
            ntx_addr_eq(&g_dht.ann_toks[i].addr, a) &&
            g_dht.ann_toks[i].port == p)
            return i;
    return -1;
}

static void dht_ann_tok_put(const ntx_addr *a, uint16_t p, const uint8_t *tok, size_t len) {
    int i = dht_ann_tok_find(a, p);
    if (i >= 0) {
        if (g_dht.ann_toks[i].len == (uint8_t)len &&
            memcmp(g_dht.ann_toks[i].tok, tok, len) == 0)
            return;
        memcpy(g_dht.ann_toks[i].tok, tok, len);
        g_dht.ann_toks[i].len = (uint8_t)len;
        g_dht.ann_toks[i].sent = 0;
        return;
    }
    int free = -1;
    for (int j = 0; j < DHT_ANN_MAX; j++)
        if (g_dht.ann_toks[j].len == 0) { free = j; break; }
    if (free < 0) {
        g_dht.ann_toks_rr = (g_dht.ann_toks_rr + 1) % DHT_ANN_MAX;
        free = g_dht.ann_toks_rr;
    }
    g_dht.ann_toks[free].addr = *a;
    g_dht.ann_toks[free].port = p;
    memcpy(g_dht.ann_toks[free].tok, tok, len);
    g_dht.ann_toks[free].len = (uint8_t)len;
    g_dht.ann_toks[free].sent = 0;
}

/* announce_peer to up to K closest nodes holding a token (both families),
   on the right socket (dht_send_to is family-aware). 1 = sent >= 1. */
static int dht_do_announce(void) {
    int sent_any = 0;
    for (int f = 0; f < 2; f++) {
        ntx_dht_rt *rt = f ? &g_dht.rt6 : &g_dht.rt4;
        ntx_dht_node nd[8];
        int nn = ntx_dht_rt_get_closest(rt, g_dht.announce_hash, nd, 8);
        for (int i = 0; i < nn; i++) {
            int ti = dht_ann_tok_find(&nd[i].addr, nd[i].port);
            if (ti < 0 || g_dht.ann_toks[ti].sent) continue;
            uint8_t tid[2];
            if (ntx_dht_tid_fresh(&g_dht.tid, tid) != 0) continue;
            uint8_t pkt[256];
            size_t n = ntx_dht_msg_enc_announce_peer(pkt, sizeof pkt, tid,
                                                     g_dht.node_id, g_dht.announce_hash,
                                                     g_dht.announce_port,
                                                     g_dht.ann_toks[ti].tok,
                                                     g_dht.ann_toks[ti].len);
            if (n == 0) continue;
            dht_send_tid(tid, &nd[i].addr, nd[i].port, NTX_DHT_TK_ANNOUNCE, pkt, n);
            g_dht.ann_toks[ti].sent = 1;
            sent_any = 1;
        }
    }
    return sent_any;
}

/* pick does not return an idx → find the position in known[] (ids are unique in lk). */
static int dht_lk_find_idx(const ntx_dht_lookup *lk, const ntx_dht_node *nd) {
    for (int i = 0; i < lk->n_known; i++)
        if (memcmp(lk->known[i].id, nd->id, 20) == 0 &&
            ntx_addr_eq(&lk->known[i].addr, &nd->addr) &&
            lk->known[i].port == nd->port)
            return i;
    return -1;
}

static void dht_lk_pump(struct dht_lkup *lk, ntx_dht_rt *rt, int family) {
    (void)rt;
    if (!lk->active || lk->lk.done) return;
    ntx_dht_node out[NTX_DHT_ALPHA];
    int nn = ntx_dht_lookup_pick(&lk->lk, out, NTX_DHT_ALPHA);
    if (nn == 0) return;
    uint64_t now = ntx_mono_ms();
    uint8_t pkt[256];
    for (int i = 0; i < nn; i++) {
        int idx = dht_lk_find_idx(&lk->lk, &out[i]);
        if (idx < 0) continue;
        uint8_t tid[2];
        if (ntx_dht_tid_fresh(&g_dht.tid, tid) != 0) {
            ntx_dht_lookup_inflight_done(&lk->lk, idx);
            continue;
        }
        size_t n = ntx_dht_msg_enc_get_peers(pkt, sizeof pkt, tid, g_dht.node_id,
                                             lk->lk.hash, 1, 1);
        if (n == 0) {
            ntx_dht_lookup_inflight_done(&lk->lk, idx);
            continue;
        }
        if (ntx_dht_tid_put(&g_dht.tid, tid, &out[i].addr, out[i].port,
                            NTX_DHT_TK_GET_PEERS, idx,
                            family ? NTX_AF_INET6 : NTX_AF_INET) != 0) {
            ntx_dht_lookup_inflight_done(&lk->lk, idx);
            continue;
        }
        lk->sent_ms[idx] = now;
        dht_send_to(&out[i].addr, out[i].port, pkt, n);
    }
}

/* Per-node timeout 2 s — the lookup library only knows the 15 s max, so
   dropping in-flight queries after 2 s without a reply happens here, in the glue. */
static void dht_lk_timeout(struct dht_lkup *lk, uint64_t now) {
    if (!lk->active) return;
    for (int i = 0; i < NTX_DHT_LK_KNOWN; i++)
        if (lk->lk.inflight[i] && lk->sent_ms[i] &&
            now - lk->sent_ms[i] >= NTX_DHT_LOOKUP_TIMEOUT_MS)
            ntx_dht_lookup_inflight_done(&lk->lk, i);
}

static int dht_source_known(const ntx_addr *addr, uint16_t port) {
    for (int i = 0; i < g_dht.n_seeds; i++)
        if (g_dht.seeds[i].port == port && ntx_addr_eq(&g_dht.seeds[i].addr, addr))
            return 1;
    ntx_dht_rt *rts[2] = {&g_dht.rt4, &g_dht.rt6};
    for (int t = 0; t < 2; t++)
        for (int b = 0; b < NTX_DHT_RT_BUCKETS; b++)
            for (int i = 0; i < rts[t]->b[b].n; i++)
                if (rts[t]->b[b].nodes[i].port == port &&
                    ntx_addr_eq(&rts[t]->b[b].nodes[i].addr, addr))
                    return 1;
    return 0;
}

/* Compact encoders — 26 B/node v4: id[20]+ip4[4](net-order)+port[2](BE). */
static size_t dht_compact_nodes_v4(const ntx_dht_node *ns, int n, uint8_t *out, size_t cap) {
    if (!ns || !out || n <= 0) return 0;
    size_t need = (size_t)n * 26;
    if (cap < need) return 0;
    for (int i = 0; i < n; i++) {
        uint8_t *p = out + (size_t)i * 26;
        memcpy(p, ns[i].id, 20);
        memcpy(p + 20, &ns[i].addr.u.v4, 4);
        uint16_t be = htons(ns[i].port);
        memcpy(p + 24, &be, 2);
    }
    return need;
}

/* 38 B/node v6: id[20]+ip6[16]+port[2](BE). */
static size_t dht_compact_nodes_v6(const ntx_dht_node *ns, int n, uint8_t *out, size_t cap) {
    if (!ns || !out || n <= 0) return 0;
    size_t need = (size_t)n * 38;
    if (cap < need) return 0;
    for (int i = 0; i < n; i++) {
        uint8_t *p = out + (size_t)i * 38;
        memcpy(p, ns[i].id, 20);
        memcpy(p + 20, ns[i].addr.u.v6, 16);
        uint16_t be = htons(ns[i].port);
        memcpy(p + 36, &be, 2);
    }
    return need;
}

/* Peer store — find by hash (refresh last_used); missing + room → alloc;
   full → evict LRU (min last_used). */
static struct dht_hash *dht_hash_find_or_alloc(const uint8_t hash[20], uint64_t now) {
    for (int i = 0; i < g_dht.n_hashes; i++)
        if (memcmp(g_dht.hashes[i].hash, hash, 20) == 0) {
            g_dht.hashes[i].last_used_ms = now;
            return &g_dht.hashes[i];
        }
    struct dht_hash *h;
    if (g_dht.n_hashes < DHT_HASHES_MAX) {
        h = &g_dht.hashes[g_dht.n_hashes++];
    } else {
        int oldest = 0;
        for (int i = 1; i < DHT_HASHES_MAX; i++)
            if (g_dht.hashes[i].last_used_ms < g_dht.hashes[oldest].last_used_ms) oldest = i;
        h = &g_dht.hashes[oldest];
    }
    memset(h, 0, sizeof *h);
    memcpy(h->hash, hash, 20);
    h->last_used_ms = now;
    return h;
}

/* Family by addr; dedup addr+port (exists → refresh seen_ms);
   full (100) → evict the oldest seen_ms. */
static void dht_hash_add(struct dht_hash *h, const ntx_addr *addr, uint16_t port, uint64_t now) {
    struct dht_stored_peer *arr;
    int *np;
    if (ntx_addr_is_v6(addr)) { arr = h->peers6; np = &h->n6; }
    else { arr = h->peers4; np = &h->n4; }
    for (int i = 0; i < *np; i++)
        if (arr[i].p.port == port && ntx_addr_eq(&arr[i].p.addr, addr)) {
            arr[i].seen_ms = now;
            return;
        }
    struct dht_stored_peer sp;
    sp.p.addr = *addr;
    sp.p.port = port;
    sp.seen_ms = now;
    if (*np < DHT_PEERS_PER_HASH) {
        arr[(*np)++] = sp;
    } else {
        int oldest = 0;
        for (int i = 1; i < DHT_PEERS_PER_HASH; i++)
            if (arr[i].seen_ms < arr[oldest].seen_ms) oldest = i;
        arr[oldest] = sp;
    }
}

/* family 0→v4 (6 B/peer: ip4 net-order + port BE), 1→v6 (18 B: ip6 + port BE);
   0 bytes when there are no peers or cap is too small. Returns the peer count. */
static int dht_hash_values(const struct dht_hash *h, int family, uint8_t *out,
                           size_t cap, size_t *out_len) {
    *out_len = 0;
    int n = family ? h->n6 : h->n4;
    size_t rec = family ? 18 : 6;
    if (n <= 0) return 0;
    if ((size_t)n * rec > cap) return 0;
    if (family) {
        for (int i = 0; i < n; i++) {
            uint8_t *p = out + (size_t)i * 18;
            memcpy(p, h->peers6[i].p.addr.u.v6, 16);
            uint16_t be = htons(h->peers6[i].p.port);
            memcpy(p + 16, &be, 2);
        }
    } else {
        for (int i = 0; i < n; i++) {
            uint8_t *p = out + (size_t)i * 6;
            memcpy(p, &h->peers4[i].p.addr.u.v4, 4);
            uint16_t be = htons(h->peers4[i].p.port);
            memcpy(p + 4, &be, 2);
        }
    }
    *out_len = (size_t)n * rec;
    return n;
}

/* Inbound query (open node — no token check for ping/find_node;
   announce_peer verifies the source token, a bad one → drop without reply). */
static void dht_handle_query(const ntx_dht_msg_view *v, const ntx_addr *src, uint16_t sport) {
    if (!v->tid || v->tid_len != 2) return;   /* BEP: tid = 2 B; missing → drop */
    uint8_t pkt[2048];
    size_t n;
    if (v->q && strcmp(v->q, "ping") == 0) {
        n = ntx_dht_msg_enc_r_ping(pkt, sizeof pkt, v->tid, g_dht.node_id);
        if (n) dht_send_to(src, sport, pkt, n);
    } else if (v->q && strcmp(v->q, "find_node") == 0) {
        if (!v->target || v->target_len != 20) return;   /* invalid → drop */
        ntx_dht_rt *rt = ntx_addr_is_v6(src) ? &g_dht.rt6 : &g_dht.rt4;
        ntx_dht_node nodes[NTX_DHT_K];
        int nn = ntx_dht_rt_get_closest(rt, v->target, nodes, NTX_DHT_K);
        uint8_t c4[NTX_DHT_K * 26], c6[NTX_DHT_K * 38];
        size_t n4 = 0, n6 = 0;
        if (ntx_addr_is_v6(src))
            n6 = dht_compact_nodes_v6(nodes, nn, c6, sizeof c6);
        else
            n4 = dht_compact_nodes_v4(nodes, nn, c4, sizeof c4);
        n = ntx_dht_msg_enc_r_find_node(pkt, sizeof pkt, v->tid, g_dht.node_id,
                                        n4 ? c4 : NULL, n4, n6 ? c6 : NULL, n6);
        if (n) dht_send_to(src, sport, pkt, n);
    } else if (v->q && strcmp(v->q, "get_peers") == 0) {
        if (!v->info_hash) return;   /* the parser only sets it when sn==20 */
        uint32_t now_s = (uint32_t)time(NULL);
        uint8_t token[8];
        ntx_dht_token_issue(&g_dht.tok, src, now_s, token);
        struct dht_hash *h = dht_hash_find_or_alloc(v->info_hash, ntx_mono_ms());
        int fam = ntx_addr_is_v6(src);
        size_t vlen = 0;
        ntx_dht_node nodes[NTX_DHT_K];
        int nn = ntx_dht_rt_get_closest(fam ? &g_dht.rt6 : &g_dht.rt4,
                                        v->info_hash, nodes, NTX_DHT_K);
        if (fam) {
            uint8_t vals6[DHT_PEERS_PER_HASH * 18];
            dht_hash_values(h, 1, vals6, sizeof vals6, &vlen);
            uint8_t c6[NTX_DHT_K * 38];
            size_t n6 = dht_compact_nodes_v6(nodes, nn, c6, sizeof c6);
            n = ntx_dht_msg_enc_r_get_peers(pkt, sizeof pkt, v->tid, g_dht.node_id,
                                            token, sizeof token,
                                            NULL, 0, vals6, vlen,
                                            NULL, 0, n6 ? c6 : NULL, n6);
        } else {
            uint8_t vals4[DHT_PEERS_PER_HASH * 6];
            dht_hash_values(h, 0, vals4, sizeof vals4, &vlen);
            uint8_t c4[NTX_DHT_K * 26];
            size_t n4 = dht_compact_nodes_v4(nodes, nn, c4, sizeof c4);
            n = ntx_dht_msg_enc_r_get_peers(pkt, sizeof pkt, v->tid, g_dht.node_id,
                                            token, sizeof token,
                                            vals4, vlen, NULL, 0,
                                            n4 ? c4 : NULL, n4, NULL, 0);
        }
        if (n) dht_send_to(src, sport, pkt, n);
    } else if (v->q && strcmp(v->q, "announce_peer") == 0) {
        if (!v->info_hash || v->port == 0 || v->token_len != NTX_DHT_TOKEN_LEN) return;
        if (!ntx_dht_token_verify(&g_dht.tok, src, (uint32_t)time(NULL), v->token))
            return;   /* bad token → drop without reply */
        dht_hash_add(dht_hash_find_or_alloc(v->info_hash, ntx_mono_ms()),
                     src, v->port, ntx_mono_ms());
        n = ntx_dht_msg_enc_r_ping(pkt, sizeof pkt, v->tid, g_dht.node_id);
        if (n) dht_send_to(src, sport, pkt, n);
    }
}

static void dht_on_datagram(const uint8_t *buf, size_t n, const ntx_addr *src, uint16_t sport) {
    ntx_dht_msg_view v;
    if (ntx_dht_msg_parse(buf, n, &v) != 0) return;
    if (!v.y) return;
    if (v.y[0] == 'q') { dht_handle_query(&v, src, sport); return; }
    if (v.y[0] != 'r') return;
    if (!v.tid || v.tid_len != NTX_DHT_TID_LEN) return;
    ntx_dht_tid_ent ent;
    if (ntx_dht_tid_take(&g_dht.tid, v.tid, src, sport, &ent) != 0) return;
    uint64_t now = ntx_mono_ms();
    if (v.id && v.id_len == 20 && dht_source_known(src, sport)) {
        ntx_dht_node nn;
        memset(&nn, 0, sizeof nn);
        memcpy(nn.id, v.id, 20);
        nn.addr = *src;
        nn.port = sport;
        nn.last_seen_ms = now;
        nn.replied = 1;
        ntx_dht_rt_add(ntx_addr_is_v6(src) ? &g_dht.rt6 : &g_dht.rt4, &nn);
    }
    if (v.token && v.token_len > 0 && v.token_len <= sizeof g_dht.ann_toks[0].tok) {
        dht_ann_tok_put(src, sport, v.token, v.token_len);
        if (g_dht.ann_active) dht_do_announce();
    }
    if (ent.kind == NTX_DHT_TK_GET_PEERS) {
        if (ent.slot >= 0) {
            struct dht_lkup *lk = (ent.family == NTX_AF_INET6) ? &g_dht.lk6 : &g_dht.lk4;
            ntx_dht_lookup_inflight_done(&lk->lk, ent.slot);
            ntx_dht_node nodes[DHT_NODES_CAP];
            int nn = 0;
            if (ent.family == NTX_AF_INET6) {
                if (v.nodes6 && v.nodes6_len > 0)
                    nn = ntx_dht_msg_parse_nodes6(v.nodes6, v.nodes6_len, nodes,
                                                  DHT_NODES_CAP, now);
            } else {
                if (v.nodes && v.nodes_len > 0)
                    nn = ntx_dht_msg_parse_nodes(v.nodes, v.nodes_len, nodes,
                                                 DHT_NODES_CAP, now);
            }
            if (nn > 0) {
                uint8_t rid[20];
                if (v.id && v.id_len == 20)
                    memcpy(rid, v.id, 20);
                else
                    memset(rid, 0, sizeof rid);
                ntx_dht_lookup_on_response(&lk->lk, rid, nodes, nn, now);
            }
            if (g_dht.pending.cb) {
                if (v.values && v.values_len > 0) {
                    ntx_dht_peer peers[DHT_PEERS_MAX];
                    int np = ntx_dht_msg_parse_values(v.values, v.values_len, peers,
                                                      DHT_PEERS_MAX);
                    if (np > 0)
                        g_dht.pending.cb(g_dht.pending.hash, peers, np, g_dht.pending.ud);
                }
                if (v.values6 && v.values6_len > 0) {
                    ntx_dht_peer peers[DHT_PEERS_MAX];
                    int np = ntx_dht_msg_parse_values6(v.values6, v.values6_len, peers,
                                                       DHT_PEERS_MAX);
                    if (np > 0)
                        g_dht.pending.cb(g_dht.pending.hash, peers, np, g_dht.pending.ud);
                }
            }
        } else if (g_dht.pending.cb && v.values && v.values_len > 0) {
            /* legacy announce get_peers (slot=-1): 1× + clear */
            ntx_dht_peer peers[DHT_PEERS_MAX];
            int np = ntx_dht_msg_parse_values(v.values, v.values_len, peers,
                                              DHT_PEERS_MAX);
            if (np > 0)
                g_dht.pending.cb(g_dht.pending.hash, peers, np, g_dht.pending.ud);
            g_dht.pending.cb = NULL;
        }
    }
    if (v.nodes && v.nodes_len > 0) {
        ntx_dht_node nodes[DHT_NODES_CAP];
        int nn = ntx_dht_msg_parse_nodes(v.nodes, v.nodes_len, nodes, DHT_NODES_CAP, now);
        for (int i = 0; i < nn; i++) ntx_dht_rt_add(&g_dht.rt4, &nodes[i]);
    }
    if (v.nodes6 && v.nodes6_len > 0) {
        ntx_dht_node nodes[DHT_NODES_CAP];
        int nn = ntx_dht_msg_parse_nodes6(v.nodes6, v.nodes6_len, nodes, DHT_NODES_CAP, now);
        for (int i = 0; i < nn; i++) ntx_dht_rt_add(&g_dht.rt6, &nodes[i]);
    }
}

/* Per-datagram input: source decode + per-source rate-limit window + dispatch.
 * Shared by the standalone recvfrom drain (dht_on_udp) and the netx shared-
 * socket demux entry (ntx_dht_input). The rate-limit / RT accounting lives here
 * unchanged — only the fd that produced the datagram differs. */
static void dht_input_one(const uint8_t *buf, ssize_t r,
                          const struct sockaddr_storage *ss, socklen_t sl) {
    (void)sl; /* ntx_addr_from_sockaddr reads the family from ss itself */
    ntx_addr src;
    uint16_t sport = 0;
    if (ntx_addr_from_sockaddr(&src, &sport, ss) != 0) return;
    uint64_t now = ntx_mono_ms();
    struct dht_inlim *slot = NULL;
    for (int i = 0; i < 16; i++)
        if (ntx_addr_eq(&g_dht.inlim[i].addr, &src)) { slot = &g_dht.inlim[i]; break; }
    if (!slot) {
        for (int i = 0; i < 16; i++)
            if (g_dht.inlim[i].win_ms == 0) { slot = &g_dht.inlim[i]; break; }
        if (!slot) {
            int oldest = 0;
            for (int i = 1; i < 16; i++)
                if (g_dht.inlim[i].win_ms < g_dht.inlim[oldest].win_ms) oldest = i;
            slot = &g_dht.inlim[oldest];
        }
        slot->addr = src;
    }
    if (now - slot->win_ms >= 1000) {   /* win_ms==0 (empty) ⇒ always reset */
        slot->win_ms = now;
        slot->count = 0;
    }
    slot->count++;
    if (slot->count > DHT_RATE_IN_PPS) {
        g_dht.rx_dropped++;
        return;   /* drop without reply; the caller keeps draining */
    }
    g_dht.rx++;
    dht_on_datagram(buf, (size_t)r, &src, sport);
}

static void dht_on_udp(int fd, void *ctx) {
    (void)ctx;
    for (;;) {   /* drain the UDP buffer (like accept_handler) — 1 recvfrom per event would leave a backlog */
        uint8_t buf[2048];
        struct sockaddr_storage ss;
        socklen_t sl = sizeof ss;
        ssize_t r = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&ss, &sl);
        if (r <= 0) return;
        dht_input_one(buf, r, &ss, sl);
    }
}

/* Shared-socket demux entry: netx owns the listen-port UDP socket and
 * hands us each DHT-classified datagram (first byte 'd'/'l'/'i'). We run the
 * same rate-limited input path; the send path uses the shared fd. */
void ntx_dht_input(ntx_netx *netx, const uint8_t *buf, size_t n,
                   const struct sockaddr_storage *from, socklen_t from_len) {
    (void)netx;
    if (!g_dht.running || !buf || n == 0) return;
    dht_input_one(buf, (ssize_t)n, from, from_len);
}

static void dht_close(void *ctx) {
    (void)ctx;
}

int ntx_dht_start(ntx_netx *netx) {
    if (g_dht.running) return 0;
    g_dht.netx = netx;
    /* Shared-socket mode: ride the netx-owned listen-port socket when
     * it is available (it is registered on the netx loop and demuxed into
     * ntx_dht_input). Otherwise fall back to DHT's own bind — the fail-soft
     * degraded mode after a shared-bind collision, where DHT still runs. */
    int sfd = netx ? ntx_netx_udp4_fd(netx) : -1;
    if (sfd >= 0) {
        g_dht.fd4 = sfd;
        g_dht.shared4 = 1;
    } else {
        g_dht.fd4 = ntx_sock_udp4();
        if (g_dht.fd4 < 0) { g_dht.netx = NULL; return -1; }
        ntx_sock_bind0(g_dht.fd4);
        g_dht.shared4 = 0;
    }
    g_dht.fd6 = ntx_sock_udp6();
    if (g_dht.fd6 >= 0 && ntx_sock_bind6(g_dht.fd6, 0) == 0) {
        close(g_dht.fd6);
        g_dht.fd6 = -1;
    }
    ntx_rand_bytes(g_dht.node_id, 20);
    if (dht_state_load(g_dht.node_id) != 0) ntx_rand_bytes(g_dht.node_id, 20);
    dht_state_save(g_dht.node_id);
    ntx_dht_token_init(&g_dht.tok);
    ntx_dht_rt_init(&g_dht.rt4, g_dht.node_id);
    ntx_dht_rt_init(&g_dht.rt6, g_dht.node_id);
    ntx_dht_tid_init(&g_dht.tid);
    ntx_cbs cbs = {dht_on_udp, NULL, dht_close};
    if (!g_dht.shared4) ntx_netx_add(netx, g_dht.fd4, EPOLLIN, &g_dht, &cbs);
    if (g_dht.fd6 >= 0) ntx_netx_add(netx, g_dht.fd6, EPOLLIN, &g_dht, &cbs);
    dht_bootstrap();
    g_dht.running = 1;
    return 0;
}

void ntx_dht_stop(void) {
    if (!g_dht.running) return;
    g_dht.lk4.active = 0;
    g_dht.lk6.active = 0;
    if (!g_dht.shared4) {
        if (g_dht.netx && g_dht.fd4 >= 0) ntx_netx_del(g_dht.netx, g_dht.fd4);
        if (g_dht.fd4 >= 0) close(g_dht.fd4);
    }
    if (g_dht.netx && g_dht.fd6 >= 0) ntx_netx_del(g_dht.netx, g_dht.fd6);
    if (g_dht.fd6 >= 0) close(g_dht.fd6);
    ntx_dht_rt_clear(&g_dht.rt4);
    ntx_dht_rt_clear(&g_dht.rt6);
    memset(&g_dht, 0, sizeof g_dht);
    g_dht.fd4 = -1;
    g_dht.fd6 = -1;
}

int ntx_dht_has_v6(void) { return g_dht.fd6 >= 0 ? 1 : 0; }

int ntx_dht_node_id_get(uint8_t out[20]) {
    if (!g_dht.running || !out) return -1;
    memcpy(out, g_dht.node_id, 20);
    return 0;
}
uint16_t ntx_dht_port4(void) {
    return g_dht.fd4 >= 0 ? ntx_sock_local_port(g_dht.fd4) : 0;
}
uint16_t ntx_dht_port6(void) {
    return g_dht.fd6 >= 0 ? ntx_sock_local_port6(g_dht.fd6) : 0;
}

void ntx_dht_lookup_peers(const uint8_t hash[20], ntx_dht_cb cb, void *ud) {
    if (!g_dht.running || !cb) return;
    g_dht.pending.cb = cb;
    g_dht.pending.ud = ud;
    memcpy(g_dht.pending.hash, hash, 20);
    uint64_t now = ntx_mono_ms();
    ntx_dht_lookup_init(&g_dht.lk4.lk, hash, now);
    ntx_dht_lookup_init(&g_dht.lk6.lk, hash, now);
    memset(g_dht.lk4.sent_ms, 0, sizeof g_dht.lk4.sent_ms);
    memset(g_dht.lk6.sent_ms, 0, sizeof g_dht.lk6.sent_ms);
    int n4 = ntx_dht_lookup_seed(&g_dht.lk4.lk, &g_dht.rt4);
    int n6 = ntx_dht_lookup_seed(&g_dht.lk6.lk, &g_dht.rt6);
    g_dht.lk4.active = (n4 > 0);
    g_dht.lk6.active = (n6 > 0);
    if (!g_dht.lk4.active && !g_dht.lk6.active) {
        g_dht.pending.cb = NULL;   /* empty RT → no-op */
        return;
    }
    dht_lk_pump(&g_dht.lk4, &g_dht.rt4, 0);
    dht_lk_pump(&g_dht.lk6, &g_dht.rt6, 1);
}

void ntx_dht_announce(const uint8_t hash[20], uint16_t port) {
    if (!g_dht.running) return;
    memcpy(g_dht.announce_hash, hash, 20);
    g_dht.announce_port = port;
    g_dht.ann_active = 1;
    g_dht.ann_since_ms = ntx_mono_ms();
    for (int i = 0; i < DHT_ANN_MAX; i++) g_dht.ann_toks[i].sent = 0;
    if (ntx_dht_lookup_active() && memcmp(g_dht.pending.hash, hash, 20) == 0)
        return;   /* lookup in progress: tokens land in ann_toks + the completion hook */
    if (dht_do_announce()) return;
    /* cold start: get_peers (want 1,1) to EVERY seed (v4 on fd4, v6 on fd6);
       the token from the reply → on_datagram → dht_do_announce */
    uint8_t pkt[256];
    int sent = 0;
    for (int i = 0; i < g_dht.n_seeds; i++) {
        uint8_t tid[2];
        if (ntx_dht_tid_fresh(&g_dht.tid, tid) != 0) continue;
        size_t n = ntx_dht_msg_enc_get_peers(pkt, sizeof pkt, tid, g_dht.node_id,
                                              hash, 1, 1);
        if (n == 0) continue;
        dht_send_tid(tid, &g_dht.seeds[i].addr, g_dht.seeds[i].port,
                     NTX_DHT_TK_GET_PEERS, pkt, n);
        sent = 1;
    }
    if (!sent) g_dht.ann_active = 0;   /* no seeds at all → no-op, empty RT */
}

void ntx_dht_tick(void) {
    if (!g_dht.running) return;
    uint64_t now = ntx_mono_ms();
    if (g_dht.ann_active && now - g_dht.ann_since_ms > 30000) g_dht.ann_active = 0;
    dht_lk_pump(&g_dht.lk4, &g_dht.rt4, 0);
    dht_lk_pump(&g_dht.lk6, &g_dht.rt6, 1);
    dht_lk_timeout(&g_dht.lk4, now);
    dht_lk_timeout(&g_dht.lk6, now);
    ntx_dht_lookup_finish_check(&g_dht.lk4.lk, now);
    ntx_dht_lookup_finish_check(&g_dht.lk6.lk, now);
    if (g_dht.lk4.lk.done && g_dht.lk6.lk.done &&
        (g_dht.lk4.active || g_dht.lk6.active)) {
        if (g_dht.ann_active &&
            memcmp(g_dht.announce_hash, g_dht.pending.hash, 20) == 0)
            dht_do_announce();   /* after the lookup finishes → announce with the collected tokens */
        g_dht.lk4.active = 0;
        g_dht.lk6.active = 0;
        g_dht.pending.cb = NULL;   /* lookup finished (values are delivered on the fly) */
    }
    if (g_dht.last_tick_ms && now - g_dht.last_tick_ms < 60000) return;
    g_dht.last_tick_ms = now;
    ntx_dht_rt_expire(&g_dht.rt4, now);
    ntx_dht_rt_expire(&g_dht.rt6, now);
    ntx_dht_tid_expire(&g_dht.tid, now, 15000);
    uint8_t tid[2];
    if (ntx_dht_tid_fresh(&g_dht.tid, tid) != 0) return;
    uint8_t pkt[128];
    size_t pn = ntx_dht_msg_enc_ping(pkt, sizeof pkt, tid, g_dht.node_id);
    if (!pn) return;
    ntx_dht_node nd;
    int nn = ntx_dht_rt_get_closest(&g_dht.rt4, g_dht.node_id, &nd, 1);
    if (nn == 0) nn = ntx_dht_rt_get_closest(&g_dht.rt6, g_dht.node_id, &nd, 1);
    if (nn > 0) {
        dht_send_tid(tid, &nd.addr, nd.port, NTX_DHT_TK_PING, pkt, pn);
    } else if (g_dht.n_seeds > 0) {
        for (int i = 0; i < g_dht.n_seeds; i++) {
            if (!ntx_addr_is_v4(&g_dht.seeds[i].addr)) continue;
            dht_send_tid(tid, &g_dht.seeds[i].addr, g_dht.seeds[i].port, NTX_DHT_TK_PING,
                         pkt, pn);
            break;
        }
    }
}

int ntx_dht_test_inject_node(const uint8_t id[20], const ntx_addr *addr, uint16_t port) {
    if (!g_dht.running) return -1;
    ntx_dht_node nn;
    memset(&nn, 0, sizeof nn);
    memcpy(nn.id, id, 20);
    nn.addr = *addr;
    nn.port = port;
    nn.last_seen_ms = ntx_mono_ms();
    nn.replied = 1;
    if (ntx_dht_rt_add(ntx_addr_is_v6(addr) ? &g_dht.rt6 : &g_dht.rt4, &nn) != 0)
        return -1;
    return 1;
}

int ntx_dht_node_count(int family) {
    if (!g_dht.running) return 0;
    return ntx_dht_rt_count(family ? &g_dht.rt6 : &g_dht.rt4);
}

int ntx_dht_lookup_active(void) {
    return (g_dht.lk4.active || g_dht.lk6.active) ? 1 : 0;
}

int ntx_dht_token_check(const ntx_addr *addr, const uint8_t tok[8]) {
    /* test hook: verify against the current unix time; 0 ok, -1 bad token/not started */
    if (!g_dht.running || !addr || !tok) return -1;
    return ntx_dht_token_verify(&g_dht.tok, addr, (uint32_t)time(NULL), tok) ? 0 : -1;
}

void ntx_dht_bootstrap(void) {
    if (!g_dht.running) return;
    dht_send_bootstrap();
}

int ntx_dht_test_inject_seed(const ntx_addr *addr, uint16_t port) {
    if (!g_dht.running || port == 0 || ntx_addr_is_zero(addr)) return -1;
    for (int i = 0; i < g_dht.n_seeds; i++)
        if (g_dht.seeds[i].port == port && ntx_addr_eq(&g_dht.seeds[i].addr, addr))
            return 1;
    if (g_dht.n_seeds >= DHT_SEEDS_MAX) return -1;
    g_dht.seeds[g_dht.n_seeds].addr = *addr;
    g_dht.seeds[g_dht.n_seeds].port = port;
    g_dht.n_seeds++;
    return 1;
}

void ntx_dht_stats(int *rx, int *tx, int *rx_dropped, int *tx_dropped) {
    if (rx) *rx = (int)g_dht.rx;
    if (tx) *tx = (int)g_dht.tx;
    if (rx_dropped) *rx_dropped = (int)g_dht.rx_dropped;
    if (tx_dropped) *tx_dropped = (int)g_dht.tx_dropped;
}
