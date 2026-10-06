#include "ntx_dht_msg.h"
#include "ntx_bencode.h"

#include <stdio.h>
#include <string.h>

/* Compact v4 — nodes (26 B) / values (6 B). */

int ntx_dht_msg_parse_nodes(const uint8_t *p, size_t n, ntx_dht_node *out,
                            int cap, uint64_t now_ms) {
    if (!p || !out || cap <= 0) return 0;
    int count = 0;
    size_t off = 0;
    while (off + 26 <= n && count < cap) {
        ntx_dht_node *nd = &out[count];
        memset(nd, 0, sizeof *nd);
        memcpy(nd->id, p + off, 20);
        uint32_t ip_net;
        memcpy(&ip_net, p + off + 20, 4);
        ntx_addr_set_v4(&nd->addr, ip_net);
        nd->port = (uint16_t)(((uint16_t)p[off + 24] << 8) | p[off + 25]);
        nd->last_seen_ms = now_ms;
        count++;
        off += 26;
    }
    return count;
}

int ntx_dht_msg_parse_values(const uint8_t *p, size_t n, ntx_dht_cpeer *out, int cap) {
    if (!p || !out || cap <= 0) return 0;
    int count = 0;
    size_t off = 0;
    while (off + 6 <= n && count < cap) {
        uint32_t ip_net;
        memcpy(&ip_net, p + off, 4);
        ntx_addr_set_v4(&out[count].addr, ip_net);
        out[count].port = (uint16_t)(((uint16_t)p[off + 4] << 8) | p[off + 5]);
        count++;
        off += 6;
    }
    return count;
}

int ntx_dht_msg_parse_nodes6(const uint8_t *p, size_t n, ntx_dht_node *out,
                             int cap, uint64_t now_ms) {
    if (!p || !out || cap <= 0) return 0;
    int count = 0;
    size_t off = 0;
    while (off + 38 <= n && count < cap) {
        ntx_dht_node *nd = &out[count];
        memset(nd, 0, sizeof *nd);
        memcpy(nd->id, p + off, 20);
        ntx_addr_set_v6(&nd->addr, p + off + 20);
        nd->port = (uint16_t)(((uint16_t)p[off + 36] << 8) | p[off + 37]);
        nd->last_seen_ms = now_ms;
        count++;
        off += 38;
    }
    return count;
}

int ntx_dht_msg_parse_values6(const uint8_t *p, size_t n, ntx_dht_cpeer *out, int cap) {
    if (!p || !out || cap <= 0) return 0;
    int count = 0;
    size_t off = 0;
    while (off + 18 <= n && count < cap) {
        ntx_addr_set_v6(&out[count].addr, p + off);
        out[count].port = (uint16_t)(((uint16_t)p[off + 16] << 8) | p[off + 17]);
        count++;
        off += 18;
    }
    return count;
}

/* --- enc queries + parse view --- */

typedef struct {
    uint8_t *b;
    size_t cap;
    size_t pos;
    int fail;
} mcur;

static void mcur_raw(mcur *c, const void *p, size_t n) {
    if (c->fail) return;
    if (c->pos + n > c->cap) {
        c->fail = 1;
        return;
    }
    memcpy(c->b + c->pos, p, n);
    c->pos += n;
}

static void mcur_byte(mcur *c, char ch) {
    mcur_raw(c, &ch, 1);
}

static void mcur_key(mcur *c, const char *key) {
    char hdr[24];
    int n = snprintf(hdr, sizeof hdr, "%zu:%s", strlen(key), key);
    mcur_raw(c, hdr, (size_t)n);
}

static void mcur_slen(mcur *c, size_t n) {
    char hdr[16];
    int dn = snprintf(hdr, sizeof hdr, "%zu:", n);
    mcur_raw(c, hdr, (size_t)dn);
}

static void mcur_want(mcur *c, int want_n4, int want_n6) {
    if (!want_n4 && !want_n6) return;
    mcur_key(c, "want");
    mcur_byte(c, 'l');
    if (want_n4) mcur_key(c, "n4");
    if (want_n6) mcur_key(c, "n6");
    mcur_byte(c, 'e');
}

static size_t mcur_done(const mcur *c) {
    return c->fail ? 0 : c->pos;
}

/* a bencode STR has no NUL; view.q is a const char* → map the known names */
static const char *qname_of(const uint8_t *sp, size_t sn) {
    if (sn == 4 && memcmp(sp, "ping", 4) == 0) return "ping";
    if (sn == 10 && memcmp(sp, "find_node", 10) == 0) return "find_node";
    if (sn == 9 && memcmp(sp, "get_peers", 9) == 0) return "get_peers";
    if (sn == 13 && memcmp(sp, "announce_peer", 13) == 0) return "announce_peer";
    return NULL;
}

size_t ntx_dht_msg_enc_ping(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                            const uint8_t id[20]) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_byte(&c, 'd');
    mcur_key(&c, "a");
    mcur_byte(&c, 'd');
    mcur_key(&c, "id");
    mcur_slen(&c, 20);
    mcur_raw(&c, id, 20);
    mcur_byte(&c, 'e');
    mcur_key(&c, "q");
    mcur_slen(&c, 4);
    mcur_raw(&c, "ping", 4);
    mcur_key(&c, "t");
    mcur_slen(&c, 2);
    mcur_raw(&c, tid, 2);
    mcur_key(&c, "y");
    mcur_slen(&c, 1);
    mcur_byte(&c, 'q');
    mcur_byte(&c, 'e');
    return mcur_done(&c);
}

size_t ntx_dht_msg_enc_find_node(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                 const uint8_t id[20], const uint8_t n[20],
                                 int want_n4, int want_n6) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_byte(&c, 'd');
    mcur_key(&c, "a");
    mcur_byte(&c, 'd');
    mcur_key(&c, "id");
    mcur_slen(&c, 20);
    mcur_raw(&c, id, 20);
    mcur_key(&c, "target");
    mcur_slen(&c, 20);
    mcur_raw(&c, n, 20);
    mcur_byte(&c, 'e');
    mcur_key(&c, "q");
    mcur_slen(&c, 10);
    mcur_raw(&c, "find_node", 10);
    mcur_key(&c, "t");
    mcur_slen(&c, 2);
    mcur_raw(&c, tid, 2);
    mcur_want(&c, want_n4, want_n6);
    mcur_key(&c, "y");
    mcur_slen(&c, 1);
    mcur_byte(&c, 'q');
    mcur_byte(&c, 'e');
    return mcur_done(&c);
}

size_t ntx_dht_msg_enc_get_peers(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                 const uint8_t id[20], const uint8_t info_hash[20],
                                 int want_n4, int want_n6) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_byte(&c, 'd');
    mcur_key(&c, "a");
    mcur_byte(&c, 'd');
    mcur_key(&c, "id");
    mcur_slen(&c, 20);
    mcur_raw(&c, id, 20);
    mcur_key(&c, "info_hash");
    mcur_slen(&c, 20);
    mcur_raw(&c, info_hash, 20);
    mcur_byte(&c, 'e');
    mcur_key(&c, "q");
    mcur_slen(&c, 9);
    mcur_raw(&c, "get_peers", 9);
    mcur_key(&c, "t");
    mcur_slen(&c, 2);
    mcur_raw(&c, tid, 2);
    mcur_want(&c, want_n4, want_n6);
    mcur_key(&c, "y");
    mcur_slen(&c, 1);
    mcur_byte(&c, 'q');
    mcur_byte(&c, 'e');
    return mcur_done(&c);
}

size_t ntx_dht_msg_enc_announce_peer(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                     const uint8_t id[20], const uint8_t info_hash[20],
                                     uint16_t port, const uint8_t *token, size_t token_len) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_byte(&c, 'd');
    mcur_key(&c, "a");
    mcur_byte(&c, 'd');
    mcur_key(&c, "id");
    mcur_slen(&c, 20);
    mcur_raw(&c, id, 20);
    mcur_key(&c, "info_hash");
    mcur_slen(&c, 20);
    mcur_raw(&c, info_hash, 20);
    char portbuf[32];
    int plen = snprintf(portbuf, sizeof portbuf, "4:porti%ue", (unsigned)port);
    mcur_raw(&c, portbuf, (size_t)plen);
    if (token && token_len > 0) {
        mcur_key(&c, "token");
        mcur_slen(&c, token_len);
        mcur_raw(&c, token, token_len);
    }
    mcur_byte(&c, 'e');
    mcur_key(&c, "q");
    mcur_slen(&c, 13);
    mcur_raw(&c, "announce_peer", 13);
    mcur_key(&c, "t");
    mcur_slen(&c, 2);
    mcur_raw(&c, tid, 2);
    mcur_key(&c, "y");
    mcur_slen(&c, 1);
    mcur_byte(&c, 'q');
    mcur_byte(&c, 'e');
    return mcur_done(&c);
}

int ntx_dht_msg_parse(const uint8_t *buf, size_t n, ntx_dht_msg_view *v) {
    if (!buf || !v || n == 0) return -1;
    memset(v, 0, sizeof *v);
    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(buf, n, &be, &consumed, 32, 65536) != 0) return -1;
    if (be.t != NTX_BE_DICT) {
        ntx_be_free(&be);
        return -1;
    }
    const ntx_be *t = ntx_be_dict_get(&be, "t");
    if (!t || t->t != NTX_BE_STR || t->sn == 0) {
        ntx_be_free(&be);
        return -1;
    }
    v->tid = t->sp;
    v->tid_len = t->sn;
    const ntx_be *y = ntx_be_dict_get(&be, "y");
    const ntx_be *r = ntx_be_dict_get(&be, "r");
    if (y && y->t == NTX_BE_STR && y->sn == 1 && y->sp[0] == 'q') {
        const ntx_be *q = ntx_be_dict_get(&be, "q");
        if (!q || q->t != NTX_BE_STR) {
            ntx_be_free(&be);
            return -1;
        }
        v->y = "q";
        v->q = qname_of(q->sp, q->sn);
        const ntx_be *a = ntx_be_dict_get(&be, "a");
        if (a && a->t == NTX_BE_DICT) {
            const ntx_be *id = ntx_be_dict_get(a, "id");
            if (id && id->t == NTX_BE_STR && id->sn == 20) {
                v->id = id->sp;
                v->id_len = id->sn;
            }
        }
        const ntx_be *ah = (a && a->t == NTX_BE_DICT) ? ntx_be_dict_get(a, "info_hash") : NULL;
        const ntx_be *nh = ntx_be_dict_get(&be, "n");
        if (!nh) nh = ntx_be_dict_get(&be, "info_hash");
        if (ah && ah->t == NTX_BE_STR && ah->sn == 20) v->info_hash = ah->sp;
        else if (nh && nh->t == NTX_BE_STR && nh->sn == 20) v->info_hash = nh->sp;
        if (v->q && strcmp(v->q, "find_node") == 0) {   /* target = a.target (BEP10); tolerant fallback top-level n/info_hash (legacy) */
            const ntx_be *t = NULL;
            if (a && a->t == NTX_BE_DICT) {
                const ntx_be *at = ntx_be_dict_get(a, "target");
                if (at && at->t == NTX_BE_STR && at->sn == 20) t = at;
            }
            if (!t && nh && nh->t == NTX_BE_STR && nh->sn == 20) t = nh;
            if (t) {
                v->target = t->sp;
                v->target_len = t->sn;
            }
        }
        const ntx_be *want = ntx_be_dict_get(&be, "want");
        if (want && want->t == NTX_BE_LIST) {
            for (size_t i = 0; i < want->ne; i++) {
                const ntx_be *w = want->el[i];
                if (w->t != NTX_BE_STR || w->sn != 2) continue;
                if (memcmp(w->sp, "n4", 2) == 0) v->want_n4 = 1;
                else if (memcmp(w->sp, "n6", 2) == 0) v->want_n6 = 1;
            }
        }
        const ntx_be *ap = (a && a->t == NTX_BE_DICT) ? ntx_be_dict_get(a, "port") : NULL;
        const ntx_be *port = ntx_be_dict_get(&be, "port");
        if (ap && ap->t == NTX_BE_INT) v->port = (uint16_t)ap->i;
        else if (port && port->t == NTX_BE_INT) v->port = (uint16_t)port->i;
        const ntx_be *atok = (a && a->t == NTX_BE_DICT) ? ntx_be_dict_get(a, "token") : NULL;
        const ntx_be *qtok = ntx_be_dict_get(&be, "token"); /* announce_peer (legacy top-level) */
        if (atok && atok->t == NTX_BE_STR) {
            v->token = atok->sp;
            v->token_len = atok->sn;
        } else if (qtok && qtok->t == NTX_BE_STR) {
            v->token = qtok->sp;
            v->token_len = qtok->sn;
        }
    } else if (r && r->t == NTX_BE_DICT) {
        v->y = "r";
        const ntx_be *id = ntx_be_dict_get(r, "id");
        if (id && id->t == NTX_BE_STR && id->sn == 20) {
            v->id = id->sp;
            v->id_len = id->sn;
        }
        const ntx_be *tok = ntx_be_dict_get(r, "token");
        if (tok && tok->t == NTX_BE_STR) {
            v->token = tok->sp;
            v->token_len = tok->sn;
        }
        const ntx_be *vals = ntx_be_dict_get(r, "values");
        if (vals && vals->t == NTX_BE_STR) {
            v->values = vals->sp;
            v->values_len = vals->sn;
        }
        const ntx_be *vals6 = ntx_be_dict_get(r, "values6");
        if (vals6 && vals6->t == NTX_BE_STR) {
            v->values6 = vals6->sp;
            v->values6_len = vals6->sn;
        }
        const ntx_be *nds = ntx_be_dict_get(r, "nodes");
        if (nds && nds->t == NTX_BE_STR) {
            v->nodes = nds->sp;
            v->nodes_len = nds->sn;
        }
        const ntx_be *nds6 = ntx_be_dict_get(r, "nodes6");
        if (nds6 && nds6->t == NTX_BE_STR) {
            v->nodes6 = nds6->sp;
            v->nodes6_len = nds6->sn;
        }
    } else {
        ntx_be_free(&be);
        return -1;
    }
    ntx_be_free(&be);
    return 0;
}

/* --- enc responses --- */

static void mcur_opt_str(mcur *c, const char *key, const uint8_t *p, size_t n) {
    if (!p || n == 0) return;
    mcur_key(c, key);
    mcur_slen(c, n);
    mcur_raw(c, p, n);
}

/* Response (BEP9): outer { r: {...}, t: <tid> } — keys sorted: "r" < "t";
   inner: id, nodes, nodes6, token, values, values6. */
static void mcur_r_head(mcur *c, const uint8_t id[20]) {
    mcur_byte(c, 'd');
    mcur_key(c, "r");
    mcur_byte(c, 'd');
    mcur_key(c, "id");
    mcur_slen(c, 20);
    mcur_raw(c, id, 20);
}

static void mcur_r_tail(mcur *c, const uint8_t tid[2]) {
    mcur_byte(c, 'e'); /* closes r */
    mcur_key(c, "t");
    mcur_slen(c, 2);
    mcur_raw(c, tid, 2);
    mcur_byte(c, 'e'); /* closes outer */
}

size_t ntx_dht_msg_enc_r_ping(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                              const uint8_t id[20]) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_r_head(&c, id);
    mcur_r_tail(&c, tid);
    return mcur_done(&c);
}

size_t ntx_dht_msg_enc_r_find_node(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                   const uint8_t id[20],
                                   const uint8_t *nodes, size_t nodes_len,
                                   const uint8_t *nodes6, size_t nodes6_len) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_r_head(&c, id);
    mcur_opt_str(&c, "nodes", nodes, nodes_len);
    mcur_opt_str(&c, "nodes6", nodes6, nodes6_len);
    mcur_r_tail(&c, tid);
    return mcur_done(&c);
}

size_t ntx_dht_msg_enc_r_get_peers(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                   const uint8_t id[20],
                                   const uint8_t *token, size_t token_len,
                                   const uint8_t *values, size_t values_len,
                                   const uint8_t *values6, size_t values6_len,
                                   const uint8_t *nodes, size_t nodes_len,
                                   const uint8_t *nodes6, size_t nodes6_len) {
    if (!pkt) return 0;
    mcur c = {pkt, cap, 0, 0};
    mcur_r_head(&c, id);
    mcur_opt_str(&c, "nodes", nodes, nodes_len);
    mcur_opt_str(&c, "nodes6", nodes6, nodes6_len);
    mcur_opt_str(&c, "token", token, token_len);
    mcur_opt_str(&c, "values", values, values_len);
    mcur_opt_str(&c, "values6", values6, values6_len);
    mcur_r_tail(&c, tid);
    return mcur_done(&c);
}
