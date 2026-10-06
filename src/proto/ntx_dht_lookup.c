#include "ntx_dht_lookup.h"
#include "ntx_dht_xor.h"

#include <string.h>

void ntx_dht_lookup_init(ntx_dht_lookup *lk, const uint8_t hash[20], uint64_t now_ms) {
    memset(lk, 0, sizeof(*lk));
    memcpy(lk->hash, hash, 20);
    lk->start_ms = now_ms;
}

int ntx_dht_lookup_seed(ntx_dht_lookup *lk, ntx_dht_rt *rt) {
    memset(lk->queried, 0, sizeof(lk->queried));
    memset(lk->inflight, 0, sizeof(lk->inflight));
    lk->n_inflight = 0;
    lk->done = 0;
    lk->n_known = ntx_dht_rt_get_closest(rt, lk->hash, lk->known, NTX_DHT_LK_KNOWN);
    if (lk->n_known == 0) lk->done = 1;
    return lk->n_known;
}

int ntx_dht_lookup_pick(ntx_dht_lookup *lk, ntx_dht_node *out, int cap) {
    if (lk->done || cap <= 0) return 0;
    int cand[NTX_DHT_LK_KNOWN];
    int n = 0;
    for (int i = 0; i < lk->n_known; i++)
        if (!lk->queried[i] && !lk->inflight[i]) cand[n++] = i;
    if (n == 0) { lk->done = 1; return 0; }
    for (int i = 1; i < n; i++) {
        int v = cand[i];
        int j = i - 1;
        while (j >= 0 &&
               ntx_dht_id_cmp_xor(lk->known[v].id, lk->known[cand[j]].id, lk->hash) < 0) {
            cand[j + 1] = cand[j];
            j--;
        }
        cand[j + 1] = v;
    }
    int take = n < cap ? n : cap;
    for (int i = 0; i < take; i++) {
        int idx = cand[i];
        lk->queried[idx] = 1;
        lk->inflight[idx] = 1;
        lk->n_inflight++;
        if (out) out[i] = lk->known[idx];
    }
    return take;
}

static int lk_find_by_id(const ntx_dht_lookup *lk, const uint8_t id[20]) {
    for (int i = 0; i < lk->n_known; i++)
        if (memcmp(lk->known[i].id, id, 20) == 0) return i;
    return -1;
}

static int lk_node_valid(const ntx_dht_node *n) {
    return !ntx_addr_is_zero(&n->addr) && n->port != 0;
}

void ntx_dht_lookup_inflight_done(ntx_dht_lookup *lk, int idx) {
    if (idx < 0 || idx >= NTX_DHT_LK_KNOWN) return;
    if (!lk->inflight[idx]) return;
    lk->inflight[idx] = 0;
    lk->n_inflight--;
}

static void lk_add_node(ntx_dht_lookup *lk, const ntx_dht_node *nn,
                        uint8_t replied, uint64_t now_ms) {
    ntx_dht_node add = *nn;
    add.last_seen_ms = now_ms;
    add.replied = replied;
    if (lk->n_known < NTX_DHT_LK_KNOWN) {
        lk->known[lk->n_known++] = add;
        return;
    }
    int victim = -1;
    for (int i = 0; i < NTX_DHT_LK_KNOWN; i++) {
        if (lk->inflight[i]) continue;
        if (victim < 0 ||
            ntx_dht_id_cmp_xor(lk->known[i].id, lk->known[victim].id, lk->hash) > 0)
            victim = i;
    }
    if (victim < 0) return;
    lk->known[victim] = add;
    lk->queried[victim] = 0;
    lk->inflight[victim] = 0;
}

void ntx_dht_lookup_on_response(ntx_dht_lookup *lk, const uint8_t responder_id[20],
                                const ntx_dht_node *nodes, int n, uint64_t now_ms) {
    int ri = lk_find_by_id(lk, responder_id);
    if (ri >= 0) lk->known[ri].replied = 1;
    for (int k = 0; k < n; k++) {
        const ntx_dht_node *nn = &nodes[k];
        if (!lk_node_valid(nn)) continue;
        if (lk_find_by_id(lk, nn->id) >= 0) continue;
        uint8_t replied = (memcmp(nn->id, responder_id, 20) == 0) ? 1 : 0;
        lk_add_node(lk, nn, replied, now_ms);
    }
}

void ntx_dht_lookup_finish_check(ntx_dht_lookup *lk, uint64_t now_ms) {
    if (lk->done) return;
    if (now_ms - lk->start_ms > NTX_DHT_LOOKUP_MAX_MS) {
        lk->done = 1;
        return;
    }
    if (lk->n_inflight == 0) {
        int all = 1;
        for (int i = 0; i < lk->n_known; i++)
            if (!lk->queried[i]) { all = 0; break; }
        if (all) lk->done = 1;
    }
}

int ntx_dht_lookup_closest(const ntx_dht_lookup *lk, ntx_dht_node *out, int cap) {
    if (cap <= 0 || lk->n_known == 0) return 0;
    int cand[NTX_DHT_LK_KNOWN];
    int n = 0;
    for (int i = 0; i < lk->n_known; i++) cand[n++] = i;
    for (int i = 1; i < n; i++) {
        int v = cand[i];
        int j = i - 1;
        while (j >= 0 &&
               ntx_dht_id_cmp_xor(lk->known[v].id, lk->known[cand[j]].id, lk->hash) < 0) {
            cand[j + 1] = cand[j];
            j--;
        }
        cand[j + 1] = v;
    }
    int take = n < cap ? n : cap;
    for (int i = 0; i < take; i++)
        if (out) out[i] = lk->known[cand[i]];
    return take;
}
