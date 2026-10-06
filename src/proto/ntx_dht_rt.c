#include "ntx_dht_rt.h"
#include "ntx_dht_xor.h"

#include <string.h>
#include <time.h>

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static int bucket_of(const ntx_dht_rt *rt, const uint8_t id[20]) {
    return (int)((id[0] ^ rt->self_id[0]) >> 4);
}

static void repl_push(ntx_dht_rt *rt, const ntx_dht_node *n) {
    if (rt->n_repl < NTX_DHT_RT_REPL) {
        rt->repl[rt->n_repl++] = *n;
        return;
    }
    memmove(&rt->repl[0], &rt->repl[1],
            (size_t)(NTX_DHT_RT_REPL - 1) * sizeof(ntx_dht_node));
    rt->repl[NTX_DHT_RT_REPL - 1] = *n;
}

void ntx_dht_rt_init(ntx_dht_rt *rt, const uint8_t self_id[20]) {
    memset(rt, 0, sizeof(*rt));
    memcpy(rt->self_id, self_id, 20);
}

void ntx_dht_rt_clear(ntx_dht_rt *rt) {
    uint8_t self[20];
    memcpy(self, rt->self_id, 20);
    memset(rt, 0, sizeof(*rt));
    memcpy(rt->self_id, self, 20);
}

int ntx_dht_rt_count(const ntx_dht_rt *rt) {
    int n = 0;
    for (int i = 0; i < NTX_DHT_RT_BUCKETS; i++) n += rt->b[i].n;
    return n;
}

int ntx_dht_rt_add(ntx_dht_rt *rt, const ntx_dht_node *n) {
    if (ntx_addr_is_zero(&n->addr) || n->port == 0 ||
        memcmp(n->id, rt->self_id, 20) == 0)
        return -1;
    uint64_t seen = n->last_seen_ms != 0 ? n->last_seen_ms : mono_ms();
    /* dedup: same addr+port (anywhere in the RT) → refresh, no duplicate */
    for (int bi = 0; bi < NTX_DHT_RT_BUCKETS; bi++) {
        for (int i = 0; i < rt->b[bi].n; i++) {
            if (rt->b[bi].nodes[i].port == n->port &&
                ntx_addr_eq(&rt->b[bi].nodes[i].addr, &n->addr)) {
                rt->b[bi].nodes[i].last_seen_ms = seen;
                rt->b[bi].nodes[i].replied |= n->replied;
                return 0;
            }
        }
    }
    int k = bucket_of(rt, n->id);
    ntx_dht_node m = *n;
    m.last_seen_ms = seen;
    if (rt->b[k].n < NTX_DHT_K) {
        rt->b[k].nodes[rt->b[k].n++] = m;
        return 0;
    }
    /* bucket full */
    if (m.replied) {
        /* evict the oldest non-replied; if all replied → the oldest */
        int victim = -1;
        for (int i = 0; i < rt->b[k].n; i++) {
            if (rt->b[k].nodes[i].replied) continue;
            if (victim < 0 ||
                rt->b[k].nodes[i].last_seen_ms < rt->b[k].nodes[victim].last_seen_ms)
                victim = i;
        }
        if (victim < 0) {
            for (int i = 0; i < rt->b[k].n; i++)
                if (victim < 0 ||
                    rt->b[k].nodes[i].last_seen_ms < rt->b[k].nodes[victim].last_seen_ms)
                    victim = i;
        }
        repl_push(rt, &rt->b[k].nodes[victim]);
        rt->b[k].nodes[victim] = m;
        return 0;
    }
    repl_push(rt, &m);
    return 0;
}

int ntx_dht_rt_get_closest(ntx_dht_rt *rt, const uint8_t target[20],
                           ntx_dht_node *out, int cap) {
    if (cap <= 0) return 0;
    ntx_dht_node tmp[NTX_DHT_RT_BUCKETS * NTX_DHT_K];
    int n = 0;
    for (int i = 0; i < NTX_DHT_RT_BUCKETS; i++)
        for (int j = 0; j < rt->b[i].n; j++)
            tmp[n++] = rt->b[i].nodes[j];
    for (int i = 1; i < n; i++) {
        ntx_dht_node cur = tmp[i];
        int j = i - 1;
        while (j >= 0 && ntx_dht_id_cmp_xor(tmp[j].id, cur.id, target) > 0) {
            tmp[j + 1] = tmp[j];
            j--;
        }
        tmp[j + 1] = cur;
    }
    int k = n < cap ? n : cap;
    memcpy(out, tmp, (size_t)k * sizeof(ntx_dht_node));
    return k;
}

int ntx_dht_rt_expire(ntx_dht_rt *rt, uint64_t now_ms) {
    int removed = 0;
    for (int bi = 0; bi < NTX_DHT_RT_BUCKETS; bi++) {
        int w = 0;
        for (int i = 0; i < rt->b[bi].n; i++) {
            if (now_ms - rt->b[bi].nodes[i].last_seen_ms > NTX_DHT_NODE_EXPIRE_MS) {
                removed++;
            } else {
                rt->b[bi].nodes[w++] = rt->b[bi].nodes[i];
            }
        }
        rt->b[bi].n = w;
    }
    int w = 0;
    for (int i = 0; i < rt->n_repl; i++) {
        if (now_ms - rt->repl[i].last_seen_ms > NTX_DHT_NODE_EXPIRE_MS) {
            removed++;
        } else {
            rt->repl[w++] = rt->repl[i];
        }
    }
    rt->n_repl = w;
    return removed;
}
