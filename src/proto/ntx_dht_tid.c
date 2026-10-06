#include "ntx_dht_tid.h"

#include "../crypto/ntx_rng.h"

#include <string.h>
#include <time.h>

static uint64_t tid_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)(ts.tv_nsec / 1000000L);
}

static void norm_addr(ntx_addr *a) {
    if (a->family != NTX_AF_INET6) return;
    const uint8_t *v = a->u.v6;
    for (int i = 0; i < 10; i++) {
        if (v[i] != 0) return;
    }
    if (v[10] != 0xFF || v[11] != 0xFF) return;
    uint32_t ip = ((uint32_t)v[12] << 24) | ((uint32_t)v[13] << 16) |
                  ((uint32_t)v[14] << 8) | (uint32_t)v[15];
    ntx_addr_set_v4(a, ip);
}

void ntx_dht_tid_init(ntx_dht_tid_map *m) {
    memset(m, 0, sizeof *m);
}

int ntx_dht_tid_put(ntx_dht_tid_map *m, const uint8_t tid[2], const ntx_addr *addr,
                    uint16_t port, ntx_dht_tid_kind kind, int slot, int family) {
    for (int i = 0; i < m->n; i++) {
        if (m->e[i].tid[0] == tid[0] && m->e[i].tid[1] == tid[1]) {
            m->e[i].addr = *addr;
            m->e[i].port = port;
            m->e[i].sent_ms = tid_mono_ms();
            m->e[i].kind = kind;
            m->e[i].slot = slot;
            m->e[i].family = family;
            return 0;
        }
    }
    if (m->n >= NTX_DHT_TID_MAX) return -1;
    ntx_dht_tid_ent *e = &m->e[m->n];
    m->n++;
    e->tid[0] = tid[0];
    e->tid[1] = tid[1];
    e->addr = *addr;
    e->port = port;
    e->sent_ms = tid_mono_ms();
    e->kind = kind;
    e->slot = slot;
    e->family = family;
    return 0;
}

int ntx_dht_tid_take(ntx_dht_tid_map *m, const uint8_t tid[2], const ntx_addr *src_addr,
                     uint16_t src_port, ntx_dht_tid_ent *out) {
    ntx_addr src = *src_addr;
    norm_addr(&src);
    for (int i = 0; i < m->n; i++) {
        const ntx_dht_tid_ent *e = &m->e[i];
        if (e->tid[0] != tid[0] || e->tid[1] != tid[1]) continue;
        if (e->port != src_port) continue;
        ntx_addr ea = e->addr;
        norm_addr(&ea);
        if (!ntx_addr_eq(&ea, &src)) continue;
        *out = *e;
        memmove(&m->e[i], &m->e[i + 1], (size_t)(m->n - i - 1) * sizeof m->e[0]);
        m->n--;
        return 0;
    }
    return -1;
}

int ntx_dht_tid_expire(ntx_dht_tid_map *m, uint64_t now_ms, uint64_t ttl_ms) {
    int removed = 0;
    for (int i = 0; i < m->n; ) {
        if (now_ms - m->e[i].sent_ms > ttl_ms) {
            memmove(&m->e[i], &m->e[i + 1], (size_t)(m->n - i - 1) * sizeof m->e[0]);
            m->n--;
            removed++;
        } else {
            i++;
        }
    }
    return removed;
}

int ntx_dht_tid_fresh(ntx_dht_tid_map *m, uint8_t tid[2]) {
    for (int attempt = 0; attempt < 32; attempt++) {
        ntx_rand_bytes(tid, NTX_DHT_TID_LEN);
        int clash = 0;
        for (int i = 0; i < m->n; i++) {
            if (m->e[i].tid[0] == tid[0] && m->e[i].tid[1] == tid[1]) {
                clash = 1;
                break;
            }
        }
        if (!clash) return 0;
    }
    memset(tid, 0, NTX_DHT_TID_LEN);
    return 0;
}
