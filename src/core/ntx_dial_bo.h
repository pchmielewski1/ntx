#ifndef NTX_DIAL_BO_H
#define NTX_DIAL_BO_H

/* Redial back-off for outbound peer connections.
 *
 * Tracker, PEX and DHT replies are mostly stale or unreachable addresses (in a live swarm only ~1-2% of
 * dials ever complete) and the same addresses come back with every announce.  Without memory the session
 * keeps spending its limited handshake slots on addresses that just failed.  A failed outbound attempt
 * blocks that address for 30 s, doubling on every further failure up to 10 min; a connection that reaches
 * the OK state forgets the history.  Pure data structure: no I/O, time is passed in by the caller. */

#include "../net/ntx_addr.h"

#include <stdint.h>
#include <string.h>

#define NTX_DIAL_BO_N 512
#define NTX_DIAL_BO_BASE_MS 30000u
#define NTX_DIAL_BO_MAX_MS 600000u

typedef struct {
    ntx_addr addr;
    uint16_t port;
    uint8_t fails;     /* consecutive failures; 0 = slot unused */
    uint64_t until;    /* blocked while now < until */
} ntx_dial_bo_ent;

typedef struct {
    ntx_dial_bo_ent e[NTX_DIAL_BO_N];
} ntx_dial_bo;

static inline ntx_dial_bo_ent *ntx_dial_bo_find(ntx_dial_bo *b, const ntx_addr *a, uint16_t port) {
    for (int i = 0; i < NTX_DIAL_BO_N; i++)
        if (b->e[i].fails && b->e[i].port == port && ntx_addr_eq(&b->e[i].addr, a)) return &b->e[i];
    return NULL;
}

static inline int ntx_dial_bo_blocked(ntx_dial_bo *b, const ntx_addr *a, uint16_t port, uint64_t now) {
    ntx_dial_bo_ent *e = ntx_dial_bo_find(b, a, port);
    return e && now < e->until;
}

static inline void ntx_dial_bo_fail(ntx_dial_bo *b, const ntx_addr *a, uint16_t port, uint64_t now) {
    ntx_dial_bo_ent *e = ntx_dial_bo_find(b, a, port);
    if (!e) {
        /* free slot, else the entry whose block ends first (least useful to keep) */
        int pick = 0;
        for (int i = 0; i < NTX_DIAL_BO_N; i++) {
            if (!b->e[i].fails) {
                pick = i;
                break;
            }
            if (b->e[i].until < b->e[pick].until) pick = i;
        }
        e = &b->e[pick];
        memset(e, 0, sizeof *e);
        e->addr = *a;
        e->port = port;
    }
    if (e->fails < 255) e->fails++;
    uint64_t d = NTX_DIAL_BO_BASE_MS;
    for (int k = 1; k < e->fails && d < NTX_DIAL_BO_MAX_MS; k++) d *= 2;
    if (d > NTX_DIAL_BO_MAX_MS) d = NTX_DIAL_BO_MAX_MS;
    e->until = now + d;
}

static inline void ntx_dial_bo_ok(ntx_dial_bo *b, const ntx_addr *a, uint16_t port) {
    ntx_dial_bo_ent *e = ntx_dial_bo_find(b, a, port);
    if (e) memset(e, 0, sizeof *e);
}

#endif
