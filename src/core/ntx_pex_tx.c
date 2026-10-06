#include "ntx_pex_tx.h"

#include <string.h>

void ntx_pex_tx_init(ntx_pex_tx *q) {
    memset(q, 0, sizeof *q);
}

static int find_slot(const ntx_pex_tx *q, const ntx_addr *addr, uint16_t port) {
    for (int i = 0; i < q->n; i++) {
        const ntx_pex_tx_slot *s = &q->slot[i];
        if (s->port == port && ntx_addr_eq(&s->addr, addr))
            return i;
    }
    return -1;
}

void ntx_pex_tx_on_connected(ntx_pex_tx *q, const ntx_addr *addr, uint16_t port) {
    if (ntx_addr_is_zero(addr) || port == 0)
        return;
    int i = find_slot(q, addr, port);
    if (i >= 0) {
        ntx_pex_tx_slot *s = &q->slot[i];
        if (s->pending_drop) {
            s->pending_drop = 0;
            if (!s->advertised)
                s->pending_add = 1;
            return;
        }
        if (s->pending_add)
            return;
        if (s->advertised)
            return;
        s->pending_add = 1;
        return;
    }
    ntx_pex_tx_slot ns;
    ns.addr = *addr;
    ns.port = port;
    ns.pending_add = 1;
    ns.pending_drop = 0;
    ns.advertised = 0;
    if (q->n == NTX_PEX_TX_Q) {
        memmove(q->slot, q->slot + 1, (size_t)(NTX_PEX_TX_Q - 1) * sizeof q->slot[0]);
        q->slot[NTX_PEX_TX_Q - 1] = ns;
    } else {
        q->slot[q->n++] = ns;
    }
}

void ntx_pex_tx_on_disconnected(ntx_pex_tx *q, const ntx_addr *addr, uint16_t port) {
    if (ntx_addr_is_zero(addr) || port == 0)
        return;
    int i = find_slot(q, addr, port);
    if (i < 0)
        return;
    ntx_pex_tx_slot *s = &q->slot[i];
    if (s->pending_add) {
        s->pending_add = 0;
        return;
    }
    if (s->advertised) {
        s->pending_drop = 1;
        s->pending_add = 0;
    }
}

static int fill_lists(ntx_pex_tx *q,
                      uint32_t *a4, uint16_t *ap4, int *na4,
                      uint8_t (*a6)[16], uint16_t *ap6, int *na6,
                      uint32_t *d4, uint16_t *dp4, int *nd4,
                      uint8_t (*d6)[16], uint16_t *dp6, int *nd6,
                      int cap_added, int cap_dropped) {
    *na4 = 0; *na6 = 0; *nd4 = 0; *nd6 = 0;
    int added = 0, dropped = 0;
    for (int i = 0; i < q->n; i++) {
        const ntx_pex_tx_slot *s = &q->slot[i];
        if (s->pending_add) {
            if (added >= cap_added)
                continue;
            if (ntx_addr_is_v4(&s->addr)) {
                a4[*na4] = s->addr.u.v4;
                ap4[*na4] = s->port;
                (*na4)++;
            } else {
                memcpy(a6[*na6], s->addr.u.v6, 16);
                ap6[*na6] = s->port;
                (*na6)++;
            }
            added++;
        } else if (s->pending_drop) {
            if (dropped >= cap_dropped)
                continue;
            if (ntx_addr_is_v4(&s->addr)) {
                d4[*nd4] = s->addr.u.v4;
                dp4[*nd4] = s->port;
                (*nd4)++;
            } else {
                memcpy(d6[*nd6], s->addr.u.v6, 16);
                dp6[*nd6] = s->port;
                (*nd6)++;
            }
            dropped++;
        }
    }
    return (*na4 + *na6 + *nd4 + *nd6) > 0 ? 0 : -1;
}

void ntx_pex_tx_commit(ntx_pex_tx *q, int na4, int na6, int nd4, int nd6) {
    int to_add = na4 + na6;
    int to_drop = nd4 + nd6;
    int done_add = 0, done_drop = 0;
    for (int i = 0; i < q->n; i++) {
        ntx_pex_tx_slot *s = &q->slot[i];
        if (s->pending_add && done_add < to_add) {
            s->pending_add = 0;
            s->advertised = 1;
            done_add++;
        } else if (s->pending_drop && done_drop < to_drop) {
            s->pending_drop = 0;
            done_drop++;
        }
    }
}

int ntx_pex_tx_peek(ntx_pex_tx *q,
                    uint32_t *a4, uint16_t *ap4, int *na4,
                    uint8_t (*a6)[16], uint16_t *ap6, int *na6,
                    uint32_t *d4, uint16_t *dp4, int *nd4,
                    uint8_t (*d6)[16], uint16_t *dp6, int *nd6,
                    int cap_added, int cap_dropped) {
    return fill_lists(q, a4, ap4, na4, a6, ap6, na6, d4, dp4, nd4, d6, dp6, nd6,
                      cap_added, cap_dropped);
}

int ntx_pex_tx_drain(ntx_pex_tx *q,
                     uint32_t *a4, uint16_t *ap4, int *na4,
                     uint8_t (*a6)[16], uint16_t *ap6, int *na6,
                     uint32_t *d4, uint16_t *dp4, int *nd4,
                     uint8_t (*d6)[16], uint16_t *dp6, int *nd6,
                     int cap_added, int cap_dropped) {
    int r = fill_lists(q, a4, ap4, na4, a6, ap6, na6, d4, dp4, nd4, d6, dp6, nd6,
                       cap_added, cap_dropped);
    if (r == 0)
        ntx_pex_tx_commit(q, *na4, *na6, *nd4, *nd6);
    return r;
}
