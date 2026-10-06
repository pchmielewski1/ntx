#ifndef NTX_PEX_TX_H
#define NTX_PEX_TX_H

#include <stdint.h>
#include "../net/ntx_addr.h"

/* BEP11 PEX outbound event queue (per torrent).
 * Queues connect/disconnect events since the last sent ut_pex so the sender
 * emits added/added6 on PH_OK and dropped/dropped6 on disconnect of
 * previously advertised peers, with elision of transient connect->disconnect
 * pairs that were never advertised. */

#define NTX_PEX_TX_Q 64
#define NTX_PEX_TX_MSG_MAX 50

typedef struct {
    ntx_addr addr;
    uint16_t port;
    uint8_t pending_add;  /* 1 = connect not yet emitted as added */
    uint8_t pending_drop; /* 1 = advertised peer disconnected, not yet emitted */
    uint8_t advertised;   /* 1 = emitted in a prior added while live */
} ntx_pex_tx_slot;

struct ntx_pex_tx {
    ntx_pex_tx_slot slot[NTX_PEX_TX_Q];
    int n;
};
typedef struct ntx_pex_tx ntx_pex_tx;

void ntx_pex_tx_init(ntx_pex_tx *q);
void ntx_pex_tx_on_connected(ntx_pex_tx *q, const ntx_addr *addr, uint16_t port);
void ntx_pex_tx_on_disconnected(ntx_pex_tx *q, const ntx_addr *addr, uint16_t port);

/* Fill compact lists (slot order); clears the events that were included.
 * cap_added/cap_dropped bound combined v4+v6 counts per family.
 * Returns 0 if at least one list is non-empty, -1 if nothing to send. */
int ntx_pex_tx_drain(ntx_pex_tx *q,
                     uint32_t *a4, uint16_t *ap4, int *na4,
                     uint8_t (*a6)[16], uint16_t *ap6, int *na6,
                     uint32_t *d4, uint16_t *dp4, int *nd4,
                     uint8_t (*d6)[16], uint16_t *dp6, int *nd6,
                     int cap_added, int cap_dropped);

/* Same fill as drain without clearing (build, send, then commit on success). */
int ntx_pex_tx_peek(ntx_pex_tx *q,
                    uint32_t *a4, uint16_t *ap4, int *na4,
                    uint8_t (*a6)[16], uint16_t *ap6, int *na6,
                    uint32_t *d4, uint16_t *dp4, int *nd4,
                    uint8_t (*d6)[16], uint16_t *dp6, int *nd6,
                    int cap_added, int cap_dropped);
/* Clear exactly the events a preceding peek returned (peek order). */
void ntx_pex_tx_commit(ntx_pex_tx *q, int na4, int na6, int nd4, int nd6);

#endif
