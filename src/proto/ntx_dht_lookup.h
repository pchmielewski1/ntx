#ifndef NTX_DHT_LOOKUP_H
#define NTX_DHT_LOOKUP_H

#include <stdint.h>
#include "ntx_dht_rt.h"

#define NTX_DHT_ALPHA 3
#define NTX_DHT_LOOKUP_TIMEOUT_MS 2000u
#define NTX_DHT_LOOKUP_MAX_MS 15000u
#define NTX_DHT_LK_KNOWN 16

/* family-agnostic: works on nodes (rt4 OR rt6) */
typedef struct {
    uint8_t hash[20];
    ntx_dht_node known[NTX_DHT_LK_KNOWN];
    uint8_t queried[NTX_DHT_LK_KNOWN];
    uint8_t inflight[NTX_DHT_LK_KNOWN];
    int n_known;
    int n_inflight;
    int done;
    uint64_t start_ms;
} ntx_dht_lookup;

void ntx_dht_lookup_init(ntx_dht_lookup *lk, const uint8_t hash[20], uint64_t now_ms);
int  ntx_dht_lookup_seed(ntx_dht_lookup *lk, ntx_dht_rt *rt);
int  ntx_dht_lookup_pick(ntx_dht_lookup *lk, ntx_dht_node *out, int cap);
void ntx_dht_lookup_inflight_done(ntx_dht_lookup *lk, int idx);
void ntx_dht_lookup_on_response(ntx_dht_lookup *lk, const uint8_t responder_id[20],
                                const ntx_dht_node *nodes, int n, uint64_t now_ms);
void ntx_dht_lookup_finish_check(ntx_dht_lookup *lk, uint64_t now_ms);
int  ntx_dht_lookup_closest(const ntx_dht_lookup *lk, ntx_dht_node *out, int cap);

#endif
