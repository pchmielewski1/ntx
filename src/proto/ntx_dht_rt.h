#ifndef NTX_DHT_RT_H
#define NTX_DHT_RT_H

#include <stdint.h>
#include "../net/ntx_addr.h"

#define NTX_DHT_K 8                 /* BEP5 */
#define NTX_DHT_RT_BUCKETS 16       /* <=32 buckets; key = 1 XOR byte >> 4 */
#define NTX_DHT_RT_REPL 8           /* shared replacement list per RT */
#define NTX_DHT_NODE_EXPIRE_MS (15u*60u*1000u)

/* RT node. */
typedef struct {
    uint8_t id[20];
    ntx_addr addr;
    uint16_t port;
    uint64_t last_seen_ms;
    uint8_t replied;
} ntx_dht_node;

/* Routing table BEP5 (one instance per family: rt4/rt6).
 * "Split" = fixed granularity NTX_DHT_RT_BUCKETS=16 (key = (id[0]^self_id[0])>>4,
 * the top 4 bits of the XOR prefix); up to 32 buckets would be allowed. Dynamic splitting is out of
 * scope; a full bucket is handled by eviction/replacement per BEP5. */
typedef struct {
    uint8_t self_id[20];
    struct { ntx_dht_node nodes[NTX_DHT_K]; int n; } b[NTX_DHT_RT_BUCKETS];
    ntx_dht_node repl[NTX_DHT_RT_REPL];
    int n_repl;
} ntx_dht_rt;

void ntx_dht_rt_init(ntx_dht_rt *rt, const uint8_t self_id[20]);
void ntx_dht_rt_clear(ntx_dht_rt *rt);
int  ntx_dht_rt_add(ntx_dht_rt *rt, const ntx_dht_node *n);
     /* 0 = added/updated; -1 = rejected (zero addr, port 0, id==self) */
int  ntx_dht_rt_get_closest(ntx_dht_rt *rt, const uint8_t target[20],
                            ntx_dht_node *out, int cap);
     /* returns the count; sorted by XOR distance to target (ntx_dht_id_cmp_xor) */
int  ntx_dht_rt_expire(ntx_dht_rt *rt, uint64_t now_ms); /* returns the number removed */
int  ntx_dht_rt_count(const ntx_dht_rt *rt);             /* all nodes (excluding repl) */

#endif
