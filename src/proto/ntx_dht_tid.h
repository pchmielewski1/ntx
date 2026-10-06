#ifndef NTX_DHT_TID_H
#define NTX_DHT_TID_H
#include <stdint.h>
#include "../net/ntx_addr.h"

#define NTX_DHT_TID_LEN 2
#define NTX_DHT_TID_MAX 64

typedef enum {
    NTX_DHT_TK_PING = 0,
    NTX_DHT_TK_FIND_NODE,
    NTX_DHT_TK_GET_PEERS,
    NTX_DHT_TK_ANNOUNCE
} ntx_dht_tid_kind;

typedef struct {
    uint8_t tid[2];
    ntx_addr addr;
    uint16_t port;
    uint64_t sent_ms;
    ntx_dht_tid_kind kind;
    int slot;     /* lookup slot; -1 = none */
    int family;   /* NTX_AF_INET / NTX_AF_INET6 (send socket) */
} ntx_dht_tid_ent;

typedef struct { ntx_dht_tid_ent e[NTX_DHT_TID_MAX]; int n; } ntx_dht_tid_map;

void ntx_dht_tid_init(ntx_dht_tid_map *m);
int  ntx_dht_tid_put(ntx_dht_tid_map *m, const uint8_t tid[2], const ntx_addr *addr,
                     uint16_t port, ntx_dht_tid_kind kind, int slot, int family);
     /* 0 ok (overwrites an existing entry with the same tid); -1 = map full (no eviction) */
int  ntx_dht_tid_take(ntx_dht_tid_map *m, const uint8_t tid[2], const ntx_addr *src_addr,
                      uint16_t src_port, ntx_dht_tid_ent *out);
     /* match: tid EQUAL + source: ntx_addr_eq after NORMALIZATION (v4-mapped v6 → v4,
        i.e. if src_addr is a v6 with the ::ffff:a.b.c.d prefix → compare it as v4 a.b.c.d);
        port EQUAL; removes the entry; 0 ok / -1 not found */
int  ntx_dht_tid_expire(ntx_dht_tid_map *m, uint64_t now_ms, uint64_t ttl_ms);
     /* removes entries with now - sent_ms > ttl; returns the count */
int  ntx_dht_tid_fresh(ntx_dht_tid_map *m, uint8_t tid[2]);
     /* random 2 B (ntx_rand_bytes) chosen not to collide with any active tid
        (max 32 tries; after that returns 0 anyway); 0 ok */
#endif
