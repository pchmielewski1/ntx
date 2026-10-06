#ifndef NTX_DHT_MSG_H
#define NTX_DHT_MSG_H
#include <stddef.h>
#include <stdint.h>
#include "../net/ntx_addr.h"
#include "ntx_dht_rt.h"   /* ntx_dht_node */

/* Compact peer (target ntx_dht_peer type) */
typedef struct { ntx_addr addr; uint16_t port; } ntx_dht_cpeer;

/* --- parse compact --- */
int ntx_dht_msg_parse_nodes (const uint8_t *p, size_t n, ntx_dht_node *out, int cap, uint64_t now_ms);
   /* 26 B record: id[20]+ip4[4](net-order)+port[2](BE) → out[i].addr=set_v4, port host-order, last_seen_ms=now_ms; a tail <26 B is ignored; returns the count (0..cap); cap<=0 → 0 */
int ntx_dht_msg_parse_values(const uint8_t *p, size_t n, ntx_dht_cpeer *out, int cap);
   /* 6 B record: ip4[4]+port[2](BE); a tail <6 B is ignored */
int ntx_dht_msg_parse_nodes6 (const uint8_t *p, size_t n, ntx_dht_node *out, int cap, uint64_t now_ms);
   /* 38 B record: id[20]+ip6[16]+port[2](BE) → set_v6 */
int ntx_dht_msg_parse_values6(const uint8_t *p, size_t n, ntx_dht_cpeer *out, int cap);
   /* 18 B record: ip6[16]+port[2](BE) */

/* --- view (parsed query/response) --- */
typedef struct {
    const uint8_t *tid;   size_t tid_len;    /* typically 2 B */
    const char    *y;                                /* "q" | "r" */
    const char    *q;                                /* ping|find_node|get_peers|announce_peer; NULL when y=r */
    const uint8_t *id;     size_t id_len;            /* a.id (query) */
    const uint8_t *target; size_t target_len;        /* find_node: a.target (20 B); NULL in the other queries */
    const uint8_t *info_hash;                        /* 20 B; NULL when absent */
    int            want_n4, want_n6;                 /* from the want list */
    uint16_t       port;                             /* announce_peer; 0 = none */
    const uint8_t *nodes;    size_t nodes_len;
    const uint8_t *nodes6;   size_t nodes6_len;
    const uint8_t *values;   size_t values_len;
    const uint8_t *values6;  size_t values6_len;
    const uint8_t *token;    size_t token_len;
} ntx_dht_msg_view;
int ntx_dht_msg_parse(const uint8_t *buf, size_t n, ntx_dht_msg_view *v);
   /* 0 ok / -1 fail; v is zeroed before filling; does not free the buffer (pointers point into buf) */

/* --- enc queries (tid = 2 B) --- */
size_t ntx_dht_msg_enc_ping(uint8_t *pkt, size_t cap, const uint8_t tid[2], const uint8_t id[20]);
size_t ntx_dht_msg_enc_find_node(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                 const uint8_t id[20], const uint8_t n[20],
                                 int want_n4, int want_n6);
size_t ntx_dht_msg_enc_get_peers(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                 const uint8_t id[20], const uint8_t info_hash[20],
                                 int want_n4, int want_n6);
size_t ntx_dht_msg_enc_announce_peer(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                     const uint8_t id[20], const uint8_t info_hash[20],
                                     uint16_t port, const uint8_t *token, size_t token_len);
   /* returns the byte count; 0 = cap too small */

/* --- enc responses --- */
size_t ntx_dht_msg_enc_r_ping(uint8_t *pkt, size_t cap, const uint8_t tid[2], const uint8_t id[20]);
size_t ntx_dht_msg_enc_r_find_node(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                   const uint8_t id[20],
                                   const uint8_t *nodes, size_t nodes_len,
                                   const uint8_t *nodes6, size_t nodes6_len);
size_t ntx_dht_msg_enc_r_get_peers(uint8_t *pkt, size_t cap, const uint8_t tid[2],
                                   const uint8_t id[20],
                                   const uint8_t *token, size_t token_len,
                                   const uint8_t *values,  size_t values_len,
                                   const uint8_t *values6, size_t values6_len,
                                   const uint8_t *nodes,   size_t nodes_len,
                                   const uint8_t *nodes6,  size_t nodes6_len);
   /* field omitted when the pointer is NULL or len==0 */
#endif
