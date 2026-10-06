#ifndef NTX_DHT_H
#define NTX_DHT_H

#include <stdint.h>
#include <sys/socket.h>
#include "../net/ntx_netx.h"
#include "ntx_dht_msg.h"   /* ntx_dht_cpeer */

typedef ntx_dht_cpeer ntx_dht_peer;   /* { ntx_addr addr; uint16_t port; } */
typedef void (*ntx_dht_cb)(const uint8_t hash[20], const ntx_dht_peer *p, int n, void *ud);

int ntx_dht_start(ntx_netx *netx);
void ntx_dht_stop(void);
/* Shared-socket demux entry: the netx recv loop hands each
 * DHT-classified datagram (first byte 'd'/'l'/'i') to this input, which runs
 * the same per-source rate-limit window and dispatch as the standalone
 * listener. Referenced weakly by ntx_netx so netx-only TUs still link. */
void ntx_dht_input(ntx_netx *netx, const uint8_t *buf, size_t n,
                   const struct sockaddr_storage *from, socklen_t from_len);
void ntx_dht_set_state_path(const char *path);  /* NULL = no persistence; the pointer must stay valid; call before ntx_dht_start */
void ntx_dht_lookup_peers(const uint8_t hash[20], ntx_dht_cb cb, void *ud);
void ntx_dht_announce(const uint8_t hash[20], uint16_t port);
void ntx_dht_tick(void);
void ntx_dht_bootstrap(void);   /* re-sends find_node(self) to the current seeds; no-op when !running */

int ntx_dht_has_v6(void);        /* fd6 >= 0 */
uint16_t ntx_dht_port4(void);    /* local port fd4 (host order); 0 = none */
uint16_t ntx_dht_port6(void);    /* local port fd6; 0 = no v6 */

/* --- test hook / stats --- */
int ntx_dht_node_id_get(uint8_t out[20]);
    /* 0 ok; -1 = not started (test/stats) */
int ntx_dht_test_inject_node(const uint8_t id[20], const ntx_addr *addr, uint16_t port);
    /* rt_add to rt4/rt6 by family, replied=1; 1 = ok, -1 = rejected/not started */
int ntx_dht_test_inject_seed(const ntx_addr *addr, uint16_t port);
    /* adds a seed (if not a duplicate); 1 = ok/exists, -1 = full/not started */
int ntx_dht_node_count(int family);
    /* RT node count: 0 = AF_INET (rt4), 1 = AF_INET6 (rt6) */
int ntx_dht_lookup_active(void);
    /* 1 = iterative get_peers active (lk4 or lk6), 0 = none/finished */
int ntx_dht_token_check(const ntx_addr *addr, const uint8_t tok[8]);
    /* test hook: verify the token against the current unix time; 0 ok, -1 bad/not started */
void ntx_dht_stats(int *rx, int *tx, int *rx_dropped, int *tx_dropped);
    /* datagram counters (rx/tx) and rate-limit drops (rx_dropped/tx_dropped);
       each pointer may be NULL; counters reset in ntx_dht_stop */

#endif
