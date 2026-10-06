#ifndef NTX_NETX_H
#define NTX_NETX_H

#include <stddef.h>
#include <sys/types.h>
#include <stdint.h>
#include "ntx_addr.h"
#include "../core/ntx_config.h"

typedef struct ntx_netx ntx_netx;
typedef struct ntx_tunnel ntx_tunnel;
typedef struct ntx_utp ntx_utp;

typedef void (*ntx_cb_rw)(int fd, void *ctx);
typedef void (*ntx_cb_close)(void *ctx);
typedef void (*ntx_cb_timer)(void *arg);
typedef void (*ntx_cb_accept)(ntx_netx *n, int peer_fd, void *ctx);

typedef struct {
    ntx_cb_rw r;
    ntx_cb_rw w;
    ntx_cb_close cl;
} ntx_cbs;

ntx_netx *ntx_netx_init(const ntx_config *cfg);
void ntx_netx_free(ntx_netx *n);
void ntx_netx_run(ntx_netx *n);
void ntx_netx_run_once(ntx_netx *n, int timeout_ms);
void ntx_netx_quit(ntx_netx *n);
void ntx_netx_add(ntx_netx *n, int fd, uint32_t ev, void *ctx, const ntx_cbs *cbs);
void ntx_netx_del(ntx_netx *n, int fd);
void ntx_netx_mod(ntx_netx *n, int fd, uint32_t ev);
void ntx_netx_timer(ntx_netx *n, uint32_t ms, ntx_cb_timer cb, void *arg);
/* Remove every pending (cb, arg) timer still sitting in the heap: an owner
 * that frees the callback's context must cancel first, or a later run_once
 * fires into freed memory. */
void ntx_netx_timer_cancel(ntx_netx *n, ntx_cb_timer cb, void *arg);
/* Connect to a peer: port in host order, addr in network order (v4 or v6).
 * Both families reach every egress path: raw, SOCKS (ATYP 0x04), tunnel
 * (OPEN_V6 cmd=3) and the uTP dial — the v4-only hard gate is
 * gone; a family the chosen transport cannot serve falls through to the next. */
int ntx_netx_route_connect(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs);
int ntx_netx_route_connect_tcp(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs);
void ntx_netx_set_accept(ntx_netx *n, ntx_cb_accept cb, void *ctx);
uint16_t ntx_netx_port(const ntx_netx *n);
/* IPv6 listen port (host order); 0 = no v6 listen socket. */
uint16_t ntx_netx_port6(const ntx_netx *n);
/* Shared per-family UDP owner: the netx-owned datagram socket
 * bound to the listen port that both DHT and uTP ride, demultiplexed by first
 * byte. Returns the fd, or -1 when the bind collided (fail-soft: DHT runs on
 * its own socket, uTP is off). */
int ntx_netx_udp4_fd(const ntx_netx *n);
/* IPv6 sibling of the shared owner: the netx-owned AF_INET6
 * datagram socket bound to the same listen port with IPV6_V6ONLY=1, so v6
 * peers reach uTP on the single advertised port. -1 when IPv6 is unavailable
 * in the environment or the bind collided (fail-soft: v6 uTP is simply off, v4
 * is unaffected). v4-mapped peers never appear here — V6ONLY keeps ::/0 v6-only
 * and every v4 peer arrives on the v4 socket, normalised by
 * ntx_addr_from_sockaddr. */
int ntx_netx_udp6_fd(const ntx_netx *n);
/* Shared-socket classifier counters (any arg NULL to skip). demux_drop counts
 * datagrams whose first byte is neither a DHT bencode start nor a legal uTP
 * v1 header — the demux_unknown class. */
void ntx_netx_demux_stats(const ntx_netx *n, uint64_t *dht, uint64_t *utp,
                          uint64_t *drop);
/* UI read-only views of the uTP transport:
 * active connection count (0 when uTP is off) and the utp_v6 flag (1 when the
 * v6 listen sibling is bound or a v6 conn exists). NULL-safe. */
int ntx_netx_utp_conns(const ntx_netx *n);
int ntx_netx_utp_v6(const ntx_netx *n);
ssize_t ntx_netx_read(ntx_netx *n, int fd, uint8_t *buf, size_t cap);
ssize_t ntx_netx_write(ntx_netx *netx, int fd, const uint8_t *buf, size_t len);
int ntx_netx_peer_connected(ntx_netx *n, int fd);

/* Shared-socket datagram classification (BEP5/BEP29): pure first-byte
 * table — 'd'/'l'/'i' → bencode DHT; high nibble type 0..4 + low nibble ver 1
 * → uTP header start; everything else (incl. empty) → NTX_UDP_DROP. No I/O.
 * 0x64 cannot be a legal uTP v1 byte (that would be type=6, ver=4). */
typedef enum { NTX_UDP_DHT = 1, NTX_UDP_UTP = 2, NTX_UDP_DROP = 0 } ntx_udp_kind;
ntx_udp_kind ntx_udp_classify(const uint8_t *pkt, size_t n);

#endif
