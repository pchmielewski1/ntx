#ifndef NTX_PROXY_H
#define NTX_PROXY_H

#include <stddef.h>
#include <stdint.h>

#include "../core/ntx_config.h"
#include "ntx_addr.h"

typedef struct {
    int st;
    uint8_t buf[512];
    size_t blen;
    ntx_addr addr;
    uint16_t port;
    int fd;
    void *app_ctx;
    void (*app_r)(int fd, void *ctx);
    void (*app_w)(int fd, void *ctx);
    void (*app_cl)(void *ctx);
} ntx_proxy;

void ntx_proxy_init(ntx_proxy *p, int fd, const ntx_addr *addr, uint16_t port, void *app_ctx,
                    void (*app_r)(int fd, void *ctx),
                    void (*app_w)(int fd, void *ctx),
                    void (*app_cl)(void *ctx));
int ntx_proxy_step(ntx_proxy *p, int readable);
int ntx_proxy_done(const ntx_proxy *p);
uint16_t ntx_proxy_local_port(int fd);

/* ntx_proxy_parse_spec is implemented in ntx_proxy.c
 * (SOCKS glue: route_connect_proxy/proxy_fail_close/proxy_io_cb stays in ntx_netx.c —
 *  it references private types of ntx_netx.c: ntx_connect_ctx, n->fds, n->cfg) */
int ntx_proxy_parse_spec(const char *spec, ntx_config *cfg, char *hostbuf, size_t hcap);

/* RFC1928 §7 UDP ASSOCIATE. The TCP control connection is the same
 * SOCKS5 session as CONNECT; the relay returns BND.ADDR/BND.PORT and the caller
 * uses a separate UDP socket for the encapsulated uTP datagrams. */
typedef struct ntx_proxy_udp ntx_proxy_udp;
typedef void (*ntx_proxy_udp_ready_fn)(void *ctx, const ntx_addr *bnd,
                                       uint16_t bnd_port);
typedef void (*ntx_proxy_udp_packet_fn)(void *ctx, const ntx_addr *src,
                                        uint16_t src_port, const uint8_t *data,
                                        size_t data_len);
typedef void (*ntx_proxy_udp_closed_fn)(void *ctx);

ntx_proxy_udp *ntx_proxy_udp_associate(int tcp_fd, const ntx_addr *dst,
                                       uint16_t dst_port, void *ctx,
                                       ntx_proxy_udp_ready_fn ready,
                                       ntx_proxy_udp_packet_fn packet,
                                       ntx_proxy_udp_closed_fn closed);
int ntx_proxy_udp_step(ntx_proxy_udp *p, int readable);
int ntx_proxy_udp_recv(ntx_proxy_udp *p);
int ntx_proxy_udp_done(const ntx_proxy_udp *p);
int ntx_proxy_udp_send_datagram(ntx_proxy_udp *p, const ntx_addr *dst,
                                uint16_t dst_port, const uint8_t *data,
                                size_t data_len);
int ntx_proxy_udp_fd(const ntx_proxy_udp *p);
int ntx_proxy_udp_tcp_fd(const ntx_proxy_udp *p);
void ntx_proxy_udp_free(ntx_proxy_udp *p);
void ntx_proxy_udp_stats(const ntx_proxy_udp *p, uint64_t *frag_drop);

int ntx_proxy_udp_encap(const ntx_addr *dst, uint16_t dst_port,
                        const uint8_t *data, size_t data_len, uint8_t *out,
                        size_t cap);
int ntx_proxy_udp_decap(const uint8_t *pkt, size_t n, ntx_addr *dst,
                        uint16_t *dst_port, const uint8_t **data,
                        size_t *data_len);
#endif
