#ifndef NTX_TUNNEL_H
#define NTX_TUNNEL_H

#include <stdint.h>
#include <stddef.h>
#include "ntx_netx.h"
#include "ntx_addr.h"

typedef struct ntx_tunnel ntx_tunnel;

ntx_tunnel *ntx_tunnel_connect(ntx_netx *netx, const char *host, uint16_t port);
void ntx_tunnel_free(ntx_tunnel *t);
int ntx_tunnel_ready(const ntx_tunnel *t);
int ntx_tunnel_route_connect(ntx_tunnel *t, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs);
ssize_t ntx_tunnel_virt_read(ntx_tunnel *t, int virt_fd, uint8_t *buf, size_t cap);
int ntx_tunnel_virt_write(ntx_tunnel *t, int virt_fd, const uint8_t *buf, size_t n);
int ntx_tunnel_virt_connected(ntx_tunnel *t, int virt_fd);

#endif
