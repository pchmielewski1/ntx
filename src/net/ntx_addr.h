#ifndef NTX_ADDR_H
#define NTX_ADDR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>

enum { NTX_AF_INET = 4, NTX_AF_INET6 = 6 };

typedef struct ntx_addr {
    uint8_t family; /* NTX_AF_INET | NTX_AF_INET6 */
    uint8_t _pad[3];
    union {
        uint32_t v4; /* network byte order */
        uint8_t v6[16]; /* network byte order */
    } u;
} ntx_addr;

void ntx_addr_clear(ntx_addr *a);
void ntx_addr_set_v4(ntx_addr *a, uint32_t ip_net);
void ntx_addr_set_v6(ntx_addr *a, const uint8_t v6[16]);
int ntx_addr_is_v4(const ntx_addr *a);
int ntx_addr_is_v6(const ntx_addr *a);
int ntx_addr_is_zero(const ntx_addr *a);
/* 1 for an address a remote party must not be able to steer us to: unspecified, loopback,
 * link-local (incl. the 169.254.169.254 cloud metadata address), multicast and reserved/broadcast,
 * for IPv4 and IPv6 (v4-mapped / v4-compatible forms are judged by the embedded IPv4 address).
 * RFC 1918 / ULA / CGNAT space is NOT special: LAN swarms are legitimate. */
int ntx_addr_is_special(const ntx_addr *a);
int ntx_addr_eq(const ntx_addr *x, const ntx_addr *y);
int ntx_addr_ntop(const ntx_addr *a, char *out, size_t cap);
int ntx_addr_from_sockaddr(ntx_addr *a, uint16_t *port_out,
                           const struct sockaddr_storage *ss);

#endif
