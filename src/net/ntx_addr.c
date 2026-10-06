#include "ntx_addr.h"

#include <arpa/inet.h>
#include <string.h>

void ntx_addr_clear(ntx_addr *a) { memset(a, 0, sizeof *a); }

void ntx_addr_set_v4(ntx_addr *a, uint32_t ip_net) {
    ntx_addr_clear(a);
    a->family = NTX_AF_INET;
    a->u.v4 = ip_net;
}

void ntx_addr_set_v6(ntx_addr *a, const uint8_t v6[16]) {
    ntx_addr_clear(a);
    a->family = NTX_AF_INET6;
    memcpy(a->u.v6, v6, 16);
}

int ntx_addr_is_v4(const ntx_addr *a) { return a->family == NTX_AF_INET; }

int ntx_addr_is_v6(const ntx_addr *a) { return a->family == NTX_AF_INET6; }

int ntx_addr_is_zero(const ntx_addr *a) {
    if (a->family == NTX_AF_INET) return a->u.v4 == 0;
    for (int i = 0; i < 16; i++)
        if (a->u.v6[i]) return 0;
    return 1;
}

static int v4_special(uint32_t ip_net) {
    uint32_t h = ntohl(ip_net);
    uint32_t top = h >> 24;
    if (top == 0 || top == 127) return 1;      /* "this network", loopback */
    if ((h >> 16) == 0xA9FEu) return 1;        /* 169.254/16 link-local + metadata */
    if (top >= 224) return 1;                  /* multicast, reserved, broadcast */
    return 0;
}

int ntx_addr_is_special(const ntx_addr *a) {
    if (a->family == NTX_AF_INET) return v4_special(a->u.v4);
    if (a->family != NTX_AF_INET6) return 1;
    const uint8_t *p = a->u.v6;
    int z10 = 1;
    for (int i = 0; i < 10; i++)
        if (p[i]) z10 = 0;
    if (z10 && p[10] == 0xff && p[11] == 0xff) {          /* ::ffff:a.b.c.d */
        uint32_t v4;
        memcpy(&v4, p + 12, 4);
        return v4_special(v4);
    }
    int z12 = z10 && p[10] == 0 && p[11] == 0;
    if (z12) {                                            /* ::, ::1, ::a.b.c.d (v4-compatible) */
        uint32_t v4;
        memcpy(&v4, p + 12, 4);
        return v4 == 0 || v4_special(v4) || ntohl(v4) == 1;
    }
    if (p[0] == 0xff) return 1;                           /* multicast */
    if (p[0] == 0xfe && (p[1] & 0xc0) == 0x80) return 1;  /* fe80::/10 link-local */
    return 0;
}

int ntx_addr_eq(const ntx_addr *x, const ntx_addr *y) {
    if (x->family != y->family) return 0;
    if (x->family == NTX_AF_INET) return x->u.v4 == y->u.v4;
    return memcmp(x->u.v6, y->u.v6, 16) == 0;
}

int ntx_addr_ntop(const ntx_addr *a, char *out, size_t cap) {
    if (a->family == NTX_AF_INET)
        return inet_ntop(AF_INET, &a->u.v4, out, (socklen_t)cap) != NULL ? 0 : -1;
    if (a->family == NTX_AF_INET6)
        return inet_ntop(AF_INET6, a->u.v6, out, (socklen_t)cap) != NULL ? 0 : -1;
    return -1;
}

int ntx_addr_from_sockaddr(ntx_addr *a, uint16_t *port_out,
                           const struct sockaddr_storage *ss) {
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *in4 = (const struct sockaddr_in *)ss;
        ntx_addr_set_v4(a, in4->sin_addr.s_addr);
        if (port_out) *port_out = ntohs(in4->sin_port);
        return 0;
    }
    if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *in6 = (const struct sockaddr_in6 *)ss;
        const uint8_t *p = in6->sin6_addr.s6_addr;
        int mapped = p[10] == 0xff && p[11] == 0xff;
        for (int i = 0; i < 10 && mapped; i++)
            if (p[i]) mapped = 0;
        if (mapped) {
            ntx_addr_set_v4(a, ((uint32_t)p[12] << 24) | ((uint32_t)p[13] << 16) |
                               ((uint32_t)p[14] << 8) | (uint32_t)p[15]);
        } else {
            ntx_addr_set_v6(a, p);
        }
        if (port_out) *port_out = ntohs(in6->sin6_port);
        return 0;
    }
    return -1;
}
