#include "ntx_sock.h"
#include "../proto/ntx_doh.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

/*
 * Weak stub so unit tests that #include ntx_sock.c without DoH/TLS still link.
 * Full binary + tests that include ntx_doh.c get the strong DoH implementation.
 */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int ntx_doh_lookup_a(const char *host, uint32_t *ip_out) {
    if (!host || !ip_out) return -1;
    unsigned a = 0, b = 0, c = 0, d = 0;
    if (sscanf(host, "%u.%u.%u.%u", &a, &b, &c, &d) != 4 ||
        a > 255u || b > 255u || c > 255u || d > 255u)
        return -1;
    uint8_t oct[4] = { (uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d };
    memcpy(ip_out, oct, 4);
    return 0;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
int ntx_doh_lookup_aaaa(const char *host, uint8_t out[16]) {
    (void)host;
    (void)out;
    return -1;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak)) unsigned ntx_doh_ok;
__attribute__((weak)) unsigned ntx_doh_fail;
__attribute__((weak)) unsigned ntx_doh_mitm_fail;
__attribute__((weak))
#endif
void ntx_doh_status(char *tag_out, size_t tag_cap, int *busy_out) {
    if (tag_out && tag_cap > 0) tag_out[0] = 0;
    if (busy_out) *busy_out = 0;
}

#if defined(__GNUC__) || defined(__clang__)
__attribute__((weak))
#endif
void ntx_doh_set_ui_kick(void (*fn)(void)) {
    (void)fn;
}

int ntx_sock_tcp4(void) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    return fd;
}

int ntx_sock_tcp6(void) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    return fd;
}

int ntx_sock_udp4(void) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    return fd;
}

int ntx_sock_udp6(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) < 0) {
        close(fd);
        return -1;
    }
    return fd;
}

uint16_t ntx_sock_local_port(int fd) {
    struct sockaddr_in sa;
    socklen_t len = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &len) < 0) return 0;
    return ntohs(sa.sin_port);
}

uint16_t ntx_sock_bind0(int fd) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = 0;
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) return 0;
    return ntx_sock_local_port(fd);
}

uint16_t ntx_sock_bind_range(int fd, uint16_t lo, uint16_t hi) {
    if (lo == 0 && hi == 0) return ntx_sock_bind0(fd);
    if (hi < lo) {
        uint16_t t = lo;
        lo = hi;
        hi = t;
    }
    if (lo == 0) lo = 1;
    for (uint32_t p = lo; p <= (uint32_t)hi; p++) {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons((uint16_t)p);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0)
            return ntx_sock_local_port(fd);
    }
    return ntx_sock_bind0(fd);
}

uint16_t ntx_sock_local_port6(int fd) {
    struct sockaddr_in6 sa;
    socklen_t len = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &len) < 0) return 0;
    return ntohs(sa.sin6_port);
}

uint16_t ntx_sock_bind6(int fd, uint16_t port) {
    int one = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_any;
    sa.sin6_port = htons(port);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) return 0;
    return ntx_sock_local_port6(fd);
}

uint16_t ntx_sock_bind_range6(int fd, uint16_t lo, uint16_t hi) {
    if (lo == 0 && hi == 0) return ntx_sock_bind6(fd, 0);
    if (hi < lo) {
        uint16_t t = lo;
        lo = hi;
        hi = t;
    }
    if (lo == 0) lo = 1;
    int one = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    for (uint32_t p = lo; p <= (uint32_t)hi; p++) {
        struct sockaddr_in6 sa;
        memset(&sa, 0, sizeof sa);
        sa.sin6_family = AF_INET6;
        sa.sin6_addr = in6addr_any;
        sa.sin6_port = htons((uint16_t)p);
        if (bind(fd, (struct sockaddr *)&sa, sizeof sa) == 0)
            return ntx_sock_local_port6(fd);
    }
    return ntx_sock_bind6(fd, 0);
}

int ntx_sock_listen(int fd, int backlog) {
    return listen(fd, backlog);
}

int ntx_sock_accept4(int listen_fd) {
    int fd = accept(listen_fd, NULL, NULL);
    if (fd < 0) return -1;
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0) fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

int ntx_sock_connect_addr(int fd, const ntx_addr *addr, uint16_t port) {
    if (!addr) return -1;
    if (addr->family == NTX_AF_INET) {
        if (addr->u.v4 == 0) return -1; /* unspecified */
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = addr->u.v4;
        sa.sin_port = htons(port);
        int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
        if (rc < 0 && errno != EINPROGRESS) return -1;
        return 0;
    }
    if (addr->family == NTX_AF_INET6) {
        int any = 0;
        for (int i = 0; i < 16; i++)
            if (addr->u.v6[i]) {
                any = 1;
                break;
            }
        if (!any) return -1; /* unspecified */
        struct sockaddr_in6 sa6;
        memset(&sa6, 0, sizeof sa6);
        sa6.sin6_family = AF_INET6;
        memcpy(&sa6.sin6_addr, addr->u.v6, 16);
        sa6.sin6_port = htons(port);
        int rc = connect(fd, (struct sockaddr *)&sa6, sizeof sa6);
        if (rc < 0 && errno != EINPROGRESS) return -1;
        return 0;
    }
    return -1;
}

int ntx_sock_connect4(int fd, uint32_t ip_net, uint16_t port) {
    ntx_addr a;
    memset(&a, 0, sizeof a);
    a.family = NTX_AF_INET;
    a.u.v4 = ip_net;
    return ntx_sock_connect_addr(fd, &a, port);
}

int ntx_sock_resolve(const char *host, ntx_addr *out) {
    if (!host || !out) return -1;
    memset(out, 0, sizeof *out);
    unsigned a = 0, b = 0, c = 0, d = 0;
    int consumed = 0;
    if (sscanf(host, "%u.%u.%u.%u%n", &a, &b, &c, &d, &consumed) == 4 &&
        a <= 255u && b <= 255u && c <= 255u && d <= 255u &&
        (size_t)consumed == strlen(host)) {
        out->family = NTX_AF_INET;
        out->u.v4 = htonl((a << 24) | (b << 16) | (c << 8) | d);
        return 0;
    }
    if (strchr(host, ':')) {
        const char *s = host;
        if (*s == '[') {
            const char *close = strchr(s + 1, ']');
            if (!close) return -1;
            uint8_t v6[16];
            char tmp[40];
            size_t n = (size_t)(close - (s + 1));
            if (n >= sizeof tmp) return -1;
            memcpy(tmp, s + 1, n);
            tmp[n] = 0;
            if (inet_pton(AF_INET6, tmp, v6) != 1) return -1;
            out->family = NTX_AF_INET6;
            memcpy(out->u.v6, v6, 16);
            return 0;
        }
        if (inet_pton(AF_INET6, s, out->u.v6) == 1) {
            out->family = NTX_AF_INET6;
            return 0;
        }
        return -1;
    }
    uint8_t v6[16];
    if (ntx_doh_lookup_aaaa(host, v6) == 0) {
        out->family = NTX_AF_INET6;
        memcpy(out->u.v6, v6, 16);
        return 0;
    }
    uint32_t v4;
    if (ntx_doh_lookup_a(host, &v4) == 0) {
        out->family = NTX_AF_INET;
        out->u.v4 = v4;
        return 0;
    }
    return -1;
}

int ntx_sock_resolve4(const char *host, uint32_t *ip_out) {
    /* CRITICAL: do not call ntx_sock_resolve (AAAA-first). UDP trackers / old
       code paths need IPv4; a host with an AAAA record (explodie.org etc.) used to get v6 and
       resolve4 failed with (dns) even though an A record exists. */
    if (!host || !ip_out) return -1;
    unsigned a = 0, b = 0, c = 0, d = 0;
    int consumed = 0;
    if (sscanf(host, "%u.%u.%u.%u%n", &a, &b, &c, &d, &consumed) == 4 &&
        a <= 255u && b <= 255u && c <= 255u && d <= 255u &&
        (size_t)consumed == strlen(host)) {
        *ip_out = htonl((a << 24) | (b << 16) | (c << 8) | d);
        return (*ip_out != 0) ? 0 : -1;
    }
    if (strchr(host, ':')) return -1; /* v6 literal — not v4 */
    return ntx_doh_lookup_a(host, ip_out);
}

int ntx_sock_tcp_connect_host(const char *host, uint16_t port) {
    uint32_t ip = 0;
    if (ntx_sock_resolve4(host, &ip) != 0) return -1;
    int fd = ntx_sock_tcp4();
    if (fd < 0) return -1;
    if (ntx_sock_connect4(fd, ip, port) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

int ntx_sock_parse_host_port(const char *spec, char *hostbuf, size_t hcap,
                             const char **host_out, uint16_t *port_out) {
    size_t i = 0;
    const char *p = spec;
    while (*p && *p != ':' && i + 1 < hcap) hostbuf[i++] = *p++;
    hostbuf[i] = 0;
    if (*p != ':') return -1;
    p++;
    char *pend = 0; /* the port must be the whole remainder (no trailing text) */
    long pr = strtol(p, &pend, 10);
    if (pend == p || *pend || pr <= 0 || pr > 65535) return -1;
    *host_out = hostbuf;
    *port_out = (uint16_t)pr;
    return 0;
}
