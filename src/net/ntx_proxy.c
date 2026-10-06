#include "ntx_proxy.h"
#include "ntx_sock.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif

#define PROXY_ST_GW_PENDING (-2)

static int proxy_send_all(int fd, const uint8_t *d, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t r = send(fd, d + off, n - off, MSG_NOSIGNAL);
        if (r < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) return -1;
            return -2;
        }
        off += (size_t)r;
    }
    return 0;
}

static int proxy_recv_more(ntx_proxy *p) {
    size_t space = sizeof p->buf - p->blen;
    if (space == 0) return -1;
    ssize_t r = recv(p->fd, p->buf + p->blen, space, 0);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    if (r == 0) return -1;
    p->blen += (size_t)r;
    return 1;
}

static int proxy_parse_ar(const ntx_proxy *p) {
    if (p->blen < 4) return 0;
    if (p->buf[0] != 0x05) return -1;
    if (p->buf[1] != 0x00) return -1;
    size_t bnd;
    switch (p->buf[3]) {
    case 0x01:
        bnd = 4;
        break;
    case 0x03:
        if (p->blen < 5) return 0;
        bnd = 1 + (size_t)p->buf[4];
        break;
    case 0x04:
        bnd = 16;
        break;
    default:
        return -1;
    }
    if (p->blen < 4 + bnd + 2) return 0;
    return 1;
}

void ntx_proxy_init(ntx_proxy *p, int fd, const ntx_addr *addr, uint16_t port, void *app_ctx,
                    void (*app_r)(int fd, void *ctx),
                    void (*app_w)(int fd, void *ctx),
                    void (*app_cl)(void *ctx)) {
    memset(p, 0, sizeof *p);
    p->fd = fd;
    p->addr = *addr;
    p->port = port;
    p->app_ctx = app_ctx;
    p->app_r = app_r;
    p->app_w = app_w;
    p->app_cl = app_cl;
    p->st = PROXY_ST_GW_PENDING;
}

int ntx_proxy_step(ntx_proxy *p, int readable) {
    if (p->st == -1) return -1;
    if (p->st == PROXY_ST_GW_PENDING) {
        uint8_t gw[3] = {0x05, 0x01, 0x00};
        int rc = proxy_send_all(p->fd, gw, 3);
        if (rc == -1) return 0;
        if (rc != 0) {
            p->st = -1;
            return -1;
        }
        p->st = 0;
    }
    if (p->st == 0) {
        if (!readable) return 0;
        int rc = proxy_recv_more(p);
        if (rc < 0) {
            p->st = -1;
            return -1;
        }
        if (rc == 0) return 0;
        if (p->blen < 2) return 0;
        if (p->buf[0] != 0x05 || p->buf[1] != 0x00) {
            p->st = -1;
            return -1;
        }
        p->blen = 0;
        p->st = 1;
    }
    if (p->st == 1) {
        uint8_t aq[22];
        size_t an;
        aq[0] = 0x05;
        aq[1] = 0x01;
        aq[2] = 0x00;
        if (ntx_addr_is_v6(&p->addr)) {
            aq[3] = 0x04;
            memcpy(aq + 4, p->addr.u.v6, 16);
            aq[20] = (uint8_t)(p->port >> 8);
            aq[21] = (uint8_t)(p->port & 0xFF);
            an = 22;
        } else {
            aq[3] = 0x01;
            memcpy(aq + 4, &p->addr.u.v4, 4);
            aq[8] = (uint8_t)(p->port >> 8);
            aq[9] = (uint8_t)(p->port & 0xFF);
            an = 10;
        }
        int rc = proxy_send_all(p->fd, aq, an);
        if (rc == -1) return 0;
        if (rc != 0) {
            p->st = -1;
            return -1;
        }
        p->st = 2;
        if (!readable) return 0;
    }
    if (p->st == 2) {
        if (!readable) return 0;
        int rc = proxy_recv_more(p);
        if (rc < 0) {
            p->st = -1;
            return -1;
        }
        if (rc == 0) return 0;
        int ok = proxy_parse_ar(p);
        if (ok < 0) {
            p->st = -1;
            return -1;
        }
        if (ok == 0) return 0;
        p->st = 3;
        return 1;
    }
    if (p->st == 3) return 1;
    return 0;
}

int ntx_proxy_done(const ntx_proxy *p) {
    return p->st == 3 ? 1 : 0;
}

uint16_t ntx_proxy_local_port(int fd) {
    return ntx_sock_local_port(fd);
}

int ntx_proxy_parse_spec(const char *spec, ntx_config *cfg, char *hostbuf, size_t hcap) {
    const char *p = spec;
    if (strncmp(p, "socks5:", 7) == 0) p += 7;
    size_t i = 0;
    while (*p && *p != ':' && i + 1 < hcap) hostbuf[i++] = *p++;
    hostbuf[i] = 0;
    if (*p != ':') return -1;
    p++;
    /* the port must be the whole remainder: "http:127.0.0.1:8080" used to parse as
       host "http", port 127 (trailing text ignored) and silently configure nonsense */
    char *pend = 0;
    long pr = strtol(p, &pend, 10);
    if (pend == p || *pend || pr <= 0 || pr > 65535) return -1;
    cfg->proxy = 1;
    cfg->socks5 = 1;
    cfg->proxy_host = hostbuf;
    cfg->proxy_port = (uint16_t)pr;
    return 0;
}

/* ---- RFC1928 §7 UDP ASSOCIATE -------------------------------------- */

#define PUDP_ST_FAIL (-1)
#define PUDP_ST_GW_PENDING (-2)
#define PUDP_ST_GW_REPLY 0
#define PUDP_ST_AQ_PENDING 1
#define PUDP_ST_AR_PENDING 2
#define PUDP_ST_READY 3

struct ntx_proxy_udp {
    int st;
    int fd;
    int udp_fd;
    uint8_t buf[512];
    size_t blen;
    ntx_addr dst;
    uint16_t dst_port;
    ntx_addr bnd;
    uint16_t bnd_port;
    uint64_t proxy_frag_drop;
    void *ctx;
    ntx_proxy_udp_ready_fn ready;
    ntx_proxy_udp_packet_fn packet;
    ntx_proxy_udp_closed_fn closed;
};

static void pudp_consume(ntx_proxy_udp *p, size_t n) {
    if (n >= p->blen) {
        p->blen = 0;
        return;
    }
    memmove(p->buf, p->buf + n, p->blen - n);
    p->blen -= n;
}

static int pudp_recv_more(ntx_proxy_udp *p) {
    size_t space = sizeof p->buf - p->blen;
    if (space == 0) return -1;
    ssize_t r = recv(p->fd, p->buf + p->blen, space, 0);
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    if (r == 0) return -1;
    p->blen += (size_t)r;
    return 1;
}

static int pudp_parse_ar(ntx_proxy_udp *p) {
    if (p->blen < 4) return 0;
    if (p->buf[0] != 0x05 || p->buf[1] != 0x00 || p->buf[2] != 0x00) return -1;
    size_t alen;
    switch (p->buf[3]) {
    case 0x01:
        alen = 4;
        break;
    case 0x04:
        alen = 16;
        break;
    default:
        return -1;
    }
    if (p->blen < 4 + alen + 2) return 0;
    memset(&p->bnd, 0, sizeof p->bnd);
    if (alen == 4) {
        p->bnd.family = NTX_AF_INET;
        memcpy(&p->bnd.u.v4, p->buf + 4, 4);
    } else {
        p->bnd.family = NTX_AF_INET6;
        memcpy(p->bnd.u.v6, p->buf + 4, 16);
    }
    p->bnd_port = (uint16_t)(((uint16_t)p->buf[4 + alen] << 8) |
                              p->buf[5 + alen]);
    pudp_consume(p, 4 + alen + 2);
    return 1;
}

static int pudp_sockaddr_eq_bnd(const struct sockaddr_storage *ss,
                                const ntx_addr *bnd, uint16_t port) {
    const struct sockaddr_in *sa = (const struct sockaddr_in *)ss;
    const struct sockaddr_in6 *sa6 = (const struct sockaddr_in6 *)ss;
    uint16_t sport;
    if (ntx_addr_is_v4(bnd)) {
        if (sa->sin_family != AF_INET) return 0;
        sport = ntohs(sa->sin_port);
        return sport == port && sa->sin_addr.s_addr == bnd->u.v4;
    }
    if (ntx_addr_is_v6(bnd)) {
        if (sa6->sin6_family != AF_INET6) return 0;
        sport = ntohs(sa6->sin6_port);
        return sport == port && memcmp(&sa6->sin6_addr, bnd->u.v6, 16) == 0;
    }
    return 0;
}

int ntx_proxy_udp_encap(const ntx_addr *dst, uint16_t dst_port,
                        const uint8_t *data, size_t data_len, uint8_t *out,
                        size_t cap) {
    if (!dst || !data || !out) return -1;
    int v6 = ntx_addr_is_v6(dst);
    if (!v6 && !ntx_addr_is_v4(dst)) return -1;
    size_t alen = v6 ? 16 : 4;
    size_t hdr = 4 + alen + 2;
    if (cap < hdr + data_len) return -1;
    memset(out, 0, hdr);
    out[3] = v6 ? 0x04 : 0x01;
    if (v6) {
        memcpy(out + 4, dst->u.v6, 16);
        out[20] = (uint8_t)(dst_port >> 8);
        out[21] = (uint8_t)(dst_port & 0xFF);
    } else {
        memcpy(out + 4, &dst->u.v4, 4);
        out[8] = (uint8_t)(dst_port >> 8);
        out[9] = (uint8_t)(dst_port & 0xFF);
    }
    if (data_len) memcpy(out + hdr, data, data_len);
    return (int)(hdr + data_len);
}

int ntx_proxy_udp_decap(const uint8_t *pkt, size_t n, ntx_addr *dst,
                         uint16_t *dst_port, const uint8_t **data,
                         size_t *data_len) {
    if (!pkt || !dst || !dst_port || !data || !data_len) return -1;
    if (n < 6) return -1;
    if (pkt[0] != 0x00 || pkt[1] != 0x00) return -1;
    if (pkt[2] != 0x00) return -1;
    size_t alen;
    if (pkt[3] == 0x01) alen = 4;
    else if (pkt[3] == 0x04) alen = 16;
    else return -1;
    size_t hdr = 4 + alen + 2;
    if (n < hdr) return -1;
    memset(dst, 0, sizeof *dst);
    if (alen == 4) {
        dst->family = NTX_AF_INET;
        memcpy(&dst->u.v4, pkt + 4, 4);
        *dst_port = (uint16_t)(((uint16_t)pkt[8] << 8) | pkt[9]);
    } else {
        dst->family = NTX_AF_INET6;
        memcpy(dst->u.v6, pkt + 4, 16);
        *dst_port = (uint16_t)(((uint16_t)pkt[20] << 8) | pkt[21]);
    }
    *data = pkt + hdr;
    *data_len = n - hdr;
    return 0;
}

ntx_proxy_udp *ntx_proxy_udp_associate(int tcp_fd, const ntx_addr *dst,
                                       uint16_t dst_port, void *ctx,
                                       ntx_proxy_udp_ready_fn ready,
                                       ntx_proxy_udp_packet_fn packet,
                                       ntx_proxy_udp_closed_fn closed) {
    if (tcp_fd < 0 || !dst || (!ntx_addr_is_v4(dst) && !ntx_addr_is_v6(dst)))
        return NULL;
    int udp_fd = ntx_sock_udp4();
    if (udp_fd < 0) return NULL;
    if (ntx_sock_bind0(udp_fd) == 0) {
        close(udp_fd);
        return NULL;
    }
    ntx_proxy_udp *p = calloc(1, sizeof *p);
    if (!p) {
        close(udp_fd);
        return NULL;
    }
    p->st = PUDP_ST_GW_PENDING;
    p->fd = tcp_fd;
    p->udp_fd = udp_fd;
    p->dst = *dst;
    p->dst_port = dst_port;
    p->ctx = ctx;
    p->ready = ready;
    p->packet = packet;
    p->closed = closed;
    return p;
}

int ntx_proxy_udp_step(ntx_proxy_udp *p, int readable) {
    if (!p || p->st == PUDP_ST_FAIL) return -1;
    if (p->st == PUDP_ST_READY) return 1;

    if (p->st == PUDP_ST_GW_PENDING) {
        uint8_t gw[3] = {0x05, 0x01, 0x00};
        int rc = proxy_send_all(p->fd, gw, sizeof gw);
        if (rc == -1) return 0;
        if (rc != 0) {
            p->st = PUDP_ST_FAIL;
            if (p->closed) p->closed(p->ctx);
            return -1;
        }
        p->st = PUDP_ST_GW_REPLY;
    }

    if (p->st == PUDP_ST_GW_REPLY) {
        if (!readable) return 0;
        int rc = pudp_recv_more(p);
        if (rc < 0) {
            p->st = PUDP_ST_FAIL;
            if (p->closed) p->closed(p->ctx);
            return -1;
        }
        if (rc == 0) return 0;
        if (p->blen < 2) return 0;
        if (p->buf[0] != 0x05 || p->buf[1] != 0x00) {
            p->st = PUDP_ST_FAIL;
            if (p->closed) p->closed(p->ctx);
            return -1;
        }
        pudp_consume(p, 2);
        p->st = PUDP_ST_AQ_PENDING;
    }

    if (p->st == PUDP_ST_AQ_PENDING) {
        uint8_t aq[22];
        size_t an;
        aq[0] = 0x05;
        aq[1] = 0x03;
        aq[2] = 0x00;
        if (ntx_addr_is_v6(&p->dst)) {
            aq[3] = 0x04;
            memcpy(aq + 4, p->dst.u.v6, 16);
            aq[20] = (uint8_t)(p->dst_port >> 8);
            aq[21] = (uint8_t)(p->dst_port & 0xFF);
            an = 22;
        } else {
            aq[3] = 0x01;
            memcpy(aq + 4, &p->dst.u.v4, 4);
            aq[8] = (uint8_t)(p->dst_port >> 8);
            aq[9] = (uint8_t)(p->dst_port & 0xFF);
            an = 10;
        }
        int rc = proxy_send_all(p->fd, aq, an);
        if (rc == -1) return 0;
        if (rc != 0) {
            p->st = PUDP_ST_FAIL;
            if (p->closed) p->closed(p->ctx);
            return -1;
        }
        p->st = PUDP_ST_AR_PENDING;
        if (!readable) return 0;
    }

    if (p->st == PUDP_ST_AR_PENDING) {
        if (!readable) return 0;
        int rc = pudp_recv_more(p);
        if (rc < 0) {
            p->st = PUDP_ST_FAIL;
            if (p->closed) p->closed(p->ctx);
            return -1;
        }
        if (rc == 0) return 0;
        int ok = pudp_parse_ar(p);
        if (ok < 0) {
            p->st = PUDP_ST_FAIL;
            if (p->closed) p->closed(p->ctx);
            return -1;
        }
        if (ok == 0) return 0;
        p->st = PUDP_ST_READY;
        if (p->ready) p->ready(p->ctx, &p->bnd, p->bnd_port);
        return 1;
    }

    return 0;
}

int ntx_proxy_udp_recv(ntx_proxy_udp *p) {
    if (!p || p->st != PUDP_ST_READY || p->udp_fd < 0) return 0;
    int delivered = 0;
    for (;;) {
        uint8_t buf[4096];
        struct sockaddr_storage from;
        socklen_t flen = sizeof from;
        ssize_t r = recvfrom(p->udp_fd, buf, sizeof buf, 0,
                             (struct sockaddr *)&from, &flen);
        if (r <= 0) break;
        if (!pudp_sockaddr_eq_bnd(&from, &p->bnd, p->bnd_port)) continue;
        if (r >= 3 && buf[2] != 0) {
            p->proxy_frag_drop++;
            continue;
        }
        ntx_addr dst;
        uint16_t dport = 0;
        const uint8_t *data = NULL;
        size_t dlen = 0;
        if (ntx_proxy_udp_decap(buf, (size_t)r, &dst, &dport, &data, &dlen) != 0)
            continue;
        if (p->packet && dlen > 0) {
            p->packet(p->ctx, &dst, dport, data, dlen);
            delivered++;
        }
    }
    return delivered;
}

int ntx_proxy_udp_done(const ntx_proxy_udp *p) {
    return p && p->st == PUDP_ST_READY;
}

int ntx_proxy_udp_send_datagram(ntx_proxy_udp *p, const ntx_addr *dst,
                                uint16_t dst_port, const uint8_t *data,
                                size_t data_len) {
    if (!p || p->st != PUDP_ST_READY || p->udp_fd < 0) return -1;
    uint8_t buf[4096];
    int n = ntx_proxy_udp_encap(dst, dst_port, data, data_len, buf, sizeof buf);
    if (n < 0) return -1;
    struct sockaddr_storage to;
    memset(&to, 0, sizeof to);
    if (ntx_addr_is_v6(&p->bnd)) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)&to;
        sa6->sin6_family = AF_INET6;
        memcpy(&sa6->sin6_addr, p->bnd.u.v6, 16);
        sa6->sin6_port = htons(p->bnd_port);
    } else {
        struct sockaddr_in *sa = (struct sockaddr_in *)&to;
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = p->bnd.u.v4;
        sa->sin_port = htons(p->bnd_port);
    }
    ssize_t r = sendto(p->udp_fd, buf, (size_t)n, MSG_NOSIGNAL,
                       (const struct sockaddr *)&to,
                       ntx_addr_is_v6(&p->bnd) ? sizeof(struct sockaddr_in6)
                                               : sizeof(struct sockaddr_in));
    if (r < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) return 0;
        return -1;
    }
    return 0;
}

int ntx_proxy_udp_fd(const ntx_proxy_udp *p) {
    return p ? p->udp_fd : -1;
}

int ntx_proxy_udp_tcp_fd(const ntx_proxy_udp *p) {
    return p ? p->fd : -1;
}

void ntx_proxy_udp_free(ntx_proxy_udp *p) {
    if (!p) return;
    if (p->fd >= 0) close(p->fd);
    if (p->udp_fd >= 0) close(p->udp_fd);
    free(p);
}

void ntx_proxy_udp_stats(const ntx_proxy_udp *p, uint64_t *frag_drop) {
    if (!p) return;
    if (frag_drop) *frag_drop = p->proxy_frag_drop;
}
