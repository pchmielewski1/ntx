#include "ntx_tunnel.h"
#include "ntx_sock.h"
#include "../crypto/ntx_aes.h"
#include "../crypto/ntx_hmac.h"
#include "../crypto/ntx_rng.h"
#include "../crypto/ntx_sha1.h"
#include "../proto/ntx_wire.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <unistd.h>

#define TNL_VIRT_MAX 64
#define TNL_FRAME_MAX 16384
#define TNL_CMD_OPEN 1
#define TNL_CMD_OPEN_OK 2
#define TNL_CMD_OPEN_V6 3

typedef struct {
    int used;
    uint16_t sid;
    void *ctx;
    ntx_cbs cbs;
    uint8_t rbuf[TNL_FRAME_MAX];
    size_t rlen;
    int connect_done;
} tnl_virt;

struct ntx_tunnel {
    ntx_netx *netx;
    int fd;
    int state;
    uint8_t hs_out[32];
    size_t hs_sent;
    uint8_t hs_in[32];
    size_t hs_inn;
    uint8_t mac_key[20];
    ntx_aes128_ctr tx_ctr;
    ntx_aes128_ctr rx_ctr;
    uint8_t frame_buf[TNL_FRAME_MAX + 22];
    size_t frame_len;
    uint16_t frame_need;
    tnl_virt virt[TNL_VIRT_MAX];
    uint16_t next_sid;
};

static int tnl_hmac_ok(const ntx_tunnel *t, const uint8_t *len2, const uint8_t *payload, size_t n,
                       const uint8_t *mac) {
    uint8_t tmp[22 + TNL_FRAME_MAX];
    if (n + 2 > sizeof tmp) return 0;
    memcpy(tmp, len2, 2);
    memcpy(tmp + 2, payload, n);
    uint8_t exp[20];
    ntx_hmac_sha1(t->mac_key, 20, tmp, n + 2, exp);
    uint8_t diff = 0;
    for (int i = 0; i < 20; i++) diff |= (uint8_t)(exp[i] ^ mac[i]);
    return diff == 0;
}

static int tnl_send_frame(ntx_tunnel *t, uint16_t sid, const uint8_t *data, size_t n) {
    if (n + 4 > TNL_FRAME_MAX || t->fd < 0) return -1;
    uint8_t payload[TNL_FRAME_MAX];
    ntx_wire_wr16(payload, sid);
    if (n) memcpy(payload + 2, data, n);
    size_t plen = 2 + n;
    uint8_t len2[2];
    ntx_wire_wr16(len2, (uint16_t)plen);
    ntx_aes128_ctr_xcrypt(&t->tx_ctr, payload, plen);
    uint8_t mac[20];
    uint8_t hm[2 + TNL_FRAME_MAX];
    memcpy(hm, len2, 2);
    memcpy(hm + 2, payload, plen);
    ntx_hmac_sha1(t->mac_key, 20, hm, plen + 2, mac);
    uint8_t wire[2 + TNL_FRAME_MAX + 20];
    memcpy(wire, len2, 2);
    memcpy(wire + 2, payload, plen);
    memcpy(wire + 2 + plen, mac, 20);
    size_t total = 2 + plen + 20;
    size_t off = 0;
    while (off < total) {
        ssize_t w = write(t->fd, wire + off, total - off);
        if (w < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        off += (size_t)w;
    }
    return 0;
}

static tnl_virt *tnl_virt_get(ntx_tunnel *t, uint16_t sid) {
    for (int i = 0; i < TNL_VIRT_MAX; i++)
        if (t->virt[i].used && t->virt[i].sid == sid) return &t->virt[i];
    return NULL;
}

static tnl_virt *tnl_virt_alloc(ntx_tunnel *t, uint16_t sid) {
    for (int i = 0; i < TNL_VIRT_MAX; i++) {
        if (!t->virt[i].used) {
            memset(&t->virt[i], 0, sizeof t->virt[i]);
            t->virt[i].used = 1;
            t->virt[i].sid = sid;
            return &t->virt[i];
        }
    }
    return NULL;
}

static void tnl_virt_del(ntx_tunnel *t, tnl_virt *v) {
    if (v->cbs.cl) v->cbs.cl(v->ctx);
    memset(v, 0, sizeof *v);
    (void)t;
}

static void tnl_dispatch(ntx_tunnel *t, uint16_t sid, const uint8_t *data, size_t n) {
    if (sid == 0 && n >= 1) {
        if (data[0] == TNL_CMD_OPEN_OK && n >= 3) {
            uint16_t nsid = ntx_wire_rd16(data + 1);
            tnl_virt *v = tnl_virt_get(t, 0);
            if (v && !v->connect_done) {
                tnl_virt *nv = tnl_virt_alloc(t, nsid);
                if (nv) {
                    nv->ctx = v->ctx;
                    nv->cbs = v->cbs;
                    nv->connect_done = 1;
                    if (nv->cbs.w) nv->cbs.w(-nsid, nv->ctx);
                }
                tnl_virt_del(t, v);
            }
            return;
        }
    }
    tnl_virt *v = tnl_virt_get(t, sid);
    if (!v) return;
    if (v->rlen + n > TNL_FRAME_MAX) n = TNL_FRAME_MAX - v->rlen;
    memcpy(v->rbuf + v->rlen, data, n);
    v->rlen += n;
    if (v->cbs.r) v->cbs.r(-(int)sid, v->ctx);
}

static void tnl_on_frame(ntx_tunnel *t) {
    uint16_t plen = ntx_wire_rd16(t->frame_buf);
    if (plen > TNL_FRAME_MAX) {
        t->frame_len = 0;
        t->frame_need = 0;
        return;
    }
    size_t total = 2 + (size_t)plen + 20;
    if (t->frame_len < total) return;
    uint8_t *payload = t->frame_buf + 2;
    const uint8_t *mac = t->frame_buf + 2 + plen;
    if (!tnl_hmac_ok(t, t->frame_buf, payload, plen, mac)) {
        t->frame_len = 0;
        t->frame_need = 0;
        return;
    }
    ntx_aes128_ctr_xcrypt(&t->rx_ctr, payload, plen);
    if (plen >= 2) tnl_dispatch(t, ntx_wire_rd16(payload), payload + 2, plen - 2);
    t->frame_len = 0;
    t->frame_need = 0;
}

static void tnl_io(int fd, void *ctx) {
    ntx_tunnel *t = ctx;
    if (t->state < 3) {
        if (t->hs_sent < 32) {
            ssize_t w = write(fd, t->hs_out + t->hs_sent, 32 - t->hs_sent);
            if (w > 0) t->hs_sent += (size_t)w;
        }
        uint8_t tmp[64];
        ssize_t r = read(fd, tmp, sizeof tmp);
        if (r > 0) {
            size_t cp = (size_t)r;
            if (t->hs_inn + cp > 32) cp = 32 - t->hs_inn;
            memcpy(t->hs_in + t->hs_inn, tmp, cp);
            t->hs_inn += cp;
        } else if (r == 0) {
            ntx_netx_del(t->netx, fd);
            close(fd);
            t->fd = -1;
            return;
        }
        if (t->hs_sent >= 32 && t->hs_inn >= 32) {
            if (memcmp(t->hs_in, "NTX1", 4) != 0) {
                ntx_netx_del(t->netx, fd);
                close(fd);
                t->fd = -1;
                return;
            }
            uint8_t mk[36];
            memcpy(mk, t->hs_out + 4, 16);
            memcpy(mk + 16, t->hs_in + 4, 16);
            memcpy(mk + 32, t->hs_out + 20, 4);
            ntx_sha1(mk, 36, t->mac_key);
            uint8_t ctr_c[16], ctr_s[16];
            memset(ctr_c, 0, sizeof ctr_c);
            memset(ctr_s, 0, sizeof ctr_s);
            memcpy(ctr_c, t->hs_out + 20, 12);
            memcpy(ctr_s, t->hs_in + 20, 12);
            ntx_aes128_ctr_init(&t->tx_ctr, t->hs_out + 4, ctr_c);
            ntx_aes128_ctr_init(&t->rx_ctr, t->hs_in + 4, ctr_s);
            t->state = 3;
        }
        return;
    }
    for (;;) {
        if (t->frame_need == 0) {
            ssize_t r = read(fd, t->frame_buf + t->frame_len, 2 - t->frame_len);
            if (r <= 0) break;
            t->frame_len += (size_t)r;
            if (t->frame_len < 2) break;
            t->frame_need = ntx_wire_rd16(t->frame_buf);
            if (t->frame_need > TNL_FRAME_MAX) {
                t->frame_len = 0;
                t->frame_need = 0;
                break;
            }
        }
        size_t want = 2 + (size_t)t->frame_need + 20;
        if (t->frame_len < want) {
            ssize_t r = read(fd, t->frame_buf + t->frame_len, want - t->frame_len);
            if (r <= 0) break;
            t->frame_len += (size_t)r;
        }
        if (t->frame_len >= want) tnl_on_frame(t);
        else break;
    }
}

static void tnl_close(void *ctx) {
    ntx_tunnel *t = ctx;
    if (t->fd >= 0) {
        close(t->fd);
        t->fd = -1;
    }
    for (int i = 0; i < TNL_VIRT_MAX; i++)
        if (t->virt[i].used) tnl_virt_del(t, &t->virt[i]);
}

ntx_tunnel *ntx_tunnel_connect(ntx_netx *netx, const char *host, uint16_t port) {
    int fd = ntx_sock_tcp_connect_host(host, port);
    if (fd < 0) return NULL;
    ntx_tunnel *t = calloc(1, sizeof *t);
    if (!t) {
        close(fd);
        return NULL;
    }
    t->netx = netx;
    t->fd = fd;
    t->next_sid = 1;
    memcpy(t->hs_out, "NTX1", 4);
    ntx_rand_bytes(t->hs_out + 4, 28);
    ntx_cbs cbs = {tnl_io, tnl_io, tnl_close};
    ntx_netx_add(netx, fd, EPOLLIN | EPOLLOUT, t, &cbs);
    return t;
}

void ntx_tunnel_free(ntx_tunnel *t) {
    if (!t) return;
    if (t->fd >= 0) {
        ntx_netx_del(t->netx, t->fd);
        close(t->fd);
    }
    for (int i = 0; i < TNL_VIRT_MAX; i++)
        if (t->virt[i].used) tnl_virt_del(t, &t->virt[i]);
    free(t);
}

static size_t tnl_open_req(const ntx_addr *addr, uint16_t port, uint8_t *out, size_t cap) {
    if (ntx_addr_is_v6(addr)) {
        if (cap < 19) return 0;
        out[0] = TNL_CMD_OPEN_V6;
        memcpy(out + 1, addr->u.v6, 16);
        out[17] = (uint8_t)(port >> 8);
        out[18] = (uint8_t)(port & 0xFF);
        return 19;
    }
    if (cap < 7) return 0;
    out[0] = TNL_CMD_OPEN;
    memcpy(out + 1, &addr->u.v4, 4);
    out[5] = (uint8_t)(port >> 8);
    out[6] = (uint8_t)(port & 0xFF);
    return 7;
}

int ntx_tunnel_route_connect(ntx_tunnel *t, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs) {
    if (!t || !addr || t->state < 3) return -1;
    tnl_virt *v = tnl_virt_alloc(t, 0);
    if (!v) return -1;
    v->ctx = ctx;
    v->cbs = *cbs;
    uint8_t req[19];
    size_t n = tnl_open_req(addr, port, req, sizeof req);
    if (n == 0) {
        tnl_virt_del(t, v);
        return -1;
    }
    if (tnl_send_frame(t, 0, req, n) != 0) {
        tnl_virt_del(t, v);
        return -1;
    }
    return -(int)(t->next_sid++);
}

int ntx_tunnel_ready(const ntx_tunnel *t) {
    return t && t->state >= 3;
}

int ntx_tunnel_virt_connected(ntx_tunnel *t, int virt_fd) {
    if (!t || virt_fd >= 0) return 0;
    tnl_virt *v = tnl_virt_get(t, (uint16_t)(-virt_fd));
    return v && v->connect_done;
}

ssize_t ntx_tunnel_virt_read(ntx_tunnel *t, int virt_fd, uint8_t *buf, size_t cap) {
    if (!t || virt_fd >= 0) return -1;
    tnl_virt *v = tnl_virt_get(t, (uint16_t)(-virt_fd));
    if (!v || !v->connect_done) return -1;
    size_t n = v->rlen;
    if (n > cap) n = cap;
    if (n) {
        memcpy(buf, v->rbuf, n);
        memmove(v->rbuf, v->rbuf + n, v->rlen - n);
        v->rlen -= n;
    }
    return (ssize_t)n;
}

int ntx_tunnel_virt_write(ntx_tunnel *t, int virt_fd, const uint8_t *buf, size_t n) {
    if (!t || virt_fd >= 0) return -1;
    return tnl_send_frame(t, (uint16_t)(-virt_fd), buf, n);
}
