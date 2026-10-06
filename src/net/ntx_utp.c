#include "ntx_utp.h"
#include "ntx_proxy.h"
#include "ntx_sock.h"
#include "../crypto/ntx_rng.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* BEP29 netx glue: one shared UDP socket, demuxed by (peer addr+port,
 * conn_id) into per-connection slots. Each slot owns a virt fd
 * (-(NTX_UTP_VIRT_BASE + index)) that behaves like the NTX1 tunnel virt fds
 * (fd < 0). The state machine itself lives in ntx_utp_sm.c; this file only
 * wires it to the netx event loop and the UDP socket.
 *
 * All glue statics use the utp_glue_ prefix to avoid clashing with the SM's
 * statics when a test TU includes both .c files. */

/* 64 KB receive buffer per connection slot. */
#define UTP_RB 65536u

typedef struct {
    struct ntx_utp *u; /* back-pointer */
    ntx_utp_conn *conn; /* opaque SM instance (NULL until allocated) */
    struct sockaddr_storage peer;
    socklen_t peer_len;
    ntx_addr peer_addr; /* for ops->peer */
    uint16_t peer_port; /* host order, for ops->peer_port */
    ntx_utp_conn_ops ops; /* SM ops — must outlive the conn (SM holds a pointer) */
    void *ctx; /* app ctx (route_connect) */
    ntx_cbs cbs; /* app cbs (route_connect) */
    int used;
    int inbound; /* 1 = accept path (fires accept_cb); 0 = outbound */
    int accept_fired;
    int connect_done; /* outbound: SM reached CONNECTED (cbs.w fired once) */
    int close_fired; /* cbs.cl fired exactly once (remote drop / explicit teardown) */
    int closed;
    uint8_t *rbuf;
    size_t rbuf_len;
    size_t rbuf_off;
    ntx_proxy_udp *px; /* SOCKS5 UDP associate transport (NULL = direct) */
} utp_glue_slot;

struct ntx_utp {
    ntx_netx *netx;
    int fd; /* AF_INET datagram socket (primary; the shared v4 owner) */
    uint16_t port;
    int shared; /* fd is the netx-owned shared socket: do not close, no own epoll reg */
    /* IPv6 sibling. AF_INET6 socket carrying every v6 peer: in
     * shared mode it is the netx-owned single-port owner (shared6 => do not
     * close, netx already polls it), standalone mode we own it and register
     * EPOLLIN ourselves. -1 = no v6 in this environment; v6 dials then fail
     * cleanly and route_connect falls through to raw TCP. */
    int fd6;
    uint16_t port6;
    int shared6;
    ntx_cb_accept accept_cb;
    void *accept_ctx;
    utp_glue_slot slots[NTX_UTP_MAX_CONNS];
};

/* ---- SM ops (ctx = utp_glue_slot*) ---- */

static void utp_glue_kick_close(utp_glue_slot *s);

static uint64_t utp_glue_clock(void *ctx) {
    (void)ctx;
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint64_t us = (uint64_t)ts.tv_sec * 1000000ULL + (uint64_t)ts.tv_nsec / 1000ULL;
    return (uint32_t)us; /* 32-bit wrap is correct per uTP (BEP29) */
}

static void utp_glue_tx(const uint8_t *pkt, size_t n, void *ctx) {
    utp_glue_slot *s = ctx;
    if (s->px) {
        /* SOCKS5 associate path: while the TCP ASSOCIATE is still pending the
         * SM has not been initiated, so this branch normally only runs once the
         * relay BND address is known. */
        if (ntx_proxy_udp_done(s->px))
            ntx_proxy_udp_send_datagram(s->px, &s->peer_addr, s->peer_port, pkt,
                                      n);
        return;
    }
    /* Family-selective send: the slot's peer sockaddr carries its own
     * family, and a socket may only sendto a same-family destination. v4 peers
     * keep using the primary socket, v6 peers the AF_INET6 sibling; a missing
     * sibling (no IPv6 here) drops the packet the same way a dead socket did —
     * the SM's retransmit timer then drives the connection to its timeout. */
    const struct sockaddr *sa = (const struct sockaddr *)&s->peer;
    int fd = (sa->sa_family == AF_INET6) ? s->u->fd6 : s->u->fd;
    if (fd < 0) return;
    sendto(fd, pkt, n, 0, sa, s->peer_len);
}

static void utp_glue_rx(const uint8_t *data, size_t n, void *ctx) {
    utp_glue_slot *s = ctx;
    /* Compact: move the unread bytes to the front so we can append linearly. */
    if (s->rbuf_off > 0) {
        size_t rem = s->rbuf_len - s->rbuf_off;
        memmove(s->rbuf, s->rbuf + s->rbuf_off, rem);
        s->rbuf_len = rem;
        s->rbuf_off = 0;
    }
    /* Overflow policy: drop the tail of the incoming payload (keep the oldest
     * bytes already buffered). A full 64 KB window means the reader is not
     * keeping up; dropping the newest bytes bounds memory and preserves order. */
    size_t space = UTP_RB - s->rbuf_len;
    if (n > space) n = space;
    if (n) {
        memcpy(s->rbuf + s->rbuf_len, data, n);
        s->rbuf_len += n;
    }
}

static void utp_glue_on_timer(void *arg) {
    utp_glue_slot *s = arg;
    if (s->used && s->conn) ntx_utp_conn_on_timer(s->conn);
}

static void utp_glue_timer(uint32_t delay_ms, void *ctx) {
    utp_glue_slot *s = ctx;
    ntx_netx_timer(s->u->netx, delay_ms, utp_glue_on_timer, s);
}

static void utp_glue_closed(void *ctx) {
    utp_glue_slot *s = ctx;
    s->closed = 1; /* slot stays until drained or ntx_utp_free */
    /* Remote teardown (FIN drained / RESET / timeout): tell the owning session so
     * it drops the peer. ntx_utp_free tears down without a session attached, so
     * guard on the callback being present. */
    if (s->cbs.cl) utp_glue_kick_close(s);
}

/* ---- helpers ---- */

static int utp_glue_peer_match(const struct sockaddr_storage *a,
                               const struct sockaddr_storage *b) {
    const struct sockaddr_in *ia = (const struct sockaddr_in *)a;
    const struct sockaddr_in *ib = (const struct sockaddr_in *)b;
    if (ia->sin_family == AF_INET && ib->sin_family == AF_INET)
        return ia->sin_addr.s_addr == ib->sin_addr.s_addr &&
               ia->sin_port == ib->sin_port;
    const struct sockaddr_in6 *ja = (const struct sockaddr_in6 *)a;
    const struct sockaddr_in6 *jb = (const struct sockaddr_in6 *)b;
    if (ja->sin6_family == AF_INET6 && jb->sin6_family == AF_INET6)
        return ja->sin6_port == jb->sin6_port &&
               memcmp(&ja->sin6_addr, &jb->sin6_addr, 16) == 0;
    return 0;
}

static socklen_t utp_glue_make_sockaddr(const ntx_addr *a, uint16_t port,
                                        struct sockaddr_storage *out) {
    memset(out, 0, sizeof *out);
    if (ntx_addr_is_v4(a)) {
        struct sockaddr_in *sa = (struct sockaddr_in *)out;
        sa->sin_family = AF_INET;
        sa->sin_addr.s_addr = a->u.v4;
        sa->sin_port = htons(port);
        return (socklen_t)sizeof *sa;
    }
    if (ntx_addr_is_v6(a)) {
        struct sockaddr_in6 *sa6 = (struct sockaddr_in6 *)out;
        sa6->sin6_family = AF_INET6;
        memcpy(&sa6->sin6_addr, a->u.v6, 16);
        sa6->sin6_port = htons(port);
        return (socklen_t)sizeof *sa6;
    }
    return 0;
}

static int utp_glue_alloc(struct ntx_utp *u) {
    for (int i = 0; i < NTX_UTP_MAX_CONNS; i++) {
        utp_glue_slot *s = &u->slots[i];
        if (s->used) continue;
        uint8_t *rb = malloc(UTP_RB);
        if (!rb) return -1;
        memset(s, 0, sizeof *s);
        s->u = u;
        s->rbuf = rb;
        s->used = 1;
        return i;
    }
    return -1;
}

static void utp_glue_reap_halfopen(void *arg);

static void utp_glue_release(struct ntx_utp *u, int idx) {
    utp_glue_slot *s = &u->slots[idx];
    ntx_netx_timer_cancel(u->netx, utp_glue_reap_halfopen, s);
    if (s->px) {
        int tcpfd = ntx_proxy_udp_tcp_fd(s->px);
        int udpfd = ntx_proxy_udp_fd(s->px);
        if (tcpfd >= 0) ntx_netx_del(u->netx, tcpfd);
        if (udpfd >= 0) ntx_netx_del(u->netx, udpfd);
        ntx_proxy_udp_free(s->px);
        s->px = NULL;
    }
    if (s->conn) {
        ntx_utp_conn_free(s->conn);
        s->conn = NULL;
    }
    if (s->rbuf) {
        free(s->rbuf);
        s->rbuf = NULL;
    }
    memset(s, 0, sizeof *s);
}

/* Inbound slot that has not yet carried its first ST_DATA. */
static int utp_glue_is_halfopen(const utp_glue_slot *s) {
    return s->used && s->inbound && !s->accept_fired && s->conn;
}

static void utp_glue_reap_halfopen(void *arg) {
    utp_glue_slot *s = arg;
    if (!utp_glue_is_halfopen(s)) return;
    utp_glue_release(s->u, (int)(s - s->u->slots));
}

static int utp_glue_same_src(const struct sockaddr_storage *a, const struct sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return 0;
    if (a->ss_family == AF_INET)
        return ((const struct sockaddr_in *)a)->sin_addr.s_addr == ((const struct sockaddr_in *)b)->sin_addr.s_addr;
    if (a->ss_family == AF_INET6)
        return memcmp(&((const struct sockaddr_in6 *)a)->sin6_addr, &((const struct sockaddr_in6 *)b)->sin6_addr,
                      16) == 0;
    return 0;
}

static utp_glue_slot *utp_glue_by_fd(struct ntx_utp *u, int virt_fd) {
    if (!u || virt_fd >= 0) return NULL;
    int idx = -virt_fd - NTX_UTP_VIRT_BASE;
    if (idx < 0 || idx >= NTX_UTP_MAX_CONNS) return NULL;
    utp_glue_slot *s = &u->slots[idx];
    return s->used ? s : NULL;
}

static void utp_glue_fill_ops(utp_glue_slot *s, ntx_utp_conn_ops *ops) {
    ops->peer = &s->peer_addr;
    ops->peer_port = s->peer_port;
    ops->tx = utp_glue_tx;
    ops->rx = utp_glue_rx;
    ops->timer = utp_glue_timer;
    ops->closed = utp_glue_closed;
    ops->clock = utp_glue_clock;
    ops->ctx = s;
}

/* ---- UDP read / demux ---- */

/* Notify the owning session that a slot has buffered payload (or is gone).
 * Mirrors the tunnel's tnl_dispatch push: virt fds have no epoll edge, so the
 * transport itself drives the session's read callback. Guarded on unread bytes
 * so a spurious kick never reads an empty rbuf (which the session would read
 * as EOF). */
static void utp_glue_kick_read(utp_glue_slot *s, int vfd) {
    if (s->cbs.r && s->rbuf_len > s->rbuf_off) s->cbs.r(vfd, s->ctx);
}

/* Fire the close callback exactly once (remote RESET/FIN/timeout, or an
 * explicit teardown). The session reacts by dropping the peer, which calls
 * ntx_netx_del(virt_fd) → ntx_utp_virt_close to release the slot. */
static void utp_glue_kick_close(utp_glue_slot *s) {
    if (s->close_fired) return;
    s->close_fired = 1;
    s->closed = 1;
    if (s->cbs.cl) s->cbs.cl(s->ctx);
}

/* One datagram in, already recvfrom'd: parse the uTP header, demux by
 * (peer addr+port, conn_id) into a slot, feed the SM, and push read/close
 * notifications to the session. Shared by the standalone recv loop and the
 * netx shared-socket demux entry (ntx_utp_input). */
static void utp_glue_deliver(struct ntx_utp *u, const uint8_t *buf, size_t n,
                             const struct sockaddr_storage *from,
                             socklen_t from_len) {
    if (n < NTX_UTP_HDR_LEN) return; /* too short */
    ntx_utp_hdr h;
    if (ntx_utp_hdr_parse(buf, n, &h) != 0) return; /* bad hdr */

    utp_glue_slot *slot = NULL;
    for (int i = 0; i < NTX_UTP_MAX_CONNS; i++) {
        utp_glue_slot *s = &u->slots[i];
        if (!s->used || !s->conn) continue;
        if (!utp_glue_peer_match(from, &s->peer)) continue;
        if (h.conn_id != ntx_utp_conn_recv_id(s->conn)) continue;
        slot = s;
        break;
    }

    if (slot) {
        int vfd = -(NTX_UTP_VIRT_BASE + (int)(slot - u->slots));
        int rc = ntx_utp_conn_input(slot->conn, buf, n);
        if (rc == -1) {
            utp_glue_kick_close(slot);
            return;
        }
        if (!slot->inbound) {
            /* outbound: signal CONNECTED once via the app write cb. */
            if (!slot->connect_done && ntx_utp_conn_connected(slot->conn)) {
                slot->connect_done = 1;
                if (slot->cbs.w) slot->cbs.w(vfd, slot->ctx);
            }
        } else if (h.type == NTX_UTP_ST_DATA && !slot->accept_fired) {
            /* netx-accept style: the first ST_DATA (carrying the BT handshake)
             * hands the virt fd to the session; the session then registers its
             * rw callbacks on this slot via ntx_netx_add → ntx_utp_bind_fd. */
            slot->accept_fired = 1;
            if (u->accept_cb) u->accept_cb(u->netx, vfd, u->accept_ctx);
        }
        /* The SM may have delivered payload to the rbuf (or the peer sent a
         * FIN that drained the conn). Push a read so the session drains it; the
         * conn_input call above already ran rx synchronously, and the accept
         * callback (if any) has already wired cbs, so reading now is safe. */
        if (ntx_utp_conn_connected(slot->conn))
            utp_glue_kick_read(slot, vfd);
        else if (slot->closed)
            utp_glue_kick_close(slot);
        return;
    }

    if (h.type == NTX_UTP_ST_SYN) {
        int half = 0, half_src = 0;
        for (int i = 0; i < NTX_UTP_MAX_CONNS; i++) {
            if (!utp_glue_is_halfopen(&u->slots[i])) continue;
            half++;
            if (utp_glue_same_src(&u->slots[i].peer, from)) half_src++;
        }
        if (half >= NTX_UTP_MAX_HALFOPEN || half_src >= NTX_UTP_MAX_HALFOPEN_PER_SRC) return;
        int idx = utp_glue_alloc(u);
        if (idx < 0) return; /* table full: drop the SYN */
        utp_glue_slot *s = &u->slots[idx];
        s->peer = *from;
        s->peer_len = from_len;
        ntx_addr_from_sockaddr(&s->peer_addr, &s->peer_port, from);
        utp_glue_fill_ops(s, &s->ops);
        s->conn = ntx_utp_conn_accept(h.conn_id, h.seq_nr, h.ts_us, &s->ops);
        if (!s->conn) {
            utp_glue_release(u, idx);
            return;
        }
        s->inbound = 1;
        ntx_netx_timer(u->netx, NTX_UTP_HALFOPEN_MS, utp_glue_reap_halfopen, s);
        return;
    }
    /* else: drop (unknown peer, or non-SYN to a missing conn) */
}

static void utp_glue_on_read(int fd, void *ctx) {
    struct ntx_utp *u = ctx;
    for (;;) {
        uint8_t buf[4096];
        struct sockaddr_storage from;
        socklen_t from_len = sizeof from;
        ssize_t n = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from,
                             &from_len);
        if (n <= 0) break; /* EAGAIN or error */
        utp_glue_deliver(u, buf, (size_t)n, &from, from_len);
    }
}

/* Shared-socket demux entry: the netx recv loop hands us one
 * uTP-classified datagram plus its sender; we demux by (peer, conn_id) as the
 * standalone listener does. */
void ntx_utp_input(ntx_utp *u, const uint8_t *buf, size_t n,
                   const struct sockaddr_storage *from, socklen_t from_len) {
    if (!u) return;
    utp_glue_deliver(u, buf, n, from, from_len);
}

/* ---- SOCKS5 UDP ASSOCIATE glue ---- */

static void utp_proxy_teardown(utp_glue_slot *s, int fire_close) {
    if (!s || !s->used) return;
    int idx = (int)(s - s->u->slots);
    if (s->px) {
        int tcpfd = ntx_proxy_udp_tcp_fd(s->px);
        int udpfd = ntx_proxy_udp_fd(s->px);
        if (tcpfd >= 0) ntx_netx_del(s->u->netx, tcpfd);
        if (udpfd >= 0) ntx_netx_del(s->u->netx, udpfd);
        ntx_proxy_udp_free(s->px);
        s->px = NULL;
    }
    if (fire_close) utp_glue_kick_close(s);
    utp_glue_release(s->u, idx);
}

static void utp_proxy_ready(void *ctx, const ntx_addr *bnd, uint16_t bnd_port) {
    utp_glue_slot *s = ctx;
    (void)bnd;
    (void)bnd_port;
    if (!s || !s->used || s->conn) return;
    uint16_t conn_id = (uint16_t)(ntx_rand_u32() & 0xFFFFu);
    s->conn = ntx_utp_conn_initiate(conn_id, &s->ops);
    if (!s->conn) utp_proxy_teardown(s, 1);
}

static void utp_proxy_packet(void *ctx, const ntx_addr *src, uint16_t src_port,
                              const uint8_t *data, size_t n) {
    utp_glue_slot *s = ctx;
    if (!s || !s->used || !s->conn) return;
    /* The relay reply header carries the peer source address. Only feed the
     * owning outbound connection when it matches the dialled peer; stray
     * datagrams are dropped rather than letting the proxy become a reflector. */
    if (!ntx_addr_eq(src, &s->peer_addr) || src_port != s->peer_port) return;
    struct sockaddr_storage from;
    socklen_t flen = utp_glue_make_sockaddr(src, src_port, &from);
    if (flen == 0) return;
    utp_glue_deliver(s->u, data, n, &from, flen);
}

static void utp_proxy_closed(void *ctx) {
    utp_glue_slot *s = ctx;
    if (!s || !s->used) return;
    utp_proxy_teardown(s, 1);
}

static void utp_proxy_tcp_io(int fd, void *ctx) {
    utp_glue_slot *s = ctx;
    (void)fd;
    if (!s || !s->used || !s->px) return;
    int rc = ntx_proxy_udp_step(s->px, 1);
    if (rc < 0) utp_proxy_teardown(s, 1);
}

static void utp_proxy_tcp_close(void *ctx) {
    utp_glue_slot *s = ctx;
    if (!s || !s->used) return;
    utp_proxy_teardown(s, 1);
}

static void utp_proxy_udp_io(int fd, void *ctx) {
    utp_glue_slot *s = ctx;
    (void)fd;
    if (!s || !s->used || !s->px) return;
    ntx_proxy_udp_recv(s->px);
}

/* ---- public API ---- */

ntx_utp *ntx_utp_listen(ntx_netx *netx, uint16_t port, ntx_cb_accept accept_cb,
                        void *accept_ctx) {
    /* Shared-socket mode: when netx already owns a UDP socket on the
     * requested port, ride it instead of binding a second one. The netx recv
     * demux loop classifies datagrams and calls ntx_utp_input, so the glue does
     * not register its own EPOLLIN and must not close the netx-owned fd.
     * Dual-stack: the AF_INET6 sibling rides along when netx managed
     * to bind it to the same port; its datagrams arrive through the very same
     * demux loop, so no extra registration is needed here. */
    int shared_fd = netx ? ntx_netx_udp4_fd(netx) : -1;
    if (shared_fd >= 0 && ntx_netx_port(netx) == port) {
        struct ntx_utp *u = calloc(1, sizeof *u);
        if (!u) return NULL;
        u->netx = netx;
        u->fd = shared_fd;
        u->port = port;
        u->shared = 1;
        u->fd6 = ntx_netx_udp6_fd(netx);
        u->shared6 = u->fd6 >= 0;
        u->port6 = u->shared6 ? port : 0;
        u->accept_cb = accept_cb;
        u->accept_ctx = accept_ctx;
        return u;
    }
    int fd = ntx_sock_udp4();
    if (fd < 0) return NULL;
    uint16_t bound;
    if (port == 0) {
        bound = ntx_sock_bind0(fd);
    } else {
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = htons(port);
        if (bind(fd, (const struct sockaddr *)&sa, sizeof sa) < 0) {
            close(fd);
            return NULL; /* fail-soft: no uTP listen */
        }
        bound = ntx_sock_local_port(fd);
    }
    if (bound == 0) {
        close(fd);
        return NULL;
    }
    struct ntx_utp *u = calloc(1, sizeof *u);
    if (!u) {
        close(fd);
        return NULL;
    }
    u->netx = netx;
    u->fd = fd;
    u->port = bound;
    u->accept_cb = accept_cb;
    u->accept_ctx = accept_ctx;
    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = utp_glue_on_read;
    ntx_netx_add(netx, fd, EPOLLIN, u, &cbs);
    /* Standalone dual-stack sibling: bind [::]:bound with V6ONLY=1 so
     * the two family sockets can share the one advertised port number. Best
     * effort — an IPv6-less host or a taken port leaves fd6 at -1 and this is a
     * v4-only listener, exactly the plain v4 shape. An explicit port that the
     * v6 side cannot reach is not fatal: the v4 socket already holds the
     * advertised number, so keep listening on it alone. */
    int fd6 = ntx_sock_udp6();
    if (fd6 >= 0) {
        uint16_t got6 = ntx_sock_bind6(fd6, bound);
        if (got6 == bound && got6 != 0) {
            u->fd6 = fd6;
            u->port6 = got6;
            ntx_cbs c6;
            memset(&c6, 0, sizeof c6);
            c6.r = utp_glue_on_read;
            ntx_netx_add(netx, fd6, EPOLLIN, u, &c6);
        } else {
            close(fd6);
        }
    }
    return u;
}

void ntx_utp_free(ntx_utp *u) {
    if (!u) return;
    for (int i = 0; i < NTX_UTP_MAX_CONNS; i++) {
        utp_glue_slot *s = &u->slots[i];
        if (!s->used) continue;
        /* Reuse the per-peer teardown path so proxy fds are del'd from epoll and
         * closed before the uTP engine itself disappears. */
        utp_proxy_teardown(s, 0);
    }
    if (u->fd >= 0 && !u->shared) {
        /* Standalone socket: we own its loop registration and its lifetime. The
         * shared netx socket is owned (and closed) by ntx_netx_free. */
        ntx_netx_del(u->netx, u->fd);
        close(u->fd);
        u->fd = -1;
    } else if (u->shared) {
        u->fd = -1; /* do not del/close the netx-owned shared socket */
    }
    /* v6 sibling: same ownership rule as the v4 side — a shared-mode fd6 is the
     * netx-owned owner (netx closes it), a standalone one is ours to unregister
     * and close. */
    if (u->fd6 >= 0 && !u->shared6) {
        ntx_netx_del(u->netx, u->fd6);
        close(u->fd6);
        u->fd6 = -1;
    } else if (u->shared6) {
        u->fd6 = -1;
    }
    free(u);
}

/* Register the session's rw/close callbacks on an accepted (inbound) virt fd.
 * Called from ntx_netx_add when the session arms the peer after accept; the
 * outbound path already captured cbs at route_connect. */
int ntx_utp_bind_fd(ntx_utp *u, int virt_fd, void *ctx, const ntx_cbs *cbs) {
    utp_glue_slot *s = utp_glue_by_fd(u, virt_fd);
    if (!s) return -1;
    s->ctx = ctx;
    if (cbs) s->cbs = *cbs;
    return 0;
}

/* Tear a virt connection down on behalf of the session (peer drop / close).
 * Best-effort FIN, then release the slot. Does not fire cbs.cl: the caller is
 * the session itself, already tearing the peer down. */
void ntx_utp_virt_close(ntx_utp *u, int virt_fd) {
    utp_glue_slot *s = utp_glue_by_fd(u, virt_fd);
    if (!s) return;
    int idx = (int)(s - u->slots);
    if (s->conn && ntx_utp_conn_connected(s->conn)) ntx_utp_conn_close(s->conn);
    utp_glue_release(u, idx);
}

uint16_t ntx_utp_port(const ntx_utp *u) {
    return u ? u->port : 0;
}

/* UI read-only views: no state, no I/O. */
int ntx_utp_conn_count(const ntx_utp *u) {
    if (!u) return 0;
    int n = 0;
    for (int i = 0; i < NTX_UTP_MAX_CONNS; i++)
        if (u->slots[i].used && u->slots[i].conn && !u->slots[i].closed) n++;
    return n;
}

int ntx_utp_v6_live(const ntx_utp *u) {
    if (!u) return 0;
    if (u->fd6 >= 0) return 1; /* v6 listen sibling bound (shared or owned) */
    for (int i = 0; i < NTX_UTP_MAX_CONNS; i++)
        if (u->slots[i].used && u->slots[i].conn && ntx_addr_is_v6(&u->slots[i].peer_addr))
            return 1;
    return 0;
}

int ntx_utp_route_connect(ntx_utp *u, const ntx_addr *addr, uint16_t port,
                          void *ctx, const ntx_cbs *cbs) {
    if (!u || !addr || u->fd < 0) return -1;
    /* Family gate: v4 dials ride the primary socket, v6 dials the
     * AF_INET6 sibling. Without a v6 socket (IPv6-less host, or the shared
     * bind collided) a v6 dial is refused here so route_connect can still fall
     * through to raw TCP rather than open a connection that could never send.
     * An unknown family is a caller bug, not a v6 peer — reject, do not coerce
     * it into a sockaddr_in6 the way the old else-branch did. */
    int v6 = ntx_addr_is_v6(addr);
    if (!v6 && !ntx_addr_is_v4(addr)) return -1;
    if (v6 && u->fd6 < 0) return -1;
    int idx = utp_glue_alloc(u);
    if (idx < 0) return -1;
    utp_glue_slot *s = &u->slots[idx];
    s->peer_len = utp_glue_make_sockaddr(addr, port, &s->peer);
    if (s->peer_len == 0) {
        utp_glue_release(u, idx);
        return -1;
    }
    s->peer_addr = *addr;
    s->peer_port = port;
    s->ctx = ctx;
    ntx_cbs ccbs;
    memset(&ccbs, 0, sizeof ccbs);
    if (cbs) ccbs = *cbs;
    s->cbs = ccbs;
    s->inbound = 0;
    utp_glue_fill_ops(s, &s->ops);
    /* 16-bit conn id from the project RNG (ntx_rand_u32, low 16 bits). */
    uint16_t conn_id = (uint16_t)(ntx_rand_u32() & 0xFFFFu);
    s->conn = ntx_utp_conn_initiate(conn_id, &s->ops);
    if (!s->conn) {
        utp_glue_release(u, idx);
        return -1;
    }
    return -(NTX_UTP_VIRT_BASE + idx);
}

int ntx_utp_route_connect_proxy(ntx_utp *u, const ntx_addr *addr,
                                uint16_t port, void *ctx,
                                const ntx_cbs *cbs, const ntx_config *cfg) {
    if (!u || !addr || !cfg || !cfg->proxy_host || u->fd < 0) return -1;
    /* Both families: the relay framing is family-generic — RFC1928
     * §7 carries ATYP 0x01 (v4) or 0x04 (v6, 16 B) and ntx_proxy_udp_encap/
     * decap already speak both, so a v6 DST.ADDR needs no extra glue here. The
     * uTP datagrams never touch a local socket on this path (they go through
     * the relay BND socket), so fd6 is not a precondition. */
    if (!ntx_addr_is_v4(addr) && !ntx_addr_is_v6(addr)) return -1;
    int idx = utp_glue_alloc(u);
    if (idx < 0) return -1;
    utp_glue_slot *s = &u->slots[idx];
    s->peer_len = utp_glue_make_sockaddr(addr, port, &s->peer);
    if (s->peer_len == 0) {
        utp_glue_release(u, idx);
        return -1;
    }
    s->peer_addr = *addr;
    s->peer_port = port;
    s->ctx = ctx;
    ntx_cbs ccbs;
    memset(&ccbs, 0, sizeof ccbs);
    if (cbs) ccbs = *cbs;
    s->cbs = ccbs;
    s->inbound = 0;
    utp_glue_fill_ops(s, &s->ops);

    int tcpfd = ntx_sock_tcp_connect_host(cfg->proxy_host, cfg->proxy_port);
    if (tcpfd < 0) {
        utp_glue_release(u, idx);
        return -1;
    }
    s->px = ntx_proxy_udp_associate(tcpfd, addr, port, s, utp_proxy_ready,
                                     utp_proxy_packet, utp_proxy_closed);
    if (!s->px) {
        close(tcpfd);
        utp_glue_release(u, idx);
        return -1;
    }

    ntx_cbs pcbs;
    memset(&pcbs, 0, sizeof pcbs);
    pcbs.r = utp_proxy_tcp_io;
    pcbs.w = utp_proxy_tcp_io;
    pcbs.cl = utp_proxy_tcp_close;
    ntx_netx_add(u->netx, tcpfd, EPOLLIN | EPOLLOUT, s, &pcbs);

    int udpfd = ntx_proxy_udp_fd(s->px);
    memset(&pcbs, 0, sizeof pcbs);
    pcbs.r = utp_proxy_udp_io;
    ntx_netx_add(u->netx, udpfd, EPOLLIN, s, &pcbs);

    int rc = ntx_proxy_udp_step(s->px, 0);
    if (rc < 0) {
        utp_proxy_teardown(s, 1);
        return -1;
    }
    return -(NTX_UTP_VIRT_BASE + idx);
}

ssize_t ntx_utp_virt_read(ntx_utp *u, int virt_fd, uint8_t *buf, size_t cap) {
    utp_glue_slot *s = utp_glue_by_fd(u, virt_fd);
    if (!s) return -1;
    size_t avail = s->rbuf_len - s->rbuf_off;
    if (avail == 0) {
        /* Mirror a non-blocking socket: an empty-but-live connection is
         * "would block" (-1/EAGAIN), NOT EOF (0). Callers (the PE handshake and
         * peer_on_rw) treat a 0 return as graceful peer EOF, so returning 0
         * here would make the initiator fail every uTP BT handshake before the
         * responder's reply has arrived. */
        if (s->closed) { errno = ECONNRESET; return -1; }
        errno = EAGAIN;
        return -1;
    }
    size_t n = avail < cap ? avail : cap;
    memcpy(buf, s->rbuf + s->rbuf_off, n);
    s->rbuf_off += n;
    return (ssize_t)n;
}

ssize_t ntx_utp_virt_write(ntx_utp *u, int virt_fd, const uint8_t *buf, size_t n) {
    utp_glue_slot *s = utp_glue_by_fd(u, virt_fd);
    if (!s || !s->conn) return -1;
    if (!n) return 0;
    ssize_t acc = (ssize_t)ntx_utp_conn_write(s->conn, buf, n);
    /* Write-side twin of virt_read's non-blocking-socket mirror: the SM's
     * conn_write returns 0 when the send window/queue cannot accept a single
     * byte (the D12 gate) — that is "would block", not "wrote nothing".
     * Callers (peer_out_flush, send_raw, pe_send_out) recognize only
     * -1/EAGAIN as back-pressure and buffer for retry; a leaked 0 drives
     * out_flush down its fatal path and send_raw discards the message AFTER
     * ntx_pe_encrypt advanced the send RC4 — wire bytes lost, keystream
     * advanced, the peer's next BT message decrypts to garbage (bad_msg_len). */
    if (acc == 0) { errno = EAGAIN; return -1; }
    return acc;
}

int ntx_utp_virt_connected(ntx_utp *u, int virt_fd) {
    utp_glue_slot *s = utp_glue_by_fd(u, virt_fd);
    if (!s || !s->conn) return 0;
    return ntx_utp_conn_connected(s->conn);
}
