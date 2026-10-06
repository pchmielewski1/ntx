#include "ntx_netx.h"
#include "ntx_sock.h"
#include "ntx_proxy.h"
#include "ntx_tunnel.h"
#include "ntx_utp.h"

#include <errno.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "../ui/ntx_diag.h"
#include "../core/ntx_time.h"

/* Optional uTP glue (BEP29, ntx_utp.c): unit tests that #include
 * ntx_netx.c without ntx_utp.c still link — the weak refs resolve to NULL
 * there (same pattern as the weak DoH stubs in ntx_sock.c). Every call site
 * is gated on n->utp being non-NULL, which only happens when ntx_utp_listen
 * itself resolved, so a NULL entry point is never called. */
#if defined(__GNUC__) || defined(__clang__)
#define NTX_UTP_WEAK __attribute__((weak))
#else
#define NTX_UTP_WEAK
#endif
NTX_UTP_WEAK ntx_utp *ntx_utp_listen(ntx_netx *netx, uint16_t port,
                                     ntx_cb_accept accept_cb, void *accept_ctx);
NTX_UTP_WEAK void ntx_utp_free(ntx_utp *u);
NTX_UTP_WEAK int ntx_utp_route_connect(ntx_utp *u, const ntx_addr *addr,
                                       uint16_t port, void *ctx,
                                       const ntx_cbs *cbs);
NTX_UTP_WEAK int ntx_utp_route_connect_proxy(ntx_utp *u, const ntx_addr *addr,
                                             uint16_t port, void *ctx,
                                             const ntx_cbs *cbs,
                                             const ntx_config *cfg);
NTX_UTP_WEAK ssize_t ntx_utp_virt_read(ntx_utp *u, int virt_fd, uint8_t *buf,
                                       size_t cap);
NTX_UTP_WEAK ssize_t ntx_utp_virt_write(ntx_utp *u, int virt_fd,
                                        const uint8_t *buf, size_t n);
NTX_UTP_WEAK int ntx_utp_virt_connected(ntx_utp *u, int virt_fd);
/* UI read-only views (same weak contract: the call sites below are
 * gated on n->utp, which only exists once ntx_utp_listen resolved). */
NTX_UTP_WEAK int ntx_utp_conn_count(const ntx_utp *u);
NTX_UTP_WEAK int ntx_utp_v6_live(const ntx_utp *u);
/* uTP shared-socket input entry: fed one classified datagram plus the
 * sender's sockaddr by the netx recv demux loop; the glue demuxes by
 * (peer addr+port, conn_id) exactly as the standalone listener did. */
NTX_UTP_WEAK void ntx_utp_input(ntx_utp *u, const uint8_t *buf, size_t n,
                                const struct sockaddr_storage *from,
                                socklen_t from_len);
/* Virt-fd I/O wiring (BEP29): the session arms an accepted/dialled
 * uTP peer through ntx_netx_add/mod/del exactly like a TCP fd, but a virt fd has
 * no epoll entry — the glue owns the readiness edge. These route the per-fd
 * read/write/close callbacks into the owning slot so the glue can push a read
 * when payload lands (the tunnel does the same via tnl_dispatch). */
NTX_UTP_WEAK int ntx_utp_bind_fd(ntx_utp *u, int virt_fd, void *ctx,
                                 const ntx_cbs *cbs);
NTX_UTP_WEAK void ntx_utp_virt_close(ntx_utp *u, int virt_fd);
/* Shared-socket demux: the DHT input entry, reached from the netx
 * recv loop for a DHT-classified datagram. Weak so netx-only TUs link. */
struct ntx_netx;
NTX_UTP_WEAK void ntx_dht_input(struct ntx_netx *netx, const uint8_t *buf,
                                size_t n, const struct sockaddr_storage *from,
                                socklen_t from_len);

typedef struct {
    int used;
    void *ctx;
    ntx_cbs cbs;
    uint32_t ev;
} ntx_fd_entry;

typedef struct ntx_connect_ctx {
    ntx_netx *netx;
    ntx_proxy proxy;
    void *app_ctx;
    ntx_cbs app_cbs;
} ntx_connect_ctx;

struct ntx_netx {
    int epfd;
    ntx_fd_entry *fds;
    int cap;
    int listen_fd;
    uint16_t listen_port;
    int listen_fd6;
    uint16_t listen_port6;
    ntx_cb_accept accept_cb;
    void *accept_ctx;
    int quit;
    uint64_t *hdue;
    ntx_cb_timer *hcb;
    void **harg;
    int hn;
    int hcap;
    const ntx_config *cfg;
    ntx_tunnel *tunnel;
    ntx_utp *utp;
    /* Shared per-family UDP owner: one socket bound to the listen
     * port; the recv loop classifies each datagram (ntx_udp_classify) and hands
     * it to DHT or the uTP glue. Fail-soft: udp4_fd < 0 means the bind collided
     * and neither subsystem is served from here (DHT falls back to its own
     * socket, uTP is off). Counters feed the UI. */
    int udp4_fd;
    uint16_t udp4_port;
    /* IPv6 sibling: same single-port convention, AF_INET6 with
     * IPV6_V6ONLY=1 so the two family sockets never race for the same peer
     * (a v4 peer is only ever seen on udp4_fd, a v6 peer only here). Bound
     * independently: no IPv6 in the environment, or the port taken, leaves it
     * at -1 and v6 uTP stays off while v4 keeps working. */
    int udp6_fd;
    uint16_t udp6_port;
    uint64_t demux_dht;
    uint64_t demux_utp;
    uint64_t demux_drop;
};

static void heap_swap(ntx_netx *n, int a, int b) {
    uint64_t td = n->hdue[a];
    n->hdue[a] = n->hdue[b];
    n->hdue[b] = td;
    ntx_cb_timer tc = n->hcb[a];
    n->hcb[a] = n->hcb[b];
    n->hcb[b] = tc;
    void *ta = n->harg[a];
    n->harg[a] = n->harg[b];
    n->harg[b] = ta;
}

static void heap_push(ntx_netx *n, uint64_t due, ntx_cb_timer cb, void *arg) {
    if (n->hn >= n->hcap) {
        int nc = n->hcap ? n->hcap * 2 : 8;
        n->hdue = realloc(n->hdue, (size_t)nc * sizeof *n->hdue);
        n->hcb = realloc(n->hcb, (size_t)nc * sizeof *n->hcb);
        n->harg = realloc(n->harg, (size_t)nc * sizeof *n->harg);
        n->hcap = nc;
    }
    int i = n->hn++;
    n->hdue[i] = due;
    n->hcb[i] = cb;
    n->harg[i] = arg;
    while (i > 0) {
        int p = (i - 1) / 2;
        if (n->hdue[p] <= n->hdue[i]) break;
        heap_swap(n, p, i);
        i = p;
    }
}

static void heap_pop(ntx_netx *n) {
    int last = --n->hn;
    if (last > 0) {
        n->hdue[0] = n->hdue[last];
        n->hcb[0] = n->hcb[last];
        n->harg[0] = n->harg[last];
    }
    int i = 0;
    for (;;) {
        int l = 2 * i + 1, r = l + 1, s = i;
        if (l < n->hn && n->hdue[l] < n->hdue[s]) s = l;
        if (r < n->hn && n->hdue[r] < n->hdue[s]) s = r;
        if (s == i) break;
        heap_swap(n, s, i);
        i = s;
    }
}

/* 0 = slot for fd exists, -1 = out of memory (the table is left as it was). */
static int ensure_fd(ntx_netx *n, int fd) {
    if (fd < n->cap) return 0;
    int nc = n->cap ? n->cap : 64;
    while (nc <= fd) nc *= 2;
    ntx_fd_entry *nf = realloc(n->fds, (size_t)nc * sizeof *nf);
    if (!nf) return -1;
    memset(nf + n->cap, 0, (size_t)(nc - n->cap) * sizeof *nf);
    n->fds = nf;
    n->cap = nc;
    return 0;
}

static void accept_handler(int fd, void *ctx) {
    ntx_netx *n = ctx;
    for (;;) {
        int peer = ntx_sock_accept4(fd);
        if (peer < 0) break;
        if (n->accept_cb) n->accept_cb(n, peer, n->accept_ctx);
    }
}

/* Shared-socket receive demux. One recvfrom drain on the netx-owned
 * UDP socket; each datagram is classified by its first byte and routed: DHT →
 * the DHT input entry (which keeps its own rate-limit/RT accounting), uTP → the
 * uTP glue input (which demuxes further by (peer, conn_id)). Anything else is
 * dropped and counted. A subsystem whose entry did not link (weak NULL) is
 * skipped, not crashed on. */
static void udp_demux_handler(int fd, void *ctx) {
    ntx_netx *n = ctx;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_storage from;
        socklen_t flen = sizeof from;
        ssize_t r = recvfrom(fd, buf, sizeof buf, 0, (struct sockaddr *)&from,
                             &flen);
        if (r <= 0) break;
        switch (ntx_udp_classify(buf, (size_t)r)) {
        case NTX_UDP_DHT:
            n->demux_dht++;
            if (ntx_dht_input)
                ntx_dht_input(n, buf, (size_t)r, &from, flen);
            break;
        case NTX_UDP_UTP:
            if (n->utp && ntx_utp_input) {
                n->demux_utp++;
                ntx_utp_input(n->utp, buf, (size_t)r, &from, flen);
            } else {
                /* uTP engine absent (fail-soft bind collision → uTP disabled): a
                 * uTP-shaped datagram has no consumer, so it is a drop, not a
                 * delivered uTP packet. Counting it as demux_utp would overstate
                 * the delivered volume; keep dht+utp+drop == total recv invariant. */
                n->demux_drop++;
            }
            break;
        default:
            n->demux_drop++;
            break;
        }
    }
}

/* uTP accept (BEP29): deliver the accepted virt fd through the same accept
 * callback the TCP listener uses (ntx_netx_set_accept) so the session sees a
 * single accept path for both transports. */
static void utp_accept_fwd(ntx_netx *n, int virt_fd, void *ctx) {
    ntx_netx *netx = ctx;
    (void)n;
    if (netx->accept_cb) netx->accept_cb(netx, virt_fd, netx->accept_ctx);
}

static void proxy_io_cb(int fd, void *ctx) {
    ntx_connect_ctx *cc = ctx;
    int rc = ntx_proxy_step(&cc->proxy, 1);
    if (rc < 0) {
        if (cc->app_cbs.cl) cc->app_cbs.cl(cc->app_ctx);
        ntx_netx_del(cc->netx, fd);
        free(cc);
        return;
    }
    if (rc == 1) {
        ntx_netx *netx = cc->netx;
        ntx_fd_entry *f = &netx->fds[fd];
        void *app_ctx = cc->app_ctx;
        ntx_cbs app_cbs = cc->app_cbs;
        free(cc);
        f->ctx = app_ctx;
        f->cbs = app_cbs;
        ntx_netx_mod(netx, fd, EPOLLIN | EPOLLOUT);
        if (f->cbs.w) f->cbs.w(fd, f->ctx);
    }
}

static void proxy_fail_close(void *ctx) {
    ntx_connect_ctx *cc = ctx;
    int fd = cc->proxy.fd;
    if (cc->app_cbs.cl) cc->app_cbs.cl(cc->app_ctx);
    ntx_netx_del(cc->netx, fd);
    if (fd >= 0) close(fd);
    free(cc);
}


static int route_connect_raw(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs) {
    int v6 = ntx_addr_is_v6(addr);
    int fd = v6 ? ntx_sock_tcp6() : ntx_sock_tcp4();
    if (fd < 0) return -1;
    if (v6)
        ntx_sock_bind6(fd, 0);
    else
        ntx_sock_bind0(fd);
    int rc = ntx_sock_connect_addr(fd, addr, port);
    if (rc < 0) {
        close(fd);
        return -1;
    }
    ntx_netx_add(n, fd, EPOLLOUT, ctx, cbs);
    /* Already connected (instant connect): EPOLLOUT may not re-fire. */
    if (ntx_netx_peer_connected(n, fd) && cbs && cbs->w) cbs->w(fd, ctx);
    return fd;
}

static int route_connect_proxy(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs) {
    const ntx_config *cfg = n->cfg;
    if (!cfg || !cfg->proxy_host) return -1;
    int fd = ntx_sock_tcp_connect_host(cfg->proxy_host, cfg->proxy_port);
    if (fd < 0) return -1;
    ntx_connect_ctx *cc = calloc(1, sizeof *cc);
    if (!cc) {
        close(fd);
        return -1;
    }
    cc->netx = n;
    cc->app_ctx = ctx;
    cc->app_cbs = *cbs;
    ntx_proxy_init(&cc->proxy, fd, addr, port, cc, proxy_io_cb, proxy_io_cb, proxy_fail_close);
    ntx_cbs pcbs = {proxy_io_cb, proxy_io_cb, proxy_fail_close};
    ntx_netx_add(n, fd, EPOLLIN | EPOLLOUT, cc, &pcbs);
    return fd;
}

ntx_netx *ntx_netx_init(const ntx_config *cfg) {
    ntx_netx *n = calloc(1, sizeof *n);
    if (!n) return NULL;
    n->cfg = cfg;
    n->epfd = epoll_create1(EPOLL_CLOEXEC);
    n->listen_fd = ntx_sock_tcp4();
    if (n->epfd < 0 || n->listen_fd < 0) {
        if (n->epfd >= 0) close(n->epfd);
        if (n->listen_fd >= 0) close(n->listen_fd);
        free(n);
        return NULL;
    }
    if (cfg)
        n->listen_port = ntx_sock_bind_range(n->listen_fd, cfg->port_lo, cfg->port_hi);
    else
        n->listen_port = ntx_sock_bind0(n->listen_fd);
    ntx_sock_listen(n->listen_fd, 64);
    n->listen_fd6 = -1;
    {
        int fd6 = ntx_sock_tcp6();
        if (fd6 >= 0) {
            uint16_t p6 = ntx_sock_bind6(fd6, n->listen_port);
            if (p6 == 0) {
                p6 = ntx_sock_bind6(fd6, 0);
                if (p6 > 0 && cfg && cfg->verbose)
                    ntx_diag("ntx: listen v6: port %u busy, using ephemeral %u\n",
                             (unsigned)n->listen_port, (unsigned)p6);
            }
            if (p6 > 0 && ntx_sock_listen(fd6, 64) == 0) {
                n->listen_fd6 = fd6;
                n->listen_port6 = p6;
            } else {
                close(fd6);
            }
        }
    }
    ntx_cbs lcbs;
    memset(&lcbs, 0, sizeof lcbs);
    lcbs.r = accept_handler;
    ntx_netx_add(n, n->listen_fd, EPOLLIN, n, &lcbs);
    ntx_netx_add(n, n->listen_fd6, EPOLLIN, n, &lcbs);
    if (cfg && cfg->tunnel && cfg->tunnel_host)
        n->tunnel = ntx_tunnel_connect(n, cfg->tunnel_host, cfg->tunnel_port);
    /* Shared per-family UDP owner: one socket on the listen port that
     * both DHT and uTP ride, demultiplexed by first byte. Bind failure is
     * fail-soft — udp4_fd stays -1, DHT later falls back to its own socket and
     * uTP is simply off; the TCP listener and the rest of netx are unaffected. */
    n->udp4_fd = -1;
    {
        int ufd = ntx_sock_udp4();
        if (ufd >= 0) {
            /* Bind to the exact TCP listen port (BT single-port convention: peers
             * reach us on one port for both transports). An explicit bind — not
             * bind_range — so a collision fails soft rather than silently drifting
             * to an ephemeral port that would break the advertised port. */
            struct sockaddr_in sa;
            memset(&sa, 0, sizeof sa);
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(INADDR_ANY);
            sa.sin_port = htons(n->listen_port);
            int ok = bind(ufd, (const struct sockaddr *)&sa, sizeof sa) == 0;
            uint16_t got = ok ? ntx_sock_local_port(ufd) : 0;
            if (ok && got == n->listen_port && got != 0) {
                n->udp4_fd = ufd;
                n->udp4_port = got;
                ntx_cbs ucbs;
                memset(&ucbs, 0, sizeof ucbs);
                ucbs.r = udp_demux_handler;
                ntx_netx_add(n, ufd, EPOLLIN, n, &ucbs);
            } else {
                if (cfg && cfg->verbose)
                    ntx_diag("ntx: shared udp :%u busy — dht standalone, utp off\n",
                            (unsigned)n->listen_port);
                close(ufd);
            }
        }
    }
    /* IPv6 sibling of the shared owner: the same single-port
     * convention on AF_INET6 so v6 peers reach uTP on the advertised port.
     * V6ONLY=1 (set by ntx_sock_udp6 before any bind) keeps this socket from
     * also claiming v4-mapped traffic — the family split is therefore exact
     * and mirrors how the rest of netx pairs listen_fd/listen_fd6. Bind is
     * attempted independently of the v4 result and fails soft: no IPv6 stack,
     * or the port already taken, leaves udp6_fd at -1 (v6 uTP off, v4 intact). */
    n->udp6_fd = -1;
    {
        int fd6 = ntx_sock_udp6();
        if (fd6 >= 0) {
            uint16_t got6 = n->listen_port ? ntx_sock_bind6(fd6, n->listen_port) : 0;
            if (got6 == n->listen_port && got6 != 0) {
                n->udp6_fd = fd6;
                n->udp6_port = got6;
                ntx_cbs ucbs6;
                memset(&ucbs6, 0, sizeof ucbs6);
                ucbs6.r = udp_demux_handler;
                ntx_netx_add(n, fd6, EPOLLIN, n, &ucbs6);
            } else {
                if (cfg && cfg->verbose)
                    ntx_diag("ntx: shared udp6 :%u unavailable — v6 utp off\n",
                            (unsigned)n->listen_port);
                close(fd6);
            }
        }
    }
    /* uTP listens on the shared socket (BT single-port convention). Fail-soft:
     * no shared socket, or the entry point did not link ⇒ no uTP. */
    if (cfg && cfg->utp && ntx_utp_listen && n->udp4_fd >= 0)
        n->utp = ntx_utp_listen(n, n->listen_port, utp_accept_fwd, n);
    return n;
}

void ntx_netx_free(ntx_netx *n) {
    if (!n) return;
    if (n->tunnel) ntx_tunnel_free(n->tunnel);
    if (n->utp) ntx_utp_free(n->utp);
    free(n->fds);
    free(n->hdue);
    free(n->hcb);
    free(n->harg);
    if (n->epfd >= 0) close(n->epfd);
    if (n->listen_fd >= 0) close(n->listen_fd);
    if (n->listen_fd6 >= 0) close(n->listen_fd6);
    if (n->udp4_fd >= 0) close(n->udp4_fd);
    if (n->udp6_fd >= 0) close(n->udp6_fd);
    free(n);
}

void ntx_netx_quit(ntx_netx *n) {
    n->quit = 1;
}

void ntx_netx_set_accept(ntx_netx *n, ntx_cb_accept cb, void *ctx) {
    n->accept_cb = cb;
    n->accept_ctx = ctx;
}

uint16_t ntx_netx_port(const ntx_netx *n) {
    return n->listen_port;
}

/* Shared per-family UDP owner accessors. ntx_netx_udp4_fd returns the
 * netx-owned datagram socket bound to the listen port, or -1 when the bind
 * collided (fail-soft). DHT uses it as its send fd and receives through the
 * netx recv demux loop; a -1 answer tells DHT to fall back to its own socket.
 * ntx_netx_demux_stats reports the classifier counters (any arg may be NULL);
 * demux_dht/demux_utp count datagrams actually dispatched to that consumer, and
 * demux_drop counts everything received but undeliverable: first bytes that are
 * neither DHT nor a legal uTP header, plus a uTP-shaped datagram that arrived
 * while the uTP engine is absent (fail-soft bind collision). Thus
 * demux_dht + demux_utp + demux_drop == total datagrams recv'd. */
int ntx_netx_udp4_fd(const ntx_netx *n) {
    return n ? n->udp4_fd : -1;
}

/* IPv6 sibling of the shared per-family UDP owner. Returns the
 * netx-owned AF_INET6 datagram socket bound to the listen port with
 * IPV6_V6ONLY=1, or -1 when IPv6 is unavailable / the bind collided. The uTP
 * glue rides it as its v6 send socket and receives v6 datagrams through the
 * same udp_demux_handler (the classifier is family-agnostic; the counters are
 * per-owner, not per-family, so the UI sees one demux_dht/demux_utp/demux_drop
 * picture across both families and dht+utp+drop still equals the total recv). */
int ntx_netx_udp6_fd(const ntx_netx *n) {
    return n ? n->udp6_fd : -1;
}

void ntx_netx_demux_stats(const ntx_netx *n, uint64_t *dht, uint64_t *utp,
                          uint64_t *drop) {
    if (!n) return;
    if (dht) *dht = n->demux_dht;
    if (utp) *utp = n->demux_utp;
    if (drop) *drop = n->demux_drop;
}

/* UI read-only views: thin NULL-safe
 * delegation to the uTP glue; 0 when the transport is off (no n->utp). */
int ntx_netx_utp_conns(const ntx_netx *n) { return n && n->utp ? ntx_utp_conn_count(n->utp) : 0; }
int ntx_netx_utp_v6(const ntx_netx *n) { return n && n->utp ? ntx_utp_v6_live(n->utp) : 0; }

uint16_t ntx_netx_port6(const ntx_netx *n) {
    return n->listen_port6;
}

/* Shared-socket datagram classification: first byte 'd'/'l'/'i' →
 * bencode DHT (BEP5); high nibble = type 0..4 AND low nibble = ver 1 → uTP
 * header start (BEP29); anything else, incl. an empty datagram, → drop.
 * Pure: buffer + len in, enum out; the unknown branch is the demux_unknown
 * class (counter lives in the shared recv path). */
ntx_udp_kind ntx_udp_classify(const uint8_t *pkt, size_t n) {
    if (!pkt || n == 0) return NTX_UDP_DROP;
    uint8_t b = pkt[0];
    if (b == 'd' || b == 'l' || b == 'i') return NTX_UDP_DHT;
    if ((b >> 4) <= 4 && (b & 0x0F) == 1) return NTX_UDP_UTP;
    return NTX_UDP_DROP;
}

void ntx_netx_add(ntx_netx *n, int fd, uint32_t ev, void *ctx, const ntx_cbs *cbs) {
    if (fd < 0) {
        /* uTP virt fd: register the app's rw/close callbacks on the glue slot
         * so the transport can push a read when payload arrives (no epoll entry
         * exists for a negative fd). Mirrors the tunnel, which stores cbs in the
         * virt slot at route_connect. */
        if (n && n->utp && ntx_utp_bind_fd && fd <= -NTX_UTP_VIRT_BASE)
            ntx_utp_bind_fd(n->utp, fd, ctx, cbs);
        return;
    }
    if (ensure_fd(n, fd) != 0) return; /* OOM: the fd stays unregistered (handshake timeout reaps it) */
    ntx_fd_entry *f = &n->fds[fd];
    f->used = 1;
    f->ctx = ctx;
    f->cbs = *cbs;
    f->ev = ev;
    struct epoll_event ee;
    ee.events = ev;
    ee.data.fd = fd;
    epoll_ctl(n->epfd, EPOLL_CTL_ADD, fd, &ee);
}

void ntx_netx_mod(ntx_netx *n, int fd, uint32_t ev) {
    if (fd < 0 || fd >= n->cap) return;
    ntx_fd_entry *f = &n->fds[fd];
    if (f->used && f->ev == ev) return;
    f->ev = ev;
    struct epoll_event ee;
    ee.events = ev;
    ee.data.fd = fd;
    epoll_ctl(n->epfd, EPOLL_CTL_MOD, fd, &ee);
}

void ntx_netx_del(ntx_netx *n, int fd) {
    if (fd < 0) {
        /* uTP virt fd: the session dropping the peer tears the connection down
         * through the glue (FIN best-effort + slot release). No epoll entry to
         * remove for a negative fd. */
        if (n && n->utp && ntx_utp_virt_close && fd <= -NTX_UTP_VIRT_BASE)
            ntx_utp_virt_close(n->utp, fd);
        return;
    }
    if (fd >= n->cap) return;
    ntx_fd_entry *f = &n->fds[fd];
    if (!f->used) return;
    f->used = 0;
    f->ctx = NULL;
    epoll_ctl(n->epfd, EPOLL_CTL_DEL, fd, NULL);
}

void ntx_netx_timer(ntx_netx *n, uint32_t ms, ntx_cb_timer cb, void *arg) {
    heap_push(n, ntx_mono_ms() + ms, cb, arg);
}

void ntx_netx_timer_cancel(ntx_netx *n, ntx_cb_timer cb, void *arg) {
    int w = 0;
    int removed = 0;
    for (int r = 0; r < n->hn; r++) {
        if (n->hcb[r] == cb && n->harg[r] == arg) { removed = 1; continue; }
        n->hdue[w] = n->hdue[r];
        n->hcb[w] = n->hcb[r];
        n->harg[w] = n->harg[r];
        w++;
    }
    if (!removed) return;
    n->hn = w;
    /* Compaction broke the heap order: restore it bottom-up. */
    for (int i = w / 2 - 1; i >= 0; i--) {
        int x = i;
        for (;;) {
            int l = 2 * x + 1, rr = l + 1, s = x;
            if (l < w && n->hdue[l] < n->hdue[s]) s = l;
            if (rr < w && n->hdue[rr] < n->hdue[s]) s = rr;
            if (s == x) break;
            heap_swap(n, s, x);
            x = s;
        }
    }
}

static int route_connect_ex(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs,
                            int allow_utp) {
    if (!addr) return -1;
    if (n->tunnel && ntx_tunnel_ready(n->tunnel)) {
        return ntx_tunnel_route_connect(n->tunnel, addr, port, ctx, cbs);
    }
    /* uTP dial (BEP29, --utp): both families (the v4-only hard
     * gate — v6 peers ride the AF_INET6 sibling of the shared socket). The glue
     * returns a virt fd (<= -NTX_UTP_VIRT_BASE) on success and -1 when it has
     * no socket for that family / the table is full; only a real virt fd is
     * terminal, so an unavailable uTP falls through to the proxy/raw path
     * instead of failing the dial (tunnel -> uTP/proxy -> raw ordering held).
     * With --proxy + --utp the same branch carries datagrams through SOCKS5
     * UDP ASSOCIATE; a failed associate dial likewise falls through to
     * the TCP CONNECT proxy, never to a direct leak. */
    if (allow_utp && n->utp && (ntx_addr_is_v4(addr) || ntx_addr_is_v6(addr))) {
        int vfd = -1;
        if (n->cfg && n->cfg->proxy && n->cfg->proxy_host &&
            ntx_utp_route_connect_proxy) {
            vfd = ntx_utp_route_connect_proxy(n->utp, addr, port, ctx, cbs,
                                              n->cfg);
        } else if (ntx_utp_route_connect) {
            vfd = ntx_utp_route_connect(n->utp, addr, port, ctx, cbs);
        }
        if (vfd <= -NTX_UTP_VIRT_BASE) return vfd;
    }
    if (n->cfg && n->cfg->proxy && n->cfg->proxy_host) {
        return route_connect_proxy(n, addr, port, ctx, cbs);
    }
    return route_connect_raw(n, addr, port, ctx, cbs);
}

int ntx_netx_route_connect(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs) {
    return route_connect_ex(n, addr, port, ctx, cbs, 1);
}

/* Same routing without the uTP step: the TCP retry for a peer that did not answer a uTP dial. */
int ntx_netx_route_connect_tcp(ntx_netx *n, const ntx_addr *addr, uint16_t port, void *ctx, const ntx_cbs *cbs) {
    return route_connect_ex(n, addr, port, ctx, cbs, 0);
}

ssize_t ntx_netx_read(ntx_netx *n, int fd, uint8_t *buf, size_t cap) {
    if (fd >= 0) return read(fd, buf, cap);
    if (n && n->utp && fd <= -NTX_UTP_VIRT_BASE)
        return ntx_utp_virt_read(n->utp, fd, buf, cap);
    if (n && n->tunnel) return ntx_tunnel_virt_read(n->tunnel, fd, buf, cap);
    return -1;
}

ssize_t ntx_netx_write(ntx_netx *n, int fd, const uint8_t *buf, size_t len) {
    if (fd >= 0) return write(fd, buf, len);
    if (n && n->utp && fd <= -NTX_UTP_VIRT_BASE)
        return ntx_utp_virt_write(n->utp, fd, buf, len);
    if (n && n->tunnel) return ntx_tunnel_virt_write(n->tunnel, fd, buf, len) == 0 ? (ssize_t)len : -1;
    return -1;
}

int ntx_netx_peer_connected(ntx_netx *n, int fd) {
    if (fd >= 0) {
        /* getpeername only — getsockopt(SO_ERROR) clears the pending error and
         * would hide connect failures from callers that check SO_ERROR next. */
        struct sockaddr_storage ss;
        socklen_t slen = sizeof ss;
        if (getpeername(fd, (struct sockaddr *)&ss, &slen) != 0) return 0;
        return 1;
    }
    if (n && n->utp && fd <= -NTX_UTP_VIRT_BASE)
        return ntx_utp_virt_connected(n->utp, fd);
    if (n && n->tunnel) return ntx_tunnel_virt_connected(n->tunnel, fd);
    return 0;
}

void ntx_netx_run_once(ntx_netx *n, int timeout_ms) {
    uint64_t now = ntx_mono_ms();
    int to = timeout_ms;
    if (n->hn > 0) {
        int64_t d = (int64_t)n->hdue[0] - (int64_t)now;
        if (d < to) to = (int)d;
        if (to < 0) to = 0;
    }
    if (to > 60000) to = 60000;
    struct epoll_event evs[64];
    int ne = epoll_wait(n->epfd, evs, 64, to);
    if (ne < 0 && errno != EINTR) return;
    for (int i = 0; i < ne; i++) {
        int fd = evs[i].data.fd;
        if (fd < 0 || fd >= n->cap) continue;
        ntx_fd_entry *f = &n->fds[fd];
        if (!f->used) continue;
        uint32_t e = evs[i].events;
        void *ctx = f->ctx;
        /* A callback may close and ntx_netx_del() its own fd (EOF, protocol error). That
           clears f->used/f->ctx, so the remaining callbacks for this event must not run:
           they would receive ctx == NULL (e.g. a tunnel to an unreachable host crashed in
           tnl_io on the EPOLLOUT that followed the EPOLLIN/EOF). Compare ctx as well so a
           slot re-used by a new fd inside the callback is not driven with the old events. */
        if ((e & EPOLLIN) && f->cbs.r) f->cbs.r(fd, ctx);
        if (!f->used || f->ctx != ctx) continue;
        if ((e & EPOLLOUT) && f->cbs.w) f->cbs.w(fd, ctx);
        if (!f->used || f->ctx != ctx) continue;
        if ((e & (EPOLLERR | EPOLLHUP)) && f->cbs.cl) f->cbs.cl(ctx);
    }
    while (n->hn > 0 && n->hdue[0] <= ntx_mono_ms()) {
        ntx_cb_timer cb = n->hcb[0];
        void *arg = n->harg[0];
        heap_pop(n);
        cb(arg);
    }
}

void ntx_netx_run(ntx_netx *n) {
    while (!n->quit) ntx_netx_run_once(n, 60000);
}
