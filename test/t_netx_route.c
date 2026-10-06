/* Egress regression GUARD for the proxy/tunnel egress.
 *
 * Contract: route_connect order tunnel → uTP/proxy → raw MUST
 * not break; --proxy keeps TCP peers + HTTP(S); uTP rides SOCKS UDP ASSOCIATE
 * when --utp; --tunnel keeps priority. Tor is an external SOCKS5 proxy
 * (socks5:127.0.0.1:9050), not in-tree.
 *
 * No live Tor/VPN is started (unit/framing level is the requirement).
 * The decision matrix is driven at the ntx_netx_route_connect() branch level:
 * this TU #includes ntx_netx.c and supplies STRONG replacements for the weak
 * uTP entry points and the tunnel entry points, so every branch choice is
 * observable and deterministic (recorders + loopback listeners, poll-bounded
 * pumps — no sleeps-as-sync).
 *
 * Matrix (asserted below):
 *  A  tunnel ready + utp + proxy, v4  → tunnel path (precedence lock)
 *  B  tunnel NOT ready + utp + proxy  → falls to uTP/proxy-associate
 *  C  no tunnel + utp + proxy, v4     → uTP SOCKS UDP ASSOCIATE dial (cfg fwd)
 *  D  no tunnel + utp, no proxy       → raw uTP dial
 *  E  no tunnel, no utp + proxy, v4   → TCP peer through SOCKS5 (greeting)
 *  F  no tunnel, no utp, no proxy     → raw TCP
 *  G1 utp + no proxy, v6              → raw uTP dial (v4 gate removed)
 *  G1b no utp + no proxy, v6           → raw TCP (fallback kept)
 *  G2 utp + proxy, v6                 → uTP through SOCKS5 UDP ASSOCIATE
 *  G2b no utp + proxy, v6              → TCP peer through SOCKS5 ATYP=4
 *  G3 tunnel ready, v6                → tunnel path (family-agnostic)
 *  H  NULL addr                       → -1, no branch entered
 *  I  utp cfg but shared-udp collide → uTP off, proxy still serves TCP peers
 *
 * G1/G1b/G2/G2b depend on an IPv6 loopback stack; if the host lacks one they
 * print SKIP (honest absence, not a pass). The v6 uTP leg is asserted for
 * real whenever ::1 is bindable. */
#include <arpa/inet.h>
#include <errno.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/ui/ntx_diag.c"
#include "../src/net/ntx_netx.c"

static int fails;
static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails = 1;
}

/* ------------------------------------------------------------------ stubs */

/* uTP glue (weak in ntx_netx.c; strong here records the branch taken). */
static int utp_listen_calls;
static int utp_free_calls;
static int utp_dial_calls;      /* raw uTP dial */
static int utp_proxy_dial_calls;/* SOCKS UDP ASSOCIATE dial */
static ntx_addr utp_dial_addr, utp_proxy_dial_addr;
static uint16_t utp_dial_port, utp_proxy_dial_port;
static const ntx_config *utp_proxy_fwd_cfg; /* cfg forwarded to the associate dial */
static char g_utp_store[64];

ntx_utp *ntx_utp_listen(ntx_netx *netx, uint16_t port, ntx_cb_accept accept_cb,
                        void *accept_ctx) {
    (void)netx; (void)accept_cb; (void)accept_ctx;
    utp_listen_calls++;
    (void)port;
    return (ntx_utp *)g_utp_store;
}
void ntx_utp_free(ntx_utp *u) { (void)u; utp_free_calls++; }
int ntx_utp_route_connect(ntx_utp *u, const ntx_addr *addr, uint16_t port,
                          void *ctx, const ntx_cbs *cbs) {
    (void)u; (void)ctx; (void)cbs;
    utp_dial_calls++; utp_dial_addr = *addr; utp_dial_port = port;
    return -(NTX_UTP_VIRT_BASE + 1);
}
int ntx_utp_route_connect_proxy(ntx_utp *u, const ntx_addr *addr,
                                uint16_t port, void *ctx, const ntx_cbs *cbs,
                                const ntx_config *cfg) {
    (void)u; (void)ctx; (void)cbs;
    utp_proxy_dial_calls++;
    utp_proxy_dial_addr = *addr; utp_proxy_dial_port = port;
    utp_proxy_fwd_cfg = cfg;
    return -(NTX_UTP_VIRT_BASE + 2);
}
ssize_t ntx_utp_virt_read(ntx_utp *u, int virt_fd, uint8_t *buf, size_t cap) {
    (void)u; (void)virt_fd; (void)buf; (void)cap; return -1;
}
ssize_t ntx_utp_virt_write(ntx_utp *u, int virt_fd, const uint8_t *buf,
                           size_t n) {
    (void)u; (void)virt_fd; (void)buf; (void)n; return -1;
}
int ntx_utp_virt_connected(ntx_utp *u, int virt_fd) {
    (void)u; (void)virt_fd; return 0;
}
int ntx_utp_bind_fd(ntx_utp *u, int virt_fd, void *ctx, const ntx_cbs *cbs) {
    (void)u; (void)virt_fd; (void)ctx; (void)cbs; return 0;
}
void ntx_utp_virt_close(ntx_utp *u, int virt_fd) {
    (void)u; (void)virt_fd;
}

/* NTX1 tunnel (strong in ntx_tunnel.c — NOT #included here; stubbed). */
#define TNL_SENTINEL (-5000)
static int tnl_connect_calls;
static int tnl_route_calls;
static char tnl_host[64];
static uint16_t tnl_port;
static int tnl_ready_flag = 1;
static ntx_addr tnl_route_addr;
static uint16_t tnl_route_port;
static char g_tnl_store[64];

ntx_tunnel *ntx_tunnel_connect(ntx_netx *netx, const char *host,
                               uint16_t port) {
    (void)netx;
    tnl_connect_calls++;
    snprintf(tnl_host, sizeof tnl_host, "%s", host ? host : "");
    tnl_port = port;
    return (ntx_tunnel *)g_tnl_store;
}
void ntx_tunnel_free(ntx_tunnel *t) { (void)t; }
int ntx_tunnel_ready(const ntx_tunnel *t) { (void)t; return tnl_ready_flag; }
int ntx_tunnel_route_connect(ntx_tunnel *t, const ntx_addr *addr,
                             uint16_t port, void *ctx, const ntx_cbs *cbs) {
    (void)t; (void)ctx; (void)cbs;
    tnl_route_calls++;
    tnl_route_addr = *addr; tnl_route_port = port;
    return TNL_SENTINEL;
}
ssize_t ntx_tunnel_virt_read(ntx_tunnel *t, int virt_fd, uint8_t *buf,
                             size_t cap) {
    (void)t; (void)virt_fd; (void)buf; (void)cap; return -1;
}
int ntx_tunnel_virt_write(ntx_tunnel *t, int virt_fd, const uint8_t *buf,
                          size_t n) {
    (void)t; (void)virt_fd; (void)buf; (void)n; return -1;
}
int ntx_tunnel_virt_connected(ntx_tunnel *t, int virt_fd) {
    (void)t; (void)virt_fd; return 0;
}

static void reset_recorders(void) {
    utp_listen_calls = utp_free_calls = 0;
    utp_dial_calls = utp_proxy_dial_calls = 0;
    utp_proxy_fwd_cfg = NULL;
    tnl_connect_calls = tnl_route_calls = 0;
    tnl_host[0] = '\0'; tnl_port = 0;
    tnl_ready_flag = 1;
}

/* ------------------------------------------------------------- socket util */

static int listen_v4(uint16_t *port_out) {
    int fd = ntx_sock_tcp4();
    if (fd < 0) return -1;
    uint16_t p = ntx_sock_bind0(fd);
    if (p == 0 || ntx_sock_listen(fd, 16) < 0) { close(fd); return -1; }
    *port_out = p;
    return fd;
}

static int v6_available(void) {
    int fd = socket(AF_INET6, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    sa.sin6_addr = in6addr_loopback;
    int ok = bind(fd, (const struct sockaddr *)&sa, sizeof sa) == 0 &&
           listen(fd, 4) == 0;
    close(fd);
    return ok;
}

static int listen_v6(uint16_t *port_out) {
    int fd = ntx_sock_tcp6();
    if (fd < 0) return -1;
    uint16_t p = ntx_sock_bind6(fd, 0);
    if (p == 0 || ntx_sock_listen(fd, 16) < 0) { close(fd); return -1; }
    *port_out = p;
    return fd;
}

/* Accept only if a connection is already pending (poll-bounded: a loopback
 * SYN that will arrive, arrives in microseconds; absence after the window is
 * a true "no connection" for branch discrimination). */
static int poll_accept(int lfd, int ms) {
    struct pollfd pf = { lfd, POLLIN, 0 };
    int pr = poll(&pf, 1, ms);
    if (pr < 0 && errno == EINTR) pr = poll(&pf, 1, ms);
    if (pr <= 0) return -1;
    return ntx_sock_accept4(lfd);
}

static int recv_bounded(int fd, uint8_t *buf, size_t want, int pumps,
                        ntx_netx *n) {
    size_t got = 0;
    for (int i = 0; got < want && i < 40 + pumps * 40; i++) {
        ssize_t r = recv(fd, buf + got, want - got, 0);
        if (r > 0) { got += (size_t)r; continue; }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pf = { fd, POLLIN, 0 };
            if (poll(&pf, 1, 10) > 0) continue;
            if (n) ntx_netx_run_once(n, 10);
            continue;
        }
        return -1;
    }
    return got == want ? (int)got : -1;
}

static void pump_until(int cond_done, ntx_netx *n, int max_iters) {
    for (int i = 0; i < max_iters && !cond_done; i++) ntx_netx_run_once(n, 10);
}

/* app write callback fired by proxy_io_cb when the SOCKS handshake completes */
static int app_w_fired;
static void mark_w(int fd, void *ctx) { (void)fd; *(int *)ctx = 1; }

/* --------------------------------------------------------------- test cfgs */

static uint16_t g_port; /* fixed listen port for every netx instance */

static void fill_cfg(ntx_config *cfg, const char *store) {
    memset(cfg, 0, sizeof *cfg);
    cfg->store_dir = store;
    cfg->port_lo = g_port;
    cfg->port_hi = g_port;
    cfg->max_peers = 8;
}

/* fake SOCKS5 server: a plain loopback listener; the client under test must
 * reach IT (not the target) when the proxy branch is taken. */
typedef struct { int lfd; uint16_t port; } fake_proxy;

/* ------------------------------------------------------------------ cells */

/* A — tunnel ready + --utp + --proxy all set: tunnel wins:
 * breaking the tunnel → uTP/proxy → raw order is a failure). */
static void cell_a_tunnel_precedence(void) {
    reset_recorders();
    fake_proxy fp = { -1, 0 };
    fp.lfd = listen_v4(&fp.port);
    check(fp.lfd >= 0, "A:fake-proxy-listen");

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = fp.port;
    cfg.tunnel = 1; cfg.tunnel_host = "127.0.0.1"; cfg.tunnel_port = 4444;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "A:netx-init");
    if (!n) { close(fp.lfd); return; }

    /* --tunnel=HOST:PORT wiring reaches the tunnel dialer verbatim. */
    check(tnl_connect_calls == 1 && strcmp(tnl_host, "127.0.0.1") == 0 &&
          tnl_port == 4444, "A:tunnel-cfg-forwarded");
    /* uTP is genuinely up (shared socket bound) yet must not intercept. */
    check(n->utp != NULL && n->udp4_fd >= 0, "A:utp-online");

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 6881, NULL, &cbs);
    check(fd == TNL_SENTINEL, "A:tunnel-path-chosen");
    check(tnl_route_calls == 1 && tnl_route_port == 6881 &&
          ntx_addr_eq(&tnl_route_addr, &tgt), "A:tunnel-target-forwarded");
    check(utp_dial_calls == 0 && utp_proxy_dial_calls == 0,
          "A:utp-not-intercepted-despite-flags");
    check(poll_accept(fp.lfd, 60) < 0, "A:no-proxy-tcp-dial");

    ntx_netx_free(n);
    close(fp.lfd);
}

/* B — tunnel configured but NOT ready: falls through to the next priority
 * (uTP/proxy). Pins the ready-gate + the rest of the order. */
static void cell_b_tunnel_not_ready_falls_through(void) {
    reset_recorders();
    tnl_ready_flag = 0;
    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = 9050;
    cfg.tunnel = 1; cfg.tunnel_host = "127.0.0.1"; cfg.tunnel_port = 4444;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "B:netx-init");
    if (!n) return;
    check(n->tunnel != NULL, "B:tunnel-attached");

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 6881, NULL, &cbs);
    check(tnl_route_calls == 0, "B:not-ready-does-not-eat-dial");
    check(fd == -(NTX_UTP_VIRT_BASE + 2) && utp_proxy_dial_calls == 1,
          "B:falls-to-utp-proxy-associate");

    ntx_netx_free(n);
}

/* C — no tunnel, --utp + --proxy: the uTP dial must go through the SOCKS UDP
 * ASSOCIATE path (uTP over SOCKS UDP ASSOCIATE when --utp), and the
 * cfg (proxy host/port) must be forwarded so the associate dial can reach it. */
static void cell_c_utp_rides_socks_associate(void) {
    reset_recorders();
    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = 9051;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "C:netx-init");
    if (!n) return;
    check(n->utp != NULL, "C:utp-online");
    check(tnl_connect_calls == 0, "C:no-tunnel-dial-without-flag");

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 6881, NULL, &cbs);
    check(fd == -(NTX_UTP_VIRT_BASE + 2), "C:associate-dial-returned-virtfd");
    check(utp_proxy_dial_calls == 1 && utp_dial_calls == 0,
          "C:associate-not-silent-raw-utp");
    check(ntx_addr_eq(&utp_proxy_dial_addr, &tgt) &&
          utp_proxy_dial_port == 6881, "C:associate-target-forwarded");
    /* The associate path dials the proxy itself: the cfg must arrive intact. */
    check(utp_proxy_fwd_cfg != NULL && utp_proxy_fwd_cfg->proxy &&
          utp_proxy_fwd_cfg->proxy_port == 9051 &&
          utp_proxy_fwd_cfg->proxy_host &&
          strcmp(utp_proxy_fwd_cfg->proxy_host, "127.0.0.1") == 0,
          "C:associate-cfg-forwarded");

    ntx_netx_free(n);
}

/* D — no tunnel, --utp without --proxy: raw uTP dial (the associate stub must
 * NOT be used; the raw path stays untouched per ntx_utp.h). */
static void cell_d_utp_raw_when_no_proxy(void) {
    reset_recorders();
    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "D:netx-init");
    if (!n) return;
    check(n->utp != NULL, "D:utp-online");

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 6881, NULL, &cbs);
    check(fd == -(NTX_UTP_VIRT_BASE + 1), "D:raw-utp-dial");
    check(utp_dial_calls == 1 && utp_proxy_dial_calls == 0,
          "D:no-associate-without-proxy");
    check(ntx_addr_eq(&utp_dial_addr, &tgt) && utp_dial_port == 6881,
          "D:raw-utp-target-forwarded");

    ntx_netx_free(n);
}

/* E — no tunnel, no --utp, --proxy: TCP peer connects still ride SOCKS5
 * (TCP must not regress). The fake proxy must see the
 * SOCKS greeting; the real target must see nothing. */
static void cell_e_tcp_peer_through_proxy(void) {
    reset_recorders();
    fake_proxy fp = { -1, 0 };
    fp.lfd = listen_v4(&fp.port);
    check(fp.lfd >= 0, "E:fake-proxy-listen");
    uint16_t tport = 0;
    int tlfd = listen_v4(&tport);
    check(tlfd >= 0, "E:target-listen");

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = fp.port;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "E:netx-init");
    if (!n) { close(fp.lfd); close(tlfd); return; }
    check(n->utp == NULL, "E:utp-off");

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, tport, NULL, &cbs);
    check(fd >= 0, "E:proxy-dial-real-fd");

    int pfd = poll_accept(fp.lfd, 200);
    check(pfd >= 0, "E:proxy-accepted-peer-connect");
    uint8_t gw[3];
    int r = recv_bounded(pfd, gw, 3, 20, n);
    check(r == 3 && gw[0] == 0x05 && gw[1] == 0x01 && gw[2] == 0x00,
          "E:socks-greeting-to-proxy");
    check(poll_accept(tlfd, 60) < 0, "E:target-not-directly-dialed");

    if (pfd >= 0) close(pfd);
    close(fd >= 0 ? fd : -1);
    ntx_netx_free(n);
    close(fp.lfd);
    close(tlfd);
}

/* F — nothing configured: raw TCP straight to the target. */
static void cell_f_raw_tcp_default(void) {
    reset_recorders();
    fake_proxy fp = { -1, 0 };
    fp.lfd = listen_v4(&fp.port);
    check(fp.lfd >= 0, "F:fake-proxy-listen");
    uint16_t tport = 0;
    int tlfd = listen_v4(&tport);
    check(tlfd >= 0, "F:target-listen");

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "F:netx-init");
    if (!n) { close(fp.lfd); close(tlfd); return; }

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, tport, NULL, &cbs);
    check(fd >= 0, "F:raw-dial-real-fd");
    int cfd = poll_accept(tlfd, 200);
    check(cfd >= 0, "F:target-accepted-directly");
    uint8_t b[3];
    struct pollfd pf = { cfd, POLLIN, 0 };
    int pr = poll(&pf, 1, 30); /* raw sends nothing before the app writes */
    check(pr == 0 || recv(cfd, b, sizeof b, MSG_PEEK) <= 0,
          "F:raw-sends-no-socks-framing");
    check(poll_accept(fp.lfd, 30) < 0, "F:proxy-untouched");
    check(utp_dial_calls == 0 && utp_proxy_dial_calls == 0 &&
          tnl_route_calls == 0, "F:no-other-branch");

    if (cfd >= 0) close(cfd);
    if (fd >= 0) close(fd);
    ntx_netx_free(n);
    close(fp.lfd);
    close(tlfd);
}

/* G1 — --utp without --proxy, v6 target: the v4-only hard gate at
 * route_connect is gone, so a v6 peer is routed to the uTP dial (the AF_INET6
 * sibling of the shared owner) instead of falling through to raw TCP. The
 * raw branch must therefore NOT be taken any more — no TCP reaches the target. */
static void cell_g1_v6_routes_to_utp(void) {
    if (!v6_available()) { printf("SKIP G1 (no ipv6 loopback)\n"); return; }
    reset_recorders();
    uint16_t tport = 0;
    int tlfd = listen_v6(&tport);
    check(tlfd >= 0, "G1:v6-target-listen");
    if (tlfd < 0) return;

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "G1:netx-init");
    if (!n) { close(tlfd); return; }
    check(n->utp != NULL, "G1:utp-online");

    uint8_t v6[16] = { 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    ntx_addr tgt; ntx_addr_set_v6(&tgt, v6);
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, tport, NULL, &cbs);
    check(utp_dial_calls == 1 && utp_proxy_dial_calls == 0,
          "G1:v6-routes-to-utp-dial");
    check(ntx_addr_eq(&utp_dial_addr, &tgt) && utp_dial_port == tport,
          "G1:utp-dial-carries-v6-target");
    check(fd <= -NTX_UTP_VIRT_BASE, "G1:v6-utp-virt-fd");
    int cfd = poll_accept(tlfd, 200);
    check(cfd < 0, "G1:v6-no-raw-tcp-fallback");

    if (cfd >= 0) close(cfd);
    if (fd >= 0) close(fd);
    ntx_netx_free(n);
    close(tlfd);
}

/* G1b — the other half of the v6 routing: with --utp OFF a v6 peer still
 * reaches raw TCP. Removing the gate must not have swallowed the fallback that every v6-only
 * swarm outside BEP29 depends on. */
static void cell_g1b_v6_raw_when_utp_off(void) {
    if (!v6_available()) { printf("SKIP G1b (no ipv6 loopback)\n"); return; }
    reset_recorders();
    uint16_t tport = 0;
    int tlfd = listen_v6(&tport);
    check(tlfd >= 0, "G1b:v6-target-listen");
    if (tlfd < 0) return;

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 0;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "G1b:netx-init");
    if (!n) { close(tlfd); return; }

    uint8_t v6[16] = { 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    ntx_addr tgt; ntx_addr_set_v6(&tgt, v6);
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, tport, NULL, &cbs);
    check(utp_dial_calls == 0 && utp_proxy_dial_calls == 0,
          "G1b:v6-utp-branch-not-entered");
    check(fd >= 0, "G1b:v6-raw-dial");
    int cfd = poll_accept(tlfd, 200);
    check(cfd >= 0, "G1b:v6-target-accepted");

    if (cfd >= 0) close(cfd);
    if (fd >= 0) close(fd);
    ntx_netx_free(n);
    close(tlfd);
}

/* G2 — --utp + --proxy, v6 target: the uTP/SOCKS5 UDP ASSOCIATE branch now
 * carries a v6 DST too (RFC1928 §7 ATYP=0x04, already spoken by
 * ntx_proxy_udp_encap), so that is the branch route_connect picks. G2b then
 * pins the *other* half of the same pair: with --utp off the very same v6
 * endpoint must still travel through the SOCKS5 TCP CONNECT as ATYP=4. */
static void cell_g2_v6_tcp_through_proxy(void) {
    if (!v6_available()) { printf("SKIP G2 (no ipv6 loopback)\n"); return; }
    reset_recorders();
    fake_proxy fp = { -1, 0 };
    fp.lfd = listen_v4(&fp.port);
    check(fp.lfd >= 0, "G2:fake-proxy-listen");
    if (fp.lfd < 0) return;

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = fp.port;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "G2:netx-init");
    if (!n) { close(fp.lfd); return; }
    check(n->utp != NULL, "G2:utp-online");

    uint8_t v6[16] = { 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01 };
    ntx_addr tgt; ntx_addr_set_v6(&tgt, v6);
    app_w_fired = 0;
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    cbs.w = mark_w;
    int fd = ntx_netx_route_connect(n, &tgt, 6881, &app_w_fired, &cbs);
    check(fd == -(NTX_UTP_VIRT_BASE + 2) && utp_proxy_dial_calls == 1 &&
              utp_dial_calls == 0, "G2:v6-routes-to-utp-associate");
    check(ntx_addr_eq(&utp_proxy_dial_addr, &tgt) && utp_proxy_dial_port == 6881 &&
              utp_proxy_fwd_cfg == &cfg, "G2:associate-carries-v6-dst-and-cfg");
    if (fd >= 0) close(fd);
    ntx_netx_free(n);

    /* G2b — same target, --utp off: the TCP CONNECT path must still deliver a
     * v6 DST as ATYP=4 with the right bytes on the wire. */
    reset_recorders();
    cfg.utp = 0;
    ntx_netx *np = ntx_netx_init(&cfg);
    check(np != NULL, "G2b:netx-init");
    if (!np) { close(fp.lfd); return; }
    app_w_fired = 0;
    fd = ntx_netx_route_connect(np, &tgt, 6881, &app_w_fired, &cbs);
    check(fd >= 0, "G2b:proxy-dial-real-fd");
    check(utp_dial_calls == 0 && utp_proxy_dial_calls == 0,
          "G2b:v6-not-swallowed-by-utp-when-off");

    int pfd = poll_accept(fp.lfd, 200);
    check(pfd >= 0, "G2:proxy-accepted");
    if (pfd >= 0) {
        uint8_t gw[3];
        check(recv_bounded(pfd, gw, 3, 20, np) == 3 &&
              gw[0] == 0x05 && gw[1] == 0x01 && gw[2] == 0x00,
              "G2:socks-greeting");
        uint8_t am[2] = { 0x05, 0x00 };
        ssize_t s = send(pfd, am, 2, MSG_NOSIGNAL);
        check(s == 2, "G2:method-reply-sent");
        uint8_t aq[22];
        check(recv_bounded(pfd, aq, 22, 40, np) == 22, "G2:connect-request-22B");
        check(aq[0] == 0x05 && aq[1] == 0x01 && aq[2] == 0x00 &&
              aq[3] == 0x04, "G2:connect-v6-atyp4");
        check(memcmp(aq + 4, v6, 16) == 0 && aq[19] == 0x01,
              "G2:connect-v6-addr");
        check(aq[20] == 0x1A && aq[21] == 0xE1, "G2:connect-v6-port");
        uint8_t ar[22];
        memset(ar, 0, sizeof ar);
        ar[0] = 0x05; ar[1] = 0x00; ar[3] = 0x04;
        s = send(pfd, ar, 22, MSG_NOSIGNAL);
        check(s == 22, "G2:connect-reply-sent");
        pump_until(app_w_fired, np, 200);
        check(app_w_fired == 1, "G2:proxy-connect-completed-app-notified");
        close(pfd);
    }
    if (fd >= 0) close(fd);
    ntx_netx_free(np);
    close(fp.lfd);
}

/* G3 — tunnel ready, v6 target: the tunnel is family-agnostic (OPEN_V6 cmd=3
 * in ntx_tunnel.c), so --tunnel keeps priority for v6 peers too. */
static void cell_g3_tunnel_serves_v6(void) {
    reset_recorders();
    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = 9052;
    cfg.tunnel = 1; cfg.tunnel_host = "127.0.0.1"; cfg.tunnel_port = 4444;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "G3:netx-init");
    if (!n) return;

    uint8_t v6[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                        0, 0, 0, 0, 0, 0, 0, 0x01 };
    ntx_addr tgt; ntx_addr_set_v6(&tgt, v6);
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 6881, NULL, &cbs);
    check(fd == TNL_SENTINEL && tnl_route_calls == 1, "G3:tunnel-wins-for-v6");
    check(ntx_addr_eq(&tnl_route_addr, &tgt), "G3:tunnel-v6-target");
    check(utp_dial_calls == 0 && utp_proxy_dial_calls == 0,
          "G3:v6-not-via-utp-or-proxy");

    ntx_netx_free(n);
}

/* H — NULL addr is rejected before any branch. */
static void cell_h_null_addr(void) {
    reset_recorders();
    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = 9053;
    cfg.tunnel = 1; cfg.tunnel_host = "127.0.0.1"; cfg.tunnel_port = 4444;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "H:netx-init");
    if (!n) return;
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    check(ntx_netx_route_connect(n, NULL, 1, NULL, &cbs) == -1, "H:null-rejected");
    check(tnl_route_calls == 0 && utp_dial_calls == 0 &&
          utp_proxy_dial_calls == 0, "H:no-branch-on-null");
    ntx_netx_free(n);
}

/* I — --utp + --proxy but the shared UDP owner could not bind (external
 * occupant): uTP is off fail-soft and the TCP-peer proxy path MUST still be
 * wired (the "--utp interaction must not silently drop proxy egress" guard). */
static void cell_i_utp_off_proxy_still_serves(void) {
    reset_recorders();
    /* Hold the UDP side of the listen port so netx's shared owner collides. */
    int hold = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    check(hold >= 0, "I:hold-socket");
    if (hold < 0) return;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(g_port);
    check(bind(hold, (const struct sockaddr *)&sa, sizeof sa) == 0,
          "I:hold-udp-port");

    fake_proxy fp = { -1, 0 };
    fp.lfd = listen_v4(&fp.port);
    check(fp.lfd >= 0, "I:fake-proxy-listen");

    ntx_config cfg; fill_cfg(&cfg, "test/.scratch/19/store");
    cfg.utp = 1;
    cfg.proxy = 1; cfg.proxy_host = "127.0.0.1"; cfg.proxy_port = fp.port;
    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "I:netx-init");
    if (!n) { close(hold); close(fp.lfd); return; }
    check(n->utp == NULL && n->udp4_fd == -1, "I:utp-off-failsoft");

    ntx_addr tgt; ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs; memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 6881, NULL, &cbs);
    check(utp_dial_calls == 0 && utp_proxy_dial_calls == 0,
          "I:no-utp-intercept-when-off");
    check(fd >= 0, "I:proxy-dial-real-fd");
    int pfd = poll_accept(fp.lfd, 200);
    uint8_t gw[3];
    check(pfd >= 0 && recv_bounded(pfd, gw, 3, 20, n) == 3 &&
          gw[0] == 0x05 && gw[1] == 0x01 && gw[2] == 0x00,
          "I:socks-greeting-despite-utp-off");

    if (pfd >= 0) close(pfd);
    if (fd >= 0) close(fd);
    ntx_netx_free(n);
    close(fp.lfd);
    close(hold);
}

int main(void) {
    g_port = 6980;
    cell_a_tunnel_precedence();
    cell_b_tunnel_not_ready_falls_through();
    cell_c_utp_rides_socks_associate();
    cell_d_utp_raw_when_no_proxy();
    cell_e_tcp_peer_through_proxy();
    cell_f_raw_tcp_default();
    cell_g1_v6_routes_to_utp();
    cell_g1b_v6_raw_when_utp_off();
    cell_g2_v6_tcp_through_proxy();
    cell_g3_tunnel_serves_v6();
    cell_h_null_addr();
    cell_i_utp_off_proxy_still_serves();
    if (!fails) printf("PASS egress-route-matrix\n");
    else printf("FAIL egress-route-matrix\n");
    return fails ? 1 : 0;
}
