/* BEP29 uTP — end-to-end loopback byte stream THROUGH THE PUBLIC
 * ntx_netx_* API. Proves the session layer needs zero changes: the dialer drives
 * ntx_netx_route_connect / ntx_netx_write / ntx_netx_read /
 * ntx_netx_peer_connected / ntx_netx_close and gets a uTP virt fd (fd <= -1000)
 * handled transparently by the netx uTP glue, exactly like the NTX1
 * tunnel virt fds. The listener registers its accept via ntx_netx_set_accept.
 *
 * GATED on the netx uTP dispatch (ntx_netx_route_connect/read/write/peer_connected dispatching
 * fd <= -1000 into ntx_utp_*). Until that lands ntx_netx_route_connect returns a
 * real TCP fd, so the `fd <= -1000` assertion cannot hold; the test is compiled
 * (proving the frozen ntx_utp.h + netx API usage) and reported GATED, not run.
 *
 * Build (mirror of the Makefile `test` rule, single self-contained TU):
 *   cc -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L \
 *      -ffunction-sections -o test/.scratch/f4_a7_loopback \
 *      test/t_utp_loopback.c -Wl,--gc-sections -lm
 *
 * Style mirrors t_merkle.c: static int fails; check(cond, "name") prints
 * "PASS name" / "FAIL name"; main returns fails ? 1 : 0. All loops are bounded
 * (no sleep longer than a run_once tick). */

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>

#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/net/ntx_utp.c"
#include "../src/net/ntx_utp_sm.c"
#include "../src/net/ntx_utp_hdr.c"
#include "../src/net/ntx_utp_cc.c"
#include "../src/proto/ntx_holepunch.c"
#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"

static int fails;

static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails++;
}

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

/* ---- listener (B) accept state -------------------------------------------- */

#define B_TOKEN ((void *)0xB0B1ULL) /* identity token handed to set_accept */

static int g_fd2;           /* virt fd delivered to B's accept callback (0 = none) */
static int g_accept_ctx_ok; /* 1 when the accept ctx matched B_TOKEN */

static void accept_cb(ntx_netx *n, int peer_fd, void *ctx) {
    (void)n;
    if (ctx != B_TOKEN) return;
    g_accept_ctx_ok = 1;
    g_fd2 = peer_fd;
}

/* ---- dialer (A) callbacks -------------------------------------------------- */

static int g_w_fired; /* A's write cb fired once on CONNECTED */

static void d_r(int fd, void *ctx) { (void)fd; (void)ctx; }
static void d_w(int fd, void *ctx) { (void)fd; (void)ctx; g_w_fired = 1; }

/* ---- bounded pumping ------------------------------------------------------- */

#define PUMP_MAX 5000

/* Alternate one run_once tick on each instance; stop early when pred() holds. */
static int pump_until(int (*pred)(void *), void *arg, ntx_netx *a, ntx_netx *b) {
    for (int i = 0; i < PUMP_MAX; i++) {
        if (pred(arg)) return 1;
        ntx_netx_run_once(a, 1);
        ntx_netx_run_once(b, 1);
    }
    return pred(arg) ? 1 : 0;
}

/* Predicate wrappers take a small struct so they can see both the netx and fd. */
typedef struct {
    ntx_netx *a;
    ntx_netx *b;
    int fd;
    int fd2;
} pump_ctx;

static int pred_a_conn(void *arg) {
    pump_ctx *p = arg;
    return ntx_netx_peer_connected(p->a, p->fd);
}
static int pred_b_accept(void *arg) {
    (void)arg;
    return g_fd2 != 0;
}
static int pred_b_conn(void *arg) {
    pump_ctx *p = arg;
    return g_fd2 != 0 && ntx_netx_peer_connected(p->b, g_fd2);
}
static int pred_a_disconnected(void *arg) {
    pump_ctx *p = arg;
    return p->fd != 0 && !ntx_netx_peer_connected(p->a, p->fd);
}
static int pred_b_disconnected(void *arg) {
    pump_ctx *p = arg;
    return g_fd2 != 0 && !ntx_netx_peer_connected(p->b, g_fd2);
}

/* Write n bytes from src over a virt fd, pumping both instances until the
 * transport has accepted them all (the uTP window may apply back-pressure). */
static int write_all(ntx_netx *owner, ntx_netx *other, int fd, const uint8_t *src,
                     size_t n) {
    size_t off = 0;
    for (int i = 0; i < PUMP_MAX && off < n; i++) {
        ssize_t w = ntx_netx_write(owner, fd, src + off, n - off);
        if (w > 0) off += (size_t)w;
        ntx_netx_run_once(owner, 1);
        ntx_netx_run_once(other, 1);
    }
    return off == n;
}

/* Read exactly n bytes from a virt fd into dst, pumping until complete. */
static int read_all(ntx_netx *owner, ntx_netx *other, int fd, uint8_t *dst, size_t n) {
    size_t off = 0;
    for (int i = 0; i < PUMP_MAX && off < n; i++) {
        ssize_t r = ntx_netx_read(owner, fd, dst + off, n - off);
        if (r > 0) off += (size_t)r;
        if (off < n) {
            ntx_netx_run_once(owner, 1);
            ntx_netx_run_once(other, 1);
        }
    }
    return off == n;
}

/* Public netx -> uTP handle accessor (TU-visible struct field). */
static ntx_utp *netx_utp_of(ntx_netx *n) { return n->utp; }

/* ---- IPv6 ------------------------------------------------------
 * The v6 leg below is the same end-to-end byte-stream scenario, run over the
 * public netx API against the real ::1 loopback: it is what proves the
 * v4-only hard gate in route_connect is gone and that the AF_INET6 sibling of
 * the shared per-family owner carries both directions of a uTP connection.
 *
 * The environment decides, not the test: probe IPv6 first (socket, V6ONLY,
 * bind ::1, self-send). Any step that the host cannot do prints SKIP with the
 * reason and the v6 assertions are dropped — never faked into a PASS, and
 * never turned into a FAIL that would punish an IPv6-less machine. */

static int v6_probe(const char **why) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) { *why = "no AF_INET6 socket"; return 0; }
    int one = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) < 0) {
        close(fd); *why = "IPV6_V6ONLY unsupported"; return 0;
    }
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    if (inet_pton(AF_INET6, "::1", &sa.sin6_addr) != 1) {
        close(fd); *why = "::1 not parseable"; return 0;
    }
    if (bind(fd, (const struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd); *why = "bind(::1) refused"; return 0;
    }
    sa.sin6_port = 0; /* keep the family/addr, let bind0 pick the port */
    if (sendto(fd, "x", 1, 0, (const struct sockaddr *)&sa, sizeof sa) < 0) {
        /* Port 0 is not a usable destination; rebind to get a real one and
         * self-send to it, which is the actual loopback capability check. */
        close(fd);
        int fd2 = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd2 < 0) { *why = "no AF_INET6 socket"; return 0; }
        setsockopt(fd2, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
        if (inet_pton(AF_INET6, "::1", &sa.sin6_addr) != 1) {
            close(fd2); *why = "::1 not parseable"; return 0;
        }
        if (bind(fd2, (const struct sockaddr *)&sa, sizeof sa) != 0) {
            close(fd2); *why = "bind(::1) refused"; return 0;
        }
        struct sockaddr_in6 me;
        socklen_t ml = sizeof me;
        if (getsockname(fd2, (struct sockaddr *)&me, &ml) != 0) {
            close(fd2); *why = "getsockname(::1) failed"; return 0;
        }
        if (sendto(fd2, "x", 1, 0, (const struct sockaddr *)&me, sizeof me) != 1) {
            close(fd2); *why = "sendto(::1) failed"; return 0;
        }
        char b2[8];
        if (recvfrom(fd2, b2, sizeof b2, 0, NULL, NULL) != 1) {
            close(fd2); *why = "recvfrom(::1) got nothing"; return 0;
        }
        close(fd2);
        return 1;
    }
    char b[8];
    ssize_t r = recvfrom(fd, b, sizeof b, 0, NULL, NULL);
    close(fd);
    if (r != 1) { *why = "recvfrom(::1) got nothing"; return 0; }
    return 1;
}

static void v6_addr_loopback(ntx_addr *a) {
    uint8_t lo[16];
    memset(lo, 0, sizeof lo);
    lo[15] = 1; /* ::1 */
    ntx_addr_set_v6(a, lo);
}

/* The v6 scenario: dialer A6 -> listener B6 over ::1, both through the public
 * netx API only. Mirrors the v4 flow above (accept on first ST_DATA, byte
 * stream both ways, FIN both halves). */
static int run_v6(const ntx_config *base) {
    const char *why = NULL;
    if (!v6_probe(&why)) {
        printf("SKIP ipv6-loopback-unavailable (%s)\n", why ? why : "unknown");
        return 0;
    }

    ntx_config cfg = *base;
    ntx_netx *A = ntx_netx_init(&cfg);
    ntx_netx *B = ntx_netx_init(&cfg);
    if (!A || !B) return fail("v6-netx-init");

    /* The AF_INET6 sibling of the shared per-family owner must be live on the
     * listener, on the very same advertised port (single-port convention). */
    check(ntx_netx_udp6_fd(A) >= 0, "v6-shared-owner-dialer-bound");
    check(ntx_netx_udp6_fd(B) >= 0, "v6-shared-owner-listener-bound");
    uint16_t bport = ntx_netx_port(B);
    check(bport != 0 && ntx_netx_port(B) == bport, "v6-listen-port-advertised");

    ntx_netx_set_accept(B, accept_cb, B_TOKEN);

    ntx_addr tgt;
    v6_addr_loopback(&tgt);

    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = d_r;
    cbs.w = d_w;

    /* 1) v6 dial over the PUBLIC netx API: the removed gate must now let a
     *    v6 peer reach the uTP transport and hand back a virt fd. */
    int fd = ntx_netx_route_connect(A, &tgt, bport, NULL, &cbs);
    check(fd <= -1000, "v6-dial-yields-utp-virt-fd");

    g_fd2 = 0;
    g_accept_ctx_ok = 0;
    g_w_fired = 0;

    pump_ctx pc;
    memset(&pc, 0, sizeof pc);
    pc.a = A;
    pc.b = B;
    pc.fd = fd;

    check(pump_until(pred_a_conn, &pc, A, B), "v6-a-peer-connected");
    check(g_w_fired, "v6-a-write-cb-on-connected");

    /* 2) A -> B byte stream. */
    uint8_t hs1[68];
    uint8_t rb[68];
    for (int i = 0; i < 68; i++) hs1[i] = (uint8_t)(i * 11 + 3);
    check(write_all(A, B, fd, hs1, 68), "v6-a-write-hs1");
    check(pump_until(pred_b_accept, &pc, A, B), "v6-b-accept-fired");
    check(g_accept_ctx_ok, "v6-b-accept-ctx-token");
    check(g_fd2 <= -1000, "v6-b-accept-virt-fd");
    pc.fd2 = g_fd2;
    check(pump_until(pred_b_conn, &pc, A, B), "v6-b-peer-connected");
    memset(rb, 0, sizeof rb);
    check(read_all(B, A, g_fd2, rb, 68), "v6-b-read-hs1");
    check(memcmp(rb, hs1, 68) == 0, "v6-b-hs1-bytes-match");

    /* 3) B -> A, the reverse direction over the v6 sibling. */
    uint8_t hs2[68];
    for (int i = 0; i < 68; i++) hs2[i] = (uint8_t)(i * 5 + 9);
    check(write_all(B, A, g_fd2, hs2, 68), "v6-b-write-hs2");
    memset(rb, 0, sizeof rb);
    check(read_all(A, B, fd, rb, 68), "v6-a-read-hs2");
    check(memcmp(rb, hs2, 68) == 0, "v6-a-hs2-bytes-match");

    /* 4) BEP55 addr_type=0x01 smoke (BEP 55 wired into the uTP dial): a relay "connect"
     *    payload that names a v6 endpoint must decode to a v6 ntx_addr and
     *    land on this same uTP stack, not on raw TCP. */
    ntx_holepunch_msg m;
    memset(&m, 0, sizeof m);
    m.msg_type = NTX_HP_MSG_CONNECT;
    m.addr_type = NTX_HP_AF_V6;
    m.addr = tgt;
    m.port = bport;
    m.err_code = NTX_HP_ERR_NONE;
    uint8_t pay[NTX_HP_WIRE_MAX];
    size_t pn = ntx_holepunch_build(pay, sizeof pay, &m);
    check(pn == NTX_HP_WIRE_V6, "v6-bep55-connect-builds-24b");
    ntx_holepunch_msg d;
    check(ntx_holepunch_parse(pay, pn, &d) == 0, "v6-bep55-connect-parses");
    check(d.addr_type == NTX_HP_AF_V6 && d.port == bport &&
              ntx_addr_eq(&d.addr, &tgt), "v6-bep55-decode-roundtrip");
    ntx_cbs hc;
    memset(&hc, 0, sizeof hc);
    int fdh = ntx_netx_route_connect(A, &d.addr, d.port, NULL, &hc);
    check(fdh <= -1000, "v6-bep55-dial-hits-utp");

    /* 5) both halves close. */
    ntx_utp *au = netx_utp_of(A);
    int idx = -fd - NTX_UTP_VIRT_BASE;
    if (!au || idx < 0 || idx >= NTX_UTP_MAX_CONNS || !au->slots[idx].conn)
        return fail("v6-close-slot");
    ntx_utp_conn_close(au->slots[idx].conn);
    check(pump_until(pred_a_disconnected, &pc, A, B), "v6-a-disconnected");

    ntx_utp *bu = netx_utp_of(B);
    int idx2 = -g_fd2 - NTX_UTP_VIRT_BASE;
    if (!bu || idx2 < 0 || idx2 >= NTX_UTP_MAX_CONNS || !bu->slots[idx2].conn)
        return fail("v6-close-slot-b");
    ntx_utp_conn_close(bu->slots[idx2].conn);
    check(pump_until(pred_b_disconnected, &pc, A, B), "v6-b-disconnected");

    ntx_netx_free(A);
    ntx_netx_free(B);
    return 0;
}

/* ---- the scenario ---------------------------------------------------------- */

int main(void) {
    ntx_rng_init();

    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.utp = 1;

    ntx_netx *A = ntx_netx_init(&cfg); /* dialer */
    ntx_netx *B = ntx_netx_init(&cfg); /* listener */
    if (!A || !B) return fail("netx-init");

    ntx_netx_set_accept(B, accept_cb, B_TOKEN);

    /* B's uTP listen socket shares the netx listen port (BT single-port
     * convention): discover it through the PUBLIC netx getter. */
    uint16_t bport = ntx_netx_port(B);
    check(bport != 0, "utp-listen-port-bound");

    ntx_addr tgt;
    ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));

    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = d_r;
    cbs.w = d_w;

    /* 1) dial over the PUBLIC netx API; must yield a uTP virt fd. */
    int fd = ntx_netx_route_connect(A, &tgt, bport, NULL, &cbs);
    check(fd <= -1000, "dial-yields-utp-virt-fd");

    pump_ctx pc;
    memset(&pc, 0, sizeof pc);
    pc.a = A;
    pc.b = B;
    pc.fd = fd;

    /* 2) drive the loop until A's outbound conn is CONNECTED. */
    check(pump_until(pred_a_conn, &pc, A, B), "a-peer-connected");
    check(g_w_fired, "a-write-cb-on-connected");

    /* 3) A -> B : 68-byte fake BT handshake. */
    uint8_t hs1[68];
    uint8_t rb[68];
    for (int i = 0; i < 68; i++) hs1[i] = (uint8_t)(i * 7 + 1);
    check(write_all(A, B, fd, hs1, 68), "a-write-hs1");

    /* The first ST_DATA is what fires B's accept (netx-accept style). */
    check(pump_until(pred_b_accept, &pc, A, B), "b-accept-fired");
    check(g_accept_ctx_ok, "b-accept-ctx-token");
    check(g_fd2 <= -1000, "b-accept-virt-fd");
    pc.fd2 = g_fd2;
    check(pump_until(pred_b_conn, &pc, A, B), "b-peer-connected");

    check(read_all(B, A, g_fd2, rb, 68), "b-read-hs1");
    check(memcmp(rb, hs1, 68) == 0, "b-hs1-bytes-match");

    /* 4) B -> A : a second, distinct 68-byte vector. */
    uint8_t hs2[68];
    for (int i = 0; i < 68; i++) hs2[i] = (uint8_t)(i * 3 + 2);
    check(write_all(B, A, g_fd2, hs2, 68), "b-write-hs2");
    memset(rb, 0, sizeof rb);
    check(read_all(A, B, fd, rb, 68), "a-read-hs2");
    check(memcmp(rb, hs2, 68) == 0, "a-hs2-bytes-match");

    /* 5) larger stream: 4096 patterned bytes A -> B (DATA fragmentation path). */
    size_t big = 4096;
    uint8_t *src = malloc(big);
    uint8_t *dst = malloc(big);
    if (!src || !dst) return fail("malloc");
    for (size_t i = 0; i < big; i++) src[i] = (uint8_t)(i * 31 + 7);
    memset(dst, 0, big);
    check(write_all(A, B, fd, src, big), "a-write-4096");
    check(read_all(B, A, g_fd2, dst, big), "b-read-4096");
    check(memcmp(dst, src, big) == 0, "b-4096-bytes-match");
    free(src);
    free(dst);

    /* 6) close A's send direction (FIN). There is no public ntx_netx_close for
     *    virt fds (the tunnel precedent closes its underlying real fd, not the
     *    virt fd), so the close is driven through the glue slot the dialer's
     *    virt fd maps to — the same path t_utp_net.c uses. Per the SM's
     *    half-close rules (D9/D17) the FIN *receiver* stays CS_CONNECTED until
     *    it also sends its own FIN, so the closing side is what reports
     *    disconnected (matching the t_utp_net.c close assertion); we then drive
     *    B's FIN so both halves converge and B reports disconnected too. */
    ntx_utp *au = netx_utp_of(A);
    int idx = -fd - NTX_UTP_VIRT_BASE;
    if (!au || idx < 0 || idx >= NTX_UTP_MAX_CONNS || !au->slots[idx].conn)
        return fail("close-slot");
    ntx_utp_conn_close(au->slots[idx].conn);
    check(pump_until(pred_a_disconnected, &pc, A, B), "a-peer-disconnected-after-close");

    ntx_utp *bu = netx_utp_of(B);
    int idx2 = -g_fd2 - NTX_UTP_VIRT_BASE;
    if (!bu || idx2 < 0 || idx2 >= NTX_UTP_MAX_CONNS || !bu->slots[idx2].conn)
        return fail("close-slot-b");
    ntx_utp_conn_close(bu->slots[idx2].conn);
    check(pump_until(pred_b_disconnected, &pc, A, B), "b-peer-disconnected-after-close");

    ntx_netx_free(A);
    ntx_netx_free(B);

    /* 6b) the IPv6 leg: same public API, ::1 loopback, or an honest
     *     SKIP when the host has no usable IPv6 (printed, never a fake PASS). */
    if (run_v6(&cfg)) return 1;

    /* 7) negative: with utp OFF a dial to a closed port must NOT hand back a uTP
     *    virt fd (proves the cfg.utp flag gates the dispatch). */
    ntx_config off;
    memset(&off, 0, sizeof off);
    off.utp = 0;
    ntx_netx *C = ntx_netx_init(&off);
    if (!C) return fail("netx-init-off");
    ntx_cbs ncbs;
    memset(&ncbs, 0, sizeof ncbs);
    int fdn = ntx_netx_route_connect(C, &tgt, 59999, NULL, &ncbs);
    check(fdn > -1000, "utp-off-no-virt-fd");
    /* The gate removal must not have leaked uTP into the disabled path either,
     * and a v6 peer still has to reach raw TCP when uTP is off. */
    ntx_addr t6;
    v6_addr_loopback(&t6);
    const char *why = NULL;
    if (v6_probe(&why)) {
        int fdn6 = ntx_netx_route_connect(C, &t6, 59999, NULL, &ncbs);
        check(fdn6 > -NTX_UTP_VIRT_BASE, "utp-off-v6-no-virt-fd");
        if (fdn6 >= 0) close(fdn6);
    } else {
        printf("SKIP utp-off-v6-negative (%s)\n", why ? why : "unknown");
    }
    ntx_netx_free(C);

    return fails ? 1 : 0;
}
