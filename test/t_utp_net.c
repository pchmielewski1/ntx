/* GATED: links the uTP state machine (src/net/ntx_utp_sm.c), which lands in
 * parallel with this netx glue. Do not run until the SM is present; the gate
 * compiles the whole TU (glue + SM + netx/tunnel stack) on real UDP loopback.
 *
 * What it proves: ntx_utp_listen binds a UDP socket on the netx loop, inbound
 * SYN demux allocates a conn, outbound route_connect initiates a conn, and the
 * two endpoints exchange payload over the virt fds in both directions, then
 * close. Mirrors the NTX1 tunnel virt-fd pattern (fd < 0). */

#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>
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
#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"

static int g_fd2; /* virt fd delivered to u2's accept callback */

static void accept_cb_1(ntx_netx *n, int peer_fd, void *ctx) {
    (void)n;
    (void)peer_fd;
    (void)ctx;
}

/* Virt fds are per ntx_utp instance (own slot tables), so the numeric value
 * of u2's accepted fd may equal u1's outbound fd. Instance identity is
 * proven by the accept_ctx token instead. */
#define U2_TOKEN ((void *)0x51ULL)

static void accept_cb_2(ntx_netx *n, int peer_fd, void *ctx) {
    (void)n;
    if (ctx != U2_TOKEN) return;
    g_fd2 = peer_fd;
}

static uint64_t mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int g_fails;
static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) g_fails++;
}

/* ---- IPv6 ------------------------------------------------------
 * Standalone-mode dual-stack: ntx_utp_listen also binds the AF_INET6 sibling,
 * so a listener reached over ::1 is the same engine, same slot table, same
 * virt-fd contract. The host decides whether the leg runs at all — a machine
 * without usable IPv6 gets a printed SKIP and zero assertions, never a PASS
 * that was not proven and never a FAIL that punishes the platform. */
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
    struct sockaddr_in6 me;
    socklen_t ml = sizeof me;
    if (getsockname(fd, (struct sockaddr *)&me, &ml) != 0) {
        close(fd); *why = "getsockname(::1) failed"; return 0;
    }
    if (sendto(fd, "x", 1, 0, (const struct sockaddr *)&me, sizeof me) != 1) {
        close(fd); *why = "sendto(::1) failed"; return 0;
    }
    char b[8];
    if (recvfrom(fd, b, sizeof b, 0, NULL, NULL) != 1) {
        close(fd); *why = "recvfrom(::1) got nothing"; return 0;
    }
    close(fd);
    return 1;
}

static void v6_loopback(ntx_addr *a) {
    uint8_t lo[16];
    memset(lo, 0, sizeof lo);
    lo[15] = 1;
    ntx_addr_set_v6(a, lo);
}

static int g_v6_fd2;
#define V6_TOKEN ((void *)0xBEEF5ULL)

static void accept_cb_v6(ntx_netx *n, int peer_fd, void *ctx) {
    (void)n;
    if (ctx != V6_TOKEN) return;
    g_v6_fd2 = peer_fd;
}

/* u3 -> u4 over ::1, both standalone listeners, exercising the v6 sibling of
 * the transport's own socket pair in both directions. */
static int run_v6_standalone(ntx_netx *netx) {
    const char *why = NULL;
    if (!v6_probe(&why)) {
        printf("SKIP ipv6-loopback-unavailable (%s)\n", why ? why : "unknown");
        return 0;
    }

    ntx_utp *u3 = ntx_utp_listen(netx, 0, accept_cb_1, NULL); /* dialer */
    ntx_utp *u4 = ntx_utp_listen(netx, 0, accept_cb_v6, V6_TOKEN); /* listener */
    if (!u3 || !u4) return fail("v6-standalone-listen");

    /* The v6 sibling must exist and carry the very same advertised number. */
    check(u3->fd6 >= 0, "v6-standalone-dialer-sibling-bound");
    check(u4->fd6 >= 0, "v6-standalone-listener-sibling-bound");
    check(u4->port6 == ntx_utp_port(u4) && u4->port6 != 0,
          "v6-standalone-single-port-convention");

    ntx_addr a6;
    v6_loopback(&a6);
    uint16_t p4 = ntx_utp_port(u4);

    ntx_cbs c;
    memset(&c, 0, sizeof c);
    g_v6_fd2 = 0;
    int fd3 = ntx_utp_route_connect(u3, &a6, p4, NULL, &c);
    check(fd3 <= -NTX_UTP_VIRT_BASE, "v6-dial-yields-virt-fd");

    uint64_t t0 = mono_ms();
    while (!ntx_utp_virt_connected(u3, fd3) && mono_ms() - t0 < 2000)
        ntx_netx_run_once(netx, 50);
    check(ntx_utp_virt_connected(u3, fd3), "v6-dialer-connected");

    check(ntx_utp_virt_write(u3, fd3, (const uint8_t *)"v6 hello", 8) >= 0,
          "v6-write-out");
    t0 = mono_ms();
    while (g_v6_fd2 == 0 && mono_ms() - t0 < 2000) ntx_netx_run_once(netx, 50);
    check(g_v6_fd2 <= -NTX_UTP_VIRT_BASE, "v6-accept-virt-fd");

    uint8_t buf[32];
    ssize_t rn = 0;
    t0 = mono_ms();
    while (mono_ms() - t0 < 2000) {
        rn = ntx_utp_virt_read(u4, g_v6_fd2, buf, sizeof buf);
        if (rn > 0) break;
        ntx_netx_run_once(netx, 50);
    }
    check(rn == 8 && memcmp(buf, "v6 hello", 8) == 0, "v6-read-bytes-match");

    check(ntx_utp_virt_write(u4, g_v6_fd2, (const uint8_t *)"ack", 3) >= 0,
          "v6-write-back");
    rn = 0;
    t0 = mono_ms();
    while (mono_ms() - t0 < 2000) {
        rn = ntx_utp_virt_read(u3, fd3, buf, sizeof buf);
        if (rn > 0) break;
        ntx_netx_run_once(netx, 50);
    }
    check(rn == 3 && memcmp(buf, "ack", 3) == 0, "v6-read-back-bytes-match");

    /* A family the glue cannot serve is refused, not coerced into a v6
     * sockaddr the way the old else-branch did (regression guard on the
     * route_connect family gate). */
    ntx_addr bogus;
    memset(&bogus, 0, sizeof bogus);
    bogus.family = 0;
    check(ntx_utp_route_connect(u3, &bogus, p4, NULL, &c) == -1,
          "v6-rejects-unknown-family");

    ntx_utp_free(u3);
    ntx_utp_free(u4);
    return 0;
}

int main(void) {
    ntx_rng_init();

    ntx_netx *netx = ntx_netx_init(NULL);
    if (!netx) return fail("netx");

    ntx_utp *u1 = ntx_utp_listen(netx, 0, accept_cb_1, NULL);
    ntx_utp *u2 = ntx_utp_listen(netx, 0, accept_cb_2, U2_TOKEN);
    if (!u1 || !u2) return fail("listen");

    ntx_addr a2;
    ntx_addr_set_v4(&a2, inet_addr("127.0.0.1"));
    uint16_t p2 = ntx_utp_port(u2);

    /* 1) outbound: u1 -> u2. */
    ntx_cbs cbs1;
    memset(&cbs1, 0, sizeof cbs1);
    int fd1 = ntx_utp_route_connect(u1, &a2, p2, NULL, &cbs1);
    if (fd1 >= 0) return fail("route_connect");

    /* 2) drive the loop until u1's outbound conn is CONNECTED (handshake). */
    uint64_t t0 = mono_ms();
    while (!ntx_utp_virt_connected(u1, fd1) && mono_ms() - t0 < 2000)
        ntx_netx_run_once(netx, 50);
    if (!ntx_utp_virt_connected(u1, fd1)) return fail("u1-not-connected");

    /* 3) u1 -> u2 payload. The first ST_DATA is what fires u2's accept, so
     *    drive until accept_cb_2 delivers a (different) virt fd. */
    if (ntx_utp_virt_write(u1, fd1, (const uint8_t *)"hello uTP", 9) < 0)
        return fail("write1");
    t0 = mono_ms();
    while (g_fd2 == 0 && mono_ms() - t0 < 2000)
        ntx_netx_run_once(netx, 50);
    if (g_fd2 == 0) return fail("no-accept");
    if (g_fd2 >= 0) return fail("not-virt-fd");

    uint8_t buf[64];
    t0 = mono_ms();
    ssize_t rn = 0;
    while (mono_ms() - t0 < 2000) {
        rn = ntx_utp_virt_read(u2, g_fd2, buf, sizeof buf);
        if (rn > 0) break;
        ntx_netx_run_once(netx, 50);
    }
    if (rn != 9 || memcmp(buf, "hello uTP", 9) != 0) return fail("read1");

    /* 4) symmetric: u2 -> u1. */
    if (ntx_utp_virt_write(u2, g_fd2, (const uint8_t *)"world", 5) < 0)
        return fail("write2");
    t0 = mono_ms();
    rn = 0;
    while (mono_ms() - t0 < 2000) {
        rn = ntx_utp_virt_read(u1, fd1, buf, sizeof buf);
        if (rn > 0) break;
        ntx_netx_run_once(netx, 50);
    }
    if (rn != 5 || memcmp(buf, "world", 5) != 0) return fail("read2");

    /* 5) close u1's outbound conn (FIN) -> eventually disconnected. The
     *    frozen header has no public virt-close, so drive the SM close through
     *    the (internal, TU-visible) slot. */
    int idx1 = -fd1 - NTX_UTP_VIRT_BASE;
    ntx_utp_conn_close(u1->slots[idx1].conn);
    t0 = mono_ms();
    while (ntx_utp_virt_connected(u1, fd1) && mono_ms() - t0 < 2000)
        ntx_netx_run_once(netx, 50);
    if (ntx_utp_virt_connected(u1, fd1) != 0) return fail("still-connected");

    /* 6) bound port matches getsockname. */
    uint16_t p1 = ntx_utp_port(u1);
    if (p1 == 0 || p1 != ntx_sock_local_port(u1->fd)) return fail("port");

    /* 7) IPv6 leg: standalone dual-stack listeners over ::1, or an
     *    honest printed SKIP when the host has no usable IPv6. */
    if (run_v6_standalone(netx)) return 1;

    ntx_utp_free(u1);
    ntx_utp_free(u2);
    ntx_netx_free(netx);
    if (g_fails) return 1;
    printf("PASS\n");
    return 0;
}
