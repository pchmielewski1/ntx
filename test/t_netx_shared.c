/* Fail-soft matrix for the shared per-family UDP owner.
 *
 * When the netx-owned datagram socket cannot bind the listen
 * port (an external occupant holds it), the shared owner fails soft — udp4_fd
 * stays -1, DHT falls back to its OWN bound socket and keeps working, and uTP
 * is simply off; the TCP listener and the rest of netx are unaffected and
 * nothing crashes. This test reproduces the collision by holding the port with
 * an external (non-REUSEADDR) UDP socket, drives netx init, and asserts each
 * degraded-mode property; then releases the port and re-inits to assert the
 * shared owner recovers (binds again, uTP comes back on).
 *
 * Self-contained TU (mirrors t_dht.c): every production .c it links is
 * #included so the DHT global singleton + the weak ntx_utp_* entry points the
 * netx demux loop calls are all present in one translation unit. */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/proto/ntx_pex.c"
#include "../src/ui/ntx_diag.c"
#include "../src/net/ntx_utp.c"
#include "../src/net/ntx_utp_sm.c"
#include "../src/net/ntx_utp_hdr.c"
#include "../src/net/ntx_utp_cc.c"

static int fails;
static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails = 1;
}

/* --- tiny bencode helpers (local copies; t_dht.c keeps its own) ---------- */
static size_t be_raw(uint8_t *b, size_t off, const void *v, size_t n) {
    memcpy(b + off, v, n);
    return off + n;
}
static size_t be_key(uint8_t *b, size_t off, const char *k) {
    char h[24];
    int n = snprintf(h, sizeof h, "%zu:%s", strlen(k), k);
    return be_raw(b, off, h, (size_t)n);
}
static size_t be_str(uint8_t *b, size_t off, const void *v, size_t n) {
    char h[16];
    int m = snprintf(h, sizeof h, "%zu:", n);
    off = be_raw(b, off, h, (size_t)m);
    return be_raw(b, off, v, n);
}

/* Build a well-formed DHT ping query so the node parses it and counts an rx
 * (and replies → tx). Proves DHT is live on whichever socket it ended up on. */
static size_t build_ping(uint8_t *pkt, uint8_t tid0, uint8_t tid1) {
    size_t e = 0;
    pkt[e++] = 'd';
    e = be_key(pkt, e, "a");
    pkt[e++] = 'd';
    e = be_key(pkt, e, "id");
    uint8_t id[20];
    memset(id, tid0, 20);
    e = be_str(pkt, e, id, 20);
    pkt[e++] = 'e';
    e = be_key(pkt, e, "q");
    e = be_str(pkt, e, "ping", 4);
    e = be_key(pkt, e, "t");
    uint8_t tid[2] = { tid0, tid1 };
    e = be_str(pkt, e, tid, 2);
    e = be_key(pkt, e, "y");
    e = be_str(pkt, e, "q", 1);
    pkt[e++] = 'e';
    return e;
}

/* Send n_ping pings to DHT's advertised v4 port and pump netx; return the rx
 * delta observed. A nonzero delta means the datagrams reached DHT's socket and
 * were parsed — the transport is functional on that fd. */
static int dht_rx_delta_after_pings(ntx_netx *n, uint16_t port, int n_ping) {
    int s = ntx_sock_udp4();
    if (s < 0) return -1;
    ntx_sock_bind0(s);
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof dst);
    dst.sin_family = AF_INET;
    dst.sin_addr.s_addr = inet_addr("127.0.0.1");
    dst.sin_port = htons(port);
    int rx0, tx0, rd0, td0, rx1, tx1, rd1, td1;
    ntx_dht_stats(&rx0, &tx0, &rd0, &td0);
    for (int i = 0; i < n_ping; i++) {
        uint8_t pkt[128];
        size_t e = build_ping(pkt, (uint8_t)(0x30 + i), (uint8_t)(0xC0 + i));
        if (sendto(s, pkt, e, 0, (struct sockaddr *)&dst, sizeof dst) < 0) {
            close(s);
            return -1;
        }
    }
    for (int i = 0; i < 8; i++) ntx_netx_run_once(n, 40);
    ntx_dht_stats(&rx1, &tx1, &rd1, &td1);
    close(s);
    return (rx1 - rx0) + (tx1 - tx0);
}

/* Hold a UDP port with an external socket that does NOT set SO_REUSEADDR, so a
 * later bind to the same addr:port from netx (which does set REUSEADDR) still
 * collides — exactly the "another process owns the port" fail-soft trigger. */
static int hold_udp_port(uint16_t port) {
    int s = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (s < 0) return -1;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    sa.sin_port = htons(port);
    if (bind(s, (const struct sockaddr *)&sa, sizeof sa) != 0) {
        close(s);
        return -1;
    }
    return s;
}

/* ---- IPv6 side of the shared owner ---------------------------
 * The v6 sibling is bound independently of the v4 one, so the matrix has to
 * say something about both families. Same honesty rule as everywhere else:
 * when the host has no usable IPv6 the v6 checks print SKIP and assert
 * nothing, they never report a PASS that was not measured. */
static int v6_usable(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return 0;
    int one = 1;
    if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one) < 0) {
        close(fd);
        return 0;
    }
    struct sockaddr_in6 sa;
    memset(&sa, 0, sizeof sa);
    sa.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &sa.sin6_addr);
    int ok = bind(fd, (const struct sockaddr *)&sa, sizeof sa) == 0;
    close(fd);
    return ok;
}

static uint16_t v6_bound_port(int fd) {
    struct sockaddr_in6 sa;
    socklen_t l = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &l) != 0) return 0;
    return ntohs(sa.sin6_port);
}

/* One datagram to [::1]:port from a fresh ::1 client socket. */
static int send_v6(uint16_t port, const uint8_t *pkt, size_t n) {
    int s = ntx_sock_udp6();
    if (s < 0) return -1;
    struct sockaddr_in6 me;
    memset(&me, 0, sizeof me);
    me.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &me.sin6_addr);
    if (bind(s, (const struct sockaddr *)&me, sizeof me) != 0) {
        close(s);
        return -1;
    }
    struct sockaddr_in6 dst = me;
    dst.sin6_port = htons(port);
    ssize_t r = sendto(s, pkt, n, 0, (const struct sockaddr *)&dst, sizeof dst);
    close(s);
    return (int)r;
}

/* 20-byte uTP ST_SYN header (type 4, ver 1 → first byte 0x41): the classifier
 * must call it uTP and hand it to the glue, which demuxes it by peer+conn_id. */
static size_t build_syn(uint8_t *h, uint16_t conn_id) {
    memset(h, 0, 20);
    h[0] = (uint8_t)((NTX_UTP_ST_SYN << 4) | NTX_UTP_VER);
    h[1] = 0; /* no extension chain */
    h[2] = (uint8_t)(conn_id >> 8);
    h[3] = (uint8_t)(conn_id & 0xFF);
    h[4] = 0; h[5] = 0; h[6] = 0; h[7] = 1;         /* ts_us */
    h[8] = 0; h[9] = 0; h[10] = 0; h[11] = 0;       /* ts_diff_us */
    h[12] = 0; h[13] = 0; h[14] = 0x10; h[15] = 0;  /* wnd_size = 4096 */
    h[16] = 0; h[17] = 1;                            /* seq_nr = 1 */
    h[18] = 0; h[19] = 0;                            /* ack_nr = 0 */
    return 20;
}

int main(void) {
    ntx_rng_init();
    ntx_dht_set_state_path("test/.scratch/14/dht_state_shared");

    const uint16_t PORT = 6971; /* external occupant + netx TCP listener land here */

    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.store_dir = "test/.scratch/14/store";
    cfg.port_lo = PORT;
    cfg.port_hi = PORT; /* force the exact port so the collision is deterministic */
    cfg.max_peers = 50;
    cfg.utp = 1;
    cfg.dht = 1;

    /* ---- Fail-soft: an external process already holds the listen port. ---- */
    int hold = hold_udp_port(PORT);
    check(hold >= 0, "occupant-holds-listen-port");
    if (hold < 0) return 1;

    ntx_netx *n = ntx_netx_init(&cfg);
    check(n != NULL, "netx-init-failsoft-no-abort");
    if (!n) { close(hold); return 1; }

    /* The TCP listener still bound the advertised port (different protocol). */
    check(ntx_netx_port(n) == PORT, "tcp-listener-still-bound");
    /* The shared UDP owner could not bind → -1 (fail-soft, not a crash). */
    check(ntx_netx_udp4_fd(n) == -1, "shared-owner-bind-collided-failsoft");
    /* The v6 sibling is a separate family socket bound independently, so a v4
     * occupant does not dictate its fate; when it did bind it must still hold
     * the advertised number (and uTP stays off because the v4 owner is missing
     * — proved by the dial check below). */
    if (v6_usable()) {
        int c6 = ntx_netx_udp6_fd(n);
        check(c6 == -1 || v6_bound_port(c6) == PORT,
              "failsoft-v6-leg-independent-of-v4-collision");
    } else {
        printf("SKIP failsoft-v6-leg-independent (no ::1 bind possible)\n");
    }

    /* DHT falls back to its own socket and stays fully functional. */
    check(ntx_dht_start(n) == 0, "dht-standalone-start");
    uint16_t dport = ntx_dht_port4();
    check(dport != 0, "dht-own-socket-bound");
    int delta = dht_rx_delta_after_pings(n, dport, 6);
    check(delta > 0, "dht-standalone-functional-own-socket");

    /* Nothing traversed the shared demux (there is no shared socket). */
    uint64_t dd = 0, du = 0, dr = 0;
    ntx_netx_demux_stats(n, &dd, &du, &dr);
    check(dd == 0 && du == 0, "demux-idle-no-shared-socket");

    /* uTP is off: with no shared socket the listener never started, so a v4
     * dial is not intercepted by uTP (returns a real fd / -1, never a virt fd).
     * This is meaningful because the uTP entry points ARE linked — the gating
     * is purely the missing shared socket. */
    ntx_addr tgt;
    ntx_addr_set_v4(&tgt, inet_addr("127.0.0.1"));
    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    int fd = ntx_netx_route_connect(n, &tgt, 9, NULL, &cbs);
    check(fd > -NTX_UTP_VIRT_BASE, "utp-off-dial-not-intercepted");
    if (fd >= 0) close(fd);

    ntx_dht_stop();
    ntx_netx_free(n);
    close(hold);

    /* ---- Recovery: the port is free again, the shared owner binds. ---- */
    ntx_netx *n2 = ntx_netx_init(&cfg);
    check(n2 != NULL, "netx-reinit-after-release");
    if (!n2) return fails ? 1 : 0;
    check(ntx_netx_udp4_fd(n2) >= 0, "recovery-shared-owner-bound");

    /* DHT now rides the recovered shared socket (no own-socket fallback). */
    check(ntx_dht_start(n2) == 0, "recovery-dht-start-on-shared");

    /* With the shared socket back, uTP comes online: a v4 dial now yields a
     * virt fd (the listener is running on the shared socket). */
    ntx_cbs cbs2;
    memset(&cbs2, 0, sizeof cbs2);
    int fd2 = ntx_netx_route_connect(n2, &tgt, 9, NULL, &cbs2);
    check(fd2 <= -NTX_UTP_VIRT_BASE, "recovery-utp-on-virt-dial");

    /* And DHT rides the shared socket this time (no own-socket fallback): a
     * ping to the shared port is delivered through the demux loop. */
    uint16_t sport = ntx_netx_port(n2);
    int delta2 = dht_rx_delta_after_pings(n2, sport, 6);
    check(delta2 > 0, "recovery-dht-via-shared-demux");
    uint64_t dd2 = 0, du2 = 0, dr2 = 0;
    ntx_netx_demux_stats(n2, &dd2, &du2, &dr2);
    check(dd2 >= 1, "recovery-demux-dht-counted");

    /* ---- IPv6 sibling of the recovered shared owner. ---- */
    if (!v6_usable()) {
        printf("SKIP ipv6-loopback-unavailable (no ::1 bind possible)\n");
    } else {
        int fd6 = ntx_netx_udp6_fd(n2);
        check(fd6 >= 0, "recovery-v6-shared-owner-bound");
        check(fd6 != ntx_netx_udp4_fd(n2), "recovery-v6-is-its-own-family-socket");
        /* Single-port convention: the v6 sibling answers on the very port the
         * client advertises, so a v6 peer needs no second port number. */
        check(fd6 >= 0 && v6_bound_port(fd6) == sport,
              "recovery-v6-shares-the-advertised-port");

        uint64_t b_d = 0, b_u = 0, b_r = 0;
        ntx_netx_demux_stats(n2, &b_d, &b_u, &b_r);

        uint8_t ping[128];
        size_t pn = build_ping(ping, 0x41, 0x9E);
        check(send_v6(sport, ping, pn) == (int)pn, "recovery-v6-ping-sent");
        for (int i = 0; i < 8; i++) ntx_netx_run_once(n2, 40);
        uint64_t a_d = 0, a_u = 0, a_r = 0;
        ntx_netx_demux_stats(n2, &a_d, &a_u, &a_r);
        check(a_d > b_d, "recovery-v6-demux-routes-dht");

        /* A uTP-shaped datagram on the v6 socket must be classified uTP and
         * delivered to the glue (which is what lets a punched v6 SYN in from
         * the outside reach the connection table). */
        b_d = a_d; b_u = a_u; b_r = a_r;
        uint8_t syn[20];
        size_t sn = build_syn(syn, 0x1234);
        check(send_v6(sport, syn, sn) == (int)sn, "recovery-v6-syn-sent");
        for (int i = 0; i < 8; i++) ntx_netx_run_once(n2, 40);
        ntx_netx_demux_stats(n2, &a_d, &a_u, &a_r);
        check(a_u > b_u, "recovery-v6-demux-routes-utp");

        /* Garbage on either family lands in the drop bucket, never in a
         * consumer — the counters stay a partition of what was received. */
        b_d = a_d; b_u = a_u; b_r = a_r;
        uint8_t junk[8] = { 0xFF, 1, 2, 3, 4, 5, 6, 7 };
        check(send_v6(sport, junk, sizeof junk) == (int)sizeof junk,
              "recovery-v6-junk-sent");
        for (int i = 0; i < 8; i++) ntx_netx_run_once(n2, 40);
        ntx_netx_demux_stats(n2, &a_d, &a_u, &a_r);
        check(a_r > b_r, "recovery-v6-junk-counted-as-drop");
    }

    ntx_dht_stop();
    ntx_netx_free(n2);

    return fails ? 1 : 0;
}
