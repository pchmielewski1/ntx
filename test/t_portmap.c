#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../src/core/ntx_session.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_peer.c"
#include "../src/core/ntx_store.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/proto/ntx_pe.c"
#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_holepunch.c"
#include "../src/proto/ntx_pex.c"
#include "../src/proto/ntx_http.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_magnet.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/ui/ntx_diag.c"
#include "../src/core/ntx_session_stats.c"
#include "../src/core/ntx_pieceblk.c"
#include "../src/core/ntx_session_webseed.c"
#include "../src/core/ntx_session_pex.c"
#include "../src/core/ntx_session_meta.c"
#include "../src/core/ntx_session_vlog.c"
#include "../src/core/ntx_session_pe.c"
#include "../src/core/ntx_session_bt_hs.c"
#include "../src/proto/ntx_btmsg.c"
#include "../src/proto/ntx_utmeta.c"
#include "../src/proto/ntx_pe_vc.c"

#include "../src/core/ntx_share.c"
#include "../src/core/ntx_share_meta.c"
#include "../src/core/ntx_share_out.c"
#include "../src/core/ntx_session_priv.c"
#include "../src/core/ntx_session_portmap.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/proto/ntx_pcp.c"

/* Design §8 — the session port-mapping driver. The gateway is a fake UDP socket
 * on 127.0.0.1, the default route comes from a fixture under test/.scratch, and
 * the retry/renewal clock is virtual through ntx_portmap_test_advance_ms, so no
 * case waits on wall time and none of them touches the network. */

static int fails;

static void ck(int cond, const char *what) {
    if (!cond) {
        printf("FAIL %s\n", what);
        fails++;
    }
}

static void ck_eq(long got, long want, const char *what) {
    if (got != want) {
        printf("FAIL %s got=%ld want=%ld\n", what, got, want);
        fails++;
    }
}

#define SCRATCH "test/.scratch/portmap"
#define EXT_PORT 40123

/* The two schedules the RFCs mandate, spelled out here rather than read from the
 * driver: a test that asked the driver for its own constants could not fail when
 * the driver had the wrong ones (R11). */
#define PCP_IRT_MS 3000u   /* RFC 6887 §8.1.1 initial retransmission timeout */
#define PCP_MRT_MS 1024000u /* RFC 6887 §8.1.1 maximum retransmission timeout */
#define NATPMP_IRT_MS 250u /* RFC 6886 §3.1 initial interval, doubled, nine sends */

/* The gateway's own verdicts, spelled out rather than read from the driver: a test
 * that asked the codec which codes mean "no" could not fail when the codec treated
 * them as silence (R14). PCP numbering is RFC 6887 §7.4, NAT-PMP's RFC 6886 §3.5. */
#define PCP_RES_NOT_AUTHORIZED 2u
#define PCP_RES_NETWORK_FAILURE 7u
#define PCP_RES_NO_RESOURCES 8u
#define PCP_RES_USER_EX_QUOTA 10u
#define NATPMP_RES_NOT_AUTHORIZED 2u
#define NATPMP_RES_NETWORK_FAILURE 3u
#define NATPMP_RES_OUT_OF_RESOURCES 4u
#define NATPMP_RES_UNSUPP_OPCODE 5u

static char *read_all(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return NULL;
    static char buf[8192];
    size_t n = fread(buf, 1, sizeof buf - 1, f);
    buf[n] = '\0';
    fclose(f);
    char *out = malloc(n + 1);
    if (!out) {
        printf("FAIL oom\n");
        exit(1);
    }
    memcpy(out, buf, n + 1);
    return out;
}

static void wr(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) {
        printf("FAIL write %s: %s\n", path, strerror(errno));
        exit(1);
    }
    fputs(text, f);
    fclose(f);
}

/* A deterministic regular file for the Q2 share (ntx_session_share_add refuses
 * anything but a regular file of size > 0; the content is irrelevant here). */
static void mk_file(const char *path, uint64_t size, uint8_t seed) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        printf("FAIL mk_open %s: %s\n", path, strerror(errno));
        exit(1);
    }
    uint32_t x = 0x12345678u ^ seed;
    uint64_t done = 0;
    while (done < size) {
        uint8_t buf[4096];
        size_t want = size - done < sizeof buf ? (size_t)(size - done) : sizeof buf;
        for (size_t i = 0; i < want; i++) {
            x = x * 1103515245u + 12345u;
            buf[i] = (uint8_t)(x >> 16);
        }
        if (write(fd, buf, want) != (ssize_t)want) {
            printf("FAIL mk_write\n");
            exit(1);
        }
        done += want;
    }
    close(fd);
}

/* ---- R15 fixtures: lines copied verbatim out of `cat /proc/net/ipv6_route` on
 * this host, kernel padding included. The layout is
 * dst(32hex) dpl(2hex) src(32hex) spl(2hex) nexthop(32hex) metric(8hex)
 * refcnt(8hex) use(8hex) flags(8hex) iface,
 * the three addresses as 16 raw bytes in network order and EVERY number in hex —
 * prefix lengths too, so a host route reads 80 and the dead metric ffffffff. */

/* The fields of the RA-learned default of this box, spelled out once so a gate
 * fixture can differ from the kernel's own line in the ONE field it is about:
 * ::/0 via fe80::1 on wlP9s9, metric 00000258, flags 00000003 = RTF_UP|RTF_GATEWAY. */
#define V6_DPY "00000000000000000000000000000000 00 00000000000000000000000000000000 00 " /* dst dpl src spl */
#define V6_NH1 "fe800000000000000000000000000001 "                                         /* nexthop fe80::1 */
#define V6_NH2 "fe800000000000000000000000000002 "                                         /* nexthop fe80::2 */
#define V6_RU "0000000e 00000000 "                                                          /* refcnt use */
#define V6_MET "00000258 "                                                                  /* metric 600 */
#define V6_IF "   wlP9s9\n"                                                                 /* iface, padding kept */
#define V6_FLAGS(f) V6_DPY V6_NH1 V6_MET V6_RU f V6_IF
#define V6_DEFAULT V6_FLAGS("00000003")
#define V6_METRIC(m) V6_DPY V6_NH1 m " " V6_RU "00000003" V6_IF

/* networkd's blackhole on an IPv4-only box: ::/0 on lo, no RTF_UP, RTF_REJECT
 * (0x200) set and metric ffffffff. The parser must refuse it, and this is exactly
 * the line a "dst is :: and dpl is 0" check would accept. */
#define V6_LO_BLACKHOLE "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "                \
                        "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200       lo\n"

/* What the driver's route fixture holds: this host's table cut to the lines that
 * matter — two on-link prefixes, the fe80::1 default, a /128 on lo and the
 * blackhole. Nothing here is invented. */
static const char V6_ROUTES_REAL[] =
    "20011b81051170000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000258 00000001 00000000 00000001   wlP9s9\n"
    "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000400 00000015 00000000 00000001   wlP9s9\n" V6_DEFAULT
    "00000000000000000000000000000001 80 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000000 00000017 00000000 80200001       lo\n" V6_LO_BLACKHOLE;

static const uint8_t V6_NH_FE80_1[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t V6_NH_FE80_2[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2};

/* S17b: the same default with a gateway this box can actually reach. lo holds
 * ::1/128 here and NO interface has a link-local prefix, so a fe80:: nexthop is
 * undialable in this sandbox (probed: connect("fe80::1%lo") = ENETUNREACH, and
 * EINVAL on every interface whose IPv6 is off) while ::1 connects. The scope
 * rules therefore get pinned on the value the driver hands connect() plus the
 * kernel's answer, not on a round trip to a router that cannot exist here. */
#define V6_NH_LO "00000000000000000000000000000001 " /* nexthop ::1 */
#define V6_DEFAULT_LO V6_DPY V6_NH_LO V6_MET V6_RU "00000003" "   lo\n"
/* fe80::1 reached through `iface` — for the sin6_scope_id cases. */
#define V6_LINKLOCAL(iface) V6_DPY V6_NH1 V6_MET V6_RU "00000003" "   " iface "\n"
/* [::1], the one v6 address this box routes. */
static const uint8_t V6_LO_ADDR[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

/* ---- S17c: the addresses a v6 sequence is judged on -------------------------
 * The gateway of every S17c case is still ::1, because nothing else can be bound
 * here (`bind(2001:db8::1)` is EADDRNOTAVAIL and `ip -6 addr add` is EPERM — both
 * probed); what the cases vary is the CLIENT address, which the sandbox can only
 * supply through the hook (see the T block). The client addresses below are the four
 * shapes pm6_is_global has to tell apart, and the external address a v6 gateway
 * hands back. */
static const uint8_t V6_CLIENT_GLOBAL[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                             0, 0, 0, 0, 0, 0, 0x12, 0x34}; /* 2001:db8::1234 */
static const uint8_t V6_EXT_GLOBAL[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0x09}; /* 2001:db8::9 */
static const uint8_t V6_CLIENT_ULA[16] = {0xfd, 0, 0, 0, 0, 0, 0, 0,
                                          0, 0, 0, 0, 0, 0, 0, 0x01}; /* fd00::1 */
static const uint8_t V6_CLIENT_LINKLOCAL[16] = {0xfe, 0x80, 0, 0, 0, 0, 0, 0,
                                                0, 0, 0, 0, 0, 0, 0, 0x11}; /* fe80::11 */
static const uint8_t V6_CLIENT_MAPPED[16] = {0, 0, 0, 0, 0, 0, 0, 0,
                                             0, 0, 0xff, 0xff, 192, 0, 2, 1}; /* ::ffff:192.0.2.1 */
static const uint8_t V6_UNSPEC[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

/* Default route through the fake gateway. /proc/net/route prints the gateway as
 * a host-byte-order hex u32 (127.0.0.1 → 0100007F, 203.0.113.1 → 017100CB);
 * /proc/net/ipv6_route prints 16 raw bytes in network order. */
static char v4path[256], v6path[256]; /* outlive the call: the hook keeps the pointers */

static void write_routes(const char *gw_host_hex, const char *gw_net_hex) {
    char line[512];
    snprintf(v4path, sizeof v4path, "%s/route4", SCRATCH);
    snprintf(v6path, sizeof v6path, "%s/route6", SCRATCH);
    snprintf(line, sizeof line,
             "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
             "lo\t00000000\t%s\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
             "lo\t0100007F\t00000000\t0001\t0\t0\t100\t000000FF\t0\t0\t0\n", gw_host_hex);
    wr(v4path, line);
    /* R15: the v6 file used to hold ONE invented line — the nexthop written into the
     * src field with spl 40, a ::ffff:a.b.c.d gateway and decimal-looking numbers. No
     * kernel ever writes that shape, so the parser it was written against matched
     * nothing real and the fixture hid it. Real lines of this host's table now stand
     * in its place. gw_net_hex is unused: the v4 route is what the driver dials, and
     * both fake gateways are 127.0.0.1, so the v6 router is the same box either way. */
    (void)gw_net_hex;
    wr(v6path, V6_ROUTES_REAL);
    ntx_portmap_test_set_route_files(v4path, v6path);
}

/* One /proc/net/ipv6_route fixture pointed at the parser, with the v4 file of the
 * caller's choosing beside it (NULL = none readable). */
static const char *write_route6(const char *text, const char *v4) {
    static char path[256];
    snprintf(path, sizeof path, "%s/r15_route6", SCRATCH);
    wr(path, text);
    ntx_portmap_test_set_route_files(v4, path);
    return path;
}

#define GW_LO "0100007F", "7F000001"
#define GW_PUB "017100CB", "CB007101"

/* ---- fake gateway ---- */

static int gwd;
static uint16_t gw_port;
static struct sockaddr_in g_from; /* who sent the last request: replies go back there */

/* The fake gateway's Epoch (RFC 6887 §8.7: seconds since it booted). A healthy
 * gateway's counter advances with the same seconds the client's clock advances, so the
 * harness reports the baseline it handed out last plus the seconds since that answer —
 * the figure the client must expect, with no real-clock jitter to read as a §8.5
 * restart. A case that wants the opposite hands pcp_grant_epoch / pcp_answer_all an
 * explicit value: 0 for a gateway that just rebooted, or one claiming an Epoch that
 * cannot be its own boot (the §8.5 upper bound), or a frozen counter. */
static uint64_t gw_reply_at;

static uint32_t gw_epoch_live(const struct ntx_portmap *pm) {
    if (!pm || !pm->epoch_seen) return 100;
    return pm->epoch + (uint32_t)((pm_now() - gw_reply_at) / 1000u);
}

static void gw_start(void) {
    gwd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(gwd, (struct sockaddr *)&sa, sizeof sa)) {
        printf("FAIL gw bind\n");
        exit(1);
    }
    socklen_t sl = sizeof sa;
    getsockname(gwd, (struct sockaddr *)&sa, &sl);
    gw_port = ntohs(sa.sin_port);
    ntx_portmap_test_set_gateway_port(gw_port);
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

/* One datagram the driver sent. Its socket is connect()ed to the gateway, so a
 * datagram from any other endpoint never reaches it. */
static ssize_t gw_get(uint8_t *buf, size_t cap) {
    struct sockaddr_in f;
    socklen_t fl = sizeof f;
    ssize_t r = recvfrom(gwd, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&f, &fl);
    if (r >= 0) g_from = f;
    return r;
}

static int gw_wait(uint8_t *buf, size_t cap, int ms) {
    for (int i = 0; i <= ms / 2; i++) {
        ssize_t r = gw_get(buf, cap);
        if (r >= 0) return (int)r;
        struct timespec ts = {0, 2 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

static void gw_drain(void) {
    uint8_t buf[2048];
    while (gw_get(buf, sizeof buf) >= 0) {
    }
}

static int gw_pending(void) {
    uint8_t buf[2048];
    return gw_get(buf, sizeof buf) >= 0;
}

static void gw_to(const uint8_t *b, size_t n, int from_fd) {
    if (sendto(from_fd, b, n, 0, (struct sockaddr *)&g_from, sizeof g_from) < 0) {
        printf("FAIL gw send: %s\n", strerror(errno));
        exit(1);
    }
}

static void gw_send(const uint8_t *b, size_t n) { gw_to(b, n, gwd); }

/* ---- S17b: the fake gateway's IPv6 sibling ---------------------------------
 * The v4 fake above never needed an address: both of its fixtures are 127.0.0.1
 * and ntx_portmap_test_set_gateway_port carries a port alone. A v6 gateway needs
 * BOTH — its address is whatever /proc/net/ipv6_route names — so S17b gets a port
 * hook of its own (pm_gw_port() and pm_gw6_port() stay separate on purpose: a case
 * must be able to hand v4 a live gateway and v6 a dead one, which is how the two
 * halves are proven independent).
 *
 * A link-local gateway cannot be reached from this box: `cat /proc/net/if_inet6`
 * holds only ::1/128 on lo, so connect("fe80::1%lo") is ENETUNREACH while the same
 * connect WITHOUT a scope is EINVAL (both probed here). Those two errnos are what
 * make the scope rule testable at all — the kernel only reaches a route lookup once
 * a scope was applied — and getpeername cannot show it: it answers the peer scope
 * from sk_bound_dev_if, which a connect-time sin6_scope_id does not set (also
 * probed), so it reads 0 even for a socket connected to [::1] with scope 1. */

static int gw6d = -1;
static uint16_t gw6_port;
static struct sockaddr_in6 gw6_from; /* who sent the last v6 request */

static void gw6_mk(struct sockaddr_in6 *sa, const char *ip, uint16_t port) {
    memset(sa, 0, sizeof *sa);
    sa->sin6_family = AF_INET6;
    sa->sin6_port = htons(port);
    if (inet_pton(AF_INET6, ip, &sa->sin6_addr) != 1) {
        printf("FAIL gw6 inet_pton %s\n", ip);
        exit(1);
    }
}

/* ::1 on an ephemeral port. Unlike the rest of this file's v6 fixtures the answer
 * is NOT soft-skipped: this suite is the v6 socket's only proof, and a case that
 * quietly passed because there was no v6 stack is the failure mode §0.2 warns
 * about. A box without ::1 therefore reports FAIL here, loudly. */
static void gw6_start(void) {
    gw6d = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in6 sa;
    gw6_mk(&sa, "::1", 0);
    if (gw6d < 0 || bind(gw6d, (struct sockaddr *)&sa, sizeof sa)) {
        printf("FAIL gw6 bind ::1 — no IPv6 loopback in this environment\n");
        exit(1);
    }
    socklen_t sl = sizeof sa;
    getsockname(gw6d, (struct sockaddr *)&sa, &sl);
    gw6_port = ntohs(sa.sin6_port);
    ntx_portmap_test_set_gateway6_port(gw6_port);
}

static ssize_t gw6_get(uint8_t *buf, size_t cap) {
    struct sockaddr_in6 f;
    socklen_t fl = sizeof f;
    ssize_t r = recvfrom(gw6d, buf, cap, MSG_DONTWAIT, (struct sockaddr *)&f, &fl);
    if (r >= 0) gw6_from = f;
    return r;
}

static void gw6_drain(void) {
    uint8_t buf[2048];
    while (gw6_get(buf, sizeof buf) >= 0) {
    }
}

static int gw6_pending(void) {
    uint8_t buf[2048];
    return gw6_get(buf, sizeof buf) >= 0;
}

/* One datagram from the v6 gateway to a specific peer — the driver's connected
 * socket, which never sends in S17b, so the gateway cannot learn it by listening.
 * A peer the driver never connected to is the failure the case is about, so this
 * reports it and carries on instead of ending the run: the later cases each pin
 * their own behaviour and must still get their turn. */
static void gw6_to(const uint8_t *b, size_t n, const struct sockaddr_in6 *to) {
    if (sendto(gw6d, b, n, 0, (struct sockaddr *)to, sizeof *to) < 0) {
        printf("FAIL gw6 send: %s\n", strerror(errno));
        fails++;
    }
}

/* An ephemeral v6 port that is bound, learned and released: nothing answers there,
 * so a datagram sent to it comes back as ICMPv6 port-unreachable — the v6 sibling
 * of dead_port(), whose ECONNREFUSED the v6 half must judge without a fallback. */
static uint16_t dead_port6(void) {
    uint16_t p = 0;
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in6 sa;
    gw6_mk(&sa, "::1", 0);
    if (fd < 0 || bind(fd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("FAIL dead_port6 bind: %s\n", strerror(errno));
        exit(1);
    }
    socklen_t sl = sizeof sa;
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    p = ntohs(sa.sin6_port);
    close(fd);
    return p;
}

/* The control for the scope cases: the same connect() pm_open6 makes for a
 * link-local gateway, with the scope left at 0. The kernel cannot pick a device for
 * a link-local destination without one and refuses with EINVAL before any route
 * lookup, so a SCOPED attempt whose errno is not EINVAL is the proof that a scope
 * was applied. getpeername cannot show the scope: it answers from sk_bound_dev_if,
 * which a connect()-time sin6_scope_id does not touch. */
static int v6_probe_scopeless(void) {
    int fd = socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    int one = 1;
    setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof one);
    struct sockaddr_in6 sa;
    gw6_mk(&sa, "fe80::1", 5351);
    sa.sin6_scope_id = 0;
    int rc = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    int err = rc < 0 ? errno : 0;
    close(fd);
    return err;
}

/* The peer the driver's v6 socket is connected to, straight off the kernel. */
static int pm6_peername(struct ntx_portmap *pm, struct sockaddr_in6 *out) {
    if (!pm || pm->fd6 < 0) return -1;
    socklen_t l = sizeof *out;
    memset(out, 0, sizeof *out);
    return getpeername(pm->fd6, (struct sockaddr *)out, &l);
}

/* The driver's own v6 endpoint — the address the gateway answers to. */
static int pm6_sockname(struct ntx_portmap *pm, struct sockaddr_in6 *out) {
    if (!pm || pm->fd6 < 0) return -1;
    socklen_t l = sizeof *out;
    memset(out, 0, sizeof *out);
    return getsockname(pm->fd6, (struct sockaddr *)out, &l);
}

static void pcp_resp(uint8_t out[60], const uint8_t req[60], uint16_t ext_port, const uint8_t ext_ip[16],
                     uint32_t lifetime, uint32_t epoch) {
    gw_reply_at = pm_now(); /* the Epoch on the wire is read from the instant of this answer */
    memset(out, 0, 60);
    out[0] = 2;
    out[1] = 0x81; /* R set | opcode MAP */
    out[4] = (uint8_t)(lifetime >> 24);
    out[5] = (uint8_t)(lifetime >> 16);
    out[6] = (uint8_t)(lifetime >> 8);
    out[7] = (uint8_t)lifetime;
    out[8] = (uint8_t)(epoch >> 24);
    out[9] = (uint8_t)(epoch >> 16);
    out[10] = (uint8_t)(epoch >> 8);
    out[11] = (uint8_t)epoch;
    memcpy(out + 24, req + 24, 12); /* echo the nonce */
    out[36] = req[36];               /* echo the protocol */
    out[40] = req[40];               /* echo the internal port */
    out[41] = req[41];
    out[42] = (uint8_t)(ext_port >> 8);
    out[43] = (uint8_t)ext_port;
    memcpy(out + 44, ext_ip, 16);
}

static void pcp_v4(uint8_t ip16[16], uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    memset(ip16, 0, 16);
    ip16[10] = 0xff;
    ip16[11] = 0xff;
    ip16[12] = a;
    ip16[13] = b;
    ip16[14] = c;
    ip16[15] = d;
}

static void natpmp_addr_resp(uint8_t out[12], uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    memset(out, 0, 12);
    out[1] = 128; /* OP 0 + response bit */
    out[8] = a;
    out[9] = b;
    out[10] = c;
    out[11] = d;
}

static void natpmp_map_resp(uint8_t out[16], uint8_t op, uint16_t int_port, uint16_t ext_port, uint32_t lifetime) {
    memset(out, 0, 16);
    out[1] = (uint8_t)(128 + op);
    out[8] = (uint8_t)(int_port >> 8);
    out[9] = (uint8_t)int_port;
    out[10] = (uint8_t)(ext_port >> 8);
    out[11] = (uint8_t)ext_port;
    out[12] = (uint8_t)(lifetime >> 24);
    out[13] = (uint8_t)(lifetime >> 16);
    out[14] = (uint8_t)(lifetime >> 8);
    out[15] = (uint8_t)lifetime;
}

/* ---- session helpers ---- */

typedef struct {
    ntx_config cfg;
    ntx_netx *n;
    ntx_session *s;
} sess;

/* Field reads for the cases where mapping is refused outright: §5 keeps the driver
 * from being allocated at all, so `x->s->pm` is NULL and a bare `pm->fd6` would
 * read freed memory instead of failing the way it should. */
static long pm6_fd(const sess *x) { return x->s->pm ? (long)x->s->pm->fd6 : -1; }
static long pm6_v4fd(const sess *x) { return x->s->pm ? (long)x->s->pm->fd : -1; }
static long pm6_tried(const sess *x) { return x->s->pm ? (long)x->s->pm->gw6_tried : 0; }

/* `port_map` is handed to ntx_config BEFORE the session is built, which is the
 * production order (parse_args → ntx_netx_init → ntx_session_init) and the whole
 * point of the R16 cases: what a session does at bring-up with --port-map set.
 * A case that only cares about the driver's own state machine keeps using
 * sess_open(), which leaves the field 0 exactly as it did before. */
static void sess_open_pm(sess *x, const char *tag, int port_map, int proxy) {
    char dir[256];
    snprintf(dir, sizeof dir, "%s/%s", SCRATCH, tag);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        printf("FAIL store dir\n");
        exit(1);
    }
    memset(x, 0, sizeof *x);
    x->cfg.port_map = port_map;
    /* --port-map together with --proxy is refused by parse_args; a case that pins
     * what the driver does anyway sets the fields before the session exists, which
     * is the only way the §5 rule can be tested at bring-up. */
    if (proxy) {
        x->cfg.proxy = 1;
        x->cfg.proxy_host = "127.0.0.1";
        x->cfg.proxy_port = 1080;
    }
    /* The session keeps the ntx_config pointer (s->cfg = cfg), so store_dir must
     * outlive this frame: Q2's share path reads it from ntx_session_share_add
     * long after sess_open_pm returned. Same rule t_share_session.c pins. */
    x->cfg.store_dir = strdup(dir);
    x->cfg.port_lo = 6881;
    x->cfg.port_hi = 6991;
    x->cfg.max_peers = 8;
    x->cfg.dht = 0;
    x->n = ntx_netx_init(&x->cfg);
    if (!x->n) {
        printf("FAIL netx_init\n");
        exit(1);
    }
    x->s = ntx_session_init(x->n, &x->cfg);
    if (!x->s) {
        printf("FAIL session_init\n");
        exit(1);
    }
    /* The previous case's stop() leaves its lifetime-0 deletes queued on the fake
     * gateway; a case must never read another case's datagram. Same for the v6
     * sibling, whose socket outlives every case. */
    gw_drain();
    gw6_drain();
}

/* port_map 0 ("automatic with a share", i.e. --no flag given): the state-machine
 * cases drive the driver themselves through pm_start(), so they never need the
 * flag set before bring-up. */
static void sess_open(sess *x, const char *tag) { sess_open_pm(x, tag, 0, 0); }

static void sess_close(sess *x) {
    ntx_session_free(x->s);
    ntx_netx_free(x->n);
    free((void *)x->cfg.store_dir);
    x->cfg.store_dir = NULL;
}

/* Real I/O pump (epoll + the self-rearming 100 ms session tick). */
static void pump_ms(ntx_netx *n, int ms) {
    for (int i = 0; i < ms / 2 + 1; i++) ntx_netx_run_once(n, 2);
}

/* The retry/renewal clock is virtual, so cases drive the state machine directly
 * after moving it instead of guessing how long run_once really took. */
static void pm_tick(sess *x) { ntx_session_portmap_tick(x->s); }

static void pm_start(sess *x) {
    ntx_session_portmap_want(x->s, 1);
    pm_tick(x);
}

/* ---- S17c: the v6 half of the fake gateway, and the v6 wire probes -----------
 * The v4 probes above (pcp_grant / pcp_resp / pcp_err24 / pm_sends_in) have v6
 * siblings rather than parameters: reading the v6 datagram out of gwd would be
 * reading a socket the v6 sequence never sends on, and the two halves being driven
 * apart is what the independence cases are made of. The Epoch baseline is the v6
 * sequence's own (pm->s6.epoch), so a v4 answer cannot stabilise a v6 §8.5 test. */

static uint64_t gw6_reply_at;

static uint32_t gw6_epoch_live(const struct ntx_portmap *pm) {
    if (!pm || !pm->s6.epoch_seen) return 100;
    return pm->s6.epoch + (uint32_t)((pm_now() - gw6_reply_at) / 1000u);
}

static ssize_t gw6_wait(uint8_t *buf, size_t cap, int ms) {
    for (int i = 0; i <= ms / 2; i++) {
        ssize_t r = gw6_get(buf, cap);
        if (r >= 0) return r;
        struct timespec ts = {0, 2 * 1000 * 1000};
        nanosleep(&ts, NULL);
    }
    return -1;
}

static int gw6_sends_in(sess *x, uint64_t step_ms, int steps) {
    uint8_t buf[2048];
    int n = 0;
    for (int i = 0; i < steps; i++) {
        ntx_portmap_test_advance_ms(step_ms);
        pm_tick(x);
        pump_ms(x->n, 10);
        while (gw6_get(buf, sizeof buf) >= 0) n++;
    }
    return n;
}

static uint8_t granted6_nonce[256][12]; /* by protocol: the v6 delete must repeat it (§11.1) */

static int gw6_req_is(const uint8_t *b, ssize_t n, uint8_t proto, uint32_t lifetime) {
    return n == 60 && b[0] == 2 && b[1] == 1 && b[36] == proto && rd32(b + 4) == lifetime;
}

/* The v6 reply goes back to whoever sent it, which for a connected socket is the
 * driver's own endpoint. */
static void gw6_answer(const uint8_t *b, size_t n) { gw6_to(b, n, &gw6_from); }

static void pcp_grant6_epoch(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16],
                             uint32_t lifetime, uint32_t epoch) {
    uint8_t req[2048], rsp[64];
    for (int spins = 0; spins < 400; spins++) {
        ssize_t n = gw6_get(req, sizeof req);
        if (n < 0) {
            ntx_portmap_test_advance_ms(250);
            pm_tick(x);
            ntx_netx_run_once(x->n, 2);
            continue;
        }
        if (!gw6_req_is(req, n, proto, 7200)) continue;
        memcpy(granted6_nonce[proto], req + 24, 12);
        gw6_reply_at = pm_now();
        pcp_resp(rsp, req, ext_port, ext_ip, lifetime, epoch);
        gw6_answer(rsp, 60);
        pump_ms(x->n, 20);
        return;
    }
    printf("FAIL no v6 pcp request proto=%u\n", proto);
    fails++;
}

static void pcp_grant6(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16], uint32_t lifetime) {
    pcp_grant6_epoch(x, proto, ext_port, ext_ip, lifetime, gw6_epoch_live(x->s->pm));
}

/* Wait (clock-walking, bounded) for the next v6 MAP request of `proto` and copy it
 * out; 1 on success, 0 if none appeared. The caller answers it — which is what makes
 * a case that must NOT answer one expressible. */
static int pcp6_next_req(sess *x, uint8_t proto, uint8_t out[60]) {
    uint8_t req[2048];
    for (int spins = 0; spins < 800; spins++) {
        ssize_t n = gw6_get(req, sizeof req);
        if (n >= 0 && gw6_req_is(req, n, proto, 7200)) {
            memcpy(out, req, 60);
            return 1;
        }
        ntx_portmap_test_advance_ms(250);
        pm_tick(x);
        ntx_netx_run_once(x->n, 2);
    }
    return 0;
}

/* v6 state reads: the accessors are NULL-safe, so no probe helper is needed. */
static long pm6_state6(const sess *x) { return (long)ntx_session_portmap_state6(x->s); }
static long pm6_ext6(const sess *x) { return (long)ntx_session_ext_port6(x->s); }

/* S17d: the stats the operator reads. Refreshed through the real path
 * (ntx_session_stats_refresh → the double buffer → ntx_session_snapshot), so what the
 * U cases pin is the published line, not a call into the driver. */
static void sess_stats(sess *x, ntx_stats *st) {
    ntx_session_stats_refresh(x->s, 0);
    ntx_session_snapshot(x->s, st);
}
/* ---- retransmission pacing probes (R11) -------------------------------------
 * The schedule is read from the driver at the instant a datagram was observed,
 * which is also the instant the driver computed the next one: `next_try - now` is
 * then the interval just used and `gap` the un-jittered base of the next, so the
 * assertions are exact instead of guessed from wall time. Nothing here sleeps. */

/* ms still to wait before the outstanding query is retransmitted. */
static long pm_wait_ms(const struct ntx_portmap *pm) { return (long)(pm->next_try - pm_now()); }

/* The read above is taken some milliseconds after the driver computed the schedule
 * with its own pm_now(), and the real clock moves under the virtual offset. Half a
 * tick of slack covers it without hiding a schedule that is off by seconds. */
#define PM_WAIT_SLACK 64

/* 1 when the wait just used sits inside `base` ±10% (RFC 6887 §8.1.1 IRT/MRT with
 * its jitter), plus the slack the real clock accrues between the driver's send and
 * this read. Exactness of the schedule is pinned on pm->gap, where no clock can
 * drift. */
static int pm_wait_jittered(const struct ntx_portmap *pm, uint32_t base) {
    long w = pm_wait_ms(pm);
    long slack = (long)base / 10 + PM_WAIT_SLACK;
    return w >= (long)base - slack && w <= (long)base + slack;
}

/* 1 when the wait just used is `base` — RFC 6886 §3.1 has no jitter, so the only
 * tolerance is the slack; the doubling itself is pinned on pm->gap. */
static int pm_wait_close(const struct ntx_portmap *pm, uint32_t base) {
    long w = pm_wait_ms(pm);
    return w >= (long)base - PM_WAIT_SLACK && w <= (long)base + PM_WAIT_SLACK;
}

/* The jitter itself, decided without any clock: every draw must land in the ±10%
 * window of RFC 6887 §8.1.1 and the draws must not all be the same value (a
 * schedule without jitter — the state before R11 — repeats one value forever).
 * Sampled by putting the schedule at `ms` and letting the driver compute the wait
 * for its next send, so it is the schedule the driver really uses. */
static void pm_check_jitter(sess *x, uint32_t ms, const char *tag) {
    uint32_t lo = ms - ms / 10u, hi = ms + ms / 10u;
    uint8_t buf[2048];
    long first = -1;
    int distinct = 0;
    for (int i = 0; i < 60; i++) {
        gw_drain();
        x->s->pm->gap = ms;
        pm_send(x->s->pm);
        long w = pm_wait_ms(x->s->pm);
        if (w < (long)lo || w > (long)hi) {
            printf("FAIL %s_out_of_window got=%ld want=%u..%u\n", tag, w, lo, hi);
            fails++;
            return;
        }
        if (first < 0) first = w;
        else if (w != first) distinct = 1;
    }
    (void)gw_get(buf, sizeof buf);
    if (!distinct) {
        printf("FAIL %s_no_jitter all=%ld\n", tag, first);
        fails++;
    }
}

/* How many datagrams the driver sends over steps × step_ms of clock. A refusal has
 * to stop the schedule instead of replaying the whole nine-send schedule against a
 * gateway that already said no, so the cases below count on the wire (R14). */
static int pm_sends_in(sess *x, uint64_t step_ms, int steps) {
    uint8_t buf[2048];
    int n = 0;
    for (int i = 0; i < steps; i++) {
        ntx_portmap_test_advance_ms(step_ms);
        pm_tick(x);
        pump_ms(x->n, 10);
        while (gw_get(buf, sizeof buf) >= 0) n++;
    }
    return n;
}

/* One PCP MAP error reply, 24 B: the response header of RFC 6887 §7.2 with the R
 * bit and opcode MAP set, the result code in octet 3 and the error lifetime in
 * octets 4..7 — and no opcode data, which §7.4 allows an error to omit. This is
 * the form the codec used to throw away as "too short" (R14). */
static void pcp_err24(uint8_t out[24], uint32_t res, uint32_t lifetime) {
    memset(out, 0, 24);
    out[0] = 2;
    out[1] = 0x81;
    out[3] = (uint8_t)res;
    out[4] = (uint8_t)(lifetime >> 24);
    out[5] = (uint8_t)(lifetime >> 16);
    out[6] = (uint8_t)(lifetime >> 8);
    out[7] = (uint8_t)lifetime;
}

/* Put the driver into NAT-PMP mode with the TCP mapping query outstanding, the way
 * a v1-only gateway is reached: the UNSUPP_VERSION answer, then the reply to the
 * external-address query. Returns the length of the mapping request on the wire. */
static int gw_to_natpmp_map(sess *x, uint8_t *req, size_t cap) {
    const uint8_t unsupp[4] = {0, 0, 0, 1}; /* Vers 0, OP 0, Result 1 = UNSUPP_VERSION */
    if (gw_wait(req, cap, 300) != 60) return -1;
    gw_send(unsupp, sizeof unsupp);
    pump_ms(x->n, 40);
    if (gw_wait(req, cap, 300) != 2) return -1;
    uint8_t aresp[12];
    natpmp_addr_resp(aresp, 203, 0, 113, 9);
    gw_send(aresp, sizeof aresp);
    pump_ms(x->n, 40); /* the driver only reads the reply when the loop runs */
    return (int)gw_wait(req, cap, 300);
}

/* One retransmission: nothing may go out before the scheduled instant, and the
 * datagram must go out once it is reached. 0 = sent early, never sent, or the
 * schedule had already run out (a wait of 0 means the driver did not wait at all). */
static int pm_send_at_due(sess *x) {
    uint8_t buf[2048];
    long w = pm_wait_ms(x->s->pm);
    if (w <= 0) return 0;
    ntx_portmap_test_advance_ms((uint64_t)w - 1);
    pm_tick(x);
    if (gw_get(buf, sizeof buf) >= 0) return 0;
    /* The due instant, plus up to 5 ms of slack for the real clock the driver's
     * pm_now() also sees (the virtual offset is the only thing the test moves). */
    for (int i = 0; i < 6; i++) {
        ntx_portmap_test_advance_ms(1);
        pm_tick(x);
        if (gw_get(buf, sizeof buf) >= 0) return 1;
    }
    return 0;
}

static int req_is(const uint8_t *b, ssize_t n, uint8_t proto, uint32_t lifetime) {
    return n == 60 && b[0] == 2 && b[1] == 1 && b[36] == proto && rd32(b + 4) == lifetime;
}

static uint16_t req_int_port(const uint8_t *b) {
    return (uint16_t)((b[40] << 8) | b[41]);
}

/* One PCP exchange for one protocol: wait for its request, answer SUCCESS. */
static uint8_t granted_nonce[256][12]; /* by protocol: the delete must repeat it (§11.1) */

static void pcp_grant_epoch(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16],
                            uint32_t lifetime, uint32_t epoch) {
    uint8_t req[2048], rsp[64];
    for (int spins = 0; spins < 400; spins++) {
        ssize_t n = gw_get(req, sizeof req);
        if (n < 0) {
            ntx_portmap_test_advance_ms(250);
            pm_tick(x);
            ntx_netx_run_once(x->n, 2);
            continue;
        }
        if (!req_is(req, n, proto, 7200)) continue;
        memcpy(granted_nonce[proto], req + 24, 12);
        pcp_resp(rsp, req, ext_port, ext_ip, lifetime, epoch);
        gw_send(rsp, 60);
        pump_ms(x->n, 20);
        return;
    }
    printf("FAIL no pcp request proto=%u\n", proto);
    fails++;
}

static void pcp_grant(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16], uint32_t lifetime) {
    pcp_grant_epoch(x, proto, ext_port, ext_ip, lifetime, gw_epoch_live(x->s->pm));
}

/* pcp_answer_all: answer every PCP MAP query that goes out over `steps` × `step_ms`
 * of clock, and return how many QUERIES were seen — a query being a nonce, so a
 * retransmission of the outstanding one is not a second query. The request-loop probe
 * of R10: a driver that re-requests from inside its receive path without moving its
 * Epoch baseline is handed a fresh rollback with every answer, so this counts one
 * fresh nonce per round trip instead of the one re-request the schedule allows. The
 * pump is bounded (`cap`): a looping driver must show up as a failure, not as a
 * hanging test. PCP_EPOCH_LIVE answers with what a healthy gateway reports — its
 * counter in step with the client's clock — so recovery rounds are never mistaken for
 * a second restart. */
#define PCP_EPOCH_LIVE 0xffffffffu

static int pcp_answer_all(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16], uint32_t lifetime,
                          uint32_t epoch, const char *tag, uint64_t step_ms, int steps) {
    const int cap = 64; /* nothing legitimately asks this often in the window below */
    uint8_t req[2048], rsp[64];
    uint8_t seen[cap][12];
    int q = 0;
    for (int i = 0; i < steps; i++) {
        ssize_t r;
        /* The datagrams of the step the caller just pumped are the FIRST ones counted:
         * draining them here would hide a driver that answers a rollback by sending
         * from inside the receive path, which is the exact behaviour probed. */
        while ((r = gw_get(req, sizeof req)) > 0) {
            if (!req_is(req, r, proto, 7200)) continue;
            int fresh = 1;
            for (int k = 0; k < q; k++)
                if (memcmp(seen[k], req + 24, 12) == 0) fresh = 0;
            if (fresh) {
                if (q >= cap) {
                    printf("  (%s: %d queries in %d ms — request loop)\n", tag, q, (int)(step_ms * steps));
                    gw_drain();
                    return q;
                }
                memcpy(seen[q++], req + 24, 12);
            }
            pcp_resp(rsp, req, ext_port, ext_ip, lifetime,
                     epoch == PCP_EPOCH_LIVE ? gw_epoch_live(x->s->pm) : epoch);
            gw_send(rsp, 60);
        }
        ntx_portmap_test_advance_ms(step_ms);
        pm_tick(x);
        pump_ms(x->n, 10);
    }
    gw_drain();
    return q;
}

static void both_active(sess *x, uint16_t ext, const uint8_t ip[16]) {
    pcp_grant(x, NTX_PCP_PROTO_TCP, ext, ip, 7200);
    pcp_grant(x, NTX_PCP_PROTO_UDP, ext, ip, 7200);
}

/* How many FRESH MAP queries — distinct nonces — go out over steps × step_ms of
 * clock while nobody answers. The re-acquisition probe of R12: a driver that re-asks
 * on every tick is counted here, and so is one that never asks again. Retransmissions
 * of the outstanding query repeat its nonce and are not counted (the rule
 * pcp_answer_all uses). The pump is bounded, so a looping driver fails instead of
 * hanging. */
static int pm_fresh_queries_in(sess *x, uint8_t proto, const uint8_t known[12], uint64_t step_ms, int steps) {
    const int cap = 64;
    uint8_t buf[2048], seen[cap][12];
    int q = 0;
    if (known) memcpy(seen[q++], known, 12); /* the grant's own nonce is not a new ask */
    for (int i = 0; i < steps; i++) {
        ntx_portmap_test_advance_ms(step_ms);
        pm_tick(x);
        pump_ms(x->n, 10);
        ssize_t r;
        while ((r = gw_get(buf, sizeof buf)) > 0) {
            if (!req_is(buf, r, proto, 7200)) continue;
            int fresh = 1;
            for (int k = 0; k < q; k++)
                if (memcmp(seen[k], buf + 24, 12) == 0) fresh = 0;
            if (fresh) {
                if (q < cap) memcpy(seen[q], buf + 24, 12);
                q++;
            }
        }
    }
    gw_drain();
    return q;
}

/* pcp_grant for a request that may still be sitting on its retransmission schedule:
 * the clock walks in 5 s steps (up to a bounded 4000 s of it, so a driver that never
 * asks again is a FAIL and not a hang) until the datagram appears, then the canned
 * SUCCESS goes back. The gateway came back to life; the driver owes it a query. */
static void pcp_grant_whenever(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16],
                               uint32_t lifetime) {
    uint8_t req[2048], rsp[64];
    for (int spins = 0; spins < 800; spins++) {
        ssize_t n = gw_get(req, sizeof req);
        if (n < 0) {
            ntx_portmap_test_advance_ms(5000);
            pm_tick(x);
            ntx_netx_run_once(x->n, 2);
            continue;
        }
        if (!req_is(req, n, proto, 7200)) continue;
        /* The last retransmission of the renewal that just died, and any copy of it,
         * carries the DEAD grant's nonce and answers nothing any more. Answering it
         * here would hand the case its pass to a datagram nobody is waiting for. The
         * re-acquisition has to be a fresh query, which is also what O4 pins. */
        if (memcmp(req + 24, granted_nonce[proto], 12) == 0) continue;
        memcpy(granted_nonce[proto], req + 24, 12);
        pcp_resp(rsp, req, ext_port, ext_ip, lifetime, gw_epoch_live(x->s->pm));
        gw_send(rsp, 60);
        pump_ms(x->n, 20);
        return;
    }
    printf("FAIL no pcp request within the window proto=%u\n", proto);
    fails++;
}

/* Walk the outstanding query's retransmission budget against a gateway that says
 * nothing: one tick per scheduled instant, exactly as case D drives it. Bounded, so a
 * driver that keeps a query open forever is a FAIL and not a hang. 1 = the budget ran
 * out (the phase is no longer outstanding). */
static int pm_burn_budget(sess *x, int ph) {
    for (int i = 0; i < 16; i++) {
        if (x->s->pm->phase != ph) return 1;
        long w = pm_wait_ms(x->s->pm);
        ntx_portmap_test_advance_ms((uint64_t)(w > 0 ? w + 5 : 5));
        pm_tick(x);
    }
    return x->s->pm->phase != ph;
}

/* Wait (clock-walking, bounded) for the next MAP request of `proto` and copy it out;
 * 1 on success, 0 if none appeared within the window. The caller answers it, which is
 * what makes a case that must NOT answer one (a query left to die) expressible. */
static int pm_next_req(sess *x, uint8_t proto, uint8_t out[60]) {
    uint8_t req[2048];
    for (int spins = 0; spins < 800; spins++) {
        ssize_t n = gw_get(req, sizeof req);
        if (n >= 0 && req_is(req, n, proto, 7200)) {
            memcpy(out, req, 60);
            return 1;
        }
        ntx_portmap_test_advance_ms(250);
        pm_tick(x);
        ntx_netx_run_once(x->n, 2);
    }
    return 0;
}



/* ---- the announce port, straight off the wire (as t_session_trk_udp.c does) ---- */

static int udp_loopback(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa)) {
        printf("FAIL udp bind\n");
        exit(1);
    }
    socklen_t sl = sizeof sa;
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    *port = ntohs(sa.sin_port);
    return fd;
}

/* Announce to a fake UDP tracker on loopback and read the port field (offset 96)
 * back off the 98 B announce request. -1 = never saw one. */
static int announce_port_on_wire(sess *x) {
    uint8_t buf[2048];
    uint16_t tport = 0;
    int trk = udp_loopback(&tport);
    snprintf(x->s->trk_urls[0][0], sizeof x->s->trk_urls[0][0], "udp://127.0.0.1:%u", (unsigned)tport);
    x->s->trk_n[0] = 1;
    for (int round = 0; round < 30; round++) {
        ntx_session_trk_announce(x->s, 0, 0);
        ntx_session_trk_pump_udp(x->s);
        for (int i = 0; i < 20; i++) {
            ntx_netx_run_once(x->n, 2);
            struct sockaddr_in from;
            socklen_t fl = sizeof from;
            ssize_t r;
            while ((r = recvfrom(trk, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&from, &fl)) > 0) {
                if (r == 16) {
                    uint8_t rsp[20];
                    memset(rsp, 0, sizeof rsp);
                    memcpy(rsp + 4, buf + 12, 4); /* echo the transaction id */
                    memset(rsp + 8, 0x5a, 8);
                    if (sendto(trk, rsp, sizeof rsp, 0, (struct sockaddr *)&from, fl) < 0) {
                        printf("FAIL trk send: %s\n", strerror(errno));
                        exit(1);
                    }
                } else if (r == 98) {
                    close(trk);
                    return (buf[96] << 8) | buf[97];
                }
            }
        }
    }
    close(trk);
    return -1;
}

/* The `p` field of the extended handshake we offer (peer output buffer, the
 * t_session_ext_tx.c pattern). */
static int ext_handshake_port(sess *x) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
        printf("FAIL socketpair\n");
        exit(1);
    }
    fcntl(fds[0], F_SETFL, O_NONBLOCK);
    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(x->s, fds[0], &pa, 1234, 0);
    if (pi < 0) {
        printf("FAIL peer_alloc\n");
        exit(1);
    }
    x->s->peer_plain[pi] = 1;
    x->s->peer_phase[pi] = PH_OK;
    x->s->peer_tts[pi] = 0;
    x->s->peer_hello_sent[pi] = 1;
    x->s->peer_meta_id[pi] = 2;
    x->s->peer_pex_id[pi] = 1;
    x->s->peer_out_len[pi] = 0;
    ntx_session_peer_send_ext_handshake(x->s, pi);
    uint8_t wire[512];
    ssize_t rn = read(fds[1], wire, sizeof wire);
    close(fds[1]);
    if (rn < 7) {
        printf("FAIL no ext handshake\n");
        exit(1);
    }
    ntx_be top;
    size_t used = 0;
    if (ntx_be_parse(wire + 6, (size_t)(rn - 6), &top, &used, 8, 4096) != 0) {
        printf("FAIL ext handshake parse\n");
        exit(1);
    }
    int port = -1;
    const ntx_be *p = ntx_be_dict_get(&top, "p");
    if (p && p->t == NTX_BE_INT) port = (int)p->i;
    ntx_be_free(&top);
    ntx_session_peer_free(x->s, pi); /* frees the slot buffers, closes fds[0] */
    ntx_peer_free(&x->s->peers[pi]); /* ntx_session_peer_free leaves the peer struct */
    return port;
}

static void one_torrent(sess *x) {
    uint8_t ih[20];
    for (int i = 0; i < 20; i++) ih[i] = (uint8_t)(i + 1);
    x->s->n_tts = 1;
    ntx_torrent_init_meta(&x->s->tts[0], ih);
}

/* ---- R9 helpers: a port nobody listens on, and a real-clock loop counter ---- */

/* An ephemeral port that is bound, learned and immediately released: nothing
 * answers there, so every datagram the driver's connect()ed socket sends comes
 * back as ICMP port-unreachable — the R9 repro, without a fake gateway. */
static uint16_t dead_port(void) {
    uint16_t p = 0;
    int fd = udp_loopback(&p);
    close(fd);
    return p;
}

/* The review's repro, in one step: put one ICMP port-unreachable on the
 * connect()ed socket and leave it there. Nothing else will send from here (the
 * sequence is over), so with no close callback the pending error holds EPOLLERR
 * asserted and the loop never blocks again. */
static void pm_arm_icmp(struct ntx_portmap *pm) {
    uint8_t one[2] = {0, 0};
    (void)send(pm->fd, one, sizeof one, MSG_DONTWAIT);
    struct timespec ts = {0, 100 * 1000 * 1000};
    nanosleep(&ts, NULL);
}

/* How many loop iterations `ms` of wall time buys. With a pending ICMP error and
 * no close callback, epoll_wait returns instantly forever — that is the 100% CPU
 * spin of R9 (581 577 events in 0,3 s in the review's repro). */
static long pm_loop_iters(ntx_netx *n, int ms) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    long iters = 0;
    for (;;) {
        ntx_netx_run_once(n, 20);
        iters++;
        clock_gettime(CLOCK_MONOTONIC, &t1);
        if ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 >= ms) return iters;
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) {
        printf("FAIL scratch\n");
        exit(1);
    }
    if (mkdir(SCRATCH, 0755) != 0 && errno != EEXIST) {
        printf("FAIL scratch/pm\n");
        exit(1);
    }
    write_routes(GW_LO);
    gw_start();
    gw6_start();

    /* ---- A. PCP grants a different external port: state, adv_port, announce, ext `p` ---- */
    {
        sess x;
        sess_open(&x, "a");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        one_torrent(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "A_off_before_want");
        ck(!gw_pending(), "A_no_datagram_before_want");

        pm_start(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "A_pending");
        uint8_t req[2048];
        int n = gw_wait(req, sizeof req, 300);
        ck_eq(n, 60, "A_first_request_len");
        ck(req_is(req, n, NTX_PCP_PROTO_TCP, 7200), "A_first_request_is_pcp_tcp");
        ck_eq(req_int_port(req), ntx_netx_port(x.n), "A_internal_port_is_listen_port");

        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        both_active(&x, EXT_PORT, pub);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "A_active");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "A_adv_port");
        ck(ntx_netx_port(x.n) != EXT_PORT, "A_ext_differs_from_listen");
        ck_eq(announce_port_on_wire(&x), EXT_PORT, "A_announce_port");
        ck_eq(ext_handshake_port(&x), EXT_PORT, "A_ext_handshake_p");

        /* The nonce each grant was made with (§11.1: a delete must repeat it). */
        uint8_t tcp_nonce[12], udp_nonce[12];
        memcpy(tcp_nonce, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        memcpy(udp_nonce, granted_nonce[NTX_PCP_PROTO_UDP], 12);
        ck(memcmp(tcp_nonce, udp_nonce, 12) != 0, "A_fresh_nonce_per_mapping");

        gw_drain();
        ntx_session_portmap_stop(x.s);
        int zero = 0, total = 0, del_tcp = 0, del_udp = 0;
        for (ssize_t r; (r = gw_get(req, sizeof req)) >= 0;) {
            total++;
            if (r != 60 || rd32(req + 4) != 0) continue;
            zero++;
            if (req[36] == NTX_PCP_PROTO_TCP && memcmp(req + 24, tcp_nonce, 12) == 0) del_tcp++;
            if (req[36] == NTX_PCP_PROTO_UDP && memcmp(req + 24, udp_nonce, 12) == 0) del_udp++;
        }
        ck_eq(total, 2, "A_stop_sends_only");
        ck_eq(zero, 2, "A_stop_lifetime0");
        ck_eq(del_tcp, 1, "A_stop_tcp_same_nonce");
        ck_eq(del_udp, 1, "A_stop_udp_same_nonce");
        ck(ntx_session_adv_port(x.s) == ntx_netx_port(x.n), "A_listen_after_stop");
        sess_close(&x);
    }

    /* ---- B. reply from another source is ignored ---- */
    {
        sess x;
        sess_open(&x, "b");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "B_request");
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 7);
        uint16_t oport;
        int other = udp_loopback(&oport);
        ck_eq((long)sendto(other, rsp, 60, 0, (struct sockaddr *)&g_from, sizeof g_from), 60, "B_forged_send");
        pump_ms(x.n, 150);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "B_forged_ignored");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "B_forged_no_adv_port");
        close(other);
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- B2. the source filter itself (pm_src_ok).

     * The client socket is connect()ed, so the kernel drops anything not from
     * gateway:5351 before recvfrom ever reports it — the forged datagram in case B
     * cannot reach pm_rx either way. That makes the filter untestable from outside,
     * so it is tested directly: §8 makes the source test the boundary, not connect(). */
    {
        struct ntx_portmap probe;
        memset(&probe, 0, sizeof probe);
        probe.gw = htonl(0x7f000001u);
        struct sockaddr_in sa;
        memset(&sa, 0, sizeof sa);
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(0x7f000001u);
        sa.sin_port = htons(gw_port);
        ck(pm_src_ok(&probe, &sa), "B2_gateway_src_accepted");
        sa.sin_port = htons((uint16_t)(gw_port == 5351u ? 5352u : 5351u));
        ck(!pm_src_ok(&probe, &sa), "B2_wrong_port_rejected");
        sa.sin_port = htons(gw_port);
        sa.sin_addr.s_addr = htonl(0x7f000002u);
        ck(!pm_src_ok(&probe, &sa), "B2_wrong_ip_rejected");
        sa.sin_addr.s_addr = htonl(0x7f000001u);
        sa.sin_family = AF_INET6;
        ck(!pm_src_ok(&probe, &sa), "B2_wrong_family_rejected");
    }

    /* ---- C. wrong nonce is ignored ---- */
    {
        sess x;
        sess_open(&x, "c");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "C_request");
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 7);
        rsp[24] ^= 0x5a; /* the nonce no longer matches the request */
        gw_send(rsp, 60);
        pump_ms(x.n, 150);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "C_bad_nonce_ignored");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "C_bad_nonce_no_adv_port");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- D. no reply: PCP paces per RFC 6887 §8.1.1 (IRT 3 s, doubled) ----
     * The gaps are read off the wire against the virtual clock: each one must land
     * in base ±10% (the RFC's jitter), doubling from 3 s. Nine sends is the hard
     * cap, so the schedule here is 3 s, 6, 12, 24, 48, 96, 192, 384 s. */
    {
        sess x;
        sess_open(&x, "d");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "D_attempt1");
        gw_drain();
        int attempts = 1;
        uint32_t base = PCP_IRT_MS;
        for (int i = 0; i < 8; i++) {
            uint32_t next = base * 2 > PCP_MRT_MS ? PCP_MRT_MS : base * 2;
            if (!pm_wait_jittered(x.s->pm, base)) {
                printf("FAIL D_wait_%d got=%ld want=%u+/-10%%\n", i, pm_wait_ms(x.s->pm), base);
                fails++;
                break;
            }
            if (x.s->pm->gap != next) {
                printf("FAIL D_base_%d got=%u want=%u\n", i, x.s->pm->gap, next);
                fails++;
                break;
            }
            if (!pm_send_at_due(&x)) {
                printf("FAIL D_send_at_due_%d base=%u wait=%ld\n", i, base, pm_wait_ms(x.s->pm));
                fails++;
                break;
            }
            attempts++;
            base = next;
        }
        ck_eq(attempts, 9, "D_nine_attempts");
        ck(!gw_pending(), "D_no_tenth_attempt");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "D_pending_until_budget_out");
        ntx_portmap_test_advance_ms((uint64_t)base * 2); /* past the last scheduled gap */
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "D_none");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "D_none_adv_port");
        int quiet = 1;
        for (int i = 0; i < 6; i++) {
            ntx_portmap_test_advance_ms(60000);
            pm_tick(&x);
            pump_ms(x.n, 10);
            if (gw_pending()) quiet = 0;
        }
        gw_drain();
        ck(quiet, "D_none_stays_quiet");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- D2. NAT-PMP paces per RFC 6886 §3.1: 250 ms, doubled, nine attempts.
     * Reached the way a v1-only gateway is reached: the UNSUPP_VERSION answer.
     * No jitter here — RFC 6886 knows none — so every gap is an equality. ---- */
    {
        sess x;
        sess_open(&x, "d2");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "D2_pcp_request");
        const uint8_t unsupp[4] = {0, 0, 0, 1}; /* Vers 0, OP 0, Result 1 = UNSUPP_VERSION */
        gw_send(unsupp, 4);
        pump_ms(x.n, 40);
        ck_eq(gw_wait(req, sizeof req, 300), 2, "D2_natpmp_addr_request");
        ck(req[0] == 0 && req[1] == 0, "D2_natpmp_addr_query");
        gw_drain();
        int attempts = 1;
        uint32_t base = NATPMP_IRT_MS;
        for (int i = 0; i < 8; i++) {
            if (!pm_wait_close(x.s->pm, base)) {
                printf("FAIL D2_wait_%d got=%ld want=%u\n", i, pm_wait_ms(x.s->pm), base);
                fails++;
                break;
            }
            if (x.s->pm->gap != base * 2) {
                printf("FAIL D2_base_%d got=%u want=%u\n", i, x.s->pm->gap, base * 2);
                fails++;
                break;
            }
            if (!pm_send_at_due(&x)) {
                printf("FAIL D2_send_at_due_%d base=%u wait=%ld\n", i, base, pm_wait_ms(x.s->pm));
                fails++;
                break;
            }
            attempts++;
            base *= 2;
        }
        ck_eq(attempts, 9, "D2_nine_attempts_natpmp");
        ck(!gw_pending(), "D2_no_tenth_attempt_natpmp");
        ntx_portmap_test_advance_ms(base * 2); /* past the last scheduled gap */
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "D2_none_after_budget");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- D3. the PCP gap doubles but never past MRT (RFC 6887 §8.1.1, 1024 s).
     * Nine sends per query cannot reach 1024 s on its own, so the doubling step is
     * driven at the cap directly: with the gap already at MRT, the next step must
     * stay AT MRT instead of doubling past it. ---- */
    {
        sess x;
        sess_open(&x, "d3");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "D3_request");
        gw_drain();
        x.s->pm->gap = 1024000u; /* MRT: the step below would double this */
        pm_send(x.s->pm);
        ck_eq(x.s->pm->gap, 1024000u, "D3_doubling_caps_at_MRT");
        ck_eq(gw_get(req, sizeof req), 60, "D3_send_still_goes_out");
        pm_check_jitter(&x, PCP_IRT_MS, "D3_jitter_at_IRT");
        pm_check_jitter(&x, 1024000u, "D3_jitter_at_MRT");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- E. UNSUPP_VERSION, then NAT-PMP ---- */
    {
        sess x;
        sess_open(&x, "e");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[16];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "E_pcp_request");
        const uint8_t unsupp[4] = {0, 0, 0, 1}; /* RFC 6886 §3.5: Vers 0, OP 0, Result 1 */
        gw_send(unsupp, 4);
        pump_ms(x.n, 40);
        int n = gw_wait(req, sizeof req, 300);
        ck_eq(n, 2, "E_natpmp_addr_request_len");
        ck(n == 2 && req[0] == 0 && req[1] == 0, "E_natpmp_addr_request");
        uint8_t aresp[12];
        natpmp_addr_resp(aresp, 203, 0, 113, 9);
        gw_send(aresp, 12);
        pump_ms(x.n, 40);
        n = gw_wait(req, sizeof req, 300);
        ck_eq(n, 12, "E_natpmp_tcp_request_len");
        ck(n == 12 && req[0] == 0 && req[1] == 2 && rd32(req + 8) == 7200, "E_natpmp_tcp_request");
        ck(n == 12 && ((req[4] << 8) | req[5]) == ntx_netx_port(x.n), "E_natpmp_int_port");
        uint16_t lp = (uint16_t)ntx_netx_port(x.n);
        natpmp_map_resp(rsp, 2, lp, EXT_PORT, 3600);
        gw_send(rsp, 16);
        pump_ms(x.n, 40);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "E_active_via_natpmp");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "E_adv_port_natpmp");
        n = gw_wait(req, sizeof req, 300);
        ck_eq(n, 12, "E_natpmp_udp_request_len");
        ck(n == 12 && req[1] == 1, "E_natpmp_udp_request");
        natpmp_map_resp(rsp, 1, lp, EXT_PORT, 3600);
        gw_send(rsp, 16);
        pump_ms(x.n, 40);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "E_active_udp_natpmp");
        gw_drain();
        ntx_session_portmap_stop(x.s);
        int zero = 0, total = 0;
        for (ssize_t r; (r = gw_get(req, sizeof req)) >= 0;) {
            total++;
            if (r == 12 && rd32(req + 8) == 0) zero++;
        }
        ck_eq(total, 2, "E_stop_sends_only");
        ck_eq(zero, 2, "E_natpmp_stop_lifetime0");
        sess_close(&x);
    }

/* ---- F. CGNAT external address, and the one-off diagnosis ---- */
    {
        char diagpath[256], diag2[256];
        snprintf(diagpath, sizeof diagpath, "%s/diag.log", SCRATCH);
        snprintf(diag2, sizeof diag2, "%s/diag2.log", SCRATCH);
        unlink(diagpath);
        unlink(diag2);
        ck_eq(ntx_diag_open(diagpath), 0, "F_diag_capture");
        sess x;
        sess_open(&x, "f");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "F_request");
        uint8_t cgn[16];
        pcp_v4(cgn, 100, 64, 1, 1);
        pcp_resp(rsp, req, EXT_PORT, cgn, 7200, 7);
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_CGNAT, "F_cgnat");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "F_cgnat_adv_port");
        /* Nothing was ever granted here (the verdict lands on the FIRST ask), so the
         * verdict owes the gateway nothing: no lifetime-0 datagram. R18's deletes are
         * for mappings actually held at the instant of the verdict. */
        ck(!gw_pending(), "F_cgnat_no_grant_no_delete");
        gw_drain();
        for (int i = 0; i < 4; i++) {
            ntx_portmap_test_advance_ms(60000);
            pm_tick(&x);
            pump_ms(x.n, 10);
        }
        ck(!gw_pending(), "F_cgnat_stays_quiet");
        gw_drain();
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        char *text = read_all(diagpath);
        ck(text && strstr(text, "port mapping will not help: the ISP uses CGNAT"), "F_warning_text");
        free(text);

        /* A second detection must not repeat it (§8: the diagnosis is stated once). */
        ck_eq(ntx_diag_open(diag2), 0, "F2_diag_capture");
        sess y;
        sess_open(&y, "f2");
        y.cfg.port_map = 1;
        pm_start(&y);
        ck_eq(gw_wait(req, sizeof req, 300), 60, "F2_request");
        pcp_resp(rsp, req, EXT_PORT, cgn, 7200, 7);
        gw_send(rsp, 60);
        pump_ms(y.n, 40);
        pm_tick(&y);
        ck(ntx_session_portmap_state(y.s) == NTX_PM_CGNAT, "F2_cgnat");
        ntx_session_portmap_stop(y.s);
        sess_close(&y);
        text = read_all(diag2);
        ck(text && !strstr(text, "CGNAT"), "F_warning_once");
        free(text);
        ntx_diag_close();
    }

    /* ---- F3 / F4. R18: the CGNAT verdict deletes what it is giving up on.
     *
     * `pm_cgnat` dropped the grant state without ever telling the gateway, so the
     * firewall entries the client had just been handed stayed armed until their
     * lifetime ran out — up to 7200 s of inbound hole behind a mapping ntx had
     * publicly given up on. RFC 6887 §11.1 / RFC 6886 §3.3: lifetime 0 with the
     * nonce the grant was made with, BEFORE `pm_clear_grants` wipes that state
     * (after it, `active` is 0 and there is nothing left to build the delete from).
     * Pre-fix both cases: state CGNAT, grants cleared, ZERO datagrams on the wire. */

    /* F3. PCP: the TCP mapping is HELD and the verdict arrives on the UDP ask —
     * the MAP reply for the phase that never got a grant names a CGNAT external
     * address. Only the TCP mapping is held, so exactly one delete goes out, with
     * the TCP grant's nonce (§11.1). */
    {
        sess x;
        sess_open(&x, "f3");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t pub[16], cgn[16], req[2048], rsp[64], ureq[60], tdel[12];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_v4(cgn, 100, 64, 1, 1);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "F3_active_before_verdict");
        uint8_t gn[12];
        memcpy(gn, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        gw_drain();
        ck(pm_next_req(&x, NTX_PCP_PROTO_UDP, ureq), "F3_udp_query_out");
        memset(tdel, 0, sizeof tdel);
        pcp_resp(rsp, ureq, EXT_PORT, cgn, 7200, gw_epoch_live(x.s->pm));
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_CGNAT, "F3_cgnat");
        int dels = 0, tcp_dels = 0, udp_dels = 0;
        for (ssize_t r; (r = gw_get(req, sizeof req)) >= 0;) {
            if (r != 60 || rd32(req + 4) != 0) continue;
            dels++;
            if (req[36] == NTX_PCP_PROTO_TCP) {
                tcp_dels++;
                memcpy(tdel, req + 24, 12);
                ck_eq((req[42] << 8) | req[43], EXT_PORT, "F3_delete_suggests_granted_port");
                ck(memcmp(req + 44, pub, 16) == 0, "F3_delete_suggests_granted_ip");
            }
            if (req[36] == NTX_PCP_PROTO_UDP) udp_dels++;
        }
        ck_eq(dels, 1, "F3_one_delete_for_the_held_mapping");
        ck_eq(tcp_dels, 1, "F3_tcp_delete_sent");
        ck(memcmp(tdel, gn, 12) == 0, "F3_delete_repeats_grant_nonce");
        ck_eq(udp_dels, 0, "F3_no_delete_for_the_ungranted_phase");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "F3_adv_port_after_verdict");
        for (int i = 0; i < 4; i++) {
            ntx_portmap_test_advance_ms(60000);
            pm_tick(&x);
            pump_ms(x.n, 10);
        }
        ck(!gw_pending(), "F3_stays_quiet_after_the_deletes");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* F4. NAT-PMP: both mappings are held and the verdict arrives on the
     * external-address query — the arm of the CGNAT check the ordinary single-pass
     * flow never reaches with a grant in hand (the ADDR query always comes first;
     * only a family switch re-arms it, which is the state pm_refused/UNSUPP_VERSION
     * leaves and what `addr_done = 0` puts the driver back into here). The deletes
     * are the NAT-PMP shape: 12 B, lifetime 0, one per held mapping. */
    {
        sess x;
        sess_open(&x, "f4");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[16], aresp[12];
        uint16_t lp = ntx_netx_port(x.n);
        ck(gw_to_natpmp_map(&x, req, sizeof req) == 12, "F4_natpmp_map_query");
        natpmp_map_resp(rsp, 2, lp, EXT_PORT, 3600); /* RFC 6886 §3.3: OP 2 = TCP */
        gw_send(rsp, 16);
        pump_ms(x.n, 40);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "F4_tcp_active");
        ck_eq(gw_wait(req, sizeof req, 300), 12, "F4_udp_map_query");
        ck(req[1] == 1, "F4_udp_map_opcode");
        natpmp_map_resp(rsp, 1, lp, EXT_PORT, 3600); /* OP 1 = UDP */
        gw_send(rsp, 16);
        pump_ms(x.n, 40);
        gw_drain();
        x.s->pm->addr_done = 0; /* the family switch's state: the ADDR ask is owed */
        pm_tick(&x);
        ck_eq(gw_wait(req, sizeof req, 300), 2, "F4_addr_query_out");
        natpmp_addr_resp(aresp, 100, 64, 1, 1);
        gw_send(aresp, sizeof aresp);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_CGNAT, "F4_cgnat");
        int dels = 0, tcp_dels = 0, udp_dels = 0;
        for (ssize_t r; (r = gw_get(req, sizeof req)) >= 0;) {
            if (r != 12 || rd32(req + 8) != 0) continue;
            dels++;
            ck_eq(req_int_port(req), lp, "F4_delete_names_the_internal_port");
            /* RFC 6886 §3.3: opcode 1 is UDP, 2 is TCP — same as pm_op_of. */
            if (req[1] == 2) tcp_dels++;
            if (req[1] == 1) udp_dels++;
        }
        ck_eq(dels, 2, "F4_two_deletes_for_two_held_mappings");
        ck_eq(tcp_dels, 1, "F4_tcp_delete_sent");
        ck_eq(udp_dels, 1, "F4_udp_delete_sent");
        for (int i = 0; i < 4; i++) {
            ntx_portmap_test_advance_ms(60000);
            pm_tick(&x);
            pump_ms(x.n, 10);
        }
        ck(!gw_pending(), "F4_stays_quiet_after_the_deletes");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- G. renewal at half the granted lifetime ---- */
    {
        sess x;
        sess_open(&x, "g");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "G_active");
        gw_drain();
        ntx_portmap_test_advance_ms(3599000);
        pm_tick(&x);
        ck(!gw_pending(), "G_no_early_renew");
        ntx_portmap_test_advance_ms(2000);
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "G_renew_sent");
        ck(req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "G_renew_is_pcp_tcp");
        ck_eq(req_int_port(req), ntx_netx_port(x.n), "G_renew_internal_port");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- H. epoch rollback (RFC 6887 §8.5) re-requests — exactly once.

     * The gateway reboots between two replies: its Epoch counter starts over (RFC
     * 6887 §8.7), so the renewal answer carries an Epoch far below the baseline. The
     * case used to answer the grant with Epoch 7, the rollback with 3 and the
     * re-request with 7 again — the last one above the baseline, so the reply that had
     * to re-trigger the defect never did and the loop of R10 was invisible (the review
     * says the same: "Test H odtwarza epokę 7 = bazowej, więc pętli nie widzi"). The
     * gateway here is rebooted for good — every answer it gives is 0 — which is what
     * turns "re-request from inside the receive path" into a datagram per round trip.
     * Pre-fix: H_one_re_request_not_a_loop got=30 want=1, H_recovered and
     * H_recovered_adv_port got=6881 want=40124. */
    {
        sess x;
        sess_open(&x, "h");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "H_active");
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_get(req, sizeof req), 60, "H_renew_sent");
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 0); /* counter starts over: §8.5 restart */
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "H_rollback_pending");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "H_rollback_no_adv_port");
        /* One re-request for one rollback, on the schedule — not one per round trip.
         * The gateway is still the rebooted one, so its counter is near zero; the
         * first answer to the re-request becomes the new baseline and is granted. */
        ck_eq(pcp_answer_all(&x, NTX_PCP_PROTO_TCP, 40124, pub, 7200, 0, "H", 1000, 30), 1,
              "H_one_re_request_not_a_loop");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "H_recovered");
        ck_eq(ntx_session_adv_port(x.s), 40124, "H_recovered_adv_port");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- H2. an Epoch too LARGE for the elapsed time is a restart too (§8.5).

     * The rollback alone cannot see a gateway claiming far more uptime than the
     * client's own clock says has passed since the last answer — §8.5's second
     * condition. Pre-fix only `epoch < baseline` counted, so this reply was a plain
     * grant: the state stayed ACTIVE on a stale port and nothing was ever re-requested
     * (H2_rollback_pending, H2_rollback_no_adv_port got=40123 want=6881,
     * H2_one_re_request got=0 want=1, H2_recovered_adv_port got=40123 want=40125). */
    {
        sess x;
        sess_open(&x, "h2");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "H2_active");
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_get(req, sizeof req), 60, "H2_renew_sent");
        /* 3 000 000 000 s ≈ 95 years of uptime, seconds after an answer that said
         * ~3600: the counter cannot have moved that far, so this is a restart. */
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 3000000000u);
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "H2_rollback_pending");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "H2_rollback_no_adv_port");
        ck_eq(pcp_answer_all(&x, NTX_PCP_PROTO_TCP, 40125, pub, 7200, PCP_EPOCH_LIVE, "H2", 1000, 30), 1,
              "H2_one_re_request_not_a_loop");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "H2_recovered");
        ck_eq(ntx_session_adv_port(x.s), 40125, "H2_recovered_adv_port");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- H3. lifetime 0 in a MAP reply is a refusal, not a re-request (R10).

     * RFC 6887 §11.1 makes Lifetime 0 the delete, so a SUCCESS MAP reply carrying it
     * grants nothing. Pre-fix this went to pm_lost, which sent a fresh query from
     * inside the receive path — and the fresh query was answered with lifetime 0
     * again, so requests and refusals chased each other. As a refusal (the S10 rule)
     * the schedule ends and nothing more goes out: lifetime 0 names no wait, so there
     * is no deferred retry either. Pre-fix: H3_none, H3_nothing_outstanding got=1
     * want=-1, H3_no_retries got=1 want=0, H3_no_further_resend got=6 want=0,
     * H3_stays_none. */
    {
        sess x;
        sess_open(&x, "h3");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "H3_request");
        pcp_resp(rsp, req, EXT_PORT, pub, 0, gw_epoch_live(x.s->pm));
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "H3_none");
        ck_eq(x.s->pm->phase, -1, "H3_nothing_outstanding");
        ck_eq(x.s->pm->tries, 0, "H3_no_retries");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "H3_none_adv_port");
        ck_eq(pm_sends_in(&x, 60000, 6), 0, "H3_no_further_resend");
        /* And it stays that way while the gateway keeps answering: a driver that
         * re-requests from the rx path is handed a fresh refusal with every answer. */
        ck_eq(pcp_answer_all(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 0, PCP_EPOCH_LIVE, "H3b", 1000, 30), 0,
              "H3_zero_lifetime_no_loop");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "H3_stays_none");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- H4. NAT-PMP: lifetime 0 in the mapping reply is the same refusal (R10).

     * RFC 6886 §3.3 puts the Lifetime in the mapping response and 0 means the mapping
     * is not held, so both families must answer it the same way. Pre-fix both called
     * pm_lost — NAT-PMP at its 250 ms schedule (H4_none, H4_nothing_outstanding got=1
     * want=-1, H4_no_further_resend got=8 want=0). ---- */
    {
        sess x;
        sess_open(&x, "h4");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[16];
        ck_eq(gw_to_natpmp_map(&x, req, sizeof req), 12, "H4_natpmp_map_request");
        natpmp_map_resp(rsp, 2, (uint16_t)ntx_netx_port(x.n), EXT_PORT, 0);
        gw_send(rsp, sizeof rsp);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "H4_none");
        ck_eq(x.s->pm->phase, -1, "H4_nothing_outstanding");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "H4_none_adv_port");
        gw_send(rsp, sizeof rsp); /* the same refusal again: still nothing goes out */
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck_eq(pm_sends_in(&x, 60000, 6), 0, "H4_no_further_resend");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- H5. the same rollbacked reply five times: still one re-request (R10).

     * Re-delivery is what UDP under loss does, and it is what multiplied the requests
     * pre-fix: every copy re-entered pm_lost and pm_lost sent. Pre-fix:
     * H5_one_re_request_for_five_replies got=30 want=1. ---- */
    {
        sess x;
        sess_open(&x, "h5");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_get(req, sizeof req), 60, "H5_renew_sent");
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 0);
        for (int i = 0; i < 5; i++) {
            gw_send(rsp, 60);
            pump_ms(x.n, 20);
        }
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "H5_rollback_pending");
        ck_eq(pcp_answer_all(&x, NTX_PCP_PROTO_TCP, 40126, pub, 7200, PCP_EPOCH_LIVE, "H5", 1000, 30), 1,
              "H5_one_re_request_for_five_replies");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "H5_recovered");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- H6. an Epoch that never agrees with our clock ends the sequence.

     * A gateway whose counter stands still is a restart on every answer (§8.5's lower
     * bound), and each detection legitimately arms one re-request — so a driver that
     * only re-requests cannot loop, but it can still be walked forever by a broken
     * counter. PM_MAX_RESTARTS bounds the consecutive detections: a handful of
     * queries, then the sequence is over and the state says none, like any other
     * refusal. Pre-fix: one request per answer, forever (the probe hit its cap). ---- */
    {
        sess x;
        sess_open(&x, "h6");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_get(req, sizeof req), 60, "H6_renew_sent");
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 5); /* frozen counter, far below base */
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        /* 3 s per step: every answer then lands far enough after the previous baseline
         * to be judged a restart again, which is the pathological gateway. */
        int q = pcp_answer_all(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200, 5, "H6", 3000, 40);
        if (q > 5) {
            printf("FAIL H6_bounded_queries got=%d want<=5\n", q);
            fails++;
        }
        ck(q >= 1, "H6_re-requested_at_all");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "H6_none_after_bound");
        ck_eq(x.s->pm->phase, -1, "H6_nothing_outstanding");
        ck_eq(pm_sends_in(&x, 60000, 6), 0, "H6_stays_quiet");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- I. absurd granted lifetime is capped (RFC 6887 §8.3) ---- */
    {
        sess x;
        sess_open(&x, "i");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "I_request");
        pcp_resp(rsp, req, EXT_PORT, pub, 4000000000u, 7);
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "I_active_capped");
        gw_drain();
        ntx_portmap_test_advance_ms(3599000);
        pm_tick(&x);
        ck(!gw_pending(), "I_renew_at_capped_half");
        ntx_portmap_test_advance_ms(2000);
        pm_tick(&x);
        ck_eq(gw_get(req, sizeof req), 60, "I_capped_renew_sent");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- O. a renewal and a delete carry the nonce of the GRANT (R13).
     *
     * RFC 6887 §11.2: the gateway identifies a mapping by the nonce, so renewing one
     * means sending the SAME request again — a fresh nonce reads as a request for a
     * NEW mapping, and the mapping already in place is left to expire on its own
     * (7200 s) next to the new one. §11.1: a delete carries the grant's nonce too, or
     * the gateway has no mapping to match it against and drops the datagram.
     * Pre-fix `pm_start_query` drew a fresh nonce for EVERY query, renewals included,
     * and copied it into `grant_nonce[phase]` at SEND time, so the renewal asked for a
     * second mapping and the delete of a renewal in flight named a nonce the gateway
     * was never asked about. ---- */

    /* O1. the renewal is the grant's request again: same nonce, and it suggests the
     * address and port the gateway assigned (§11.2). */
    {
        sess x;
        sess_open(&x, "o1");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        uint8_t gn[12];
        memcpy(gn, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000); /* past half of the 7200 s grant */
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "O1_renew_sent");
        ck(req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "O1_renew_is_pcp_tcp");
        ck(memcmp(req + 24, gn, 12) == 0, "O1_renew_reuses_grant_nonce");
        ck_eq((req[42] << 8) | req[43], EXT_PORT, "O1_renew_suggests_granted_port");
        ck(memcmp(req + 44, pub, 16) == 0, "O1_renew_suggests_granted_ip");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* O2. two renewals in a row keep that one nonce — it belongs to the mapping, not
     * to the query. */
    {
        sess x;
        sess_open(&x, "o2");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        uint8_t gn[12];
        memcpy(gn, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        gw_drain();
        uint8_t req[2048], rsp[64];
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        ck_eq(gw_get(req, sizeof req), 60, "O2_renew1_sent");
        ck(memcmp(req + 24, gn, 12) == 0, "O2_renew1_same_nonce");
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, gw_epoch_live(x.s->pm));
        gw_send(rsp, 60);
        pump_ms(x.n, 20);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        ck_eq(gw_get(req, sizeof req), 60, "O2_renew2_sent");
        ck(memcmp(req + 24, gn, 12) == 0, "O2_renew2_same_nonce");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* O3. stop() with a renewal unanswered: the lifetime-0 delete repeats the NONCE
     * THE GATEWAY GRANTED, not the one the outstanding renewal happened to carry. */
    {
        sess x;
        sess_open(&x, "o3");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        uint8_t gn[12];
        memcpy(gn, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048], dn[12];
        ck_eq(gw_get(req, sizeof req), 60, "O3_renew_in_flight");
        ck_eq(rd32(req + 4), 7200, "O3_renew_is_no_delete");
        ck(memcmp(req + 24, gn, 12) == 0, "O3_renewal_carries_grant_nonce");
        memset(dn, 0, sizeof dn);
        ntx_session_portmap_stop(x.s);
        int dels = 0;
        while (gw_get(req, sizeof req) >= 0) {
            if (rd32(req + 4) != 0 || req[36] != NTX_PCP_PROTO_TCP) continue;
            dels++;
            memcpy(dn, req + 24, 12);
        }
        ck_eq(dels, 1, "O3_one_delete");
        ck(memcmp(dn, gn, 12) == 0, "O3_delete_repeats_grant_nonce");
        sess_close(&x);
    }

    /* O4. the other side of the rule, so O1 cannot be satisfied by never refreshing:
     * the acquisition after a §8.5 rollback is a NEW mapping and MUST draw a new
     * nonce (and state no preference for the external address again, §11.1). */
    {
        sess x;
        sess_open(&x, "o4");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        uint8_t gn[12];
        memcpy(gn, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048], rsp[64], zeros[16];
        memset(zeros, 0, sizeof zeros);
        ck_eq(gw_get(req, sizeof req), 60, "O4_renew_sent");
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 0); /* the counter starts over: restart */
        gw_send(rsp, 60);
        pump_ms(x.n, 20);
        pm_tick(&x); /* the tick owes the one fresh query of the rollback (R10) */
        ck_eq(gw_get(req, sizeof req), 60, "O4_fresh_query_sent");
        ck(req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "O4_fresh_query_is_pcp_tcp");
        ck(memcmp(req + 24, gn, 12) != 0, "O4_new_acquisition_draws_new_nonce");
        ck(memcmp(req + 44, zeros, 16) == 0, "O4_fresh_ask_no_suggested_ip");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- P. the gateway goes quiet AFTER a grant: the grant is lost, not kept (R12).

     * The renewal of a mapping is answered by nothing. The retransmission budget runs
     * out, the gateway lets the mapping expire at the end of its lifetime — and the
     * driver used to keep the grant: `pm_give_up_phase` set `failed[ph]` and left
     * `active[ph] = 1`, so the state stayed ACTIVE forever, `ntx_session_adv_port`
     * went on handing out the port the gateway had stopped forwarding (announce and
     * the ext-handshake `p` told the swarm to dial a dead port), and the renewal loop,
     * which only walks `active && !failed`, never asked for a mapping again. Pre-fix
     * failures of this group: P1_adv_port_back_to_listen got=40123 want=6881,
     * P1_pending_after_renewal_failed (state stayed 2), P1_grant_dropped got=1,
     * P1_announce_back_to_listen got=40123, P2_no_reacquisition_window /
     * P2_adv_port_new_ext / P2_reannounce_carries_new_ext, and P4_tcp_renewal_lost_* —
     * i.e. nothing ever came back. ---- */

    /* P1. the whole renewal budget dies: adv_port returns the LISTEN port, the state
     * says a re-acquisition is owed, and the re-acquisition is bounded. */
    {
        sess x;
        sess_open(&x, "p1");
        x.cfg.port_map = 1;
        one_torrent(&x);
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "P1_active");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "P1_adv_port");
        uint8_t gn[12];
        memcpy(gn, granted_nonce[NTX_PCP_PROTO_TCP], 12);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000); /* past half of the 7200 s grant */
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "P1_renew_sent");
        ck(memcmp(req + 24, gn, 12) == 0, "P1_renewal_is_the_grant_query");
        /* The budget, spent in silence. */
        ck(pm_burn_budget(&x, PM_PH_TCP), "P1_budget_exhausted");
        ck_eq(x.s->pm->phase, -1, "P1_nothing_outstanding");
        ck_eq(x.s->pm->active[PM_PH_TCP], 0, "P1_grant_dropped");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "P1_adv_port_back_to_listen");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "P1_pending_after_renewal_failed");
        /* The swarm is told, not left dialling the dead port. */
        ck_eq(announce_port_on_wire(&x), ntx_netx_port(x.n), "P1_announce_back_to_listen");
        /* Re-acquisition is owed and paced: over two hours a handful of FRESH queries
         * (the grant's own nonce excluded), not zero and not hundreds. */
        int q = pm_fresh_queries_in(&x, NTX_PCP_PROTO_TCP, gn, 60000, 120);
        if (q < 1 || q > 24) {
            printf("FAIL P1_bounded_reacquisition got=%d want=1..24\n", q);
            fails++;
        }
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* P2. the gateway answers again, with a DIFFERENT external port: the re-acquisition
     * must take it and the share must re-announce with it (the S09 path, on a RE-grant). */
    {
        sess x;
        sess_open(&x, "p2");
        x.cfg.port_map = 1;
        one_torrent(&x);
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        gw_drain(); /* the gateway was quiet for the whole budget */
        ck(pm_burn_budget(&x, PM_PH_TCP), "P2_budget_exhausted");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "P2_adv_port_back_to_listen");
        uint8_t dead[12];
        memcpy(dead, granted_nonce[NTX_PCP_PROTO_TCP], 12); /* the nonce of the grant that died */
        pcp_grant_whenever(&x, NTX_PCP_PROTO_TCP, 40131, pub, 7200);
        /* §11.1/§11.2 (R13): with no live grant the ask is a NEW acquisition, so it must
         * not go out under the dead mapping's nonce — the gateway keys on it, and a repeat
         * would renew (and later delete) a mapping that is already gone. */
        ck(memcmp(granted_nonce[NTX_PCP_PROTO_TCP], dead, 12) != 0, "P2_reacquisition_draws_fresh_nonce");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "P2_reacquired");
        ck_eq(ntx_session_adv_port(x.s), 40131, "P2_adv_port_new_ext");
        ck_eq(announce_port_on_wire(&x), 40131, "P2_reannounce_carries_new_ext");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* P3. the other edge: a renewal that is merely IN FLIGHT keeps the grant advertised.
     * The gateway still holds the mapping until its lifetime runs out, so dropping the
     * port here would take a working share off the reachable address for nothing. */
    {
        sess x;
        sess_open(&x, "p3");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "P3_renew_sent");
        for (int i = 0; i < 4 && x.s->pm->tries < 5; i++) {
            long w = pm_wait_ms(x.s->pm);
            ntx_portmap_test_advance_ms((uint64_t)(w > 0 ? w + 5 : 5));
            pm_tick(&x);
        }
        ck(x.s->pm->tries >= 3, "P3_retransmissions_made");
        ck(x.s->pm->tries < (int)PM_MAX_TRIES, "P3_budget_not_spent");
        ck_eq(x.s->pm->active[PM_PH_TCP], 1, "P3_in_flight_still_holds");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "P3_in_flight_advertises_grant");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "P3_in_flight_stays_active");
        ck_eq(ext_handshake_port(&x), EXT_PORT, "P3_ext_handshake_in_flight");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* P4. both mappings. `ntx_session_adv_port` depends on the TCP mapping alone, so a
     * UDP mapping that dies must not cost the advertised TCP port, and a TCP mapping
     * that dies must cost it — with the live UDP mapping left alone. Pinned as it is,
     * not as one might wish it were: the UDP external port is never advertised
     * anywhere, so nothing about a dead UDP grant can reach the swarm. */
    {
        sess x;
        sess_open(&x, "p4u");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        both_active(&x, EXT_PORT, pub);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "P4u_both_active");
        gw_drain();
        ntx_portmap_test_advance_ms(3601000); /* both renew windows open */
        pm_tick(&x);
        uint8_t req[2048];
        /* The TCP renewal is the first query out; answer it, so only UDP dies. */
        ck_eq(gw_get(req, sizeof req), 60, "P4u_tcp_renew_sent");
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        uint8_t ureq[60];
        ck(pm_next_req(&x, NTX_PCP_PROTO_UDP, ureq), "P4u_udp_renew_sent");
        ck_eq(x.s->pm->phase, PM_PH_UDP, "P4u_udp_renewal_outstanding");
        ck(pm_burn_budget(&x, PM_PH_UDP), "P4u_udp_budget_exhausted");
        ck_eq(x.s->pm->active[PM_PH_UDP], 0, "P4u_udp_grant_dropped");
        ck_eq(x.s->pm->active[PM_PH_TCP], 1, "P4u_tcp_grant_kept");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "P4u_dead_udp_keeps_tcp_port");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "P4u_stays_active");
        int q = pm_fresh_queries_in(&x, NTX_PCP_PROTO_UDP, NULL, 60000, 30);
        if (q < 1 || q > 12) {
            printf("FAIL P4u_udp_reacquisition_bounded got=%d want=1..12\n", q);
            fails++;
        }
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }
    {
        sess x;
        sess_open(&x, "p4t");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        one_torrent(&x);
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        both_active(&x, EXT_PORT, pub);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "P4t_tcp_renew_sent");
        ck(pm_burn_budget(&x, PM_PH_TCP), "P4t_tcp_budget_exhausted");
        ck_eq(x.s->pm->active[PM_PH_TCP], 0, "P4t_tcp_grant_dropped");
        ck_eq(x.s->pm->active[PM_PH_UDP], 1, "P4t_udp_grant_untouched");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "P4t_dead_tcp_drops_adv_port");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "P4t_pending_while_tcp_owed");
        ck_eq(announce_port_on_wire(&x), ntx_netx_port(x.n), "P4t_announce_drops_dead_port");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* P5. the lifetime half of the adv_port rule: a gateway whose grant is shorter than
     * one send cycle. The renewal is legitimately still in flight (its budget is not
     * spent), yet the gateway has stopped forwarding the port at the end of its
     * Lifetime, so the port must not be advertised any more. With the normal 7200 s
     * grant this can never happen — the nine PCP sends end ~783 s in, far inside the
     * 3600 s renew window — which is why the case hands out 40 s. */
    {
        sess x;
        sess_open(&x, "p5");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 40);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "P5_active");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "P5_adv_port_while_held");
        gw_drain();
        ntx_portmap_test_advance_ms(21000); /* past renew_at = life/2, renewal goes out */
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "P5_renew_sent");
        ck_eq(x.s->pm->tries, 1, "P5_one_send_only");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "P5_in_flight_inside_lifetime");
        ntx_portmap_test_advance_ms(20000); /* the lifetime has now run out here too */
        ck_eq(x.s->pm->tries, 1, "P5_still_in_flight");
        ck_eq(x.s->pm->active[PM_PH_TCP], 1, "P5_grant_still_recorded");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "P5_no_port_past_lifetime");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* P6. the backoff is BOUNDED and does not stop. The re-acquisition must go on for
     * the life of the share (a router reboot outlives an hour) but never turn into a
     * storm, so a whole day against a dead gateway is counted here: the asks keep
     * coming, and their number has an upper bound a runaway would blow. The schedule
     * is one nine-send query cycle per wait, and the wait doubles per ask from 5 min to
     * the 1 h ceiling, so a day costs a few dozen asks, not thousands. Pre-fix: nothing
     * came at all after the renewal died (the probe counted 0). */
    {
        sess x;
        sess_open(&x, "p6");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&x);
        gw_drain();
        ck(pm_burn_budget(&x, PM_PH_TCP), "P6_budget_exhausted");
        /* 24 h of silence, one tick a minute. */
        int q = pm_fresh_queries_in(&x, NTX_PCP_PROTO_TCP, granted_nonce[NTX_PCP_PROTO_TCP], 60000, 1440);
        if (q < 8) {
            printf("FAIL P6_kept_asking got=%d want>=8\n", q);
            fails++;
        }
        if (q > 60) {
            printf("FAIL P6_backoff_bound got=%d want<=60\n", q);
            fails++;
        }
        /* And the ceiling really is a ceiling: the last ask of the day waits an hour, so
         * the tail of the window holds at most two of them per hour. */
        int tail = pm_fresh_queries_in(&x, NTX_PCP_PROTO_TCP, granted_nonce[NTX_PCP_PROTO_TCP], 60000, 120);
        if (tail > 6) {
            printf("FAIL P6_ceiling_holds tail=%d want<=6\n", tail);
            fails++;
        }
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "P6_no_stale_port_after_a_day");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- M. a datagram that carries no verdict at all: no grant, no immediate
     * resend, and the retransmission schedule continues (§8.3).     *
     * This case used to answer with result 7 (NETWORK_FAILURE) and then pin the
     * driver retransmitting the query eight more times, i.e. it pinned the very
     * behaviour review §6 / R14 calls the defect: a refusal the gateway stated
     * outright was indistinguishable from silence. The pacing probe now rides a
     * reply that is not an answer (opcode PEER, not MAP), which is the one thing
     * that legitimately leaves the schedule running. The refusals are M2..M7. ---- */
    {
        sess x;
        sess_open(&x, "m");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M_request");
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 7);
        rsp[1] = 0x82; /* R set, opcode PEER: not an answer to a MAP query */
        gw_send(rsp, 60);
        pump_ms(x.n, 120); /* two real ticks */
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "M_no_grant");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "M_no_adv_port");
        ck(!gw_pending(), "M_no_immediate_resend");
        /* The outstanding query is PCP, so the schedule it retransmits on is the
         * RFC 6887 §8.1.1 one: base IRT 3 s, doubled after the first send — not the
         * 250 ms of RFC 6886 §3.1 that this case used to pin (R11). The base is read
         * from the driver because the pump below has already spent real clock, which
         * a `next_try − now` probe could not discount. The jitter itself is pinned on
         * the wire in case D, where nothing consumes real time around the send. */
        ck_eq(x.s->pm->gap, 2u * PCP_IRT_MS, "M_resend_schedule");
        ck(pm_send_at_due(&x), "M_resend_on_schedule");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- M2. PCP NOT_AUTHORIZED as a 24 B result-only error (R14).

     * RFC 6887 §7.2 puts the verdict in the common header, which an error reply may
     * carry on its own. Pre-fix the codec demanded the whole 60 B MAP reply before it
     * would read octet 3, so this refusal was indistinguishable from silence: the
     * driver replayed the nine-send schedule (~128 s of PCP) against a gateway that
     * had already said no, and the state stayed `pending`. Pre-fix failure:
     * M2_no_further_resend got=8 want=0, M2_none got=1 want=3, and the result code
     * is absent from the verbose log. ---- */
    {
        char diagpath[256];
        snprintf(diagpath, sizeof diagpath, "%s/diag_m2.log", SCRATCH);
        unlink(diagpath);
        ck_eq(ntx_diag_open(diagpath), 0, "M2_diag_capture");
        sess x;
        sess_open(&x, "m2");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], err[24];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M2_request");
        pcp_err24(err, PCP_RES_NOT_AUTHORIZED, 1800);
        gw_send(err, sizeof err);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M2_none");
        ck_eq(x.s->pm->phase, -1, "M2_nothing_outstanding");
        ck_eq(x.s->pm->tries, 0, "M2_no_retries");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "M2_none_adv_port");
        ck_eq(pm_sends_in(&x, 60000, 6), 0, "M2_no_further_resend");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        char *text = read_all(diagpath);
        ck(text && strstr(text, "NOT_AUTHORIZED") && strstr(text, "2"), "M2_verbose_result_code");
        free(text);
        ntx_diag_close();
    }

    /* ---- M3. PCP NOT_AUTHORIZED in a full 60 B MAP reply (R14).

     * The other half of the same defect: the reply is long enough to parse and the
     * result octet is non-zero, which pre-fix the codec folded to "no reply" as well
     * (`result != SUCCESS` → -1). Same verdict as M2 — pre-fix: still retransmitting
     * (got=8 want=0) and the state stays `pending`. ---- */
    {
        sess x;
        sess_open(&x, "m3");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[64];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M3_request");
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_resp(rsp, req, EXT_PORT, pub, 1800, 7);
        rsp[3] = PCP_RES_NOT_AUTHORIZED;
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M3_none");
        ck_eq(x.s->pm->phase, -1, "M3_nothing_outstanding");
        ck_eq(pm_sends_in(&x, 60000, 6), 0, "M3_no_further_resend");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- M4. USER_EX_QUOTA and UNSUPP_OPCODE are definitive too (R14).

     * Both arrive as 24 B result-only errors; neither may leave the schedule running. ---- */
    {
        static const uint32_t res[] = {PCP_RES_USER_EX_QUOTA, 4u /* UNSUPP_OPCODE */};
        for (int i = 0; i < 2; i++) {
            sess x;
            sess_open(&x, "m4");
            x.cfg.port_map = 1;
            pm_start(&x);
            uint8_t req[2048], err[24];
            ck_eq(gw_wait(req, sizeof req, 300), 60, "M4_request");
            pcp_err24(err, res[i], 1800);
            gw_send(err, sizeof err);
            pump_ms(x.n, 40);
            pm_tick(&x);
            ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M4_none");
            ck_eq(pm_sends_in(&x, 60000, 6), 0, "M4_no_further_resend");
            ntx_session_portmap_stop(x.s);
            sess_close(&x);
        }
    }

    /* ---- M5. NAT-PMP opcode-128 refusals end the schedule (R14).

     * RFC 6886 §3.5: 2 Not Authorized, 3 Network Failure, 4 Out of resources, 5
     * Unsupported opcode. 3 and 4 are the retryable pair (M7/M8); with lifetime 0
     * every one of them is final, and 2 and 5 are final whatever the lifetime says.
     * Pre-fix the codec returned -1 for all of them, so all four replayed the nine
     * NAT-PMP sends and the state stayed `pending`. ---- */
    {
        static const struct {
            uint16_t res;
            const char *tag;
        } cases[] = {
            {NATPMP_RES_NOT_AUTHORIZED, "m5a"},
            {NATPMP_RES_NETWORK_FAILURE, "m5b"},
            {NATPMP_RES_UNSUPP_OPCODE, "m5c"},
            {NATPMP_RES_OUT_OF_RESOURCES, "m5d"},
        };
        for (int i = 0; i < 4; i++) {
            sess x;
            sess_open(&x, cases[i].tag);
            x.cfg.port_map = 1;
            pm_start(&x);
            uint8_t req[2048], rsp[16];
            int n = gw_to_natpmp_map(&x, req, sizeof req);
            ck_eq(n, 12, "M5_natpmp_map_request");
            natpmp_map_resp(rsp, 2, (uint16_t)ntx_netx_port(x.n), 0, 0);
            rsp[2] = 0;
            rsp[3] = (uint8_t)cases[i].res;
            gw_send(rsp, sizeof rsp);
            pump_ms(x.n, 40);
            pm_tick(&x);
            ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M5_none");
            ck_eq(x.s->pm->phase, -1, "M5_nothing_outstanding");
            ck_eq(pm_sends_in(&x, 60000, 4), 0, "M5_no_further_resend");
            ntx_session_portmap_stop(x.s);
            sess_close(&x);
        }
    }

    /* ---- M6. a refused sequence stays refused: the state is final (R14).

     * Nothing may come back to life after a definitive refusal, not through the
     * clock and not through a tick: the schedule is over, not paused. ---- */
    {
        sess x;
        sess_open(&x, "m6");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], err[24];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M6_request");
        pcp_err24(err, PCP_RES_NOT_AUTHORIZED, 1800);
        gw_send(err, sizeof err);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck_eq(pm_sends_in(&x, 600000, 12), 0, "M6_final_for_two_hours");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M6_stays_none");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- M7. NO_RESOURCES carries a retry-after: one attempt, never sooner than
     * 60 s (R14).

     * RFC 6887 §7.4 calls NO_RESOURCES and NETWORK_FAILURE short-lifetime errors and
     * §8 says the same request may succeed later, so the schedule stops (no replay of
     * the nine sends) and exactly one further attempt is made after the lifetime the
     * reply itself names. lifetime 120 → nothing before 120 s, one at 120 s; the
     * lifetime is never allowed to hurry the driver below 60 s, and lifetime 0 means
     * the gateway offered no retry at all. Pre-fix: eight sends in the 0..119 s window
     * and no single deferred attempt at 120 s. ---- */
    {
        sess x;
        sess_open(&x, "m7");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], err[24];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M7_request");
        pcp_err24(err, PCP_RES_NO_RESOURCES, 120);
        gw_send(err, sizeof err);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M7_none_while_waiting");
        ck_eq(pm_sends_in(&x, 30000, 3), 0, "M7_quiet_before_120s"); /* 0..90 s */
        ck_eq(pm_sends_in(&x, 29000, 1), 0, "M7_still_quiet_at_119s");
        ck_eq(pm_sends_in(&x, 2000, 1), 1, "M7_one_retry_after_lifetime");
        /* The retry is a real query again, so its own schedule runs from there. */
        ck_eq(x.s->pm->phase, PM_PH_TCP, "M7_retry_outstanding");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "M7_retry_pending");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }
    {
        /* The 60 s floor: a lifetime of 10 s must not buy a retry at 10 s. */
        sess x;
        sess_open(&x, "m7b");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], err[24];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M7b_request");
        pcp_err24(err, PCP_RES_NETWORK_FAILURE, 10);
        gw_send(err, sizeof err);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck_eq(pm_sends_in(&x, 29000, 2), 0, "M7b_quiet_below_60s_floor"); /* 0..58 s */
        ck_eq(pm_sends_in(&x, 3000, 1), 1, "M7b_retry_at_the_floor");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }
    {
        /* lifetime 0 in the reply = the gateway named no retry: `none` is final. */
        sess x;
        sess_open(&x, "m7c");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], err[24];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "M7c_request");
        pcp_err24(err, PCP_RES_NO_RESOURCES, 0);
        gw_send(err, sizeof err);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M7c_none");
        ck_eq(pm_sends_in(&x, 60000, 12), 0, "M7c_lifetime0_no_retry");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- M8. NAT-PMP "Out of resources" with a lifetime: same one deferred
     * attempt (RFC 6886 §3.5 codes 3 and 4 are the retryable pair). ---- */
    {
        sess x;
        sess_open(&x, "m8");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[16];
        ck_eq(gw_to_natpmp_map(&x, req, sizeof req), 12, "M8_natpmp_map_request");
        natpmp_map_resp(rsp, 2, (uint16_t)ntx_netx_port(x.n), 0, 300);
        rsp[3] = NATPMP_RES_OUT_OF_RESOURCES;
        gw_send(rsp, sizeof rsp);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "M8_none_while_waiting");
        ck_eq(pm_sends_in(&x, 55000, 4), 0, "M8_quiet_before_300s"); /* 0..220 s */
        ck_eq(pm_sends_in(&x, 90000, 1), 1, "M8_one_retry_after_lifetime"); /* → 310 s */
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- M9. a deferred retry must not stall the renewal of a grant we hold
     * (R14, the fall-through in the tick).

     * The one attempt a NO_RESOURCES promised is pending until the wait it names.
     * While we wait, a mapping that IS active still has its renew window, and losing
     * it costs the grant: the gateway drops it at the end of its lifetime. So the
     * wait has to fall through to the renewals, not return. Pre-fix the tick bailed
     * out on the pending retry and the TCP renewal never went out. ---- */
    {
        sess x;
        sess_open(&x, "m9");
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "M9_active");
        gw_drain();
        /* A retryable refusal on the UDP query, deferred to the lifetime it names. */
        x.s->pm->retry_ph = PM_PH_UDP;
        x.s->pm->retried = 1; /* the one allowed attempt is already spent: nothing to send */
        x.s->pm->retry_at = pm_now() + 7200000u; /* due long after the renew window */
        ntx_portmap_test_advance_ms(3601000); /* past the TCP renew window */
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "M9_renew_not_stalled");
        ck(req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "M9_renew_is_tcp");
        ck_eq(x.s->pm->retry_ph, PM_PH_UDP, "M9_retry_still_pending");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- J. public address on the default route: no mapping at all ---- */
    {
        write_routes(GW_PUB);
        sess x;
        sess_open(&x, "j");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "J_off_public_addr");
        ck(!gw_pending(), "J_no_datagram_public_addr");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "J_adv_port_public_addr");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        write_routes(GW_LO);
    }

    /* ---- K. proxy or tunnel: nothing on the wire, state OFF ---- */
    {
        sess x;
        sess_open(&x, "k");
        x.cfg.port_map = 1;
        x.cfg.proxy = 1;
        x.cfg.proxy_host = "127.0.0.1";
        x.cfg.proxy_port = 1080;
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "K_off_proxy");
        ck(!gw_pending(), "K_no_datagram_proxy");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "K_adv_port_proxy");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }
    {
        sess x;
        sess_open(&x, "k2");
        x.cfg.port_map = 1;
        x.cfg.tunnel = 1;
        x.cfg.tunnel_host = "127.0.0.1";
        x.cfg.tunnel_port = 4444;
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "K_off_tunnel");
        ck(!gw_pending(), "K_no_datagram_tunnel");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- L. --no-port-map: no socket, stays OFF ---- */
    {
        sess x;
        sess_open(&x, "l");
        x.cfg.port_map = -1;
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "L_off_no_port_map");
        ck(!gw_pending(), "L_no_datagram_no_port_map");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "L_adv_port_no_port_map");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- Q. R16: --port-map maps the listen port with NO share at all.

     * docs/cli.md promises it ("this flag turns it on for a session without one too")
     * and docs/network.md says the same, but the driver was only ever started by
     * ntx_session_portmap_want() from the share path (ntx_session_share_add /
     * ntx_session_share_on_remove), so with --port-map and no --share nothing was
     * ever mapped — the flag was a no-op and the status line showed no `map-`/
     * `map:` tag because the state stayed OFF. Pre-fix failures of this group:
     * Q1_pending_at_bringup got=0 want=1, Q1_no_share_datagram_on_wire got=-1
     * want=60, Q1_want_set_by_bringup got=0 want=1, Q2_no_teardown_datagrams
     * got=0 want=0-with-want-still-1 (the driver never wanted anything at all),
     * Q2_mapping_still_wanted_after_last_share got=0 want=1. ---- */

    /* Q1. the flag alone puts a PCP request on the wire — no share, no want() call
     * by hand, only what ntx_session_init owes the config. */
    {
        sess x;
        sess_open_pm(&x, "q1", 1, 0);
        /* Bring-up owes the driver nothing but the ask: `want` is set by the session
         * itself (no pm_start(), no share, no hand call), and the session's own tick
         * is what opens the socket and puts the query on the wire. */
        ck(x.s->pm && x.s->pm->want, "Q1_want_set_by_bringup");
        uint8_t req[2048];
        pump_ms(x.n, 300);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "Q1_pending_after_tick");
        int n = gw_wait(req, sizeof req, 300); /* pumped by the session's own tick */
        ck_eq(n, 60, "Q1_no_share_datagram_on_wire");
        ck(req_is(req, n, NTX_PCP_PROTO_TCP, 7200), "Q1_first_request_is_pcp_tcp");
        ck_eq(req_int_port(req), ntx_netx_port(x.n), "Q1_internal_port_is_listen_port");

        /* And it is not just the flag in the config: the grant reaches the port we
         * advertise, which is the whole point of mapping without a share. */
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "Q1_active_without_share");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "Q1_adv_port_without_share");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* Q2. a share comes and goes and the mapping the user asked for stays: the
     * session maps on its own from bring-up, the share's own ntx_session_portmap_want
     * (s, 1) must not restart that sequence, and the release at the end of
     * ntx_session_share_on_remove() — ntx_session_portmap_want(s, 0) — may drop the
     * SHARE's claim on the mapping, never the user's. */
    {
        sess x;
        sess_open_pm(&x, "q2", 1, 0);
        uint8_t req[2048];
        pump_ms(x.n, 200); /* the session tick is what opens the socket and sends */
        ck_eq(gw_wait(req, sizeof req, 300), 60, "Q2_request_at_bringup");
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "Q2_active_before_share");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "Q2_adv_port_before_share");
        gw_drain();

        char p[256];
        snprintf(p, sizeof p, "%s/q2/share.bin", SCRATCH);
        mk_file(p, 4096, 201);
        ntx_share_err se = NTX_SHARE_OK;
        int ti = ntx_session_share_add(x.s, p, NULL, &se);
        if (ti < 0) {
            printf("FAIL Q2_share_add e=%d\n", (int)se);
            fails++;
        }
        /* The share's want(1) is a no-op for a driver that already wants the
         * mapping: no fresh sequence, so no new datagram and no lost grant. */
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "Q2_active_with_share");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "Q2_adv_port_with_share");
        ck(!gw_pending(), "Q2_share_add_sends_nothing");

        ntx_session_remove(x.s, ti); /* the last share is gone: §8 release runs */
        pump_ms(x.n, 100);
        ck(x.s->pm && x.s->pm->want, "Q2_mapping_still_wanted_after_last_share");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "Q2_still_active_after_last_share");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "Q2_adv_port_after_last_share");
        int dels = 0;
        while (gw_get(req, sizeof req) >= 0)
            if (rd32(req + 4) == 0) dels++;
        ck_eq(dels, 0, "Q2_no_delete_on_last_share_removal");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* Q3. the guard: without the flag the session must still map NOTHING. Q1 must
     * not be satisfied by simply always starting the driver. */
    {
        sess x;
        sess_open_pm(&x, "q3", 0, 0);
        pump_ms(x.n, 20);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "Q3_off_auto_no_share");
        ck(!x.s->pm || !x.s->pm->want, "Q3_not_wanted_auto_no_share");
        ck(!gw_pending(), "Q3_no_datagram_auto_no_share");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "Q3_adv_port_auto_no_share");
        /* A whole day of ticks: a driver that woke up late would still show here. */
        ck_eq(pm_sends_in(&x, 60000, 12), 0, "Q3_stays_quiet");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* Q4. the guard on the other axis: --port-map under a proxy stays OFF, and the
     * bring-up call must not smuggle the mapping past §5's rule. */
    {
        sess x;
        sess_open_pm(&x, "q4", 1, 1);
        pump_ms(x.n, 20);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "Q4_off_proxy_at_bringup");
        ck(!gw_pending(), "Q4_no_datagram_proxy_at_bringup");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "Q4_adv_port_proxy_at_bringup");
        ck_eq(pm_sends_in(&x, 60000, 6), 0, "Q4_stays_quiet_proxy");
        sess_close(&x);
    }

    /* ---- N. R9: ICMP port-unreachable must not spin the loop.

     * The gateway port is a port that was bound and released, so nothing listens:
     * every datagram the connect()ed driver socket sends comes back as ICMP
     * port-unreachable, which a connected UDP socket reports as a pending SO_ERROR
     * and epoll as level-triggered EPOLLERR. With nothing reading SO_ERROR the loop
     * never blocks (the review's repro: 581 577 events in 0,3 s) and the discarded
     * send() result loses the retransmission. The outstanding request is read from
     * the driver because the fake gateway cannot see datagrams sent to a dead port —
     * req/reqlen is verbatim what goes on the wire. */
    {
        sess x;
        sess_open(&x, "n");
        x.cfg.port_map = 1;
        ntx_portmap_test_set_gateway_port(dead_port());
        pm_start(&x);
        ck_eq(x.s->pm->phase, PM_PH_TCP, "N_pcp_tcp_outstanding");
        ck_eq(x.s->pm->fam, PM_PCP, "N_starts_as_pcp");
        ck_eq((long)x.s->pm->reqlen, 60, "N_pcp_request_on_wire");

        /* One pass of the loop is what has to see the error and judge it: EPOLLIN
         * and EPOLLERR are reported together and the clock never moves here, so the
         * verdict comes from the socket, not from a retransmission. */
        int spins = 0;
        while (x.s->pm->fam == PM_PCP && spins++ < 50) {
            struct timespec ts = {0, 5 * 1000 * 1000};
            nanosleep(&ts, NULL);
            ntx_netx_run_once(x.n, 2);
        }
        ck_eq(x.s->pm->fam, PM_NATPMP, "N_pcp_refused_falls_back_to_natpmp");
        ck_eq(x.s->pm->phase, PM_PH_ADDR, "N_fallback_is_natpmp_addr_query");
        ck_eq((long)x.s->pm->reqlen, 2, "N_natpmp_addr_query_on_wire");
        ck(x.s->pm->req[0] == 0 && x.s->pm->req[1] == 0, "N_natpmp_addr_request_bytes");
        ck_eq(x.s->pm->tries, 1, "N_fallback_gets_a_fresh_schedule");

        /* NAT-PMP reaches the same dead port: the loop, on its own and with the
         * clock standing still, must judge that refusal too. */
        spins = 0;
        while (ntx_session_portmap_state(x.s) == NTX_PM_PENDING && spins++ < 50) {
            struct timespec ts = {0, 5 * 1000 * 1000};
            nanosleep(&ts, NULL);
            ntx_netx_run_once(x.n, 2);
        }
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "N_none_after_both_refused");
        ck_eq(x.s->pm->fam, PM_NATPMP, "N_no_pingpong_back_to_pcp");
        ck_eq(x.s->pm->phase, -1, "N_nothing_outstanding");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "N_none_adv_port");

        /* None is final: no re-opened sequence, and no step back to PCP. */
        for (int i = 0; i < 4; i++) {
            ntx_portmap_test_advance_ms(60000);
            pm_tick(&x);
            ntx_netx_run_once(x.n, 2);
        }
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "N_none_stays_quiet");
        ck_eq(x.s->pm->phase, -1, "N_quiet_nothing_outstanding");
        ck_eq(x.s->pm->tries, 0, "N_quiet_no_retries");

        /* The 100 % CPU case, measured on a live error: one more ICMP on the socket,
         * then 1 s of wall time must still buy a bounded number of loop iterations.
         * Nothing sends from here any more, so pre-fix the error stays pending,
         * epoll_wait returns instantly forever and this counts >100 000 iterations. */
        pm_arm_icmp(x.s->pm);
        long iters = pm_loop_iters(x.n, 1000);
        if (iters >= 5000) printf("  (spin: %ld loop iterations in 1 s)\n", iters);
        ck(iters < 5000, "N_bounded_loop_after_icmp");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "N_spin_does_not_reopen");

        gw_drain();
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- N2. R9: a hard send error (not a refusal) ends the attempt.

     * shutdown(SHUT_WR) makes every send fail with EPIPE, which is not a "no
     * responder" refusal. The result must not be discarded into the retry budget:
     * the attempt ends there and the state says none. */
    {
        sess x;
        sess_open(&x, "n2");
        x.cfg.port_map = 1;
        ntx_portmap_test_set_gateway_port(dead_port());
        pm_start(&x);
        ck_eq(x.s->pm->phase, PM_PH_TCP, "N2_pcp_tcp_outstanding");
        shutdown(x.s->pm->fd, SHUT_WR);
        /* The retransmission is what calls send() again, and the schedule is the PCP
         * one now, so the clock has to reach the scheduled instant. */
        ntx_portmap_test_advance_ms((uint64_t)(pm_wait_ms(x.s->pm) + 5));
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_NONE, "N2_hard_send_error_ends_attempt");
        ck_eq(x.s->pm->phase, -1, "N2_nothing_outstanding");
        ck(x.s->pm->tries <= 1, "N2_no_retry_budget_burned");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "N2_none_adv_port");
        /* A dead socket must not keep the loop awake either. */
        long iters = pm_loop_iters(x.n, 500);
        if (iters >= 5000) printf("  (spin: %ld loop iterations in 0,5 s)\n", iters);
        ck(iters < 5000, "N2_bounded_loop_after_send_error");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    ntx_portmap_test_set_gateway_port(gw_port);

    /* ---- R. R15 / S17a: the /proc/net/ipv6_route default-route parser.
     *
     * The kernel writes
     * dst(32hex) dpl(2hex) src(32hex) spl(2hex) nexthop(32hex) metric(8hex)
     * refcnt(8hex) use(8hex) flags(8hex) iface,
     * addresses as 16 raw bytes in network order and every number in hex. A default
     * route is dst all-zero with dpl 0, and is only a gateway if RTF_UP (0x1) and
     * RTF_GATEWAY (0x2) are set, RTF_REJECT (0x200) is not, and the metric is not
     * ffffffff (the unreachable ::/0 networkd leaves on lo). The nexthop is a NATIVE
     * v6 address — the old parser read the src field as the nexthop, expected a
     * v4-mapped one, and read the four hex numbers as decimal, so no real line could
     * ever match (R15). Every fixture below is a line of a real
     * `cat /proc/net/ipv6_route` from this host, only the field under test changed.
     *
     * S17a is the parser only: nothing here dials the v6 gateway (S17b). */
    {
        /* R1. the real table of this host: the fe80::1 default is found, the lo
         * blackhole is not, and the gateway is the native address, byte for byte. */
        struct pm_gw6 g;
        write_route6(V6_ROUTES_REAL, NULL);
        ck(pm_route6(&g) == 1, "R1_real_table_found");
        ck(memcmp(g.addr, V6_NH_FE80_1, 16) == 0, "R1_nexthop_is_fe80_1_bytes");
        ck(g.addr[10] != 0xff || g.addr[11] != 0xff, "R1_nexthop_not_v4_mapped");
        ck(strcmp(g.iface, "wlP9s9") == 0, "R1_iface_captured");

        /* R1b. the lo line alone — metric ffffffff, RTF_REJECT, no RTF_UP: refused.
         * This is the line the fix had to start rejecting; the pre-fix parser could
         * not read it at all, so a parser that only checked "dst is :: and dpl is 0"
         * would accept it and keep declaring an IPv4-only host IPv6-capable. */
        memset(&g, 0xA5, sizeof g);
        write_route6(V6_LO_BLACKHOLE, NULL);
        ck(pm_route6(&g) == 0, "R1b_lo_blackhole_rejected");
        ck(g.addr[0] == 0xA5 && g.iface[0] == (char)0xA5, "R1b_rejected_line_writes_nothing");

        /* R2. two usable defaults: the LOWEST metric wins, in either order. The
         * metrics differ by one (0x258 = 600 against 0x1f4 = 500) and the two nexthops
         * differ in the last byte only, so first-wins and decimal-metric reads both
         * show up here. */
        const char *hi = V6_DEFAULT;                                            /* fe80::1, 0x258 */
        const char *lo = V6_DPY V6_NH2 "000001f4 " V6_RU "00000003" V6_IF;      /* fe80::2, 0x1f4 */
        char both[1024];
        snprintf(both, sizeof both, "%s%s", hi, lo);
        memset(&g, 0, sizeof g);
        write_route6(both, NULL);
        ck(pm_route6(&g) == 1, "R2_lowest_metric_found");
        ck(memcmp(g.addr, V6_NH_FE80_2, 16) == 0, "R2_lowest_metric_wins");
        snprintf(both, sizeof both, "%s%s", lo, hi); /* same table, other order */
        memset(&g, 0, sizeof g);
        write_route6(both, NULL);
        ck(pm_route6(&g) == 1, "R2_reversed_found");
        ck(memcmp(g.addr, V6_NH_FE80_2, 16) == 0, "R2_lowest_metric_wins_reversed");

        /* R3. the gates, one field at a time, each against the real line. */
        struct {
            const char *line;
            const char *what;
        } bad[] = {
            {V6_FLAGS("00000001"), "R3_no_rtf_gateway_rejected"},
            {V6_FLAGS("00000002"), "R3_no_rtf_up_rejected"},
            {V6_FLAGS("00000203"), "R3_rtf_reject_rejected"},
            {V6_FLAGS("00000000"), "R3_no_flags_rejected"},
            {V6_METRIC("ffffffff"), "R3_dead_metric_rejected"},
            {V6_METRIC("FFFFFFFE"), "R3_uppercase_hex_accepted"}, /* sanity: this one is fine */
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            memset(&g, 0, sizeof g);
            write_route6(bad[i].line, NULL);
            int got = pm_route6(&g);
            if (i == 5) { /* the only accepted line in the table */
                ck(got == 1, bad[i].what);
                ck(memcmp(g.addr, V6_NH_FE80_1, 16) == 0, "R3_uppercase_metric_gate_nexthop");
            } else {
                ck(got == 0, bad[i].what);
            }
        }

        /* R3b. prefix traps: ::/0 means dst all-zero AND dpl 0. */
        struct {
            const char *line;
            const char *what;
        } prefix[] = {
            /* non-zero dst at prefix 0 — looks like a default to a startswith test */
            {"20010db8000000000000000000000000 00 00000000000000000000000000000000 00 "
             "fe800000000000000000000000000001 00000258 00000015 00000000 00000003   wlP9s9\n",
             "R3b_nonzero_dst_prefix0_rejected"},
            /* all-zero dst at prefix 40 — an on-link prefix, not a default */
            {"00000000000000000000000000000000 40 00000000000000000000000000000000 00 "
             "fe800000000000000000000000000001 00000258 00000015 00000000 00000003   wlP9s9\n",
             "R3b_zero_dst_prefix40_rejected"},
            /* ::1 at prefix 0 */
            {"00000000000000000000000000000001 00 00000000000000000000000000000000 00 "
             "fe800000000000000000000000000001 00000258 00000015 00000000 00000003   wlP9s9\n",
             "R3b_loopback_dst_rejected"},
            /* a directly-connected default: RTF_UP|RTF_GATEWAY as usual, but the
             * kernel wrote an all-zero nexthop — there is no gateway to ask */
            {V6_DPY "00000000000000000000000000000000 00000258 " V6_RU "00000003" V6_IF,
             "R3b_zero_nexthop_rejected"},
        };
        for (size_t i = 0; i < sizeof prefix / sizeof prefix[0]; i++) {
            memset(&g, 0, sizeof g);
            write_route6(prefix[i].line, NULL);
            ck(pm_route6(&g) == 0, prefix[i].what);
        }

        /* R4. robustness: garbage, truncation, overflow-sized hex, a missing file.
         * None of these may be selected and none may crash or read out of bounds. */
        struct {
            const char *line;
            const char *what;
        } junk[] = {
            {"", "R4_empty_file"},
            {"\n\n   \n\t\n", "R4_blank_lines"},
            {"garbage\n", "R4_prose_line"},
            {"00000000000000000000000000000000 00\n", "R4_truncated_line"},
            {V6_DPY "fe8000000000000000000000000000001 00000258 00000015 00000000\n",
             "R4_missing_iface_field"},
            {V6_DPY "fe800000000000000000000000000000g 00000258 00000015 00000000 00000003   wlP9s9\n",
             "R4_non_hex_nexthop"},
            {"00000000000000000000000000000000x 00 00000000000000000000000000000000 00 "
             "fe800000000000000000000000000001 00000258 00000015 00000000 00000003   wlP9s9\n",
             "R4_overlong_dst"},
            {V6_DPY "fe8000000000000000000000000000001 00000258 00000015 00000000 "
             "0000000000000003   wlP9s9\n",
             "R4_overlong_flags"},
            {V6_DPY "fe8000000000000000000000000000001 ffffffff0 00000015 00000000 00000003   wlP9s9\n",
             "R4_overlong_metric"},
            {V6_DPY "fe8000000000000000000000000000001 00000258 00000015 00000000 00000003 "
             "averyveryverylonginterfacesnamethatthekernelcannotprint\n",
             "R4_overlong_iface"},
        };
        for (size_t i = 0; i < sizeof junk / sizeof junk[0]; i++) {
            memset(&g, 0, sizeof g);
            write_route6(junk[i].line, NULL);
            ck(pm_route6(&g) == 0, junk[i].what);
        }
        memset(&g, 0, sizeof g);
        ntx_portmap_test_set_route_files(NULL, SCRATCH "/definitely_absent");
        ck(pm_route6(&g) == 0, "R4_missing_file_no_route");

        /* The interface name has to fit the buffer the driver keeps for
         * sin6_scope_id (S17b): IF_NAMESIZE-1 characters is the longest the kernel
         * can print — br-138d098fd78d on this host is one — and anything longer is
         * not a line it wrote. */
        {
            char line[256];
            snprintf(line, sizeof line, V6_DPY V6_NH1 V6_MET V6_RU "00000003"
                     "   abcdefghijklmno\n"); /* 15 = IF_NAMESIZE - 1 */
            memset(&g, 0, sizeof g);
            write_route6(line, NULL);
            ck(pm_route6(&g) == 1, "R4_iface_of_IF_NAMESIZE_minus_1_accepted");
            ck(strcmp(g.iface, "abcdefghijklmno") == 0, "R4_long_iface_name_captured");
            snprintf(line, sizeof line, V6_DPY V6_NH1 V6_MET V6_RU "00000003"
                     "   abcdefghijklmnop\n"); /* 16 = IF_NAMESIZE: cannot be printed */
            memset(&g, 0, sizeof g);
            write_route6(line, NULL);
            ck(pm_route6(&g) == 0, "R4_iface_of_IF_NAMESIZE_rejected");
        }

        /* A junk line between the real default and the blackhole changes nothing:
         * the good line is still read, the bad one still refused. */
        memset(&g, 0, sizeof g);
        write_route6(V6_DEFAULT "junk\n" V6_LO_BLACKHOLE, NULL);
        ck(pm_route6(&g) == 1, "R4_junk_line_between_good_and_bad");
        ck(memcmp(g.addr, V6_NH_FE80_1, 16) == 0, "R4_junk_line_nexthop_survives");
        ck(strcmp(g.iface, "wlP9s9") == 0, "R4_junk_line_iface_survives");

        /* R5. the parser is on the production path: pm_open reads the v6 default and
         * keeps the gateway address and the interface for S17b, without dialing it
         * (the socket it opens today is the AF_INET one, and NAT-PMP is IPv4-only). */
        write_routes(GW_LO);
        sess x;
        sess_open(&x, "r1");
        x.cfg.port_map = 1;
        pm_start(&x);
        ck_eq(x.s->pm->gw6_seen, 1, "R5_driver_read_the_v6_route");
        ck(memcmp(x.s->pm->gw6.addr, V6_NH_FE80_1, 16) == 0, "R5_driver_gw6_bytes");
        ck(strcmp(x.s->pm->gw6.iface, "wlP9s9") == 0, "R5_driver_gw6_iface");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "R5_v4_sequence_untouched");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);

        /* R5b. S17a's boundary stated: a host with no IPv4 default but a usable v6
         * one has its route parsed and kept, and still maps nothing — S17b is what
         * turns that state into an AF_INET6 PCP sequence. */
        {
            char v4path2[256];
            snprintf(v4path2, sizeof v4path2, "%s/r15_no_v4_default", SCRATCH);
            wr(v4path2, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                        "wlP9s9\t0101A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n");
            write_route6(V6_ROUTES_REAL, v4path2);
            sess y;
            sess_open(&y, "r2");
            y.cfg.port_map = 1;
            pm_start(&y);
            pump_ms(y.n, 20);
            ck_eq(y.s->pm->gw6_seen, 1, "R5b_v6_route_parsed_without_v4_default");
            ck(memcmp(y.s->pm->gw6.addr, V6_NH_FE80_1, 16) == 0, "R5b_gw6_kept_without_v4_default");
            ck(ntx_session_portmap_state(y.s) == NTX_PM_NONE, "R5b_no_v6_socket_yet");
            ck(!gw_pending(), "R5b_no_datagram_without_v4_default");
            sess_close(&y);
        }
        write_routes(GW_LO);
        gw_drain();
    }

    /* ---- S. R15 / S17b: the AF_INET6 PCP socket and its source rule.

     * S17b is the socket and the receive-side validation only: nothing here sends a
     * v6 PCP MAP request (S17c), so the two rules the sub-step is made of — connect
     * to the v6 gateway:5351 with a scope for a link-local router, and accept a
     * datagram only from that gateway address INCLUDING its scope and on 5351 — are
     * pinned on the socket the kernel holds (getpeername) and on the rx counters
     * (rx6_seen / rx6_ok) the driver keeps for exactly that purpose. */
    {
        /* S1. the socket is opened and connected when the v6 default names a gateway
         * this box can reach: [::1] on the fake gateway's port, which is why the v6
         * half needed an address-aware hook of its own (the v4 hook carries a port
         * alone, and both v4 fixtures are 127.0.0.1). */
        sess x;
        sess_open(&x, "s1");
        x.cfg.port_map = 1;
        write_routes(GW_LO);
        write_route6(V6_DEFAULT_LO, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm->fd6 >= 0, "S1_v6_socket_opened");
        ck_eq(x.s->pm->gw6_connected, 1, "S1_v6_connected_flag");
        ck_eq(x.s->pm->gw6_tried, 1, "S1_v6_attempt_recorded");
        struct sockaddr_in6 peer;
        ck(pm6_peername(x.s->pm, &peer) == 0, "S1_v6_getpeername");
        ck(peer.sin6_family == AF_INET6, "S1_v6_peer_family");
        ck_eq(ntohs(peer.sin6_port), (long)gw6_port, "S1_v6_peer_is_gateway_port");
        ck(memcmp(peer.sin6_addr.s6_addr, V6_LO_ADDR, 16) == 0, "S1_v6_peer_is_gateway_addr");
        ck_eq(x.s->pm->gw6_err, 0, "S1_no_v6_error");
        /* The v4 sequence is untouched by all of it: same state, same phase, and the
         * v4 request still goes to the v4 fake — nothing is sent to the v6 one yet. */
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "S1_v4_sequence_untouched");
        ck_eq(x.s->pm->phase, PM_PH_TCP, "S1_v4_phase_untouched");
        ck(gw_pending(), "S1_v4_request_still_on_v4_wire");
        /* Nothing is sent on the v6 socket yet, for the reason S17c made decisive: on
         * this box the kernel answers ::1 for the connected socket's own address, and
         * §8 refuses a request that names a loopback client. T1 is the case that does
         * put a MAP request on this wire, and T10 pins this one. */
        ck(!gw6_pending(), "S1b_no_v6_request_yet");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);

        /* S1c. no usable v6 default (only networkd's lo blackhole): no socket and no
         * attempt, while the v4 half behaves exactly as before. */
        sess_open(&x, "s1c");
        x.cfg.port_map = 1;
        write_route6(V6_LO_BLACKHOLE, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck_eq(x.s->pm->gw6_seen, 0, "S1c_no_v6_route");
        ck_eq(x.s->pm->fd6, -1, "S1c_no_v6_socket_without_route");
        ck_eq(x.s->pm->gw6_tried, 0, "S1c_no_attempt_without_route");
        ck(x.s->pm->fd >= 0, "S1c_v4_socket_still_open");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "S1c_v4_pending");
        ck(gw_pending(), "S1c_v4_request_on_wire");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);

        /* S1d. the v6 half opens from the v6 route ALONE: with no v4 default in the
         * table the v4 sequence says NONE and the v6 socket is still connected. That
         * state is the one R15 left unreachable — a v6-only host got nothing. */
        {
            char nov4[256];
            snprintf(nov4, sizeof nov4, "%s/s1d_no_v4", SCRATCH);
            wr(nov4, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                     "wlP9s9\t0101A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n");
            sess y;
            sess_open(&y, "s1d");
            y.cfg.port_map = 1;
            write_route6(V6_DEFAULT_LO, nov4);
            pm_start(&y);
            pump_ms(y.n, 20);
            ck(y.s->pm->fd6 >= 0, "S1d_v6_socket_without_v4_default");
            ck(y.s->pm->fd < 0, "S1d_no_v4_socket_without_v4_default");
            ck(ntx_session_portmap_state(y.s) == NTX_PM_NONE, "S1d_v4_state_none");
            ck(!gw_pending(), "S1d_no_v4_datagram");
            sess_close(&y);
        }
    }

    /* ---- S2. a link-local gateway gets sin6_scope_id = if_nametoindex(iface).
     *
     * getpeername cannot witness this: the kernel answers the peer scope from
     * sk_bound_dev_if, which a connect()-time sin6_scope_id does not set, so it
     * reads 0 for a socket connected to [::1] with scope 1 (probed while writing
     * this). What IS observable is the kernel's answer to the connect itself, and
     * the two halves of that answer separate cleanly: a link-local connect WITHOUT
     * a scope is EINVAL (no device can be chosen), WITH a scope it is the route
     * lookup's ENETUNREACH — this box has no link-local prefix on any interface
     * (`cat /proc/net/if_inet6` holds only ::1/128 on lo), so neither one can
     * connect, and only the scoped attempt reaches a routing decision at all.
     * v6_probe_scopeless() is the control: the same connect the driver makes,
     * without the scope, so the assertion is a differential and not a guess. */
    {
        const unsigned lo_idx = if_nametoindex("lo");
        ck(lo_idx != 0, "S2_precondition_lo_resolves");

        sess x;
        sess_open(&x, "s2");
        x.cfg.port_map = 1;
        write_routes(GW_LO);
        write_route6(V6_LINKLOCAL("lo"), v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck_eq(x.s->pm->gw6_seen, 1, "S2_link_local_route_seen");
        ck_eq(x.s->pm->gw6_tried, 1, "S2_link_local_attempted");
        ck_eq(x.s->pm->gw6_scope, (long)lo_idx, "S2_scope_is_if_nametoindex_iface");
        /* The differential that proves the scope reached connect(): a SCOPELESS
         * link-local connect is always EINVAL (the kernel has no device to pick and
         * says so before any route lookup), so the driver's attempt must NOT report
         * EINVAL — on this box it reports ENETUNREACH, the routing decision only a
         * scoped attempt is allowed to reach. Whether it then connects is the box's
         * business (a router with a link-local prefix answers it), so the pairing is
         * what is asserted, not one errno. */
        ck_eq(v6_probe_scopeless(), EINVAL, "S2_control_scopeless_is_EINVAL");
        ck(x.s->pm->gw6_err != EINVAL, "S2_scoped_connect_reached_the_route_lookup");
        ck(x.s->pm->gw6_err != 0 || x.s->pm->fd6 >= 0, "S2_v6_connected_only_when_kernel_took_it");
        ck(x.s->pm->gw6_err == 0 || x.s->pm->fd6 < 0, "S2_v6_socket_dropped_on_refusal");
        /* The v4 half of the same sequence is untouched. */
        ck(x.s->pm->fd >= 0, "S2_v4_socket_open");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "S2_v4_pending");
        ck(gw_pending(), "S2_v4_request_on_wire");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);

        /* S2b. the same link-local gateway through an interface that does not exist:
         * the scope is not a number to invent, so v6 is skipped outright — before any
         * connect() — and the v4 sequence carries on as if v6 had never been mentioned. */
        sess_open(&x, "s2b");
        x.cfg.port_map = 1;
        write_route6(V6_LINKLOCAL("nosuchif9"), v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck_eq(x.s->pm->gw6_seen, 1, "S2b_route_seen");
        ck_eq(x.s->pm->gw6_tried, 1, "S2b_attempt_marked");
        ck_eq(x.s->pm->gw6_scope, 0, "S2b_no_scope_invented");
        ck_eq(x.s->pm->fd6, -1, "S2b_v6_skipped");
        ck_eq(x.s->pm->gw6_err, 0, "S2b_skipped_not_refused");
        ck(x.s->pm->fd >= 0, "S2b_v4_unaffected_socket");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "S2b_v4_unaffected_state");
        ck_eq(x.s->pm->phase, PM_PH_TCP, "S2b_v4_unaffected_phase");
        ck(gw_pending(), "S2b_v4_request_on_wire");
        ck_eq(x.s->pm->tries, 1, "S2b_v4_schedule_untouched");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);

        /* S2c. the name the ROUTE printed is the name that gets resolved — the scope
         * is not lo's index by hard-coding. A second resolvable interface is the
         * cleanest witness; where the box has only lo (the case in this sandbox:
         * if_nametoindex answers for lo and nothing else), a name that differs from
         * lo's spelling is the witness instead, because a hard-coded index would
         * still come back non-zero for it. */
        {
            char other[IF_NAMESIZE] = "LO"; /* not a name on any Linux box */
            unsigned oi = 0;
            for (unsigned i = 2; i < 64 && !oi; i++) {
                char nm[IF_NAMESIZE];
                if (if_indextoname(i, nm) && (oi = if_nametoindex(nm)) != 0)
                    memcpy(other, nm, sizeof other);
            }
            char line[512];
            sess_open(&x, "s2c");
            x.cfg.port_map = 1;
            snprintf(line, sizeof line, V6_DPY V6_NH1 V6_MET V6_RU "00000003" "   %s\n", other);
            write_route6(line, v4path);
            pm_start(&x);
            pump_ms(x.n, 20);
            ck_eq(x.s->pm->gw6_scope, (long)oi, "S2c_scope_follows_the_route_iface");
            if (oi) ck(x.s->pm->gw6_scope != (long)if_nametoindex("lo"), "S2c_scope_is_not_lo_by_default");
            ntx_session_portmap_stop(x.s);
            sess_close(&x);
        }
    }

    /* ---- S3. the v6 source rule: gateway address INCLUDING scope, port 5351.
     *
     * §8 makes the source test the boundary, not connect(), and this is the one
     * place ntx accepts unsolicited UDP, so it is pinned both ways.
     * (a) live: a datagram that the kernel delivers to the connected socket is read
     *     by the v6 callback and counted, and one the rule rejects is counted as
     *     seen-but-not-accepted — the drop happens inside pm_on_rw6 with the packet
     *     already in hand, because the test moves the rule's own expectation
     *     (pm->gw6.addr / the port hook / the scope) out from under it. That is what
     *     makes the drop observable instead of merely unfalsifiable.
     * (b) direct on pm_src6_ok: the two cases the connected socket can never show,
     *     because the kernel drops them before recvfrom reports anything — a wrong
     *     source ADDRESS and a wrong SCOPE. Same reasoning as case B2 above. */
    {
        sess x;
        sess_open(&x, "s3");
        x.cfg.port_map = 1;
        write_routes(GW_LO);
        write_route6(V6_DEFAULT_LO, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm->fd6 >= 0, "S3_v6_socket_open");
        struct sockaddr_in6 me;
        ck(pm6_sockname(x.s->pm, &me) == 0, "S3_v6_getsockname");

        uint8_t junk[16];
        memset(junk, 0xA7, sizeof junk);
        const uint32_t v4_phase_before = (uint32_t)x.s->pm->phase;
        const int v4_state_before = (int)ntx_session_portmap_state(x.s);

        /* (a1) from the gateway address on the gateway port: delivered AND accepted. */
        gw6_to(junk, sizeof junk, &me);
        pump_ms(x.n, 40);
        ck_eq(x.s->pm->rx6_seen, 1, "S3_gateway_datagram_read");
        ck_eq(x.s->pm->rx6_ok, 1, "S3_gateway_datagram_accepted");
        /* Nothing is consumed by it: no parser and no request before S17c, so the v4
         * sequence cannot have moved either. */
        ck_eq(x.s->pm->phase, (long)v4_phase_before, "S3_v4_phase_not_moved_by_v6_rx");
        ck_eq((int)ntx_session_portmap_state(x.s), v4_state_before, "S3_v4_state_not_moved_by_v6_rx");
        ck_eq(x.s->pm->active[PM_PH_TCP], 0, "S3_v6_datagram_grants_nothing");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "S3_v6_datagram_no_adv_port");

        /* (a2) same packet, expectation moved to a DIFFERENT gateway address: the
         * kernel still delivers (the peer is the one connect() set), so the drop is
         * provably ours. */
        uint8_t other[16];
        memset(other, 0x20, 16);
        other[0] = 0x20;
        other[1] = 0x01;
        uint8_t saved6[16];
        memcpy(saved6, x.s->pm->gw6.addr, 16);
        memcpy(x.s->pm->gw6.addr, other, 16);
        gw6_to(junk, sizeof junk, &me);
        pump_ms(x.n, 40);
        ck_eq(x.s->pm->rx6_seen, 2, "S3_wrong_addr_read");
        ck_eq(x.s->pm->rx6_ok, 1, "S3_wrong_addr_dropped");
        memcpy(x.s->pm->gw6.addr, saved6, 16);

        /* (a3) right address, expectation on the port moved: also dropped. */
        const uint16_t keep = gw6_port;
        ntx_portmap_test_set_gateway6_port((uint16_t)(keep == 5351u ? 5352u : 5351u));
        gw6_to(junk, sizeof junk, &me);
        pump_ms(x.n, 40);
        ck_eq(x.s->pm->rx6_seen, 3, "S3_wrong_port_read");
        ck_eq(x.s->pm->rx6_ok, 1, "S3_wrong_port_dropped");
        ntx_portmap_test_set_gateway6_port(keep);

        /* (a4) right address and port, expectation on the SCOPE moved: the scope is
         * part of the source, not decoration. */
        const unsigned sc = x.s->pm->gw6_scope;
        x.s->pm->gw6_scope = sc == 0u ? 3u : 0u;
        gw6_to(junk, sizeof junk, &me);
        pump_ms(x.n, 40);
        ck_eq(x.s->pm->rx6_seen, 4, "S3_wrong_scope_read");
        ck_eq(x.s->pm->rx6_ok, 1, "S3_wrong_scope_dropped");
        x.s->pm->gw6_scope = sc;

        /* The budget of PM_RX_BUDGET datagrams per callback does not lose the good
         * one that follows four bad ones. */
        gw6_to(junk, sizeof junk, &me);
        pump_ms(x.n, 40);
        ck_eq(x.s->pm->rx6_seen, 5, "S3_fifth_datagram_read");
        ck_eq(x.s->pm->rx6_ok, 2, "S3_good_datagram_after_bad_ones_accepted");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);

        /* (b) the filter itself, on a probe the way B2 does it: the address, the
         * scope and the port each have to match, and nothing else may pass. */
        {
            struct ntx_portmap probe;
            memset(&probe, 0, sizeof probe);
            memcpy(probe.gw6.addr, V6_LO_ADDR, 16);
            probe.gw6_scope = 2u;
            struct sockaddr_in6 sa;
            gw6_mk(&sa, "::1", gw6_port);
            sa.sin6_scope_id = 2u;
            ck(pm_src6_ok(&probe, &sa), "S3b_gateway_src_accepted");
            sa.sin6_port = htons((uint16_t)(gw6_port == 5351u ? 5352u : 5351u));
            ck(!pm_src6_ok(&probe, &sa), "S3b_wrong_port_rejected");
            gw6_mk(&sa, "::1", gw6_port);
            sa.sin6_scope_id = 3u;
            ck(!pm_src6_ok(&probe, &sa), "S3b_wrong_scope_rejected");
            gw6_mk(&sa, "::2", gw6_port);
            sa.sin6_scope_id = 2u;
            ck(!pm_src6_ok(&probe, &sa), "S3b_wrong_addr_rejected");
            gw6_mk(&sa, "fe80::1", gw6_port);
            sa.sin6_scope_id = 2u;
            ck(!pm_src6_ok(&probe, &sa), "S3b_link_local_addr_rejected_for_global_gw");
            /* A link-local gateway is only the same source with the same scope. */
            memcpy(probe.gw6.addr, V6_NH_FE80_1, 16);
            probe.gw6_scope = 2u;
            gw6_mk(&sa, "fe80::1", gw6_port);
            sa.sin6_scope_id = 2u;
            ck(pm_src6_ok(&probe, &sa), "S3b_link_local_gw_with_scope_accepted");
            sa.sin6_scope_id = 0u;
            ck(!pm_src6_ok(&probe, &sa), "S3b_link_local_gw_without_scope_rejected");
            sa.sin6_scope_id = 2u;
            sa.sin6_family = AF_INET;
            ck(!pm_src6_ok(&probe, &sa), "S3b_wrong_family_rejected");
        }
    }

    /* ---- S4. EPOLLERR / ECONNREFUSED on the v6 socket: bounded, and it does not
     * touch the v4 sequence. There is no NAT-PMP fallback to take (RFC 6886 is
     * IPv4-only), so the v6 half simply ends.
     *
     * The v6 gateway port is pointed at a released ephemeral port BEFORE the socket
     * is opened, so the driver's own socket faces a dead endpoint — the v6 shape of
     * case N. connect() of a UDP socket takes a dead port happily, so the ICMP is
     * armed by one send on the driver's fd exactly as pm_arm_icmp does for v4, and
     * nothing else sends from here. */
    {
        sess x;
        sess_open(&x, "s4");
        x.cfg.port_map = 1;
        write_routes(GW_LO);
        write_route6(V6_DEFAULT_LO, v4path);
        const uint16_t keep = gw6_port;
        ntx_portmap_test_set_gateway6_port(dead_port6());
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm->fd6 >= 0, "S4_v6_socket_opened_to_dead_port");
        struct sockaddr_in6 peer;
        ck(pm6_peername(x.s->pm, &peer) == 0, "S4_connected_before_the_error");
        ck_eq(x.s->pm->fam, PM_PCP, "S4_v4_starts_as_pcp");
        ck_eq(x.s->pm->phase, PM_PH_TCP, "S4_v4_query_outstanding");

        uint8_t one[2] = {0, 0};
        (void)send(x.s->pm->fd6, one, sizeof one, MSG_DONTWAIT);
        struct timespec ts = {0, 100 * 1000 * 1000};
        nanosleep(&ts, NULL);
        /* One pass of the loop must see the error and judge it: EPOLLIN and EPOLLERR
         * arrive together and the clock never moves here. */
        int spins = 0;
        while (x.s->pm->fd6 >= 0 && spins++ < 50) ntx_netx_run_once(x.n, 2);
        ck(spins < 50, "S4_v6_error_judged_promptly");
        ck_eq(x.s->pm->fd6, -1, "S4_v6_half_ended_by_refusal");
        ck_eq(x.s->pm->gw6_err, ECONNREFUSED, "S4_refusal_recorded");
        /* It stayed a v6-only verdict: the family is still PCP — no NAT-PMP step —
         * the v4 query that was outstanding is still the outstanding one, and the v4
         * socket is open. */
        ck_eq(x.s->pm->fam, PM_PCP, "S4_no_natpmp_fallback_from_v6");
        ck_eq(x.s->pm->phase, PM_PH_TCP, "S4_v4_query_still_outstanding");
        ck_eq(x.s->pm->tries, 1, "S4_v4_schedule_untouched");
        ck(x.s->pm->fd >= 0, "S4_v4_socket_alive");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "S4_v4_state_alive");

        /* No spin: the callback read SO_ERROR, so half a second of wall time still
         * buys a bounded number of iterations. */
        long iters = pm_loop_iters(x.n, 500);
        if (iters >= 5000) printf("  (v6 spin: %ld loop iterations in 0,5 s)\n", iters);
        ck(iters < 5000, "S4_bounded_loop_after_v6_icmp");

        /* The v4 sequence still works after the v6 half died: grant it and the state
         * and adv_port move, which no v6 refusal was allowed to prevent. */
        uint8_t pub[16];
        pcp_v4(pub, 200, 0, 2, 1);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "S4_v4_grant_after_v6_refusal");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "S4_v4_adv_port_after_v6_refusal");
        ntx_portmap_test_set_gateway6_port(keep);
        gw_drain();
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- S4b. the other half of the error rule: an error that is NOT a refusal
     * ends the v6 half without a step to NAT-PMP either.
     *
     * S17b never sends on the v6 socket, so the only errno that can reach the v6
     * error path from outside is the ICMP one case S4 already drives; a hard socket
     * error (EPIPE, ENOBUFS …) therefore gets the direct probe case B2 uses for
     * pm_src_ok. What is pinned is the SEPARATION: pm_sock_err6 must not reach
     * pm_sock_err's family, phase, tries or grants. */
    {
        sess x;
        sess_open(&x, "s4b");
        x.cfg.port_map = 1;
        write_routes(GW_LO);
        write_route6(V6_DEFAULT_LO, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm->fd6 >= 0, "S4b_v6_socket_open");
        const int v4_fd = x.s->pm->fd;
        const int v4_phase = x.s->pm->phase;
        const int v4_tries = x.s->pm->tries;
        pm_sock_err6(x.s->pm, EPIPE);
        ck_eq(x.s->pm->fd6, -1, "S4b_hard_error_ends_v6_half");
        ck_eq(x.s->pm->gw6_err, EPIPE, "S4b_hard_error_recorded");
        ck_eq(x.s->pm->fam, PM_PCP, "S4b_hard_error_takes_no_natpmp_step");
        ck(x.s->pm->fd >= 0, "S4b_v4_socket_alive");
        ck_eq(x.s->pm->fd, (long)v4_fd, "S4b_v4_socket_is_the_same_fd");
        ck_eq(x.s->pm->phase, (long)v4_phase, "S4b_v4_phase_untouched");
        ck_eq(x.s->pm->tries, (long)v4_tries, "S4b_v4_schedule_untouched");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "S4b_v4_state_alive");
        long iters = pm_loop_iters(x.n, 300);
        if (iters >= 5000) printf("  (v6 spin: %ld loop iterations in 0,3 s)\n", iters);
        ck(iters < 5000, "S4b_bounded_loop_after_v6_hard_error");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
    }

    /* ---- S5. --proxy / --tunnel / --no-port-map: no v6 socket at all, exactly as
     * for v4 (§5). With mapping refused the driver is never even allocated, so the
     * probe helpers answer -1/0 for a session that has no pm at all. */
    {
        sess x;
        sess_open_pm(&x, "s5", 1, 1); /* --port-map together with --proxy */
        write_routes(GW_LO);
        write_route6(V6_DEFAULT_LO, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck_eq(pm6_fd(&x), -1, "S5_no_v6_socket_under_proxy");
        ck_eq(pm6_tried(&x), 0, "S5_no_v6_attempt_under_proxy");
        ck_eq(pm6_v4fd(&x), -1, "S5_no_v4_socket_under_proxy");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "S5_off_under_proxy");
        ck(!gw6_pending(), "S5_no_v6_datagram_under_proxy");
        sess_close(&x);

        sess_open(&x, "s5b");
        x.cfg.port_map = 1;
        x.cfg.tunnel = 1;
        x.cfg.tunnel_host = "127.0.0.1";
        x.cfg.tunnel_port = 4444;
        pm_start(&x);
        pump_ms(x.n, 20);
        ck_eq(pm6_fd(&x), -1, "S5_no_v6_socket_under_tunnel");
        ck_eq(pm6_tried(&x), 0, "S5_no_v6_attempt_under_tunnel");
        ck(!gw6_pending(), "S5_no_v6_datagram_under_tunnel");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "S5_off_under_tunnel");
        sess_close(&x);

        sess_open(&x, "s5c");
        x.cfg.port_map = -1;
        pm_start(&x);
        pump_ms(x.n, 20);
        ck_eq(pm6_fd(&x), -1, "S5_no_v6_socket_with_no_port_map");
        ck_eq(pm6_v4fd(&x), -1, "S5_no_v4_socket_with_no_port_map");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_OFF, "S5_off_with_no_port_map");
        sess_close(&x);
    }

    /* ---- S6. stop() takes the v6 half down with the v4 one, and a fresh sequence
     * starts from clean counters. */
    {
        sess x;
        sess_open(&x, "s6");
        x.cfg.port_map = 1;
        write_routes(GW_LO);
        write_route6(V6_DEFAULT_LO, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm->fd6 >= 0, "S6_opened");
        struct sockaddr_in6 me;
        pm6_sockname(x.s->pm, &me);
        uint8_t junk[8] = {9, 9, 9, 9, 9, 9, 9, 9};
        gw6_to(junk, sizeof junk, &me);
        pump_ms(x.n, 40);
        ck_eq(x.s->pm->rx6_ok, 1, "S6_datagram_accepted");
        ntx_session_portmap_stop(x.s);
        ck(!x.s->pm, "S6_stop_frees_the_driver");
        /* Re-arming starts a clean sequence: fresh counters, both sockets open. */
        ntx_session_portmap_want(x.s, 1);
        pm_tick(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm && x.s->pm->fd6 >= 0, "S6_socket_reopened");
        ck_eq(x.s->pm->rx6_seen, 0, "S6_fresh_sequence_resets_counters");
        ck_eq(x.s->pm->rx6_ok, 0, "S6_fresh_sequence_resets_accepted");
        sess_close(&x);
    }

    /* ---- T. R15 / S17c: PCP MAP over IPv6.

     * What S17b left undone: nothing was ever sent on fd6. These cases put MAP
     * requests on that socket and pin the rules the sub-step is made of — the client
     * address is the getsockname() address of the connected socket and must be
     * routable (a ULA or link-local one SKIPS the family, state NONE, nothing on the
     * wire), the granted external port MUST equal the listen port or the mapping is
     * deleted with its own nonce, and v4/v6 keep separate state and separate
     * schedules.
     *
     * Two things the sandbox forces. (1) The gateway's address cannot be invented:
     * every bind outside lo is EADDRNOTAVAIL and `ip -6 addr add` is EPERM (both
     * probed), so the v6 route names a real loopback address and the fake gateway
     * binds it. (2) The CLIENT address the kernel picks for a socket connected to
     * [::1] is always ::1, which is exactly the address §8 refuses to name in a
     * request, so the sequence would never start: ntx_portmap_test_set_client6()
     * hands the driver the address the kernel would have answered on a real host, and
     * pm6_is_global still judges it. Every case that does NOT set it runs the real
     * getsockname path (T10 pins that that is ::1 and that it means silence). */
    {
        /* T1. the wire format of a v6 TCP MAP request. */
        sess x;
        sess_open(&x, "t1");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint8_t req[2048];
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T1_v6_request_on_wire");
        ck_eq(req[0], 2, "T1_pcp_version");
        ck_eq(req[1], 1, "T1_opcode_map_request");
        ck_eq(req[2], 0, "T1_reserved_zero");
        ck_eq(req[3], 0, "T1_reserved_zero_3");
        ck_eq(rd32(req + 4), 7200, "T1_lifetime_two_hours");
        ck(memcmp(req + 8, V6_CLIENT_GLOBAL, 16) == 0, "T1_client_ip_is_getsockname_addr");
        ck_eq(req[36], NTX_PCP_PROTO_TCP, "T1_protocol_tcp");
        ck_eq(req[37] | req[38] | req[39], 0, "T1_map_reserved_zero");
        ck_eq(req_int_port(req), ntx_netx_port(x.n), "T1_internal_port_is_listen_port");
        ck_eq((req[42] << 8) | req[43], ntx_netx_port(x.n), "T1_suggested_port_is_listen_port");
        uint8_t zeros[16];
        memset(zeros, 0, sizeof zeros);
        ck(memcmp(req + 44, zeros, 16) == 0, "T1_fresh_ask_no_suggested_ip");
        /* The client address is the socket's own — the byte-for-byte identity with
         * what the kernel reports is the rule, not a value copied into the fixture. */
        ck_eq(x.s->pm->s6.client_ip[0], 0x20, "T1_client_ip_is_native_v6");
        ck(memcmp(x.s->pm->s6.client_ip, V6_CLIENT_GLOBAL, 16) == 0, "T1_driver_keeps_the_address");
        ck_eq(ntx_session_portmap_state(x.s), NTX_PM_PENDING, "T1_v4_pending_too");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
        gw6_drain();
    }

    /* T2. a grant whose external port IS the listen port: v6 ACTIVE, renewal reuses
     * the grant nonce and suggests the granted address (§11.2), the delete at stop
     * carries that same nonce (§11.1). */
    {
        sess x;
        sess_open(&x, "t2");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint16_t lp = ntx_netx_port(x.n);
        pcp_grant6(&x, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        ck_eq(pm6_state6(&x), NTX_PM_ACTIVE, "T2_v6_active");
        ck_eq(pm6_ext6(&x), (long)lp, "T2_ext_port6_is_listen_port");
        ck_eq(x.s->pm->s6.active[PM_PH_TCP], 1, "T2_tcp_active");
        uint8_t gn[12];
        memcpy(gn, granted6_nonce[NTX_PCP_PROTO_TCP], 12);
        /* The v4 half, driven from the same tick, is untouched by the v6 grant. */
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "T2_v4_state_untouched");
        ck_eq(ntx_session_adv_port(x.s), lp, "T2_adv_port_not_moved_by_v6");
        gw6_drain();
        ntx_portmap_test_advance_ms(3601000); /* past half of the 7200 s grant */
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw6_get(req, sizeof req), 60, "T2_v6_renewal_sent");
        ck(gw6_req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "T2_renewal_is_pcp_tcp");
        ck(memcmp(req + 24, gn, 12) == 0, "T2_renewal_reuses_grant_nonce");
        ck_eq((req[42] << 8) | req[43], lp, "T2_renewal_suggests_granted_port");
        ck(memcmp(req + 44, V6_EXT_GLOBAL, 16) == 0, "T2_renewal_suggests_granted_ip");
        ck(memcmp(req + 8, V6_CLIENT_GLOBAL, 16) == 0, "T2_renewal_client_ip_stable");
        ntx_session_portmap_stop(x.s);
        int dels = 0;
        while (gw6_get(req, sizeof req) >= 0) {
            if (rd32(req + 4) != 0 || req[36] != NTX_PCP_PROTO_TCP) continue;
            dels++;
            ck(memcmp(req + 24, gn, 12) == 0, "T2_delete_repeats_grant_nonce");
            ck_eq((req[42] << 8) | req[43], lp, "T2_delete_suggests_granted_port");
            ck(memcmp(req + 44, V6_EXT_GLOBAL, 16) == 0, "T2_delete_suggests_granted_ip");
        }
        ck_eq(dels, 1, "T2_one_v6_delete_at_stop");
        ck_eq(pm6_state6(&x), NTX_PM_OFF, "T2_v6_off_after_stop");
        ck_eq(pm6_ext6(&x), 0, "T2_no_ext_port_after_stop");
        ntx_portmap_test_set_client6(NULL);
        sess_close(&x);
        gw_drain();
        gw6_drain();
    }

    /* T3. THE RULE: a grant whose external port is not the listen port is deleted
     * with the nonce it was granted, warned on the diag, and never advertised. The
     * announce carries ONE port (ntx_session_adv_port is a v4 decision), so a v6
     * mapping on any other port is a firewall hole for a port no peer can be told. */
    {
        char diagpath[256];
        snprintf(diagpath, sizeof diagpath, "%s/diag_t3.log", SCRATCH);
        unlink(diagpath);
        ck_eq(ntx_diag_open(diagpath), 0, "T3_diag_capture");
        sess x;
        sess_open(&x, "t3");
        x.cfg.port_map = 1;
        one_torrent(&x);
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint16_t lp = ntx_netx_port(x.n);
        uint8_t req[2048];
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T3_request");
        uint8_t rsp[64], gn[12];
        memcpy(gn, req + 24, 12);
        gw6_reply_at = pm_now();
        pcp_resp(rsp, req, EXT_PORT, V6_EXT_GLOBAL, 7200, gw6_epoch_live(x.s->pm)); /* != listen port */
        gw6_answer(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        int dels = 0;
        while (gw6_get(req, sizeof req) >= 0) {
            if (rd32(req + 4) != 0) continue;
            dels++;
            ck(memcmp(req + 24, gn, 12) == 0, "T3_delete_uses_the_grant_nonce");
            ck_eq((req[42] << 8) | req[43], EXT_PORT, "T3_delete_names_the_wrong_port");
            ck(memcmp(req + 44, V6_EXT_GLOBAL, 16) == 0, "T3_delete_suggests_granted_ip");
        }
        ck_eq(dels, 1, "T3_bad_grant_is_deleted");
        ck_eq(pm6_state6(&x), NTX_PM_NONE, "T3_v6_none_after_bad_grant");
        ck_eq(pm6_ext6(&x), 0, "T3_ext_port6_never_the_wrong_port");
        ck_eq(x.s->pm->s6.active[PM_PH_TCP], 0, "T3_not_active");
        ck_eq(ntx_session_adv_port(x.s), lp, "T3_adv_port_stays_the_listen_port");
        /* And it stays that way: no re-request against a gateway that already answered. */
        ck_eq(gw6_sends_in(&x, 60000, 6), 0, "T3_no_further_v6_request");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        char *text = read_all(diagpath);
        ck(text && strstr(text, "not the listen port"), "T3_warning_on_diag");
        ck(text && strstr(text, "mapping removed"), "T3_warning_says_removed");
        free(text);
        ntx_diag_close();
        ntx_portmap_test_set_client6(NULL);
        gw_drain();
        gw6_drain();
    }

    /* T4. only a non-routable client address: the family is SKIPPED with state NONE
     * and nothing reaches the wire (§8). Three shapes of it — ULA, link-local and the
     * loopback this box actually gets from getsockname() — plus the v4-mapped shape
     * that R15 was about. */
    {
        struct {
            const uint8_t *addr;
            const char *what;
        } bad[] = {
            {V6_CLIENT_ULA, "T4_ula_skipped"},
            {V6_CLIENT_LINKLOCAL, "T4_link_local_skipped"},
            {V6_LO_ADDR, "T4_loopback_skipped"},
            {V6_CLIENT_MAPPED, "T4_v4_mapped_skipped"},
        };
        for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
            sess x;
            char tag[32];
            snprintf(tag, sizeof tag, "t4_%u", (unsigned)i);
            sess_open(&x, tag);
            x.cfg.port_map = 1;
            write_route6(V6_DEFAULT_LO, v4path);
            ntx_portmap_test_set_client6(bad[i].addr);
            pm_start(&x);
            pump_ms(x.n, 20);
            ck_eq(pm6_state6(&x), NTX_PM_NONE, bad[i].what);
            ck_eq(pm6_ext6(&x), 0, "T4_no_ext_port_when_skipped");
            ck(!gw6_pending(), "T4_nothing_on_the_v6_wire");
            ck_eq(x.s->pm->s6.phase, -1, "T4_no_v6_query_outstanding");
            ck_eq(gw6_sends_in(&x, 60000, 6), 0, "T4_stays_quiet");
            /* Skipped means v6 only: the v4 sequence runs exactly as if v6 were absent. */
            ck(x.s->pm->fd >= 0, "T4_v4_socket_alive");
            ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "T4_v4_unaffected");
            ck(gw_pending(), "T4_v4_request_still_on_wire");
            ntx_portmap_test_set_client6(NULL);
            ntx_session_portmap_stop(x.s);
            sess_close(&x);
            gw_drain();
            gw6_drain();
        }

        /* The predicate itself, on the addresses the socket can come back with. */
        ck(pm6_is_global(V6_CLIENT_GLOBAL), "T4_global_accepted");
        ck(pm6_is_global(V6_EXT_GLOBAL), "T4_documentation_prefix_accepted");
        ck(!pm6_is_global(V6_CLIENT_ULA), "T4_ula_refused");
        ck(!pm6_is_global(V6_CLIENT_LINKLOCAL), "T4_link_local_refused");
        ck(!pm6_is_global(V6_LO_ADDR), "T4_loopback_refused");
        ck(!pm6_is_global(V6_CLIENT_MAPPED), "T4_v4_mapped_refused");
        ck(!pm6_is_global(V6_UNSPEC), "T4_unspecified_refused");
        uint8_t mc[16];
        memset(mc, 0, sizeof mc);
        mc[0] = 0xff;
        ck(!pm6_is_global(mc), "T4_multicast_refused");
    }

    /* T5. result codes over v6 (§7.4): NOT_AUTHORIZED ends the schedule, the §8.5
     * epoch restart costs exactly one bounded re-request, and the retryable pair gets
     * one deferred retry no sooner than 60 s. All three are the v4 rules of S10/S11/
     * R14 replayed against the v6 gateway. */
    {
        char diagpath[256];
        snprintf(diagpath, sizeof diagpath, "%s/diag_t5.log", SCRATCH);
        unlink(diagpath);
        ck_eq(ntx_diag_open(diagpath), 0, "T5_diag_capture");
        sess x;
        sess_open(&x, "t5a");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint8_t req[2048], err[24];
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T5a_request");
        pcp_err24(err, PCP_RES_NOT_AUTHORIZED, 1800);
        gw6_answer(err, sizeof err);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck_eq(pm6_state6(&x), NTX_PM_NONE, "T5a_none_after_not_authorized");
        ck_eq(x.s->pm->s6.phase, -1, "T5a_nothing_outstanding");
        ck_eq(x.s->pm->s6.tries, 0, "T5a_no_retries");
        ck_eq(gw6_sends_in(&x, 60000, 6), 0, "T5a_no_further_resend");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        char *text = read_all(diagpath);
        ck(text && strstr(text, "NOT_AUTHORIZED"), "T5a_result_named_on_diag");
        free(text);
        ntx_diag_close();
        gw_drain();
        gw6_drain();

        /* T5b. §8.5: the gateway's Epoch fails the restart test → every v6 grant is
         * dropped and ONE fresh query goes out (new nonce, no suggested address). */
        sess y;
        sess_open(&y, "t5b");
        y.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&y);
        uint16_t lp = ntx_netx_port(y.n);
        pcp_grant6(&y, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        ck_eq(pm6_state6(&y), NTX_PM_ACTIVE, "T5b_active_before_restart");
        uint8_t gn[12];
        memcpy(gn, granted6_nonce[NTX_PCP_PROTO_TCP], 12);
        gw6_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&y);
        uint8_t rsp[64];
        ck_eq(gw6_get(req, sizeof req), 60, "T5b_renewal_sent");
        gw6_reply_at = pm_now();
        pcp_resp(rsp, req, lp, V6_EXT_GLOBAL, 7200, 0); /* the counter starts over */
        gw6_answer(rsp, 60);
        pump_ms(y.n, 20);
        pm_tick(&y); /* the tick owes the one fresh query of the rollback (R10) */
        ck_eq(gw6_get(req, sizeof req), 60, "T5b_fresh_query_sent");
        ck(gw6_req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "T5b_fresh_query_is_pcp_tcp");
        ck(memcmp(req + 24, gn, 12) != 0, "T5b_new_acquisition_draws_new_nonce");
        uint8_t zeros[16];
        memset(zeros, 0, sizeof zeros);
        ck(memcmp(req + 44, zeros, 16) == 0, "T5b_fresh_ask_no_suggested_ip");
        ck_eq(pm6_state6(&y), NTX_PM_PENDING, "T5b_pending_after_rollback");
        /* The one re-request is the whole rollback: with the IRT at 3 s (jittered to
         * no sooner than 2,7 s) two 1 s of clock must still buy nothing. */
        ck_eq(gw6_sends_in(&y, 1000, 2), 0, "T5b_one_query_not_a_loop");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(y.s);
        sess_close(&y);
        gw_drain();
        gw6_drain();

        /* T5c. §7.4 NO_RESOURCES with a retry-after: schedule stops, ONE attempt after
         * the wait the reply names. */
        sess z;
        sess_open(&z, "t5c");
        z.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&z);
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T5c_request");
        pcp_err24(err, PCP_RES_NO_RESOURCES, 120);
        gw6_answer(err, sizeof err);
        pump_ms(z.n, 40);
        pm_tick(&z);
        ck_eq(pm6_state6(&z), NTX_PM_NONE, "T5c_none_while_waiting");
        ck_eq(gw6_sends_in(&z, 30000, 3), 0, "T5c_quiet_before_120s"); /* 0..90 s */
        ck_eq(gw6_sends_in(&z, 29000, 1), 0, "T5c_still_quiet_at_119s");
        ck_eq(gw6_sends_in(&z, 2000, 1), 1, "T5c_one_retry_after_lifetime");
        ck_eq(z.s->pm->s6.phase, PM_PH_TCP, "T5c_retry_outstanding");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(z.s);
        sess_close(&z);
        gw_drain();
        gw6_drain();

        /* T5c2. the 60 s floor: the 10 s the reply names must not buy a retry at 10 s
         * (PM_RETRY_MIN_S, the same floor the v4 sequence of M7b obeys). */
        sess v;
        sess_open(&v, "t5c2");
        v.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&v);
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T5c2_request");
        pcp_err24(err, PCP_RES_NETWORK_FAILURE, 10);
        gw6_answer(err, sizeof err);
        pump_ms(v.n, 40);
        pm_tick(&v);
        ck_eq(gw6_sends_in(&v, 29000, 2), 0, "T5c2_quiet_below_60s_floor"); /* 0..58 s */
        ck_eq(gw6_sends_in(&v, 3000, 1), 1, "T5c2_retry_at_the_floor");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(v.s);
        sess_close(&v);
        gw_drain();
        gw6_drain();

        /* T5c3. lifetime 0 in the reply names no retry at all: `none` is final. */
        sess u;
        sess_open(&u, "t5c3");
        u.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&u);
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T5c3_request");
        pcp_err24(err, PCP_RES_NO_RESOURCES, 0);
        gw6_answer(err, sizeof err);
        pump_ms(u.n, 40);
        pm_tick(&u);
        ck_eq(pm6_state6(&u), NTX_PM_NONE, "T5c3_none");
        ck_eq(gw6_sends_in(&u, 60000, 12), 0, "T5c3_lifetime0_no_retry");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(u.s);
        sess_close(&u);
        gw_drain();
        gw6_drain();

        /* T5d. the NAT-PMP shape of an answer (version 0): RFC 6886 has no IPv6 form,
         * so a v6 gateway that speaks only NAT-PMP is a refusal, not a fallback. The
         * v4 half is still free to fall back on its own socket. */
        sess w;
        sess_open(&w, "t5d");
        w.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&w);
        ck_eq(gw6_wait(req, sizeof req, 400), 60, "T5d_request");
        const uint8_t unsupp[4] = {0, 0, 0, 1};
        gw6_answer(unsupp, sizeof unsupp);
        pump_ms(w.n, 40);
        pm_tick(&w);
        ck_eq(pm6_state6(&w), NTX_PM_NONE, "T5d_natpmp_answer_is_a_refusal");
        ck_eq(w.s->pm->fam, PM_PCP, "T5d_no_fallback_from_the_v6_answer");
        ck_eq(gw6_sends_in(&w, 60000, 4), 0, "T5d_v6_stays_quiet");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(w.s);
        sess_close(&w);
        gw_drain();
        gw6_drain();
    }

    /* T6. UDP is mapped over v6 only with --utp, exactly as v4 (§8). */
    {
        sess x;
        sess_open(&x, "t6a");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint16_t lp = ntx_netx_port(x.n);
        pcp_grant6(&x, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        ck_eq(gw6_sends_in(&x, 5000, 6), 0, "T6_no_udp_query_without_utp");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
        gw6_drain();

        sess y;
        sess_open(&y, "t6b");
        y.cfg.port_map = 1;
        y.cfg.utp = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&y);
        lp = ntx_netx_port(y.n);
        pcp_grant6(&y, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        uint8_t req[2048];
        ck(pcp6_next_req(&y, NTX_PCP_PROTO_UDP, req), "T6_udp_query_with_utp");
        ck_eq(req_int_port(req), lp, "T6_udp_internal_port_is_listen_port");
        ck_eq((req[42] << 8) | req[43], lp, "T6_udp_suggested_port_is_listen_port");
        ck(memcmp(req + 8, V6_CLIENT_GLOBAL, 16) == 0, "T6_udp_client_ip_same_as_tcp");
        uint8_t rsp[64];
        gw6_reply_at = pm_now();
        pcp_resp(rsp, req, lp, V6_EXT_GLOBAL, 7200, gw6_epoch_live(y.s->pm));
        gw6_answer(rsp, 60);
        pump_ms(y.n, 20);
        ck_eq(y.s->pm->s6.active[PM_PH_UDP], 1, "T6_udp_active_on_the_right_port");
        ck_eq(y.s->pm->s6.ext[PM_PH_UDP], (long)lp, "T6_udp_ext_is_the_listen_port");
        ck_eq(pm6_state6(&y), NTX_PM_ACTIVE, "T6_active_with_udp_too");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(y.s);
        sess_close(&y);
        gw_drain();
        gw6_drain();
    }

    /* T7. the families are independent: v6 ACTIVE with v4 NONE, v4 ACTIVE with v6
     * refused, each keeping its own renewals, and a v6 socket error leaving the v4
     * schedule exactly where it was (S17b pinned the socket half; this is the
     * sequence half). */
    {
        /* (a) v6 granted, v4 gateway silent: v6 keeps renewing, v4 stays on its own
         * retransmission schedule, and adv_port never picks the v6 grant up. The v4
         * half gets a socket that is bound and never read rather than dead_port(),
         * whose ICMP would have it take the NAT-PMP step and end the sequence — the
         * point here is a schedule still running, not one already settled. */
        sess x;
        uint16_t silent4 = 0;
        int silent_fd = udp_loopback(&silent4);
        sess_open(&x, "t7a");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        const uint16_t keep4 = gw_port;
        ntx_portmap_test_set_gateway_port(silent4);
        pm_start(&x);
        uint16_t lp = ntx_netx_port(x.n);
        pcp_grant6(&x, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        ck_eq(pm6_state6(&x), NTX_PM_ACTIVE, "T7a_v6_active");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "T7a_v4_pending");
        ck_eq(ntx_session_adv_port(x.s), lp, "T7a_adv_port_still_listen");
        gw_drain();
        /* v6 ACTIVE while the v4 sequence is mid-schedule: 60 s of clock moves the v4
         * retransmissions along (their own IRT/MRT clock, jitter included) without
         * touching the v6 grant, and without adv_port ever taking it. */
        ck_eq(gw6_sends_in(&x, 15000, 4), 0, "T7a_v6_silent_while_v4_retries");
        ck_eq(x.s->pm->phase, PM_PH_TCP, "T7a_v4_query_still_outstanding");
        ck(x.s->pm->tries >= 3, "T7a_v4_schedule_moved_on_its_own");
        ck_eq(ntx_session_portmap_state(x.s), NTX_PM_PENDING, "T7a_v4_state_alive");
        ck_eq(pm6_state6(&x), NTX_PM_ACTIVE, "T7a_v6_still_active_during_v4_retries");
        ntx_portmap_test_advance_ms(3601000 - 60000); /* past half of the 7200 s grant */
        pm_tick(&x);
        uint8_t areq[2048];
        ck_eq(gw6_get(areq, sizeof areq), 60, "T7a_v6_renewal_goes_out");
        ck(gw6_req_is(areq, 60, NTX_PCP_PROTO_TCP, 7200), "T7a_renewal_is_tcp");
        ck_eq(pm6_state6(&x), NTX_PM_ACTIVE, "T7a_still_active_while_renewal_in_flight");
        close(silent_fd);
        ntx_portmap_test_set_gateway_port(keep4);
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
        gw6_drain();

        /* (b) v4 granted, v6 refused with NOT_AUTHORIZED: v4 keeps its grant and its
         * renewals; the v6 verdict changes nothing about them. */
        sess y;
        sess_open(&y, "t7b");
        y.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&y);
        lp = ntx_netx_port(y.n);
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_grant(&y, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200); /* v4 grants a DIFFERENT port */
        ck(ntx_session_portmap_state(y.s) == NTX_PM_ACTIVE, "T7b_v4_active");
        ck_eq(ntx_session_adv_port(y.s), EXT_PORT, "T7b_adv_port_is_the_v4_grant");
        uint8_t req[2048], err[24];
        ck(pcp6_next_req(&y, NTX_PCP_PROTO_TCP, req), "T7b_v6_query_out");
        pcp_err24(err, PCP_RES_NOT_AUTHORIZED, 0);
        gw6_answer(err, sizeof err);
        pump_ms(y.n, 40);
        pm_tick(&y);
        ck_eq(pm6_state6(&y), NTX_PM_NONE, "T7b_v6_refused");
        ck(ntx_session_portmap_state(y.s) == NTX_PM_ACTIVE, "T7b_v4_still_active");
        ck_eq(ntx_session_adv_port(y.s), EXT_PORT, "T7b_adv_port_unmoved_by_v6_refusal");
        gw_drain();
        ntx_portmap_test_advance_ms(3601000);
        pm_tick(&y);
        ck_eq(gw_get(req, sizeof req), 60, "T7b_v4_renewal_still_goes_out");
        ck(req_is(req, 60, NTX_PCP_PROTO_TCP, 7200), "T7b_v4_renewal_is_tcp");
        ck_eq(gw6_sends_in(&y, 60000, 4), 0, "T7b_v6_stays_refused");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(y.s);
        sess_close(&y);
        gw_drain();
        gw6_drain();

        /* (c) a v6 socket error mid-sequence: the v4 grants, phases, tries and state
         * are bit-for-bit what they were (the S174 separation, now with a live v6
         * schedule on the other socket). */
        sess z;
        sess_open(&z, "t7c");
        z.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&z);
        lp = ntx_netx_port(z.n);
        pcp_grant6(&z, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        pcp_grant(&z, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck_eq(pm6_state6(&z), NTX_PM_ACTIVE, "T7c_both_active_precondition");
        const int v4_fd = z.s->pm->fd;
        const int v4_phase = z.s->pm->phase;
        const int v4_tries = z.s->pm->tries;
        const uint32_t v4_epoch = z.s->pm->epoch;
        pm_sock_err6(z.s->pm, EHOSTUNREACH);
        ck_eq(z.s->pm->fd6, -1, "T7c_v6_socket_gone");
        ck_eq(pm6_state6(&z), NTX_PM_NONE, "T7c_v6_half_ended");
        ck_eq(z.s->pm->s6.active[PM_PH_TCP], 0, "T7c_v6_grant_dropped_with_the_socket");
        ck_eq(pm6_ext6(&z), 0, "T7c_no_ext_port6_after_error");
        ck_eq(z.s->pm->fd, (long)v4_fd, "T7c_same_v4_fd");
        ck_eq(z.s->pm->phase, (long)v4_phase, "T7c_v4_phase_untouched");
        ck_eq(z.s->pm->tries, (long)v4_tries, "T7c_v4_schedule_untouched");
        ck_eq(z.s->pm->epoch, (long)v4_epoch, "T7c_v4_epoch_baseline_untouched");
        ck(ntx_session_portmap_state(z.s) == NTX_PM_ACTIVE, "T7c_v4_still_ACTIVE");
        ck_eq(ntx_session_adv_port(z.s), EXT_PORT, "T7c_v4_adv_port_survives_v6_error");
        long iters = pm_loop_iters(z.n, 300);
        if (iters >= 5000) printf("  (v6 spin: %ld loop iterations in 0,3 s)\n", iters);
        ck(iters < 5000, "T7c_bounded_loop_after_v6_hard_error");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(z.s);
        sess_close(&z);
        gw_drain();
        gw6_drain();

        /* (d) the reverse: v4 refuses outright and the v6 sequence still runs. A host
         * whose v4 default is gone is the R15 case that got nothing. */
        char nov4[256];
        snprintf(nov4, sizeof nov4, "%s/t7d_no_v4", SCRATCH);
        wr(nov4, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                 "wlP9s9\t0101A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n");
        sess w;
        sess_open(&w, "t7d");
        w.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, nov4);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&w);
        ck(w.s->pm->fd < 0, "T7d_no_v4_socket");
        ck(ntx_session_portmap_state(w.s) == NTX_PM_NONE, "T7d_v4_none");
        ck_eq(pm6_state6(&w), NTX_PM_PENDING, "T7d_v6_still_running");
        pcp_grant6(&w, NTX_PCP_PROTO_TCP, ntx_netx_port(w.n), V6_EXT_GLOBAL, 7200);
        ck_eq(pm6_state6(&w), NTX_PM_ACTIVE, "T7d_v6_active_without_any_v4");
        ck_eq(ntx_session_adv_port(w.s), ntx_netx_port(w.n), "T7d_adv_port_still_listen");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(w.s);
        sess_close(&w);
        gw_drain();
        gw6_drain();
    }

    /* T8. exit deletes: stop() sends lifetime 0 for both v6 mappings, fire-and-forget
     * like v4, and a half that mapped nothing sends nothing. */
    {
        sess x;
        sess_open(&x, "t8");
        x.cfg.port_map = 1;
        x.cfg.utp = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint16_t lp = ntx_netx_port(x.n);
        pcp_grant6(&x, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        pcp_grant6(&x, NTX_PCP_PROTO_UDP, lp, V6_EXT_GLOBAL, 7200);
        uint8_t tcp_nonce[12], udp_nonce[12];
        memcpy(tcp_nonce, granted6_nonce[NTX_PCP_PROTO_TCP], 12);
        memcpy(udp_nonce, granted6_nonce[NTX_PCP_PROTO_UDP], 12);
        ck(memcmp(tcp_nonce, udp_nonce, 12) != 0, "T8_fresh_nonce_per_mapping");
        gw6_drain();
        ntx_session_portmap_stop(x.s);
        uint8_t req[2048];
        int zero = 0, total = 0, del_tcp = 0, del_udp = 0;
        for (ssize_t r; (r = gw6_get(req, sizeof req)) >= 0;) {
            total++;
            if (r != 60 || rd32(req + 4) != 0) continue;
            zero++;
            if (req[36] == NTX_PCP_PROTO_TCP && memcmp(req + 24, tcp_nonce, 12) == 0) del_tcp++;
            if (req[36] == NTX_PCP_PROTO_UDP && memcmp(req + 24, udp_nonce, 12) == 0) del_udp++;
        }
        ck_eq(total, 2, "T8_stop_sends_only_the_deletes");
        ck_eq(zero, 2, "T8_lifetime0");
        ck_eq(del_tcp, 1, "T8_tcp_delete_same_nonce");
        ck_eq(del_udp, 1, "T8_udp_delete_same_nonce");
        sess_close(&x);
        gw_drain();
        gw6_drain();

        /* Nothing held: nothing sent. */
        sess y;
        sess_open(&y, "t8b");
        y.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&y);
        gw6_drain();
        ntx_session_portmap_stop(y.s);
        ck(!gw6_pending(), "T8b_no_delete_without_a_grant");
        sess_close(&y);
        gw_drain();
        gw6_drain();
    }

    /* T9. --proxy / --tunnel: no v6 request at all (§5), and the state stays OFF
     * rather than claiming a verdict it never reached. */
    {
        sess x;
        sess_open_pm(&x, "t9", 1, 1);
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(!gw6_pending(), "T9_no_v6_datagram_under_proxy");
        ck_eq(pm6_state6(&x), NTX_PM_OFF, "T9_off_under_proxy");
        ntx_portmap_test_set_client6(NULL);
        sess_close(&x);

        sess_open(&x, "t9b");
        x.cfg.port_map = 1;
        x.cfg.tunnel = 1;
        x.cfg.tunnel_host = "127.0.0.1";
        x.cfg.tunnel_port = 4444;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(!gw6_pending(), "T9_no_v6_datagram_under_tunnel");
        ck_eq(pm6_state6(&x), NTX_PM_OFF, "T9_off_under_tunnel");
        ntx_portmap_test_set_client6(NULL);
        sess_close(&x);
        gw_drain();
        gw6_drain();
    }

    /* T10. the production path, with the hook cleared: the client address IS what
     * getsockname answers, and on this box that is ::1 — so the family is skipped.
     * Without this case the hook could stand in for the rule forever. */
    {
        sess x;
        sess_open(&x, "t10");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        pm_start(&x);
        pump_ms(x.n, 20);
        ck(x.s->pm->fd6 >= 0, "T10_socket_up");
        struct sockaddr_in6 me;
        ck(pm6_sockname(x.s->pm, &me) == 0, "T10_getsockname");
        ck(memcmp(me.sin6_addr.s6_addr, V6_LO_ADDR, 16) == 0, "T10_kernel_picks_loopback");
        ck_eq(pm6_state6(&x), NTX_PM_NONE, "T10_skipped_on_the_real_address");
        ck(!gw6_pending(), "T10_nothing_on_wire_with_the_real_address");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
        gw6_drain();
    }

    /* ---- U. S17d / R15: the stats the operator reads.

     * The three fields the sub-step adds are the aggregate `port_map` (ACTIVE when
     * EITHER family is active), `port_map6` (the v6 family's own verdict) and
     * `ext_port6` (its grant). What the cases pin, beyond the values themselves, is
     * that the aggregate can go ACTIVE from one family alone in BOTH directions, that
     * a family which was never brought up is the identity of the aggregate (so the
     * v4-only numbers every existing test pins do not move), and that `ext_port` stays
     * the v4 grant while `ext_port6` stays the v6 one — an aggregate that is ACTIVE
     * because of v6 must not put a v4 port in the JSON, and the other way round.
     *
     * Read through the real publishing path (stats_refresh → the double buffer →
     * snapshot), the same one ntx_main's --stats-json and the status line consume. */
    {
        /* U1. v6 ACTIVE while v4 has no route at all: the aggregate is ACTIVE on the
         * strength of v6 alone, and `ext_port` (a v4 field) stays 0 — there is no v4
         * grant to report, and adv_port is still the listen port. */
        char nov4[256];
        snprintf(nov4, sizeof nov4, "%s/u1_no_v4", SCRATCH);
        wr(nov4, "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
                 "wlP9s9\t0101A8C0\t00000000\t0001\t0\t0\t600\t00FFFFFF\t0\t0\t0\n");
        sess x;
        sess_open(&x, "u1");
        x.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, nov4);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&x);
        uint16_t lp = ntx_netx_port(x.n);
        pcp_grant6(&x, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        ntx_stats st;
        sess_stats(&x, &st);
        ck_eq((long)st.port_map, NTX_PM_ACTIVE, "U1_aggregate_active_from_v6_alone");
        ck_eq(st.ext_port, 0, "U1_ext_port_stays_v4s_own");
        ck_eq((long)st.port_map6, NTX_PM_ACTIVE, "U1_port_map6_active");
        ck_eq(st.ext_port6, lp, "U1_ext_port6_is_the_grant");
        ck_eq(ntx_session_adv_port(x.s), lp, "U1_adv_port_still_listen");
        ck_eq((long)ntx_session_portmap_state(x.s), NTX_PM_NONE, "U1_v4_itself_is_none");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
        gw6_drain();

        /* U2. the reverse: v4 ACTIVE (a foreign external port, which is legal for v4)
         * while the v6 gateway refused. ACTIVE from v4 alone, and the v6 fields say
         * `none` / 0 rather than borrowing anything. */
        sess y;
        sess_open(&y, "u2");
        y.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&y);
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pcp_grant(&y, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        uint8_t req[2048], err[24];
        ck(pcp6_next_req(&y, NTX_PCP_PROTO_TCP, req), "U2_v6_query_out");
        pcp_err24(err, PCP_RES_NOT_AUTHORIZED, 0);
        gw6_answer(err, sizeof err);
        pump_ms(y.n, 40);
        pm_tick(&y);
        sess_stats(&y, &st);
        ck_eq((long)st.port_map, NTX_PM_ACTIVE, "U2_aggregate_active_from_v4_alone");
        ck_eq(st.ext_port, EXT_PORT, "U2_ext_port_is_the_v4_grant");
        ck_eq((long)st.port_map6, NTX_PM_NONE, "U2_port_map6_none");
        ck_eq(st.ext_port6, 0, "U2_no_ext_port6_without_a_grant");
        ck_eq(ntx_session_adv_port(y.s), EXT_PORT, "U2_adv_port_is_the_v4_grant");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(y.s);
        sess_close(&y);
        gw_drain();
        gw6_drain();

        /* U3. both ACTIVE at once: the aggregate is ACTIVE, and each family keeps its
         * OWN port — v4's grant is a foreign port, v6's is by rule the listen port. */
        sess z;
        sess_open(&z, "u3");
        z.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&z);
        lp = ntx_netx_port(z.n);
        pcp_grant6(&z, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        pcp_grant(&z, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        sess_stats(&z, &st);
        ck_eq((long)st.port_map, NTX_PM_ACTIVE, "U3_aggregate_active");
        ck_eq(st.ext_port, EXT_PORT, "U3_ext_port_v4");
        ck_eq((long)st.port_map6, NTX_PM_ACTIVE, "U3_port_map6_active");
        ck_eq(st.ext_port6, lp, "U3_ext_port6_v6");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(z.s);
        sess_close(&z);
        gw_drain();
        gw6_drain();

        /* U4. the v4-only case every pre-S17d test pins: no v6 default route, so the v6
         * half was never brought up (OFF) and the aggregate is the v4 state verbatim —
         * OFF is the identity of the merge, not a state that dilutes it. */
        sess v;
        sess_open(&v, "u4");
        v.cfg.port_map = 1;
        write_route6(V6_LO_BLACKHOLE, v4path);
        pm_start(&v);
        sess_stats(&v, &st);
        ck_eq((long)st.port_map, NTX_PM_PENDING, "U4_v4_only_aggregate_is_v4");
        ck_eq((long)st.port_map6, NTX_PM_OFF, "U4_port_map6_off_without_a_v6_route");
        ck_eq(st.ext_port6, 0, "U4_ext_port6_zero");
        ntx_session_portmap_stop(v.s);
        sess_close(&v);
        gw_drain();
        gw6_drain();

        /* U5. v4 CGNAT while v6 refused: nothing is reachable, so the aggregate keeps
         * the most informative refusal — `cgnat` beats `none`. The v6 half can never
         * reach 4 by itself (RFC 6886 has no IPv6, so there is no external-address
         * query to reveal a CGNAT), which is what U9 pins. */
        sess w;
        sess_open(&w, "u5");
        w.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&w);
        uint8_t rsp[64], cgn[16];
        pcp_v4(cgn, 100, 64, 1, 1);
        ck_eq(gw_wait(req, sizeof req, 400), 60, "U5_v4_request");
        pcp_resp(rsp, req, EXT_PORT, cgn, 7200, 7);
        gw_send(rsp, 60);
        pump_ms(w.n, 40);
        pm_tick(&w);
        ck(pcp6_next_req(&w, NTX_PCP_PROTO_TCP, req), "U5_v6_query_out");
        pcp_err24(err, PCP_RES_NOT_AUTHORIZED, 0);
        gw6_answer(err, sizeof err);
        pump_ms(w.n, 40);
        pm_tick(&w);
        sess_stats(&w, &st);
        ck_eq((long)st.port_map, NTX_PM_CGNAT, "U5_cgnat_beats_none");
        ck_eq(st.ext_port, 0, "U5_no_ext_port_on_cgnat");
        ck_eq((long)st.port_map6, NTX_PM_NONE, "U5_port_map6_none");
        ck_eq(st.ext_port6, 0, "U5_no_ext_port6_on_refusal");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(w.s);
        sess_close(&w);
        gw_drain();
        gw6_drain();

        /* U6. v4 CGNAT but v6 ACTIVE: the operator IS reachable over v6, so ACTIVE
         * outranks the CGNAT diagnosis — and `port_map6` still says which family it
         * came from, which is the whole reason the per-family field exists. */
        sess u;
        sess_open(&u, "u6");
        u.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&u);
        lp = ntx_netx_port(u.n);
        ck_eq(gw_wait(req, sizeof req, 400), 60, "U6_v4_request");
        pcp_resp(rsp, req, EXT_PORT, cgn, 7200, 7);
        gw_send(rsp, 60);
        pump_ms(u.n, 40);
        pm_tick(&u);
        pcp_grant6(&u, NTX_PCP_PROTO_TCP, lp, V6_EXT_GLOBAL, 7200);
        sess_stats(&u, &st);
        ck_eq((long)st.port_map, NTX_PM_ACTIVE, "U6_active_beats_cgnat");
        ck_eq((long)st.port_map6, NTX_PM_ACTIVE, "U6_port_map6_names_the_family");
        ck_eq(st.ext_port6, lp, "U6_ext_port6_is_the_grant");
        ck_eq(st.ext_port, 0, "U6_ext_port_not_borrowed_from_v6");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(u.s);
        sess_close(&u);
        gw_drain();
        gw6_drain();

        /* U7. neither family brought up: a public next hop for v4 (§8: no NAT to
         * traverse) and no v6 default at all — every field 0, and no datagram either. */
        sess q;
        sess_open(&q, "u7");
        q.cfg.port_map = 1;
        write_routes(GW_PUB);                      /* v4: public next hop, no NAT to traverse */
        write_route6(V6_LO_BLACKHOLE, v4path);     /* v6: nothing but networkd's blackhole */
        pm_start(&q);
        pump_ms(q.n, 20);
        sess_stats(&q, &st);
        ck_eq((long)st.port_map, NTX_PM_OFF, "U7_public_address_no_mapping");
        ck_eq((long)st.port_map6, NTX_PM_OFF, "U7_port_map6_off");
        ck_eq(st.ext_port, 0, "U7_ext_port_zero");
        ck_eq(st.ext_port6, 0, "U7_ext_port6_zero");
        ck(!gw_pending() && !gw6_pending(), "U7_nothing_on_either_wire");
        sess_close(&q);
        gw_drain();
        gw6_drain();

        /* U8. --proxy / --tunnel: neither family is asked, so the stats say OFF and not
         * a verdict of `none` the driver never reached (§5). */
        sess p;
        sess_open_pm(&p, "u8", 1, 1);
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&p);
        pump_ms(p.n, 20);
        sess_stats(&p, &st);
        ck_eq((long)st.port_map, NTX_PM_OFF, "U8_off_under_proxy");
        ck_eq((long)st.port_map6, NTX_PM_OFF, "U8_port_map6_off_under_proxy");
        ck_eq(st.ext_port, 0, "U8_ext_port_zero_under_proxy");
        ck_eq(st.ext_port6, 0, "U8_ext_port6_zero_under_proxy");
        ntx_portmap_test_set_client6(NULL);
        sess_close(&p);

        sess_open(&p, "u8b");
        p.cfg.port_map = 1;
        p.cfg.tunnel = 1;
        p.cfg.tunnel_host = "127.0.0.1";
        p.cfg.tunnel_port = 4444;
        write_route6(V6_DEFAULT_LO, v4path);
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&p);
        pump_ms(p.n, 20);
        sess_stats(&p, &st);
        ck_eq((long)st.port_map, NTX_PM_OFF, "U8_off_under_tunnel");
        ck_eq((long)st.port_map6, NTX_PM_OFF, "U8_port_map6_off_under_tunnel");
        ntx_portmap_test_set_client6(NULL);
        sess_close(&p);
        gw_drain();
        gw6_drain();

        /* U9. a family still asking is PENDING on its own and in the aggregate, and
         * `ext_port6` is 0 until a grant exists. Also the ceiling of the enum: the v6
         * half has no CGNAT to reach, so 4 never appears in port_map6. */
        sess o;
        sess_open(&o, "u9");
        o.cfg.port_map = 1;
        write_route6(V6_DEFAULT_LO, nov4); /* v6 route, no v4 route at all */
        ntx_portmap_test_set_client6(V6_CLIENT_GLOBAL);
        pm_start(&o);
        pump_ms(o.n, 20);
        sess_stats(&o, &st);
        ck_eq((long)st.port_map, NTX_PM_PENDING, "U9_pending_aggregates");
        ck_eq((long)st.port_map6, NTX_PM_PENDING, "U9_port_map6_pending");
        ck_eq(st.ext_port6, 0, "U9_no_ext_port6_before_the_grant");
        ck_eq(st.ext_port, 0, "U9_no_ext_port_without_a_v4");
        ck_eq(pm6_state6(&o) == NTX_PM_CGNAT ? 1 : 0, 0, "U9_v6_has_no_cgnat_state");
        ntx_portmap_test_set_client6(NULL);
        ntx_session_portmap_stop(o.s);
        sess_close(&o);
        gw_drain();
        gw6_drain();
    }

    /* ---- V. R19: the UDP ask names the port the TCP mapping holds, and a gateway
     * that hands UDP another one is flagged.

     * One announce carries one port — `ntx_session_adv_port` reads the TCP grant alone
     * — so a gateway that mapped TCP to port X and UDP to port Y leaves the peer
     * guessing which of the two it reached. The ask therefore suggests `ext[TCP]`
     * whenever the TCP mapping is held (RFC 6887 §11.1: the suggested external port is
     * a preference, not a demand), and a gateway that grants UDP something else anyway
     * is met by one diagnostic line — the UDP port is advertised nowhere, so the grant
     * is kept and only the divergence is made visible. Pre-fix the fresh UDP ask always
     * named the listen port: V1_udp_suggests_the_tcp_grant got=6881 want=40123,
     * V4_udp_suggests_the_tcp_grant got=6881 want=40123, and V3_divergence_flagged had
     * no line at all in the verbose log.
     *
     * The v6 half is untouched by this: S17c pins a granted v6 external port to the
     * listen port (pm_grant6 deletes anything else), so there the two rules would be
     * the same rule, and suggesting the TCP grant could only ask for a port the v6
     * sequence would then delete. */

    /* V1. PCP, TCP granted a foreign port: the UDP ask suggests THAT port, and keeps
     * the listen port as its internal port (§11.1: internal port, external preference
     * — the two fields are not the same thing). */
    write_routes(GW_LO);
    ntx_portmap_test_set_client6(NULL);
    {
        sess x;
        sess_open(&x, "v1");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "V1_tcp_grant_is_advertised");
        gw_drain();
        uint8_t ureq[60];
        ck(pm_next_req(&x, NTX_PCP_PROTO_UDP, ureq), "V1_udp_query_out");
        ck_eq(req_int_port(ureq), ntx_netx_port(x.n), "V1_udp_internal_port_is_listen_port");
        ck_eq((ureq[42] << 8) | ureq[43], EXT_PORT, "V1_udp_suggests_the_tcp_grant");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
    }

    /* V2. the other arm, so V1 cannot be satisfied by always echoing the TCP field:
     * the TCP grant is GONE (its renewal budget died in silence, R12) when the UDP ask
     * goes out, so there is no grant to suggest and the ask names the listen port.
     * Passes before the fix too — this is the guard on the no-grant path. */
    {
        sess x;
        sess_open(&x, "v2");
        x.cfg.port_map = 1; /* no --utp yet: nothing asks for UDP while TCP is held */
        uint8_t pub[16];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ntx_portmap_test_advance_ms(3601000); /* the renew window opens, nobody answers */
        pm_tick(&x);
        uint8_t req[2048];
        ck_eq(gw_get(req, sizeof req), 60, "V2_tcp_renew_sent");
        ck(pm_burn_budget(&x, PM_PH_TCP), "V2_tcp_budget_exhausted");
        ck_eq(x.s->pm->active[PM_PH_TCP], 0, "V2_tcp_grant_dropped");
        x.cfg.utp = 1; /* --utp comes on only after the TCP grant is gone */
        uint8_t ureq[60];
        ck(pm_next_req(&x, NTX_PCP_PROTO_UDP, ureq), "V2_udp_query_without_a_tcp_grant");
        ck_eq(req_int_port(ureq), ntx_netx_port(x.n), "V2_udp_internal_port_is_listen_port");
        ck_eq((ureq[42] << 8) | ureq[43], ntx_netx_port(x.n), "V2_udp_falls_back_to_the_listen_port");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
    }

    /* V3. the gateway ignores the suggestion: UDP gets a port of its own. The grant is
     * KEPT (it is never advertised, so it costs the swarm nothing) and the divergence
     * gets one line in the verbose log. */
    {
        char diagpath[256];
        snprintf(diagpath, sizeof diagpath, "%s/diag_v3.log", SCRATCH);
        unlink(diagpath);
        ck_eq(ntx_diag_open(diagpath), 0, "V3_diag_capture");
        sess x;
        sess_open(&x, "v3");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        uint8_t pub[16], rsp[64], ureq[60];
        pcp_v4(pub, 203, 0, 113, 9);
        pm_start(&x);
        pcp_grant(&x, NTX_PCP_PROTO_TCP, EXT_PORT, pub, 7200);
        gw_drain();
        ck(pm_next_req(&x, NTX_PCP_PROTO_UDP, ureq), "V3_udp_query_out");
        const uint16_t uport = (uint16_t)(EXT_PORT + 7);
        pcp_resp(rsp, ureq, uport, pub, 7200, gw_epoch_live(x.s->pm));
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck_eq(x.s->pm->active[PM_PH_UDP], 1, "V3_udp_grant_kept");
        ck_eq(x.s->pm->ext[PM_PH_UDP], (long)uport, "V3_udp_ext_is_the_gateways_port");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "V3_stays_active");
        ck_eq(ntx_session_adv_port(x.s), EXT_PORT, "V3_adv_port_still_the_tcp_grant");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        char want[64];
        snprintf(want, sizeof want, "%u", (unsigned)uport);
        char *text = read_all(diagpath);
        ck(text && strstr(text, "differs from the TCP port") && strstr(text, want) &&
               strstr(text, "40123"),
           "V3_divergence_flagged");
        free(text);
        ntx_diag_close();
        gw_drain();
    }

    /* V4. the same rule over NAT-PMP (RFC 6886 §3.3): the request keeps opcode 1 for
     * UDP and the listen port as its INTERNAL port, and the suggested external port
     * (octets 6..7) becomes the TCP grant. Renewals and deletes keep the granted port
     * exactly as they were — F4/O1 pin those shapes. */
    {
        sess x;
        sess_open(&x, "v4");
        x.cfg.utp = 1;
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048], rsp[16];
        uint16_t lp = ntx_netx_port(x.n);
        ck(gw_to_natpmp_map(&x, req, sizeof req) == 12, "V4_natpmp_tcp_query");
        ck_eq(req[1], 2, "V4_tcp_opcode");
        natpmp_map_resp(rsp, 2, lp, EXT_PORT, 3600); /* OP 2 = TCP, mapped to EXT_PORT */
        gw_send(rsp, 16);
        pump_ms(x.n, 40);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "V4_tcp_active");
        /* The UDP ask is the next query out. Whether the pump that read the TCP reply
         * already ran the tick that sends it depends on the 100 ms session timer, so the
         * case drives the schedule itself and takes the first datagram off the wire —
         * nothing is drained first, or the query would be thrown away. */
        uint8_t ureq[64];
        ssize_t un = -1;
        for (int i = 0; i < 40 && un < 0; i++) {
            pm_tick(&x);
            un = gw_get(ureq, sizeof ureq);
            if (un < 0) ntx_portmap_test_advance_ms(50);
        }
        ck_eq(un, 12, "V4_udp_query_out");
        ck_eq(ureq[1], 1, "V4_udp_opcode");
        ck_eq((ureq[4] << 8) | ureq[5], lp, "V4_udp_internal_port_is_listen_port");
        ck_eq((ureq[6] << 8) | ureq[7], EXT_PORT, "V4_udp_suggests_the_tcp_grant");
        ck_eq(rd32(ureq + 8), 7200, "V4_udp_asks_for_the_usual_lifetime");
        ntx_session_portmap_stop(x.s);
        sess_close(&x);
        gw_drain();
    }

    ntx_portmap_test_set_client6(NULL);
    write_routes(GW_LO);
    gw_drain();
    gw6_drain();

    close(gwd);
    if (fails) {
        printf("t_portmap: %d FAILURES\n", fails);
        return 1;
    }
    printf("PASS portmap\n");
    return 0;
}
