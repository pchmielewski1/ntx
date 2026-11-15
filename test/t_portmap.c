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
    snprintf(line, sizeof line,
             "00000000000000000000000000000000 00 00000000000000000000FFFF%s 40 "
             "00000000000000000000000000000000 00000100 00000001 00000000 00000001 lo\n", gw_net_hex);
    wr(v6path, line);
    ntx_portmap_test_set_route_files(v4path, v6path);
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

static void sess_open(sess *x, const char *tag) {
    char dir[256];
    snprintf(dir, sizeof dir, "%s/%s", SCRATCH, tag);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) {
        printf("FAIL store dir\n");
        exit(1);
    }
    memset(x, 0, sizeof *x);
    x->cfg.store_dir = dir;
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
     * gateway; a case must never read another case's datagram. */
    gw_drain();
}

static void sess_close(sess *x) {
    ntx_session_free(x->s);
    ntx_netx_free(x->n);
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

    /* ---- M. a datagram that carries no verdict at all: no grant, no immediate
     * resend, and the retransmission schedule continues (§8.3).
     *
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

    close(gwd);
    if (fails) {
        printf("t_portmap: %d FAILURES\n", fails);
        return 1;
    }
    printf("PASS portmap\n");
    return 0;
}
