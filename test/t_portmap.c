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

static int req_is(const uint8_t *b, ssize_t n, uint8_t proto, uint32_t lifetime) {
    return n == 60 && b[0] == 2 && b[1] == 1 && b[36] == proto && rd32(b + 4) == lifetime;
}

static uint16_t req_int_port(const uint8_t *b) {
    return (uint16_t)((b[40] << 8) | b[41]);
}

/* One PCP exchange for one protocol: wait for its request, answer SUCCESS. */
static uint8_t granted_nonce[256][12]; /* by protocol: the delete must repeat it (§11.1) */

static void pcp_grant(sess *x, uint8_t proto, uint16_t ext_port, const uint8_t ext_ip[16], uint32_t lifetime) {
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
        pcp_resp(rsp, req, ext_port, ext_ip, lifetime, 7);
        gw_send(rsp, 60);
        pump_ms(x->n, 20);
        return;
    }
    printf("FAIL no pcp request proto=%u\n", proto);
    fails++;
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

    /* ---- D. no reply: 9 attempts (250 ms, doubled) then NONE ---- */
    {
        sess x;
        sess_open(&x, "d");
        x.cfg.port_map = 1;
        pm_start(&x);
        uint8_t req[2048];
        ck_eq(gw_wait(req, sizeof req, 300), 60, "D_attempt1");
        gw_drain();
        int attempts = 1;
        uint32_t gap = 250;
        for (int i = 0; i < 8; i++) {
            ntx_portmap_test_advance_ms(gap - 1);
            pm_tick(&x);
            if (gw_pending()) break; /* retried early: the schedule is wrong */
            ntx_portmap_test_advance_ms(1);
            pm_tick(&x);
            if (gw_get(req, sizeof req) < 0) break;
            gw_drain();
            attempts++;
            gap *= 2;
        }
        ck_eq(attempts, 9, "D_nine_attempts");
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "D_pending_until_budget_out");
        ntx_portmap_test_advance_ms(gap);
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

    /* ---- H. epoch rollback (RFC 6887 §8.5) re-requests ---- */
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
        pcp_resp(rsp, req, EXT_PORT, pub, 7200, 3); /* epoch went backwards: gateway rebooted */
        gw_send(rsp, 60);
        pump_ms(x.n, 40);
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "H_rollback_pending");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "H_rollback_no_adv_port");
        gw_drain();
        pcp_grant(&x, NTX_PCP_PROTO_TCP, 40124, pub, 7200);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_ACTIVE, "H_recovered");
        ck_eq(ntx_session_adv_port(x.s), 40124, "H_recovered_adv_port");
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

    /* ---- M. definitive non-success: no grant, and no immediate resend (§8.3) ---- */
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
        rsp[3] = 7; /* NETWORK_FAILURE: the codec folds it to "not a grant" */
        gw_send(rsp, 60);
        pump_ms(x.n, 120); /* two real ticks */
        pm_tick(&x);
        ck(ntx_session_portmap_state(x.s) == NTX_PM_PENDING, "M_no_grant");
        ck_eq(ntx_session_adv_port(x.s), ntx_netx_port(x.n), "M_no_adv_port");
        ck(!gw_pending(), "M_no_immediate_resend");
        ntx_portmap_test_advance_ms(260);
        pm_tick(&x);
        ck_eq(gw_get(req, sizeof req), 60, "M_resend_on_schedule");
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

    close(gwd);
    if (fails) {
        printf("t_portmap: %d FAILURES\n", fails);
        return 1;
    }
    printf("PASS portmap\n");
    return 0;
}
