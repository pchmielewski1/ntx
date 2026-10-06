/* BEP11 PEX outbound (TX) — lifecycle tests.
 *
 * Full-session TU (same #include block as t_pex_flood.c): socketpair
 * capture, loopback only, no event loop. Drives ntx_session_data_pex_tick
 * with queued connect/disconnect events and asserts the outbound ut_pex
 * ext message to the receiver: added on PH_OK, dropped after sp_drop,
 * elision of connect->disconnect before any send, 60 s per-peer rate
 * limit, 50-cap per list, and no contact in added+dropped of one msg.
 * Deterministic: no network, count/addr-based assertions.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

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

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

/* ---------------- session helpers ---------------- */

static const char *MAGNET =
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=PF&tr=udp://tracker.example.com:6969";

static void cfg_default(ntx_config *cfg, int max_peers) {
    memset(cfg, 0, sizeof *cfg);
    cfg->store_dir = "downloads";
    cfg->port_lo = 6881;
    cfg->port_hi = 6891;
    cfg->max_peers = max_peers;
}

static ntx_session *mk(const ntx_config *cfg, ntx_netx **n) {
    *n = ntx_netx_init(cfg);
    if (!*n) fail("netx_init");
    ntx_session *s = ntx_session_init(*n, cfg);
    if (!s) fail("session_init");
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("add_magnet");
    if (s->n_tts != 1) fail("add_magnet_n");
    return s;
}

static void drop(ntx_session *s, ntx_netx *n) {
    ntx_session_free(s);
    ntx_netx_free(n);
}

/* Two PH_OK peers on tts 0:
 *   pi 0 = receiver "A" 10.0.0.1:6881, pex_id = NTX_EXT_LOCAL_PEX,
 *         real socketpair fd (capture end handed back in *cap_fd),
 *   pi 1 = "B" 10.0.0.2:6881, fd -1 (never dialed in this harness).
 * Returns pi of A (0 on a fresh session). */
static int setup_two_peers(ntx_session *s, int *cap_fd) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return -1;
    fcntl(fds[0], F_SETFL, O_NONBLOCK);

    ntx_addr a;
    ntx_addr_set_v4(&a, htonl(0x0a000001u));
    int pi = ntx_session_peer_alloc(s, fds[0], &a, 6881, 0);
    if (pi < 0) {
        close(fds[0]);
        close(fds[1]);
        return -1;
    }
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_pex_id[pi] = NTX_EXT_LOCAL_PEX;
    s->peer_hello_sent[pi] = 1;
    s->peer_pex_last_ms[pi] = 0;

    ntx_addr b;
    ntx_addr_set_v4(&b, htonl(0x0a000002u));
    int pj = ntx_session_peer_alloc(s, -1, &b, 6881, 0);
    if (pj < 0) {
        ntx_session_peer_free(s, pi);
        close(fds[1]);
        return -1;
    }
    s->peer_phase[pj] = PH_OK;
    s->peer_pex_last_ms[pj] = 0;

    *cap_fd = fds[1];
    return pi;
}

/* Read one full wire message (4 B BE length + body) from the capture socket. */
static int read_wire(int fd, uint8_t *wire, size_t cap, size_t *outn) {
    size_t got = 0;
    while (got < 4) {
        ssize_t r = read(fd, wire + got, 4 - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    uint32_t body = ((uint32_t)wire[0] << 24) | ((uint32_t)wire[1] << 16) |
                    ((uint32_t)wire[2] << 8) | (uint32_t)wire[3];
    /* wire = 4 B length prefix + body (msg_id + ext_id + payload) */
    if (body < 2 || (size_t)body + 4 > cap) return -1;
    size_t full = 4 + (size_t)body;
    while (got < full) {
        ssize_t r = read(fd, wire + got, full - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    *outn = got;
    return 0;
}

/* ---------------- parse helpers ---------------- */

#define PP_CAP 64

typedef struct {
    uint32_t aip[PP_CAP];
    uint16_t apt[PP_CAP];
    int na;
    uint32_t dip[PP_CAP];
    uint16_t dport[PP_CAP];
    int nd;
    uint8_t a6ip[PP_CAP][16];
    uint16_t a6port[PP_CAP];
    int na6;
    uint8_t d6ip[PP_CAP][16];
    uint16_t d6port[PP_CAP];
    int nd6;
} parsed_pex;

static void parse_payload(const uint8_t *payload, size_t plen, parsed_pex *r) {
    memset(r, 0, sizeof *r);
    if (ntx_pex_parse_ex(payload, plen, r->aip, r->apt, &r->na, r->dip, r->dport,
                         &r->nd, PP_CAP, r->a6ip, r->a6port, &r->na6, r->d6ip,
                         r->d6port, &r->nd6, PP_CAP) != 0)
        fail("parse_payload");
}

/* Read one wire message from the capture socket and parse its ut_pex payload. */
static void read_and_parse(int fd, parsed_pex *r) {
    uint8_t wire[4096];
    size_t wn = 0;
    if (read_wire(fd, wire, sizeof wire, &wn) != 0) fail("no_wire");
    if (wn < 6) fail("wire_short");
    if (wire[4] != MSG_EXT) fail("wire_not_ext");
    if (wire[5] != NTX_EXT_LOCAL_PEX) fail("wire_ext_id");
    parse_payload(wire + 6, wn - 6, r);
}

/* 1 = at least one byte pending on the capture socket. */
static int bytes_pending(int fd) {
    struct pollfd pfd;
    pfd.fd = fd;
    pfd.events = POLLIN;
    pfd.revents = 0;
    return poll(&pfd, 1, 0) > 0;
}

static int has4(const parsed_pex *r, uint32_t ip, uint16_t port, int dropped) {
    if (dropped) {
        for (int i = 0; i < r->nd; i++)
            if (r->dip[i] == ip && r->dport[i] == port) return 1;
        return 0;
    }
    for (int i = 0; i < r->na; i++)
        if (r->aip[i] == ip && r->apt[i] == port) return 1;
    return 0;
}

/* A contact must not appear in added and dropped of the same message. */
static void assert_no_same_msg(const parsed_pex *r, const char *name) {
    for (int i = 0; i < r->na; i++)
        for (int j = 0; j < r->nd; j++)
            if (r->aip[i] == r->dip[j] && r->apt[i] == r->dport[j]) fail(name);
    for (int i = 0; i < r->na6; i++)
        for (int j = 0; j < r->nd6; j++)
            if (r->a6port[i] == r->d6port[j] &&
                memcmp(r->a6ip[i], r->d6ip[j], 16) == 0)
                fail(name);
}

/* ---------------- outbound tests ---------------- */

static void test_outbound_added_contains_peer(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    int cap_fd = -1;
    int pi = setup_two_peers(s, &cap_fd);
    if (pi < 0) fail("setup_two_peers");

    /* B reached PH_OK -> queued as added candidate for tts 0 */
    ntx_addr b;
    ntx_addr_set_v4(&b, htonl(0x0a000002u));
    ntx_pex_tx_on_connected(&s->pex_tx[0], &b, 6881);

    /* force both tick gates open: coarse tick gate + per-peer rate limit */
    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600; /* (tick_n % 600) == 0 */
    ntx_session_data_pex_tick(s);

    uint8_t wire[2048];
    size_t wn = 0;
    if (read_wire(cap_fd, wire, sizeof wire, &wn) != 0) fail("outbound_no_wire");
    if (wn < 6) fail("outbound_short");
    if (wire[4] != MSG_EXT) fail("outbound_not_ext");
    if (wire[5] != NTX_EXT_LOCAL_PEX) fail("outbound_ext_id");
    const uint8_t *payload = wire + 6;
    size_t plen = wn - 6;

    static uint32_t aip[8], dip[8];
    static uint16_t apt[8], dport[8];
    static uint8_t a6ip[8][16], d6ip[8][16];
    static uint16_t a6port[8], d6port[8];
    int na = 0, nd = 0, na6 = 0, nd6 = 0;
    if (ntx_pex_parse_ex(payload, plen, aip, apt, &na, dip, dport, &nd, 8,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 8) != 0)
        fail("outbound_parse");
    if (na + na6 != 1) fail("outbound_count");
    if (na != 1) fail("outbound_family"); /* v4 contact must land in added, not added6 */
    if (aip[0] != htonl(0x0a000002u) || apt[0] != 6881) fail("outbound_entry");

    close(cap_fd);
    drop(s, n);
}

/* added first, then sp_drop(B) -> next tick carries B in dropped, not added. */
static void test_tx_dropped_after_drop(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    int cap_fd = -1;
    int pi = setup_two_peers(s, &cap_fd);
    if (pi < 0) fail("setup_two_peers");

    ntx_addr b;
    ntx_addr_set_v4(&b, htonl(0x0a000002u));
    ntx_pex_tx_on_connected(&s->pex_tx[0], &b, 6881);

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600;
    ntx_session_data_pex_tick(s);
    parsed_pex p1;
    read_and_parse(cap_fd, &p1);
    if (p1.na != 1 || p1.nd != 0) fail("drop_phase1_count");
    if (!has4(&p1, htonl(0x0a000002u), 6881, 0)) fail("drop_phase1_added");
    assert_no_same_msg(&p1, "drop_phase1_same_msg");

    /* B is PH_OK -> was_ok hook enqueues the disconnect */
    sp_drop(s, 1, "test");

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 1200;
    ntx_session_data_pex_tick(s);
    parsed_pex p2;
    read_and_parse(cap_fd, &p2);
    if (p2.nd != 1 || p2.na != 0) fail("drop_phase2_count");
    if (p2.nd6 != 0 || p2.na6 != 0) fail("drop_phase2_family");
    if (!has4(&p2, htonl(0x0a000002u), 6881, 1)) fail("drop_phase2_dropped");
    if (has4(&p2, htonl(0x0a000002u), 6881, 0)) fail("drop_phase2_still_added");
    assert_no_same_msg(&p2, "drop_phase2_same_msg");

    close(cap_fd);
    drop(s, n);
}

/* connect+disconnect before any tick -> elided: no wire bytes at all. */
static void test_tx_elision(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    int cap_fd = -1;
    int pi = setup_two_peers(s, &cap_fd);
    if (pi < 0) fail("setup_two_peers");

    ntx_addr b;
    ntx_addr_set_v4(&b, htonl(0x0a000002u));
    ntx_pex_tx_on_connected(&s->pex_tx[0], &b, 6881);
    ntx_pex_tx_on_disconnected(&s->pex_tx[0], &b, 6881);

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600;
    ntx_session_data_pex_tick(s);
    if (bytes_pending(cap_fd)) fail("elision_wire");

    close(cap_fd);
    drop(s, n);
}

/* Second tick within the 60 s window must not send; after reset it delivers. */
static void test_tx_rate_limit(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    int cap_fd = -1;
    int pi = setup_two_peers(s, &cap_fd);
    if (pi < 0) fail("setup_two_peers");

    ntx_addr b, c;
    ntx_addr_set_v4(&b, htonl(0x0a000002u));
    ntx_addr_set_v4(&c, htonl(0x0a000003u));
    ntx_pex_tx_on_connected(&s->pex_tx[0], &b, 6881);

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600;
    ntx_session_data_pex_tick(s);
    parsed_pex p1;
    read_and_parse(cap_fd, &p1);
    if (p1.na != 1 || !has4(&p1, htonl(0x0a000002u), 6881, 0)) fail("rate_phase1_added");
    if (s->peer_pex_last_ms[pi] == 0) fail("rate_last_ms_unset");

    /* new connect while the window is open: tick must stay silent */
    ntx_pex_tx_on_connected(&s->pex_tx[0], &c, 6881);
    s->tick_n = 1200; /* coarse gate open, per-peer rate limit must block */
    ntx_session_data_pex_tick(s);
    if (bytes_pending(cap_fd)) fail("rate_wire_in_window");

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 1800;
    ntx_session_data_pex_tick(s);
    parsed_pex p2;
    read_and_parse(cap_fd, &p2);
    if (p2.na != 1 || p2.nd != 0) fail("rate_phase2_count");
    if (!has4(&p2, htonl(0x0a000003u), 6881, 0)) fail("rate_phase2_added");
    if (has4(&p2, htonl(0x0a000002u), 6881, 0)) fail("rate_phase2_resend_b");
    assert_no_same_msg(&p2, "rate_phase2_same_msg");

    close(cap_fd);
    drop(s, n);
}

/* 60 queued connects: first tick caps at 50 added; after all disconnect,
 * second tick caps at 50 dropped and the 10 never-advertised elide. */
static void test_tx_drop_cap(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    int cap_fd = -1;
    int pi = setup_two_peers(s, &cap_fd);
    if (pi < 0) fail("setup_two_peers");

    for (int x = 1; x <= 60; x++) {
        ntx_addr a;
        ntx_addr_set_v4(&a, htonl(0x0a010000u + (uint32_t)x));
        ntx_pex_tx_on_connected(&s->pex_tx[0], &a, 6881);
    }

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600;
    ntx_session_data_pex_tick(s);
    parsed_pex p1;
    read_and_parse(cap_fd, &p1);
    if (p1.na != 50 || p1.nd != 0) fail("cap_phase1_count");
    if (p1.na6 != 0 || p1.nd6 != 0) fail("cap_phase1_family");
    assert_no_same_msg(&p1, "cap_phase1_same_msg");

    for (int x = 1; x <= 60; x++) {
        ntx_addr a;
        ntx_addr_set_v4(&a, htonl(0x0a010000u + (uint32_t)x));
        ntx_pex_tx_on_disconnected(&s->pex_tx[0], &a, 6881);
    }

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 1200;
    ntx_session_data_pex_tick(s);
    parsed_pex p2;
    read_and_parse(cap_fd, &p2);
    if (p2.nd != 50 || p2.na != 0) fail("cap_phase2_count");
    if (p2.nd6 != 0 || p2.na6 != 0) fail("cap_phase2_family");
    /* the 10 never-advertised (x=51..60) must be elided, not dropped */
    for (int x = 51; x <= 60; x++)
        if (has4(&p2, htonl(0x0a010000u + (uint32_t)x), 6881, 1))
            fail("cap_phase2_elided_in_dropped");
    assert_no_same_msg(&p2, "cap_phase2_same_msg");

    close(cap_fd);
    drop(s, n);
}

/* Mixed pending adds + pending drops of different contacts in one message:
 * no contact may appear in both added and dropped. */
static void test_tx_no_same_msg(void) {
    ntx_config cfg;
    cfg_default(&cfg, 50);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);

    int cap_fd = -1;
    int pi = setup_two_peers(s, &cap_fd);
    if (pi < 0) fail("setup_two_peers");

    ntx_addr b, c, d;
    ntx_addr_set_v4(&b, htonl(0x0a000002u));
    ntx_addr_set_v4(&c, htonl(0x0a000003u));
    ntx_addr_set_v4(&d, htonl(0x0a000004u));
    ntx_pex_tx_on_connected(&s->pex_tx[0], &b, 6881);
    ntx_pex_tx_on_connected(&s->pex_tx[0], &c, 6881);

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600;
    ntx_session_data_pex_tick(s);
    parsed_pex p1;
    read_and_parse(cap_fd, &p1);
    if (p1.na != 2 || p1.nd != 0) fail("same_phase1_count");
    assert_no_same_msg(&p1, "same_phase1");

    /* B (advertised) disconnects -> dropped; D connects -> added */
    ntx_pex_tx_on_disconnected(&s->pex_tx[0], &b, 6881);
    ntx_pex_tx_on_connected(&s->pex_tx[0], &d, 6881);

    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 1200;
    ntx_session_data_pex_tick(s);
    parsed_pex p2;
    read_and_parse(cap_fd, &p2);
    if (p2.na != 1 || p2.nd != 1) fail("same_phase2_count");
    if (!has4(&p2, htonl(0x0a000004u), 6881, 0)) fail("same_phase2_added");
    if (!has4(&p2, htonl(0x0a000002u), 6881, 1)) fail("same_phase2_dropped");
    assert_no_same_msg(&p2, "same_phase2");

    close(cap_fd);
    drop(s, n);
}

int main(void) {
    ntx_rng_init();

    test_outbound_added_contains_peer();
    printf("PASS outbound_added_contains_peer\n");

    test_tx_dropped_after_drop();
    printf("PASS tx_dropped_after_drop\n");

    test_tx_elision();
    printf("PASS tx_elision\n");

    test_tx_rate_limit();
    printf("PASS tx_rate_limit\n");

    test_tx_drop_cap();
    printf("PASS tx_drop_cap\n");

    test_tx_no_same_msg();
    printf("PASS tx_no_same_msg\n");

    return 0;
}
