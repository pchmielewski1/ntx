/* Design §7 / §7.1: strict MSE for shares + the inbound-plaintext hold.
 *
 *  - an inbound plaintext connection gets NO answer before its initiator hash
 *    arrived and matched a slot (removes the port-scan info-hash leak);
 *  - after the match a strict slot is refused without sending a byte, every
 *    other slot is answered with the MATCHED slot's handshake (never the first
 *    live one);
 *  - an outbound connection answered in plaintext by a strict slot is dropped;
 *  - MSE to a strict slot still works and counts as an inbound success.
 *
 * Full-session TU (same #include block as t_priv_bep27.c): socketpair capture,
 * loopback-only dials, no event loop.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/stat.h>
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

static const char *SCRATCH = "test/.scratch/pe_strict";

static void fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

static void scratch(void) {
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) fail("scratch");
    if (mkdir(SCRATCH, 0755) != 0 && errno != EEXIST) fail("scratch_dir");
}

static void cfg_base(ntx_config *cfg, int utp) {
    memset(cfg, 0, sizeof *cfg);
    cfg->store_dir = SCRATCH;
    cfg->port_lo = 6981;
    cfg->port_hi = 7009;
    cfg->max_peers = 50;
    cfg->compat_peers = 1; /* §7: the fallback stays for non-strict slots */
    cfg->allow_local_peers = 1;
    cfg->utp = utp;
}

static ntx_session *mk(const ntx_config *cfg, ntx_netx **n) {
    *n = ntx_netx_init(cfg);
    if (!*n) fail("netx_init");
    ntx_session *s = ntx_session_init(*n, cfg);
    if (!s) fail("session_init");
    return s;
}

static void drop(ntx_session *s, ntx_netx *n) {
    ntx_session_free(s);
    ntx_netx_free(n);
}

static ntx_addr lo4(uint8_t last) {
    ntx_addr r;
    ntx_addr_set_v4(&r, htonl((0x7fu << 24) | last));
    return r;
}

/* Slot ti gets a distinct info_hash; `strict` mirrors what A5 sets for a share. */
static void set_slot(ntx_session *s, int ti, uint8_t seed, int strict) {
    uint8_t ih[20];
    memset(ih, (uint8_t)(0x40 + seed), sizeof ih);
    ih[0] = seed;
    ntx_torrent_init_meta(&s->tts[ti], ih);
    s->tts[ti].state = NTX_TTS_DL;
    s->tts_enc_strict[ti] = (uint8_t)strict;
    if (ti + 1 > s->n_tts) s->n_tts = ti + 1;
}

static void mk_hs(uint8_t m[68], const uint8_t ih[20], const uint8_t pid[20]) {
    memset(m, 0, 68);
    m[0] = 19;
    memcpy(m + 1, "BitTorrent protocol", 19);
    m[25] = 0x10;
    m[27] = 0x04;
    memcpy(m + 28, ih, 20);
    memcpy(m + 48, pid, 20);
}

static int nb(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) fail("nonblock");
    return fd;
}

/* Everything the peer end received, with a short timeout so "nothing was sent"
 * is an assertion and not a blocked read. */
static size_t recv_all(int fd, uint8_t *buf, size_t cap) {
    size_t got = 0;
    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 60) <= 0) break;
        ssize_t r = read(fd, buf + got, cap - got);
        if (r <= 0) break;
        got += (size_t)r;
        if (got == cap) break;
    }
    return got;
}

static int has_magic(const uint8_t *b, size_t n) {
    for (size_t i = 0; i + 19 <= n; i++)
        if (memcmp(b + i, "BitTorrent protocol", 19) == 0) return 1;
    return 0;
}

/* Accepted (inbound) peer on a socketpair; *cli is the end the test talks as. */
static int accept_peer(ntx_session *s, const ntx_addr *a, uint16_t port, int *cli) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) fail("socketpair");
    nb(fds[0]);
    nb(fds[1]);
    int pi = ntx_session_peer_alloc(s, fds[0], a, port, -1);
    if (pi < 0) fail("peer_alloc");
    ntx_session_peer_on_accept(s, s->netx, fds[0], NULL);
    *cli = fds[1];
    return pi;
}

static int send_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        return -1;
    }
    return 0;
}

/* §7.1 step 1: \x13BitTorrent protocol + 8 reserved bytes and nothing more —
 * we must stay silent (no handshake yet, so no info-hash leak to a scanner). */
static void test_inbound_partial_silence(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    set_slot(s, 0, 0x11, 0);

    ntx_addr a = lo4(1);
    int cli = -1;
    int pi = accept_peer(s, &a, 51000, &cli);

    uint8_t part[28];
    memset(part, 0, sizeof part);
    part[0] = 19;
    memcpy(part + 1, "BitTorrent protocol", 19);
    if (send_all(cli, part, sizeof part) != 0) fail("write_partial");
    for (int k = 0; k < 3; k++) ntx_session_peer_hs_tick(s);

    uint8_t got[2048];
    size_t gn = recv_all(cli, got, sizeof got);
    if (s->peers[pi].fd == -1) fail("partial_closed_early");
    if (gn != 0) fail("answered_before_initiator_hash");
    if (s->peer_out_len[pi] != 0) fail("outbuf_pending_before_hash");
    if (s->peer_phase[pi] != PH_BTHS) fail("not_waiting_in_bths");
    close(cli);
    drop(s, n);
    printf("PASS strict_inbound_partial_silence\n");
}

/* §7.1 step 2: full 68 B with an unknown hash → drop, nothing sent. */
static void test_inbound_unknown_hash(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    set_slot(s, 0, 0x22, 0);

    ntx_addr a = lo4(2);
    int cli = -1;
    int pi = accept_peer(s, &a, 51001, &cli);

    uint8_t unknown[20], hs[68];
    memset(unknown, 0xDE, sizeof unknown);
    mk_hs(hs, unknown, (const uint8_t *)"-peer0000000000000000");
    if (send_all(cli, hs, sizeof hs) != 0) fail("write_hs");
    for (int k = 0; k < 3; k++) ntx_session_peer_hs_tick(s);

    uint8_t got[2048];
    size_t gn = recv_all(cli, got, sizeof got);
    if (s->peers[pi].fd != -1) fail("unknown_hash_kept");
    if (gn != 0) fail("answered_unknown_hash");
    close(cli);
    drop(s, n);
    printf("PASS strict_inbound_unknown_hash\n");
}

/* §7.1 step 4: the answer carries the MATCHED slot's hash, not the first live
 * slot's (the session holds two slots, the peer names the second one). */
static void test_inbound_matches_second_slot(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    set_slot(s, 0, 0x33, 0);
    set_slot(s, 1, 0x44, 0);

    ntx_addr a = lo4(3);
    int cli = -1;
    int pi = accept_peer(s, &a, 51002, &cli);

    uint8_t hs[68];
    mk_hs(hs, s->tts[1].info_hash, (const uint8_t *)"-peer0000000000000000");
    if (send_all(cli, hs, sizeof hs) != 0) fail("write_hs");
    for (int k = 0; k < 3; k++) ntx_session_peer_hs_tick(s);

    uint8_t got[2048];
    size_t gn = recv_all(cli, got, sizeof got);
    if (gn < 68) fail("no_reply_hs");
    if (got[0] != 19 || memcmp(got + 1, "BitTorrent protocol", 19) != 0) fail("reply_magic");
    if (memcmp(got + 28, s->tts[1].info_hash, 20) != 0) fail("reply_hash_not_matched_slot");
    if (memcmp(got + 28, s->tts[0].info_hash, 20) == 0) fail("reply_hash_is_first_slot");
    if (s->peer_tts[pi] != 1) fail("peer_bound_to_wrong_slot");
    if (s->peer_phase[pi] != PH_OK) fail("peer_not_ok");
    close(cli);
    drop(s, n);
    printf("PASS strict_inbound_matches_second_slot\n");
}

/* §7: a plaintext initiator naming a strict slot is dropped without a reply,
 * compat_peers on and regardless of which slot number it is. */
static void test_inbound_strict_slot(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    set_slot(s, 0, 0x55, 1); /* strict share */
    set_slot(s, 1, 0x66, 0); /* public control slot */

    ntx_addr a = lo4(4);
    int cli = -1;
    int pi = accept_peer(s, &a, 51003, &cli);

    uint8_t hs[68];
    mk_hs(hs, s->tts[0].info_hash, (const uint8_t *)"-peer0000000000000000");
    if (send_all(cli, hs, sizeof hs) != 0) fail("write_hs");
    for (int k = 0; k < 3; k++) ntx_session_peer_hs_tick(s);

    uint8_t got[2048];
    size_t gn = recv_all(cli, got, sizeof got);
    if (s->peers[pi].fd != -1) fail("strict_plaintext_kept");
    if (gn != 0) fail("strict_plaintext_answered");
    close(cli);
    drop(s, n);
    printf("PASS strict_inbound_strict_slot\n");
}

/* §7: an outbound dial answered in plaintext by a strict slot is dropped. */
static void test_outbound_to_strict_dropped(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0);
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    /* ANY, not 127.0.0.1: the dial below targets 127.0.0.5 and a listener bound
     * to a single loopback address would never see it (accept would block). */
    sa.sin_addr.s_addr = htonl(INADDR_ANY);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 4)) fail("listen");
    socklen_t sl = sizeof sa;
    if (getsockname(lfd, (struct sockaddr *)&sa, &sl)) fail("getsockname");
    uint16_t port = ntohs(sa.sin_port);

    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    set_slot(s, 0, 0x77, 1);
    ntx_addr a = lo4(5);
    if (!ntx_session_add_peer_dial_ex(s, 0, &a, port, 1)) fail("dial");
    int pi = -1;
    for (int k = 0; k < NTX_SESSION_MAX_PEERS; k++)
        if (s->peers[k].fd != -1) pi = k;
    if (pi < 0) fail("dial_slot");
    if (!s->peer_outbound[pi]) fail("not_marked_outbound");

    int far = accept(lfd, NULL, NULL);
    if (far < 0) fail("accept");
    nb(far);
    uint8_t hs[68];
    mk_hs(hs, s->tts[0].info_hash, (const uint8_t *)"-peer0000000000000000");

    int alive = 1;
    for (int k = 0; k < 400 && alive; k++) {
        uint8_t sink[2048];
        while (recv(far, sink, sizeof sink, MSG_DONTWAIT) > 0) {}
        if (k == 2 && send_all(far, hs, sizeof hs) != 0) fail("write_far");
        ntx_session_peer_hs_tick(s);
        alive = s->peers[pi].fd != -1;
        if (alive) {
            struct timespec ts = {0, 2000000};
            nanosleep(&ts, NULL);
        }
    }
    uint8_t got[4096];
    size_t gn = 0;
    for (;;) {
        ssize_t r = recv(far, got + gn, sizeof got - gn, MSG_DONTWAIT);
        if (r <= 0) break;
        gn += (size_t)r;
    }
    if (alive) fail("outbound_plaintext_to_strict_kept");
    if (has_magic(got, gn)) fail("outbound_sent_plaintext_hs_to_strict");
    close(far);
    close(lfd);
    drop(s, n);
    printf("PASS strict_outbound_plaintext_dropped\n");
}

/* §7: MSE to a strict slot is unaffected — it reaches PH_OK and the inbound
 * reachability counter (tts_in_ok) for that slot counts it. */
static void test_mse_to_strict_counts_in_ok(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    set_slot(s, 0, 0x88, 1);

    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) fail("socketpair");
    nb(fds[0]);
    nb(fds[1]);
    int pi = ntx_session_peer_alloc(s, fds[0], &(ntx_addr){0}, 51004, -1);
    if (pi < 0) fail("peer_alloc");
    ntx_session_peer_on_accept(s, s->netx, fds[0], NULL);

    ntx_pe cli_pe;
    ntx_pe_init(&cli_pe, NTX_PE_INITIATOR, fds[1]);
    ntx_pe_set_infohash(&cli_pe, s->tts[0].info_hash);
    uint8_t hs[68];
    mk_hs(hs, s->tts[0].info_hash, (const uint8_t *)"-peer0000000000000000");
    ntx_pe_set_bt_handshake(&cli_pe, hs);

    int idle = 0;
    for (int k = 0; k < 20000 && !cli_pe.done; k++) {
        int r = ntx_pe_step(&cli_pe);
        if (r < 0) break;
        ntx_session_peer_hs_tick(s);
        if (r == 0) {
            if (++idle > 2000) break;
        } else idle = 0;
    }
    if (cli_pe.done != 1) fail("mse_initiator_failed");
    if (s->peers[pi].fd == -1) fail("mse_inbound_dropped");
    if (s->peer_phase[pi] != PH_OK) fail("mse_inbound_not_ok");
    if (s->peer_tts[pi] != 0) fail("mse_bound_wrong_slot");
    if (s->tts_in_ok[0] != 1) fail("tts_in_ok_not_counted");
    close(fds[1]);
    drop(s, n);
    printf("PASS strict_mse_inbound_ok_counts\n");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    scratch();
    test_inbound_partial_silence();
    test_inbound_unknown_hash();
    test_inbound_matches_second_slot();
    test_inbound_strict_slot();
    test_outbound_to_strict_dropped();
    test_mse_to_strict_counts_in_ok();
    printf("ALL PASS\n");
    return 0;
}
