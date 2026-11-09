/* BEP 27 (design §4): a torrent whose info dict carries a non-zero `private`
 * never touches DHT, PEX or ut_holepunch, is only dialled by tracker-sourced
 * addresses, and a magnet that turns out to be private closes the outbound
 * connections dialled before the info dict was known.
 *
 * Full-session TU (same #include block as t_pex_outbound.c): socketpair
 * capture, loopback-only dials (public controls dial 127.0.0.x so the refused
 * private cases never reach the socket layer at all), no event loop.
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
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

/* Produced by Task B1 in ntx_session.c. Declared here because the prototype
 * belongs in ntx_session_internal.h, which Task 1 owns. */
int ntx_session_add_peer_src(struct ntx_session *s, int ti, const ntx_addr *a,
                             uint16_t port, uint8_t src);

static const char *MAGNET =
    "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=B27"
    "&tr=udp://tracker.example.com:6969";
static const char *SCRATCH = "test/.scratch/priv_bep27";
/* Loopback ports for the public-control dials, clear of the 6881-6891 listen
 * range so a dial never connects back into our own listener. */
#define DIAL_PORT 47123

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

static void cfg_base(ntx_config *cfg, int dht, int utp) {
    memset(cfg, 0, sizeof *cfg);
    cfg->store_dir = SCRATCH;
    cfg->port_lo = 6881;
    cfg->port_hi = 6891;
    cfg->max_peers = 50;
    cfg->dht = dht;
    cfg->utp = utp;
    cfg->allow_local_peers = 1; /* the public-control dials target loopback */
}

static void scratch(void) {
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) fail("scratch");
    if (mkdir(SCRATCH, 0755) != 0 && errno != EEXIST) fail("scratch_dir");
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

static ntx_addr lo4(uint8_t last) {
    ntx_addr r;
    ntx_addr_set_v4(&r, htonl((0x7fu << 24) | last));
    return r;
}

static ntx_addr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    ntx_addr r;
    ntx_addr_set_v4(&r, htonl(((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d));
    return r;
}

static int live_peers(const ntx_session *s) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1) c++;
    return c;
}

static int pi_of(const ntx_session *s, const ntx_addr *a, uint16_t port) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1 && ntx_addr_eq(&s->peers[pi].addr, a) && s->peers[pi].port == port)
            return pi;
    return -1;
}

/* PH_OK plaintext peer of tts `ti` on a socketpair; *cap_fd is the end the test
 * reads the bytes ntx sends to it from. */
static int add_peer_captured(ntx_session *s, int ti, const ntx_addr *a, uint16_t port, int *cap_fd) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) fail("socketpair");
    if (fcntl(fds[0], F_SETFL, O_NONBLOCK) < 0) fail("nonblock");
    int pi = ntx_session_peer_alloc(s, fds[0], a, port, ti);
    if (pi < 0) fail("peer_alloc");
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    *cap_fd = fds[1];
    return pi;
}

/* One 4-byte-length-prefixed wire message from the capture socket. A short poll
 * timeout keeps "nothing was sent" an assertion instead of a blocked read. */
static int read_wire(int fd, uint8_t *wire, size_t cap, size_t *outn) {
    size_t got = 0;
    while (got < 4) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 200) <= 0) return -1;
        ssize_t r = read(fd, wire + got, 4 - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    uint32_t body = ((uint32_t)wire[0] << 24) | ((uint32_t)wire[1] << 16) |
                    ((uint32_t)wire[2] << 8) | (uint32_t)wire[3];
    if (body < 2 || (size_t)body + 4 > cap) return -1;
    size_t full = 4 + (size_t)body;
    while (got < full) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 200) <= 0) return -1;
        ssize_t r = read(fd, wire + got, full - got);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    *outn = got;
    return 0;
}

static int name_seen(const char **names, int n, const char *want) {
    for (int i = 0; i < n; i++)
        if (strcmp(names[i], want) == 0) return 1;
    return 0;
}

/* §4.2/§4.3: the ext-handshake of a private slot offers ut_metadata only (the
 * metadata exchange stays, magnet peers must still be able to hand over the
 * info dict); the public control keeps offering all three. */
static void ext_hs_advertises(int priv) {
    ntx_config cfg;
    cfg_base(&cfg, 0, 1);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    s->tts[0].priv = (uint8_t)priv;
    s->tts[0].have_meta = 1;
    s->tts[0].info_raw_n = 4096;

    ntx_addr a = lo4(1);
    int cap_fd = -1;
    int pi = add_peer_captured(s, 0, &a, 6881, &cap_fd);
    ntx_session_peer_send_ext_handshake(s, pi);

    uint8_t wire[1024];
    size_t wn = 0;
    if (read_wire(cap_fd, wire, sizeof wire, &wn) != 0) fail("ext_hs_no_wire");
    if (wn < 6 || wire[4] != MSG_EXT || wire[5] != 0) fail("ext_hs_framing");

    uint8_t ids[8];
    const char *names[8];
    int n_ext = -1, msize = 0;
    if (ntx_ext_handshake_parse(wire + 6, wn - 6, ids, 8, names, &n_ext, &msize) != 0)
        fail("ext_hs_parse");
    if (n_ext <= 0) fail("ext_hs_n_ext");
    if (!name_seen(names, n_ext, NTX_EXT_NAME_UT_METADATA)) fail("ext_hs_no_metadata");
    if (msize != 4096) fail("ext_hs_metadata_size");
    if (priv) {
        if (name_seen(names, n_ext, NTX_EXT_NAME_UT_PEX)) fail("ext_hs_pex_offered");
        if (name_seen(names, n_ext, NTX_EXT_NAME_UT_HOLEPUNCH)) fail("ext_hs_holepunch_offered");
        if (n_ext != 1) fail("ext_hs_count");
    } else {
        if (!name_seen(names, n_ext, NTX_EXT_NAME_UT_PEX)) fail("ext_hs_public_pex");
        if (!name_seen(names, n_ext, NTX_EXT_NAME_UT_HOLEPUNCH)) fail("ext_hs_public_hp");
    }
    for (int i = 0; i < n_ext; i++) free((void *)names[i]);
    close(cap_fd);
    drop(s, n);
}

static void test_ext_handshake(void) {
    ext_hs_advertises(1);
    ext_hs_advertises(0);
    printf("PASS priv_ext_handshake\n");
}

/* §4.2: an inbound ut_pex naming 10.9.9.9 must not create a dial on a private
 * slot. The public control (loopback contact, so nothing leaves the host) must
 * still dial it. */
static void test_pex_rx(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0, 0);
    ntx_addr peer_a = lo4(1);
    ntx_addr pex_private = v4(10, 9, 9, 9);
    ntx_addr pex_public = lo4(9);

    for (int priv = 1; priv >= 0; priv--) {
        ntx_addr added = priv ? pex_private : pex_public;
        uint32_t a4[1];
        uint16_t ap4[1];
        a4[0] = added.u.v4;
        ap4[0] = DIAL_PORT;
        uint8_t payload[512];
        size_t pn = 0;
        if (ntx_pex_build_msg(payload, sizeof payload, &pn, a4, ap4, 1, NULL, NULL, 0,
                              NULL, NULL, 0, NULL, NULL, 0) != 0)
            fail("pex_build");

        ntx_netx *n;
        ntx_session *s = mk(&cfg, &n);
        s->tts[0].priv = (uint8_t)priv;
        int cap_fd = -1;
        int pi = add_peer_captured(s, 0, &peer_a, 6881, &cap_fd);
        s->peer_pex_id[pi] = NTX_EXT_LOCAL_PEX;
        ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_PEX, payload, pn);
        int imported = pi_of(s, &added, DIAL_PORT) >= 0;
        if (priv) {
            if (imported || live_peers(s) != 1) fail("pex_rx_private_imported");
            if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_PEX) != 0) fail("pex_rx_hook");
        } else {
            if (!imported || live_peers(s) != 2) fail("pex_rx_public_not_imported");
            if (pi_of(s, &pex_private, DIAL_PORT) >= 0) fail("pex_rx_public_hook_refused");
        }
        close(cap_fd);
        drop(s, n);
    }
    printf("PASS priv_pex_rx\n");
}

/* §4.2: PEX we would advertise to a peer of a private slot is never sent, even
 * when that peer negotiated ut_pex before the magnet turned private. */
static void test_pex_tx(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    s->tts[0].priv = 1;

    ntx_addr a = lo4(1), b = lo4(2);
    int cap_fd = -1;
    int pi = add_peer_captured(s, 0, &a, 6881, &cap_fd);
    s->peer_pex_id[pi] = NTX_EXT_LOCAL_PEX;
    ntx_pex_tx_on_connected(&s->pex_tx[0], &b, DIAL_PORT);
    s->peer_pex_last_ms[pi] = 0;
    s->tick_n = 600; /* opens the coarse ~60 s tick gate */
    ntx_session_data_pex_tick(s);
    if (live_peers(s) != 1) fail("pex_tx_private_dial");

    uint8_t wire[2048];
    size_t wn = 0;
    if (read_wire(cap_fd, wire, sizeof wire, &wn) == 0) fail("pex_tx_private_wire");
    close(cap_fd);
    drop(s, n);

    /* control: the same setup without `private` puts the pex message on the wire */
    ntx_netx *m;
    ntx_session *p = mk(&cfg, &m);
    int cap2 = -1;
    int pj = add_peer_captured(p, 0, &a, 6881, &cap2);
    p->peer_pex_id[pj] = NTX_EXT_LOCAL_PEX;
    ntx_pex_tx_on_connected(&p->pex_tx[0], &b, DIAL_PORT);
    p->peer_pex_last_ms[pj] = 0;
    p->tick_n = 600;
    ntx_session_data_pex_tick(p);
    if (read_wire(cap2, wire, sizeof wire, &wn) != 0) fail("pex_tx_public_no_wire");
    if (wn < 6 || wire[5] != NTX_EXT_LOCAL_PEX) fail("pex_tx_public_ext_id");
    close(cap2);
    drop(p, m);
    printf("PASS priv_pex_tx\n");
}

/* §4.3: a BEP55 connect on a private slot is ignored — hp_rx_connect stays 0
 * and no dial is launched. The public control counts it and dials. */
static void test_holepunch_rx(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0, 1);
    ntx_addr peer_a = lo4(1);
    ntx_holepunch_msg m;
    memset(&m, 0, sizeof m);
    m.msg_type = NTX_HP_MSG_CONNECT;
    m.addr_type = NTX_HP_AF_V4;
    m.port = 7777;

    for (int priv = 1; priv >= 0; priv--) {
        m.addr = priv ? v4(10, 9, 9, 9) : lo4(9);
        uint8_t pay[NTX_HP_WIRE_MAX];
        size_t pn = ntx_holepunch_build(pay, sizeof pay, &m);
        if (pn != NTX_HP_WIRE_V4) fail("hp_build");

        ntx_netx *n;
        ntx_session *s = mk(&cfg, &n);
        s->tts[0].priv = (uint8_t)priv;
        int cap_fd = -1;
        int pi = add_peer_captured(s, 0, &peer_a, 6881, &cap_fd);
        s->peer_holepunch_id[pi] = NTX_EXT_LOCAL_HOLEPUNCH;
        ntx_session_data_on_ext(s, pi, (int)NTX_EXT_LOCAL_HOLEPUNCH, pay, pn);
        if (priv) {
            if (s->hp_rx_connect != 0 || s->hp_dial_ok != 0 || s->hp_dial_fail != 0)
                fail("hp_rx_private_counted");
            if (live_peers(s) != 1) fail("hp_rx_private_dial");
        } else {
            if (s->hp_rx_connect != 1) fail("hp_rx_public_not_counted");
            if (live_peers(s) != 2) fail("hp_rx_public_not_dialled");
        }
        close(cap_fd);
        drop(s, n);
    }
    printf("PASS priv_holepunch_rx\n");
}

/* §4.4: only tracker-sourced addresses may be dialled on a private slot, and
 * the origin is recorded on the slot in every case. */
static void test_dial_src(void) {
    ntx_config cfg;
    cfg_base(&cfg, 0, 0);

    for (int priv = 1; priv >= 0; priv--) {
        ntx_addr trk_a = lo4(1), dht_a = lo4(2), pex_a = lo4(3), hp_a = lo4(4);
        if (priv) {
            /* Refused sources use non-loopback addresses: the point is that the
             * policy stops the dial before the socket layer is ever reached. */
            dht_a = v4(10, 2, 2, 2);
            pex_a = v4(10, 3, 3, 3);
            hp_a = v4(10, 4, 4, 4);
        }
        ntx_netx *n;
        ntx_session *s = mk(&cfg, &n);
        s->tts[0].priv = (uint8_t)priv;

        ntx_session_add_peer_from_tracker(s, 0, &trk_a, DIAL_PORT);
        int tpi = pi_of(s, &trk_a, DIAL_PORT);
        if (tpi < 0 || s->peer_src[tpi] != NTX_PSRC_TRACKER) fail("src_tracker");

        int r_dht = ntx_session_add_peer_src(s, 0, &dht_a, DIAL_PORT, NTX_PSRC_DHT);
        int r_pex = ntx_session_add_peer_src(s, 0, &pex_a, DIAL_PORT + 1, NTX_PSRC_PEX);
        int r_hp = ntx_session_add_peer_src(s, 0, &hp_a, DIAL_PORT + 2, NTX_PSRC_HOLEPUNCH);
        if (priv) {
            if (r_dht || r_pex || r_hp) fail("dial_src_private_allowed");
            if (live_peers(s) != 1) fail("dial_src_private_slot_leak");
        } else {
            if (!r_dht || !r_pex || !r_hp) fail("dial_src_public_refused");
            if (live_peers(s) != 4) fail("dial_src_public_count");
            int d = pi_of(s, &dht_a, DIAL_PORT), p = pi_of(s, &pex_a, DIAL_PORT + 1),
               h = pi_of(s, &hp_a, DIAL_PORT + 2);
            if (d < 0 || s->peer_src[d] != NTX_PSRC_DHT) fail("src_dht");
            if (p < 0 || s->peer_src[p] != NTX_PSRC_PEX) fail("src_pex");
            if (h < 0 || s->peer_src[h] != NTX_PSRC_HOLEPUNCH) fail("src_hp");
        }
        drop(s, n);
    }
    printf("PASS priv_dial_src\n");
}

/* §4.1 plus the hook contract: cfg.dht alone is not enough, and BEP 9 metadata
 * stays allowed on a private slot. */
static void test_dht_gate(void) {
    ntx_config cfg;
    cfg_base(&cfg, 1, 0);
    ntx_netx *n;
    ntx_session *s = mk(&cfg, &n);
    if (sp_dht_allowed(s, 0) != 1) fail("dht_public");
    s->tts[0].priv = 1;
    if (sp_dht_allowed(s, 0) != 0) fail("dht_private");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_PEX) != 0) fail("ext_pex_private");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_HOLEPUNCH) != 0) fail("ext_hp_private");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_METADATA) != 1) fail("ext_meta_private");
    if (sp_dial_allowed(s, 0, NTX_PSRC_TRACKER) != 1) fail("dial_trk_private");
    if (sp_dial_allowed(s, 0, NTX_PSRC_DHT) != 0) fail("dial_dht_private");
    if (sp_dial_allowed(s, 0, NTX_PSRC_PEX) != 0) fail("dial_pex_private");
    if (sp_dial_allowed(s, 0, NTX_PSRC_HOLEPUNCH) != 0) fail("dial_hp_private");
    if (sp_dial_allowed(s, 0, NTX_PSRC_INBOUND) != 0) fail("dial_in_private");
    if (sp_dial_allowed(s, 0, NTX_PSRC_NONE) != 0) fail("dial_none_private");
    drop(s, n);
    printf("PASS priv_policy\n");
}

/* ---- magnet -> private (§4.5) --------------------------------------------- */

#define PS 1024u
#define NP 1u

/* Single-piece v1 info dict; `priv` adds the `private` = 1 key. */
static size_t build_info(uint8_t *out, size_t cap, int priv, uint8_t hash_out[20]) {
    static uint8_t pat[PS];
    for (uint32_t i = 0; i < PS; i++) pat[i] = (uint8_t)(i * 7 + 3);
    uint8_t h0[20];
    ntx_sha1(pat, PS, h0);
    size_t o = (size_t)snprintf((char *)out, cap, "d12:piece lengthi%ue6:pieces%u:", PS, NP * 20u);
    memcpy(out + o, h0, 20);
    o += 20;
    o += (size_t)snprintf((char *)out + o, cap - o, "6:lengthi%ue4:name3:b27", PS * NP);
    if (priv) o += (size_t)snprintf((char *)out + o, cap - o, "7:privatei1e");
    o += (size_t)snprintf((char *)out + o, cap - o, "e");
    ntx_sha1(out, o, hash_out);
    return o;
}

static void test_magnet_to_private(void) {
    uint8_t info[512];
    uint8_t ih[20];
    size_t info_n = build_info(info, sizeof info, 1, ih);
    char url[256], hex[41];
    for (int i = 0; i < 20; i++) snprintf(hex + i * 2, 3, "%02x", ih[i]);
    snprintf(url, sizeof url, "magnet:?xt=urn:btih:%s&dn=b27&tr=udp://tr.example.com:6969", hex);

    ntx_config cfg;
    cfg_base(&cfg, 1, 0);
    ntx_netx *n = ntx_netx_init(&cfg);
    if (!n) fail("netx_init");
    ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) fail("session_init");
    if (ntx_session_add_magnet(s, url) != 0) fail("add_magnet");
    if (memcmp(s->tts[0].info_hash, ih, 20) != 0) fail("info_hash");
    if (s->tts[0].priv != 0) fail("priv_before_meta");

    /* Three peers while the privacy is still unknown: one tracker-dialled, one
     * DHT-dialled, one really accepted. */
    ntx_addr trk_a = lo4(1), dht_a = lo4(2);
    ntx_session_add_peer_from_tracker(s, 0, &trk_a, DIAL_PORT);
    int tpi = pi_of(s, &trk_a, DIAL_PORT);
    if (tpi < 0 || s->peer_src[tpi] != NTX_PSRC_TRACKER) fail("trk_peer");
    if (!ntx_session_add_peer_src(s, 0, &dht_a, DIAL_PORT, NTX_PSRC_DHT)) fail("dht_dial");
    int dpi = pi_of(s, &dht_a, DIAL_PORT);
    if (dpi < 0 || s->peer_src[dpi] != NTX_PSRC_DHT) fail("dht_peer");

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 4)) fail("listen");
    socklen_t sl = sizeof sa;
    if (getsockname(lfd, (struct sockaddr *)&sa, &sl)) fail("getsockname");
    int cl = socket(AF_INET, SOCK_STREAM, 0);
    if (connect(cl, (struct sockaddr *)&sa, sizeof sa)) fail("connect");
    int afd = accept(lfd, NULL, NULL);
    if (afd < 0) fail("accept");
    if (fcntl(afd, F_SETFL, O_NONBLOCK) < 0) fail("nonblock");
    ntx_session_accept_cb(s, n, afd, NULL);
    int api = -1;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd == afd) api = pi;
    if (api < 0) fail("accept_slot");
    if (s->peer_src[api] != NTX_PSRC_INBOUND) fail("inbound_src");
    s->peer_tts[api] = 0; /* what the BT-handshake hash match does for an accept */

    if (live_peers(s) != 3) fail("pre_transition_peers");
    if (sp_dht_allowed(s, 0) != 1) fail("pre_transition_dht");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_PEX) != 1) fail("pre_transition_pex");

    meta_buf[0] = malloc(info_n);
    if (!meta_buf[0]) fail("meta_buf");
    memcpy(meta_buf[0], info, info_n);
    meta_total[0] = (uint32_t)info_n;
    meta_assemble(s, 0);

    if (s->tts[0].priv != 1) fail("priv_flag");
    if (s->peers[tpi].fd == -1) fail("tracker_peer_closed");
    if (s->peer_src[tpi] != NTX_PSRC_TRACKER) fail("tracker_src_lost");
    if (s->peers[api].fd == -1) fail("inbound_peer_closed");
    if (s->peers[dpi].fd != -1) fail("dht_peer_still_open");
    if (sp_dht_allowed(s, 0) != 0) fail("post_transition_dht");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_PEX) != 0) fail("post_transition_pex");

    /* A late DHT answer for the now-private slot is dropped outright: no new
     * slot, and the closed one is not revived by the uTP TCP fallback. */
    ntx_dht_peer dp[1];
    dp[0].addr = dht_a;
    dp[0].port = DIAL_PORT;
    dht_peers_cb(ih, dp, 1, s);
    ntx_session_peer_hs_tick(s);
    if (pi_of(s, &dht_a, DIAL_PORT) >= 0) fail("dht_result_applied");

    close(cl);
    close(afd);
    close(lfd);
    drop(s, n);
    printf("PASS priv_magnet_to_private\n");
}

int main(void) {
    ntx_rng_init();
    scratch();
    test_ext_handshake();
    test_pex_rx();
    test_pex_tx();
    test_holepunch_rx();
    test_dial_src();
    test_dht_gate();
    test_magnet_to_private();
    return 0;
}
