/* These checks age timestamps by subtracting from the monotonic clock, which counts from boot: offset it so a freshly started host cannot underflow. */
#define NTX_MONO_BASE_MS 86400000LL
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
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

/* split-out module sources, included directly */
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

#include <netinet/in.h>

static void nb(int fd) { fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK); }

/* Security audit: connection-level resource limits.
 *  - an established peer that goes silent is dropped (it used to hold a slot forever)
 *  - one source address cannot fill the peer table with inbound connections
 *  - REQUESTs are not served (no disk read, no accounting) while the peer is not draining its output */

#define PS 32768U

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int live_from(const ntx_session *s, const ntx_addr *a) {
    int n = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1 && ntx_addr_eq(&s->peers[pi].addr, a)) n++;
    return n;
}

static int test_idle(void) {
    ntx_config cfg = {0};
    cfg.allow_local_peers = 1;
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20] = {7};
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    ntx_addr a;
    ntx_addr_set_v4(&a, htonl(0x7f000001));
    int sv1[2], sv2[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) || socketpair(AF_UNIX, SOCK_STREAM, 0, sv2)) return fail("socketpair");
    nb(sv1[0]);
    nb(sv2[0]);
    int silent = ntx_session_peer_alloc(s, sv1[0], &a, 1111, 0);
    int active = ntx_session_peer_alloc(s, sv2[0], &a, 2222, 0);
    if (silent < 0 || active < 0) return fail("alloc");
    uint64_t now = ntx_mono_ms();
    for (int k = 0; k < 2; k++) {
        int pi = k ? active : silent;
        s->peer_phase[pi] = PH_OK;
        s->peer_plain[pi] = 1;
        s->peer_hello_sent[pi] = 1;
        s->peers[pi].hs_t0 = now - (uint64_t)(NTX_PEER_IDLE_TIMEOUT_S + 60) * 1000u;
    }
    s->peers[active].rx_t0 = now; /* heard from it just now */
    ntx_session_peer_hs_tick(s);
    if (s->peers[silent].fd != -1) return fail("silent_peer_kept");
    if (s->peers[active].fd == -1) return fail("active_peer_dropped");
    ntx_session_free(s);
    ntx_netx_free(n);
    close(sv1[1]);
    close(sv2[1]);
    printf("PASS idle_peer_dropped\n");
    return 0;
}

static int test_per_ip(void) {
    ntx_config cfg = {0};
    cfg.allow_local_peers = 1;
    cfg.max_peers = 100;
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) || listen(lfd, 64)) return fail("listen");
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    int cl[40];
    for (int i = 0; i < 40; i++) {
        cl[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (connect(cl[i], (struct sockaddr *)&sa, sizeof sa)) return fail("connect");
        int fd = accept(lfd, NULL, NULL);
        if (fd < 0) return fail("accept");
        nb(fd);
        ntx_session_accept_cb(s, n, fd, NULL);
    }
    ntx_addr lo;
    ntx_addr_set_v4(&lo, htonl(0x7f000001));
    int live = live_from(s, &lo);
    if (live <= 0 || live > NTX_PEER_MAX_PER_ADDR) return fail("per_addr_cap");
    ntx_session_free(s);
    ntx_netx_free(n);
    for (int i = 0; i < 40; i++) close(cl[i]);
    close(lfd);
    printf("PASS per_addr_cap\n");
    return 0;
}

static int test_request_backpressure(void) {
    unlink("downloads/test");
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    static uint8_t pat[PS];
    for (uint32_t i = 0; i < PS; i++) pat[i] = (uint8_t)(i * 11 + 7);
    uint8_t h0[20];
    ntx_sha1(pat, PS, h0);
    static uint8_t info[256];
    int ninfo = snprintf((char *)info, sizeof(info), "d12:piece lengthi%ue6:pieces20:", PS);
    memcpy(info + ninfo, h0, 20);
    ninfo += 20;
    ninfo += snprintf((char *)info + ninfo, sizeof(info) - (size_t)ninfo, "6:lengthi%ue4:name4:teste", PS);
    uint8_t ih[20];
    ntx_sha1(info, (size_t)ninfo, ih);
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    if (ntx_torrent_set_metainfo(&s->tts[0], info, (size_t)ninfo, "downloads", NULL) != 0) return fail("metainfo");
    ntx_session_on_metainfo(s, 0);
    ntx_torrent *t = &s->tts[0];
    if (ntx_store_write(&t->store, 0, 0, pat, PS) != 0) return fail("seed_write");
    t->have[0] = 1;
    t->have_n = 1;
    ntx_addr a;
    ntx_addr_set_v4(&a, htonl(0x7f000001));
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv)) return fail("socketpair");
    nb(sv[0]);
    int pi = ntx_session_peer_alloc(s, sv[0], &a, 3333, 0);
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    ntx_peer_set_we_choke(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 1);

    /* sanity: with an empty output queue a request is served */
    ntx_session_data_on_request(s, pi, 0, 0, 16384);
    if (s->up_total != 16384) return fail("request_not_served");

    /* the peer is not reading: its queue is (nearly) full -> do not read the disk / count upload */
    if (!s->peer_out[pi]) s->peer_out[pi] = malloc(NTX_PEER_OUTBUF);
    s->peer_out_off[pi] = 0;
    s->peer_out_len[pi] = NTX_PEER_OUTBUF - 100;
    uint64_t before = s->up_total;
    for (int i = 0; i < 100; i++) ntx_session_data_on_request(s, pi, 0, 0, 16384);
    if (s->up_total != before) return fail("served_into_full_queue");
    ntx_session_free(s);
    ntx_netx_free(n);
    close(sv[1]);
    unlink("downloads/test");
    printf("PASS request_backpressure\n");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    if (test_idle()) return 1;
    if (test_per_ip()) return 1;
    if (test_request_backpressure()) return 1;
    return 0;
}
