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

/* A SYN that gets no answer within a couple of seconds almost never will (in a live swarm ~99% of dials time
 * out).  While the session has too few working peers it gives up on a pending connect after 2.5 s instead of
 * 5 s so the slot is reused sooner; once enough peers work, slow links get the full 5 s. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static ntx_addr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    ntx_addr x;
    ntx_addr_set_v4(&x, htonl(((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d));
    return x;
}

static int slot_alive(const ntx_session *s, const ntx_addr *a, uint16_t port) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1 && s->peers[pi].port == port && ntx_addr_eq(&s->peers[pi].addr, a)) return pi;
    return -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&la, sizeof la) != 0 || listen(lfd, 64) != 0) return fail("listen");
    socklen_t ll = sizeof la;
    getsockname(lfd, (struct sockaddr *)&la, &ll);
    ntx_config cfg = {0};
    cfg.max_peers = 50;
    cfg.proxy = 1;
    cfg.proxy_host = "127.0.0.1";
    cfg.proxy_port = ntohs(la.sin_port);
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20] = {7};
    ntx_torrent_init_meta(&s->tts[0], ih);
    s->tts[0].state = NTX_TTS_DL;
    s->n_tts = 1;

    ntx_addr x = v4(8, 8, 4, 4);
    if (!ntx_session_add_peer_dial(s, 0, &x, 6881)) return fail("dial");
    int pi = slot_alive(s, &x, 6881);
    if (pi < 0) return fail("slot");
    s->peers[pi].conn_t0 = ntx_mono_ms() - 3000; /* 3 s of silence */
    ntx_session_peer_hs_tick(s);
    if (slot_alive(s, &x, 6881) >= 0) return fail("few_peers_gives_up_after_3s");
    printf("PASS conn_timeout_fast_when_starved\n");

    /* three working peers: the full 5 s applies */
    int sv[NTX_MIN_OK_PEERS][2];
    for (int k = 0; k < NTX_MIN_OK_PEERS; k++) {
        if (socketpair(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0, sv[k]) != 0) return fail("socketpair");
        ntx_addr pa = v4(9, 9, 9, (uint8_t)(1 + k));
        int q = ntx_session_peer_alloc(s, sv[k][0], &pa, 6881, 0);
        if (q < 0) return fail("alloc");
        s->peers[q].fd = sv[k][0];
        s->peer_phase[q] = PH_OK;
        s->peer_plain[q] = 1;
        s->peers[q].hs_t0 = ntx_mono_ms();
    }
    ntx_dial_bo_ok(&s->dial_bo, &x, 6881);
    if (!ntx_session_add_peer_dial(s, 0, &x, 6881)) return fail("dial2");
    pi = slot_alive(s, &x, 6881);
    s->peers[pi].conn_t0 = ntx_mono_ms() - 3000;
    ntx_session_peer_hs_tick(s);
    if (slot_alive(s, &x, 6881) < 0) return fail("enough_peers_keeps_waiting_at_3s");
    s->peers[pi].conn_t0 = ntx_mono_ms() - 5200;
    ntx_session_peer_hs_tick(s);
    if (slot_alive(s, &x, 6881) >= 0) return fail("gives_up_after_5s");
    printf("PASS conn_timeout_full_when_healthy\n");

    ntx_session_free(s);
    ntx_netx_free(n);
    close(lfd);
    printf("ALL PASS\n");
    return 0;
}
