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

/* An HTTP tracker may return compact "peers" (v4) and "peers6" in one reply.  The session used to walk
 * the v4 arrays up to the TOTAL peer count (v4 + v6), reading stack bytes the parser never wrote and
 * dialling whatever they happened to contain. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

/* leave recognisable garbage where the callee's stack frame will be */
__attribute__((noinline)) static void poison_stack(void) {
    volatile uint8_t junk[32768];
    for (size_t i = 0; i < sizeof junk; i++) junk[i] = 0xAA;
}

static int count_peers(const ntx_session *s, int ti) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_tts[pi] == ti && s->peers[pi].fd != -1) c++;
    return c;
}

static int has_addr_v4(const ntx_session *s, int ti, uint32_t ip_net) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_tts[pi] == ti && s->peers[pi].fd != -1 && ntx_addr_is_v4(&s->peers[pi].addr) &&
            s->peers[pi].addr.u.v4 == ip_net)
            return 1;
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    /* Dial through a SOCKS5 "proxy" that is just a listening socket on loopback: the peers show up
     * in the session, but no packet ever leaves the machine. */
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&la, sizeof la) != 0 || listen(lfd, 16) != 0) return fail("listen");
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
    s->tts[0].state = NTX_TTS_META;
    s->n_tts = 1;
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "http://tracker.test/announce");

    /* d8:intervali1800e5:peers6:<1 v4 peer>6:peers618:<1 v6 peer>e */
    uint8_t body[128];
    size_t o = 0;
    o += (size_t)sprintf((char *)body + o, "d8:intervali1800e5:peers6:");
    const uint8_t v4[6] = {8, 8, 4, 4, 0x1A, 0xE1}; /* 8.8.4.4:6881 */
    memcpy(body + o, v4, 6); o += 6;
    o += (size_t)sprintf((char *)body + o, "6:peers618:");
    const uint8_t v6[18] = {0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0x88, 0x88, 0x1A, 0xE2};
    memcpy(body + o, v6, 18); o += 18;
    body[o++] = 'e';

    poison_stack();
    trk_http_apply(s, 0, 0, s->trk_urls[0][0], body, o);

    if (!has_addr_v4(s, 0, htonl(0x08080404u))) return fail("real_v4_peer_missing");
    int c = count_peers(s, 0);
    if (c != 2) {
        printf("peers=%d\n", c);
        return fail("only_the_two_real_peers");
    }
    if (has_addr_v4(s, 0, 0xAAAAAAAAu)) return fail("garbage_peer_dialled");
    printf("PASS http_mixed_peers\n");

    ntx_session_free(s);
    ntx_netx_free(n);

    /* A reply may carry far more than 64 peers now that we ask for 200: every one of them is used. */
    cfg.max_peers = 128;
    n = ntx_netx_init(&cfg);
    s = ntx_session_init(n, &cfg);
    ntx_torrent_init_meta(&s->tts[0], ih);
    s->tts[0].state = NTX_TTS_META;
    s->n_tts = 1;
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "http://tracker.test/announce");
    static uint8_t big[1024];
    o = (size_t)sprintf((char *)big, "d8:intervali1800e5:peers%d:", 90 * 6);
    for (int k = 0; k < 90; k++) {
        const uint8_t pr[6] = {9, 9, (uint8_t)(1 + k / 200), (uint8_t)(1 + k), 0x1A, 0xE1};
        memcpy(big + o, pr, 6);
        o += 6;
    }
    big[o++] = 'e';
    trk_http_apply(s, 0, 0, s->trk_urls[0][0], big, o);
    c = count_peers(s, 0);
    if (c != 90) {
        printf("peers=%d\n", c);
        return fail("all_90_peers_used");
    }
    printf("PASS http_many_peers\n");
    ntx_session_free(s);
    ntx_netx_free(n);
    close(lfd);
    printf("ALL PASS\n");
    return 0;
}
