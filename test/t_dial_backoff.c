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

/* Redial back-off: an address whose outbound attempt just failed is not dialled again straight away, so the
 * limited handshake slots go to fresh candidates instead of the same dead ones announce after announce. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static ntx_addr v4(uint8_t a, uint8_t b, uint8_t c, uint8_t d) {
    ntx_addr x;
    ntx_addr_set_v4(&x, htonl(((uint32_t)a << 24) | ((uint32_t)b << 16) | ((uint32_t)c << 8) | d));
    return x;
}

static int pi_of(const ntx_session *s, const ntx_addr *a, uint16_t port) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1 && s->peers[pi].port == port && ntx_addr_eq(&s->peers[pi].addr, a)) return pi;
    return -1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();

    /* --- pure data structure ------------------------------------------------------------------ */
    {
        static ntx_dial_bo b;
        ntx_addr a = v4(9, 9, 9, 9), o = v4(9, 9, 9, 10);
        if (ntx_dial_bo_blocked(&b, &a, 6881, 1000)) return fail("fresh_not_blocked");
        ntx_dial_bo_fail(&b, &a, 6881, 1000);
        if (!ntx_dial_bo_blocked(&b, &a, 6881, 1000 + NTX_DIAL_BO_BASE_MS - 1)) return fail("blocked_for_base");
        if (ntx_dial_bo_blocked(&b, &a, 6881, 1000 + NTX_DIAL_BO_BASE_MS)) return fail("unblocked_after_base");
        if (ntx_dial_bo_blocked(&b, &a, 6882, 1000)) return fail("other_port_not_blocked");
        if (ntx_dial_bo_blocked(&b, &o, 6881, 1000)) return fail("other_addr_not_blocked");
        ntx_dial_bo_fail(&b, &a, 6881, 100000);
        if (!ntx_dial_bo_blocked(&b, &a, 6881, 100000 + 2 * NTX_DIAL_BO_BASE_MS - 1)) return fail("doubles");
        if (ntx_dial_bo_blocked(&b, &a, 6881, 100000 + 2 * NTX_DIAL_BO_BASE_MS)) return fail("doubles_ends");
        for (int i = 0; i < 40; i++) ntx_dial_bo_fail(&b, &a, 6881, 0);
        if (ntx_dial_bo_blocked(&b, &a, 6881, NTX_DIAL_BO_MAX_MS)) return fail("capped_at_max");
        ntx_dial_bo_ok(&b, &a, 6881);
        if (ntx_dial_bo_blocked(&b, &a, 6881, 1)) return fail("ok_forgets");
        /* full table: new failures still get a slot (the entry that expires first is replaced) */
        for (int i = 0; i < NTX_DIAL_BO_N + 50; i++) {
            ntx_addr x = v4(10, 1, (uint8_t)(i >> 8), (uint8_t)i);
            ntx_dial_bo_fail(&b, &x, 6881, 1000 + (uint64_t)i);
        }
        ntx_addr last = v4(10, 1, (uint8_t)((NTX_DIAL_BO_N + 49) >> 8), (uint8_t)(NTX_DIAL_BO_N + 49));
        if (!ntx_dial_bo_blocked(&b, &last, 6881, 2000)) return fail("full_table_keeps_newest");
        printf("PASS dial_bo_struct\n");
    }

    /* --- session integration (dials go to a loopback listener posing as a SOCKS5 proxy) -------- */
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

    ntx_addr x = v4(8, 8, 4, 4), y = v4(8, 8, 8, 8);
    if (!ntx_session_add_peer_dial(s, 0, &x, 6881)) return fail("first_dial");
    int pi = pi_of(s, &x, 6881);
    if (pi < 0) return fail("slot_for_x");
    sp_drop(s, pi, "conn_timeout");
    if (ntx_session_add_peer_dial(s, 0, &x, 6881)) return fail("redial_after_failure_is_blocked");
    if (!ntx_session_add_peer_dial(s, 0, &y, 6881)) return fail("other_address_still_dialled");
    if (!ntx_session_add_peer_dial_ex(s, 0, &x, 6881, 1)) return fail("forced_dial_bypasses_backoff");
    printf("PASS dial_backoff_blocks_redial\n");

    /* once the block has run out the address is dialled again */
    pi = pi_of(s, &x, 6881);
    sp_drop(s, pi, "hs_timeout");
    ntx_dial_bo_ent *e = ntx_dial_bo_find(&s->dial_bo, &x, 6881);
    if (!e) return fail("failure_recorded");
    e->until = 1; /* long past */
    if (!ntx_session_add_peer_dial(s, 0, &x, 6881)) return fail("redial_after_expiry");
    printf("PASS dial_backoff_expires\n");

    /* a peer that reached OK and later leaves is not penalised */
    pi = pi_of(s, &x, 6881);
    s->peer_phase[pi] = PH_OK;
    sp_drop(s, pi, "eof");
    if (ntx_dial_bo_find(&s->dial_bo, &x, 6881)) return fail("ok_peer_leaves_cleanly");
    if (!ntx_session_add_peer_dial(s, 0, &x, 6881)) return fail("redial_of_good_peer");
    printf("PASS dial_backoff_good_peer\n");

    ntx_session_free(s);
    ntx_netx_free(n);
    close(lfd);
    printf("ALL PASS\n");
    return 0;
}
