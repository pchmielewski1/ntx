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

#define PS 32768U

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

int main(void) {
    ntx_rng_init();
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
    ninfo += snprintf((char *)info + ninfo, sizeof(info) - ninfo, "6:lengthi%ue4:name4:teste", PS);

    uint8_t ih[20];
    ntx_sha1(info, (size_t)ninfo, ih);

    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    if (ntx_torrent_set_metainfo(&s->tts[0], info, (size_t)ninfo, "downloads", NULL) != 0) {
        ntx_session_free(s);
        ntx_netx_free(n);
        return fail("metainfo");
    }
    ntx_session_on_metainfo(s, 0);

    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, -1, &pa4, 6881, 0);
    if (pi < 0) return fail("alloc");
    s->peers[pi].fd = 1;
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    ntx_peer_set_phave(&s->peers[pi], 0, 1);
    ntx_peer_set_choke_us(&s->peers[pi], 0);
    ntx_peer_set_we_int(&s->peers[pi], 1);
    s->tts[0].rarity[0] = 1;

    /* Half piece — no verify yet (block bitmap, not high-water). */
    ntx_session_data_on_piece(s, pi, 0, 0, pat, 16384);
    if (s->tts[0].have[0]) {
        ntx_session_free(s);
        ntx_netx_free(n);
        return fail("early_verify");
    }

    /* Endgame: finish remaining block → verified. */
    ntx_session_data_on_piece(s, pi, 0, 16384, pat + 16384, PS - 16384);
    if (!s->tts[0].have[0] || s->tts[0].have_n != 1) {
        ntx_session_free(s);
        ntx_netx_free(n);
        return fail("endgame_verify");
    }

    unlink("downloads/test");
    printf("PASS session_endgame\n");
    s->peers[pi].fd = -1;
    ntx_session_free(s);
    ntx_netx_free(n);
    return 0;
}
