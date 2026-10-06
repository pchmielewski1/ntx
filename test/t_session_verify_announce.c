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

/* A torrent resumed from a paused verification must announce `started` like one whose verification ran to
 * the end. A torrent that is already complete on disk deliberately sends no tracker announce (see t3d). */

static int fails;
static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails++;
}

static int announced(const ntx_session *s) {
    return s->trk_udp_pending[0][0] || s->trk_http_pending[0][0];
}

int main(void) {
    ntx_rng_init();
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20] = {7};
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    snprintf(s->trk_urls[0][0], sizeof s->trk_urls[0][0], "udp://127.0.0.1:9");
    s->trk_n[0] = 1;

    /* verification found every piece: DONE */
    s->tts[0].state = NTX_TTS_DONE;
    ntx_session_tts_verify_done(s, 0);
    check(!announced(s), "complete_torrent_sends_no_announce");
    s->trk_udp_pending[0][0] = 0;

    /* verification found missing pieces: DL */
    s->tts[0].state = NTX_TTS_DL;
    ntx_session_tts_verify_done(s, 0);
    check(announced(s), "incomplete_torrent_announces_started");
    s->trk_udp_pending[0][0] = 0;

    /* paused during verification, resumed with pieces missing: goes straight to DL, still announces */
    s->tts[0].state = NTX_TTS_VERIFY;
    s->tts[0].np = 4;
    s->tts[0].have_n = 1;
    ntx_session_set_paused(s, 0, 1);
    ntx_session_set_paused(s, 0, 0);
    check(s->tts[0].state == NTX_TTS_DL, "resume_goes_to_dl");
    check(announced(s), "resume_from_verify_announces_started");

    printf(fails ? "FAIL session_verify_announce\n" : "PASS session_verify_announce\n");
    return fails ? 1 : 0;
}
