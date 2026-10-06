#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
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

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int test_bep6_ignore(void) {
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    if (ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=t") != 0)
        return fail("magnet");
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, -1, &pa4, 1234, 0);
    if (pi < 0) return fail("alloc");
    s->peer_phase[pi] = PH_OK;
    s->peer_tts[pi] = 0;
    s->tts[0].state = NTX_TTS_DL;
    s->tts[0].have_meta = 1;
    s->tts[0].np = 1;
    s->peers[pi].phave = calloc(1, 1);
    s->peers[pi].phave_n = 1;

    static const struct {
        uint8_t type;
        const char *name;
    } msgs[] = {{13, "suggest"}, {16, "reject"}, {17, "allowed_fast"}};
    for (size_t i = 0; i < sizeof msgs / sizeof msgs[0]; i++) {
        uint8_t m[9];
        m[0] = 0;
        m[1] = 0;
        m[2] = 0;
        m[3] = 5;
        m[4] = msgs[i].type;
        m[5] = m[6] = m[7] = m[8] = 0;
        memcpy(s->peer_buf[pi], m, 9);
        s->peer_buflen[pi] = 9;
        ntx_session_peer_process_inbuf(s, pi);
        if (s->peer_phase[pi] == PH_OK && s->peer_buflen[pi] == 0) {
            printf("PASS msg_%s\n", msgs[i].name);
        } else {
            return fail(msgs[i].name);
        }
    }
    ntx_session_free(s);
    ntx_netx_free(n);
    return 0;
}

static int test_coalesced_ka_piece(void) {
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    if (ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=t") != 0)
        return fail("magnet");
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, -1, &pa4, 1234, 0);
    if (pi < 0) return fail("alloc");
    s->peer_phase[pi] = PH_OK;
    s->peer_tts[pi] = 0;
    s->tts[0].state = NTX_TTS_DL;
    s->tts[0].have_meta = 1;
    s->tts[0].np = 1;
    s->peers[pi].phave = calloc(1, 1);
    s->peers[pi].phave_n = 1;

    uint8_t *b = s->peer_buf[pi];
    size_t bl = 0;
    b[0] = b[1] = b[2] = b[3] = 0;
    bl = 4;
    b[4] = 0;
    b[5] = 0;
    b[6] = 0;
    b[7] = 1;
    b[8] = 0;
    bl = 9;
    s->peer_buflen[pi] = bl;
    ntx_session_peer_process_inbuf(s, pi);
    if (s->peer_phase[pi] != PH_OK || s->peer_buflen[pi] != 0) return fail("coalesced");
    printf("PASS coalesced_ka_piece\n");
    ntx_session_free(s);
    ntx_netx_free(n);
    return 0;
}

static int test_interest_after_bitfield(void) {
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    if (ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=t") != 0)
        return fail("magnet");
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, -1, &pa4, 1234, 0);
    if (pi < 0) return fail("alloc");
    s->peer_phase[pi] = PH_OK;
    s->peer_tts[pi] = 0;
    s->tts[0].state = NTX_TTS_DL;
    s->tts[0].have_meta = 1;
    s->tts[0].np = 8;
    s->tts[0].ps = 16384;
    s->tts[0].size = 8 * 16384ULL;
    s->tts[0].phash = calloc(8 * 20, 1);
    s->tts[0].have = calloc(8, 1);
    s->tts[0].rarity = calloc(8, sizeof(uint32_t));
    s->tts[0].store.ps = 16384;
    s->tts[0].store.size = 8 * 16384ULL;
    s->peers[pi].phave = calloc(8, 1);
    s->peers[pi].phave_n = 8;
    ntx_peer_set_we_int(&s->peers[pi], 1);

    uint8_t none[5] = {0, 0, 0, 1, 0x0f};
    memcpy(s->peer_buf[pi], none, 5);
    s->peer_buflen[pi] = 5;
    ntx_session_peer_process_inbuf(s, pi);
    ntx_session_data_refill(s, 0);
    if (s->peers[pi].we_int) return fail("interest_after_have_none");

    uint8_t bf[6] = {0, 0, 0, 2, 5, 0x80};
    memcpy(s->peer_buf[pi], bf, 6);
    s->peer_buflen[pi] = 6;
    ntx_session_peer_process_inbuf(s, pi);
    ntx_session_data_refill(s, 0);

    if (!s->peers[pi].we_int) return fail("interest_not_restored");
    if (!ntx_peer_has(&s->peers[pi], 0)) return fail("bitfield_not_applied");
    printf("PASS interest_after_bitfield\n");
    free(s->tts[0].phash);
    free(s->tts[0].have);
    free(s->tts[0].rarity);
    ntx_session_free(s);
    ntx_netx_free(n);
    return 0;
}

int main(void) {
    ntx_rng_init();
    if (test_bep6_ignore() != 0) return 1;
    if (test_coalesced_ka_piece() != 0) return 1;
    return test_interest_after_bitfield();
}
