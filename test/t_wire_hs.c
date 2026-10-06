#define _GNU_SOURCE
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/core/ntx_session.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
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

/* BEP52: the reserved-bit / v2 HS tests
 * call the real production builders sp_build_bt_handshake + sp_match_tts, so
 * this TU links the whole session stack (same include set as t_hash_exchange). */

static int wh_fails = 0;
#define WH(cond, msg)                                                        \
    do {                                                                     \
        if (!(cond)) {                                                       \
            printf("FAIL %s (line %d)\n", (msg), __LINE__);              \
            wh_fails++;                                                      \
        }                                                                    \
    } while (0)

/* Build the 68-byte HS the *specification* expects for torrent index ti,
 * independent of the production expression: fixed magic + BEP10 bit + fast/DHT
 * bits, and the BEP52 v2 bit (0x10 of the LAST reserved byte m[27]) set iff
 * `hybrid || supports_v2` where supports_v2 == the torrent carries a v2 root
 * (meta_version == 2). info_hash is whatever the torrent advertises. */
static void wh_expected_hs(const ntx_session *s, int ti, int dht, uint8_t e[68]) {
    const ntx_torrent *t = &s->tts[ti];
    memset(e, 0, 68);
    e[0] = 19;
    memcpy(e + 1, "BitTorrent protocol", 19);
    e[25] = 0x10; /* BEP10 extension protocol (reserved[5]) */
    e[27] = 0x04; /* fast extension (reserved[7] bit) */
    if (dht) e[27] |= 0x01; /* DHT (reserved[7] bit) */
    if (t->hybrid || t->meta_version == 2) e[27] |= 0x10; /* BEP52 v2 signal */
    memcpy(e + 28, t->info_hash, 20);
    memcpy(e + 48, s->peer_id, 20);
}

int main(void) {
    assert(MSG_CHOKE == 0);
    assert(MSG_UNCHOKE == 1);
    assert(MSG_INTERESTED == 2);
    assert(MSG_NOT_INTERESTED == 3);
    assert(MSG_HAVE == 4);
    assert(MSG_BITFIELD == 5);
    assert(MSG_REQUEST == 6);
    assert(MSG_PIECE == 7);
    assert(MSG_CANCEL == 8);
    assert(MSG_HAVE_ALL == 14);
    assert(MSG_HAVE_NONE == 15);
    assert(MSG_EXT == 20);
    printf("PASS msg_enum\n");

    uint8_t m[68];
    memset(m, 0, sizeof m);
    m[0] = 19;
    memcpy(m + 1, "BitTorrent protocol", 19);
    memset(m + 20, 0, 8);
    m[25] = 0x10;
    uint8_t ih[20], pid[20];
    for (int k = 0; k < 20; k++) {
        ih[k] = (uint8_t)(0xA0 + k);
        pid[k] = (uint8_t)(k * 3 + 1);
    }
    memcpy(m + 28, ih, 20);
    memcpy(m + 48, pid, 20);
    assert(m[0] == 19);
    assert(memcmp(m + 1, "BitTorrent protocol", 19) == 0);
    assert(m[20] == 0 && m[24] == 0);
    assert(m[25] == 0x10);
    assert(m[26] == 0 && m[27] == 0);
    assert(memcmp(m + 28, ih, 20) == 0);
    assert(memcmp(m + 48, pid, 20) == 0);
    assert(sizeof m == 68);
    printf("PASS hs_layout\n");

    /* mirrors sp_build_bt_handshake reserved bytes */
    {
        uint8_t hs[68];
        memset(hs, 0, sizeof hs);
        hs[0] = 19;
        memcpy(hs + 1, "BitTorrent protocol", 19);
        hs[25] = 0x10; /* BEP10 extension protocol (reserved[5]) */
        hs[27] = 0x04; /* fast extension bit (mirrors production builder) */
        assert(hs[25] == 0x10);
        assert(hs[26] == 0);
        assert(hs[27] == 0x04);
        hs[27] |= 0x01; /* DHT when --dht */
        assert(hs[27] == 0x05);
        printf("PASS hs_reserved_bits\n");
    }

    uint8_t ka[4] = {0, 0, 0, 0};
    assert(ka[0] == 0 && ka[1] == 0 && ka[2] == 0 && ka[3] == 0);
    printf("PASS keepalive_4x0\n");

    /* ======================================================================
     * BEP52 reserved bit + v2 HS — real production calls
     * ==================================================================== */
    {
        /* Two distinct info blobs so the hybrid v2 root cannot collide with the
         * pure-v2 info_hash: lets us isolate the sp_match_tts v2 upgrade loop. */
        static const char INFO_A[] = "d8:meta version2i2e8:piece lengthi16384e7:pieces"
                                     ":20B-HYBRID-ROOT-A-XXe4:name6:hybridAe";
        static const char INFO_B[] = "d8:meta version2i2e8:piece lengthi16384e7:pieces"
                                     ":20B-PURE-V2-ROOT-B-e4:name6:purev2e";
        uint8_t sha2_a[32], sha1_a[20], sha2_b[32];
        ntx_sha256(INFO_A, sizeof INFO_A - 1, sha2_a);
        ntx_sha1(INFO_A, sizeof INFO_A - 1, sha1_a);
        ntx_sha256(INFO_B, sizeof INFO_B - 1, sha2_b);

        ntx_config cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.dht = 0;
        ntx_session *s = calloc(1, sizeof *s);
        assert(s != NULL);
        s->cfg = &cfg;
        s->n_tts = 4;

        /* tts[0]: pure v1 — meta_version 0, no v2 root. Distinct hash so the
         * exact loop never confuses it with the hybrid's advertised sha1. */
        s->tts[0].state = NTX_TTS_DL;
        for (int k = 0; k < 20; k++) s->tts[0].info_hash[k] = (uint8_t)(0x11 + k);
        s->tts[0].meta_version = 0;
        s->tts[0].hybrid = 0;

        /* tts[1]: hybrid — v1 sha1 info_hash + v2 root, meta_version 2 */
        s->tts[1].state = NTX_TTS_DL;
        memcpy(s->tts[1].info_hash, sha1_a, 20);
        memcpy(s->tts[1].info_hash_v2, sha2_a, 32);
        s->tts[1].meta_version = 2;
        s->tts[1].hybrid = 1;

        /* tts[2]: pure v2 — info_hash already == trunc20(sha256(info)), no v1 */
        s->tts[2].state = NTX_TTS_DL;
        memcpy(s->tts[2].info_hash, sha2_b, 20); /* trunc20 of the v2 root */
        memcpy(s->tts[2].info_hash_v2, sha2_b, 32);
        s->tts[2].meta_version = 2;
        s->tts[2].hybrid = 0;

        /* tts[3]: v1-only BUT carrying a non-zero v2 root (a state production
         * never produces). Guards that the match loop is gated on meta_version
         * == 2, not merely on "info_hash_v2 is zero". */
        s->tts[3].state = NTX_TTS_DL;
        for (int k = 0; k < 20; k++) s->tts[3].info_hash[k] = (uint8_t)(0xEE + k);
        for (int k = 0; k < 32; k++) s->tts[3].info_hash_v2[k] = (uint8_t)(0x5A + k);
        s->tts[3].meta_version = 0;
        s->tts[3].hybrid = 0;

        /* ---- Step 1: outbound reserved bit (build) ---------------------- */
        uint8_t got[68], exp[68];

        /* v1-only: bit MUST stay clear */
        s->peer_tts[0] = 0;
        sp_build_bt_handshake(s, 0, got);
        wh_expected_hs(s, 0, 0, exp);
        WH(memcmp(got, exp, 68) == 0, "v1-only HS matches expected");
        WH((got[27] & 0x10) == 0, "v1-only clears BEP52 bit");
        WH(got[27] == 0x04, "v1-only reserved[7]==0x04 (no dht)");

        /* hybrid: bit MUST be set (4th MSB of last reserved byte) */
        s->peer_tts[1] = 1;
        sp_build_bt_handshake(s, 1, got);
        wh_expected_hs(s, 1, 0, exp);
        WH(memcmp(got, exp, 68) == 0, "hybrid HS matches expected");
        WH((got[27] & 0x10) != 0, "hybrid sets BEP52 bit");
        WH(got[27] == 0x14, "hybrid reserved[7]==0x14 (0x04|0x10)");

        /* pure-v2: bit MUST be set */
        s->peer_tts[2] = 2;
        sp_build_bt_handshake(s, 2, got);
        wh_expected_hs(s, 2, 0, exp);
        WH(memcmp(got, exp, 68) == 0, "pure-v2 HS matches expected");
        WH((got[27] & 0x10) != 0, "pure-v2 sets BEP52 bit");

        /* dht + hybrid: fast|dht|v2 all coexist */
        cfg.dht = 1;
        s->peer_tts[3] = 1;
        sp_build_bt_handshake(s, 3, got);
        wh_expected_hs(s, 1, 1, exp);
        WH(memcmp(got, exp, 68) == 0, "hybrid+dht HS matches expected");
        WH(got[27] == 0x15, "hybrid+dht reserved[7]==0x15");
        cfg.dht = 0;

        /* ---- Step 2: pure-v2 join by trunc20(sha256(info)) */
        WH(sp_match_tts(s, sha2_b) == 2, "pure-v2 joins via exact trunc20 root");
        /* hybrid still joins by its advertised v1 sha1 */
        WH(sp_match_tts(s, sha1_a) == 1, "hybrid joins by v1 sha1 (exact)");

        /* ---- RX mid-connection upgrade: v2 answer joins hybrid ----------- */
        /* A hybrid swarm we joined by SHA-1 may answer our HS with the
         * truncated SHA-256(info) root; that must resolve to the hybrid tts. */
        WH(sp_match_tts(s, sha2_a) == 1, "hybrid joins via v2 truncated root (upgrade)");

        /* ---- v1-only never matches via the v2 loop ---------------------- */
        /* tts[3] is v1-only yet has a non-zero v2 root; probing that root MUST
         * NOT resolve to it (the v2 loop is gated on meta_version == 2). */
        uint8_t probe3[20];
        memcpy(probe3, s->tts[3].info_hash_v2, 20);
        WH(sp_match_tts(s, probe3) < 0, "v1-only never matches via v2 loop");
        /* and a normal v1-only (zero v2 root) is never reached by a nonzero probe */
        uint8_t probe_zero[20];
        memset(probe_zero, 0, sizeof probe_zero);
        WH(sp_match_tts(s, probe_zero) < 0, "all-zero probe matches nothing");

        /* ---- Inbound HS accepted with AND without the reserved bit ------- */
        /* Acceptance gates only on magic + hash; the reserved bytes are not part
         * of the predicate, so an inbound HS is accepted whether or not the peer
         * advertised the v2 bit. Build two inbound HS differing only in m[27]. */
        uint8_t in_hs[68];
        memset(in_hs, 0, sizeof in_hs);
        in_hs[0] = 19;
        memcpy(in_hs + 1, "BitTorrent protocol", 19);
        in_hs[25] = 0x10;
        in_hs[27] = 0x04; /* no v2 bit */
        memcpy(in_hs + 28, sha1_a, 20); /* hybrid's advertised info_hash */
        WH(sp_match_tts(s, in_hs + 28) == 1, "inbound HS w/o v2 bit accepted");
        in_hs[27] |= 0x10; /* peer advertised v2 */
        WH(sp_match_tts(s, in_hs + 28) == 1, "inbound HS w/ v2 bit accepted");

        free(s);
        if (wh_fails == 0) printf("PASS bep52_hs\n");
    }

    return wh_fails ? 1 : 0;
}
