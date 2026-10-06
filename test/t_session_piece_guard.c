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

/* Security audit: a peer must not be able to write block data it was never asked for, overwrite a
 * piece we already verified, or write outside the piece.  The wire path (PIECE message) only accepts
 * blocks that match an outstanding request; ntx_session_data_on_piece additionally refuses
 * out-of-range and already-complete pieces whoever calls it. */

#define PS 32768U
#define BLK 16384U

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static void wire_piece(ntx_session *s, int pi, uint32_t idx, uint32_t off, const uint8_t *d, uint32_t dl) {
    uint8_t *b = s->peer_buf[pi];
    uint32_t mlen = 9 + dl;
    b[0] = (uint8_t)(mlen >> 24); b[1] = (uint8_t)(mlen >> 16); b[2] = (uint8_t)(mlen >> 8); b[3] = (uint8_t)mlen;
    b[4] = MSG_PIECE;
    b[5] = (uint8_t)(idx >> 24); b[6] = (uint8_t)(idx >> 16); b[7] = (uint8_t)(idx >> 8); b[8] = (uint8_t)idx;
    b[9] = (uint8_t)(off >> 24); b[10] = (uint8_t)(off >> 16); b[11] = (uint8_t)(off >> 8); b[12] = (uint8_t)off;
    memcpy(b + 13, d, dl);
    s->peer_buflen[pi] = 13 + dl;
    ntx_session_peer_process_inbuf(s, pi);
}

static int all_zero(const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++)
        if (p[i]) return 0;
    return 1;
}

int main(void) {
    ntx_rng_init();
    unlink("downloads/test");
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);

    static uint8_t pat[2 * PS], evil[PS], rb[PS];
    for (uint32_t i = 0; i < 2 * PS; i++) pat[i] = (uint8_t)(i * 11 + 7);
    memset(evil, 0xEE, sizeof evil);
    uint8_t h0[20], h1[20];
    ntx_sha1(pat, PS, h0);
    ntx_sha1(pat + PS, PS, h1);

    static uint8_t info[256];
    int ninfo = snprintf((char *)info, sizeof(info), "d12:piece lengthi%ue6:pieces40:", PS);
    memcpy(info + ninfo, h0, 20);
    memcpy(info + ninfo + 20, h1, 20);
    ninfo += 40;
    ninfo += snprintf((char *)info + ninfo, sizeof(info) - (size_t)ninfo, "6:lengthi%ue4:name4:teste", 2 * PS);
    uint8_t ih[20];
    ntx_sha1(info, (size_t)ninfo, ih);

    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    if (ntx_torrent_set_metainfo(&s->tts[0], info, (size_t)ninfo, "downloads", NULL) != 0) return fail("metainfo");
    ntx_session_on_metainfo(s, 0);
    ntx_torrent *t = &s->tts[0];

    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, -1, &pa4, 6881, 0);
    if (pi < 0) return fail("alloc");
    s->peers[pi].fd = 1;
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    s->peer_tts[pi] = 0;

    /* 1. unsolicited PIECE on the wire is dropped */
    wire_piece(s, pi, 0, 0, evil, BLK);
    if (ntx_store_read(&t->store, 0, 0, rb, BLK) != (int)BLK || !all_zero(rb, BLK)) return fail("unsolicited_written");
    if (s->down_total != 0) return fail("unsolicited_counted");

    /* 2. a PIECE whose length differs from the request is dropped */
    ntx_peer_request(&s->peers[pi], 0, 0, BLK, 1);
    wire_piece(s, pi, 0, 0, evil, 100);
    if (ntx_store_read(&t->store, 0, 0, rb, BLK) != (int)BLK || !all_zero(rb, BLK)) return fail("wrong_len_written");

    /* 3. the matching PIECE is accepted */
    wire_piece(s, pi, 0, 0, pat, BLK);
    if (s->down_total != BLK) return fail("solicited_not_counted");
    if (ntx_store_read(&t->store, 0, 0, rb, BLK) != (int)BLK || memcmp(rb, pat, BLK) != 0) return fail("solicited_not_written");

    /* 4. a block that is replayed after it was consumed is unsolicited again */
    wire_piece(s, pi, 0, 0, evil, BLK);
    if (ntx_store_read(&t->store, 0, 0, rb, BLK) != (int)BLK || memcmp(rb, pat, BLK) != 0) return fail("replay_overwrote");

    /* 5. a verified piece can't be overwritten, even by a solicited-looking block */
    ntx_session_data_on_piece(s, pi, 1, 0, pat + PS, BLK);
    ntx_session_data_on_piece(s, pi, 1, BLK, pat + PS + BLK, BLK);
    if (!t->have[1]) return fail("piece1_verify");
    uint64_t before = s->down_total;
    ntx_session_data_on_piece(s, pi, 1, 0, evil, BLK);
    if (ntx_store_read(&t->store, 1, 0, rb, PS) != (int)PS || memcmp(rb, pat + PS, PS) != 0) return fail("complete_piece_overwritten");
    if (s->down_total != before) return fail("complete_piece_counted");

    /* 6. out-of-range offsets (incl. 32-bit wrap) are refused */
    ntx_session_data_on_piece(s, pi, 0, PS - 100, evil, BLK);
    ntx_session_data_on_piece(s, pi, 0, 0xFFFFFFF0u, evil, 0x20);
    ntx_session_data_on_piece(s, pi, 0, PS, evil, 1);
    ntx_session_data_on_piece(s, pi, 0, 0, evil, PS + 1);
    if (ntx_store_read(&t->store, 0, BLK, rb, BLK) != (int)BLK || !all_zero(rb, BLK)) return fail("oob_written");
    if (ntx_store_read(&t->store, 1, 0, rb, PS) != (int)PS || memcmp(rb, pat + PS, PS) != 0) return fail("oob_hit_piece1");
    if (s->down_total != before) return fail("oob_counted");

    printf("PASS session_piece_guard\n");
    ntx_session_free(s);
    ntx_netx_free(n);
    unlink("downloads/test");
    return 0;
}
