#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

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

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

/* Drain peer_out + any direct writes into sv; return bytes read into buf. */
static ssize_t drain_peer_tx(ntx_session *s, int pi, int sv, uint8_t *buf, size_t cap) {
    ntx_session_peer_out_flush(s, pi);
    ssize_t total = 0;
    for (;;) {
        ssize_t r = recv(sv, buf + total, cap - (size_t)total, MSG_DONTWAIT);
        if (r <= 0) break;
        total += r;
        if ((size_t)total >= cap) break;
    }
    return total;
}

int main(void) {
    ntx_rng_init();
    unlink("downloads/test");
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);

    static uint8_t pat[PS];
    for (uint32_t i = 0; i < PS; i++)
        pat[i] = (uint8_t)(i * 11 + 7);
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
    if (ntx_torrent_set_metainfo(&s->tts[0], info, (size_t)ninfo, "downloads", NULL) != 0)
        return fail("metainfo");
    ntx_session_on_metainfo(s, 0);

    /* Seed piece 0 into store + mark verified. */
    if (ntx_store_write(&s->tts[0].store, 0, 0, pat, PS) != 0)
        return fail("store_write");
    if (!ntx_torrent_piece_complete(&s->tts[0], 0))
        return fail("piece_complete");
    if (!s->tts[0].have[0])
        return fail("have0");
    s->tts[0].state = NTX_TTS_DONE;

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0)
        return fail("socketpair");

    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, 0, &pa4, 6881, 0);
    if (pi < 0)
        return fail("alloc");
    s->peers[pi].fd = sv[0];
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    s->peer_tts[pi] = 0;
    ntx_peer_set_we_choke(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 1);

    /* Direct upload API. */
    uint32_t req_len = 16384;
    ntx_session_data_on_request(s, pi, 0, 0, req_len);
    if (s->tts_up[0] != req_len)
        return fail("tts_up_direct");

    uint8_t rx[64 + 16384];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    if (rn < 13 || rd32(rx) != 9 + req_len || rx[4] != MSG_PIECE)
        return fail("piece_wire_direct");
    if (rd32(rx + 5) != 0 || rd32(rx + 9) != 0)
        return fail("piece_idx_off");
    if (memcmp(rx + 13, pat, req_len) != 0)
        return fail("piece_payload");
    printf("PASS upload_direct_request\n");

    /* Wire path: INTERESTED already set; inject REQUEST via inbuf. */
    s->tts_up[0] = 0;
    s->peers[pi].up_B = 0;
    uint8_t req[17];
    wr32(req, 13);
    req[4] = (uint8_t)MSG_REQUEST;
    wr32(req + 5, 0);
    wr32(req + 9, 16384);
    wr32(req + 13, 16384);
    memcpy(s->peer_buf[pi], req, 17);
    s->peer_buflen[pi] = 17;
    ntx_session_peer_process_inbuf(s, pi);
    if (s->tts_up[0] != 16384)
        return fail("tts_up_wire");

    memset(rx, 0, sizeof rx);
    rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    if (rn < 13 || rx[4] != MSG_PIECE || rd32(rx + 9) != 16384)
        return fail("piece_wire_request");
    if (memcmp(rx + 13, pat + 16384, 16384) != 0)
        return fail("piece_payload_wire");
    printf("PASS upload_wire_request\n");

    /* Choked → must not upload (CANCEL or silence; counter unchanged). */
    uint64_t up_before = s->tts_up[0];
    ntx_peer_set_we_choke(&s->peers[pi], 1);
    ntx_session_data_on_request(s, pi, 0, 0, 1024);
    if (s->tts_up[0] != up_before)
        return fail("choked_still_uploaded");
    printf("PASS upload_choked_rejects\n");

    /* Not interested → reject. */
    ntx_peer_set_we_choke(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 0);
    ntx_session_data_on_request(s, pi, 0, 0, 1024);
    if (s->tts_up[0] != up_before)
        return fail("not_interested_uploaded");
    printf("PASS upload_requires_interest\n");

    close(sv[0]);
    close(sv[1]);
    s->peers[pi].fd = -1;
    ntx_session_free(s);
    ntx_netx_free(n);
    unlink("downloads/test");
    printf("ALL t_session_upload PASS\n");
    return 0;
}
