#define _GNU_SOURCE
#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <time.h>

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

#define PS 65536U   /* four 16 KiB blocks */
#define BLK 16384U

/* Rate limits (--up-limit / --down-limit / --smooth).  They used to
 *  - drop every outgoing message (choke, have, REQUEST...) once the upload bucket was empty,
 *  - never upload at all when the limit was below one block,
 *  - throw away received blocks over the download limit,
 *  - count bytes as uploaded before they were sent,
 * and unserved requests got a CANCEL (type 8) instead of the BEP6 reject (type 16). */

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

static uint8_t pat[PS];

static ssize_t drain(ntx_session *s, int pi, int sv, uint8_t *buf, size_t cap) {
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

/* count wire messages of a type in a byte stream of length-prefixed frames */
static int count_msgs(const uint8_t *b, ssize_t n, int type) {
    int c = 0;
    ssize_t o = 0;
    while (o + 5 <= n) {
        uint32_t L = rd32(b + o);
        if (L == 0) { o += 4; continue; }
        if (b[o + 4] == type) c++;
        o += 4 + (ssize_t)L;
    }
    return c;
}

static ntx_session *mk_session(ntx_config *cfg, ntx_netx **nn, int seeded, int *pi_out, int *sv_out) {
    unlink("downloads/test");
    ntx_netx *n = ntx_netx_init(cfg);
    ntx_session *s = ntx_session_init(n, cfg);
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
    if (ntx_torrent_set_metainfo(&s->tts[0], info, (size_t)ninfo, "downloads", NULL) != 0) return NULL;
    ntx_session_on_metainfo(s, 0);
    if (seeded) {
        if (ntx_store_write(&s->tts[0].store, 0, 0, pat, PS) != 0) return NULL;
        if (!ntx_torrent_piece_complete(&s->tts[0], 0)) return NULL;
        s->tts[0].state = NTX_TTS_DONE;
    }
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return NULL;
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, 0, &pa4, 6881, 0);
    if (pi < 0) return NULL;
    s->peers[pi].fd = sv[0];
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    s->peer_tts[pi] = 0;
    ntx_peer_set_we_choke(&s->peers[pi], 0);
    ntx_peer_set_int_us(&s->peers[pi], 1);
    *pi_out = pi;
    *sv_out = sv[1];
    *nn = n;
    return s;
}

/* Pretend ms milliseconds passed without sleeping: the bucket refills from the elapsed time. */
static void age_clock(ntx_session *s, uint64_t ms) {
    s->shape_t[1] -= ms;
}

static void req(ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    ntx_session_data_on_request(s, pi, idx, off, len);
}

int main(void) {
    ntx_rng_init();
    for (uint32_t i = 0; i < PS; i++) pat[i] = (uint8_t)(i * 11 + 7);
    static uint8_t rx[8 * (BLK + 64)];
    ssize_t rn;

    /* --- upload: one block per four seconds --------------------------------------- */
    {
        ntx_config cfg = {0};
        cfg.up_limit = BLK / 4; /* a block costs four seconds of budget */
        ntx_netx *n;
        int pi, sv;
        ntx_session *s = mk_session(&cfg, &n, 1, &pi, &sv);
        if (!s) return fail("setup_up");

        req(s, pi, 0, 0, BLK);
        req(s, pi, 0, BLK, BLK);
        req(s, pi, 0, 2 * BLK, BLK);
        rn = drain(s, pi, sv, rx, sizeof rx);
        if (count_msgs(rx, rn, 7) != 1) {
            printf("pieces=%d\n", count_msgs(rx, rn, 7));
            return fail("first_block_served_rest_deferred");
        }
        if (s->tts_up[0] != BLK) return fail("counted_only_what_was_sent");

        /* control messages are never shaped */
        ntx_session_peer_send_have(s, pi, 0);
        rn = drain(s, pi, sv, rx, sizeof rx);
        if (count_msgs(rx, rn, 4) != 1) return fail("have_not_dropped_by_shaper");
        printf("PASS up_limit_control_msgs_and_first_block\n");

        /* a long idle gap repays debt only as fast as the limit allows (it used to refill the bucket) */
        age_clock(s, 1500);
        ntx_session_data_tick(s);
        rn = drain(s, pi, sv, rx, sizeof rx);
        if (count_msgs(rx, rn, 7) != 0) return fail("debt_not_forgiven_by_idle_gap");

        /* the deferred requests are served as the budget refills, not lost */
        int served = 1;
        for (int round = 0; round < 3 && served < 3; round++) {
            age_clock(s, 4100);
            ntx_session_data_tick(s);
            rn = drain(s, pi, sv, rx, sizeof rx);
            served += count_msgs(rx, rn, 7);
        }
        if (served != 3) {
            printf("served=%d\n", served);
            return fail("deferred_requests_served_later");
        }
        if (s->tts_up[0] != 3 * BLK) return fail("up_total_matches_wire");
        printf("PASS up_limit_defers_and_serves\n");

        /* a cancel from the peer removes a deferred request */
        s->tts_up[0] = 0;
        req(s, pi, 0, 0, BLK);          /* may be served at once or deferred depending on budget */
        req(s, pi, 0, BLK, BLK);
        req(s, pi, 0, 2 * BLK, BLK);
        drain(s, pi, sv, rx, sizeof rx);
        uint8_t c[17];
        wr32(c, 13);
        c[4] = 8; /* MSG_CANCEL */
        wr32(c + 5, 0);
        wr32(c + 9, 2 * BLK);
        wr32(c + 13, BLK);
        memcpy(s->peer_buf[pi], c, 17);
        s->peer_buflen[pi] = 17;
        ntx_session_peer_process_inbuf(s, pi);
        int got = 0;
        for (int round = 0; round < 4; round++) {
            age_clock(s, 4100);
            ntx_session_data_tick(s);
            rn = drain(s, pi, sv, rx, sizeof rx);
            for (ssize_t o = 0; o + 13 <= rn;) {
                uint32_t L = rd32(rx + o);
                if (L && rx[o + 4] == 7 && rd32(rx + o + 9) == 2 * BLK) return fail("cancelled_block_still_sent");
                o += 4 + (ssize_t)L;
            }
            got += count_msgs(rx, rn, 7);
        }
        printf("PASS up_limit_cancel_dequeues\n");

        close(sv);
        close(s->peers[pi].fd);
        s->peers[pi].fd = -1;
        ntx_session_free(s);
        ntx_netx_free(n);
    }

    /* --- upload: unserved requests are rejected (BEP6) for fast peers, silent otherwise ------- */
    {
        ntx_config cfg = {0};
        ntx_netx *n;
        int pi, sv;
        ntx_session *s = mk_session(&cfg, &n, 1, &pi, &sv);
        if (!s) return fail("setup_rej");
        ntx_peer_set_we_choke(&s->peers[pi], 1);

        s->peer_fast[pi] = 0;
        req(s, pi, 0, 0, BLK);
        rn = drain(s, pi, sv, rx, sizeof rx);
        if (rn != 0) return fail("non_fast_peer_gets_nothing");

        s->peer_fast[pi] = 1;
        req(s, pi, 0, BLK, BLK);
        rn = drain(s, pi, sv, rx, sizeof rx);
        if (rn != 17 || rx[4] != 16 || rd32(rx + 5) != 0 || rd32(rx + 9) != BLK || rd32(rx + 13) != BLK)
            return fail("fast_peer_gets_reject_16");
        printf("PASS reject_for_fast_peers\n");

        close(sv);
        close(s->peers[pi].fd);
        s->peers[pi].fd = -1;
        ntx_session_free(s);
        ntx_netx_free(n);
    }

    /* --- download: blocks over the limit are kept, a reject frees the request slot ------------ */
    {
        ntx_config cfg = {0};
        cfg.down_limit = 1; /* far below one block */
        ntx_netx *n;
        int pi, sv;
        ntx_session *s = mk_session(&cfg, &n, 0, &pi, &sv);
        if (!s) return fail("setup_down");
        s->peer_fast[pi] = 1;
        ntx_peer_set_phave(&s->peers[pi], 0, 1);
        ntx_peer_set_choke_us(&s->peers[pi], 0);
        ntx_peer_set_we_int(&s->peers[pi], 1);
        s->tts[0].rarity[0] = 1;

        /* reject of an outstanding request clears it */
        uint64_t now = ntx_mono_ms();
        ntx_peer_request(&s->peers[pi], 0, 0, BLK, now);
        if (s->peers[pi].n_req != 1) return fail("req_registered");
        uint8_t rj[17];
        wr32(rj, 13);
        rj[4] = 16;
        wr32(rj + 5, 0);
        wr32(rj + 9, 0);
        wr32(rj + 13, BLK);
        memcpy(s->peer_buf[pi], rj, 17);
        s->peer_buflen[pi] = 17;
        ntx_session_peer_process_inbuf(s, pi);
        for (int k = 0; k < s->peers[pi].n_req; k++)
            if (s->peers[pi].req_idx[k] == 0 && s->peers[pi].req_off[k] == 0) return fail("reject_clears_request");
        printf("PASS reject_clears_outstanding_request\n");

        for (uint32_t b = 0; b < 4; b++) {
            ntx_peer_request(&s->peers[pi], 0, b * BLK, BLK, now);
            ntx_session_data_on_piece(s, pi, 0, b * BLK, pat + b * BLK, BLK);
        }
        if (!s->tts[0].have[0]) return fail("blocks_over_down_limit_are_kept");
        printf("PASS down_limit_keeps_received_blocks\n");

        close(sv);
        close(s->peers[pi].fd);
        s->peers[pi].fd = -1;
        ntx_session_free(s);
        ntx_netx_free(n);
    }

    unlink("downloads/test");
    printf("ALL t_session_shaping PASS\n");
    return 0;
}
