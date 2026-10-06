/* These checks age timestamps by subtracting from the monotonic clock, which counts from boot: offset it so a freshly started host cannot underflow. */
#define NTX_MONO_BASE_MS 86400000LL
#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <errno.h>
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

/* A2 — slow-loris: per-request timeout/cancel with many REQUESTs in-flight.
 *
 * The peer is a non-blocking AF_UNIX socketpair: the session's CANCEL/REQUEST
 * messages are real wire bytes we parse on the test side. Time is advanced by
 * rewinding each request's req_t0 into the past (the timeout predicate is
 * `now - req_t0 > lim`, so this is equivalent to the clock crossing the
 * boundary for that request — per-request, no mock clock needed).
 */

#define PS 32768U
#define NP 8
#define NAME "a2_reqto"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

/* Drain all available bytes from the test-side socket end. */
static size_t drain_wire(int fd, uint8_t *buf, size_t bl, size_t cap) {
    for (;;) {
        if (bl >= cap) break;
        ssize_t r = read(fd, buf + bl, cap - bl);
        if (r > 0) {
            bl += (size_t)r;
            continue;
        }
        if (r == 0) break;
        if (errno == EAGAIN || errno == EWOULDBLOCK) break;
        if (errno == EINTR) continue;
        break;
    }
    return bl;
}

/* Count CANCEL messages with the exact (idx,off,len) tuple in [buf, buf+bl). */
static int count_cancel(const uint8_t *buf, size_t bl, uint32_t idx, uint32_t off, uint32_t len) {
    int n = 0;
    size_t pos = 0;
    while (pos + 4 <= bl) {
        uint32_t L = rd32(buf + pos);
        if (pos + 4 + (size_t)L > bl) break;
        if (buf[pos + 4] == MSG_CANCEL && L >= 12) {
            if (rd32(buf + pos + 5) == idx && rd32(buf + pos + 9) == off && rd32(buf + pos + 13) == len)
                n++;
        }
        pos += 4 + (size_t)L;
    }
    return n;
}

static int count_cancel_any(const uint8_t *buf, size_t bl) {
    int n = 0;
    size_t pos = 0;
    while (pos + 4 <= bl) {
        uint32_t L = rd32(buf + pos);
        if (pos + 4 + (size_t)L > bl) break;
        if (buf[pos + 4] == MSG_CANCEL) n++;
        pos += 4 + (size_t)L;
    }
    return n;
}

/* "Advance the clock" for one in-flight request: rewind its t0 by age_ms. */
static int rewind_req(ntx_peer *p, uint32_t idx, uint32_t off, uint64_t age_ms) {
    for (int r = 0; r < p->n_req; r++) {
        if (p->req_idx[r] == idx && p->req_off[r] == off) {
            p->req_t0[r] = ntx_mono_ms() - age_ms;
            return 1;
        }
    }
    return 0;
}

static int inflight(const ntx_peer *p, uint32_t idx, uint32_t off) {
    for (int r = 0; r < p->n_req; r++)
        if (p->req_idx[r] == idx && p->req_off[r] == off) return 1;
    return 0;
}

int main(void) {
    ntx_rng_init();
    unlink("downloads/" NAME);
    ntx_config cfg = {0};
    cfg.store_dir = "downloads";
    ntx_netx *n = ntx_netx_init(&cfg);
    if (!n) return fail("netx_init");
    ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) {
        ntx_netx_free(n);
        return fail("session_init");
    }

    /* 8 pieces x 32 KiB, deterministic content; phash per piece. */
    static uint8_t data[NP * PS];
    for (uint32_t i = 0; i < NP * PS; i++)
        data[i] = (uint8_t)(i * 31u + 7u);
    static uint8_t phash_all[NP * 20];
    for (uint32_t i = 0; i < NP; i++)
        ntx_sha1(data + i * PS, PS, phash_all + i * 20);

    static uint8_t info[512];
    int ninfo = snprintf((char *)info, sizeof info, "d12:piece lengthi%ue6:pieces%u:", PS, NP * 20);
    memcpy(info + ninfo, phash_all, NP * 20);
    ninfo += NP * 20;
    ninfo += snprintf((char *)info + ninfo, sizeof info - ninfo,
                      "6:lengthi%llue4:name%u:%se", (unsigned long long)(NP * PS),
                      (int)strlen(NAME), NAME);

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
    if (s->tts[0].state != NTX_TTS_DL || s->tts[0].np != NP) return fail("dl_state");
    if (!s->piece_bytes[0]) return fail("piece_bytes");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return fail("socketpair");
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);

    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, sv[0], &pa4, 6881, 0);
    if (pi < 0) return fail("peer_alloc");
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    s->peers[pi].conn_t0 = 0;
    s->peer_bf_got[pi] = 1;
    for (uint32_t i = 0; i < NP; i++)
        ntx_peer_set_phave(&s->peers[pi], i, 1);
    ntx_peer_set_choke_us(&s->peers[pi], 0);
    ntx_peer_set_we_int(&s->peers[pi], 1);
    ntx_peer *p = &s->peers[pi];

    /* Enqueue 6 in-flight REQUESTs: distinct pieces, distinct (idx,off),
     * one short len (8 KiB) to prove the cancel carries per-request fields. */
    static const struct {
        uint32_t idx, off, len;
    } reqs[6] = {{0, 0, 16384}, {1, 0, 16384}, {2, 0, 16384},
                 {3, 0, 16384}, {4, 0, 8192}, {5, 16384, 16384}};
    for (int k = 0; k < 6; k++) {
        if (ntx_session_peer_send_request(s, pi, reqs[k].idx, reqs[k].off, reqs[k].len) != 0)
            return fail("req_tx");
        if (ntx_peer_request(p, reqs[k].idx, reqs[k].off, reqs[k].len, ntx_mono_ms()) != 0)
            return fail("req_track");
    }
    if (p->n_req != 6) return fail("n_req_6");

    static uint8_t wire[65536];
    size_t wl = 0;

    /* Pre-tick: everything fresh -> no CANCEL; fill loop tops up the rest. */
    {
        size_t w0 = wl;
        ntx_session_tick(s);
        wl = drain_wire(sv[1], wire, wl, sizeof wire);
        if (count_cancel_any(wire + w0, wl - w0) != 0) return fail("pre_spurious_cancel");
    }
    if (p->n_req != NP * 2) return fail("pre_fill_16");

    /* Cross the 30 s boundary for 3 of the in-flight requests (per-request).
     * (1,0) ages to 25 s: below the normal limit, must be kept. */
    if (!rewind_req(p, 0, 0, 31000)) return fail("rewind_0");
    if (!rewind_req(p, 1, 0, 25000)) return fail("rewind_1");
    if (!rewind_req(p, 3, 0, 31000)) return fail("rewind_3");
    if (!rewind_req(p, 5, 16384, 31000)) return fail("rewind_5");

    {
        size_t w0 = wl;
        ntx_session_tick(s);
        wl = drain_wire(sv[1], wire, wl, sizeof wire);
        const uint8_t *ph = wire + w0;
        size_t phl = wl - w0;
        if (count_cancel(ph, phl, 0, 0, 16384) != 1) return fail("cancel_0");
        if (count_cancel(ph, phl, 3, 0, 16384) != 1) return fail("cancel_3");
        if (count_cancel(ph, phl, 5, 16384, 16384) != 1) return fail("cancel_5");
        if (count_cancel(ph, phl, 1, 0, 16384) != 0) return fail("keep_1_25s");
        if (count_cancel(ph, phl, 2, 0, 16384) != 0) return fail("keep_2");
        if (count_cancel(ph, phl, 4, 0, 8192) != 0) return fail("keep_4");
        if (count_cancel_any(ph, phl) != 3) return fail("cancel_total_3");
    }
    if (p->n_req != NP * 2) return fail("refill_16");
    if (!inflight(p, 0, 0) || !inflight(p, 3, 0) || !inflight(p, 5, 16384))
        return fail("refill_stale");

    /* FAST timeout: piece 6 becomes partial -> per-request limit drops to 12 s.
     * A 13 s request and the 25 s survivor from phase 1 must now be CANCELed;
     * fresh requests are kept. */
    ntx_session_data_on_piece(s, pi, 6, 0, data + 6 * PS, 16384);
    if (!piece_has_partial(s, 0)) return fail("fast_partial");
    if (!inflight(p, 6, 16384)) return fail("fast_refill");
    if (!rewind_req(p, 6, 16384, 13000)) return fail("rewind_6");
    if (!rewind_req(p, 7, 0, 25000)) return fail("rewind_7");

    {
        size_t w0 = wl;
        ntx_session_tick(s);
        wl = drain_wire(sv[1], wire, wl, sizeof wire);
        const uint8_t *ph = wire + w0;
        size_t phl = wl - w0;
        if (count_cancel(ph, phl, 6, 16384, 16384) != 1) return fail("fast_cancel_6");
        if (count_cancel(ph, phl, 7, 0, 16384) != 1) return fail("fast_cancel_7");
        if (count_cancel(ph, phl, 1, 0, 16384) != 1) return fail("fast_cancel_1");
        if (count_cancel(ph, phl, 0, 0, 16384) != 0) return fail("fast_keep_0");
        if (count_cancel(ph, phl, 2, 0, 16384) != 0) return fail("fast_keep_2");
        if (count_cancel(ph, phl, 4, 0, 8192) != 0) return fail("fast_keep_4");
    }
    if (p->n_req != NP * 2 - 1) return fail("fast_refill_15");

    /* Health after the timeout passes: a fresh REQUEST->PIECE exchange
     * completes normally (piece 2 verified) and the session keeps ticking. */
    ntx_session_data_on_piece(s, pi, 2, 0, data + 2 * PS, 16384);
    ntx_session_data_on_piece(s, pi, 2, 16384, data + 2 * PS + 16384, 16384);
    if (!s->tts[0].have[2] || s->tts[0].have_n != 1) return fail("piece2_verify");
    if (inflight(p, 2, 0) || inflight(p, 2, 16384)) return fail("piece2_req_done");
    if (s->down_total < 3u * NTX_PEER_REQ_LEN) return fail("down_total");

    {
        size_t w0 = wl;
        for (int k = 0; k < 3; k++)
            ntx_session_tick(s);
        wl = drain_wire(sv[1], wire, wl, sizeof wire);
        if (count_cancel_any(wire + w0, wl - w0) != 0) return fail("health_spurious_cancel");
    }
    if (s->peer_phase[pi] != PH_OK) return fail("health_phase");
    if (s->tts[0].state != NTX_TTS_DL) return fail("health_state");
    if (p->n_req != NP * 2 - 3) return fail("health_nreq_13");

    close(sv[1]);
    ntx_session_free(s);
    ntx_netx_free(n);
    unlink("downloads/" NAME);
    printf("PASS session_req_timeout\n");
    return 0;
}
