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

/* Endgame: once every wanted block is already requested from some peer, an idle peer that has the data
 * asks for the stalest outstanding blocks too (at most one extra copy each), and the first copy to
 * arrive cancels the others.  Without it the last percent waits for the slowest peer's timeout. */

#define PS 32768U
#define NP 4
#define NAME "endgame_dup_t"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static uint32_t rd32(const uint8_t *b) {
    return ((uint32_t)b[0] << 24) | ((uint32_t)b[1] << 16) | ((uint32_t)b[2] << 8) | (uint32_t)b[3];
}

static size_t drain_wire(int fd, uint8_t *buf, size_t bl, size_t cap) {
    for (;;) {
        if (bl >= cap) break;
        ssize_t r = read(fd, buf + bl, cap - bl);
        if (r > 0) {
            bl += (size_t)r;
            continue;
        }
        if (r < 0 && errno == EINTR) continue;
        break;
    }
    return bl;
}

static int count_cancel(const uint8_t *buf, size_t bl, uint32_t idx, uint32_t off) {
    int n = 0;
    size_t pos = 0;
    while (pos + 4 <= bl) {
        uint32_t L = rd32(buf + pos);
        if (pos + 4 + (size_t)L > bl) break;
        if (buf[pos + 4] == MSG_CANCEL && L >= 13 && rd32(buf + pos + 5) == idx &&
            rd32(buf + pos + 9) == off)
            n++;
        pos += 4 + (size_t)L;
    }
    return n;
}

static int inflight(const ntx_peer *p, uint32_t idx, uint32_t off) {
    for (int r = 0; r < p->n_req; r++)
        if (p->req_idx[r] == idx && p->req_off[r] == off) return 1;
    return 0;
}

static int mkpeer(ntx_session *s, int sv[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) return -1;
    fcntl(sv[0], F_SETFL, O_NONBLOCK);
    fcntl(sv[1], F_SETFL, O_NONBLOCK);
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, sv[0], &pa4, 6881, 0);
    if (pi < 0) return -1;
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    s->peers[pi].conn_t0 = 0;
    s->peer_bf_got[pi] = 1;
    for (uint32_t i = 0; i < NP; i++) ntx_peer_set_phave(&s->peers[pi], i, 1);
    ntx_peer_set_choke_us(&s->peers[pi], 0);
    ntx_peer_set_we_int(&s->peers[pi], 1);
    return pi;
}

int main(void) {
    ntx_rng_init();
    unlink("downloads/" NAME);
    ntx_config cfg = {0};
    cfg.store_dir = "downloads";
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) return fail("session_init");

    static uint8_t data[NP * PS];
    for (uint32_t i = 0; i < NP * PS; i++) data[i] = (uint8_t)(i * 31u + 7u);
    static uint8_t phash_all[NP * 20];
    for (uint32_t i = 0; i < NP; i++) ntx_sha1(data + i * PS, PS, phash_all + i * 20);
    static uint8_t info[512];
    int ninfo = snprintf((char *)info, sizeof info, "d12:piece lengthi%ue6:pieces%u:", PS, NP * 20);
    memcpy(info + ninfo, phash_all, NP * 20);
    ninfo += NP * 20;
    ninfo += snprintf((char *)info + ninfo, sizeof info - ninfo, "6:lengthi%llue4:name%u:%se",
                      (unsigned long long)(NP * PS), (int)strlen(NAME), NAME);
    uint8_t ih[20];
    ntx_sha1(info, (size_t)ninfo, ih);
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    if (ntx_torrent_set_metainfo(&s->tts[0], info, (size_t)ninfo, "downloads", NULL) != 0)
        return fail("metainfo");
    ntx_session_on_metainfo(s, 0);
    if (s->tts[0].state != NTX_TTS_DL) return fail("dl_state");

    int svA[2], svB[2];
    int a = mkpeer(s, svA);
    if (a < 0) return fail("peer_a");
    ntx_session_tick(s);
    ntx_peer *pa = &s->peers[a];
    if (pa->n_req != 2 * NP) return fail("a_requests_everything");

    int b = mkpeer(s, svB);
    if (b < 0) return fail("peer_b");
    ntx_peer *pb = &s->peers[b];
    ntx_session_tick(s);
    if (pb->n_req != 0) return fail("b_duplicates_fresh_requests");

    /* A has been sitting on its requests for a while */
    for (int r = 0; r < pa->n_req; r++) pa->req_t0[r] = ntx_mono_ms() - 2500;
    ntx_session_tick(s);
    if (pb->n_req != 2 * NP) return fail("b_no_endgame_requests");
    /* the idle peer does not pile a third copy on */
    int c_sv[2];
    int c = mkpeer(s, c_sv);
    if (c < 0) return fail("peer_c");
    ntx_session_tick(s);
    if (s->peers[c].n_req != 0) return fail("third_copy");

    static uint8_t wire[65536];
    size_t wl = drain_wire(svA[1], wire, 0, sizeof wire);

    /* B delivers block (0,0) first: A's copy is cancelled and forgotten */
    uint64_t before = s->down_total;
    ntx_session_data_on_piece(s, b, 0, 0, data, NTX_PEER_REQ_LEN);
    if (s->down_total != before + NTX_PEER_REQ_LEN) return fail("b_block_counted");
    wl = drain_wire(svA[1], wire, wl, sizeof wire);
    if (count_cancel(wire, wl, 0, 0) != 1) return fail("a_not_cancelled");
    if (inflight(pa, 0, 0)) return fail("a_request_kept");
    if (!inflight(pa, 0, NTX_PEER_REQ_LEN)) return fail("a_other_block_dropped");

    /* a late copy of an already stored block is dropped, not written or counted twice */
    before = s->down_total;
    uint8_t junk[NTX_PEER_REQ_LEN];
    memset(junk, 0xEE, sizeof junk);
    ntx_session_data_on_piece(s, a, 0, 0, junk, NTX_PEER_REQ_LEN);
    if (s->down_total != before) return fail("duplicate_counted");

    /* finishing the file from both peers still verifies every piece */
    for (uint32_t i = 0; i < NP; i++)
        for (uint32_t o = 0; o < PS; o += NTX_PEER_REQ_LEN) {
            if (i == 0 && o == 0) continue;
            ntx_session_data_on_piece(s, (i & 1) ? a : b, i, o, data + i * PS + o, NTX_PEER_REQ_LEN);
        }
    for (uint32_t i = 0; i < NP; i++)
        if (!s->tts[0].have[i]) return fail("piece_missing");

    printf("PASS session_endgame_dup\n");
    unlink("downloads/" NAME);
    return 0;
}
