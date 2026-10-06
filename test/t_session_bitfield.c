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

#define PS 65536U
#define BLK 16384U

/* BEP3: the bitfield of a torrent with np pieces is exactly ceil(np/8) bytes.  A wrong length used to be
 * half-applied and then treated as the peer's complete view of the swarm. */

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

__attribute__((unused)) static ssize_t drain(ntx_session *s, int pi, int sv, uint8_t *buf, size_t cap) {
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
__attribute__((unused)) static int count_msgs(const uint8_t *b, ssize_t n, int type) {
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


static void feed_bitfield(ntx_session *s, int pi, const uint8_t *bf, uint32_t n) {
    uint8_t m[64];
    wr32(m, 1 + n);
    m[4] = 5; /* MSG_BITFIELD */
    memcpy(m + 5, bf, n);
    memcpy(s->peer_buf[pi], m, 5 + n);
    s->peer_buflen[pi] = 5 + n;
    ntx_session_peer_process_inbuf(s, pi);
}

int main(void) {
    ntx_rng_init();
    for (uint32_t i = 0; i < PS; i++) pat[i] = (uint8_t)(i * 11 + 7);
    ntx_config cfg = {0};

    /* np = 1 -> exactly one byte */
    const uint8_t good[1] = {0x80};
    const uint8_t longer[3] = {0x80, 0xFF, 0xFF};
    for (int variant = 0; variant < 3; variant++) {
        ntx_netx *n;
        int pi, sv;
        ntx_session *s = mk_session(&cfg, &n, 0, &pi, &sv);
        if (!s) return fail("setup");
        if (variant == 0) feed_bitfield(s, pi, good, 1);
        if (variant == 1) feed_bitfield(s, pi, longer, 3);
        if (variant == 2) { /* empty bitfield for a 1-piece torrent: too short */
            feed_bitfield(s, pi, good, 0);
        }
        int dropped = s->peers[pi].fd == -1;
        if (variant == 0 && (dropped || !ntx_peer_has(&s->peers[pi], 0))) return fail("valid_bitfield_applied");
        if (variant != 0 && !dropped) return fail("bad_length_bitfield_drops_peer");
        close(sv);
        if (!dropped) {
            close(s->peers[pi].fd);
            s->peers[pi].fd = -1;
        }
        ntx_session_free(s);
        ntx_netx_free(n);
    }
    printf("PASS bitfield_length\n");
    unlink("downloads/test");
    printf("ALL PASS\n");
    return 0;
}
