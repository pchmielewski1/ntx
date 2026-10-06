/* These checks age timestamps by subtracting from the monotonic clock, which counts from boot: offset it so a freshly started host cannot underflow. */
#define NTX_MONO_BASE_MS 86400000LL
#define _GNU_SOURCE
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

/* BEP52 OUTBOUND hash requests (21) + torrent NEED_LAYERS state.
 *
 * A pure-v2 torrent that learned its info dict via BEP9 has no top-level piece
 * layers, so it must acquire them by asking peers for the whole piece layer via
 * a hash request (21) and folding the verified hashes (22) into a scratch
 * buffer, committed through ntx_torrent_apply_piece_layer only after every slice
 * validates against the pieces roots.
 *
 * Fixture (test/scripts/bep52_hash_msgs.py, seed "bep52-hash-msgs"):
 *   file = 262144 B = 16 x 16KiB leaves, tree height 4,
 *   piece length = 131072 (piece layer = 3), 2 pieces.
 * See BEP 52. */

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int read_file(const char *path, uint8_t **out, size_t *outn) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *b = malloc((size_t)sz);
    if (!b) { fclose(f); return -1; }
    size_t rd = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(b); return -1; }
    *out = b;
    *outn = rd;
    return 0;
}

/* Extract the string value of "key": "...." from a JSON blob into dst. */
static int json_str(const uint8_t *b, size_t n, const char *key, char *dst, size_t cap) {
    char pat[64];
    snprintf(pat, sizeof pat, "\"%s\"", key);
    size_t plen = strlen(pat);
    for (size_t i = 0; i + plen < n; i++) {
        if (memcmp(b + i, pat, plen) != 0) continue;
        size_t j = i + plen;
        while (j < n && (b[j] == ' ' || b[j] == ':' || b[j] == '\t')) j++;
        if (j >= n || b[j] != '"') continue;
        j++;
        size_t o = 0;
        while (j < n && b[j] != '"' && o + 1 < cap) dst[o++] = (char)b[j++];
        dst[o] = 0;
        return 1;
    }
    return 0;
}

static int hx(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t cap) {
    size_t nh = strlen(hex);
    if (nh % 2 || nh / 2 > cap) return -1;
    for (size_t i = 0; i < nh / 2; i++) {
        int hi = hx(hex[2 * i]), lo = hx(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return (int)(nh / 2);
}

/* Deterministic vector content: sha256("<seed>:<i>") tiled to file_size.
 * Mirrors test/scripts/bep52_hash_msgs.py content(). */
static void gen_content(uint8_t *out, size_t size) {
    size_t o = 0;
    int i = 0;
    while (o < size) {
        char s[64];
        int sl = snprintf(s, sizeof s, "bep52-hash-msgs:%d", i++);
        uint8_t h[32];
        ntx_sha256(s, (size_t)sl, h);
        size_t take = (size - o < 32) ? size - o : 32;
        memcpy(out + o, h, take);
        o += take;
    }
}

#define VEC_DIR "test/vectors/bep52/"
#define FIX_FILE_SIZE 262144u
#define FIX_PS 131072u
#define FIX_NP 2u

static int mk_ok_peer(ntx_session *s, int sv) {
    ntx_addr pa4;
    ntx_addr_set_v4(&pa4, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(s, -1, &pa4, 1234, 0);
    if (pi < 0) return -1;
    s->peers[pi].fd = sv;
    s->peer_phase[pi] = PH_OK;
    s->peer_plain[pi] = 1;
    s->peer_hello_sent[pi] = 1;
    return pi;
}

/* Feed a full BT frame (len + id + payload) into the peer buffer and drive RX. */
static void feed_frame(ntx_session *s, int pi, const uint8_t *frame, size_t n) {
    memcpy(s->peer_buf[pi], frame, n);
    s->peer_buflen[pi] = n;
    ntx_session_peer_process_inbuf(s, pi);
}

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

/* Session + connected OK peer bound to tts[0]. */
static ntx_session *mk_session_peer(ntx_netx **n, int sv[2], int *pi_out) {
    static ntx_config cfg; /* outlives the helper: the session keeps this pointer */
    memset(&cfg, 0, sizeof cfg);
    *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(*n, &cfg);
    if (ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=t") != 0) {
        ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) {
        ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    int pi = mk_ok_peer(s, sv[0]);
    if (pi < 0) {
        close(sv[0]);
        close(sv[1]);
        ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    s->peer_tts[pi] = 0;
    *pi_out = pi;
    return s;
}

static void teardown(ntx_session *s, ntx_netx *n, int sv[2], int pi) {
    close(sv[0]);
    close(sv[1]);
    s->peers[pi].fd = -1;
    ntx_session_free(s);
    ntx_netx_free(n);
}

/* Session + TWO connected OK peers bound to tts[0] (for rotation / peer-binding). */
static ntx_session *mk_session_2peers(ntx_netx **n, int sv1[2], int sv2[2], int *pa, int *pb) {
    static ntx_config cfg; /* outlives the helper: the session keeps this pointer */
    memset(&cfg, 0, sizeof cfg);
    *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(*n, &cfg);
    if (!s || ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=t") != 0) {
        if (s) ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv1) != 0) {
        ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv2) != 0) {
        close(sv1[0]); close(sv1[1]);
        ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    int a = mk_ok_peer(s, sv1[0]);
    int b = mk_ok_peer(s, sv2[0]);
    if (a < 0 || b < 0) {
        close(sv1[0]); close(sv1[1]); close(sv2[0]); close(sv2[1]);
        ntx_session_free(s);
        ntx_netx_free(*n);
        return NULL;
    }
    s->peer_tts[a] = 0;
    s->peer_tts[b] = 0;
    *pa = a;
    *pb = b;
    return s;
}

static void teardown2(ntx_session *s, ntx_netx *n, int sv1[2], int sv2[2], int a, int b) {
    close(sv1[0]); close(sv1[1]); close(sv2[0]); close(sv2[1]);
    s->peers[a].fd = -1;
    s->peers[b].fd = -1;
    ntx_session_free(s);
    ntx_netx_free(n);
}

/* Read the fixture root hex from a legal request vector's meta.json. */
static int load_root(const char *stem, uint8_t root[32]) {
    uint8_t *meta;
    size_t n;
    char path[256];
    snprintf(path, sizeof path, VEC_DIR "%s.meta.json", stem);
    if (read_file(path, &meta, &n) != 0) return 0;
    char hex[128];
    int ok = json_str(meta, n, "pieces_root", hex, sizeof hex) && hex_to_bytes(hex, root, 32) == 32;
    free(meta);
    return ok;
}

/* Populate tts[0] as a PURE-v2 torrent over the fixture file, WITHOUT a piece
 * layer (the NEED_LAYERS state). Derives the pieces root from the file content
 * itself (derived, never memorized) and cross-checks it against the
 * committed vector root. Returns 0 ok. */
static int setup_v2_nolayers(ntx_session *s) {
    ntx_torrent *t = &s->tts[0];
    memset(t, 0, sizeof *t);
    t->ps = FIX_PS;
    t->np = FIX_NP;
    t->have_meta = 1;
    t->meta_version = 2;
    t->v2_nfiles = 1;
    t->v2_len_file[0] = FIX_FILE_SIZE;
    t->v2_np_file[0] = FIX_NP;
    t->v2_first_piece[0] = 0;
    t->piece_layer = NULL;
    t->piece_layer_n = 0;
    t->store.fd = -1;
    t->store.size = FIX_FILE_SIZE;
    t->store.ps = FIX_PS;
    t->store.np = FIX_NP;
    uint8_t *content = malloc(FIX_FILE_SIZE);
    if (!content) return -1;
    gen_content(content, FIX_FILE_SIZE);
    uint8_t pl[2 * 32];
    size_t pln = 0;
    if (ntx_merkle_file_layer(content, FIX_FILE_SIZE, FIX_PS, pl, sizeof pl, &pln) != 0 || pln != 64) {
        free(content);
        return -1;
    }
    /* derive the root from the same layer the test will later deliver */
    uint8_t derived[32];
    if (ntx_merkle_root_from_layer(pl, pln, FIX_PS, FIX_FILE_SIZE, derived) != 0) {
        free(content);
        return -1;
    }
    uint8_t vec_root[32];
    if (!load_root("hash_request_piece_layer", vec_root) ||
        memcmp(derived, vec_root, 32) != 0) {
        free(content);
        return -1;
    }
    memcpy(t->v2_root[0], derived, 32);
    t->have = calloc(FIX_NP, 1);
    if (!t->have) { free(content); return -1; }
    free(content);
    return 0;
}

/* Recompute the correct piece-layer string for the fixture file (np*32 bytes). */
static int fixture_layer(uint8_t *pl, size_t cap, size_t *outn) {
    uint8_t *content = malloc(FIX_FILE_SIZE);
    if (!content) return -1;
    gen_content(content, FIX_FILE_SIZE);
    int rc = ntx_merkle_file_layer(content, FIX_FILE_SIZE, FIX_PS, pl, cap, outn);
    free(content);
    return rc;
}

static int count_request_any(const uint8_t *buf, size_t bl) {
    int n = 0;
    size_t pos = 0;
    while (pos + 4 <= bl) {
        uint32_t L = rd32(buf + pos);
        if (pos + 4 + (size_t)L > bl) break;
        if (buf[pos + 4] == MSG_REQUEST) n++;
        pos += 4 + (size_t)L;
    }
    return n;
}

static int prepare_data_peer(ntx_session *s, int pi) {
    ntx_torrent *t = &s->tts[0];
    ntx_peer *p = &s->peers[pi];
    t->state = NTX_TTS_DL;
    if (ntx_session_data_piece_blk_alloc(s, 0) != 0) return -1;
    ntx_session_data_reset_tts(0, FIX_NP);
    free(p->phave);
    p->phave = calloc(FIX_NP, 1);
    if (!p->phave) return -1;
    p->phave_n = (int)FIX_NP;
    p->phave_none = 1;
    for (uint32_t i = 0; i < FIX_NP; i++) ntx_peer_set_phave(p, i, 1);
    s->peer_bf_got[pi] = 1;
    ntx_peer_set_choke_us(p, 0);
    ntx_peer_set_we_int(p, 0);
    return 0;
}

/* Step 0 (controller-folded): the normal piece pump must stay closed while a
 * pure-v2 torrent still needs its piece layers. After the layers are applied,
 * the same peer/path must resume issuing DATA requests. */
static void test_no_data_until_layers(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "data_pump_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "data_pump_torrent"); teardown(s, n, sv, pi); return; }
    if (prepare_data_peer(s, pi) != 0) { check(0, "data_pump_peer"); teardown(s, n, sv, pi); return; }
    check(ntx_torrent_layers_pending(&s->tts[0]) == 1, "data_pump_pending");

    uint8_t pre[16];
    (void)drain_peer_tx(s, pi, sv[1], pre, sizeof pre);
    ntx_session_data_refill(s, 0);
    uint8_t rx[512];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(count_request_any(rx, (size_t)rn) == 0, "data_pump_no_request_while_pending");
    check(s->peers[pi].we_int == 0, "data_pump_no_interest_while_pending");

    uint8_t pl[64];
    size_t pln = 0;
    if (fixture_layer(pl, sizeof pl, &pln) != 0 || pln != 64) {
        check(0, "data_pump_fixture_layer");
        teardown(s, n, sv, pi);
        return;
    }
    check(ntx_torrent_apply_piece_layer(&s->tts[0], pl, pln) == 0, "data_pump_apply_layer");
    check(ntx_torrent_layers_pending(&s->tts[0]) == 0, "data_pump_pending_cleared");

    rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(count_request_any(rx, (size_t)rn) == 0, "data_pump_clean_before_resume");
    ntx_session_data_refill(s, 0);
    rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(count_request_any(rx, (size_t)rn) > 0, "data_pump_requests_resume");
    check(s->peers[pi].we_int == 1, "data_pump_interest_resumes");
    teardown(s, n, sv, pi);
}

/* T1: layers_pending is derived purely from the torrent state. */
static void test_layers_pending(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "pend_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "pend_setup_torrent"); teardown(s, n, sv, pi); return; }
    check(ntx_torrent_layers_pending(&s->tts[0]) == 1, "pend_true_when_no_layer");
    /* hybrid torrents take the v1 verify path — never pending */
    s->tts[0].hybrid = 1;
    check(ntx_torrent_layers_pending(&s->tts[0]) == 0, "pend_false_hybrid");
    s->tts[0].hybrid = 0;
    /* a single-piece-only file has no layer to fetch */
    s->tts[0].v2_len_file[0] = FIX_PS;
    check(ntx_torrent_layers_pending(&s->tts[0]) == 0, "pend_false_single_piece");
    s->tts[0].v2_len_file[0] = FIX_FILE_SIZE;
    teardown(s, n, sv, pi);
}

/* T2: apply_piece_layer accepts a correctly-derived layer and clears pending. */
static void test_apply_ok(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "apply_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "apply_setup_torrent"); teardown(s, n, sv, pi); return; }
    uint8_t pl[64];
    size_t pln = 0;
    if (fixture_layer(pl, sizeof pl, &pln) != 0 || pln != 64) {
        check(0, "apply_fixture_layer"); teardown(s, n, sv, pi); return;
    }
    check(ntx_torrent_apply_piece_layer(&s->tts[0], pl, pln) == 0, "apply_ok_returns_0");
    check(s->tts[0].piece_layer != NULL && s->tts[0].piece_layer_n == 64, "apply_stored");
    check(ntx_torrent_layers_pending(&s->tts[0]) == 0, "apply_clears_pending");
    teardown(s, n, sv, pi);
}

/* T3: apply rejects a tampered layer (a wrong slice must not be trusted). */
static void test_apply_bad(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "bad_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "bad_setup_torrent"); teardown(s, n, sv, pi); return; }
    uint8_t pl[64];
    size_t pln = 0;
    if (fixture_layer(pl, sizeof pl, &pln) != 0 || pln != 64) {
        check(0, "bad_fixture_layer"); teardown(s, n, sv, pi); return;
    }
    pl[3] ^= 0x80; /* flip one bit of the first piece hash */
    check(ntx_torrent_apply_piece_layer(&s->tts[0], pl, pln) == -1, "apply_bad_returns_1");
    check(s->tts[0].piece_layer == NULL, "apply_bad_not_stored");
    check(ntx_torrent_layers_pending(&s->tts[0]) == 1, "apply_bad_still_pending");
    /* wrong length is rejected too */
    check(ntx_torrent_apply_piece_layer(&s->tts[0], pl, 32) == -1, "apply_bad_len");
    teardown(s, n, sv, pi);
}

/* T4: the pump sends a well-formed 21 (whole piece layer) for the pending file. */
static void test_pump_sends_21(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "pump_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "pump_setup_torrent"); teardown(s, n, sv, pi); return; }
    uint32_t tx0 = s->hash_req_tx;
    ntx_session_hash_tick(s);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(rn == 53, "pump_21_len");
    check(rn >= 5 && rx[4] == 21, "pump_21_msgid");
    check(s->hash_req_tx == tx0 + 1, "pump_tx_counter");
    /* the request is the whole piece layer: base_layer=3, index=0, length=2, proof=0 */
    check(rn == 53 && rd32(rx + 5 + 32) == 3, "pump_base_layer");
    check(rn == 53 && rd32(rx + 5 + 36) == 0, "pump_index");
    check(rn == 53 && rd32(rx + 5 + 40) == 2, "pump_length");
    check(rn == 53 && rd32(rx + 5 + 44) == 0, "pump_proof_layers");
    check(rn == 53 && memcmp(rx + 5, s->tts[0].v2_root[0], 32) == 0, "pump_root");
    teardown(s, n, sv, pi);
}

/* T5: end-to-end — pump a 21, deliver the matching 22, layers get committed. */
static void test_rx_22_completes(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "rx_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "rx_setup_torrent"); teardown(s, n, sv, pi); return; }
    ntx_session_hash_tick(s);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    if (rn != 53 || rx[4] != 21) { check(0, "rx_pump_21"); teardown(s, n, sv, pi); return; }
    /* parse the request the session actually sent, then answer it */
    ntx_hash_req hdr;
    if (ntx_hash_req_parse(rx + 5, 48, &hdr) != 0) { check(0, "rx_parse_21"); teardown(s, n, sv, pi); return; }
    uint8_t pl[64];
    size_t pln = 0;
    if (fixture_layer(pl, sizeof pl, &pln) != 0 || pln != 64) { check(0, "rx_fixture"); teardown(s, n, sv, pi); return; }
    uint8_t frame[5 + 48 + 64];
    size_t fn = ntx_hash_msg_build_hashes(frame, sizeof frame, &hdr, pl, pln);
    check(fn == 5 + 48 + 64, "rx_build_22_len");
    uint32_t rx0 = s->hash_req_rx_ok;
    feed_frame(s, pi, frame, fn);
    check(s->hash_req_rx_ok == rx0 + 1, "rx_ok_counter");
    check(s->tts[0].piece_layer != NULL, "rx_layer_stored");
    check(ntx_torrent_layers_pending(&s->tts[0]) == 0, "rx_pending_cleared");
    check(s->tts[0].layers_stall == 0, "rx_no_stall");
    teardown(s, n, sv, pi);
}

/* T6: a 22 that correlates with no outstanding 21 is ignored —
 * its hashes are never ingested and the layer stays pending. */
static void test_rx_22_uncorrelated_ignored(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "unc_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "unc_setup_torrent"); teardown(s, n, sv, pi); return; }
    ntx_session_hash_tick(s);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    if (rn != 53) { check(0, "unc_pump_21"); teardown(s, n, sv, pi); return; }
    ntx_hash_req hdr;
    if (ntx_hash_req_parse(rx + 5, 48, &hdr) != 0) { check(0, "unc_parse"); teardown(s, n, sv, pi); return; }
    hdr.pieces_root[0] ^= 0xff; /* corrupt the correlation header */
    uint8_t pl[64];
    size_t pln = 0;
    if (fixture_layer(pl, sizeof pl, &pln) != 0) { check(0, "unc_fixture"); teardown(s, n, sv, pi); return; }
    uint8_t frame[5 + 48 + 64];
    size_t fn = ntx_hash_msg_build_hashes(frame, sizeof frame, &hdr, pl, pln);
    uint32_t ig0 = s->hash_ignore;
    feed_frame(s, pi, frame, fn);
    check(s->hash_ignore == ig0 + 1, "unc_ignore_counter");
    check(s->tts[0].piece_layer == NULL, "unc_not_ingested");
    check(ntx_torrent_layers_pending(&s->tts[0]) == 1, "unc_still_pending");
    teardown(s, n, sv, pi);
}

/* T7: a matching 23 marks the request failed and frees the slot (rotate). */
static void test_rx_23_frees_slot(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "rej_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "rej_setup_torrent"); teardown(s, n, sv, pi); return; }
    ntx_session_hash_tick(s);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    if (rn != 53) { check(0, "rej_pump_21"); teardown(s, n, sv, pi); return; }
    ntx_hash_req hdr;
    if (ntx_hash_req_parse(rx + 5, 48, &hdr) != 0) { check(0, "rej_parse"); teardown(s, n, sv, pi); return; }
    uint8_t frame[5 + 48];
    size_t fn = ntx_hash_msg_build_reject(frame, sizeof frame, &hdr);
    uint32_t rj0 = s->hash_rej;
    feed_frame(s, pi, frame, fn);
    check(s->hash_rej == rj0 + 1, "rej_counter");
    int any = 0;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) if (s->hash_out_used[0][k]) any = 1;
    check(any == 0, "rej_slot_freed");
    teardown(s, n, sv, pi);
}

/* T8: an outstanding 21 older than the timeout is dropped (rotate to another peer). */
static void test_timeout_rotates(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "to_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "to_setup_torrent"); teardown(s, n, sv, pi); return; }
    ntx_session_hash_tick(s);
    int slot = -1;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) if (s->hash_out_used[0][k]) slot = k;
    if (slot < 0) { check(0, "to_had_slot"); teardown(s, n, sv, pi); return; }
    /* saturate the peer budget so the freed slot is not immediately refilled */
    s->peers[pi].n_req = NTX_PEER_MAX_REQ;
    s->hash_out_t0[0][slot] = ntx_mono_ms() - (NTX_HASH_TIMEOUT_MS + 1000);
    uint32_t rj0 = s->hash_rej;
    ntx_session_hash_tick(s);
    check(s->hash_rej == rj0 + 1, "to_timeout_counts");
    check(s->hash_out_used[0][slot] == 0, "to_slot_freed");
    teardown(s, n, sv, pi);
}

/* T9: with no OK peers at all the exchange reaches a bounded layers-stall, and a
 * genuinely NEW peer re-arms it (the stall must be re-triable). */
static void test_layers_stall_bounded(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "stall_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "stall_setup_torrent"); teardown(s, n, sv, pi); return; }
    s->peers[pi].fd = -1; /* no OK peers */
    s->hash_stall_t0[0] = ntx_mono_ms() - (NTX_HASH_STALL_MS + 1000);
    ntx_session_hash_tick(s);
    check(s->tts[0].layers_stall == 1, "stall_set");
    /* a peer returns (OK-peer count rises 0 -> 1) → the bounded stall is re-armed */
    s->peers[pi].fd = sv[0];
    uint32_t tx0 = s->hash_req_tx;
    ntx_session_hash_tick(s);
    check(s->tts[0].layers_stall == 0, "stall_retriable_on_new_peer");
    check(s->hash_req_tx > tx0, "stall_rearmed_pumps");
    teardown(s, n, sv, pi);
}

/* T10: a 22 that answers a request we sent to a DIFFERENT peer is
 * ignored — the response is bound to the source peer of the outstanding 21. */
static void test_rx_22_wrong_peer_ignored(void) {
    ntx_netx *n;
    int sv1[2], sv2[2], a, b;
    ntx_session *s = mk_session_2peers(&n, sv1, sv2, &a, &b);
    if (!s) { check(0, "wp_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "wp_torrent"); teardown2(s, n, sv1, sv2, a, b); return; }
    ntx_session_hash_tick(s); /* pump sends one 21 to one of the two peers */
    uint8_t rxa[256], rxb[256];
    ssize_t ra = drain_peer_tx(s, a, sv1[1], rxa, sizeof rxa);
    ssize_t rb = drain_peer_tx(s, b, sv2[1], rxb, sizeof rxb);
    int got_a = (ra == 53 && rxa[4] == 21);
    int got_b = (rb == 53 && rxb[4] == 21);
    if (!(got_a ^ got_b)) { check(0, "wp_one_21"); teardown2(s, n, sv1, sv2, a, b); return; }
    /* the 21 went to `src`; answer it from the OTHER peer */
    int src = got_a ? a : b;
    int other = got_a ? b : a;
    int other_sv = got_a ? sv2[1] : sv1[1];
    ntx_hash_req hdr;
    if (ntx_hash_req_parse((got_a ? rxa : rxb) + 5, 48, &hdr) != 0) {
        check(0, "wp_parse"); teardown2(s, n, sv1, sv2, a, b); return;
    }
    uint8_t pl[64];
    size_t pln = 0;
    if (fixture_layer(pl, sizeof pl, &pln) != 0) { check(0, "wp_fixture"); teardown2(s, n, sv1, sv2, a, b); return; }
    uint8_t frame[5 + 48 + 64];
    size_t fn = ntx_hash_msg_build_hashes(frame, sizeof frame, &hdr, pl, pln);
    uint32_t ig0 = s->hash_ignore, ok0 = s->hash_req_rx_ok;
    feed_frame(s, other, frame, fn); /* delivered by the WRONG peer */
    check(s->hash_ignore == ig0 + 1, "wp_ignore_counter");
    check(s->hash_req_rx_ok == ok0, "wp_no_ingest");
    check(s->tts[0].piece_layer == NULL, "wp_not_committed");
    (void)src; (void)other_sv;
    /* now the correct peer answers → committed */
    uint32_t ok1 = s->hash_req_rx_ok;
    feed_frame(s, src, frame, fn);
    check(s->hash_req_rx_ok == ok1 + 1, "wp_right_peer_ok");
    check(s->tts[0].piece_layer != NULL, "wp_committed");
    teardown2(s, n, sv1, sv2, a, b);
}

/* T11: after a timeout the re-request actually goes to the OTHER
 * peer, not just expiring the slot. */
static void test_timeout_rotates_to_other_peer(void) {
    ntx_netx *n;
    int sv1[2], sv2[2], a, b;
    ntx_session *s = mk_session_2peers(&n, sv1, sv2, &a, &b);
    if (!s) { check(0, "rot_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "rot_torrent"); teardown2(s, n, sv1, sv2, a, b); return; }
    ntx_session_hash_tick(s);
    uint8_t rxa[256], rxb[256];
    ssize_t ra = drain_peer_tx(s, a, sv1[1], rxa, sizeof rxa);
    ssize_t rb = drain_peer_tx(s, b, sv2[1], rxb, sizeof rxb);
    int first_a = (ra == 53 && rxa[4] == 21);
    int first_b = (rb == 53 && rxb[4] == 21);
    check(first_a ^ first_b, "rot_first_single");
    /* expire the outstanding 21 so the pump rotates */
    int slot = -1;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) if (s->hash_out_used[0][k]) slot = k;
    if (slot < 0) { check(0, "rot_had_slot"); teardown2(s, n, sv1, sv2, a, b); return; }
    s->hash_out_t0[0][slot] = ntx_mono_ms() - (NTX_HASH_TIMEOUT_MS + 1000);
    ntx_session_hash_tick(s);
    ssize_t ra2 = drain_peer_tx(s, a, sv1[1], rxa, sizeof rxa);
    ssize_t rb2 = drain_peer_tx(s, b, sv2[1], rxb, sizeof rxb);
    int rot_ok = first_a ? (rb2 == 53 && rxb[4] == 21 && ra2 == 0)
                         : (ra2 == 53 && rxa[4] == 21 && rb2 == 0);
    check(rot_ok, "rot_second_to_other_peer");
    teardown2(s, n, sv1, sv2, a, b);
}

/* T12: once a file hits the attempt cap the exchange stalls even
 * though a peer is present — no endless 21s. */
static void test_attempts_cap_stalls(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "cap_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "cap_torrent"); teardown(s, n, sv, pi); return; }
    ntx_session_hash_tick(s); /* one attempt */
    /* pretend the file has already exhausted its attempts, nothing in flight */
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) s->hash_out_used[0][k] = 0;
    s->hash_tries[0][0] = NTX_HASH_TRIES_MAX;
    uint32_t tx0 = s->hash_req_tx;
    ntx_session_hash_tick(s);
    check(s->tts[0].layers_stall == 1, "cap_stall");
    check(s->hash_req_tx == tx0, "cap_no_more_21");
    teardown(s, n, sv, pi);
}

/* T13: layers_pending is 0 for a DEAD slot. */
static void test_dead_not_pending(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "dead_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "dead_torrent"); teardown(s, n, sv, pi); return; }
    check(ntx_torrent_layers_pending(&s->tts[0]) == 1, "dead_live_pending");
    s->tts[0].state = NTX_TTS_DEAD;
    check(ntx_torrent_layers_pending(&s->tts[0]) == 0, "dead_not_pending");
    s->tts[0].state = NTX_TTS_META;
    teardown(s, n, sv, pi);
}

/* T14: hash_reset drops scratch + outstanding + per-file state. */
static void test_hash_reset_clears(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "rst_setup"); return; }
    if (setup_v2_nolayers(s) != 0) { check(0, "rst_torrent"); teardown(s, n, sv, pi); return; }
    ntx_session_hash_tick(s);
    check(s->hash_scratch[0] != NULL, "rst_had_scratch");
    int any = 0;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) if (s->hash_out_used[0][k]) any = 1;
    check(any, "rst_had_out");
    ntx_session_hash_reset(s, 0);
    check(s->hash_scratch[0] == NULL && s->hash_scratch_n[0] == 0, "rst_scratch_gone");
    any = 0;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) if (s->hash_out_used[0][k]) any = 1;
    check(any == 0, "rst_out_gone");
    int tr = 0;
    for (int k = 0; k < NTX_TORRENT_MAX_FILES_V2; k++) tr |= s->hash_tries[0][k];
    check(tr == 0, "rst_tries_zero");
    check(s->hash_stall_t0[0] == 0, "rst_stall_zero");
    teardown(s, n, sv, pi);
}

int main(void) {
    ntx_rng_init();
    test_no_data_until_layers();
    test_layers_pending();
    test_apply_ok();
    test_apply_bad();
    test_pump_sends_21();
    test_rx_22_completes();
    test_rx_22_uncorrelated_ignored();
    test_rx_23_frees_slot();
    test_timeout_rotates();
    test_layers_stall_bounded();
    test_rx_22_wrong_peer_ignored();
    test_timeout_rotates_to_other_peer();
    test_attempts_cap_stalls();
    test_dead_not_pending();
    test_hash_reset_clears();
    return fails ? 1 : 0;
}
