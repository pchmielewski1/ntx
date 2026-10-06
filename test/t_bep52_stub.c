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

/* BEP52 inbound hash request (21) serving.
 *
 * Every well-framed 21 is answered with a 22 (hashes) or
 * 23 (hash reject). This test drives the real session RX path (sp_process_msgs
 * via ntx_session_peer_process_inbuf) on a torrent populated with the
 * deterministic vector fixture file and asserts the responses against the
 * committed vectors in test/vectors/bep52/ (expected bytes read
 * from the committed .bin/.meta.json, never hardcoded from memory).
 *
 * Fixture (test/scripts/bep52_hash_msgs.py, seed "bep52-hash-msgs"):
 *   file = 262144 B = 16 x 16KiB leaves, tree height 4,
 *   piece length = 131072 (piece layer = 3), 2 pieces.
 */

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
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

/* Build a frame (len + id + payload) into a caller buffer; returns total len. */
static size_t build_frame(uint8_t *out, size_t cap, uint8_t id, const uint8_t *payload, size_t plen) {
    if (5 + plen > cap) return 0;
    wr32(out, (uint32_t)(1 + plen));
    out[4] = id;
    memcpy(out + 5, payload, plen);
    return 5 + plen;
}

/* Populate tts[0] as a v2 torrent over the fixture file and write the data to
 * its store. Returns 0 ok. */
static int setup_v2_torrent(ntx_session *s, const uint8_t root[32]) {
    ntx_torrent *t = &s->tts[0];
    t->ps = FIX_PS;
    t->np = FIX_NP;
    t->have_meta = 1;
    t->meta_version = 2;
    t->v2_nfiles = 1;
    memcpy(t->v2_root[0], root, 32);
    t->v2_len_file[0] = FIX_FILE_SIZE;
    t->v2_np_file[0] = FIX_NP;
    t->v2_first_piece[0] = 0;
    uint8_t *content = malloc(FIX_FILE_SIZE);
    if (!content) return -1;
    gen_content(content, FIX_FILE_SIZE);
    uint8_t pl[2 * 32];
    size_t pln = 0;
    if (ntx_merkle_file_layer(content, FIX_FILE_SIZE, FIX_PS, pl, sizeof pl, &pln) != 0 || pln != 64) {
        free(content);
        return -1;
    }
    t->piece_layer = malloc(pln);
    if (!t->piece_layer) { free(content); return -1; }
    memcpy(t->piece_layer, pl, pln);
    t->piece_layer_n = pln;
    t->have = calloc(FIX_NP, 1);
    if (!t->have) { free(content); return -1; }
    t->have[0] = 1;
    t->have[1] = 1;
    if (ntx_store_open(&t->store, "test/.scratch/4/t4.store", FIX_FILE_SIZE, FIX_PS) != 0) {
        free(content);
        return -1;
    }
    if (ntx_store_write(&t->store, 0, 0, content, FIX_PS) != 0 ||
        ntx_store_write(&t->store, 1, 0, content + FIX_PS, FIX_PS) != 0) {
        free(content);
        return -1;
    }
    free(content);
    return 0;
}

/* Session + connected peer bound to tts[0]. */
static ntx_session *mk_session_peer(ntx_netx **n, int sv[2], int *pi_out) {
    ntx_config cfg;
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

/* Leaf request (base_layer=0, proof_layers=0) on a torrent that has the
 * file -> 22 carrying just the base span (4 leaf hashes, no uncles). The
 * expected leaf hashes are derived (sha256 of each 16KiB block), not memorized. */
static void test_serve_leaf_base_only(void) {
    uint8_t root[32];
    if (!load_root("hash_request_leaf", root)) { check(0, "leaf0_root_load"); return; }
    uint8_t *reqv; size_t reqn;
    if (read_file(VEC_DIR "hash_request_leaf.bin", &reqv, &reqn) != 0) { check(0, "leaf0_req_read"); return; }

    uint8_t *content = malloc(FIX_FILE_SIZE);
    gen_content(content, FIX_FILE_SIZE);
    uint8_t exp[4 * 32];
    for (int i = 0; i < 4; i++)
        ntx_sha256(content + (size_t)i * NTX_MERKLE_LEAF, NTX_MERKLE_LEAF, exp + (size_t)i * 32);
    free(content);

    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "leaf0_setup"); free(reqv); return; }
    if (setup_v2_torrent(s, root) != 0) { check(0, "leaf0_torrent"); teardown(s, n, sv, pi); free(reqv); return; }

    feed_frame(s, pi, reqv, reqn);
    uint8_t rx[512];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    size_t exp_len = 5 + 48 + 128;
    check(rn == (ssize_t)exp_len, "leaf0_frame_len");
    check(rn >= 5 && rd32(rx) == (uint32_t)(exp_len - 4), "leaf0_hdr_len");
    check(rn >= 5 && rx[4] == 22, "leaf0_msgid_hashes");
    check(rn >= 53 && memcmp(rx + 5, reqv + 5, 48) == 0, "leaf0_header_echo");
    check(rn == (ssize_t)exp_len && memcmp(rx + 5 + 48, exp, 128) == 0, "leaf0_hashes_match_derived");
    check(s->peer_phase[pi] == PH_OK, "leaf0_peer_stays_ok");

    teardown(s, n, sv, pi);
    free(reqv);
}

/* Leaf request with proof_layers=3 (length=4 -> layer 1 omitted, layers
 * 2+3 uncles on the wire) -> 22 byte-identical to the committed
 * hashes_omitted_proof_layers vector (full-frame compare). */
static void test_serve_leaf_proof_omission(void) {
    uint8_t root[32];
    if (!load_root("hash_request_leaf", root)) { check(0, "leaf3_root_load"); return; }
    uint8_t *reqv; size_t reqn;
    if (read_file(VEC_DIR "hash_request_leaf.bin", &reqv, &reqn) != 0) { check(0, "leaf3_req_read"); return; }
    uint8_t *hsv; size_t hsn;
    if (read_file(VEC_DIR "hashes_omitted_proof_layers.bin", &hsv, &hsn) != 0) {
        check(0, "leaf3_hash_read"); free(reqv); return;
    }
    /* Build the proof_layers=3 request from the leaf request (same root/base/
     * index/length); proof_layers is the last uint32 of the 48 B payload. */
    uint8_t req_frame[5 + 48];
    memcpy(req_frame, reqv, reqn);
    wr32(req_frame + 5 + 44, 3);

    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "leaf3_setup"); free(reqv); free(hsv); return; }
    if (setup_v2_torrent(s, root) != 0) { check(0, "leaf3_torrent"); teardown(s, n, sv, pi); free(reqv); free(hsv); return; }

    feed_frame(s, pi, req_frame, sizeof req_frame);
    uint8_t rx[1024];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(rn == (ssize_t)hsn, "leaf3_frame_len");
    check(rn >= 5 && rx[4] == 22, "leaf3_msgid_hashes");
    check(rn == (ssize_t)hsn && memcmp(rx, hsv, hsn) == 0, "leaf3_frame_equals_vector");
    check(s->peer_phase[pi] == PH_OK, "leaf3_peer_stays_ok");

    teardown(s, n, sv, pi);
    free(reqv);
    free(hsv);
}

/* Piece-layer request (base_layer=3) -> 22 whose hashes equal the piece
 * layer derived from the stored bytes (== the overlay of t->piece_layer). */
static void test_serve_piece_layer_22(void) {
    uint8_t root[32];
    if (!load_root("hash_request_piece_layer", root)) { check(0, "pl_root_load"); return; }
    uint8_t *reqv; size_t reqn;
    if (read_file(VEC_DIR "hash_request_piece_layer.bin", &reqv, &reqn) != 0) { check(0, "pl_req_read"); return; }

    /* expected piece layer (derived, not memorized) */
    uint8_t *content = malloc(FIX_FILE_SIZE);
    gen_content(content, FIX_FILE_SIZE);
    uint8_t exp[64];
    size_t expn = 0;
    int ok_derive = ntx_merkle_file_layer(content, FIX_FILE_SIZE, FIX_PS, exp, sizeof exp, &expn) == 0 && expn == 64;
    free(content);
    check(ok_derive, "pl_derive_ok");

    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "pl_setup"); free(reqv); return; }
    if (setup_v2_torrent(s, root) != 0) { check(0, "pl_torrent"); teardown(s, n, sv, pi); free(reqv); return; }

    feed_frame(s, pi, reqv, reqn);
    uint8_t rx[512];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    size_t exp_len = 5 + 48 + 64;
    check(rn == (ssize_t)exp_len, "pl_frame_len");
    check(rn >= 5 && rx[4] == 22, "pl_msgid_hashes");
    check(rn >= 53 && memcmp(rx + 5, reqv + 5, 48) == 0, "pl_header_echo");
    check(ok_derive && rn == (ssize_t)exp_len && memcmp(rx + 5 + 48, exp, 64) == 0, "pl_hashes_match_derived");
    check(s->peer_phase[pi] == PH_OK, "pl_peer_stays_ok");

    teardown(s, n, sv, pi);
    free(reqv);
}

/* One reject case: feed a frame, expect a 23 with the payload echoed 1:1. */
static void run_reject_case(const char *name, const uint8_t *frame, size_t fn) {
    uint8_t root[32];
    if (!load_root("hash_request_leaf", root)) { check(0, name); return; }
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, name); return; }
    if (setup_v2_torrent(s, root) != 0) { check(0, name); teardown(s, n, sv, pi); return; }

    feed_frame(s, pi, frame, fn);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    size_t plen = fn - 5;
    size_t exp_len = 5 + plen;
    check(rn == (ssize_t)exp_len, name);
    check(rn >= 5 && rx[4] == 23, "reject_msgid");
    check(rn == (ssize_t)exp_len && memcmp(rx + 5, frame + 5, plen) == 0, "reject_payload_echo");
    check(s->peer_phase[pi] == PH_OK, "reject_peer_stays_ok");

    teardown(s, n, sv, pi);
}

/* Illegal-length and illegal-index requests -> 23 echo (even though the
 * root is known, constraints fail first). */
static void test_reject_illegal(void) {
    uint8_t *a; size_t an;
    if (read_file(VEC_DIR "hash_request_illegal_length.bin", &a, &an) != 0) { check(0, "illegal_len_read"); return; }
    run_reject_case("reject_illegal_length", a, an);
    free(a);
    uint8_t *b; size_t bn;
    if (read_file(VEC_DIR "hash_request_illegal_index.bin", &b, &bn) != 0) { check(0, "illegal_idx_read"); return; }
    run_reject_case("reject_illegal_index", b, bn);
    free(b);
}

/* Legal request with an unknown pieces root -> 23 echo. */
static void test_reject_unknown_root(void) {
    uint8_t payload[48];
    memset(payload, 0, sizeof payload);
    for (int i = 0; i < 32; i++) payload[i] = (uint8_t)(0xEE ^ i); /* bogus root */
    wr32(payload + 32, 0);  /* base_layer */
    wr32(payload + 36, 0);  /* index */
    wr32(payload + 40, 2);  /* length */
    wr32(payload + 44, 0);  /* proof_layers */
    uint8_t frame[5 + 48];
    size_t fn = build_frame(frame, sizeof frame, 21, payload, 48);
    check(fn == 53, "unknown_frame_build");
    run_reject_case("reject_unknown_root", frame, fn);
}

/* Known root but the torrent has no piece layers -> 23 echo. */
static void test_reject_no_layers(void) {
    uint8_t root[32];
    if (!load_root("hash_request_leaf", root)) { check(0, "nolayers_root"); return; }
    uint8_t *reqv; size_t reqn;
    if (read_file(VEC_DIR "hash_request_leaf.bin", &reqv, &reqn) != 0) { check(0, "nolayers_req"); return; }

    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "nolayers_setup"); free(reqv); return; }
    if (setup_v2_torrent(s, root) != 0) { check(0, "nolayers_torrent"); teardown(s, n, sv, pi); free(reqv); return; }
    free(s->tts[0].piece_layer);
    s->tts[0].piece_layer = NULL;
    s->tts[0].piece_layer_n = 0;

    feed_frame(s, pi, reqv, reqn);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(rn == 53, "nolayers_reject_len");
    check(rn >= 5 && rx[4] == 23, "nolayers_msgid");
    check(rn == 53 && memcmp(rx + 5, reqv + 5, 48) == 0, "nolayers_payload_echo");

    teardown(s, n, sv, pi);
    free(reqv);
}

/* Well-framed but too short to be a request (< 48 B) -> no response. */
static void test_short_ignored(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "short_setup"); return; }
    uint8_t payload[20];
    for (int i = 0; i < 20; i++) payload[i] = (uint8_t)(0x10 + i);
    uint8_t frame[5 + 20];
    size_t fn = build_frame(frame, sizeof frame, 21, payload, 20);
    feed_frame(s, pi, frame, fn);
    uint8_t rx[128];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(rn == 0, "short_no_response");
    check(s->peer_phase[pi] == PH_OK, "short_peer_stays_ok");
    check(s->peer_buflen[pi] == 0, "short_input_consumed");
    teardown(s, n, sv, pi);
}

/* Oversized payload (not a 48 B request) -> no response. */
static void test_over_cap_ignored(void) {
    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "cap_setup"); return; }
    static uint8_t payload[16385];
    for (size_t i = 0; i < sizeof payload; i++) payload[i] = (uint8_t)(i * 7 + 3);
    uint8_t *frame = malloc(5 + sizeof payload);
    size_t fn = build_frame(frame, 5 + sizeof payload, 21, payload, sizeof payload);
    feed_frame(s, pi, frame, fn);
    uint8_t rx[128];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(rn == 0, "cap_no_response");
    check(s->peer_phase[pi] == PH_OK, "cap_peer_stays_ok");
    check(s->peer_buflen[pi] == 0, "cap_input_consumed");
    free(frame);
    teardown(s, n, sv, pi);
}

/* OOB: legal constraints (index%length==0) but index beyond the
 * base layer width. Fixture: n_leaf=16 -> p=16, tree=31 slots (992 B). base=0,
 * length=2, proof=0, index=64 passes constraints and base+lg<=height but would
 * read tree + 64*32 = 2048 B past the 992 B heap block without the bound.
 * Must now be a 23 echo (reject), not a crash / OOB read. */
static void test_reject_index_oob(void) {
    uint8_t root[32];
    if (!load_root("hash_request_leaf", root)) { check(0, "oob_root"); return; }
    uint8_t payload[48];
    memset(payload, 0, sizeof payload);
    memcpy(payload, root, 32);
    wr32(payload + 32, 0);  /* base_layer */
    wr32(payload + 36, 64); /* index (>= base_width=16) */
    wr32(payload + 40, 2);  /* length (pow2>=2; 64%2==0 so constraints pass) */
    wr32(payload + 44, 0);  /* proof_layers */
    uint8_t frame[5 + 48];
    size_t fn = build_frame(frame, sizeof frame, 21, payload, 48);
    check(fn == 53, "oob_frame_build");
    run_reject_case("reject_index_oob", frame, fn);
}

/* Rate gate: a request that would otherwise be served with a 22
 * (the leaf base-only vector) is refused with a 23 once the peer is at its
 * outstanding-request budget (n_req == NTX_PEER_MAX_REQ), proving the serve path
 * reuses the piece-request budget rather than rebuilding the tree per request. */
static void test_rate_limit_rejects(void) {
    uint8_t root[32];
    if (!load_root("hash_request_leaf", root)) { check(0, "rl_root"); return; }
    uint8_t *reqv; size_t reqn;
    if (read_file(VEC_DIR "hash_request_leaf.bin", &reqv, &reqn) != 0) { check(0, "rl_req_read"); return; }

    ntx_netx *n;
    int sv[2], pi;
    ntx_session *s = mk_session_peer(&n, sv, &pi);
    if (!s) { check(0, "rl_setup"); free(reqv); return; }
    if (setup_v2_torrent(s, root) != 0) { check(0, "rl_torrent"); teardown(s, n, sv, pi); free(reqv); return; }

    s->peers[pi].n_req = NTX_PEER_MAX_REQ; /* saturate the reused budget */
    feed_frame(s, pi, reqv, reqn);
    uint8_t rx[256];
    ssize_t rn = drain_peer_tx(s, pi, sv[1], rx, sizeof rx);
    check(rn == 53, "rate_reject_len");
    check(rn >= 5 && rx[4] == 23, "rate_reject_msgid");
    check(rn == 53 && memcmp(rx + 5, reqv + 5, 48) == 0, "rate_reject_payload_echo");
    check(s->peer_phase[pi] == PH_OK, "rate_peer_stays_ok");

    teardown(s, n, sv, pi);
    free(reqv);
}

int main(void) {
    ntx_rng_init();
    test_serve_leaf_base_only();
    test_serve_leaf_proof_omission();
    test_serve_piece_layer_22();
    test_reject_illegal();
    test_reject_unknown_root();
    test_reject_no_layers();
    test_short_ignored();
    test_over_cap_ignored();
    test_reject_index_oob();
    test_rate_limit_rejects();
    return fails ? 1 : 0;
}
