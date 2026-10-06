#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_store.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/ui/ntx_diag.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond)
        printf("PASS %s\n", name);
    else {
        printf("FAIL %s\n", name);
        fails = 1;
    }
}

static char g_basedir[64];

static int read_file(const char *path, uint8_t **out, size_t *out_n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    uint8_t *buf = malloc((size_t)(sz > 0 ? sz : 0) + 1);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return -1; }
    buf[sz] = 0; /* NUL-terminated: callers parse the data as text */
    *out = buf;
    *out_n = (size_t)sz;
    return 0;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != n * 2) return -1;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

typedef struct {
    uint32_t piece_len;
    uint32_t np_total;
    uint64_t addr_end;
    uint64_t data_size;
    uint8_t ih_full[32];
    uint8_t ih_trunc[20];
    uint8_t ih_sha1[20];
} manifest;

static int parse_manifest(const char *fx, manifest *m) {
    char path[512];
    snprintf(path, sizeof path, "test/vectors/bep52/%s/manifest.txt", fx);
    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(path, &buf, &n) != 0) return -1;
    memset(m, 0, sizeof *m);
    char *line = (char *)buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        unsigned u;
        unsigned long ul;
        char hex[80];
        if (sscanf(line, "piece_len: %u", &u) == 1) {
            m->piece_len = u;
        } else if (sscanf(line, "np_total: %u", &u) == 1) {
            m->np_total = u;
        } else if (sscanf(line, "addr_end: %lu", &ul) == 1) {
            m->addr_end = (uint64_t)ul;
        } else if (sscanf(line, "data_size: %lu", &ul) == 1) {
            m->data_size = (uint64_t)ul;
        } else if (sscanf(line, "ih_full: %79s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_full, 32) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "ih_trunc: %79s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_trunc, 20) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "ih_sha1: %79s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_sha1, 20) != 0) { free(buf); return -1; }
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return 0;
}

static int stat_size(const char *path, uint64_t *size) {
    struct stat st;
    if (stat(path, &st) != 0) return -1;
    *size = (uint64_t)st.st_size;
    return 0;
}

/* Load a fixture's meta.torrent; on success *root owns the parsed tree and
 * *buf must stay alive (info/layers point into it). */
static int load_meta(const char *fx, uint8_t **buf, size_t *n, ntx_be *root) {
    char path[512];
    snprintf(path, sizeof path, "test/vectors/bep52/%s/meta.torrent", fx);
    if (read_file(path, buf, n) != 0) return -1;
    size_t consumed = 0;
    if (ntx_be_parse(*buf, *n, root, &consumed, 32, (size_t)(1u << 20)) != 0) return -1;
    return 0;
}

static void test_single_16k(void) {
    const char *fx = "single_16k";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "single-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/single", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "single-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) { check(0, "single-info"); ntx_be_free(&root); free(buf); return; }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, layers);
    check(rc == 0, "single-set");
    check(t.np == 3, "single-np");
    check(t.size == 40000, "single-size");
    check(t.piece_layer_n == 96, "single-layer_n");
    check(t.phash == NULL, "single-phash-null");
    check(t.hybrid == 0, "single-hybrid-0");
    check(t.meta_version == 2, "single-meta-version");
    char sf[200];
    snprintf(sf, sizeof sf, "%s/single_16k", dir);
    uint64_t sz;
    check(stat_size(sf, &sz) == 0 && sz == 40000, "single-store-file");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

static void test_multi_v2(void) {
    const char *fx = "multi_v2";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "multi-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/multi", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "multi-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) { check(0, "multi-info"); ntx_be_free(&root); free(buf); return; }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, layers);
    check(rc == 0, "multi-set");
    check(t.np == 5, "multi-np");
    check(t.size == 351000, "multi-size");
    /* Frozen ntx_torrent_v2_layers emits only files with len > ps (here just
     * dir/b.dat, np=3) => 96 bytes, not np_total*32. See final-report note. */
    check(t.piece_layer_n == 96, "multi-layer_n");
    check(t.phash == NULL, "multi-phash-null");
    check(t.hybrid == 0, "multi-hybrid-0");
    uint64_t sz;
    char f0[200], f1[200], f2[200];
    snprintf(f0, sizeof f0, "%s/a.txt", dir);
    snprintf(f1, sizeof f1, "%s/dir/b.dat", dir);
    snprintf(f2, sizeof f2, "%s/dir/c.bin", dir);
    check(stat_size(f0, &sz) == 0 && sz == 50000, "multi-part0");
    check(stat_size(f1, &sz) == 0 && sz == 300000, "multi-part1");
    check(stat_size(f2, &sz) == 0 && sz == 1000, "multi-part2");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

static void test_hybrid_ok(void) {
    const char *fx = "hybrid_ok";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "hybrid-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/hybrid", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "hybrid-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) { check(0, "hybrid-info"); ntx_be_free(&root); free(buf); return; }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_sha1);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, layers);
    check(rc == 0, "hybrid-set");
    check(t.np == 4, "hybrid-np");
    check(t.size == 50000, "hybrid-size");
    check(t.hybrid == 1, "hybrid-hybrid");
    check(t.phash != NULL, "hybrid-phash");
    check(t.piece_layer_n == 128, "hybrid-layer_n");
    check(t.meta_version == 2, "hybrid-meta-version");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

static void test_hybrid_bad_order(void) {
    const char *fx = "hybrid_bad_order";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "bad-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/bad", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "bad-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) { check(0, "bad-info"); ntx_be_free(&root); free(buf); return; }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_sha1);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, layers);
    check(rc == -1, "bad-order-reject");
    ntx_be_free(&root);
    free(buf);
}

static void test_wrong_v2_hash(void) {
    const char *fx = "single_16k";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "wronghash-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/wronghash", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "wronghash-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    t.info_hash_v2[0] ^= 0x01;
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, layers);
    check(rc == -1, "wronghash-reject");
    ntx_be_free(&root);
    free(buf);
}

/* ut_metadata carries the info dict only — top-level
 * "piece layers" never arrives via BEP9. Assembling a pure-v2 info without
 * layers MUST be accepted (rc 0), the torrent must leave the META state (the
 * meta pump stops: no reject loop), and layers_pending must report 1 so the
 * session's BEP52 hash pump requests them (21/22/23). */
static void test_pure_v2_no_layers(void) {
    const char *fx = "single_16k";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "nolayers-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/nolayers", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "nolayers-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, NULL);
    check(rc == 0, "nolayers-accept");
    check(t.have_meta == 1, "nolayers-have-meta");
    check(t.meta_version == 2, "nolayers-meta-version");
    check(t.hybrid == 0, "nolayers-hybrid-0");
    check(t.piece_layer == NULL && t.piece_layer_n == 0, "nolayers-layer-null");
    check(ntx_torrent_layers_pending(&t) == 1, "nolayers-pending");
    check(t.state != NTX_TTS_META, "nolayers-leaves-meta-state"); /* no assemble spin */
    uint64_t sz;
    char sf[200];
    snprintf(sf, sizeof sf, "%s/single_16k", dir);
    check(stat_size(sf, &sz) == 0 && sz == 40000, "nolayers-store-opened");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

/* While the layers of a multi-piece file are still pending, a downloaded piece
 * must NOT be blindly trusted (tt_piece_verify's "cross-check off" shortcut is
 * only sound when the v1 SHA-1 actually verified, i.e. hybrid/v1). Junk bytes
 * must fail verification instead of being marked have. */
static void test_pure_v2_nolayers_no_blind_trust(void) {
    const char *fx = "single_16k";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "blind-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/blind", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "blind-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, NULL);
    check(rc == 0 && ntx_torrent_layers_pending(&t) == 1, "blind-setup");
    static uint8_t junk[16384];
    for (uint32_t i = 0; i < sizeof junk; i++) junk[i] = (uint8_t)(i * 7 + 3);
    check(ntx_store_write(&t.store, 0, 0, junk, sizeof junk) == 0, "blind-write");
    check(ntx_torrent_piece_complete_from(&t, 0, NULL, 1) == 0, "blind-piece-reject");
    check(t.have == NULL || t.have[0] == 0, "blind-not-have");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

/* A failed cross-check while layers are pending is "cannot verify yet", not
 * "bad data": banning every peer that serves a piece before the layers arrive
 * would starve the very hash exchange that delivers them. No ban while
 * layers_pending. */
static void test_pure_v2_nolayers_no_ban(void) {
    const char *fx = "single_16k";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "noban-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/noban", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "noban-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, NULL);
    check(rc == 0 && ntx_torrent_layers_pending(&t) == 1, "noban-setup");
    static uint8_t junk[16384];
    for (uint32_t i = 0; i < sizeof junk; i++) junk[i] = (uint8_t)(i * 11 + 5);
    (void)ntx_store_write(&t.store, 1, 0, junk, sizeof junk);
    ntx_peer src;
    memset(&src, 0, sizeof src);
    check(ntx_torrent_piece_complete_from(&t, 1, &src, 1000) == 0, "noban-piece-fail");
    check(ntx_torrent_peer_banned(&src, 1000) == 0, "noban-no-ban");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

/* Regression (Step 2): hybrid without layers keeps working via the v1 SHA-1
 * verify path; layers stay optional and layers_pending must NOT fire. */
static void test_hybrid_no_layers(void) {
    const char *fx = "hybrid_ok";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "hybnol-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/hybnol", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "hybnol-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    if (!info || info->t != NTX_BE_DICT) { check(0, "hybnol-info"); ntx_be_free(&root); free(buf); return; }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_sha1);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, NULL);
    check(rc == 0, "hybnol-accept");
    check(t.hybrid == 1, "hybnol-hybrid");
    check(t.phash != NULL, "hybnol-phash");
    check(t.piece_layer == NULL, "hybnol-layer-null");
    check(ntx_torrent_layers_pending(&t) == 0, "hybnol-not-pending");
    check(t.meta_version == 2, "hybnol-meta-version");
    ntx_store_close(&t.store);
    ntx_be_free(&root);
    free(buf);
}

/* Rebuild a standalone "piece layers" dict from the fixture's layers, with one
 * byte of the first value flipped, so the root/layer cross-check fails. */
static int build_corrupted_layers(const ntx_be *layers, uint8_t **out, size_t *out_n) {
    if (!layers || layers->nd == 0) return -1;
    const ntx_be *k = layers->k[0];
    const ntx_be *v = layers->v[0];
    if (!k || k->t != NTX_BE_STR || k->sn != 32 || !v || v->t != NTX_BE_STR || v->sn == 0) return -1;
    char kh[16], vh[16];
    int klen = snprintf(kh, sizeof kh, "%zu:", k->sn);
    int vlen = snprintf(vh, sizeof vh, "%zu:", v->sn);
    size_t total = 1 + (size_t)klen + k->sn + (size_t)vlen + v->sn + 1;
    uint8_t *b = malloc(total);
    if (!b) return -1;
    size_t o = 0;
    b[o++] = 'd';
    memcpy(b + o, kh, (size_t)klen); o += (size_t)klen;
    memcpy(b + o, k->sp, k->sn); o += k->sn;
    memcpy(b + o, vh, (size_t)vlen); o += (size_t)vlen;
    memcpy(b + o, v->sp, v->sn); o += v->sn;
    b[o++] = 'e';
    b[o - 2] ^= 0x01; /* flip last byte of the value */
    *out = b;
    *out_n = o;
    return 0;
}

static void test_corrupted_layers(void) {
    const char *fx = "single_16k";
    manifest m;
    if (parse_manifest(fx, &m) != 0) { check(0, "corrupt-manifest"); return; }
    char dir[128];
    snprintf(dir, sizeof dir, "%s/corrupt", g_basedir);

    uint8_t *buf; size_t n;
    ntx_be root;
    if (load_meta(fx, &buf, &n, &root) != 0) { check(0, "corrupt-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || !layers) { check(0, "corrupt-info"); ntx_be_free(&root); free(buf); return; }

    uint8_t *cb; size_t cn;
    if (build_corrupted_layers(layers, &cb, &cn) != 0) {
        check(0, "corrupt-build");
        ntx_be_free(&root);
        free(buf);
        return;
    }
    ntx_be cdict;
    size_t cconsumed = 0;
    if (ntx_be_parse(cb, cn, &cdict, &cconsumed, 32, (size_t)(1u << 20)) != 0) {
        check(0, "corrupt-parse");
        free(cb);
        ntx_be_free(&root);
        free(buf);
        return;
    }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_trunc);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, &cdict);
    check(rc == -1, "corrupt-reject");
    ntx_be_free(&cdict);
    free(cb);
    ntx_be_free(&root);
    free(buf);
}

static void test_invalid_meta_version(void) {
    char dir[128];
    snprintf(dir, sizeof dir, "%s/invmeta", g_basedir);

    /* meta version 3 (> 2) -> hard reject. */
    const char *infoA = "d8:meta versioni3e4:name4:xxee";
    uint8_t ihA[32];
    ntx_sha256(infoA, strlen(infoA), ihA);
    ntx_torrent tA;
    ntx_torrent_init_meta(&tA, ihA);
    memcpy(tA.info_hash_v2, ihA, 32);
    int rcA = ntx_torrent_set_metainfo(&tA, (const uint8_t *)infoA, strlen(infoA), dir, NULL);
    check(rcA == -1, "invmeta-v3-reject");

    /* meta version 2 but no "file tree" -> reject. */
    const char *infoB = "d12:piece lengthi16384e8:meta versioni2e4:name4:xxee";
    uint8_t ihB[32];
    ntx_sha256(infoB, strlen(infoB), ihB);
    ntx_torrent tB;
    ntx_torrent_init_meta(&tB, ihB);
    memcpy(tB.info_hash_v2, ihB, 32);
    int rcB = ntx_torrent_set_metainfo(&tB, (const uint8_t *)infoB, strlen(infoB), dir, NULL);
    check(rcB == -1, "invmeta-v2-no-tree-reject");
}

static void test_bad_ps(void) {
    char dir[128];
    snprintf(dir, sizeof dir, "%s/badps", g_basedir);

    static uint8_t data[16384];
    for (int i = 0; i < 16384; i++) data[i] = (uint8_t)(i * 3 + 1);
    uint8_t root[32];
    ntx_sha256(data, 16384, root); /* single 16KiB leaf => merkle root == sha256 */

    char info[512];
    size_t o;
    /* piece length 8192 (< 16384) */
    o = (size_t)snprintf(info, sizeof info,
                         "d12:piece lengthi8192e8:meta versioni2e4:name4:xxe9:file treed4:xxxd0:d6:lengthi16384e11:pieces root32:");
    memcpy(info + o, root, 32); o += 32;
    o += (size_t)snprintf(info + o, sizeof info - o, "eee");
    uint8_t ih1[32];
    ntx_sha256(info, o, ih1);
    ntx_torrent t1;
    ntx_torrent_init_meta(&t1, ih1);
    memcpy(t1.info_hash_v2, ih1, 32);
    int rc1 = ntx_torrent_set_metainfo(&t1, (const uint8_t *)info, o, dir, NULL);
    check(rc1 == -1, "badps-8192-reject");

    /* piece length 20000 (not a power of two) */
    o = (size_t)snprintf(info, sizeof info,
                         "d12:piece lengthi20000e8:meta versioni2e4:name4:xxe9:file treed4:xxxd0:d6:lengthi16384e11:pieces root32:");
    memcpy(info + o, root, 32); o += 32;
    o += (size_t)snprintf(info + o, sizeof info - o, "eee");
    uint8_t ih2[32];
    ntx_sha256(info, o, ih2);
    ntx_torrent t2;
    ntx_torrent_init_meta(&t2, ih2);
    memcpy(t2.info_hash_v2, ih2, 32);
    int rc2 = ntx_torrent_set_metainfo(&t2, (const uint8_t *)info, o, dir, NULL);
    check(rc2 == -1, "badps-20000-reject");
}

int main(void) {
    snprintf(g_basedir, sizeof g_basedir, "/tmp/ntx_bep52_meta_%d", (int)getpid());
    (void)mkdir(g_basedir, 0755);

    test_single_16k();
    test_multi_v2();
    test_hybrid_ok();
    test_hybrid_bad_order();
    test_wrong_v2_hash();
    test_pure_v2_no_layers();
    test_pure_v2_nolayers_no_blind_trust();
    test_pure_v2_nolayers_no_ban();
    test_hybrid_no_layers();
    test_corrupted_layers();
    test_invalid_meta_version();
    test_bad_ps();

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_basedir);
    int rm_rc = system(cmd);
    (void)rm_rc; /* cleanup best-effort */
    return fails ? 1 : 0;
}
