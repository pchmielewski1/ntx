/* BEP52: endgame verify vectors (load, fill, verify, done).
 *
 * For each fixture (single_16k, multi_v2, hybrid_ok): load meta.torrent the
 * way the session does (ntx_be_parse -> "info" / top-level "piece layers"),
 * init the torrent with the manifest infohashes (pure v2: ih_trunc; hybrid:
 * ih_sha1 announce hash + info_hash_v2 = ih_full, meta_version = 2), fill the
 * store from the fixture's raw file bytes, verify ALL pieces via
 * ntx_torrent_verify_range, and confirm the torrent reaches done state.
 * Plus a partial-fill twist (single_16k) pinning per-piece resumable
 * verification, and the hybrid_bad_order negative gate (reject + no store).
 *
 * Self-contained TU: #includes the .c files it links against (mirrors
 * test/t_bep52_verify.c). All expected values are read at runtime from
 * test/vectors/bep52/ manifests — nothing hardcoded.
 */
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
    uint32_t idx, fp, np;
    uint64_t len;
    char path[160];
} fx_file;

typedef struct {
    uint32_t piece_len;
    uint32_t np_total;
    uint64_t addr_end;
    uint64_t data_size;
    uint8_t ih_full[32];
    uint8_t ih_trunc[20];
    uint8_t ih_sha1[20];
    fx_file files[8];
    uint32_t nfiles;
} fx;

static int parse_manifest(const char *fxname, fx *m) {
    char path[512];
    snprintf(path, sizeof path, "test/vectors/bep52/%s/manifest.txt", fxname);
    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(path, &buf, &n) != 0) return -1;
    memset(m, 0, sizeof *m);
    char *line = (char *)buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        unsigned u, u2, u3;
        unsigned long ul;
        char hex[80], root[80];
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
        } else if (m->nfiles < 8 &&
                   sscanf(line, "file: idx=%u fp=%u np=%u len=%lu root=%79s path=%159s",
                          &u, &u2, &u3, &ul, root, m->files[m->nfiles].path) == 6) {
            m->files[m->nfiles].idx = u;
            m->files[m->nfiles].fp = u2;
            m->files[m->nfiles].np = u3;
            m->files[m->nfiles].len = (uint64_t)ul;
            m->nfiles++;
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return 0;
}

/* Load a fixture's meta.torrent; on success *root owns the parsed tree and
 * *buf must stay alive (info/layers point into it). */
static int load_meta(const char *fxname, uint8_t **buf, size_t *n, ntx_be *root) {
    char path[512];
    snprintf(path, sizeof path, "test/vectors/bep52/%s/meta.torrent", fxname);
    if (read_file(path, buf, n) != 0) return -1;
    size_t consumed = 0;
    if (ntx_be_parse(*buf, *n, root, &consumed, 32, (size_t)(1u << 20)) != 0) return -1;
    return 0;
}

/* Load the fixture metainfo the way the session does, run set_metainfo, then
 * fill the store with the fixture's raw file bytes (part start = fp*ps, one
 * ntx_store_write per piece). hybrid: init with the v1-SHA-1 announce hash
 * (manifest ih_sha1); pure v2: init with trunc20(sha256(info)) (manifest
 * ih_trunc). fill_mask: 1 = write that piece, NULL = write all. */
static int setup_fx(const char *fxname, const fx *m, const char *dir, ntx_torrent *t,
                    int hybrid, const char *tag, const uint8_t *fill_mask) {
    char name[64];
    uint8_t *buf;
    size_t n;
    ntx_be root;
    if (load_meta(fxname, &buf, &n, &root) != 0) {
        snprintf(name, sizeof name, "%s-load", tag);
        check(0, name);
        return -1;
    }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) {
        snprintf(name, sizeof name, "%s-info", tag);
        check(0, name);
        ntx_be_free(&root);
        free(buf);
        return -1;
    }

    uint8_t h20[20], h32[32];
    int mv = ntx_torrent_metainfo_hash(buf + info->start, info->end - info->start, h20, h32);
    snprintf(name, sizeof name, "%s-mv2", tag);
    check(mv == 2, name);
    snprintf(name, sizeof name, "%s-h32", tag);
    check(memcmp(h32, m->ih_full, 32) == 0, name);
    if (hybrid) {
        ntx_torrent_init_meta(t, m->ih_sha1);
    } else {
        snprintf(name, sizeof name, "%s-h20", tag);
        check(memcmp(h20, m->ih_trunc, 20) == 0, name);
        ntx_torrent_init_meta(t, h20);
    }
    memcpy(t->info_hash_v2, h32, 32);
    t->meta_version = 2;

    int rc = ntx_torrent_set_metainfo(t, buf + info->start, info->end - info->start, dir, layers);
    snprintf(name, sizeof name, "%s-set", tag);
    check(rc == 0, name);
    if (rc != 0) {
        ntx_be_free(&root);
        free(buf);
        return -1;
    }

    for (uint32_t f = 0; f < m->nfiles; f++) {
        char p[512];
        snprintf(p, sizeof p, "test/vectors/bep52/%s/%s", fxname, m->files[f].path);
        uint8_t *data;
        size_t dn;
        if (read_file(p, &data, &dn) != 0 || (uint64_t)dn != m->files[f].len) {
            snprintf(name, sizeof name, "%s-fill-read", tag);
            check(0, name);
            if (data) free(data);
            ntx_be_free(&root);
            free(buf);
            return -1;
        }
        for (uint32_t k = 0; k < m->files[f].np; k++) {
            uint32_t piece = m->files[f].fp + k;
            if (fill_mask && !fill_mask[piece]) continue;
            uint64_t off = (uint64_t)k * m->piece_len;
            uint32_t chunk = (uint32_t)(m->files[f].len - off);
            if (chunk > m->piece_len) chunk = m->piece_len;
            if (ntx_store_write(&t->store, piece, 0, data + off, chunk) != 0) {
                snprintf(name, sizeof name, "%s-fill-write", tag);
                check(0, name);
                free(data);
                ntx_be_free(&root);
                free(buf);
                return -1;
            }
        }
        free(data);
    }
    ntx_be_free(&root);
    free(buf);
    return 0;
}

static void test_single_16k(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/single", g_basedir);

    fx m;
    if (parse_manifest("single_16k", &m) != 0) { check(0, "single-manifest"); return; }
    ntx_torrent t;
    if (setup_fx("single_16k", &m, dir, &t, 0, "single", NULL) != 0) {
        check(0, "single-setup");
        return;
    }
    check(t.np == m.np_total, "single-np");
    check(t.size == m.data_size, "single-size");
    check(t.meta_version == 2, "single-meta-version");
    check(t.hybrid == 0 && t.phash == NULL, "single-pure-v2");
    check(t.piece_layer != NULL, "single-layer");
    check(memcmp(t.info_hash, m.ih_trunc, 20) == 0, "single-ih-trunc");
    check(memcmp(t.info_hash_v2, m.ih_full, 32) == 0, "single-ih-full");
    check(ntx_torrent_verify_range(&t, 0, t.np) == (int)m.np_total, "single-verify_range");
    check(t.have_n == m.np_total && ntx_torrent_done(&t), "single-done");
    check(t.verified_B == m.data_size, "single-verified_B");
    ntx_store_close(&t.store);
}

static void test_multi_v2(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/multi", g_basedir);

    fx m;
    if (parse_manifest("multi_v2", &m) != 0) { check(0, "multi-manifest"); return; }
    ntx_torrent t;
    if (setup_fx("multi_v2", &m, dir, &t, 0, "multi", NULL) != 0) {
        check(0, "multi-setup");
        return;
    }
    check(t.np == m.np_total, "multi-np");
    check(t.size == m.data_size, "multi-size");
    check(t.meta_version == 2, "multi-meta-version");
    check(t.hybrid == 0 && t.phash == NULL, "multi-pure-v2");
    check(t.piece_layer != NULL, "multi-layer");
    check(memcmp(t.info_hash, m.ih_trunc, 20) == 0, "multi-ih-trunc");
    check(memcmp(t.info_hash_v2, m.ih_full, 32) == 0, "multi-ih-full");
    check(ntx_torrent_verify_range(&t, 0, t.np) == (int)m.np_total, "multi-verify_range");
    check(t.have_n == m.np_total && ntx_torrent_done(&t), "multi-done");
    check(t.verified_B == m.data_size, "multi-verified_B");
    ntx_store_close(&t.store);
}

static void test_hybrid_ok(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/hybrid", g_basedir);

    fx m;
    if (parse_manifest("hybrid_ok", &m) != 0) { check(0, "hybrid-manifest"); return; }
    ntx_torrent t;
    if (setup_fx("hybrid_ok", &m, dir, &t, 1, "hybrid", NULL) != 0) {
        check(0, "hybrid-setup");
        return;
    }
    check(t.np == m.np_total, "hybrid-np");
    check(t.size == m.data_size, "hybrid-size");
    check(t.meta_version == 2, "hybrid-meta-version");
    check(t.hybrid == 1 && t.phash != NULL, "hybrid-both");
    check(t.piece_layer != NULL, "hybrid-layer");
    check(memcmp(t.info_hash, m.ih_sha1, 20) == 0, "hybrid-ih-sha1");
    check(memcmp(t.info_hash_v2, m.ih_full, 32) == 0, "hybrid-ih-full");
    check(ntx_torrent_verify_range(&t, 0, t.np) == (int)m.np_total, "hybrid-verify_range");
    check(t.have_n == m.np_total && ntx_torrent_done(&t), "hybrid-done");
    check(t.verified_B == m.data_size, "hybrid-verified_B");
    ntx_store_close(&t.store);
}

/* Partial-fill twist: fill only pieces 0 and 2, verify (piece 1 must fail),
 * then fill piece 1 and verify again (resumable per-piece verification). */
static void test_partial_single(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/partial", g_basedir);

    fx m;
    if (parse_manifest("single_16k", &m) != 0) { check(0, "partial-manifest"); return; }
    uint8_t mask[NTX_TORRENT_MAX_FILES_V2];
    for (uint32_t i = 0; i < m.np_total; i++) mask[i] = (i != 1) ? 1 : 0;

    ntx_torrent t;
    if (setup_fx("single_16k", &m, dir, &t, 0, "partial", mask) != 0) {
        check(0, "partial-setup");
        return;
    }
    check(ntx_torrent_verify_range(&t, 0, t.np) == 2, "partial-verify2");
    check(t.have_n == 2, "partial-have2");
    check(!ntx_torrent_done(&t), "partial-not-done");

    char p[512];
    snprintf(p, sizeof p, "test/vectors/bep52/single_16k/%s", m.files[0].path);
    uint8_t *data;
    size_t dn;
    if (read_file(p, &data, &dn) != 0 || (uint64_t)dn != m.files[0].len) {
        check(0, "partial-refill-read");
        if (data) free(data);
        ntx_store_close(&t.store);
        return;
    }
    uint64_t off = (uint64_t)m.piece_len;
    uint32_t chunk = (uint32_t)(m.files[0].len - off);
    if (chunk > m.piece_len) chunk = m.piece_len;
    check(ntx_store_write(&t.store, 1, 0, data + off, chunk) == 0, "partial-fill1");
    free(data);
    check(ntx_torrent_verify_range(&t, 0, t.np) == 1, "partial-verify1");
    check(t.have_n == 3 && ntx_torrent_done(&t), "partial-done");
    ntx_store_close(&t.store);
}

/* Negative: hybrid_bad_order must be rejected (layout validation) and must
 * not create any store directory or files. */
static void test_hybrid_bad_order(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/bad", g_basedir);

    fx m;
    if (parse_manifest("hybrid_bad_order", &m) != 0) { check(0, "bad-manifest"); return; }
    uint8_t *buf;
    size_t n;
    ntx_be root;
    if (load_meta("hybrid_bad_order", &buf, &n, &root) != 0) { check(0, "bad-load"); return; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) {
        check(0, "bad-info");
        ntx_be_free(&root);
        free(buf);
        return;
    }

    ntx_torrent t;
    ntx_torrent_init_meta(&t, m.ih_sha1);
    memcpy(t.info_hash_v2, m.ih_full, 32);
    t.meta_version = 2;
    int rc = ntx_torrent_set_metainfo(&t, buf + info->start, info->end - info->start, dir, layers);
    check(rc == -1, "bad-reject");
    struct stat st;
    check(stat(dir, &st) != 0, "bad-no-store-dir");
    ntx_be_free(&root);
    free(buf);
}

int main(void) {
    char tmpl[] = "/tmp/ntx_bep52_endgame_XXXXXX";
    if (mkdtemp(tmpl) == NULL) {
        fprintf(stderr, "mkdtemp failed\n");
        return 1;
    }
    snprintf(g_basedir, sizeof g_basedir, "%s", tmpl);

    test_single_16k();
    test_multi_v2();
    test_hybrid_ok();
    test_partial_single();
    test_hybrid_bad_order();

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_basedir);
    int rm_rc = system(cmd);
    (void)rm_rc; /* cleanup best-effort; ignore failure */
    return fails ? 1 : 0;
}
