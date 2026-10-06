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

/* Load the fixture metainfo, run set_metainfo (ih20 = ih_trunc for pure v2,
 * ih_sha1 for hybrid), then fill the store with the fixture's raw file bytes
 * (part start = fp*ps, one ntx_store_write per piece). */
static int setup_fx(const char *fxname, const char *dir, ntx_torrent *t, int hybrid) {
    fx m;
    if (parse_manifest(fxname, &m) != 0) return -1;
    uint8_t *buf;
    size_t n;
    ntx_be root;
    if (load_meta(fxname, &buf, &n, &root) != 0) return -1;
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT) { ntx_be_free(&root); free(buf); return -1; }
    ntx_torrent_init_meta(t, hybrid ? m.ih_sha1 : m.ih_trunc);
    memcpy(t->info_hash_v2, m.ih_full, 32);
    int rc = ntx_torrent_set_metainfo(t, buf + info->start, info->end - info->start, dir, layers);
    if (rc != 0) { ntx_be_free(&root); free(buf); return -1; }
    for (uint32_t f = 0; f < m.nfiles; f++) {
        char p[512];
        snprintf(p, sizeof p, "test/vectors/bep52/%s/%s", fxname, m.files[f].path);
        uint8_t *data;
        size_t dn;
        if (read_file(p, &data, &dn) != 0 || (uint64_t)dn != m.files[f].len) {
            if (data) free(data);
            ntx_be_free(&root);
            free(buf);
            return -1;
        }
        for (uint32_t k = 0; k < m.files[f].np; k++) {
            uint64_t off = (uint64_t)k * m.piece_len;
            uint32_t chunk = (uint32_t)(m.files[f].len - off);
            if (chunk > m.piece_len) chunk = m.piece_len;
            if (ntx_store_write(&t->store, m.files[f].fp + k, 0, data + off, chunk) != 0) {
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

/* Flip one stored byte (read, xor 1, write back). */
static int flip_store_byte(ntx_torrent *t, uint32_t piece, uint32_t off) {
    uint8_t b;
    if (ntx_store_read(&t->store, piece, off, &b, 1) != 1) return -1;
    b ^= 0x01;
    return ntx_store_write(&t->store, piece, off, &b, 1);
}

static void test_single_16k(void) {
    char dir[160], dir2[160];
    snprintf(dir, sizeof dir, "%s/single", g_basedir);
    snprintf(dir2, sizeof dir2, "%s/single_vr", g_basedir);

    ntx_torrent t;
    if (setup_fx("single_16k", dir, &t, 0) != 0) { check(0, "single-setup"); return; }
    check(t.np == 3, "single-np");
    check(t.meta_version == 2 && t.phash == NULL, "single-pure-v2");
    check(t.piece_layer_n == 96, "single-layer_n");
    check(ntx_torrent_piece_complete_from(&t, 0, NULL, 0) == 1, "single-piece0");
    check(ntx_torrent_piece_complete_from(&t, 1, NULL, 0) == 1, "single-piece1");
    check(ntx_torrent_piece_complete_from(&t, 2, NULL, 0) == 1, "single-piece2-short");
    check(t.have_n == 3 && t.verified_B == 40000, "single-accounting");
    check(ntx_torrent_done(&t), "single-done");
    check(ntx_torrent_piece_complete_from(&t, 3, NULL, 0) == 0, "single-oob");
    ntx_store_close(&t.store);

    ntx_torrent t2;
    if (setup_fx("single_16k", dir2, &t2, 0) != 0) { check(0, "single-vr-setup"); return; }
    check(ntx_torrent_verify_range(&t2, 0, 3) == 3, "single-verify_range");
    check(t2.have_n == 3 && ntx_torrent_done(&t2), "single-vr-done");
    ntx_store_close(&t2.store);
}

static void test_multi_v2(void) {
    char dir[160], dir2[160];
    snprintf(dir, sizeof dir, "%s/multi", g_basedir);
    snprintf(dir2, sizeof dir2, "%s/multi_vr", g_basedir);

    ntx_torrent t;
    if (setup_fx("multi_v2", dir, &t, 0) != 0) { check(0, "multi-setup"); return; }
    check(t.np == 5, "multi-np");
    check(t.meta_version == 2 && t.phash == NULL, "multi-pure-v2");
    /* only dir/b.dat (len > ps, np 3) contributes to the layer: 3*32, not 5*32 */
    check(t.piece_layer_n == 96, "multi-layer_n");
    check(ntx_torrent_piece_complete_from(&t, 0, NULL, 0) == 1, "multi-piece0-root");
    check(ntx_torrent_piece_complete_from(&t, 1, NULL, 0) == 1, "multi-piece1");
    check(ntx_torrent_piece_complete_from(&t, 2, NULL, 0) == 1, "multi-piece2");
    check(ntx_torrent_piece_complete_from(&t, 3, NULL, 0) == 1, "multi-piece3-short");
    check(ntx_torrent_piece_complete_from(&t, 4, NULL, 0) == 1, "multi-piece4-root");
    check(t.have_n == 5 && t.verified_B == 351000, "multi-accounting");
    check(ntx_torrent_done(&t), "multi-done");
    check(ntx_torrent_piece_complete_from(&t, 5, NULL, 0) == 0, "multi-oob");
    ntx_store_close(&t.store);

    ntx_torrent t2;
    if (setup_fx("multi_v2", dir2, &t2, 0) != 0) { check(0, "multi-vr-setup"); return; }
    check(ntx_torrent_verify_range(&t2, 0, 5) == 5, "multi-verify_range");
    check(t2.have_n == 5 && ntx_torrent_done(&t2), "multi-vr-done");
    ntx_store_close(&t2.store);
}

static void test_hybrid_ok(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/hybrid", g_basedir);

    ntx_torrent t;
    if (setup_fx("hybrid_ok", dir, &t, 1) != 0) { check(0, "hybrid-setup"); return; }
    check(t.np == 4, "hybrid-np");
    check(t.hybrid == 1 && t.meta_version == 2 && t.phash != NULL, "hybrid-both");
    check(t.piece_layer_n == 128, "hybrid-layer_n");
    check(ntx_torrent_piece_complete_from(&t, 0, NULL, 0) == 1, "hybrid-piece0");
    check(ntx_torrent_piece_complete_from(&t, 1, NULL, 0) == 1, "hybrid-piece1");
    check(ntx_torrent_piece_complete_from(&t, 2, NULL, 0) == 1, "hybrid-piece2");
    check(ntx_torrent_piece_complete_from(&t, 3, NULL, 0) == 1, "hybrid-piece3-short");
    check(t.have_n == 4 && t.verified_B == 50000, "hybrid-accounting");
    check(ntx_torrent_done(&t), "hybrid-done");
    check(ntx_torrent_piece_complete_from(&t, 4, NULL, 0) == 0, "hybrid-oob");
    ntx_store_close(&t.store);
}

static void test_corrupt_single(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/corr_single", g_basedir);

    ntx_torrent t;
    if (setup_fx("single_16k", dir, &t, 0) != 0) { check(0, "corr-single-setup"); return; }
    /* flip one byte in the middle of piece 1's data region */
    if (flip_store_byte(&t, 1, 8192) != 0) { check(0, "corr-single-flip"); ntx_store_close(&t.store); return; }
    check(ntx_torrent_piece_complete_from(&t, 0, NULL, 0) == 1, "corr-single-neighbor0");
    check(ntx_torrent_piece_complete_from(&t, 1, NULL, 0) == 0, "corr-single-piece1");
    check(ntx_torrent_piece_complete_from(&t, 2, NULL, 0) == 1, "corr-single-neighbor2");
    check(t.have_n == 2, "corr-single-have_n");
    ntx_store_close(&t.store);
}

static void test_corrupt_multi(void) {
    char dir[160], dir2[160];
    snprintf(dir, sizeof dir, "%s/corr_multi", g_basedir);
    snprintf(dir2, sizeof dir2, "%s/corr_multi_vr", g_basedir);

    ntx_torrent t;
    if (setup_fx("multi_v2", dir, &t, 0) != 0) { check(0, "corr-multi-setup"); return; }
    /* flip the last byte of piece 3 (b.dat's short last piece, 37856 B) */
    if (flip_store_byte(&t, 3, 37856 - 1) != 0) { check(0, "corr-multi-flip"); ntx_store_close(&t.store); return; }
    check(ntx_torrent_piece_complete_from(&t, 3, NULL, 0) == 0, "corr-multi-piece3");
    check(ntx_torrent_piece_complete_from(&t, 2, NULL, 0) == 1, "corr-multi-neighbor2");
    check(ntx_torrent_piece_complete_from(&t, 4, NULL, 0) == 1, "corr-multi-neighbor4");
    ntx_store_close(&t.store);

    ntx_torrent t2;
    if (setup_fx("multi_v2", dir2, &t2, 0) != 0) { check(0, "corr-multi-vr-setup"); return; }
    if (flip_store_byte(&t2, 3, 37856 - 1) != 0) { check(0, "corr-multi-vr-flip"); ntx_store_close(&t2.store); return; }
    check(ntx_torrent_verify_range(&t2, 0, 5) == 4, "corr-multi-verify_range");
    check(t2.have_n == 4, "corr-multi-vr-have_n");
    ntx_store_close(&t2.store);
}

/* v1 regression: hand-built v1 torrent (1 file, ps 16384, 2 pieces) pins the
 * untouched SHA-1 branch. */
static void test_v1_regression(void) {
    char dir[160];
    snprintf(dir, sizeof dir, "%s/v1", g_basedir);

    static uint8_t data[20000];
    for (uint32_t i = 0; i < 20000; i++) data[i] = (uint8_t)(i * 7 + 3);
    uint8_t h1[20], h2[20];
    ntx_sha1(data, 16384, h1);
    ntx_sha1(data + 16384, 3616, h2);

    uint8_t info[512];
    size_t o = (size_t)snprintf((char *)info, sizeof info,
                                "d6:lengthi20000e4:name4:v1tt12:piece lengthi16384e6:pieces40:");
    memcpy(info + o, h1, 20);
    o += 20;
    memcpy(info + o, h2, 20);
    o += 20;
    o += (size_t)snprintf((char *)info + o, sizeof info - o, "e");

    uint8_t ih[20];
    ntx_sha1(info, o, ih);

    ntx_torrent t;
    ntx_torrent_init_meta(&t, ih);
    int rc = ntx_torrent_set_metainfo(&t, info, o, dir, NULL);
    check(rc == 0, "v1-set");
    if (rc != 0) return;
    check(t.meta_version == 0, "v1-meta-version");
    check(t.phash != NULL, "v1-phash");
    check(t.np == 2, "v1-np");
    check(t.size == 20000, "v1-size");
    check(ntx_store_write(&t.store, 0, 0, data, 16384) == 0, "v1-fill0");
    check(ntx_store_write(&t.store, 1, 0, data + 16384, 3616) == 0, "v1-fill1");
    check(ntx_torrent_piece_complete_from(&t, 0, NULL, 0) == 1, "v1-piece0");
    check(ntx_torrent_piece_complete_from(&t, 1, NULL, 0) == 1, "v1-piece1");
    check(ntx_torrent_done(&t), "v1-done");
    check(ntx_torrent_piece_complete_from(&t, 2, NULL, 0) == 0, "v1-oob");
    /* corrupt the last piece -> fail */
    uint8_t b;
    ntx_store_read(&t.store, 1, 1000, &b, 1);
    b ^= 0x01;
    ntx_store_write(&t.store, 1, 1000, &b, 1);
    check(ntx_torrent_piece_complete_from(&t, 1, NULL, 0) == 0, "v1-corrupt-fail");
    ntx_store_close(&t.store);
}

int main(void) {
    snprintf(g_basedir, sizeof g_basedir, "/tmp/ntx_bep52_verify_%d", (int)getpid());
    (void)mkdir(g_basedir, 0755);

    test_single_16k();
    test_multi_v2();
    test_hybrid_ok();
    test_corrupt_single();
    test_corrupt_multi();
    test_v1_regression();

    char cmd[128];
    snprintf(cmd, sizeof cmd, "rm -rf %s", g_basedir);
    int rm_rc = system(cmd);
    (void)rm_rc; /* cleanup best-effort */
    return fails ? 1 : 0;
}
