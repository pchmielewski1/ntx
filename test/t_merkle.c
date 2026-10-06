#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/ntx_merkle.c"
#include "../src/crypto/ntx_sha256.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

static uint8_t *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc(sz > 0 ? (size_t)sz : 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    *n = (size_t)sz;
    return buf;
}

static uint8_t *read_path(const char *dir, const char *name, size_t *n) {
    char path[512];
    snprintf(path, sizeof path, "%s/%s", dir, name);
    return read_file(path, n);
}

static int hex32(const char *hex, uint8_t out[32]) {
    for (int i = 0; i < 32; i++) {
        int hi, lo;
        if (sscanf(hex + 2 * i, "%1x%1x", &hi, &lo) != 2) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int hexbytes(const char *hex, uint8_t *out, size_t cap, size_t *outn) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return 0;
    size_t nb = len / 2;
    if (nb > cap) return 0;
    for (size_t i = 0; i < nb; i++) {
        int hi, lo;
        if (sscanf(hex + 2 * i, "%1x%1x", &hi, &lo) != 2) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *outn = nb;
    return 1;
}

/* Find the first manifest line starting with `prefix`; copy the remainder
 * (after the prefix, up to end-of-line) into out (NUL-terminated). */
static int mf_line(const char *manifest, const char *prefix, char *out, size_t cap) {
    size_t plen = strlen(prefix);
    const char *p = manifest;
    while (p && *p) {
        if (strncmp(p, prefix, plen) == 0) {
            const char *q = p + plen;
            size_t i = 0;
            while (*q && *q != '\n' && *q != '\r' && i + 1 < cap) out[i++] = *q++;
            out[i] = 0;
            return 1;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return 0;
}

static int mf_file_root(const char *mf, int idx, uint8_t root[32]) {
    char pre[64], rest[512];
    snprintf(pre, sizeof pre, "file: idx=%d ", idx);
    if (!mf_line(mf, pre, rest, sizeof rest)) return 0;
    const char *rp = strstr(rest, "root=");
    if (!rp) return 0;
    return hex32(rp + 5, root);
}

static int mf_piece_len(const char *mf, uint32_t *ps) {
    char rest[64];
    if (!mf_line(mf, "piece_len: ", rest, sizeof rest)) return 0;
    char *end;
    long v = strtol(rest, &end, 10);
    if (end == rest || *end != 0) return 0;
    *ps = (uint32_t)v;
    return 1;
}

static uint8_t *mf_layer(const char *mf, int idx, size_t *outn) {
    char pre[64], rest[8192];
    snprintf(pre, sizeof pre, "layer: idx=%d ", idx);
    if (!mf_line(mf, pre, rest, sizeof rest)) return NULL;
    uint8_t *out = malloc(strlen(rest) / 2 + 1);
    if (!out) return NULL;
    if (!hexbytes(rest, out, strlen(rest) / 2 + 1, outn)) { free(out); return NULL; }
    return out;
}

static int mf_piece_v2(const char *mf, int idx, uint8_t h[32]) {
    char pre[64], rest[128];
    snprintf(pre, sizeof pre, "piece: idx=%d v2=", idx);
    if (!mf_line(mf, pre, rest, sizeof rest)) return 0;
    return hex32(rest, h);
}

static void test_single_16k(void) {
    const char *dir = "test/vectors/bep52/single_16k";
    size_t mfn;
    char *mf = (char *)read_path(dir, "manifest.txt", &mfn);
    check(mf != NULL, "single-manifest-read");
    if (!mf) return;

    size_t fn;
    uint8_t *file = read_path(dir, "single_16k", &fn);
    check(file != NULL && fn == 40000, "single-file-read");
    if (!file) { free(mf); return; }

    uint32_t ps = 16384;
    check(mf_piece_len(mf, &ps) && ps == 16384, "single-piece-len");

    uint8_t root[32], mroot[32];
    check(ntx_merkle_root_from_file_buf(file, fn, root) == 0, "single-root-rc");
    check(mf_file_root(mf, 0, mroot) && memcmp(root, mroot, 32) == 0, "single-root-match");

    uint8_t layerbuf[4096];
    size_t layern = 0;
    check(ntx_merkle_file_layer(file, fn, ps, layerbuf, sizeof layerbuf, &layern) == 0
              && layern == 96,
          "single-layer-len");
    size_t mln = 0;
    uint8_t *mlayer = mf_layer(mf, 0, &mln);
    check(mlayer != NULL && mln == layern && memcmp(layerbuf, mlayer, layern) == 0,
          "single-layer-match");

    check(ntx_merkle_verify_piece_layer(root, mlayer, mln, ps, 0, file + 0, 16384) == 0,
          "single-piece0");
    check(ntx_merkle_verify_piece_layer(root, mlayer, mln, ps, 1, file + 16384, 16384) == 0,
          "single-piece1");
    check(ntx_merkle_verify_piece_layer(root, mlayer, mln, ps, 2, file + 32768, 7232) == 0,
          "single-piece2");

    uint8_t pc[7232];
    memcpy(pc, file + 32768, 7232);
    pc[100] ^= 0x01;
    check(ntx_merkle_verify_piece_layer(root, mlayer, mln, ps, 2, pc, 7232) == -1,
          "single-piece-corrupt");

    uint8_t zroot[32];
    int allzero = 0;
    if (ntx_merkle_root_from_file_buf(file, 0, zroot) == 0) {
        allzero = 1;
        for (int i = 0; i < 32; i++)
            if (zroot[i]) allzero = 0;
    }
    check(allzero, "single-empty-root");

    free(mlayer);
    free(file);
    free(mf);
}

static void test_multi_v2(void) {
    const char *dir = "test/vectors/bep52/multi_v2";
    size_t mfn;
    char *mf = (char *)read_path(dir, "manifest.txt", &mfn);
    check(mf != NULL, "multi-manifest-read");
    if (!mf) return;

    uint32_t ps = 131072;
    check(mf_piece_len(mf, &ps) && ps == 131072, "multi-piece-len");

    size_t an;
    uint8_t *a = read_path(dir, "a.txt", &an);
    check(a != NULL && an == 50000, "multi-a-read");
    uint8_t aroot[32], aroot_m[32];
    check(mf_file_root(mf, 0, aroot_m), "multi-a-root-parse");
    check(ntx_merkle_root_from_file_buf(a, an, aroot) == 0 &&
              memcmp(aroot, aroot_m, 32) == 0,
          "multi-a-root-match");
    check(ntx_merkle_verify_piece_layer(aroot_m, NULL, 0, ps, 0, a, an) == 0,
          "multi-a-null-verify");

    size_t bn;
    uint8_t *b = read_path(dir, "dir/b.dat", &bn);
    check(b != NULL && bn == 300000, "multi-b-read");
    uint8_t broot_m[32];
    check(mf_file_root(mf, 1, broot_m), "multi-b-root-parse");
    size_t bln = 0;
    uint8_t *blayer = mf_layer(mf, 1, &bln);
    check(blayer != NULL && bln == 96, "multi-b-layer-read");

    uint8_t broot[32];
    check(ntx_merkle_root_from_layer(blayer, bln, ps, 300000, broot) == 0 &&
              memcmp(broot, broot_m, 32) == 0,
          "multi-b-rootfromlayer");

    uint8_t blayerbuf[4096];
    size_t bln2 = 0;
    check(ntx_merkle_file_layer(b, bn, ps, blayerbuf, sizeof blayerbuf, &bln2) == 0 &&
              bln2 == bln && memcmp(blayerbuf, blayer, bln) == 0,
          "multi-b-layer-match");

    check(ntx_merkle_verify_piece_layer(broot_m, blayer, bln, ps, 1, b + 131072, 131072) == 0,
          "multi-b-piece1");
    check(ntx_merkle_verify_piece_layer(broot_m, blayer, bln, ps, 2, b + 262144, 37856) == 0,
          "multi-b-piece2");

    uint8_t p1[32], p2[32];
    check(mf_piece_v2(mf, 2, p1) && memcmp(blayer + 32, p1, 32) == 0, "multi-b-layer-vs-piece1");
    check(mf_piece_v2(mf, 3, p2) && memcmp(blayer + 64, p2, 32) == 0, "multi-b-layer-vs-piece2");

    size_t cn;
    uint8_t *c = read_path(dir, "dir/c.bin", &cn);
    check(c != NULL && cn == 1000, "multi-c-read");
    uint8_t croot_m[32];
    check(mf_file_root(mf, 2, croot_m), "multi-c-root-parse");
    check(ntx_merkle_verify_piece_layer(croot_m, NULL, 0, ps, 0, c, cn) == 0,
          "multi-c-null-verify");

    free(a);
    free(b);
    free(c);
    free(blayer);
    free(mf);
}

/* ---- ntx_merkle_ingest_hashes: expected values derived programmatically
 * from a tree built with the existing merkle API (no hex from memory). ---- */

static uint8_t *tr_layers[40];
static size_t tr_counts[40];
static int tr_h;

static void tr_free(void) {
    for (int i = 0; i < 40; i++) {
        free(tr_layers[i]);
        tr_layers[i] = NULL;
        tr_counts[i] = 0;
    }
    tr_h = 0;
}

static int tr_build(const uint8_t *data, size_t n) {
    tr_free();
    size_t p;
    uint8_t *lev = ntx_leaves(data, n, &p);
    if (!lev) return 0;
    tr_h = 0;
    tr_layers[0] = lev;
    tr_counts[0] = p;
    while (p > 1) {
        uint8_t *up = malloc(p * 32);
        if (!up) { tr_free(); return 0; }
        memcpy(up, lev, p * 32);
        ntx_fold_once(up, p);
        lev = up;
        p >>= 1;
        tr_h++;
        tr_layers[tr_h] = up;
        tr_counts[tr_h] = p;
    }
    return 1;
}

static void tr_fill(uint8_t *d, size_t n) {
    for (size_t i = 0; i < n; i++) d[i] = (uint8_t)(i * 7u + (i >> 8) * 13u + 5u);
}

/* base-layer hashes [index, index+length) then one uncle per proof layer up
 * to the root; *proof_layers = declared P (first log2(length)-1 omitted but
 * counted per BEP52). Returns total hash count, 0 if out of tree. */
static size_t tr_blob(uint32_t base, uint32_t index, uint32_t length,
                      uint8_t *blob, uint32_t *proof_layers) {
    if (length < 2 || !ntx_pow2(length)) return 0;
    uint32_t lg = ntx_log2(length);
    if ((uint32_t)tr_h < base + lg) return 0;
    uint32_t need = (uint32_t)tr_h - (base + lg);
    *proof_layers = need + (lg - 1);
    memcpy(blob, tr_layers[base] + (size_t)index * 32, (size_t)length * 32);
    uint32_t pos = index / length;
    for (uint32_t k = 0; k < need; k++) {
        size_t upos = (size_t)((pos >> k) ^ 1u);
        memcpy(blob + ((size_t)length + k) * 32,
               tr_layers[base + lg + k] + upos * 32, 32);
    }
    return (size_t)length + need;
}

static void test_ingest(void) {
    size_t n = 312144; /* 20 leaves -> pad 32 (H=5); ps=131072 -> 3 pieces */
    uint8_t *data = malloc(n);
    uint8_t blob[16 * 32];
    uint8_t outl[8 * 32];
    size_t outn = 0;
    uint32_t P = 0;
    check(data != NULL, "ingest-alloc");
    if (!data) return;
    tr_fill(data, n);
    check(tr_build(data, n) && tr_h == 5, "ingest-tree-built");
    uint8_t root[32];
    memcpy(root, tr_layers[tr_h], 32);

    size_t nh = tr_blob(3, 0, 2, blob, &P);
    check(nh == 3 && P == 1, "ingest-piece-proof-count");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, blob, nh * 32,
                                   outl, 2 * 32, &outn) == 0
              && outn == 2 * 32 && memcmp(outl, tr_layers[3], 2 * 32) == 0,
          "ingest-happy-piece-layer");

    uint8_t fl[3 * 32];
    size_t fln = 0;
    check(ntx_merkle_file_layer(data, n, 131072, fl, sizeof fl, &fln) == 0
              && fln == 3 * 32 && memcmp(fl, tr_layers[3], 3 * 32) == 0,
          "ingest-piece-layer-agrees");

    nh = tr_blob(3, 2, 2, blob, &P);
    check(nh == 3 && P == 1, "ingest-tail-count");
    check(ntx_merkle_ingest_hashes(root, 3, 2, 2, P, blob, nh * 32,
                                   outl, 2 * 32, &outn) == 0
              && outn == 2 * 32 && memcmp(outl, tr_layers[3] + 2 * 32, 2 * 32) == 0,
          "ingest-happy-balance-tail");

    nh = tr_blob(3, 0, 2, blob, &P);
    blob[(nh - 1) * 32] ^= 0x01;
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, blob, nh * 32,
                                   outl, 2 * 32, &outn) == -1,
          "ingest-bad-proof");
    blob[(nh - 1) * 32] ^= 0x01;

    uint8_t badroot[32];
    memcpy(badroot, root, 32);
    badroot[0] ^= 0x01;
    check(ntx_merkle_ingest_hashes(badroot, 3, 0, 2, P, blob, nh * 32,
                                   outl, 2 * 32, &outn) == -1,
          "ingest-wrong-root");

    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, blob, nh * 32,
                                   outl, 2 * 32 - 1, &outn) == -1,
          "ingest-cap-too-small");

    nh = tr_blob(0, 0, 8, blob, &P);
    check(nh == 10 && P == 4, "ingest-leaf-proof-count");
    check(ntx_merkle_ingest_hashes(root, 0, 0, 8, P, blob, nh * 32,
                                   outl, 8 * 32, &outn) == 0
              && outn == 8 * 32 && memcmp(outl, tr_layers[0], 8 * 32) == 0,
          "ingest-happy-leaf-proof");

    tr_free();
    size_t n2 = 40000;
    uint8_t *d2 = malloc(n2);
    check(d2 != NULL, "ingest-alloc2");
    if (d2) {
        tr_fill(d2, n2);
        check(tr_build(d2, n2) && tr_h == 2, "ingest-16k-tree");
        uint8_t root2[32];
        memcpy(root2, tr_layers[tr_h], 32);
        nh = tr_blob(0, 0, 4, blob, &P);
        check(nh == 4 && P == 1, "ingest-leafpiece-count");
        check(ntx_merkle_ingest_hashes(root2, 0, 0, 4, P, blob, nh * 32,
                                       outl, 4 * 32, &outn) == 0
                  && outn == 4 * 32 && memcmp(outl, tr_layers[0], 4 * 32) == 0,
              "ingest-happy-leaf-eq-piece");
        uint8_t fl2[4 * 32];
        size_t fl2n = 0;
        check(ntx_merkle_file_layer(d2, n2, 16384, fl2, sizeof fl2, &fl2n) == 0
                  && fl2n == 3 * 32 && memcmp(fl2, outl, 3 * 32) == 0,
              "ingest-leafpiece-vs-file-layer");
        free(d2);
    }

    tr_build(data, n);
    memcpy(root, tr_layers[tr_h], 32);
    nh = tr_blob(3, 0, 2, blob, &P);
    check(ntx_merkle_ingest_hashes(root, 3, 0, 1, P, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-len-lt2");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 0, P, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-len-0");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 3, P, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-len-not-pow2");
    check(ntx_merkle_ingest_hashes(root, 3, 1, 2, P, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-index-not-mult");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, blob, nh * 32 - 1, outl, 8 * 32, &outn) == -1,
          "ingest-nbytes-not-32x");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P + 1, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-proof-mismatch");
    nh = tr_blob(0, 0, 8, blob, &P);
    check(ntx_merkle_ingest_hashes(root, 0, 0, 8, 1, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-proof-below-floor");
    check(ntx_merkle_ingest_hashes(NULL, 3, 0, 2, P, blob, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-null-root");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, NULL, nh * 32, outl, 8 * 32, &outn) == -1,
          "ingest-null-hashes");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, blob, nh * 32, NULL, 8 * 32, &outn) == -1,
          "ingest-null-out");
    check(ntx_merkle_ingest_hashes(root, 3, 0, 2, P, blob, nh * 32, outl, 8 * 32, NULL) == -1,
          "ingest-null-outn");
    tr_free();
    free(data);
}

int main(void) {
    test_single_16k();
    test_multi_v2();
    test_ingest();
    return fails ? 1 : 0;
}
