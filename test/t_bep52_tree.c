#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/core/ntx_torrent_v2.c"
#include "../src/proto/ntx_bencode.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond)
        printf("PASS %s\n", name);
    else {
        printf("FAIL %s\n", name);
        fails = 1;
    }
}

static int read_file(const char *path, uint8_t **out, size_t *out_n) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return -1;
    }
    long sz = ftell(f);
    if (sz < 0) {
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    uint8_t *buf = malloc((size_t)(sz > 0 ? sz : 0) + 1);
    if (!buf) {
        fclose(f);
        return -1;
    }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) {
        free(buf);
        return -1;
    }
    buf[sz] = 0; /* NUL-terminated: callers parse the data as text */
    *out = buf;
    *out_n = (size_t)sz;
    return 0;
}

typedef struct {
    int idx;
    uint32_t fp;
    uint32_t np;
    uint64_t len;
    uint8_t root[32];
    char path[512];
} mfile;

typedef struct {
    uint32_t piece_len;
    uint32_t np_total;
    uint64_t addr_end;
    uint64_t data_size;
    mfile files[64];
    int nfiles;
} manifest;

static int hex32(const char *hex, uint8_t *out) {
    if (strlen(hex) != 64) return -1;
    for (int i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return -1;
        out[i] = (uint8_t)v;
    }
    return 0;
}

static int parse_manifest(const char *fx, manifest *m) {
    char path[512];
    snprintf(path, sizeof path, "test/vectors/bep52/%s/manifest.txt", fx);
    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(path, &buf, &n) != 0) return -1;
    m->nfiles = 0;
    char *line = (char *)buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        unsigned u;
        unsigned long ul;
        int a, b, c;
        char hex[128], p[512];
        if (sscanf(line, "piece_len: %u", &u) == 1) {
            m->piece_len = u;
        } else if (sscanf(line, "np_total: %u", &u) == 1) {
            m->np_total = u;
        } else if (sscanf(line, "addr_end: %lu", &ul) == 1) {
            m->addr_end = (uint64_t)ul;
        } else if (sscanf(line, "data_size: %lu", &ul) == 1) {
            m->data_size = (uint64_t)ul;
        } else if (sscanf(line, "file: idx=%d fp=%u np=%u len=%lu root=%127s path=%511s",
                           &a, &b, &c, &ul, hex, p) == 6 &&
                   m->nfiles < 64) {
            mfile *f = &m->files[m->nfiles++];
            f->idx = a;
            f->fp = (uint32_t)b;
            f->np = (uint32_t)c;
            f->len = (uint64_t)ul;
            if (hex32(hex, f->root) != 0) {
                free(buf);
                return -1;
            }
            snprintf(f->path, sizeof f->path, "%s", p);
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return 0;
}

static void test_fixture(const char *fx) {
    manifest m;
    memset(&m, 0, sizeof m);
    char nm[160];
    snprintf(nm, sizeof nm, "%s-manifest", fx);
    if (parse_manifest(fx, &m) != 0) {
        check(0, nm);
        return;
    }
    char path[512];
    snprintf(path, sizeof path, "test/vectors/bep52/%s/meta.torrent", fx);
    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(path, &buf, &n) != 0) {
        check(0, nm);
        return;
    }
    ntx_be be;
    size_t consumed = 0;
    int prc = ntx_be_parse(buf, n, &be, &consumed, 32, (size_t)1 << 20);
    snprintf(nm, sizeof nm, "%s-parse", fx);
    check(prc == 0, nm);
    if (prc != 0) {
        free(buf);
        return;
    }
    const ntx_be *info = ntx_be_dict_get(&be, "info");
    snprintf(nm, sizeof nm, "%s-info", fx);
    check(info != NULL && info->t == NTX_BE_DICT, nm);
    const ntx_be *tree = info ? ntx_be_dict_get(info, "file tree") : NULL;
    snprintf(nm, sizeof nm, "%s-tree", fx);
    check(tree != NULL && tree->t == NTX_BE_DICT, nm);
    if (!tree) {
        ntx_be_free(&be);
        free(buf);
        return;
    }
    ntx_v2_file files[NTX_TORRENT_MAX_FILES_V2];
    uint32_t nf = 0;
    uint64_t ds = 0, ae = 0;
    int rc = ntx_torrent_v2_tree_walk(tree, m.piece_len, files,
                                      NTX_TORRENT_MAX_FILES_V2, &nf, &ds, &ae);
    snprintf(nm, sizeof nm, "%s-walk", fx);
    check(rc == 0, nm);
    if (rc != 0) {
        ntx_be_free(&be);
        free(buf);
        return;
    }
    snprintf(nm, sizeof nm, "%s-nfiles", fx);
    check(nf == (uint32_t)m.nfiles, nm);
    uint64_t np_sum = 0;
    for (uint32_t i = 0; i < nf && i < (uint32_t)m.nfiles; i++) {
        np_sum += files[i].np;
        const mfile *ef = &m.files[i];
        snprintf(nm, sizeof nm, "%s-f%u-fp", fx, i);
        check(files[i].first_piece == ef->fp, nm);
        snprintf(nm, sizeof nm, "%s-f%u-np", fx, i);
        check(files[i].np == ef->np, nm);
        snprintf(nm, sizeof nm, "%s-f%u-len", fx, i);
        check(files[i].len == ef->len, nm);
        snprintf(nm, sizeof nm, "%s-f%u-path", fx, i);
        check(strcmp(files[i].path, ef->path) == 0, nm);
        snprintf(nm, sizeof nm, "%s-f%u-root", fx, i);
        check(memcmp(files[i].root, ef->root, 32) == 0, nm);
    }
    snprintf(nm, sizeof nm, "%s-np-total", fx);
    check(np_sum == (uint64_t)m.np_total, nm);
    snprintf(nm, sizeof nm, "%s-data-size", fx);
    check(ds == m.data_size, nm);
    snprintf(nm, sizeof nm, "%s-addr-end", fx);
    check(ae == m.addr_end, nm);
    ntx_be_free(&be);
    free(buf);
}

static int walk_raw(const uint8_t *b, size_t n, uint32_t ps, ntx_v2_file *out,
                    uint32_t *nf, uint64_t *ds, uint64_t *ae) {
    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(b, n, &be, &consumed, 32, (size_t)1 << 20) != 0) return -2;
    int rc = ntx_torrent_v2_tree_walk(&be, ps, out, NTX_TORRENT_MAX_FILES_V2, nf, ds, ae);
    ntx_be_free(&be);
    return rc;
}

static int walk_str(const char *s, uint32_t ps, ntx_v2_file *out, uint32_t *nf,
                    uint64_t *ds, uint64_t *ae) {
    return walk_raw((const uint8_t *)s, strlen(s), ps, out, nf, ds, ae);
}

#define PS16 16384u

static void test_negative(void) {
    ntx_v2_file f[NTX_TORRENT_MAX_FILES_V2];
    memset(f, 0, sizeof f);
    uint32_t nf = 0;
    uint64_t ds = 0, ae = 0;
    int rc;

    check(walk_str("d0:d6:lengthi0eee", PS16, f, &nf, &ds, &ae) == -1,
          "neg-root-is-file");

    check(walk_str("d3:food0:d11:pieces root32:"
                   "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AA"
                   "eee", PS16, f, &nf, &ds, &ae) == -1,
          "neg-missing-length");

    check(walk_str("d3:food0:d6:lengthi16384eeee", PS16, f, &nf, &ds, &ae) == -1,
          "neg-no-root");

    nf = 0;
    ds = 0;
    ae = 0;
    rc = walk_str("d3:food0:d6:lengthi0eeee", PS16, f, &nf, &ds, &ae);
    check(rc == 0, "zero-len-ok");
    check(nf == 1, "zero-len-n");
    check(f[0].len == 0, "zero-len-len");
    check(f[0].np == 0, "zero-len-np");
    check(f[0].first_piece == 0, "zero-len-fp");
    check(ds == 0, "zero-len-ds");
    check(ae == 0, "zero-len-ae");
    int zero_root = 1;
    for (int i = 0; i < 32; i++)
        if (f[0].root[i]) zero_root = 0;
    check(zero_root, "zero-len-root-zero");
    check(strcmp(f[0].path, "foo") == 0, "zero-len-path");

    nf = 0;
    ds = 0;
    ae = 0;
    rc = walk_str("d1:ad0:d6:lengthi16384e11:pieces root32:"
                  "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AA"
                  "ee1:bd0:d6:lengthi0eeee", PS16, f, &nf, &ds, &ae);
    check(rc == 0, "zero-after-ok");
    check(nf == 2, "zero-after-n");
    check(f[1].first_piece == 1, "zero-after-fp-prev-total");
    check(f[1].np == 0, "zero-after-np");
    check(ae == 16384, "zero-after-ae");
    check(ds == 16384, "zero-after-ds");

    check(walk_str("d1:fd0:d6:lengthi0ee1:x1:ye" "e", PS16, f, &nf, &ds, &ae) == -1,
          "neg-sibling-keys");

    nf = 0;
    ds = 0;
    ae = 0;
    rc = walk_str("d1:ad1:.d2:..d0:d6:lengthi0eeeeee", PS16, f, &nf, &ds, &ae);
    check(rc == 0, "sanitize-ok");
    check(nf == 1, "sanitize-n");
    check(strcmp(f[0].path, "a/_/__") == 0, "sanitize-path");

    nf = 0;
    ds = 0;
    ae = 0;
    rc = walk_str("d3:x/yd0:d6:lengthi0eeee", PS16, f, &nf, &ds, &ae);
    check(rc == 0, "slash-ok");
    check(nf == 1, "slash-n");
    check(strcmp(f[0].path, "x_y") == 0, "slash-path");

    const uint8_t nulkey[] = {'d', '3', ':', 'a', 0, 'b', 'd', '0', ':', 'd', '6', ':',
                              'l', 'e', 'n', 'g', 't', 'h', 'i', '0', 'e', 'e', 'e', 'e'};
    check(walk_raw(nulkey, sizeof nulkey, PS16, f, &nf, &ds, &ae) == -1, "neg-nul-key");

    check(walk_str("d3:food0:d6:lengthi16384e11:pieces root31:"
                   "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "A"
                   "eee", PS16, f, &nf, &ds, &ae) == -1,
          "neg-root-31");

    check(walk_str("d3:food0:d6:lengthi0e11:pieces root32:"
                   "AAAAAAAAAA" "AAAAAAAAAA" "AAAAAAAAAA" "AA"
                   "eee", PS16, f, &nf, &ds, &ae) == -1,
          "neg-zero-len-with-root");

    check(walk_str("de", PS16, f, &nf, &ds, &ae) == -1, "neg-empty-tree");
    check(walk_str("i5e", PS16, f, &nf, &ds, &ae) == -1, "neg-non-dict-tree");
}

static int build_many_files(char *out, size_t cap, int n) {
    size_t o = 0;
    out[o++] = 'd';
    for (int i = 0; i < n; i++) {
        char key[8];
        int klen = snprintf(key, sizeof key, "f%02d", i);
        o += (size_t)snprintf(out + o, cap - o, "%d:%s", klen, key);
        o += (size_t)snprintf(out + o, cap - o, "d0:d6:lengthi16384e11:pieces root32:");
        for (int b = 0; b < 32; b++) out[o++] = (uint8_t)(0x41 + (i + b) % 16);
        o += (size_t)snprintf(out + o, cap - o, "ee");
    }
    out[o++] = 'e';
    return (int)o;
}

static void test_file_cap(void) {
    char buf[16384];
    ntx_v2_file f[NTX_TORRENT_MAX_FILES_V2];
    uint32_t nf = 0;
    uint64_t ds = 0, ae = 0;
    int rc;

    int n65 = build_many_files(buf, sizeof buf, 65);
    check(n65 > 0, "cap65-build");
    check(walk_raw((const uint8_t *)buf, (size_t)n65, PS16, f, &nf, &ds, &ae) == -1,
          "cap65-reject");

    int n64 = build_many_files(buf, sizeof buf, 64);
    check(n64 > 0, "cap64-build");
    rc = walk_raw((const uint8_t *)buf, (size_t)n64, PS16, f, &nf, &ds, &ae);
    check(rc == 0, "cap64-ok");
    check(nf == 64, "cap64-n");
    check(ds == 64ull * 16384ull, "cap64-ds");
    check(ae == 64ull * 16384ull, "cap64-ae");
}

int main(void) {
    test_fixture("single_16k");
    test_fixture("multi_v2");
    test_fixture("hybrid_ok");
    test_fixture("hybrid_bad_order");
    test_negative();
    test_file_cap();
    return fails ? 1 : 0;
}
