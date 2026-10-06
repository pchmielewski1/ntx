#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/proto/ntx_bencode.c"
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
    uint8_t *buf = malloc((size_t)(sz > 0 ? sz : 0) + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = 0; /* NUL-terminated: callers parse the data as text */
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

static uint8_t *mf_layer(const char *mf, int idx, size_t *outn) {
    char pre[64], rest[8192];
    snprintf(pre, sizeof pre, "layer: idx=%d ", idx);
    if (!mf_line(mf, pre, rest, sizeof rest)) return NULL;
    uint8_t *out = malloc(strlen(rest) / 2 + 1);
    if (!out) return NULL;
    if (!hexbytes(rest, out, strlen(rest) / 2 + 1, outn)) { free(out); return NULL; }
    return out;
}

/* Parse one "file: " manifest line into an ntx_v2_file. */
static int parse_file_line(const char *line, ntx_v2_file *f) {
    if (strncmp(line, "file: ", 6) != 0) return 0;
    int idx, fp, np;
    unsigned long long len;
    char root[65], path[768];
    int n = sscanf(line + 6, "idx=%d fp=%d np=%d len=%llu root=%64s path=%767s",
                   &idx, &fp, &np, &len, root, path);
    if (n != 6) return 0;
    memset(f, 0, sizeof *f);
    f->first_piece = (uint32_t)fp;
    f->np = (uint32_t)np;
    f->len = (uint64_t)len;
    snprintf(f->path, sizeof f->path, "%s", path);
    return hex32(root, f->root);
}

/* Collect all "file: " lines (in manifest order) into files[]. */
static uint32_t mf_files(const char *mf, ntx_v2_file *files, uint32_t cap) {
    uint32_t count = 0;
    const char *p = mf;
    while (p && *p) {
        if (strncmp(p, "file: ", 6) == 0) {
            const char *eol = strchr(p, '\n');
            size_t linelen = eol ? (size_t)(eol - p) : strlen(p);
            char line[1024];
            if (linelen >= sizeof line) linelen = sizeof line - 1;
            memcpy(line, p, linelen);
            line[linelen] = 0;
            if (count < cap && parse_file_line(line, &files[count])) count++;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return count;
}

/* Build a heap-allocated layers dict with `ne` entries (32-byte keys).
 * Key/value data pointers are owned by the caller. Free with ntx_be_free. */
static ntx_be *build_layers(int ne, const uint8_t *const *keys,
                            const uint8_t *const *vals, const size_t *valns) {
    ntx_be *d = calloc(1, sizeof *d);
    if (!d) return NULL;
    d->t = NTX_BE_DICT;
    d->nd = (size_t)ne;
    d->k = calloc(ne > 0 ? (size_t)ne : 1, sizeof *d->k);
    d->v = calloc(ne > 0 ? (size_t)ne : 1, sizeof *d->v);
    if (!d->k || !d->v) { ntx_be_free(d); return NULL; }
    for (int i = 0; i < ne; i++) {
        ntx_be *k = calloc(1, sizeof *k);
        ntx_be *v = calloc(1, sizeof *v);
        if (!k || !v) { ntx_be_free(d); return NULL; }
        k->t = NTX_BE_STR;
        k->sp = (uint8_t *)keys[i];
        k->sn = 32;
        v->t = NTX_BE_STR;
        v->sp = (uint8_t *)vals[i];
        v->sn = valns[i];
        d->k[i] = k;
        d->v[i] = v;
    }
    return d;
}

static void test_fixture(const char *name) {
    const char *dir = "test/vectors/bep52/";
    char dpath[512];
    snprintf(dpath, sizeof dpath, "%s%s", dir, name);
    char cbuf[96];

    size_t mn;
    uint8_t *meta = read_path(dpath, "meta.torrent", &mn);
    snprintf(cbuf, sizeof cbuf, "%s-meta-read", name);
    check(meta != NULL, cbuf);
    if (!meta) return;

    ntx_be be;
    size_t consumed = 0;
    int prc = ntx_be_parse(meta, mn, &be, &consumed, 32, 1 << 20);
    snprintf(cbuf, sizeof cbuf, "%s-meta-parse", name);
    check(prc == 0 && consumed == mn, cbuf);
    if (prc != 0) { free(meta); return; }

    const ntx_be *info = ntx_be_dict_get(&be, "info");
    const ntx_be *psv = info ? ntx_be_dict_get(info, "piece length") : NULL;
    uint32_t ps = (psv && psv->t == NTX_BE_INT) ? (uint32_t)psv->i : 0;
    snprintf(cbuf, sizeof cbuf, "%s-ps", name);
    check(info != NULL && ps != 0, cbuf);

    const ntx_be *layers = ntx_be_dict_get(&be, "piece layers");
    snprintf(cbuf, sizeof cbuf, "%s-layers-dict", name);
    check(layers != NULL && layers->t == NTX_BE_DICT, cbuf);

    size_t mfn;
    char *mf = (char *)read_path(dpath, "manifest.txt", &mfn);
    snprintf(cbuf, sizeof cbuf, "%s-manifest-read", name);
    check(mf != NULL, cbuf);
    if (!mf) { ntx_be_free(&be); free(meta); return; }

    ntx_v2_file files[NTX_TORRENT_MAX_FILES_V2];
    uint32_t n = mf_files(mf, files, NTX_TORRENT_MAX_FILES_V2);
    snprintf(cbuf, sizeof cbuf, "%s-files-count", name);
    check(n > 0, cbuf);

    uint8_t out[8192];
    size_t outn = 0;
    int rc = ntx_torrent_v2_layers(layers, files, n, ps, out, sizeof out, &outn);
    snprintf(cbuf, sizeof cbuf, "%s-layers-rc", name);
    check(rc == 0, cbuf);

    /* Expected out: concatenation of manifest layer hexes in files[] order. */
    size_t expn = 0, off = 0;
    for (uint32_t i = 0; i < n; i++)
        if (files[i].len > ps) expn += (size_t)files[i].np * 32;
    uint8_t *exp = malloc(expn > 0 ? expn : 1);
    for (uint32_t i = 0; i < n; i++) {
        if (files[i].len <= ps) continue;
        size_t ln = 0;
        uint8_t *lay = mf_layer(mf, (int)i, &ln);
        if (lay && ln == (size_t)files[i].np * 32) {
            memcpy(exp + off, lay, ln);
            off += ln;
        }
        free(lay);
    }
    snprintf(cbuf, sizeof cbuf, "%s-outn", name);
    check(outn == expn && off == expn, cbuf);
    snprintf(cbuf, sizeof cbuf, "%s-out-bytes", name);
    check(outn == off && (outn == 0 || memcmp(out, exp, outn) == 0), cbuf);

    free(exp);
    ntx_be_free(&be);
    free(meta);
    free(mf);
}

static void test_negative(void) {
    const char *dir = "test/vectors/bep52/single_16k";
    size_t mfn;
    char *mf = (char *)read_path(dir, "manifest.txt", &mfn);
    check(mf != NULL, "neg-manifest-read");
    if (!mf) return;

    ntx_v2_file files[8];
    uint32_t n = mf_files(mf, files, 8);
    uint32_t ps = 16384;
    check(n == 1 && files[0].len == 40000 && files[0].np == 3, "neg-files");

    uint8_t root[32];
    check(mf_file_root(mf, 0, root), "neg-root-parse");
    size_t ln = 0;
    uint8_t *layer = mf_layer(mf, 0, &ln);
    check(layer != NULL && ln == 96, "neg-layer-parse");
    if (!layer) { free(mf); return; }

    uint8_t out[8192];
    size_t outn = 0;

    ntx_be empty = {0};
    empty.t = NTX_BE_DICT;
    check(ntx_torrent_v2_layers(&empty, files, n, ps, out, sizeof out, &outn) == -1,
          "neg-empty-dict");

    uint8_t bogus[32];
    memset(bogus, 0xFF, 32);
    const uint8_t *keys2[2] = { root, bogus };
    const uint8_t *vals2[2] = { layer, layer };
    size_t valns2[2] = { ln, ln };
    ntx_be *d2 = build_layers(2, keys2, vals2, valns2);
    check(d2 != NULL &&
              ntx_torrent_v2_layers(d2, files, n, ps, out, sizeof out, &outn) == -1,
          "neg-spurious-key");
    ntx_be_free(d2);

    const uint8_t *keys3[1] = { root };
    const uint8_t *vals3[1] = { layer };
    size_t valns3[1] = { 31 };
    ntx_be *d3 = build_layers(1, keys3, vals3, valns3);
    check(d3 != NULL &&
              ntx_torrent_v2_layers(d3, files, n, ps, out, sizeof out, &outn) == -1,
          "neg-wrong-len");
    ntx_be_free(d3);

    uint8_t flipped[96];
    memcpy(flipped, layer, 96);
    flipped[5] ^= 0x01;
    const uint8_t *keys4[1] = { root };
    const uint8_t *vals4[1] = { flipped };
    size_t valns4[1] = { 96 };
    ntx_be *d4 = build_layers(1, keys4, vals4, valns4);
    check(d4 != NULL &&
              ntx_torrent_v2_layers(d4, files, n, ps, out, sizeof out, &outn) == -1,
          "neg-flipped-byte");
    ntx_be_free(d4);

    const uint8_t *keys5[1] = { root };
    const uint8_t *vals5[1] = { layer };
    size_t valns5[1] = { ln };
    ntx_be *d5 = build_layers(1, keys5, vals5, valns5);
    check(d5 != NULL &&
              ntx_torrent_v2_layers(d5, files, n, ps, out, sizeof out, &outn) == 0 &&
              outn == 96,
          "neg-sanity-good");
    ntx_be_free(d5);

    free(layer);
    free(mf);
}

int main(void) {
    test_fixture("single_16k");
    test_fixture("multi_v2");
    test_fixture("hybrid_ok");
    test_fixture("hybrid_bad_order");
    test_negative();
    return fails ? 1 : 0;
}
