/* Task A2 (§5.2, §4): ntx_torrent_validate_metainfo fills every torrent field
 * from the info dict + piece layers with NO disk side effect, and
 * ntx_torrent_open_store is the only half that creates files.  Also pins the
 * BEP 27 rule: any non-zero integer in `private` is private, a string or a
 * missing key is public. */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

#define FX "test/vectors/bep52/hybrid_ok"
#define SDIR "test/.scratch/torrent_validate"

static int fails;

static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails = 1;
}

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
    buf[sz] = 0;
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

#define MAXP 8

typedef struct {
    uint32_t piece_len;
    uint32_t np_total;
    uint64_t data_size;
    uint8_t ih_full[32];
    uint8_t ih_sha1[20];
    uint8_t phash[MAXP][20];
    int nph;
} manifest;

static int parse_manifest(manifest *m) {
    char path[512];
    snprintf(path, sizeof path, "%s/manifest.txt", FX);
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
        int idx;
        char v2[80], v1[80];
        if (sscanf(line, "piece_len: %u", &u) == 1) {
            m->piece_len = u;
        } else if (sscanf(line, "np_total: %u", &u) == 1) {
            m->np_total = u;
        } else if (sscanf(line, "data_size: %lu", &ul) == 1) {
            m->data_size = (uint64_t)ul;
        } else if (sscanf(line, "ih_full: %79s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_full, 32) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "ih_sha1: %79s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_sha1, 20) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "piece: idx=%d v2=%79s v1=%79s", &idx, v2, v1) == 3) {
            if (idx < 0 || idx >= MAXP) { free(buf); return -1; }
            if (hex_to_bytes(v1, m->phash[idx], 20) != 0) { free(buf); return -1; }
            if (idx + 1 > m->nph) m->nph = idx + 1;
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return m->nph > 0 ? 0 : -1;
}

/* Entries in dir, excluding "."/".."; -1 when dir does not exist. */
static int dir_entries(const char *dir) {
    DIR *d = opendir(dir);
    if (!d) return -1;
    int n = 0;
    struct dirent *de;
    while ((de = readdir(d)) != NULL) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        n++;
    }
    closedir(d);
    return n;
}

static int file_exists(const char *path) {
    struct stat st;
    return stat(path, &st) == 0;
}

static const uint8_t *g_info;   /* fixture info substring */
static size_t g_info_n;
static const uint8_t *g_layers; /* fixture "piece layers" substring */
static size_t g_layers_n;

/* info dict + a trailing key/value spliced in before the final 'e' ("private"
 * sorts after "pieces", so appending keeps the dict's key order valid). */
static size_t splice(uint8_t *out, size_t cap, const char *kv) {
    if (g_info_n < 1 || g_info_n + strlen(kv) + 1 > cap) return 0;
    memcpy(out, g_info, g_info_n - 1);
    size_t o = g_info_n - 1;
    memcpy(out + o, kv, strlen(kv));
    o += strlen(kv);
    out[o++] = 'e';
    return o;
}

static int validate_variant(const uint8_t *info, size_t n, ntx_torrent *t) {
    uint8_t h20[20], h32[32];
    if (ntx_torrent_metainfo_hash(info, n, h20, h32) != 2) return -1;
    ntx_torrent_init_meta(t, h20);
    memcpy(t->info_hash_v2, h32, 32);
    /* The v1 half gates on sha1(info); a hybrid carries both hashes. */
    ntx_sha1(info, n, t->info_hash);
    return ntx_torrent_validate_metainfo(t, info, n, g_layers, g_layers_n);
}

int main(void) {
    manifest m;
    if (parse_manifest(&m) != 0) { check(0, "manifest"); return 1; }
    mkdir("test/.scratch", 0755);
    {
        char cmd[256];
        snprintf(cmd, sizeof cmd, "rm -rf %s", SDIR);
        int rc = system(cmd);
        (void)rc;
        mkdir(SDIR, 0755);
    }

    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(FX "/meta.torrent", &buf, &n) != 0) { check(0, "fixture-load"); return 1; }
    ntx_be root;
    size_t consumed = 0;
    if (ntx_be_parse(buf, n, &root, &consumed, 32, (size_t)(1u << 20)) != 0) { check(0, "fixture-parse"); return 1; }
    const ntx_be *info = ntx_be_dict_get(&root, "info");
    const ntx_be *layers = ntx_be_dict_get(&root, "piece layers");
    if (!info || info->t != NTX_BE_DICT || !layers || layers->t != NTX_BE_DICT) {
        check(0, "fixture-keys");
        ntx_be_free(&root);
        return 1;
    }
    g_info = buf + info->start;
    g_info_n = info->end - info->start;
    g_layers = buf + layers->start;
    g_layers_n = layers->end - layers->start;

    /* --- validate: fields from info + layers, nothing on disk --- */
    {
        ntx_torrent t;
        ntx_torrent_init_meta(&t, m.ih_sha1);
        memcpy(t.info_hash_v2, m.ih_full, 32);
        int rc = ntx_torrent_validate_metainfo(&t, g_info, g_info_n, g_layers, g_layers_n);
        check(rc == 0, "validate-ok");
        check(t.ps == m.piece_len, "validate-ps");
        check(t.np == m.np_total, "validate-np");
        check(t.size == m.data_size, "validate-size");
        check(t.phash != NULL && memcmp(t.phash, m.phash, (size_t)m.nph * 20) == 0, "validate-phash-manifest");
        check(t.have != NULL && t.rarity != NULL && t.have_n == 0, "validate-have-alloc");
        check(t.info_raw != NULL && t.info_raw_n == g_info_n, "validate-info_raw");
        check(strcmp(t.name, "hello.txt") == 0, "validate-name");
        check(t.hybrid == 1 && t.meta_version == 2, "validate-hybrid");
        check(t.v2_nfiles == 1 && t.v2_len_file[0] == m.data_size, "validate-v2-fields");
        check(t.piece_layer != NULL && t.piece_layer_n == 128, "validate-piece_layer");
        check(t.priv == 0, "validate-no-private-key-public");
        check(t.store.pmap == NULL && t.store.fd == -1, "validate-store-untouched");
        tt_free(&t);
    }
    check(dir_entries(SDIR) == 0, "validate-store-dir-empty");

    /* --- private: any non-zero integer is private --- */
    {
        static const struct { const char *kv; int want; } cases[] = {
            {"7:privatei1e", 1},
            {"7:privatei7e", 1},
            {"7:privatei-1e", 1},
            {"7:private1:1", 0},
        };
        static uint8_t info[4096];
        for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
            size_t o = splice(info, sizeof info, cases[k].kv);
            check(o > 0, "private-splice");
            ntx_torrent t;
            int rc = validate_variant(info, o, &t);
            char nm[96];
            snprintf(nm, sizeof nm, "private-%s-priv-%d", cases[k].kv + 9, cases[k].want);
            check(rc == 0 && t.priv == cases[k].want, nm);
            tt_free(&t);
        }
        check(dir_entries(SDIR) == 0, "private-store-dir-empty");
    }

    /* --- set_metainfo still opens the store --- */
    {
        ntx_torrent t;
        ntx_torrent_init_meta(&t, m.ih_sha1);
        memcpy(t.info_hash_v2, m.ih_full, 32);
        int rc = ntx_torrent_set_metainfo(&t, g_info, g_info_n, SDIR, layers);
        check(rc == 0, "set_metainfo-ok");
        check(t.state == NTX_TTS_DL && t.have_meta == 1, "set_metainfo-state");
        check(t.store.pmap != NULL && t.store.np == m.np_total, "set_metainfo-store-open");
        check(file_exists(SDIR "/hello.txt"), "set_metainfo-creates-file");
        tt_free(&t);
        check(dir_entries(SDIR) == 1, "set_metainfo-one-file");
    }

    ntx_be_free(&root);
    free(buf);
    {
        char cmd[256];
        snprintf(cmd, sizeof cmd, "rm -rf %s", SDIR);
        int rc = system(cmd);
        (void)rc;
    }
    return fails ? 1 : 0;
}
