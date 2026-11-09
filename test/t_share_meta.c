/* Task A3 (§5.2, §5.3): incremental share hasher and the private hybrid
 * v1+v2 metainfo builder.  The golden bytes come from test/scripts/share_gen.py
 * (Python hashlib + handwritten bencode); the C output must match them byte for
 * byte.  Covers Review Focus 3: 1 B, exactly one piece, multiple of the piece
 * length and multiple + 1 B, and the rule that piece layers exist iff np > 1.
 * The A2 validator is the second gate: the built info + layers must validate
 * and come out private. */
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
#include "../src/core/ntx_config.h"
#include "../src/core/ntx_share_meta.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FXDIR "test/vectors/share"
#define CHUNK 7919 /* deliberately not a divisor of the piece length */
/* Fixtures hold at most 4 pieces; 8 leaves room for a hand-written manifest
 * without letting a manifest line grow past the arrays below. */
#define MAXN 8
#define MAXHEX 1200

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

static int find_sub(const uint8_t *hay, size_t hn, const uint8_t *needy, size_t nn) {
    if (nn == 0 || nn > hn) return -1;
    for (size_t i = 0; i + nn <= hn; i++)
        if (memcmp(hay + i, needy, nn) == 0) return (int)i;
    return -1;
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
    char name[512];
    uint64_t size;
    uint32_t ps;
    uint32_t np;
    int has_layers;
    char salt[64];
    long long creation_date;
    char created_by[64];
    uint8_t ih_sha1[20];
    uint8_t ih_sha256[32];
    uint8_t root[32];
    uint8_t pieces[MAXN * 20];
    uint8_t layer[MAXN * 32];
    int layer_n;
} manifest;

static void copy_field(char *dst, size_t cap, const char *s) {
    size_t n = strlen(s);
    if (n >= cap) n = cap - 1;
    memcpy(dst, s, n);
    dst[n] = '\0';
}

static int parse_manifest(const char *fx, manifest *m) {
    char path[512];
    snprintf(path, sizeof path, FXDIR "/%s/manifest.txt", fx);
    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(path, &buf, &n) != 0) return -1;
    memset(m, 0, sizeof *m);
    char *line = (char *)buf;
    while (*line) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        unsigned u;
        unsigned long long ul;
        long long ll;
        char hex[MAXHEX];
        char s[MAXHEX];
        if (sscanf(line, "name: %63s", s) == 1) {
            copy_field(m->name, sizeof m->name, s);
        } else if (sscanf(line, "size: %llu", &ul) == 1) {
            m->size = ul;
        } else if (sscanf(line, "ps: %u", &u) == 1) {
            m->ps = u;
        } else if (sscanf(line, "np: %u", &u) == 1) {
            m->np = u;
        } else if (sscanf(line, "has_layers: %u", &u) == 1) {
            m->has_layers = (int)u;
        } else if (sscanf(line, "salt: %63s", s) == 1) {
            copy_field(m->salt, sizeof m->salt, s);
        } else if (sscanf(line, "creation_date: %lld", &ll) == 1) {
            m->creation_date = ll;
        } else if (sscanf(line, "created_by: %63s", s) == 1) {
            copy_field(m->created_by, sizeof m->created_by, s);
        } else if (sscanf(line, "ih_sha1: %511s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_sha1, 20) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "ih_sha256: %511s", hex) == 1) {
            if (hex_to_bytes(hex, m->ih_sha256, 32) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "root: %511s", hex) == 1) {
            if (hex_to_bytes(hex, m->root, 32) != 0) { free(buf); return -1; }
        } else if (sscanf(line, "pieces_sha1: %1199s", hex) == 1) {
            /* the count comes from the manifest, the destination is fixed: bound it */
            size_t pn = (size_t)m->np * 20;
            if (pn > sizeof m->pieces || hex_to_bytes(hex, m->pieces, pn) != 0) {
                free(buf);
                return -1;
            }
        } else if (sscanf(line, "layer: %1199s", hex) == 1) {
            size_t ln = strlen(hex) / 2;
            if (ln > sizeof m->layer || hex_to_bytes(hex, m->layer, ln) != 0) {
                free(buf);
                return -1;
            }
            m->layer_n = (int)ln;
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return m->np > 0 && m->ps > 0 ? 0 : -1;
}

static int read_trackers(const char *fx, char trks[8][256]) {
    char path[512];
    snprintf(path, sizeof path, FXDIR "/%s/trackers.txt", fx);
    uint8_t *buf = 0;
    size_t n = 0;
    if (read_file(path, &buf, &n) != 0) return -1;
    int cnt = 0;
    char *line = (char *)buf;
    while (*line && cnt < 8) {
        char *nl = strchr(line, '\n');
        if (nl) *nl = '\0';
        if (*line) {
            snprintf(trks[cnt], 256, "%s", line);
            cnt++;
        }
        if (!nl) break;
        line = nl + 1;
    }
    free(buf);
    return cnt;
}

/* --- piece-size rule (§5.2) --- */
static void test_piece_len(void) {
    const uint64_t K = 1024, M = 1024 * 1024;
    uint32_t ps;
    struct { uint64_t size; int rc; uint32_t ps; } cases[] = {
        {1, 0, 16 * K},
        {2048ull * 16 * K, 0, 16 * K},
        {2048ull * 16 * K + 1, 0, 32 * K},
        {2048ull * 64 * M, 0, 64 * M},
        {32768ull * 64 * M, 0, 64 * M},
        {32768ull * 64 * M + 1, -1, 0},
    };
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        ps = 0;
        int rc = smeta_piece_len(cases[i].size, &ps);
        char nm[96];
        snprintf(nm, sizeof nm, "piece_len[%zu] rc=%d ps=%u", i, cases[i].rc, cases[i].ps);
        check(rc == cases[i].rc && (rc != 0 || ps == cases[i].ps), nm);
    }
    /* every power of two in the band is reachable and the count stays <= 2048 */
    for (int e = 14; e <= 26; e++) {
        uint64_t size = ((uint64_t)1 << e) * 2048;
        ps = 0;
        char nm[96];
        snprintf(nm, sizeof nm, "piece_len_pow2_e%d", e);
        check(smeta_piece_len(size, &ps) == 0 && ps == (uint32_t)1 << e, nm);
    }
    check(smeta_piece_len(0, &ps) == -1, "piece_len_zero_rejected");
    /* size + ps - 1 would wrap at the top of the range: the ceil must not be
     * allowed to land on a small piece count (ps is only written on success). */
    {
        const uint64_t tops[] = { UINT64_MAX, UINT64_MAX - 1, UINT64_MAX - NTX_SHARE_PIECE_MIN + 1,
                                  UINT64_MAX - NTX_SHARE_PIECE_MAX };
        for (size_t i = 0; i < sizeof tops / sizeof tops[0]; i++) {
            ps = 0xBADF1E;
            char nm[96];
            snprintf(nm, sizeof nm, "piece_len_overflow_%zu", i);
            check(smeta_piece_len(tops[i], &ps) == -1 && ps == 0xBADF1E, nm);
            snprintf(nm, sizeof nm, "hasher_new_overflow_%zu", i);
            check(ntx_share_hasher_new(tops[i], NTX_SHARE_PIECE_MIN) == NULL, nm);
        }
    }
}

/* Feed the fixture in CHUNK-sized pieces and compare every produced byte. */
static void test_fixture(const char *fx) {
    manifest m;
    char path[512];
    if (parse_manifest(fx, &m) != 0) { check(0, "manifest"); return; }

    uint8_t *data = 0, *want_info = 0, *want_meta = 0, *salt = 0;
    size_t data_n = 0, info_n = 0, meta_n = 0, salt_n = 0;
    snprintf(path, sizeof path, FXDIR "/%s/data.bin", fx);
    int ok = read_file(path, &data, &data_n) == 0 && data_n == m.size;
    snprintf(path, sizeof path, FXDIR "/%s/info.bin", fx);
    ok = ok && read_file(path, &want_info, &info_n) == 0;
    snprintf(path, sizeof path, FXDIR "/%s/meta.torrent", fx);
    ok = ok && read_file(path, &want_meta, &meta_n) == 0;
    snprintf(path, sizeof path, FXDIR "/%s/salt.txt", fx);
    ok = ok && read_file(path, &salt, &salt_n) == 0 && salt_n == 32;
    char nm[96];
    snprintf(nm, sizeof nm, "%s: load", fx);
    if (!ok) { check(0, nm); free(data); free(want_info); free(want_meta); free(salt); return; }
    check(1, nm);

    char trk[8][256];
    int ntrk = read_trackers(fx, trk);
    snprintf(nm, sizeof nm, "%s: trackers", fx);
    check(ntrk >= 2, nm);

    uint32_t ps = 0;
    snprintf(nm, sizeof nm, "%s: piece_len-rule", fx);
    check(smeta_piece_len(m.size, &ps) == 0 && ps == m.ps, nm);

    ntx_share_hasher *h = ntx_share_hasher_new(m.size, m.ps);
    snprintf(nm, sizeof nm, "%s: hasher-new", fx);
    check(h != NULL, nm);
    if (!h) { free(data); free(want_info); free(want_meta); free(salt); return; }

    snprintf(nm, sizeof nm, "%s: not-done-before-feed", fx);
    check(ntx_share_hasher_done(h) == 0, nm);

    size_t off = 0;
    int fed = 0;
    while (off < data_n) {
        size_t k = data_n - off < CHUNK ? data_n - off : CHUNK;
        fed |= ntx_share_hasher_feed(h, data + off, k);
        off += k;
    }
    snprintf(nm, sizeof nm, "%s: feed-chunks", fx);
    check(fed == 0, nm);
    snprintf(nm, sizeof nm, "%s: done", fx);
    check(ntx_share_hasher_done(h) == 1, nm);

    /* feeding past EOF is refused and leaves the hashes alone */
    {
        uint8_t extra = 0;
        snprintf(nm, sizeof nm, "%s: feed-overflow-rejected", fx);
        check(ntx_share_hasher_feed(h, &extra, 1) == -1 && ntx_share_hasher_done(h) == 1, nm);
    }

    /* NULL buf is refused even at n == 0 (must not count as completion) */
    {
        ntx_share_hasher *p = ntx_share_hasher_new(1, m.ps);
        snprintf(nm, sizeof nm, "%s: feed-null-buf-rejected", fx);
        check(p && ntx_share_hasher_feed(p, NULL, 0) == -1 && ntx_share_hasher_done(p) == 0, nm);
        ntx_share_hasher_free(p);
    }

    /* The single-piece root fold allocates nothing, so it cannot half-fail and
     * leave a retry to report done with SHA-1("") bytes; a byte-equal root below
     * proves the in-place fold, the valgrind/ASan run shows no malloc there. */
    if (m.np == 1) {
        ntx_share_hasher *p = ntx_share_hasher_new(m.size, m.ps);
        int prc = p ? ntx_share_hasher_feed(p, data, data_n) : -1;
        snprintf(nm, sizeof nm, "%s: single-piece-inplace-fold", fx);
        check(prc == 0 && ntx_share_hasher_done(p) == 1 &&
              ntx_share_hasher_root(p) && memcmp(ntx_share_hasher_root(p), m.root, 32) == 0 &&
              memcmp(ntx_share_hasher_sha1(p), m.pieces, 20) == 0, nm);
        ntx_share_hasher_free(p);
    }

    size_t ln = 0;
    const uint8_t *lay = ntx_share_hasher_layer(h, &ln);
    snprintf(nm, sizeof nm, "%s: sha1-list", fx);
    check(ntx_share_hasher_sha1(h) && memcmp(ntx_share_hasher_sha1(h), m.pieces, (size_t)m.np * 20) == 0, nm);
    snprintf(nm, sizeof nm, "%s: root", fx);
    check(ntx_share_hasher_root(h) && memcmp(ntx_share_hasher_root(h), m.root, 32) == 0, nm);
    snprintf(nm, sizeof nm, "%s: layer-presence(np>1)", fx);
    check((m.np > 1) == (lay != NULL) && ln == (size_t)m.layer_n, nm);
    snprintf(nm, sizeof nm, "%s: layer-bytes", fx);
    check(lay ? memcmp(lay, m.layer, ln) == 0 : (ln == 0 && m.layer_n == 0), nm);

    uint8_t *info = 0, *meta = 0;
    size_t info_cn = 0, meta_cn = 0;
    int rc = ntx_share_build_info(h, m.name, m.salt, &info, &info_cn);
    snprintf(nm, sizeof nm, "%s: build-info-ok", fx);
    check(rc == 0 && info && info_cn == info_n, nm);
    snprintf(nm, sizeof nm, "%s: info-bytes", fx);
    check(rc == 0 && info_cn == info_n && memcmp(info, want_info, info_n) == 0, nm);

    const char *trkptr[8];
    for (int i = 0; i < ntrk && i < 8; i++) trkptr[i] = trk[i];
    rc = ntx_share_build_torrent(info, info_cn, h, trkptr, ntrk, m.creation_date, &meta, &meta_cn);
    snprintf(nm, sizeof nm, "%s: build-torrent-ok", fx);
    check(rc == 0 && meta && meta_cn == meta_n, nm);
    snprintf(nm, sizeof nm, "%s: torrent-bytes", fx);
    check(rc == 0 && meta_cn == meta_n && memcmp(meta, want_meta, meta_n) == 0, nm);

    /* created by must be ntx/<NTX_VERSION>, the same source as every other version string */
    {
        char want[64];
        snprintf(want, sizeof want, "ntx/" NTX_VERSION);
        snprintf(nm, sizeof nm, "%s: created-by", fx);
        check(strcmp(m.created_by, want) == 0 && meta &&
              find_sub(meta, meta_n, (const uint8_t *)want, strlen(want)) >= 0, nm);
    }

    /* info.bin must be the exact substring the torrent carries */
    {
        snprintf(nm, sizeof nm, "%s: info-substring", fx);
        check(meta && info && find_sub(meta, meta_cn, info, info_cn) >= 0, nm);
    }

    /* --- A2 validator on the built info + layers --- */
    {
        const uint8_t *layers = NULL;
        size_t layers_n = 0;
        if (m.has_layers) {
            ntx_be top;
            size_t consumed = 0;
            size_t ls = 0, le = 0;
            int prc = ntx_be_parse(meta, meta_cn, &top, &consumed, 32, (size_t)meta_cn + 1);
            const ntx_be *pl = prc == 0 ? ntx_be_dict_get(&top, "piece layers") : NULL;
            if (pl && pl->t == NTX_BE_DICT) {
                ls = pl->start;
                le = pl->end;
            }
            ntx_be_free(&top); /* the layer bytes live in meta, not in the tree */
            if (le > ls) {
                layers = meta + ls;
                layers_n = le - ls;
            }
        }
        ntx_torrent t;
        ntx_torrent_init_meta(&t, m.ih_sha1);
        memcpy(t.info_hash_v2, m.ih_sha256, 32);
        int vrc = ntx_torrent_validate_metainfo(&t, info, info_cn, layers, layers_n);
        snprintf(nm, sizeof nm, "%s: validate-ok", fx);
        check(vrc == 0, nm);
        snprintf(nm, sizeof nm, "%s: validate-priv", fx);
        check(vrc == 0 && t.priv == 1, nm);
        snprintf(nm, sizeof nm, "%s: validate-hashes", fx);
        check(memcmp(t.info_hash, m.ih_sha1, 20) == 0 &&
              memcmp(t.info_hash_v2, m.ih_sha256, 32) == 0, nm);
        snprintf(nm, sizeof nm, "%s: validate-fields", fx);
        check(vrc == 0 && t.ps == m.ps && t.np == m.np && t.size == m.size &&
              strcmp(t.name, m.name) == 0 && t.hybrid == 1 && t.meta_version == 2, nm);
        snprintf(nm, sizeof nm, "%s: validate-phash", fx);
        check(vrc == 0 && t.phash && memcmp(t.phash, m.pieces, (size_t)m.np * 20) == 0, nm);
        snprintf(nm, sizeof nm, "%s: validate-piece_layer(np>1)", fx);
        check((m.np > 1) == (t.piece_layer != NULL) &&
              (t.piece_layer ? t.piece_layer_n == (size_t)m.layer_n : t.piece_layer_n == 0), nm);
        snprintf(nm, sizeof nm, "%s: validate-piece_layer-bytes", fx);
        check(t.piece_layer ? memcmp(t.piece_layer, m.layer, t.piece_layer_n) == 0 : 1, nm);
        snprintf(nm, sizeof nm, "%s: validate-root", fx);
        check(vrc == 0 && t.v2_nfiles == 1 && memcmp(t.v2_root[0], m.root, 32) == 0, nm);
        tt_free(&t);
    }

    /* --- bad-argument paths --- */
    {
        uint8_t *bad = 0;
        size_t badn = 0;
        snprintf(nm, sizeof nm, "%s: build-info-before-done", fx);
        ntx_share_hasher *p = ntx_share_hasher_new(m.size, m.ps);
        check(p && ntx_share_build_info(p, m.name, m.salt, &bad, &badn) == -1 && bad == NULL, nm);
        ntx_share_hasher_free(p);
        char badsalt[33];
        memcpy(badsalt, m.salt, 33);
        badsalt[0] = 'Z';
        snprintf(nm, sizeof nm, "%s: build-info-bad-salt", fx);
        check(ntx_share_build_info(h, m.name, badsalt, &bad, &badn) == -1 && bad == NULL, nm);
        snprintf(nm, sizeof nm, "%s: build-info-empty-name", fx);
        check(ntx_share_build_info(h, "", m.salt, &bad, &badn) == -1, nm);
        snprintf(nm, sizeof nm, "%s: build-torrent-no-trackers", fx);
        check(ntx_share_build_torrent(info, info_cn, h, trkptr, 0, m.creation_date, &bad, &badn) == -1, nm);
        snprintf(nm, sizeof nm, "%s: hasher-new-bad-ps", fx);
        check(ntx_share_hasher_new(m.size, 12345) == NULL && ntx_share_hasher_new(0, m.ps) == NULL, nm);
    }

    ntx_share_hasher_free(h);
    free(info);
    free(meta);
    free(data);
    free(want_info);
    free(want_meta);
    free(salt);
}

int main(void) {
    test_piece_len();
    static const char *fxs[] = { "tiny_1b", "one_piece_16k", "multi_tail", "exact_multi" };
    for (size_t i = 0; i < sizeof fxs / sizeof fxs[0]; i++) test_fixture(fxs[i]);
    return fails ? 1 : 0;
}
