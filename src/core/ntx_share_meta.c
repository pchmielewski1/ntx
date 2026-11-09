#include "ntx_share_meta.h"
#include "ntx_config.h"
#include "ntx_merkle.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_sha256.h"
#include "../proto/ntx_bencode.h"

#include <stdlib.h>
#include <string.h>

/* Incremental hasher and metainfo builder for --share (design §5.2, §5.3).
 *
 * The hasher is fed the file once, sequentially, in whatever chunk the session
 * tick can afford. It keeps only the streaming contexts of the piece in flight,
 * that piece's 16 KiB leaf hashes and the finished hashes, so its footprint is
 * O(ps + np*52) — never the file. Folding the leaves of one piece matches
 * ntx_merkle_file_layer (leaves zero-filled to ps/NTX_MERKLE_LEAF), so feeding
 * a file and hashing an in-memory buffer give the same bytes. */

#define SMETA_LEAF NTX_MERKLE_LEAF

struct ntx_share_hasher {
    uint64_t size;       /* bytes to hash */
    uint64_t fed;        /* bytes fed so far */
    uint32_t ps;
    uint32_t np;
    uint32_t T;          /* leaves per piece = ps / SMETA_LEAF */
    uint32_t piece_fill; /* bytes of the piece in flight */
    uint32_t leaf_fill;  /* bytes of the leaf in flight */
    uint32_t leaf_n;     /* leaves finished in the piece in flight */
    uint32_t piece_i;    /* pieces finished */
    int root_ok;
    ntx_sha1_ctx sha1;   /* piece in flight */
    ntx_sha256_ctx leaf; /* leaf in flight */
    uint8_t *sha1list;   /* np*20 */
    uint8_t *layer;      /* np*32, NULL when np == 1 */
    uint8_t *leaves;     /* T*32, the piece in flight */
    uint8_t root[32];
};

int smeta_piece_len(uint64_t size, uint32_t *ps) {
    if (!ps || size == 0) return -1;
    uint64_t p = NTX_SHARE_PIECE_MIN;
    while (p < NTX_SHARE_PIECE_MAX && (size + p - 1) / p > 2048) p <<= 1;
    if ((size + p - 1) / p > NTX_SHARE_MAX_PIECES) return -1;
    *ps = (uint32_t)p;
    return 0;
}

ntx_share_hasher *ntx_share_hasher_new(uint64_t size, uint32_t ps) {
    if (!size || ps < NTX_SHARE_PIECE_MIN || ps > NTX_SHARE_PIECE_MAX) return NULL;
    if ((ps & (ps - 1)) != 0) return NULL;
    if ((size + ps - 1) / ps > NTX_SHARE_MAX_PIECES) return NULL;
    ntx_share_hasher *h = calloc(1, sizeof *h);
    if (!h) return NULL;
    h->size = size;
    h->ps = ps;
    h->np = (uint32_t)((size + ps - 1) / ps);
    h->T = ps / SMETA_LEAF;
    h->sha1list = malloc((size_t)h->np * 20);
    h->leaves = malloc((size_t)h->T * 32);
    h->layer = h->np > 1 ? malloc((size_t)h->np * 32) : NULL;
    if (!h->sha1list || !h->leaves || (h->np > 1 && !h->layer)) {
        ntx_share_hasher_free(h);
        return NULL;
    }
    ntx_sha1_init(&h->sha1);
    ntx_sha256_init(&h->leaf);
    return h;
}

void ntx_share_hasher_free(ntx_share_hasher *h) {
    if (!h) return;
    free(h->sha1list);
    free(h->layer);
    free(h->leaves);
    free(h);
}

/* Fold `lev` of p 32-byte hashes down to one hash (same fold as ntx_merkle.c). */
static void smeta_fold(uint8_t *lev, size_t p) {
    while (p > 1) {
        for (size_t j = 0; j < p / 2; j++) {
            uint8_t cat[64];
            memcpy(cat, lev + j * 2 * 32, 32);
            memcpy(cat + 32, lev + (j * 2 + 1) * 32, 32);
            ntx_sha256(cat, 64, lev + j * 32);
        }
        p >>= 1;
    }
}

/* One piece done: close its SHA-1, flush a short tail leaf and fold the piece's
 * leaves. Multi-piece files store the fold as the piece-layer entry; a
 * single-piece file has no piece-layer level, so the same fold over its leaf
 * list (zero-filled to a power of two, BEP 52) *is* the pieces root and has to
 * be taken here, while leaf_n still describes the file. */
static int smeta_piece_end(ntx_share_hasher *h, int partial) {
    ntx_sha1_final(&h->sha1, h->sha1list + (size_t)h->piece_i * 20);
    ntx_sha1_init(&h->sha1);
    if (partial && h->leaf_fill) {
        ntx_sha256_final(&h->leaf, h->leaves + (size_t)h->leaf_n * 32);
        h->leaf_n++;
        h->leaf_fill = 0;
    }
    if (h->np > 1) {
        for (uint32_t i = h->leaf_n; i < h->T; i++) memset(h->leaves + (size_t)i * 32, 0, 32);
        smeta_fold(h->leaves, h->T);
        memcpy(h->layer + (size_t)h->piece_i * 32, h->leaves, 32);
    } else {
        size_t p = 1;
        while (p < h->leaf_n) p <<= 1;
        uint8_t *lev = malloc(p * 32);
        if (!lev) return -1;
        memcpy(lev, h->leaves, (size_t)h->leaf_n * 32);
        for (size_t i = h->leaf_n; i < p; i++) memset(lev + i * 32, 0, 32);
        smeta_fold(lev, p);
        memcpy(h->root, lev, 32);
        free(lev);
    }
    h->piece_i++;
    h->piece_fill = 0;
    h->leaf_n = 0;
    ntx_sha256_init(&h->leaf);
    return 0;
}

/* All bytes fed: close the last piece, then fold the piece layer up to the root. */
static int smeta_finish(ntx_share_hasher *h) {
    if (h->piece_i < h->np && smeta_piece_end(h, 1) != 0) return -1;
    if (h->np > 1 &&
        ntx_merkle_root_from_layer(h->layer, (size_t)h->np * 32, h->ps, h->size, h->root) != 0)
        return -1;
    h->root_ok = 1;
    return 0;
}

int ntx_share_hasher_feed(ntx_share_hasher *h, const uint8_t *buf, size_t n) {
    if (!h || (n && !buf)) return -1;
    if (h->fed + n > h->size) return -1; /* file grew, or fed twice */
    while (n > 0) {
        size_t room = SMETA_LEAF - h->leaf_fill;
        size_t left = (size_t)h->ps - h->piece_fill;
        if (left < room) room = left;
        size_t k = n < room ? n : room;
        ntx_sha1_update(&h->sha1, buf, k);
        ntx_sha256_update(&h->leaf, buf, k);
        buf += k;
        n -= k;
        h->fed += k;
        h->piece_fill += (uint32_t)k;
        h->leaf_fill += (uint32_t)k;
        if (h->leaf_fill == SMETA_LEAF) {
            ntx_sha256_final(&h->leaf, h->leaves + (size_t)h->leaf_n * 32);
            h->leaf_n++;
            h->leaf_fill = 0;
            ntx_sha256_init(&h->leaf);
        }
        if (h->piece_fill == h->ps && smeta_piece_end(h, 0) != 0) return -1;
    }
    if (h->fed == h->size && !h->root_ok) return smeta_finish(h);
    return 0;
}

int ntx_share_hasher_done(const ntx_share_hasher *h) {
    return h && h->fed == h->size && h->piece_i == h->np && h->root_ok;
}

const uint8_t *ntx_share_hasher_sha1(const ntx_share_hasher *h) {
    return ntx_share_hasher_done(h) ? h->sha1list : NULL;
}

const uint8_t *ntx_share_hasher_root(const ntx_share_hasher *h) {
    return ntx_share_hasher_done(h) ? h->root : NULL;
}

const uint8_t *ntx_share_hasher_layer(const ntx_share_hasher *h, size_t *n) {
    if (n) *n = 0;
    if (!ntx_share_hasher_done(h) || h->np == 1) return NULL;
    if (n) *n = (size_t)h->np * 32;
    return h->layer;
}

/* --- metainfo (§5.2) --- */

static int smeta_name_ok(const char *name) {
    if (!name || !name[0]) return 0;
    for (size_t i = 0; name[i]; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f || c == '/') return 0;
    }
    return 1;
}

static int smeta_salt_ok(const char *salt_hex) {
    if (!salt_hex) return 0;
    int i;
    for (i = 0; i < 32; i++) {
        char c = salt_hex[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) return 0;
    }
    return salt_hex[i] == '\0';
}

static void smeta_str(ntx_be *b, const void *p, size_t n) {
    memset(b, 0, sizeof *b);
    b->t = NTX_BE_STR;
    b->sp = (uint8_t *)p;
    b->sn = n;
}

static void smeta_int(ntx_be *b, int64_t v) {
    memset(b, 0, sizeof *b);
    b->t = NTX_BE_INT;
    b->i = v;
}

static void smeta_dict(ntx_be *b, const be_dict *d) {
    memset(b, 0, sizeof *b);
    b->t = NTX_BE_DICT;
    b->nd = d->n;
    b->k = d->kp;
    b->v = d->vp;
}

int ntx_share_build_info(const ntx_share_hasher *h, const char *name, const char salt_hex[33],
                         uint8_t **info, size_t *info_n) {
    if (info) *info = NULL;
    if (info_n) *info_n = 0;
    if (!h || !info || !info_n || !ntx_share_hasher_done(h)) return -1;
    if (!smeta_name_ok(name) || !smeta_salt_ok(salt_hex)) return -1;

    size_t name_n = strlen(name);
    uint8_t empty_key = 0; /* the "" key of the file's property dict */
    be_dict props, file, tree, top;
    ntx_be propsd, filed, treed, infod, k, s;
    uint8_t *buf = NULL;
    int rc = -1;
    size_t cap = (size_t)h->np * 20 + name_n * 2 + 1024;

    memset(&props, 0, sizeof props);
    memset(&file, 0, sizeof file);
    memset(&tree, 0, sizeof tree);
    memset(&top, 0, sizeof top);
    if (be_dict_init(&props, 2) || be_dict_init(&file, 1) || be_dict_init(&tree, 1) ||
        be_dict_init(&top, 8))
        goto done;

    smeta_str(&k, "length", 6);
    smeta_int(&s, (int64_t)h->size);
    if (be_dict_add(&props, k, s) != 0) goto done;
    smeta_str(&k, "pieces root", 11);
    smeta_str(&s, h->root, 32);
    if (be_dict_add(&props, k, s) != 0) goto done;

    smeta_dict(&propsd, &props);
    smeta_str(&k, &empty_key, 0);
    if (be_dict_add(&file, k, propsd) != 0) goto done;
    smeta_dict(&filed, &file);
    smeta_str(&k, name, name_n);
    if (be_dict_add(&tree, k, filed) != 0) goto done;
    smeta_dict(&treed, &tree);

    smeta_str(&k, "file tree", 9);
    if (be_dict_add(&top, k, treed) != 0) goto done;
    smeta_str(&k, "length", 6);
    smeta_int(&s, (int64_t)h->size);
    if (be_dict_add(&top, k, s) != 0) goto done;
    smeta_str(&k, "meta version", 12);
    smeta_int(&s, 2);
    if (be_dict_add(&top, k, s) != 0) goto done;
    smeta_str(&k, "name", 4);
    smeta_str(&s, name, name_n);
    if (be_dict_add(&top, k, s) != 0) goto done;
    smeta_str(&k, "ntx salt", 8);
    smeta_str(&s, salt_hex, 32);
    if (be_dict_add(&top, k, s) != 0) goto done;
    smeta_str(&k, "piece length", 12);
    smeta_int(&s, (int64_t)h->ps);
    if (be_dict_add(&top, k, s) != 0) goto done;
    smeta_str(&k, "pieces", 6);
    smeta_str(&s, h->sha1list, (size_t)h->np * 20);
    if (be_dict_add(&top, k, s) != 0) goto done;
    smeta_str(&k, "private", 7);
    smeta_int(&s, 1);
    if (be_dict_add(&top, k, s) != 0) goto done;

    smeta_dict(&infod, &top);
    buf = malloc(cap);
    if (!buf) goto done;
    if (ntx_be_encode(&infod, buf, cap, info_n) != 0) goto done;
    *info = buf;
    buf = NULL;
    rc = 0;

done:
    be_dict_free(&props);
    be_dict_free(&file);
    be_dict_free(&tree);
    be_dict_free(&top);
    free(buf);
    if (rc != 0) {
        free(*info);
        *info = NULL;
        *info_n = 0;
    }
    return rc;
}

int ntx_share_build_torrent(const uint8_t *info, size_t info_n, const ntx_share_hasher *h,
                            const char *const *trackers, int ntrk, int64_t creation_date,
                            uint8_t **out, size_t *out_n) {
    if (out) *out = NULL;
    if (out_n) *out_n = 0;
    if (!info || !h || !ntx_share_hasher_done(h) || !out || !out_n) return -1;
    if (!trackers || ntrk < 1) return -1;
    for (int i = 0; i < ntrk; i++)
        if (!trackers[i] || !trackers[i][0]) return -1;

    ntx_be infobe;
    int have_info = 0;
    size_t consumed = 0;
    if (ntx_be_parse(info, info_n, &infobe, &consumed, 32, (size_t)1 << 20) != 0) return -1;
    if (infobe.t != NTX_BE_DICT || consumed != info_n) {
        ntx_be_free(&infobe);
        return -1;
    }
    have_info = 1;

    size_t trk_bytes = 0;
    for (int i = 0; i < ntrk; i++) trk_bytes += strlen(trackers[i]);
    size_t cap = info_n + trk_bytes * 2 + (size_t)h->np * 32 + (size_t)ntrk * 16 + 1024;
    uint8_t *buf = malloc(cap);
    /* announce-list is a list of ntrk one-element lists; the encoder reads the
     * three pointer blocks below but keeps nothing after the call. */
    ntx_be *al_str = calloc((size_t)ntrk, sizeof *al_str);
    ntx_be *al_row = calloc((size_t)ntrk, sizeof *al_row);
    ntx_be **al_item = calloc((size_t)ntrk, sizeof *al_item);
    ntx_be **al_el = calloc((size_t)ntrk, sizeof *al_el);
    be_dict top, pl;
    ntx_be pld, alist, k, s;
    int rc = -1;
    memset(&top, 0, sizeof top);
    memset(&pl, 0, sizeof pl);

    if (!buf || !al_str || !al_row || !al_item || !al_el) goto done;
    if (be_dict_init(&top, 6) != 0) goto done;
    if (h->np > 1 && be_dict_init(&pl, 1) != 0) goto done;

    smeta_str(&k, "announce", 8);
    smeta_str(&s, trackers[0], strlen(trackers[0]));
    if (be_dict_add(&top, k, s) != 0) goto done;

    for (int i = 0; i < ntrk; i++) {
        smeta_str(&al_str[i], trackers[i], strlen(trackers[i]));
        al_item[i] = &al_str[i];
        memset(&al_row[i], 0, sizeof al_row[i]);
        al_row[i].t = NTX_BE_LIST;
        al_row[i].el = &al_item[i];
        al_row[i].ne = 1;
        al_el[i] = &al_row[i];
    }
    memset(&alist, 0, sizeof alist);
    alist.t = NTX_BE_LIST;
    alist.el = al_el;
    alist.ne = (size_t)ntrk;
    smeta_str(&k, "announce-list", 13);
    if (be_dict_add(&top, k, alist) != 0) goto done;

    smeta_str(&k, "created by", 10);
    smeta_str(&s, "ntx/" NTX_VERSION, strlen("ntx/" NTX_VERSION));
    if (be_dict_add(&top, k, s) != 0) goto done;

    smeta_str(&k, "creation date", 13);
    smeta_int(&s, creation_date);
    if (be_dict_add(&top, k, s) != 0) goto done;

    smeta_str(&k, "info", 4);
    if (be_dict_add(&top, k, infobe) != 0) goto done;

    if (h->np > 1) {
        /* piece layers exist only above one piece; keyed by the pieces root. */
        smeta_str(&k, h->root, 32);
        smeta_str(&s, h->layer, (size_t)h->np * 32);
        if (be_dict_add(&pl, k, s) != 0) goto done;
        smeta_dict(&pld, &pl);
        smeta_str(&k, "piece layers", 12);
        if (be_dict_add(&top, k, pld) != 0) goto done;
    }

    {
        ntx_be toprd;
        smeta_dict(&toprd, &top);
        if (ntx_be_encode(&toprd, buf, cap, out_n) != 0) goto done;
        *out = buf;
        buf = NULL;
    }
    rc = 0;

done:
    be_dict_free(&top);
    be_dict_free(&pl);
    if (have_info) ntx_be_free(&infobe);
    free(buf);
    free(al_str);
    free(al_row);
    free(al_item);
    free(al_el);
    if (rc != 0) {
        free(*out);
        *out = NULL;
        *out_n = 0;
    }
    return rc;
}
