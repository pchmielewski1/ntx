#include "ntx_torrent.h"
#include "ntx_store.h"
#include "ntx_torrent_v2.h"
#include "ntx_merkle.h"
#include "../proto/ntx_bencode.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_sha256.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#define TT_MAX_BANS 128

static struct {
    const ntx_peer *p;
    uint64_t until;
} tt_bans[TT_MAX_BANS];

void ntx_torrent_peer_ban(ntx_peer *p, uint64_t now_ms) {
    if (!p) return;
    p->we_choke = 1;
    p->spd_d = 0;
    uint64_t until = now_ms + NTX_TORRENT_PEER_BAN_MS;
    for (int i = 0; i < TT_MAX_BANS; i++) {
        if (tt_bans[i].p == (const ntx_peer *)p || !tt_bans[i].p) {
            tt_bans[i].p = p;
            tt_bans[i].until = until;
            return;
        }
    }
}

static uint64_t tt_peer_ban_until(const ntx_peer *p) {
    if (!p) return 0;
    for (int i = 0; i < TT_MAX_BANS; i++)
        if (tt_bans[i].p == p) return tt_bans[i].until;
    return 0;
}

int ntx_torrent_peer_banned(const ntx_peer *p, uint64_t now_ms) {
    uint64_t until = tt_peer_ban_until(p);
    return until != 0 && now_ms < until;
}

/* BEP52: map a global piece index to (v2 file, intra-file piece).
 * Returns 0 on success, -1 when i is outside the v2 address space. */
static int tt_v2_piece_loc(const ntx_torrent *t, uint32_t i, uint32_t *f, uint32_t *j) {
    for (uint32_t k = 0; k < t->v2_nfiles; k++) {
        if (i >= t->v2_first_piece[k] && i < t->v2_first_piece[k] + t->v2_np_file[k]) {
            *f = k;
            *j = i - t->v2_first_piece[k];
            return 0;
        }
    }
    return -1;
}

/* Piece data length: v1 -> store pl; v2/hybrid -> min(ps, len_file - j*ps)
 * (alignment gaps between files are not stored; only the last piece of a
 * file can be short). 0 when i is invalid. */
static uint32_t tt_piece_len(const ntx_torrent *t, uint32_t i) {
    if (t->meta_version == 0) return ntx_store_pl(&t->store, i);
    uint32_t f, j;
    if (tt_v2_piece_loc(t, i, &f, &j) != 0) return 0;
    uint64_t rem = t->v2_len_file[f] - (uint64_t)j * t->ps;
    return rem < t->ps ? (uint32_t)rem : t->ps;
}

/* BEP52 merkle check for one piece (v2/hybrid); buf holds the piece bytes.
 * piece_layer is the concatenation of per-file layers, only for files with
 * len > ps, in file order. */
static int tt_v2_piece_ok(const ntx_torrent *t, uint32_t i, const uint8_t *buf, uint32_t pl) {
    uint32_t f, j;
    if (tt_v2_piece_loc(t, i, &f, &j) != 0) return 0;
    if (t->v2_len_file[f] <= t->ps) {
        /* Single-piece file: piece hash == pieces root (null-layer path). */
        return ntx_merkle_verify_piece_layer(t->v2_root[f], NULL, 0, t->ps, 0, buf, pl) == 0;
    }
    if (!t->piece_layer) return 0;
    uint64_t off = 0;
    for (uint32_t g = 0; g < f; g++)
        if (t->v2_len_file[g] > t->ps) off += t->v2_np_file[g];
    const uint8_t *layer = t->piece_layer + off * 32;
    return ntx_merkle_verify_piece_layer(t->v2_root[f], layer, (size_t)t->v2_np_file[f] * 32,
                                         t->ps, j, buf, pl) == 0;
}

/* Verify one piece from the store: v1 SHA-1; v2 merkle; hybrid both (SHA-1
 * required for v1 swarm compatibility, merkle when piece_layer is present).
 * 1 = verified. */
static int tt_piece_verify(const ntx_torrent *t, uint32_t i, uint32_t pl, uint8_t *buf) {
    if (ntx_store_read(&t->store, i, 0, buf, pl) != (int)pl) return 0;
    if (t->meta_version == 0) {
        uint8_t h[20];
        ntx_sha1(buf, pl, h);
        return memcmp(h, t->phash + (size_t)i * 20, 20) == 0;
    }
    if (t->phash != NULL) {
        uint8_t h[20];
        ntx_sha1(buf, pl, h);
        if (memcmp(h, t->phash + (size_t)i * 20, 20) != 0) return 0;
    }
    /* The "cross-check off" shortcut is sound only when the v1 SHA-1 above
     * actually verified (hybrid/v1 carry phash). A pure-v2 torrent (phash
     * NULL) without layers must still not be trusted blindly: fall through to
     * tt_v2_piece_ok, which verifies single-piece files directly against the
     * pieces root (null-layer path) and refuses multi-piece files until the
     * layers arrive via the hash exchange. */
    if (t->piece_layer == NULL && t->phash != NULL) return 1;
    return tt_v2_piece_ok(t, i, buf, pl);
}

static void tt_piece_clear(ntx_torrent *t, uint32_t i) {
    if (i >= t->np) return;
    uint32_t pl = tt_piece_len(t, i);
    if (t->have[i]) {
        t->have[i] = 0;
        if (t->have_n > 0) t->have_n--;
        if (t->verified_B >= pl) t->verified_B -= pl;
    }
    t->store.pmap[i] = 0;
}

int ntx_torrent_init_meta(ntx_torrent *t, const uint8_t info_hash[20]) {
    memset(t, 0, sizeof(*t));
    memcpy(t->info_hash, info_hash, 20);
    t->store.fd = -1;
    t->have_meta = 0;
    t->state = NTX_TTS_META;
    return 0;
}

static void tt_free(ntx_torrent *t) {
    free(t->phash);
    free(t->have);
    free(t->rarity);
    free(t->info_raw);
    free(t->piece_layer);
    t->phash = NULL;
    t->have = NULL;
    t->rarity = NULL;
    t->info_raw = NULL;
    t->piece_layer = NULL;
    t->piece_layer_n = 0;
    t->info_raw_n = 0;
    ntx_store_close(&t->store);
}

static int tt_set_metainfo_v1(ntx_torrent *t, const uint8_t *info_dict, size_t info_len, const char *store_dir) {
    uint8_t h[20];
    ntx_sha1(info_dict, info_len, h);
    if (memcmp(h, t->info_hash, 20) != 0) return -1;

    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(info_dict, info_len, &be, &consumed, 32, (size_t)(1u << 24)) != 0) return -1;
    if (be.t != NTX_BE_DICT) {
        ntx_be_free(&be);
        return -1;
    }

    const ntx_be *psbe = ntx_be_dict_get(&be, "piece length");
    const ntx_be *pieces = ntx_be_dict_get(&be, "pieces");
    /* piece length is peer/file supplied and sizes a buffer per piece: 64 MiB is far above any real torrent */
    if (!psbe || psbe->t != NTX_BE_INT || psbe->i < 1 || psbe->i > (int64_t)NTX_TORRENT_MAX_PIECE_LEN) {
        ntx_be_free(&be);
        return -1;
    }
    if (!pieces || pieces->t != NTX_BE_STR || pieces->sn == 0 || pieces->sn % 20 != 0) {
        ntx_be_free(&be);
        return -1;
    }

    uint64_t size = 0;
    if (ntx_store_size_of(&be, &size) != 0) {
        ntx_be_free(&be);
        return -1;
    }

    uint32_t ps = (uint32_t)psbe->i;
    uint32_t np = (uint32_t)(pieces->sn / 20);
    /* The hash list and the store both derive the piece count; they must agree or later code indexes
     * one array with the other's bound. */
    if ((uint64_t)np != (size + ps - 1) / ps) {
        ntx_be_free(&be);
        return -1;
    }

    t->phash = malloc(pieces->sn);
    t->have = calloc(np, 1);
    t->rarity = calloc(np, sizeof(int));
    t->info_raw = malloc(info_len);
    if (!t->phash || !t->have || !t->rarity || !t->info_raw) {
        ntx_be_free(&be);
        tt_free(t);
        return -1;
    }
    memcpy(t->phash, pieces->sp, pieces->sn);
    memcpy(t->info_raw, info_dict, info_len);
    t->info_raw_n = info_len;

    memset(t->name, 0, sizeof(t->name));
    const ntx_be *name = ntx_be_dict_get(&be, "name");
    if (name && name->t == NTX_BE_STR && name->sn > 0) {
        size_t nlen = name->sn < sizeof(t->name) - 1 ? name->sn : sizeof(t->name) - 1;
        memcpy(t->name, name->sp, nlen);
    }

    t->ps = ps;
    t->np = np;
    t->size = size;
    t->have_n = 0;
    t->verified_B = 0;

    const char *dir = (store_dir && store_dir[0]) ? store_dir : "downloads";
    mkdir(dir, 0755);

    const ntx_be *files = ntx_be_dict_get(&be, "files");
    int open_rc = -1;
    if (files && files->t == NTX_BE_LIST && files->ne > 0) {
        /* Multi-file: downloads/<name>/<path…> with real extensions. */
        ntx_store_part_spec *specs = calloc(files->ne, sizeof *specs);
        char (*paths)[768] = calloc(files->ne, sizeof *paths);
        if (!specs || !paths) {
            free(specs);
            free(paths);
            ntx_be_free(&be);
            tt_free(t);
            return -1;
        }
        uint64_t off = 0;
        int ok = 1;
        for (size_t i = 0; i < files->ne; i++) {
            const ntx_be *fe = files->el[i];
            const ntx_be *flen = fe && fe->t == NTX_BE_DICT ? ntx_be_dict_get(fe, "length") : NULL;
            const ntx_be *fpath = fe && fe->t == NTX_BE_DICT ? ntx_be_dict_get(fe, "path") : NULL;
            char rel[700];
            if (!flen || flen->t != NTX_BE_INT || flen->i < 0 ||
                ntx_store_file_rel(rel, sizeof rel, name, fpath) != 0) {
                ok = 0;
                break;
            }
            if ((size_t)snprintf(paths[i], sizeof paths[i], "%s/%s", dir, rel) >= sizeof paths[i]) {
                ok = 0;
                break;
            }
            if ((uint64_t)flen->i > UINT64_MAX - off) { /* sum wraps 2^64 */
                ok = 0;
                break;
            }
            specs[i].path = paths[i];
            specs[i].start = off;
            specs[i].len = (uint64_t)flen->i;
            off += (uint64_t)flen->i;
        }
        if (ok && off == size)
            open_rc = ntx_store_open_parts(&t->store, specs, (int)files->ne, size, ps);
        /* Display name: prefer first file basename when single payload file. */
        if (open_rc == 0 && files->ne == 1) {
            const char *base = strrchr(paths[0], '/');
            base = base ? base + 1 : paths[0];
            if (base[0])
                snprintf(t->name, sizeof t->name, "%s", base);
        }
        free(specs);
        free(paths);
    } else {
        char path[600];
        size_t dirlen = strlen(dir);
        snprintf(path, sizeof(path), "%s/%s", dir, t->name[0] ? t->name : "untitled");
        for (char *p = path + dirlen + 1; *p; p++)
            if (*p == '/') *p = '_';
        open_rc = ntx_store_open(&t->store, path, size, ps);
    }
    ntx_be_free(&be);

    if (open_rc != 0) {
        tt_free(t);
        return -1;
    }

    t->state = t->store.existed ? NTX_TTS_VERIFY : NTX_TTS_DL;
    t->have_meta = 1;
    return 0;
}

/* BEP47 padding: a v1 "files" entry is padding if it carries "attr" whose
 * value contains 'p', or whose path is exactly [".pad", <int>]. */
static int tt_v1_is_padding(const ntx_be *fe) {
    if (!fe || fe->t != NTX_BE_DICT) return 0;
    const ntx_be *attr = ntx_be_dict_get(fe, "attr");
    if (attr && attr->t == NTX_BE_STR && memchr(attr->sp, 'p', attr->sn)) return 1;
    const ntx_be *fpath = ntx_be_dict_get(fe, "path");
    if (fpath && fpath->t == NTX_BE_LIST && fpath->ne == 2) {
        const ntx_be *c0 = fpath->el[0];
        const ntx_be *c1 = fpath->el[1];
        if (c0 && c0->t == NTX_BE_STR && c0->sn == 4 && memcmp(c0->sp, ".pad", 4) == 0 &&
            c1 && c1->t == NTX_BE_STR && c1->sn > 0) {
            int digits = 1;
            for (size_t k = 0; k < c1->sn; k++)
                if (c1->sp[k] < '0' || c1->sp[k] > '9') { digits = 0; break; }
            if (digits) return 1;
        }
    }
    return 0;
}

/* Join a v1 "path" list into a relative path (no torrent-name prefix), matching
 * the BEP52 file-tree path. */
static int tt_v1_file_rel(const ntx_be *fpath, char *out, size_t cap) {
    if (!fpath || fpath->t != NTX_BE_LIST || fpath->ne == 0) return -1;
    size_t o = 0;
    out[0] = '\0';
    for (size_t i = 0; i < fpath->ne; i++) {
        const ntx_be *c = fpath->el[i];
        if (!c || c->t != NTX_BE_STR) return -1;
        if (ntx_store_path_append(out, cap, &o, c->sp, c->sn) != 0) return -1;
    }
    return out[0] ? 0 : -1;
}

/* Validate that the v1 layout (single "length"/"name" or "files" array, with
 * BEP47 padding excluded) matches the v2 file table 1:1 in order/name/length,
 * that the v1 piece count equals np_total, and that the v1 total size equals
 * addr_end. Returns 0 on success, -1 on any mismatch. */
static int tt_hybrid_layout_ok(const ntx_be *info, const ntx_be *pieces,
                               const ntx_v2_file *files, uint32_t nfiles,
                               uint32_t np_total, uint64_t addr_end) {
    const ntx_be *v1files = ntx_be_dict_get(info, "files");
    const ntx_be *namebe = ntx_be_dict_get(info, "name");
    const ntx_be *lenbe = ntx_be_dict_get(info, "length");

    int v1n = 0;
    if (v1files && v1files->t == NTX_BE_LIST && v1files->ne > 0) {
        v1n = (int)v1files->ne;
    } else if (lenbe && lenbe->t == NTX_BE_INT && lenbe->i >= 0) {
        v1n = 1;
    } else {
        return -1;
    }

    char (*paths)[768] = calloc((size_t)v1n, sizeof *paths);
    uint64_t *lens = calloc((size_t)v1n, sizeof *lens);
    uint8_t *pads = calloc((size_t)v1n, 1);
    if (!paths || !lens || !pads) {
        free(paths); free(lens); free(pads);
        return -1;
    }

    int ok = 1;
    if (v1files && v1files->t == NTX_BE_LIST) {
        for (int i = 0; i < v1n; i++) {
            const ntx_be *fe = v1files->el[i];
            const ntx_be *flen = fe && fe->t == NTX_BE_DICT ? ntx_be_dict_get(fe, "length") : NULL;
            const ntx_be *fpath = fe && fe->t == NTX_BE_DICT ? ntx_be_dict_get(fe, "path") : NULL;
            if (!flen || flen->t != NTX_BE_INT || flen->i < 0 ||
                tt_v1_file_rel(fpath, paths[i], sizeof paths[i]) != 0) {
                ok = 0;
                break;
            }
            lens[i] = (uint64_t)flen->i;
            pads[i] = (uint8_t)tt_v1_is_padding(fe);
        }
    } else {
        if (!namebe || namebe->t != NTX_BE_STR || namebe->sn == 0) {
            ok = 0;
        } else {
            size_t nlen = namebe->sn < sizeof paths[0] - 1 ? namebe->sn : sizeof paths[0] - 1;
            memcpy(paths[0], namebe->sp, nlen);
            paths[0][nlen] = '\0';
            lens[0] = (uint64_t)lenbe->i;
            pads[0] = 0;
        }
    }

    if (ok) {
        uint32_t j = 0;
        for (int i = 0; i < v1n; i++) {
            if (pads[i]) continue;
            if (j >= nfiles) { ok = 0; break; }
            if (strcmp(paths[i], files[j].path) != 0 || lens[i] != files[j].len) { ok = 0; break; }
            j++;
        }
        if (ok && j != nfiles) ok = 0;
    }

    if (ok) {
        if ((uint32_t)(pieces->sn / 20) != np_total) ok = 0;
    }

    if (ok) {
        uint64_t v1_size = 0;
        if (ntx_store_size_of(info, &v1_size) != 0 || v1_size != addr_end) ok = 0;
    }

    free(paths); free(lens); free(pads);
    return ok ? 0 : -1;
}

uint32_t ntx_torrent_piece_len(const ntx_torrent *t, uint32_t i) {
    return tt_piece_len(t, i);
}

/* Copy the validated v2 file table + piece layer into the torrent and mark it
 * meta version 2. Returns -1 (caller cleans up) on allocation failure. */
static int tt_apply_v2_fields(ntx_torrent *t, const ntx_v2_file *files, uint32_t nfiles,
                              const uint8_t *layer_out, size_t layer_outn) {
    for (uint32_t i = 0; i < nfiles; i++) {
        memcpy(t->v2_root[i], files[i].root, 32);
        t->v2_first_piece[i] = files[i].first_piece;
        t->v2_np_file[i] = files[i].np;
        t->v2_len_file[i] = files[i].len;
    }
    t->v2_nfiles = nfiles;
    if (layer_outn > 0) {
        t->piece_layer = malloc(layer_outn);
        if (!t->piece_layer) return -1;
        memcpy(t->piece_layer, layer_out, layer_outn);
        t->piece_layer_n = layer_outn;
    } else {
        t->piece_layer = NULL;
        t->piece_layer_n = 0;
    }
    t->meta_version = 2;
    return 0;
}

static int tt_set_metainfo_v2(ntx_torrent *t, const uint8_t *info_dict, size_t info_len,
                              const char *store_dir, const ntx_be *piece_layers) {
    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(info_dict, info_len, &be, &consumed, 32, (size_t)(1u << 20)) != 0) return -1;
    if (be.t != NTX_BE_DICT) { ntx_be_free(&be); return -1; }

    const ntx_be *psbe = ntx_be_dict_get(&be, "piece length");
    if (!psbe || psbe->t != NTX_BE_INT || psbe->i < 16384) { ntx_be_free(&be); return -1; }
    uint64_t ps64 = (uint64_t)psbe->i;
    if ((ps64 & (ps64 - 1)) != 0) { ntx_be_free(&be); return -1; }
    if (ps64 > NTX_TORRENT_MAX_PIECE_LEN) { ntx_be_free(&be); return -1; }
    uint32_t ps = (uint32_t)ps64;

    const ntx_be *tree = ntx_be_dict_get(&be, "file tree");
    if (!tree || tree->t != NTX_BE_DICT) { ntx_be_free(&be); return -1; }

    ntx_v2_file files[NTX_TORRENT_MAX_FILES_V2];
    uint32_t nfiles = 0;
    uint64_t data_size = 0, addr_end = 0;
    if (ntx_torrent_v2_tree_walk(tree, ps, files, NTX_TORRENT_MAX_FILES_V2,
                                 &nfiles, &data_size, &addr_end) != 0) {
        ntx_be_free(&be);
        return -1;
    }
    if (nfiles == 0) { ntx_be_free(&be); return -1; }
    uint32_t np_total = 0;
    for (uint32_t i = 0; i < nfiles; i++) np_total += files[i].np;

    const ntx_be *pieces = ntx_be_dict_get(&be, "pieces");
    int hybrid = (pieces && pieces->t == NTX_BE_STR && pieces->sn > 0 && pieces->sn % 20 == 0);

    /* ut_metadata (BEP9) carries the info dict only, so the
     * top-level "piece layers" key never arrives over BEP9. For pure v2 the
     * layers are therefore OPTIONAL here: accept the info without them and
     * let ntx_torrent_layers_pending() report 1 so the session acquires them
     * through the BEP52 hash exchange instead of
     * rejecting into an endless meta re-request loop. A torrent whose files
     * are all single-piece verifies through the null-layer path and never
     * needs the layers at all. They stay mandatory only when supplied: a
     * malformed/short layers dict still rejects below. */
    uint8_t *layer_out = NULL;
    size_t layer_outn = 0;
    if (piece_layers != NULL) {
        layer_out = malloc((size_t)np_total * 32);
        if (!layer_out) { ntx_be_free(&be); return -1; }
        if (ntx_torrent_v2_layers(piece_layers, files, nfiles, ps, layer_out,
                                  (size_t)np_total * 32, &layer_outn) != 0) {
            free(layer_out);
            ntx_be_free(&be);
            return -1;
        }
    }

    if (hybrid) {
        if (tt_hybrid_layout_ok(&be, pieces, files, nfiles, np_total, addr_end) != 0) {
            free(layer_out);
            ntx_be_free(&be);
            return -1;
        }
        /* v1 layout + store: reuse the untouched v1 path (its sha1 gate passes
         * for a valid hybrid because info_hash is the v1 sha1). */
        if (tt_set_metainfo_v1(t, info_dict, info_len, store_dir) != 0) {
            free(layer_out);
            ntx_be_free(&be);
            return -1;
        }
        if (tt_apply_v2_fields(t, files, nfiles, layer_out, layer_outn) != 0) {
            tt_free(t);
            free(layer_out);
            ntx_be_free(&be);
            return -1;
        }
        t->hybrid = 1;
        free(layer_out);
        ntx_be_free(&be);
        return 0;
    }

    /* pure v2: open the store from the v2 file table. */
    const char *dir = (store_dir && store_dir[0]) ? store_dir : "downloads";
    ntx_store_part_spec *specs = calloc((size_t)nfiles, sizeof *specs);
    char (*paths)[768] = calloc((size_t)nfiles, sizeof *paths);
    if (!specs || !paths) {
        free(specs); free(paths);
        free(layer_out);
        ntx_be_free(&be);
        return -1;
    }
    for (uint32_t i = 0; i < nfiles; i++) {
        if ((size_t)snprintf(paths[i], sizeof paths[i], "%s/%s", dir, files[i].path) >= sizeof paths[i]) {
            free(specs); free(paths);
            free(layer_out);
            ntx_be_free(&be);
            return -1;
        }
        specs[i].path = paths[i];
        specs[i].start = (uint64_t)files[i].first_piece * ps;
        specs[i].len = files[i].len;
    }
    int open_rc = ntx_store_open_parts(&t->store, specs, (int)nfiles, addr_end, ps);
    free(specs);
    free(paths);
    if (open_rc != 0) {
        free(layer_out);
        ntx_be_free(&be);
        return -1;
    }

    t->have = calloc(np_total, 1);
    t->rarity = calloc(np_total, sizeof(int));
    t->info_raw = malloc(info_len);
    if (!t->have || !t->rarity || !t->info_raw) {
        tt_free(t);
        free(layer_out);
        ntx_be_free(&be);
        return -1;
    }
    memcpy(t->info_raw, info_dict, info_len);
    t->info_raw_n = info_len;

    t->ps = ps;
    t->np = np_total;
    t->size = data_size;
    t->phash = NULL;
    t->have_n = 0;
    t->verified_B = 0;

    memset(t->name, 0, sizeof(t->name));
    const char *base = strrchr(files[0].path, '/');
    base = base ? base + 1 : files[0].path;
    size_t blen = strlen(base);
    if (blen >= sizeof t->name) blen = sizeof t->name - 1;
    memcpy(t->name, base, blen);
    t->name[blen] = '\0';

    if (tt_apply_v2_fields(t, files, nfiles, layer_out, layer_outn) != 0) {
        tt_free(t);
        free(layer_out);
        ntx_be_free(&be);
        return -1;
    }

    t->state = t->store.existed ? NTX_TTS_VERIFY : NTX_TTS_DL;
    t->have_meta = 1;
    free(layer_out);
    ntx_be_free(&be);
    return 0;
}

/* Hash gate (BEFORE parsing the dict): v2/hybrid (info_hash_v2 set) requires
 * sha256(info)==info_hash_v2; v1 requires sha1(info)==info_hash. */
static int tt_hash_gate_ok(ntx_torrent *t, const uint8_t *info_dict, size_t info_len) {
    int any_v2 = 0;
    for (int i = 0; i < 32; i++)
        if (t->info_hash_v2[i]) { any_v2 = 1; break; }
    if (any_v2) {
        uint8_t h[32];
        ntx_sha256(info_dict, info_len, h);
        return memcmp(h, t->info_hash_v2, 32) == 0;
    }
    uint8_t h[20];
    ntx_sha1(info_dict, info_len, h);
    return memcmp(h, t->info_hash, 20) == 0;
}

int ntx_torrent_set_metainfo(ntx_torrent *t, const uint8_t *info_dict, size_t info_len, const char *store_dir,
                             const ntx_be *piece_layers) {
    if (!tt_hash_gate_ok(t, info_dict, info_len)) return -1;
    int mv = ntx_torrent_metainfo_version(info_dict, info_len);
    if (mv < 0) return -1;
    if (mv == 0) return tt_set_metainfo_v1(t, info_dict, info_len, store_dir);
    return tt_set_metainfo_v2(t, info_dict, info_len, store_dir, piece_layers);
}

int ntx_torrent_piece_complete_from(ntx_torrent *t, uint32_t i, ntx_peer *src, uint64_t now_ms) {
    if (i >= t->np || (t->meta_version == 0 && !t->phash)) return 0;
    uint32_t pl = tt_piece_len(t, i);
    if (pl == 0) return 0;
    uint8_t *buf = malloc(pl);
    if (!buf) return 0;
    int ok = tt_piece_verify(t, i, pl, buf);
    free(buf);
    if (ok) {
        t->store.pmap[i] = 2;
        if (!t->have[i]) {
            t->have[i] = 1;
            t->have_n++;
            t->verified_B += pl;
        }
        if (t->on_piece_have) t->on_piece_have(t, i, t->on_piece_have_ctx);
        return 1;
    }
    tt_piece_clear(t, i);
    /* While a pure-v2 torrent is still waiting for its piece layers, a failed
     * cross-check means "cannot verify yet", not "bad data" — banning every
     * peer that serves a piece would starve the BEP52 exchange that delivers
     * the layers. Drop the piece (it re-downloads once the layers land) but
     * keep the peer. */
    if (src && !ntx_torrent_layers_pending(t)) ntx_torrent_peer_ban(src, now_ms);
    return 0;
}

int ntx_torrent_piece_complete(ntx_torrent *t, uint32_t i) {
    return ntx_torrent_piece_complete_from(t, i, NULL, 0);
}

/* Rescan [from,to): verify pieces from disk, no peer ban, no on_piece_have. */
int ntx_torrent_verify_range(ntx_torrent *t, uint32_t from, uint32_t to) {
    if (!t->have_meta || (t->meta_version == 0 && !t->phash) || t->store.pmap == NULL ||
        from >= to || to > t->np || from >= t->np)
        return 0;
    int new_count = 0;
    for (uint32_t i = from; i < to; i++) {
        uint32_t pl = tt_piece_len(t, i);
        if (pl == 0) continue;
        uint8_t *buf = malloc(pl);
        if (!buf) break;
        int ok = tt_piece_verify(t, i, pl, buf);
        free(buf);
        if (ok) {
            t->store.pmap[i] = 2;
            if (!t->have[i]) {
                t->have[i] = 1;
                t->have_n++;
                t->verified_B += pl;
                new_count++;
            }
        } else {
            t->store.pmap[i] = 0;
        }
    }
    return new_count;
}

uint32_t ntx_torrent_pick(const ntx_torrent *t) {
    uint32_t best = 0xFFFFFFFFu;
    int best_r = 0;
    for (uint32_t i = 0; i < t->np; i++) {
        if (t->have[i]) continue;
        if (t->rarity[i] <= 0) continue;
        if (best == 0xFFFFFFFFu || t->rarity[i] < best_r) {
            best = i;
            best_r = t->rarity[i];
        }
    }
    return best;
}

void ntx_torrent_on_peer_have(ntx_torrent *t, uint32_t i) {
    if (i < t->np) t->rarity[i]++;
}

void ntx_torrent_on_peer_lost(ntx_torrent *t, const ntx_peer *p) {
    if (!t->rarity || !p || !p->phave || t->np == 0) return;
    uint32_t n = (uint32_t)p->phave_n;
    if (n > t->np) n = t->np;
    for (uint32_t i = 0; i < n; i++) {
        if (p->phave[i] && t->rarity[i] > 0) t->rarity[i]--;
    }
}

uint64_t ntx_torrent_verified_bytes(const ntx_torrent *t) {
    return t->verified_B;
}

int ntx_torrent_done(const ntx_torrent *t) {
    return t->np > 0 && t->have_n == t->np;
}

/* BEP52: a pure-v2 torrent (meta version 2, not hybrid) that has its info
 * metainfo but no piece layers yet still needs them via the hash exchange — but
 * only if some file is large enough (len > ps) to actually have a piece layer.
 * A torrent whose files are all single-piece (len <= ps) verifies through the
 * null-layer path and never blocks. Once apply_piece_layer stores the layers the
 * predicate drops to 0 and the DL path proceeds. */
int ntx_torrent_layers_pending(const ntx_torrent *t) {
    if (!t || t->state == NTX_TTS_DEAD) return 0;
    if (!t->have_meta || t->meta_version != 2 || t->hybrid) return 0;
    if (t->piece_layer != NULL) return 0;
    for (uint32_t i = 0; i < t->v2_nfiles; i++)
        if (t->v2_len_file[i] > t->ps) return 1;
    return 0;
}

/* Store a validated piece-layer string: the per-file concat (in file order) of
 * the piece-length hashes for every file with len > ps, exactly the layout
 * tt_v2_piece_ok indexes. Every slice is recomputed with ntx_merkle_root_from_layer
 * and compared against that file's pieces root before the bytes are trusted
 * (validate layers <-> roots before trusting storage). On success the bytes
 * become t->piece_layer (layers_pending then clears); on any mismatch nothing is
 * stored and -1 is returned. */
int ntx_torrent_apply_piece_layer(ntx_torrent *t, const uint8_t *layer, size_t n) {
    if (!t || !t->have_meta || t->meta_version != 2) return -1;
    size_t total = 0;
    for (uint32_t i = 0; i < t->v2_nfiles; i++)
        if (t->v2_len_file[i] > t->ps) total += (size_t)t->v2_np_file[i] * 32;
    if (n != total) return -1;
    if (total == 0) return 0; /* nothing to apply (all files single-piece) */
    if (!layer) return -1;
    size_t off = 0;
    for (uint32_t i = 0; i < t->v2_nfiles; i++) {
        if (t->v2_len_file[i] <= t->ps) continue;
        size_t sn = (size_t)t->v2_np_file[i] * 32;
        uint8_t root[32];
        if (ntx_merkle_root_from_layer(layer + off, sn, t->ps, t->v2_len_file[i], root) != 0) return -1;
        if (memcmp(root, t->v2_root[i], 32) != 0) return -1;
        off += sn;
    }
    uint8_t *dup = malloc(total);
    if (!dup) return -1;
    memcpy(dup, layer, total);
    free(t->piece_layer);
    t->piece_layer = dup;
    t->piece_layer_n = total;
    t->layers_stall = 0;
    return 0;
}
