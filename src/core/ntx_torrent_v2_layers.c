#include "ntx_torrent_v2.h"
#include "ntx_merkle.h"
#include "../proto/ntx_bencode.h"

#include <string.h>

int ntx_torrent_v2_layers(const ntx_be *layers, const ntx_v2_file *files,
                          uint32_t n_files, uint32_t ps, uint8_t *out, size_t cap,
                          size_t *outn) {
    if (!outn) return -1;
    *outn = 0;
    if (!layers || layers->t != NTX_BE_DICT) return -1;
    if (n_files > 0 && !files) return -1;

    /* Total output: sum of np*32 over files with len > ps. */
    size_t total = 0;
    for (uint32_t i = 0; i < n_files; i++) {
        if (files[i].len > ps) {
            total += (size_t)files[i].np * 32;
            if (total > cap) return -1;
        }
    }
    if (total > 0 && !out) return -1;

    /* Every dict entry must be keyed by the 32-byte pieces root of a file
     * with len > ps, with a value of length np*32 whose recomputed root
     * matches the key. Any other entry (unknown root, or a root of a file
     * with len <= ps) is a mismatch. */
    for (size_t e = 0; e < layers->nd; e++) {
        const ntx_be *k = layers->k[e];
        const ntx_be *v = layers->v[e];
        if (!k || k->t != NTX_BE_STR || k->sn != 32) return -1;
        int found = -1;
        for (uint32_t i = 0; i < n_files; i++) {
            if (files[i].len > ps && memcmp(files[i].root, k->sp, 32) == 0) {
                found = (int)i;
                break;
            }
        }
        if (found < 0) return -1;
        const ntx_v2_file *f = &files[found];
        if (!v || v->t != NTX_BE_STR || v->sn != (size_t)f->np * 32) return -1;
        uint8_t root[32];
        if (ntx_merkle_root_from_layer(v->sp, v->sn, ps, f->len, root) != 0)
            return -1;
        if (memcmp(root, k->sp, 32) != 0) return -1;
    }

    /* Every file with len > ps must have a matching entry; emit the layer
     * values in files[] order. */
    size_t off = 0;
    for (uint32_t i = 0; i < n_files; i++) {
        const ntx_v2_file *f = &files[i];
        if (f->len <= ps) continue;
        const ntx_be *v = NULL;
        for (size_t e = 0; e < layers->nd; e++) {
            const ntx_be *k = layers->k[e];
            if (k && k->t == NTX_BE_STR && k->sn == 32 &&
                memcmp(k->sp, f->root, 32) == 0) {
                v = layers->v[e];
                break;
            }
        }
        if (!v) return -1;
        if (out) memcpy(out + off, v->sp, v->sn);
        off += v->sn;
    }
    *outn = off;
    return 0;
}
