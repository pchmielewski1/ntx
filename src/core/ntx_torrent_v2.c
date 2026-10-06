#include "ntx_torrent_v2.h"

#include "../proto/ntx_bencode.h"

#include <string.h>

typedef struct {
    uint32_t ps;
    ntx_v2_file *out;
    uint32_t cap;
    uint32_t n_files;
    uint64_t data_size;
    uint64_t addr_end;
    uint32_t first_piece;
    int fill;
} v2_walk;

static int be_key_has_nul(const ntx_be *k) {
    return k->t == NTX_BE_STR && k->sn > 0 && memchr(k->sp, 0, k->sn) != NULL;
}

static int be_is_empty_key(const ntx_be *k) {
    return k->t == NTX_BE_STR && k->sn == 0;
}

static int dict_has_empty_child(const ntx_be *d) {
    if (d->t != NTX_BE_DICT) return 0;
    for (size_t i = 0; i < d->nd; i++)
        if (be_is_empty_key(d->k[i])) return 1;
    return 0;
}

static size_t sanitize_component(char *dst, const uint8_t *sp, size_t sn) {
    if (sn == 1 && sp[0] == '.') {
        dst[0] = '_';
        return 1;
    }
    if (sn == 2 && sp[0] == '.' && sp[1] == '.') {
        dst[0] = '_';
        dst[1] = '_';
        return 2;
    }
    size_t o = 0;
    for (size_t i = 0; i < sn; i++)
        dst[o++] = (char)(sp[i] == '/' ? '_' : sp[i]);
    return o;
}

static int join_path(char *dst, size_t cap, const char *prefix, size_t prefix_len,
                     const char *comp, size_t comp_len) {
    size_t total = prefix_len + (prefix_len ? 1u : 0u) + comp_len;
    if (total + 1 > cap) return -1;
    if (prefix_len) {
        memcpy(dst, prefix, prefix_len);
        dst[prefix_len] = '/';
        memcpy(dst + prefix_len + 1, comp, comp_len);
    } else {
        memcpy(dst, comp, comp_len);
    }
    dst[total] = '\0';
    return (int)total;
}

static int walk_file(const ntx_be *key, const ntx_be *node, const char *prefix,
                     size_t prefix_len, v2_walk *w) {
    if (node->nd != 1) return -1;
    const ntx_be *props = node->v[0];
    if (props->t != NTX_BE_DICT) return -1;
    const ntx_be *lv = ntx_be_dict_get(props, "length");
    if (!lv || lv->t != NTX_BE_INT || lv->i < 0) return -1;
    uint64_t len = (uint64_t)lv->i;
    const ntx_be *rv = ntx_be_dict_get(props, "pieces root");
    if (len > 0) {
        if (!rv || rv->t != NTX_BE_STR || rv->sn != 32) return -1;
    } else if (rv) {
        return -1;
    }
    char comp[768];
    size_t cl = sanitize_component(comp, key->sp, key->sn);
    size_t total = prefix_len + (prefix_len ? 1u : 0u) + cl;
    if (total + 1 > 768) return -1;
    uint32_t fp = w->first_piece;
    /* hostile lengths: the piece count, the running piece index and the byte total must not wrap */
    if (len > UINT64_MAX - w->data_size) return -1;
    uint64_t np64 = len ? (len - 1) / (uint64_t)w->ps + 1u : 0u;
    if (np64 > (uint64_t)UINT32_MAX - fp) return -1;
    uint32_t np = (uint32_t)np64;
    w->n_files++;
    if (w->n_files > w->cap) return -1;
    w->first_piece = fp + np;
    w->data_size += len;
    if (len > 0) w->addr_end = (uint64_t)fp * w->ps + len;
    if (w->fill) {
        ntx_v2_file *f = &w->out[w->n_files - 1];
        join_path(f->path, sizeof f->path, prefix, prefix_len, comp, cl);
        f->len = len;
        f->np = np;
        f->first_piece = fp;
        if (rv)
            memcpy(f->root, rv->sp, 32);
        else
            memset(f->root, 0, 32);
    }
    return 0;
}

static int walk_node(const ntx_be *d, const char *prefix, size_t prefix_len,
                     v2_walk *w) {
    for (size_t i = 0; i < d->nd; i++) {
        const ntx_be *k = d->k[i];
        const ntx_be *v = d->v[i];
        if (be_key_has_nul(k)) return -1;
        if (v->t == NTX_BE_DICT && dict_has_empty_child(v)) {
            if (walk_file(k, v, prefix, prefix_len, w)) return -1;
        } else {
            if (v->t != NTX_BE_DICT) return -1;
            char comp[768];
            size_t cl = sanitize_component(comp, k->sp, k->sn);
            char nprefix[768];
            int nl = join_path(nprefix, sizeof nprefix, prefix, prefix_len, comp, cl);
            if (nl < 0) return -1;
            if (walk_node(v, nprefix, (size_t)nl, w)) return -1;
        }
    }
    return 0;
}

int ntx_torrent_v2_tree_walk(const ntx_be *tree, uint32_t ps, ntx_v2_file *out,
                             uint32_t cap, uint32_t *n_files,
                             uint64_t *data_size, uint64_t *addr_end) {
    if (!tree || tree->t != NTX_BE_DICT || tree->nd == 0) return -1;
    if (!out || !n_files || !data_size || !addr_end || ps == 0) return -1;
    if (dict_has_empty_child(tree)) return -1;

    v2_walk w = {.ps = ps, .cap = cap};
    if (walk_node(tree, "", 0, &w)) return -1;
    w.out = out;
    w.fill = 1;
    w.n_files = 0;
    w.data_size = 0;
    w.addr_end = 0;
    w.first_piece = 0;
    if (walk_node(tree, "", 0, &w)) return -1;
    *n_files = w.n_files;
    *data_size = w.data_size;
    *addr_end = w.addr_end;
    return 0;
}
