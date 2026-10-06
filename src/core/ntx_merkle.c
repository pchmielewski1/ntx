#include "ntx_merkle.h"
#include "../crypto/ntx_sha256.h"

#include <stdlib.h>
#include <string.h>

static int ntx_pow2(uint32_t x) {
    return x != 0 && (x & (x - 1)) == 0;
}

static uint32_t ntx_log2(uint32_t x) {
    uint32_t r = 0;
    while (x > 1) {
        x >>= 1;
        r++;
    }
    return r;
}

static size_t ntx_next_pow2(size_t n) {
    size_t p = 1;
    while (p < n) p <<= 1;
    return p;
}

/* Fold one level in place: lev holds `p` 32-byte hashes (p a power of two,
 * p >= 2); afterwards the first p/2 slots hold the parent hashes. */
static void ntx_fold_once(uint8_t *lev, size_t p) {
    for (size_t j = 0; j < p / 2; j++) {
        uint8_t h[64];
        memcpy(h, lev + j * 2 * 32, 32);
        memcpy(h + 32, lev + (j * 2 + 1) * 32, 32);
        ntx_sha256(h, 64, lev + j * 32);
    }
}

/* SHA2-256 leaves over 16 KiB blocks of data (last block may be shorter),
 * zero-filled (32 zero bytes as leaf value) up to the next power of two.
 * *np receives the padded leaf count. Caller frees the result. */
static uint8_t *ntx_leaves(const uint8_t *data, size_t n, size_t *np) {
    size_t n_leaf = (n + NTX_MERKLE_LEAF - 1) / NTX_MERKLE_LEAF;
    size_t p = ntx_next_pow2(n_leaf > 0 ? n_leaf : 1);
    uint8_t *lev = malloc(p * 32);
    if (!lev) return NULL;
    for (size_t i = 0; i < n_leaf; i++) {
        size_t off = i * NTX_MERKLE_LEAF;
        size_t len = n - off;
        if (len > NTX_MERKLE_LEAF) len = NTX_MERKLE_LEAF;
        ntx_sha256(data + off, len, lev + i * 32);
    }
    for (size_t i = n_leaf; i < p; i++) memset(lev + i * 32, 0, 32);
    *np = p;
    return lev;
}

int ntx_merkle_root_from_file_buf(const uint8_t *data, size_t n, uint8_t root[32]) {
    if (!root) return -1;
    if (n == 0) {
        memset(root, 0, 32);
        return 0;
    }
    if (!data) return -1;
    size_t p;
    uint8_t *lev = ntx_leaves(data, n, &p);
    if (!lev) return -1;
    while (p > 1) {
        ntx_fold_once(lev, p);
        p >>= 1;
    }
    memcpy(root, lev, 32);
    free(lev);
    return 0;
}

int ntx_merkle_verify_piece_layer(const uint8_t root[32],
                                  const uint8_t *layer, size_t layer_nbytes,
                                  uint32_t piece_len, uint32_t piece_index,
                                  const uint8_t *piece_data, uint32_t piece_nbytes) {
    if (!piece_len || !ntx_pow2(piece_len) || piece_len < NTX_MERKLE_LEAF) return -1;
    if (!piece_data) return -1;
    if (layer == NULL) {
        if (!root) return -1;
        uint8_t r[32];
        if (ntx_merkle_root_from_file_buf(piece_data, piece_nbytes, r) != 0) return -1;
        return memcmp(r, root, 32) == 0 ? 0 : -1;
    }
    if ((size_t)piece_index * 32 + 32 > layer_nbytes) return -1;
    uint32_t L = ntx_log2(piece_len / NTX_MERKLE_LEAF);
    size_t target = (size_t)1 << L;
    size_t n_leaf = (piece_nbytes + NTX_MERKLE_LEAF - 1) / NTX_MERKLE_LEAF;
    if (n_leaf > target) return -1;
    uint8_t *lev = malloc(target * 32);
    if (!lev) return -1;
    for (size_t i = 0; i < n_leaf; i++) {
        size_t off = i * NTX_MERKLE_LEAF;
        size_t len = piece_nbytes - off;
        if (len > NTX_MERKLE_LEAF) len = NTX_MERKLE_LEAF;
        ntx_sha256(piece_data + off, len, lev + i * 32);
    }
    for (size_t i = n_leaf; i < target; i++) memset(lev + i * 32, 0, 32);
    size_t p = target;
    for (uint32_t i = 0; i < L; i++) {
        ntx_fold_once(lev, p);
        p >>= 1;
    }
    int ok = memcmp(lev, layer + (size_t)piece_index * 32, 32) == 0;
    free(lev);
    return ok ? 0 : -1;
}

int ntx_merkle_root_from_layer(const uint8_t *layer, size_t layer_nbytes,
                               uint32_t piece_len, uint64_t file_len,
                               uint8_t root[32]) {
    if (!root) return -1;
    if (!piece_len || !ntx_pow2(piece_len) || piece_len < NTX_MERKLE_LEAF) return -1;
    if (layer_nbytes % 32 != 0) return -1;
    if (file_len == 0) {
        memset(root, 0, 32);
        return 0;
    }
    if (!layer) return -1;
    uint32_t L = ntx_log2(piece_len / NTX_MERKLE_LEAF);
    size_t n_leaf = (file_len + NTX_MERKLE_LEAF - 1) / NTX_MERKLE_LEAF;
    size_t target = ntx_next_pow2(n_leaf) / (piece_len / NTX_MERKLE_LEAF);
    size_t n_have = layer_nbytes / 32;
    size_t n_pieces = (file_len + piece_len - 1) / piece_len;
    if (n_have > target || n_have > n_pieces) return -1;
    uint8_t *lev = malloc(target * 32);
    if (!lev) return -1;
    memcpy(lev, layer, n_have * 32);
    /* Balance-only slots: L folds of the 32-byte zero leaf value. */
    uint8_t fill[32], tmp[64];
    memset(fill, 0, 32);
    for (uint32_t i = 0; i < L; i++) {
        memcpy(tmp, fill, 32);
        memcpy(tmp + 32, fill, 32);
        ntx_sha256(tmp, 64, fill);
    }
    for (size_t i = n_have; i < target; i++) memcpy(lev + i * 32, fill, 32);
    size_t p = target;
    while (p > 1) {
        ntx_fold_once(lev, p);
        p >>= 1;
    }
    memcpy(root, lev, 32);
    free(lev);
    return 0;
}

int ntx_merkle_file_layer(const uint8_t *data, size_t n, uint32_t piece_len,
                          uint8_t *out, size_t cap, size_t *outn) {
    if (!outn) return -1;
    *outn = 0;
    if (!piece_len || !ntx_pow2(piece_len) || piece_len < NTX_MERKLE_LEAF) return -1;
    if (n == 0) return 0;
    if (!data) return -1;
    uint32_t L = ntx_log2(piece_len / NTX_MERKLE_LEAF);
    size_t p;
    uint8_t *lev = ntx_leaves(data, n, &p);
    if (!lev) return -1;
    for (uint32_t i = 0; i < L; i++) {
        ntx_fold_once(lev, p);
        p >>= 1;
    }
    size_t np = (n + piece_len - 1) / piece_len;
    if (np > p || np * 32 > cap) {
        free(lev);
        return -1;
    }
    memcpy(out, lev, np * 32);
    *outn = np * 32;
    free(lev);
    return 0;
}

int ntx_merkle_ingest_hashes(const uint8_t pieces_root[32],
                             uint32_t base_layer, uint32_t index, uint32_t length,
                             uint32_t proof_layers,
                             const uint8_t *hashes, size_t hashes_nbytes,
                             uint8_t *out_layer, size_t out_cap, size_t *out_nbytes) {
    if (!pieces_root || !hashes || !out_layer || !out_nbytes) return -1;
    *out_nbytes = 0;
    (void)base_layer; /* uncle side is derived from (index/length) parity chain */
    if (!ntx_pow2(length) || length < 2) return -1;
    if (index % length != 0) return -1;
    uint32_t lg = ntx_log2(length);
    if (proof_layers < lg - 1) return -1;
    if (hashes_nbytes % 32 != 0) return -1;
    size_t np = (size_t)proof_layers - (lg - 1);
    if (hashes_nbytes / 32 != (size_t)length + np) return -1;
    if ((size_t)length * 32 > out_cap) return -1;
    uint8_t *lev = malloc((size_t)length * 32);
    if (!lev) return -1;
    memcpy(lev, hashes, (size_t)length * 32);
    size_t p = length;
    while (p > 1) {
        ntx_fold_once(lev, p);
        p >>= 1;
    }
    uint32_t pos = index / length;
    const uint8_t *proof = hashes + (size_t)length * 32;
    uint8_t h[64];
    for (size_t k = 0; k < np; k++) {
        if (pos & 1) {
            memcpy(h, proof + k * 32, 32);
            memcpy(h + 32, lev, 32);
        } else {
            memcpy(h, lev, 32);
            memcpy(h + 32, proof + k * 32, 32);
        }
        ntx_sha256(h, 64, lev);
        pos >>= 1;
    }
    int ok = memcmp(lev, pieces_root, 32) == 0;
    if (ok) {
        memcpy(out_layer, hashes, (size_t)length * 32);
        *out_nbytes = (size_t)length * 32;
    }
    free(lev);
    return ok ? 0 : -1;
}
