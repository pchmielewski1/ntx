#ifndef NTX_TORRENT_V2_H
#define NTX_TORRENT_V2_H

#include <stddef.h>
#include <stdint.h>

typedef struct ntx_be ntx_be;

#define NTX_TORRENT_MAX_FILES_V2 64

/* One file from a BEP52 "file tree", in tree (stored key) order. */
typedef struct {
    char path[768]; /* sanitized relative path, e.g. "dir/b.dat" */
    uint64_t len;
    uint8_t root[32]; /* pieces root; zero if len == 0 */
    uint32_t np; /* ceil(len/ps); 0 if len == 0 */
    uint32_t first_piece; /* global piece index of this file's first piece */
} ntx_v2_file;

/* Walk a BEP52 "file tree" dict (the value of info["file tree"]).
 * The tree root itself must not be a file. Files are emitted in stored
 * (sorted) DFS order; every non-empty file is aligned to a piece boundary,
 * the last piece of a file may be shorter (alignment gap).
 *
 * ps: piece length, power of two, >= 16384 (caller validates).
 * out/cap: file table (NTX_TORRENT_MAX_FILES_V2 recommended); -1 when the
 *   tree has more files than cap.
 * n_files: number of files written.
 * data_size: sum of file lengths.
 * addr_end: end of the piece address space = first_piece(last)*ps +
 *   len(last); 0 when there are no (non-empty) files.
 *
 * Returns -1 on: root is a file, non-dict tree value, file properties without
 * "length" (int >= 0), non-empty file without a 32-byte "pieces root",
 * file-properties dict with sibling keys, NUL byte in a path component,
 * or more files than cap.
 * Path components exactly "." and ".." are sanitized to "_" and "__";
 * embedded '/' is replaced with '_'. */
int ntx_torrent_v2_tree_walk(const ntx_be *tree, uint32_t ps, ntx_v2_file *out,
                             uint32_t cap, uint32_t *n_files,
                             uint64_t *data_size, uint64_t *addr_end);

/* Load and validate the root-level "piece layers" dict against a file table.
 * layers must be a dict (BEP52: the field is mandatory; pass NULL -> -1).
 * Exactly one 1:1 correspondence is required:
 *   - every file with len > ps has an entry keyed by its 32-byte root,
 *     value length == np*32, and the root must match
 *     ntx_merkle_root_from_layer(value, np*32, ps, len);
 *   - every other entry (unknown root, or a root of a file with len <= ps)
 *     is a mismatch -> -1.
 * Binary 32-byte keys: compare with the file table (dict_get is strlen-based
 * and cannot be used for binary keys).
 *
 * out/cap/outn: concatenated layer values in files[] order (only files with
 * len > ps contribute); outn == sum(np*32). */
int ntx_torrent_v2_layers(const ntx_be *layers, const ntx_v2_file *files,
                          uint32_t n_files, uint32_t ps, uint8_t *out, size_t cap,
                          size_t *outn);

#endif
