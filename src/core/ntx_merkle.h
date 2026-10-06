#ifndef NTX_MERKLE_H
#define NTX_MERKLE_H

#include <stddef.h>
#include <stdint.h>

/* BEP52 merkle: branching factor 2, leaf = SHA2-256 of a 16 KiB block
 * (last block may be shorter), past-EOF leaf values are 32 zero bytes,
 * zero-filled up to a power of two before folding.
 *
 * A "piece" is piece_len bytes of file data (last piece of a file may be
 * shorter). The piece hash is:
 *   - len(file) >  piece_len: the merkle subtree root whose subtree covers
 *     exactly piece_len bytes (2^L leaves, L = log2(piece_len/16384),
 *     zero-filled to balance; for piece_len == 16384 this is just
 *     sha256(piece bytes));
 *   - len(file) <= piece_len: the file has a single piece and the tree has
 *     no piece-layer level, so the piece hash is the pieces root itself.
 *
 * The piece layer (metainfo "piece layers") is the tree level where one hash
 * covers exactly piece_len bytes; balance-only hashes (covering only
 * past-EOF data) are omitted from the stored string.
 *
 * All functions return 0 on success, -1 on invalid argument or cap.
 */

#define NTX_MERKLE_LEAF 16384u

/* Root of the file's merkle tree. n == 0 -> 32 zero bytes. */
int ntx_merkle_root_from_file_buf(const uint8_t *data, size_t n, uint8_t root[32]);

/* Verify one piece against a file's piece layer.
 * layer != NULL: piece_index is the local piece index within this file;
 *   compares the piece subtree hash with layer[piece_index*32 .. +32).
 *   Requires (piece_index+1)*32 <= layer_nbytes.
 * layer == NULL: the file has a single piece (len <= piece_len); piece_data
 *   must be the whole file and it is compared against root.
 * piece_len must be a power of two, >= 16384. */
int ntx_merkle_verify_piece_layer(const uint8_t root[32],
                                  const uint8_t *layer, size_t layer_nbytes,
                                  uint32_t piece_len, uint32_t piece_index,
                                  const uint8_t *piece_data, uint32_t piece_nbytes);

/* Recompute the file merkle root from a piece-layer string (load-time
 * validation): layer_nbytes must be a multiple of 32 with
 * layer_nbytes/32 <= ceil(file_len/piece_len); balance-only layer hashes are
 * filled with their merkle value (L folds of the 32-byte zero leaf) before
 * folding up to the root. piece_len: power of two >= 16384; file_len > 0. */
int ntx_merkle_root_from_layer(const uint8_t *layer, size_t layer_nbytes,
                               uint32_t piece_len, uint64_t file_len,
                               uint8_t root[32]);

/* Compute the piece-layer string for a file buffer at the level where one
 * hash covers piece_len bytes (np*32 bytes, np = ceil(n/piece_len);
 * balance-only hashes omitted). n == 0 -> outn = 0. */
int ntx_merkle_file_layer(const uint8_t *data, size_t n, uint32_t piece_len,
                          uint8_t *out, size_t cap, size_t *outn);

/* Apply hashes message payload: validate against pieces_root; write piece-layer
 * hashes into out_layer (cap out_cap). Returns 0 ok, -1 bad proof/args. */
/* base_layer/index/length/proof_layers are the BEP52 msg-22 header fields.
 * hashes = the base-layer hashes [index, index+length) followed by one uncle
 * hash per present proof layer up to the root; the first log2(length)-1 proof
 * layers are omitted but still counted in proof_layers (BEP52: requested range
 * covers the whole child layer). out_layer receives the verified base-layer
 * hashes (length*32 bytes) — the piece-layer hashes when base_layer is the
 * piece layer. Constraints enforced: length >= 2 and power of two,
 * index % length == 0, hashes_nbytes/32 == length + proof_layers -
 * (log2(length)-1). */
int ntx_merkle_ingest_hashes(const uint8_t pieces_root[32],
                             uint32_t base_layer, uint32_t index, uint32_t length,
                             uint32_t proof_layers,
                             const uint8_t *hashes, size_t hashes_nbytes,
                             uint8_t *out_layer, size_t out_cap, size_t *out_nbytes);

#endif
