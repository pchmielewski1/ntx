#ifndef NTX_SHARE_META_H
#define NTX_SHARE_META_H

#include <stddef.h>
#include <stdint.h>

/* Incremental hasher + private hybrid v1+v2 metainfo builder for --share
 * (design §5.2, §5.3). Bodies: ntx_share_meta.c. */

#define NTX_SHARE_PIECE_MIN (16u * 1024u)
#define NTX_SHARE_PIECE_MAX (64u * 1024u * 1024u)
/* `piece layers` is 32 B per piece and ntx's bencode parser caps strings at
 * 1 MiB (ntx_bencode.c), so a torrent ntx can read has at most this many. */
#define NTX_SHARE_MAX_PIECES 32768u

/* Piece length: smallest power of two in [16 KiB, 64 MiB] giving <= 2048
 * pieces, else 64 MiB. 0 on success; -1 when even 64 MiB exceeds
 * NTX_SHARE_MAX_PIECES (ps is still written on success). */
int smeta_piece_len(uint64_t size, uint32_t *ps);

typedef struct ntx_share_hasher ntx_share_hasher; /* opaque, heap */

/* ps must be a power of two in [NTX_SHARE_PIECE_MIN, NTX_SHARE_PIECE_MAX],
 * size > 0 and ceil(size/ps) <= NTX_SHARE_MAX_PIECES. NULL on bad args/OOM. */
ntx_share_hasher *ntx_share_hasher_new(uint64_t size, uint32_t ps);
/* Sequential file bytes; may be called with any chunk size. -1 once the total
 * exceeds size, after completion, or on OOM. */
int ntx_share_hasher_feed(ntx_share_hasher *h, const uint8_t *buf, size_t n);
/* 1 when every byte was fed (hashes are then final), else 0. */
int ntx_share_hasher_done(const ntx_share_hasher *h);
const uint8_t *ntx_share_hasher_sha1(const ntx_share_hasher *h);      /* np*20 */
const uint8_t *ntx_share_hasher_root(const ntx_share_hasher *h);      /* 32 */
const uint8_t *ntx_share_hasher_layer(const ntx_share_hasher *h, size_t *n); /* np*32, NULL when np==1 */
void ntx_share_hasher_free(ntx_share_hasher *h);

/* bencoded info dict and full .torrent; trackers = full share list order */
int ntx_share_build_info(const ntx_share_hasher *h, const char *name, const char salt_hex[33],
                         uint8_t **info, size_t *info_n);
int ntx_share_build_torrent(const uint8_t *info, size_t info_n, const ntx_share_hasher *h,
                            const char *const *trackers, int ntrk, int64_t creation_date,
                            uint8_t **out, size_t *out_n);

#endif
