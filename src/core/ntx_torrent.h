#ifndef NTX_TORRENT_H
#define NTX_TORRENT_H

#include <stdint.h>
#include <stddef.h>
#include "ntx_store.h"
#include "ntx_peer.h"
#include "../proto/ntx_bencode.h"

#define NTX_META_TIMEOUT_S 120
/* Largest piece length accepted from a metainfo (it sizes a per-piece hash buffer). */
#define NTX_TORRENT_MAX_PIECE_LEN (64u * 1024u * 1024u)

/* BEP52: per-torrent v2 file table capacity. */
#define NTX_TORRENT_MAX_FILES_V2 64

typedef enum ntx_tts_state {
    NTX_TTS_META,
    NTX_TTS_DL,
    NTX_TTS_DONE,
    NTX_TTS_PAUSED,
    NTX_TTS_VERIFY,
    NTX_TTS_DEAD
} ntx_tts_state;

typedef struct ntx_torrent ntx_torrent;
typedef void (*ntx_torrent_on_piece_fn)(ntx_torrent *t, uint32_t piece, void *ctx);

typedef struct ntx_torrent {
    uint8_t info_hash[20];
    char name[512];
    char webseed[512];
    int has_webseed;
    uint32_t ps;
    uint8_t *phash;
    uint32_t np;
    uint64_t size;
    uint8_t *have;
    uint32_t have_n;
    uint64_t verified_B;
    int *rarity;
    ntx_store store;
    int have_meta;
    ntx_tts_state state;
    uint8_t paused_from; /* JSON-API v1 §6.3: state remembered when pausing */
    uint8_t pre_complete;
    uint32_t verify_off;
    uint8_t *info_raw;
    size_t info_raw_n;
    ntx_torrent_on_piece_fn on_piece_have;
    void *on_piece_have_ctx;
    /* BEP52: v2/hybrid metainfo state (zero for pure v1 torrents) */
    uint8_t info_hash_v2[32]; /* sha256(info); zero if v1 */
    uint8_t meta_version; /* 0 = v1, 2 = v2/hybrid */
    uint8_t hybrid; /* 1 if metainfo carries both v1 and v2 fields */
    uint8_t *piece_layer; /* v2: concatenated per-file piece layers */
    size_t piece_layer_n; /* == np_total*32 for v2 verify layout */
    uint8_t layers_stall; /* pure-v2 layer acquisition stalled (bounded, not a meta loop) */
    uint8_t v2_root[NTX_TORRENT_MAX_FILES_V2][32];
    uint32_t v2_np_file[NTX_TORRENT_MAX_FILES_V2];
    uint32_t v2_first_piece[NTX_TORRENT_MAX_FILES_V2];
    uint64_t v2_len_file[NTX_TORRENT_MAX_FILES_V2];
    uint32_t v2_nfiles;
} ntx_torrent;

#define NTX_TORRENT_PEER_BAN_MS 60000u

int ntx_torrent_init_meta(ntx_torrent *t, const uint8_t info_hash[20]);
/* BEP52: detect meta version from an info dict (bencoded substring):
 * 0 = v1 (absent or "meta version" != 2), 2 = v2/hybrid, -1 invalid bencode
 * or "meta version" > 2. */
int ntx_torrent_metainfo_version(const uint8_t *info, size_t n);
/* BEP52: compute the infohash(es): out20 = sha1 (v1) or trunc20(sha256)
 * (v2); out32 = sha256 (v2 only, zeroed for v1). Returns the meta version,
 * -1 on invalid input. */
int ntx_torrent_metainfo_hash(const uint8_t *info, size_t n, uint8_t out20[20],
                              uint8_t out32[32]);
/* BEP52: piece_layers = top-level metainfo "piece layers" dict
 * (sibling of "info"), or NULL when unavailable (v1, or the info-only
 * ut_metadata flow). A NULL is accepted for pure v2 too:
 * hybrid keeps the v1 SHA-1 verify, pure v2 enters the hash-exchange path
 * (ntx_torrent_layers_pending) instead of being rejected into a meta loop. */
int ntx_torrent_set_metainfo(ntx_torrent *t, const uint8_t *info_dict, size_t info_len, const char *store_dir,
                             const ntx_be *piece_layers);
int ntx_torrent_piece_complete(ntx_torrent *t, uint32_t i);
int ntx_torrent_piece_complete_from(ntx_torrent *t, uint32_t i, ntx_peer *src, uint64_t now_ms);
int ntx_torrent_verify_range(ntx_torrent *t, uint32_t from, uint32_t to);
void ntx_torrent_peer_ban(ntx_peer *p, uint64_t now_ms);
int ntx_torrent_peer_banned(const ntx_peer *p, uint64_t now_ms);
uint32_t ntx_torrent_pick(const ntx_torrent *t);
void ntx_torrent_on_peer_have(ntx_torrent *t, uint32_t i);
void ntx_torrent_on_peer_lost(ntx_torrent *t, const ntx_peer *p);
uint64_t ntx_torrent_verified_bytes(const ntx_torrent *t);
int ntx_torrent_done(const ntx_torrent *t);

/* BEP52 hash exchange — piece-layer acquisition for pure-v2 torrents. */
/* 1 = pure-v2 torrent that already has its info metainfo but is still waiting
 * for the piece layers via the BEP52 hash exchange (21/22/23). 0 otherwise (v1,
 * hybrid, no metainfo yet, layers already present, or every file is single-piece
 * so no piece layer is required). */
int ntx_torrent_layers_pending(const ntx_torrent *t);
/* Store a validated piece-layer string: the per-file concat, in file order, of
 * the piece-length hashes for every file with len > ps (n bytes total). Each
 * per-file slice is recomputed with ntx_merkle_root_from_layer and compared
 * against that file's pieces root before the bytes are trusted; a mismatch
 * stores nothing and returns -1. Returns 0 on success (layers_pending clears). */
int ntx_torrent_apply_piece_layer(ntx_torrent *t, const uint8_t *layer, size_t n);

/* Authoritative length of piece `i` in bytes.  For a v1 torrent this is the
 * store's contiguous-layout answer; for a BEP52 v2/hybrid torrent pieces are
 * aligned PER FILE, so the last piece of every file is short and the store's
 * single-stream arithmetic (size - i*piece_size) is wrong from the second file
 * onwards.  Anything that needs a piece's length to request, store or verify
 * data must call this and NOT ntx_store_pl(). */
uint32_t ntx_torrent_piece_len(const ntx_torrent *t, uint32_t i);

#endif
