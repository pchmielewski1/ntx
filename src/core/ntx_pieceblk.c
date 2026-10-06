#include "ntx_session_internal.h"

#include <stdlib.h>
#include <string.h>

/* piece-block state (piece_blk_*, piece_*) — split out of ntx_session_data.c. */

/* verify queue state lives in ntx_session_data.c */
extern uint8_t *verify_pend[NTX_SESSION_MAX_TTS];

void piece_blk_free_tts(struct ntx_session *s, int tts_idx) {
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) return;
    if (s->piece_blk_map[tts_idx]) {
        ntx_torrent *t = &s->tts[tts_idx];
        if (t->np > 0) {
            for (uint32_t j = 0; j < t->np; j++)
                free(s->piece_blk_map[tts_idx][j]);
        }
        free(s->piece_blk_map[tts_idx]);
        s->piece_blk_map[tts_idx] = NULL;
    }
    free(s->piece_blk_n[tts_idx]);
    s->piece_blk_n[tts_idx] = NULL;
}

int piece_blk_alloc_tts(struct ntx_session *s, int tts_idx) {
    ntx_torrent *t = &s->tts[tts_idx];
    piece_blk_free_tts(s, tts_idx);
    if (!t->np) return 0;
    s->piece_blk_map[tts_idx] = calloc(t->np, sizeof(uint8_t *));
    s->piece_blk_n[tts_idx] = calloc(t->np, sizeof(uint16_t));
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx]) return -1;
    for (uint32_t j = 0; j < t->np; j++) {
        /* Block counts must come from the torrent's own piece length: a BEP52
         * piece is aligned per file, so the last piece of every file is short and
         * the store's single-stream length would size the map wrong. */
        uint32_t pl = ntx_torrent_piece_len(t, j);
        uint16_t nb = (uint16_t)((pl + NTX_PEER_REQ_LEN - 1) / NTX_PEER_REQ_LEN);
        s->piece_blk_n[tts_idx][j] = nb;
        s->piece_blk_map[tts_idx][j] = calloc(nb, 1);
        if (!s->piece_blk_map[tts_idx][j]) return -1;
    }
    return 0;
}

void piece_blk_clear(struct ntx_session *s, int tts_idx, uint32_t idx) {
    if (s->piece_bytes[tts_idx]) s->piece_bytes[tts_idx][idx] = 0;
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np) return;
    memset(s->piece_blk_map[tts_idx][idx], 0, s->piece_blk_n[tts_idx][idx]);
}

void piece_blk_mark(struct ntx_session *s, int tts_idx, uint32_t idx, uint32_t off, uint32_t len) {
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np || !len)
        return;
    uint16_t nb = s->piece_blk_n[tts_idx][idx];
    uint32_t b0 = off / NTX_PEER_REQ_LEN;
    uint32_t b1 = (off + len - 1) / NTX_PEER_REQ_LEN;
    if (b0 >= nb) return;
    if (b1 >= nb) b1 = nb - 1;
    for (uint32_t b = b0; b <= b1; b++)
        s->piece_blk_map[tts_idx][idx][b] = 1;
}

/* 1 when every block of [off, off+len) is already stored. */
int piece_blk_have(const struct ntx_session *s, int tts_idx, uint32_t idx, uint32_t off, uint32_t len) {
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np || !len)
        return 0;
    uint16_t nb = s->piece_blk_n[tts_idx][idx];
    uint32_t b0 = off / NTX_PEER_REQ_LEN;
    uint32_t b1 = (off + len - 1) / NTX_PEER_REQ_LEN;
    if (b1 >= nb) return 0;
    for (uint32_t b = b0; b <= b1; b++)
        if (!s->piece_blk_map[tts_idx][idx][b]) return 0;
    return 1;
}

/* How many peers have this block requested right now. */
int piece_block_inflight_count(const struct ntx_session *s, int tts_idx, uint32_t idx, uint32_t off) {
    int n = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != tts_idx) continue;
        const ntx_peer *p = &s->peers[pi];
        for (int rq = 0; rq < p->n_req; rq++)
            if (p->req_idx[rq] == idx && p->req_off[rq] == off) n++;
    }
    return n;
}

int piece_all_blocks(const struct ntx_session *s, int tts_idx, uint32_t idx) {
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np) return 0;
    uint16_t nb = s->piece_blk_n[tts_idx][idx];
    const uint8_t *bm = s->piece_blk_map[tts_idx][idx];
    for (uint16_t b = 0; b < nb; b++)
        if (!bm[b]) return 0;
    return 1;
}

uint32_t piece_next_off(const struct ntx_session *s, int tts_idx, uint32_t idx) {
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np) {
        return s->piece_bytes[tts_idx] ? s->piece_bytes[tts_idx][idx] : 0;
    }
    uint16_t nb = s->piece_blk_n[tts_idx][idx];
    const uint8_t *bm = s->piece_blk_map[tts_idx][idx];
    for (uint16_t b = 0; b < nb; b++)
        if (!bm[b]) return (uint32_t)b * NTX_PEER_REQ_LEN;
    return ntx_torrent_piece_len(&s->tts[tts_idx], idx);
}

uint32_t piece_got_blocks(const struct ntx_session *s, int tts_idx, uint32_t idx) {
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np) return 0;
    uint16_t nb = s->piece_blk_n[tts_idx][idx];
    const uint8_t *bm = s->piece_blk_map[tts_idx][idx];
    uint32_t n = 0;
    for (uint16_t b = 0; b < nb; b++)
        if (bm[b]) n++;
    return n;
}

int piece_block_inflight_any(const struct ntx_session *s, int tts_idx, uint32_t idx,
                                    uint32_t off, uint64_t now, int allow_stale) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != tts_idx) continue;
        const ntx_peer *p = &s->peers[pi];
        for (int rq = 0; rq < p->n_req; rq++) {
            if (p->req_idx[rq] != idx || p->req_off[rq] != off) continue;
            if (allow_stale && now > p->req_t0[rq] &&
                now - p->req_t0[rq] > (uint64_t)NTX_PEER_REQ_STALE_MS)
                continue;
            return 1;
        }
    }
    return 0;
}

/* Next missing block offset that is not already in-flight on any peer.
 * Without this, a single fill loop opens NTX_PIPE_INFLIGHT distinct pieces
 * (each still at off=0 until the first PIECE arrives) and never finishes one. */
uint32_t piece_next_off_avail(const struct ntx_session *s, int tts_idx, uint32_t idx,
                                     uint64_t now) {
    int allow_stale = piece_got_blocks(s, tts_idx, idx) > 0;
    uint32_t pl = ntx_torrent_piece_len(&s->tts[tts_idx], idx);
    if (!s->piece_blk_map[tts_idx] || !s->piece_blk_n[tts_idx] || idx >= s->tts[tts_idx].np) {
        uint32_t off = s->piece_bytes[tts_idx] ? s->piece_bytes[tts_idx][idx] : 0;
        if (piece_block_inflight_any(s, tts_idx, idx, off, now, allow_stale))
            off += (uint32_t)NTX_PEER_REQ_LEN;
        return off >= pl ? pl : off;
    }
    uint16_t nb = s->piece_blk_n[tts_idx][idx];
    const uint8_t *bm = s->piece_blk_map[tts_idx][idx];
    for (uint16_t b = 0; b < nb; b++) {
        if (bm[b]) continue;
        uint32_t off = (uint32_t)b * (uint32_t)NTX_PEER_REQ_LEN;
        if (!piece_block_inflight_any(s, tts_idx, idx, off, now, allow_stale))
            return off;
    }
    return pl;
}

int piece_has_inflight(const ntx_peer *p, uint32_t idx) {
    if (!p) return 0;
    for (int rq = 0; rq < p->n_req; rq++)
        if (p->req_idx[rq] == idx) return 1;
    return 0;
}

int piece_has_partial(const struct ntx_session *s, int tts_idx) {
    if (tts_idx < 0 || tts_idx >= s->n_tts || !s->piece_bytes[tts_idx]) return 0;
    const ntx_torrent *t = &s->tts[tts_idx];
    for (uint32_t j = 0; j < t->np; j++)
        if (!t->have[j] && s->piece_bytes[tts_idx][j] > 0)
            return 1;
    return 0;
}

int piece_want(const ntx_torrent *t, struct ntx_session *s, int tts_idx, uint32_t idx) {
    if (t->have && t->have[idx]) return 0;
    if (verify_pend[tts_idx] && verify_pend[tts_idx][idx]) return 0;
    uint32_t off = piece_next_off(s, tts_idx, idx);
    return off < ntx_torrent_piece_len(t, idx);
}
