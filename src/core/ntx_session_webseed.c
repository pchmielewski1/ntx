#include "ntx_session_internal.h"
#include "../proto/ntx_http.h"

/* HTTP webseed (BEP19): Range GET on magnet ws= / as= URL. */

/* verify queue state + pump live in ntx_session_data.c */
extern uint8_t *verify_pend[NTX_SESSION_MAX_TTS];
extern int verify_src_pi[NTX_SESSION_MAX_TTS];
extern uint32_t verify_src_idx[NTX_SESSION_MAX_TTS];

void ntx_session_webseed_tick(struct ntx_session *s, int tts_idx) {
    ntx_torrent *t = &s->tts[tts_idx];
    if (!t->has_webseed || !t->have_meta || t->state != NTX_TTS_DL || !t->ps) return;
    for (uint32_t idx = 0; idx < t->np; idx++) {
        if (!piece_want(t, s, tts_idx, idx)) continue;
        uint32_t off = piece_next_off(s, tts_idx, idx);
        uint32_t pl = ntx_store_pl(&t->store, idx);
        if (off >= pl) continue;
        uint32_t len = pl - off;
        if (len > (uint32_t)NTX_PEER_REQ_LEN) len = (uint32_t)NTX_PEER_REQ_LEN;
        uint64_t byte_off = (uint64_t)idx * (uint64_t)t->ps + (uint64_t)off;
        uint8_t buf[16384];
        size_t got = 0;
        /* https:// URLs go through ntx_http_get_range → https branch */
        if (ntx_http_get_range(t->webseed, byte_off, len, buf, len, &got) != 0 || got == 0) return;
        ntx_store_write(&t->store, idx, off, buf, got);
        s->down_total += got;
        s->tts_down[tts_idx] += got;
        s->cur_d += (uint32_t)got;
        s->tts_cur_d[tts_idx] += (uint32_t)got;
        if (s->piece_bytes[tts_idx]) {
            uint32_t end = off + (uint32_t)got;
            if (end > s->piece_bytes[tts_idx][idx]) s->piece_bytes[tts_idx][idx] = end;
            piece_blk_mark(s, tts_idx, idx, off, (uint32_t)got);
            if (piece_all_blocks(s, tts_idx, idx) && !t->have[idx] && verify_pend[tts_idx] &&
                !verify_pend[tts_idx][idx]) {
                verify_pend[tts_idx][idx] = 1;
                verify_src_pi[tts_idx] = -1;
                verify_src_idx[tts_idx] = idx;
                verify_drain(s, 8);
            }
        }
        return;
    }
}
