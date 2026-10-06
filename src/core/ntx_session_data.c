#include "ntx_session_internal.h"
#include "../ui/ntx_diag.h"
#include "../proto/ntx_utmeta.h"
#include "../proto/ntx_holepunch.h"
#include "../proto/ntx_dht.h"
#include "../proto/ntx_tracker.h"
#include "ntx_time.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <time.h>

/* meta state arrays now live in ntx_session_meta.c */
extern uint8_t *meta_buf[NTX_SESSION_MAX_TTS];
extern uint8_t *meta_have[NTX_SESSION_MAX_TTS];
extern size_t meta_len[NTX_SESSION_MAX_TTS];
extern uint32_t meta_total[NTX_SESSION_MAX_TTS];
extern uint32_t meta_have_n[NTX_SESSION_MAX_TTS];
extern uint64_t meta_t0[NTX_SESSION_MAX_TTS];
extern uint64_t dl_t0[NTX_SESSION_MAX_TTS];

uint8_t *verify_pend[NTX_SESSION_MAX_TTS];
int verify_src_pi[NTX_SESSION_MAX_TTS];
uint32_t verify_src_idx[NTX_SESSION_MAX_TTS];

void ntx_session_data_reset_tts(int tts_idx, uint32_t np) {
    free(verify_pend[tts_idx]);
    verify_pend[tts_idx] = np ? (uint8_t *)calloc(np, 1) : NULL;
}

static uint64_t data_req_timeout_ms(const struct ntx_session *s, int tts_idx) {
    if (piece_has_partial(s, tts_idx))
        return (uint64_t)NTX_PEER_REQ_TIMEOUT_FAST_S * 1000;
    return (uint64_t)NTX_PEER_REQ_TIMEOUT_S * 1000;
}

/* Token bucket for --down-limit / --up-limit. Only block payload is shaped (requests it triggers on the
 * download side, PIECE messages on the upload side); control messages are never delayed or dropped. */
int ntx_session_shape_ready(struct ntx_session *s, int up) {
    uint64_t lim = s->cfg ? (up ? s->cfg->up_limit : s->cfg->down_limit) : 0;
    if (!lim) return 1;
    if (lim > ((uint64_t)1 << 40)) return 1;
    int d = up ? 1 : 0;
    int64_t cap = (int64_t)lim; /* one second of burst */
    uint64_t now = ntx_mono_ms();
    if (!s->shape_t[d]) {
        s->shape_t[d] = now;
        s->shape_tok[d] = cap;
    } else if (now > s->shape_t[d]) {
        uint64_t el = now - s->shape_t[d];
        s->shape_t[d] = now;
        if (el > ((uint64_t)1 << 22)) el = (uint64_t)1 << 22; /* keeps el * lim far from overflow */
        /* Debt (a block bigger than the budget) is repaid by elapsed time, however long the idle gap was. */
        s->shape_tok[d] += (int64_t)(el * lim / 1000u);
        if (s->shape_tok[d] > cap) s->shape_tok[d] = cap;
    }
    return s->shape_tok[d] > 0;
}

void ntx_session_shape_use(struct ntx_session *s, int up, uint64_t n) {
    uint64_t lim = s->cfg ? (up ? s->cfg->up_limit : s->cfg->down_limit) : 0;
    if (!lim || lim > ((uint64_t)1 << 40)) return;
    s->shape_tok[up ? 1 : 0] -= (int64_t)n;
}

/* Endgame: when only a few pieces are missing and every wanted block is already requested from someone,
 * an idle peer asks for the stalest outstanding blocks as well (one extra copy at most).  The first
 * copy to arrive cancels the rest (data_cancel_copies), so the last percent no longer waits for the
 * slowest peer's request timeout. */
#define NTX_ENDGAME_MAX_PIECES 32u
#define NTX_ENDGAME_MIN_AGE_MS 1500u

static int data_pick_endgame(struct ntx_session *s, int tts_idx, int pi, uint64_t now,
                             uint32_t *oidx, uint32_t *ooff, uint32_t *olen) {
    ntx_torrent *t = &s->tts[tts_idx];
    const ntx_peer *p = &s->peers[pi];
    uint32_t missing = 0;
    for (uint32_t j = 0; j < t->np; j++)
        if (!t->have[j] && ++missing > NTX_ENDGAME_MAX_PIECES) return -1;
    uint64_t best_age = 0;
    int found = 0;
    for (int q = 0; q < NTX_SESSION_MAX_PEERS; q++) {
        if (q == pi || s->peer_phase[q] != PH_OK || s->peer_tts[q] != tts_idx) continue;
        const ntx_peer *o = &s->peers[q];
        for (int r = 0; r < o->n_req; r++) {
            uint64_t age = now > o->req_t0[r] ? now - o->req_t0[r] : 0;
            if (age < NTX_ENDGAME_MIN_AGE_MS || age <= best_age) continue;
            uint32_t ri = o->req_idx[r], ro = o->req_off[r], rl = o->req_len[r];
            if (ri >= t->np || !ntx_peer_has(p, ri) || !piece_want(t, s, tts_idx, ri)) continue;
            if (piece_blk_have(s, tts_idx, ri, ro, rl)) continue;
            int mine = 0;
            for (int k = 0; k < p->n_req; k++)
                if (p->req_idx[k] == ri && p->req_off[k] == ro) mine = 1;
            if (mine || piece_block_inflight_count(s, tts_idx, ri, ro) >= 2) continue;
            best_age = age;
            *oidx = ri;
            *ooff = ro;
            *olen = rl;
            found = 1;
        }
    }
    return found ? 0 : -1;
}

/* A block arrived: forget (and cancel) the copies other peers still owe us. */
static void data_cancel_copies(struct ntx_session *s, int tts_idx, int from_pi, uint32_t idx,
                               uint32_t off) {
    for (int q = 0; q < NTX_SESSION_MAX_PEERS; q++) {
        if (q == from_pi || s->peer_phase[q] != PH_OK || s->peer_tts[q] != tts_idx) continue;
        ntx_peer *o = &s->peers[q];
        for (int r = 0; r < o->n_req; r++) {
            if (o->req_idx[r] != idx || o->req_off[r] != off) continue;
            ntx_session_peer_send_cancel(s, q, idx, off, o->req_len[r]);
            ntx_peer_request_done(o, idx, off);
            break;
        }
    }
}

static int data_request_one(struct ntx_session *s, int tts_idx, int pi, uint64_t now) {
    ntx_torrent *t = &s->tts[tts_idx];
    ntx_peer *p = &s->peers[pi];
    if (!ntx_peer_can_download(p)) return -1;
    if (now < s->peer_noreq_until[pi]) return -1; /* the peer just rejected a request */
    if (!ntx_session_shape_ready(s, 0)) return -1; /* --down-limit: out of budget until it refills */
    if (ntx_torrent_peer_banned(p, now)) {
        if (s->cfg && s->cfg->verbose)
            ntx_diag("ntx: req_skip pi=%d why=banned\n", pi);
        return -1;
    }

    uint32_t pick_idx = 0xFFFFFFFFu;
    uint32_t pick_off = 0;

    /* Pass 1: finish pieces already in progress (disk and/or in-flight). */
    uint32_t best_partial = 0xFFFFFFFFu;
    uint32_t best_partial_off = 0;
    uint32_t best_partial_got = 0;
    for (uint32_t idx = 0; idx < t->np; idx++) {
        if (!ntx_peer_has(p, idx) || !piece_want(t, s, tts_idx, idx)) continue;
        uint32_t got = piece_got_blocks(s, tts_idx, idx);
        if (got == 0 && !piece_has_inflight(p, idx)) continue;
        uint32_t pl = ntx_torrent_piece_len(t, idx);
        uint32_t off = piece_next_off_avail(s, tts_idx, idx, now);
        if (off >= pl) continue;
        if (best_partial == 0xFFFFFFFFu || got > best_partial_got ||
            (got == best_partial_got && off > best_partial_off)) {
            best_partial = idx;
            best_partial_off = off;
            best_partial_got = got;
        }
    }
    if (best_partial != 0xFFFFFFFFu) {
        pick_idx = best_partial;
        pick_off = best_partial_off;
    } else {
        /* Pass 2: rarest untouched piece (one new piece at a time per fill). */
        int best_r = INT_MAX;
        for (uint32_t idx = 0; idx < t->np; idx++) {
            if (!ntx_peer_has(p, idx) || !piece_want(t, s, tts_idx, idx)) continue;
            int rarity = (t->rarity && t->rarity[idx] > 0) ? t->rarity[idx] : 1;
            uint32_t off = piece_next_off_avail(s, tts_idx, idx, now);
            uint32_t pl = ntx_torrent_piece_len(t, idx);
            if (off >= pl) continue;
            if (rarity < best_r) {
                pick_idx = idx;
                pick_off = off;
                best_r = rarity;
            }
        }
    }
    uint32_t len = 0;
    if (pick_idx == 0xFFFFFFFFu && data_pick_endgame(s, tts_idx, pi, now, &pick_idx, &pick_off, &len) == 0) {
        if (s->cfg && s->cfg->verbose)
            ntx_diag("ntx: endgame_dup pi=%d idx=%u off=%u len=%u\n", pi, pick_idx, pick_off, len);
    } else if (pick_idx == 0xFFFFFFFFu) {
        if (s->cfg && s->cfg->verbose)
            ntx_diag("ntx: req_skip pi=%d why=no_piece choke_us=%d we_int=%d bf_got=%d phave=%u/%d "
                     "n_req=%d\n",
                     pi, p->choke_us, p->we_int, (int)s->peer_bf_got[pi], (unsigned)sp_phave_count(p),
                     p->phave_n, p->n_req);
        return -1;
    }
    if (len == 0) {
        uint32_t pl = ntx_torrent_piece_len(t, pick_idx);
        len = pl - pick_off;
        if (len > (uint32_t)NTX_PEER_REQ_LEN) len = (uint32_t)NTX_PEER_REQ_LEN;
    }
    if (ntx_session_peer_send_request(s, pi, pick_idx, pick_off, len) != 0) {
        if (s->cfg && s->cfg->verbose)
            ntx_diag("ntx: req_tx_fail pi=%d idx=%u off=%u len=%u\n", pi, pick_idx, pick_off, len);
        return -1;
    }
    if (ntx_peer_request(p, pick_idx, pick_off, len, now) != 0) return -1;
    ntx_session_shape_use(s, 0, len);
    if (s->cfg && s->cfg->verbose)
        ntx_diag("ntx: req_tx pi=%d idx=%u off=%u len=%u n_req=%d choke_us=%d we_int=%d phave=%u/%d\n",
                 pi, pick_idx, pick_off, len, p->n_req, p->choke_us, p->we_int,
                 (unsigned)sp_phave_count(p), p->phave_n);
    return 0;
}

int ntx_session_data_piece_blk_alloc(struct ntx_session *s, int tts_idx) {
    return piece_blk_alloc_tts(s, tts_idx);
}

static int data_opt_pi = -1;

static int data_ratio_threshold_hit(struct ntx_session *s, int ti) {
    if (ti < 0 || ti >= s->n_tts) return 0;
    ntx_torrent *t = &s->tts[ti];
    if (t->size == 0) return 0;
    return s->tts_up[ti] >= (uint64_t)NTX_SEED_RATIO_NUM * t->size;
}

static void data_enter_ratio_done(struct ntx_session *s, int ti) {
    if (ti < 0 || ti >= s->n_tts || s->tts_ratio_done[ti]) return;
    s->tts_ratio_done[ti] = 1;
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: seed ratio reached ti=%d up=%llu size=%llu\n", ti,
                (unsigned long long)s->tts_up[ti], (unsigned long long)s->tts[ti].size);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_tts[pi] != ti || s->peer_phase[pi] != PH_OK || s->peers[pi].fd == -1) continue;
        if (!s->peers[pi].we_choke) {
            ntx_peer_set_we_choke(&s->peers[pi], 1);
            ntx_session_peer_send_choke(s, pi, 1);
        }
        if (s->peers[pi].we_int) {
            ntx_peer_set_we_int(&s->peers[pi], 0);
            ntx_session_peer_send_interest(s, pi, 0);
        }
        ntx_session_peer_out_flush(s, pi);
    }
    ntx_session_trk_announce(s, ti, NTX_TRACKER_EVENT_STOPPED);
}

static int data_pick_opt_unchoke(const int *rank, int n) {
    int pool[NTX_SESSION_MAX_PEERS];
    int np = 0;
    for (int a = NTX_UNCHOKE_BEST; a < n; a++)
        pool[np++] = rank[a];
    if (np == 0) return -1;
    uint32_t r = (uint32_t)(data_opt_pi + 1) * 2654435761u + (uint32_t)n;
    return pool[r % (uint32_t)np];
}

static int data_peer_leeching(struct ntx_session *s, int pi) {
    int ti = s->peer_tts[pi];
    if (ti < 0 || ti >= s->n_tts) return 0;
    ntx_torrent *t = &s->tts[ti];
    if (ntx_torrent_layers_pending(t)) return 0;
    ntx_peer *p = &s->peers[pi];
    if (!p->we_int) return 0;
    if (t->state == NTX_TTS_META && s->peer_meta_size[pi] > 0) return 1;
    if (t->state != NTX_TTS_DL) return 0;
    for (uint32_t j = 0; j < t->np; j++)
        if (ntx_peer_has(p, j) && piece_want(t, s, ti, j))
            return 1;
    return 0;
}

static void data_update_peer_interest(struct ntx_session *s, int pi) {
    int tts_idx = s->peer_tts[pi];
    if (tts_idx < 0 || tts_idx >= s->n_tts) return;
    ntx_torrent *t = &s->tts[tts_idx];
    ntx_peer *p = &s->peers[pi];
    int prev = p->we_int;
    const char *why = NULL;
    if (ntx_torrent_layers_pending(t)) {
        if (p->we_int) {
            ntx_peer_set_we_int(p, 0);
            ntx_session_peer_send_interest(s, pi, 0);
            why = "layers_pending";
        }
        return;
    }
    if (t->state != NTX_TTS_DL || s->tts_ratio_done[tts_idx]) {
        if (p->we_int) {
            ntx_peer_set_we_int(p, 0);
            ntx_session_peer_send_interest(s, pi, 0);
            why = (t->state != NTX_TTS_DL) ? "not_dl" : "ratio_done";
        }
    } else if (p->phave_none) {
        if (!s->peer_bf_got[pi]) {
            if (!p->we_int) {
                ntx_peer_set_we_int(p, 1);
                ntx_session_peer_send_interest(s, pi, 1);
                why = "await_bf";
            }
        } else if (p->we_int) {
            ntx_peer_set_we_int(p, 0);
            ntx_session_peer_send_interest(s, pi, 0);
            why = "phave_empty";
        }
    } else {
        int want = 0;
        for (uint32_t idx = 0; idx < t->np; idx++) {
            if (ntx_peer_has(p, idx) && piece_want(t, s, tts_idx, idx)) {
                want = 1;
                break;
            }
        }
        if (want != p->we_int) {
            ntx_peer_set_we_int(p, want);
            ntx_session_peer_send_interest(s, pi, want);
            why = want ? "want_pieces" : "no_overlap";
        }
    }
    if (why && s->cfg && s->cfg->verbose && prev != p->we_int) {
        uint32_t phn = 0;
        if (p->phave && p->phave_n > 0)
            for (int i = 0; i < p->phave_n; i++)
                if (p->phave[i]) phn++;
        ntx_diag("ntx: we_int pi=%d %d->%d why=%s choke_us=%d bf_got=%d phave_none=%d "
                 "phave=%u/%d\n",
                 pi, prev, p->we_int, why, p->choke_us, (int)s->peer_bf_got[pi], p->phave_none,
                 (unsigned)phn, p->phave_n);
    }
}

void ntx_session_data_update_peer_interest(struct ntx_session *s, int pi) {
    data_update_peer_interest(s, pi);
}

static void data_fill_peer(struct ntx_session *s, int tts_idx, int pi) {
    if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != tts_idx) return;
    if (s->tts[tts_idx].state != NTX_TTS_DL) return;
    data_update_peer_interest(s, pi);
    if (ntx_torrent_layers_pending(&s->tts[tts_idx])) return;
    uint64_t now = ntx_mono_ms();
    int depth = ntx_peer_pipe_depth(&s->peers[pi], now);
    while (ntx_peer_req_count(&s->peers[pi]) < depth) {
        if (data_request_one(s, tts_idx, pi, now) != 0) break;
    }
}

static void data_fill_all(struct ntx_session *s, int tts_idx) {
    ntx_torrent *t = &s->tts[tts_idx];
    if (t->state != NTX_TTS_DL) return;
    /* Pure-v2 torrents wait for the BEP52 piece layers before the normal piece
     * pump starts. Update interest first so stale INTERESTED flags are cleared. */
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] == PH_OK && s->peer_tts[pi] == tts_idx)
            data_update_peer_interest(s, pi);
    }
    if (ntx_torrent_layers_pending(t)) return;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        data_fill_peer(s, tts_idx, pi);
}

void ntx_session_data_refill(struct ntx_session *s, int tts_idx) {
    if (tts_idx < 0 || tts_idx >= s->n_tts) return;
    data_fill_all(s, tts_idx);
}

void ntx_session_data_on_unchoke(struct ntx_session *s, int pi) {
    int tts_idx = s->peer_tts[pi];
    if (tts_idx < 0 || tts_idx >= s->n_tts) return;
    if (s->cfg && s->cfg->verbose) {
        ntx_peer *p = &s->peers[pi];
        ntx_diag("ntx: unchoke_fill pi=%d can_dl=%d choke_us=%d we_int=%d bf_got=%d phave=%u/%d "
                 "n_req=%d\n",
                 pi, ntx_peer_can_download(p), p->choke_us, p->we_int, (int)s->peer_bf_got[pi],
                 (unsigned)sp_phave_count(p), p->phave_n, p->n_req);
    }
    data_fill_peer(s, tts_idx, pi);
    if (s->cfg && s->cfg->verbose)
        ntx_diag("ntx: unchoke_fill_done pi=%d n_req=%d\n", pi, s->peers[pi].n_req);
}

void ntx_session_data_on_choke(struct ntx_session *s, int pi) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    ntx_peer *p = &s->peers[pi];
    int nreq = p->n_req;
    int tts_idx = s->peer_tts[pi];
    for (int r = 0; r < p->n_req; r++)
        ntx_session_peer_send_cancel(s, pi, p->req_idx[r], p->req_off[r], p->req_len[r]);
    ntx_peer_clear_requests(p);
    if (s->cfg && s->cfg->verbose && nreq > 0)
        ntx_diag("ntx: req_clear pi=%d n=%d why=choke_rx refill=1\n", pi, nreq);
    if (tts_idx >= 0 && tts_idx < s->n_tts)
        ntx_session_data_refill(s, tts_idx);
}

static void data_broadcast_have(struct ntx_session *s, int tts_idx, uint32_t idx) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != tts_idx || s->peers[pi].fd == -1) continue;
        ntx_session_peer_send_have(s, pi, idx);
    }
}

static void data_check_torrent_done(struct ntx_session *s, int tts_idx) {
    ntx_torrent *t = &s->tts[tts_idx];
    if (!ntx_torrent_done(t) || t->state == NTX_TTS_DONE) return;
    t->state = NTX_TTS_DONE;
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: download complete ti=%d\n", tts_idx);
    if (!t->pre_complete)
        ntx_session_trk_announce(s, tts_idx, NTX_TRACKER_EVENT_COMPLETED);
    if (s->cfg && s->cfg->dht)
        ntx_dht_announce(t->info_hash, ntx_netx_port(s->netx));
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != tts_idx || s->peers[pi].fd == -1) continue;
        ntx_session_peer_send_have_all(s, pi);
        if (s->peers[pi].we_int) {
            ntx_peer_set_we_int(&s->peers[pi], 0);
            ntx_session_peer_send_interest(s, pi, 0);
        }
        ntx_session_peer_out_flush(s, pi);
    }
    if (data_ratio_threshold_hit(s, tts_idx))
        data_enter_ratio_done(s, tts_idx);
}

void verify_drain(struct ntx_session *s, int max_jobs) {
    uint64_t now = ntx_mono_ms();
    for (int n = 0; n < max_jobs; n++) {
        int found = 0;
        for (int i = 0; i < s->n_tts; i++) {
            ntx_torrent *t = &s->tts[i];
            if (t->state != NTX_TTS_DL || !verify_pend[i]) continue;
            for (uint32_t idx = 0; idx < t->np; idx++) {
                if (!verify_pend[i][idx]) continue;
                verify_pend[i][idx] = 0;
                int src_pi = (verify_src_idx[i] == idx) ? verify_src_pi[i] : -1;
                ntx_peer *src = (src_pi >= 0 && src_pi < NTX_SESSION_MAX_PEERS) ? &s->peers[src_pi] : NULL;
                int ok = ntx_torrent_piece_complete_from(t, idx, src, now);
                if (!ok) {
                    piece_blk_clear(s, i, idx);
                    if (s->cfg && s->cfg->verbose)
                        ntx_diag( "ntx: piece hash fail ti=%d idx=%u\n", i, idx);
                } else if (ok) {
                    data_broadcast_have(s, i, idx);
                    if (s->cfg && s->cfg->verbose)
                        ntx_diag( "ntx: piece ok ti=%d idx=%u have=%u/%u\n", i, idx,
                                (unsigned)t->have_n, (unsigned)t->np);
                }
                found = 1;
                data_check_torrent_done(s, i);
                goto done_one;
            }
        }
        if (!found) break;
    done_one:;
    }
}

void ntx_session_data_on_piece(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, const uint8_t *data, uint32_t len) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    int i = s->peer_tts[pi];
    if (i < 0 || i >= s->n_tts) return;
    ntx_torrent *t = &s->tts[i];
    if (idx >= t->np) return;
    if (s->cfg && s->cfg->verbose)
        ntx_diag("ntx: piece_rx pi=%d idx=%u off=%u len=%u\n", pi, idx, off, len);
    ntx_peer_request_done(&s->peers[pi], idx, off);
    /* Whoever the caller is: never write outside the piece (off + len must not wrap either) and never
     * over a piece we already verified.  The data would be unchecked and would corrupt the file. */
    if (t->have[idx] || (uint64_t)off + len > ntx_torrent_piece_len(t, idx)) return;
    /* Second copy of a block already stored (endgame, or a timed-out request answered late). */
    if (piece_blk_have(s, i, idx, off, len)) {
        if (t->state == NTX_TTS_DL) data_fill_peer(s, i, pi);
        return;
    }
    if (ntx_store_write(&t->store, idx, off, data, len) != 0) return;
    s->down_total += len;
    s->tts_down[i] += len;
    s->cur_d += len;
    s->tts_cur_d[i] += len;
    s->peers[pi].down_B += len;
    s->peers[pi].spd_d += (double)len;
    if (s->piece_bytes[i]) {
        uint32_t end = off + len;
        if (end > s->piece_bytes[i][idx]) s->piece_bytes[i][idx] = end;
        piece_blk_mark(s, i, idx, off, len);
        data_cancel_copies(s, i, pi, idx, off);
        if (piece_all_blocks(s, i, idx)) {
            if (!t->have[idx] && verify_pend[i] && !verify_pend[i][idx]) {
                verify_pend[i][idx] = 1;
                verify_src_pi[i] = pi;
                verify_src_idx[i] = idx;
                verify_drain(s, 8);
            }
        }
    }
    if (t->state == NTX_TTS_DL)
        data_fill_peer(s, i, pi);
}

/* A request we will not serve: BEP6 peers are told so with reject_request; for everybody else the
 * request is simply left unanswered (the peer times it out). */
static void data_refuse(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    ntx_session_peer_send_reject(s, pi, idx, off, len);
}

/* Read the block and put it on the wire. 0 = sent (counted as uploaded), -1 = could not. */
static int data_serve(struct ntx_session *s, int pi, int i, uint32_t idx, uint32_t off, uint32_t len) {
    ntx_torrent *t = &s->tts[i];
    uint8_t buf[NTX_PEER_REQ_LEN];
    int n = ntx_store_read(&t->store, idx, off, buf, len);
    if (n <= 0) {
        data_refuse(s, pi, idx, off, len);
        return -1;
    }
    if (ntx_session_peer_send_piece(s, pi, idx, off, buf, (uint32_t)n) != 0) return -1;
    ntx_session_shape_use(s, 1, (uint64_t)n);
    s->up_total += (uint64_t)n;
    s->tts_up[i] += (uint64_t)n;
    s->cur_u += (uint32_t)n;
    s->tts_cur_u[i] += (uint32_t)n;
    s->peers[pi].up_B += (uint64_t)n;
    if (t->state == NTX_TTS_DONE && data_ratio_threshold_hit(s, i)) data_enter_ratio_done(s, i);
    return 0;
}

/* Normalise and validate a block request against the torrent. 0 = ok (*len possibly shortened). */
static int data_request_ok(struct ntx_session *s, int pi, int i, uint32_t idx, uint32_t off, uint32_t *len) {
    ntx_torrent *t = &s->tts[i];
    if (s->tts_ratio_done[i] || t->state == NTX_TTS_PAUSED || t->state == NTX_TTS_META ||
        t->state == NTX_TTS_DEAD)
        return -1;
    if (s->peers[pi].we_choke || !ntx_peer_can_send(&s->peers[pi])) return -1;
    if (idx >= t->np || !t->have || !t->have[idx]) return -1;
    /* v2/hybrid pieces are aligned per file, so the store's single-stream
     * length is not the piece's length: using it here cancels or mis-clips
     * legitimate requests for every piece past the first file's end. */
    uint32_t pl = ntx_torrent_piece_len(t, idx);
    if (off >= pl) return -1;
    if (*len > pl - off) *len = pl - off;
    if (*len > (uint32_t)NTX_PEER_REQ_LEN) *len = (uint32_t)NTX_PEER_REQ_LEN;
    if (*len == 0) return -1;
    return 0;
}

static int data_up_room(const struct ntx_session *s, int pi, uint32_t len) {
    return s->peer_out_len[pi] + 13u + len <= NTX_PEER_OUTBUF;
}

void ntx_session_data_on_request(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    int i = s->peer_tts[pi];
    if (i < 0 || i >= s->n_tts) return;
    uint32_t want = len;
    if (data_request_ok(s, pi, i, idx, off, &len) != 0) {
        data_refuse(s, pi, idx, off, want);
        return;
    }
    /* Serve now when nothing is waiting, the upload budget allows it and the peer is draining what we
     * already queued; otherwise keep the request and serve it from the tick (in order). Serving more
     * than the peer reads would only be dropped by the output buffer after a pointless disk read. */
    if (s->upq_n[pi] == 0 && ntx_session_shape_ready(s, 1) && data_up_room(s, pi, len)) {
        (void)data_serve(s, pi, i, idx, off, len);
        return;
    }
    if (s->upq_n[pi] >= NTX_UPQ_MAX) {
        data_refuse(s, pi, idx, off, want);
        return;
    }
    for (int k = 0; k < s->upq_n[pi]; k++)
        if (s->upq[pi][k].idx == idx && s->upq[pi][k].off == off) return; /* already waiting */
    s->upq[pi][s->upq_n[pi]].idx = idx;
    s->upq[pi][s->upq_n[pi]].off = off;
    s->upq[pi][s->upq_n[pi]].len = len;
    s->upq_n[pi]++;
}

/* The peer withdrew a request that is still waiting for upload budget. */
void ntx_session_data_on_cancel(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    (void)len;
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    for (int k = 0; k < s->upq_n[pi]; k++) {
        if (s->upq[pi][k].idx != idx || s->upq[pi][k].off != off) continue;
        memmove(&s->upq[pi][k], &s->upq[pi][k + 1], (size_t)(s->upq_n[pi] - k - 1) * sizeof s->upq[pi][0]);
        s->upq_n[pi]--;
        return;
    }
}

/* BEP6 reject_request: the peer will not answer this request. Free the slot and leave the peer alone
 * for a moment, otherwise the next fill would just ask for the same block again. */
void ntx_session_data_on_reject(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    if (!ntx_peer_request_match(&s->peers[pi], idx, off, len)) return;
    ntx_peer_request_done(&s->peers[pi], idx, off);
    s->peer_noreq_until[pi] = ntx_mono_ms() + 5000u;
}

/* Called every tick: serve deferred requests while the budget and the peer's buffer allow. */
static void data_up_drain(struct ntx_session *s) {
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->upq_n[pi] == 0) continue;
        int i = s->peer_tts[pi];
        if (s->peers[pi].fd == -1 || s->peer_phase[pi] != PH_OK || i < 0 || i >= s->n_tts) {
            s->upq_n[pi] = 0;
            continue;
        }
        while (s->upq_n[pi] > 0) {
            uint32_t idx = s->upq[pi][0].idx, off = s->upq[pi][0].off, len = s->upq[pi][0].len;
            if (data_request_ok(s, pi, i, idx, off, &len) != 0) { /* choked / paused / gone meanwhile */
                data_refuse(s, pi, idx, off, s->upq[pi][0].len);
                memmove(&s->upq[pi][0], &s->upq[pi][1], (size_t)(s->upq_n[pi] - 1) * sizeof s->upq[pi][0]);
                s->upq_n[pi]--;
                continue;
            }
            if (!ntx_session_shape_ready(s, 1) || !data_up_room(s, pi, len)) break;
            memmove(&s->upq[pi][0], &s->upq[pi][1], (size_t)(s->upq_n[pi] - 1) * sizeof s->upq[pi][0]);
            s->upq_n[pi]--;
            (void)data_serve(s, pi, i, idx, off, len);
        }
    }
}

void ntx_session_data_on_ext(struct ntx_session *s, int pi, int ext_id, const uint8_t *payload, size_t plen) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    /* BEP10: TX uses peer's ext IDs; RX uses our local IDs (peer sends with our advertised IDs). */
    if (!ext_is_metadata(s, pi, ext_id)) {
        if (ext_is_holepunch(s, pi, ext_id)) {
            ntx_session_holepunch_on_rx(s, pi, payload, plen);
            return;
        }
        if (ext_is_pex(s, pi, ext_id))
            ntx_session_data_on_pex(s, pi, payload, plen);
        return;
    }
    int i = s->peer_tts[pi];
    if (i < 0 || i >= s->n_tts) return;
    ntx_torrent *t = &s->tts[i];
    int mt = 0;
    uint32_t piece = 0, total_size = 0;
    const uint8_t *data = 0;
    size_t dlen = 0;
    if (ntx_ut_metadata_parse(payload, plen, &mt, &piece, &total_size, &data, &dlen) != 0) {
        return;
    }
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: meta rx pi=%d ext_id=%d type=%d piece=%u dlen=%zu\n", pi, ext_id, mt, piece, dlen);
    if (mt == NTX_UT_METADATA_REQUEST) {
        /* BEP9: any peer holding the info dict may answer, so the gate is
         * "do we have the metadata", NOT "are we still fetching it".  Gating on
         * NTX_TTS_META made a seeder that loaded a .torrent (or finished a
         * magnet) refuse every request, which left magnet-only peers with no
         * source of the info dict.  send_metainfo re-checks and the requester
         * hash-gates the assembled result against its own xt. */
        if (ntx_session_data_send_metainfo(s, pi, piece) < 0)
            meta_reject(s, pi, piece);
    } else if (mt == NTX_UT_METADATA_DATA) {
        if (s->peer_meta_req[pi] > 0) s->peer_meta_req[pi]--;
        if (s->peer_meta_inflight[pi] == piece) s->peer_meta_inflight[pi] = UINT32_MAX;
        if (t->state != NTX_TTS_META) return;
        if (total_size == 0) return;
        if (meta_total[i] == 0) {
            meta_total[i] = total_size;
            meta_buf[i] = calloc(total_size, 1);
            meta_have[i] = calloc(ntx_ut_metadata_npieces(total_size), 1);
            if (!meta_buf[i] || !meta_have[i]) {
                meta_reset(i);
                return;
            }
            if (meta_t0[i] == 0) meta_t0[i] = ntx_mono_ms();
        }
        if (meta_total[i] != total_size) {
            meta_reset(i);
            return;
        }
        uint32_t npieces = ntx_ut_metadata_npieces(meta_total[i]);
        if (piece >= npieces) return;
        if (ntx_ut_metadata_piece_write(meta_buf[i], meta_total[i], piece, data, dlen) != 0) return;
        if (!meta_have[i][piece]) {
            meta_have[i][piece] = 1;
            meta_have_n[i]++;
            meta_len[i] += dlen;
        }
        if (meta_have_n[i] >= npieces)
            meta_assemble(s, i);
        else
            ntx_session_data_meta_pump_peer(s, pi);
    } else {
        if (s->peer_meta_req[pi] > 0) s->peer_meta_req[pi]--;
        if (mt == NTX_UT_METADATA_REJECT && s->peer_meta_inflight[pi] == piece)
            s->peer_meta_inflight[pi] = UINT32_MAX;
        ntx_session_data_meta_pump_peer(s, pi);
    }
}

void ntx_session_data_tick(struct ntx_session *s) {
    uint64_t now = ntx_mono_ms();
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] != PH_OK) continue;
        int ti = s->peer_tts[pi];
        uint64_t lim = (ti >= 0 && ti < s->n_tts) ? data_req_timeout_ms(s, ti)
                                                  : (uint64_t)NTX_PEER_REQ_TIMEOUT_S * 1000;
        ntx_peer *p = &s->peers[pi];
        for (int r = 0; r < p->n_req; r++) {
            if (now > p->req_t0[r] && now - p->req_t0[r] > lim) {
                if (s->cfg && s->cfg->verbose)
                    ntx_diag( "ntx: req timeout pi=%d idx=%u off=%u len=%u age=%llums\n", pi,
                            p->req_idx[r], p->req_off[r], p->req_len[r],
                            (unsigned long long)(now - p->req_t0[r]));
                ntx_session_peer_send_cancel(s, pi, p->req_idx[r], p->req_off[r], p->req_len[r]);
            }
        }
        int cleared = ntx_peer_timeout_lim(p, now, lim);
        if (cleared > 0 && s->peer_tts[pi] >= 0 && s->peer_tts[pi] < s->n_tts)
            data_fill_peer(s, s->peer_tts[pi], pi);
        else if (cleared > 0 && s->cfg && s->cfg->verbose)
            ntx_diag( "ntx: req cleared pi=%d remain=%d\n", pi, p->n_req);
    }
    data_up_drain(s);
    for (int i = 0; i < s->n_tts; i++)
        data_fill_all(s, i);
    if (s->tick_n % 50 == 0) {
        for (int i = 0; i < s->n_tts; i++) {
            if (s->tts[i].state != NTX_TTS_DL || !s->tts[i].has_webseed) continue;
            int un = 0;
            for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
                if (s->peer_tts[pi] == i && s->peer_phase[pi] == PH_OK && ntx_peer_can_download(&s->peers[pi]))
                    un++;
            if (un == 0) ntx_session_webseed_tick(s, i);
        }
    }
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1)
            ntx_session_peer_out_flush(s, pi);
    verify_drain(s, 16);
    ntx_session_data_pex_tick(s);
    for (int i = 0; i < s->n_tts; i++) {
        ntx_torrent *t = &s->tts[i];
        if (t->state != NTX_TTS_META) continue;
        if (meta_t0[i] == 0) meta_t0[i] = now;
        if (now > meta_t0[i] && now - meta_t0[i] > (uint64_t)NTX_META_TIMEOUT_S * 1000u) {
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: meta timeout ti=%d retry\n", i);
            meta_t0[i] = now;
            meta_retry_all(s, i);
        }
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peer_tts[pi] != i) continue;
            ntx_session_data_meta_pump_peer(s, pi);
        }
    }
    if (s->tick_n % 40 == 0) {
        /* Re-evaluate upload choke every ~4 s. */
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
            s->peers[pi].spd_d *= 0.5;

        /* Ratio-done: never upload. */
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peer_phase[pi] != PH_OK) continue;
            int ti = s->peer_tts[pi];
            if (ti < 0 || ti >= s->n_tts || !s->tts_ratio_done[ti]) continue;
            if (s->peers[pi].we_choke) continue;
            ntx_peer_set_we_choke(&s->peers[pi], 1);
            ntx_session_peer_send_choke(s, pi, 1);
        }

        /* Pure seed: prefer peers interested in us (int_us). */
        for (int ti = 0; ti < s->n_tts; ti++) {
            if (s->tts[ti].state != NTX_TTS_DONE || s->tts_ratio_done[ti]) continue;
            int ok[NTX_SESSION_MAX_PEERS];
            int n = 0;
            for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
                if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != ti) continue;
                ok[n++] = pi;
            }
            for (int a = 0; a < n; a++)
                for (int b = a + 1; b < n; b++) {
                    int pa = ok[a], pb = ok[b];
                    int ia = s->peers[pa].int_us, ib = s->peers[pb].int_us;
                    if (ib > ia || (ib == ia && s->peers[pb].spd_d > s->peers[pa].spd_d)) {
                        int tmp = ok[a];
                        ok[a] = ok[b];
                        ok[b] = tmp;
                    }
                }
            int seed_opt = -1;
            if (s->tick_n % NTX_OPT_UNCHOKE_TICKS == 0 && n > NTX_UNCHOKE_BEST)
                seed_opt = data_pick_opt_unchoke(ok, n);
            for (int a = 0; a < n; a++) {
                int pi = ok[a];
                int choke = s->peers[pi].int_us ? 0
                                                  : (a >= NTX_UNCHOKE_BEST && pi != seed_opt);
                if (s->peers[pi].we_choke == choke) continue;
                ntx_peer_set_we_choke(&s->peers[pi], choke);
                ntx_session_peer_send_choke(s, pi, choke);
            }
        }

        /* Download: tit-for-tat by download speed from peer. */
        int ok[NTX_SESSION_MAX_PEERS];
        int n = 0;
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peer_phase[pi] != PH_OK) continue;
            int ti = s->peer_tts[pi];
            if (ti < 0 || ti >= s->n_tts) continue;
            if (s->tts[ti].state != NTX_TTS_DL && s->tts[ti].state != NTX_TTS_META) continue;
            if (s->tts_ratio_done[ti]) continue;
            ok[n++] = pi;
        }
        for (int a = 0; a < n; a++)
            for (int b = a + 1; b < n; b++)
                if (s->peers[ok[b]].spd_d > s->peers[ok[a]].spd_d) {
                    int tmp = ok[a];
                    ok[a] = ok[b];
                    ok[b] = tmp;
                }
        if (s->tick_n % NTX_OPT_UNCHOKE_TICKS == 0)
            data_opt_pi = data_pick_opt_unchoke(ok, n);
        for (int a = 0; a < n; a++) {
            int pi = ok[a];
            int ti = s->peer_tts[pi];
            int choke = a >= NTX_UNCHOKE_BEST && pi != data_opt_pi;
            if (data_peer_leeching(s, pi)) choke = 0;
            if (ti >= 0 && ti < s->n_tts && s->tts[ti].state == NTX_TTS_META && meta_t0[ti] &&
                now - meta_t0[ti] < 60000 && s->peers[pi].we_int)
                choke = 0;
            if (ti >= 0 && ti < s->n_tts && dl_t0[ti] && now > dl_t0[ti] &&
                now - dl_t0[ti] < 60000 && s->peers[pi].we_int)
                choke = 0;
            if (s->peers[pi].we_choke == choke) continue;
            ntx_peer_set_we_choke(&s->peers[pi], choke);
            ntx_session_peer_send_choke(s, pi, choke);
        }
    }
    if (s->tick_n % 60 == 0)
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
            if (s->peer_phase[pi] == PH_OK)
                ntx_session_peer_send_keepalive(s, pi);
    if (s->tick_n % 150 == 0)
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peer_phase[pi] != PH_OK) continue;
            if (!s->peers[pi].choke_us || !s->peers[pi].we_int) continue;
            ntx_session_peer_send_interest(s, pi, 1);
        }
    if (s->tick_n % 50 == 0)
        for (int i = 0; i < s->n_tts; i++) {
            if (s->tts[i].state != NTX_TTS_DL || !piece_has_partial(s, i)) continue;
            int un = 0;
            for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
                if (s->peer_phase[pi] == PH_OK && s->peer_tts[pi] == i &&
                    ntx_peer_can_download(&s->peers[pi]))
                    un++;
            if (un == 0) {
                for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
                    if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != i) continue;
                    if (!s->peers[pi].we_int || !s->peers[pi].choke_us) continue;
                    ntx_session_peer_send_interest(s, pi, 1);
                }
                s->trk_next[i] = now;
                ntx_session_trk_boost_peers(s);
            }
        }
}

void ntx_session_data_verify_tick(struct ntx_session *s) {
    for (int i = 0; i < s->n_tts; i++) {
        ntx_torrent *t = &s->tts[i];
        if (t->state != NTX_TTS_VERIFY) continue;
        uint32_t budget = (2u * 1024u * 1024u) / (t->ps ? (uint32_t)t->ps : 1u);
        if (budget < 1u) budget = 1u;
        uint32_t to = t->verify_off + budget;
        if (to > t->np) to = t->np;
        ntx_torrent_verify_range(t, t->verify_off, to);
        t->verify_off = to;
        if (t->verify_off >= t->np) {
            if (t->have_n == t->np) {
                t->state = NTX_TTS_DONE;
                t->pre_complete = 1;
            } else {
                t->state = NTX_TTS_DL;
            }
            ntx_session_tts_verify_done(s, (uint32_t)i);
            if (t->pre_complete)
                data_check_torrent_done(s, i);
        }
    }
}

uint32_t ntx_session_data_verify_pending(int tts_idx, uint32_t np) {
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS || !verify_pend[tts_idx] || np == 0)
        return 0;
    uint32_t n = 0;
    for (uint32_t j = 0; j < np; j++)
        if (verify_pend[tts_idx][j])
            n++;
    return n;
}

/* ---- BEP55 ut_holepunch ---------------------------- */

int ext_is_holepunch(struct ntx_session *s, int pi, int ext_id) {
    (void)s;
    (void)pi;
    /* Peer sends to us using our advertised ut_holepunch ID. */
    return ext_id == (int)NTX_EXT_LOCAL_HOLEPUNCH;
}

/* Dial a uTP connection to a punched endpoint. Uses the sanctioned session
 * dial path (ntx_session_add_peer_from_tracker -> ntx_netx_route_connect),
 * which is the public route that dispatches to the uTP dial API when the
 * shared-socket uTP listener is live (cfg.utp). The dial is dedup'd by the
 * (addr,port) pair there, so a repeat connect is a no-op. */
void ntx_session_holepunch_dial(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port) {
    if (!s || !addr || port == 0) return;
    if (ntx_addr_is_zero(addr)) return;
    if (tts_idx < 0 || tts_idx >= s->n_tts) return;
    if (s->cfg && s->cfg->verbose) {
        char ip[48];
        if (ntx_addr_ntop(addr, ip, sizeof ip) != 0) snprintf(ip, sizeof ip, "?");
        ntx_diag("ntx: hp dial ti=%d %s:%u\n", tts_idx, ip, (unsigned)port);
    }
    /* punch_ok = dial launched toward the
     * punched endpoint; punch_fail = dial refused before launch (dedup,
     * caps, alloc, dead route). This is the single
     * aggregation site for the counters. */
    if (ntx_session_add_peer_dial_ex(s, tts_idx, addr, port, 1)) /* the remote dials us as well: no back-off */
        s->hp_dial_ok++;
    else
        s->hp_dial_fail++;
}

/* Deterministic tie-break once a peer reaches PH_OK: if two live handshaked
 * peers share the same endpoint (one dialled by us, one dialled by them — the
 * BEP55 "both dials succeeded" race), keep exactly one and drop the other.
 * The winner is decided by the shared peer_id pair so BOTH sides agree on the
 * same surviving socket. Returns 1 if it dropped a peer, 0 otherwise. */
int ntx_session_holepunch_resolve_race(struct ntx_session *s, int pi) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return 0;
    ntx_peer *p = &s->peers[pi];
    if (!p->id_set || p->fd == -1 || s->peer_phase[pi] != PH_OK) return 0;
    /* Find the other live PH_OK peer that is the SAME remote (same peer_id +
     * same address). The dual-dial pair shares the remote's 20-byte BT peer_id
     * and address; the LOCAL port differs (the accepted half records port 0 in
     * the uTP accept path), so the peer_id — not the port — is the identity
     * key that actually co-references the two halves of one logical peer. */
    int other = -1;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++) {
        if (i == pi) continue;
        if (s->peers[i].fd == -1 || s->peer_phase[i] != PH_OK) continue;
        if (!s->peers[i].id_set) continue;
        if (memcmp(s->peers[i].id, p->id, sizeof p->id) != 0) continue;
        if (!ntx_addr_eq(&s->peers[i].addr, &p->addr)) continue;
        other = i;
        break;
    }
    if (other < 0) return 0;
    /* Only a genuine dual-dial race has one side outbound and the other not:
     * two inbound or two outbound slots at one endpoint are not the BEP55
     * race (the dial path already dedups same-direction dials). */
    int a_out = s->peer_outbound[pi];
    int b_out = s->peer_outbound[other];
    if (a_out == b_out) return 0;
    /* out_wins==1 => the connection WE dialled survives; drop the accepted one.
     * out_wins==0 => the connection that dialled US survives; drop our dial. */
    int out_wins = ntx_holepunch_race_winner(s->peer_id, p->id);
    int keep_out = out_wins; /* the slot whose peer_outbound==1 is kept when 1 */
    int loser = (keep_out == 1) ? (a_out ? other : pi) : (a_out ? pi : other);
    if (loser < 0 || loser >= NTX_SESSION_MAX_PEERS || s->peers[loser].fd == -1) return 0;
    s->hp_race_dropped++;
    if (s->cfg && s->cfg->verbose) ntx_diag("ntx: hp race resolved drop pi=%d\n", loser);
    sp_drop(s, loser, "bep55-race");
    return 1;
}

/* RX entry for a ut_holepunch payload (already framed by ntx_ext_msg_parse).
 * Handles connect (dial) and error (record); an inbound rendezvous is only
 * meaningful to a relay, so a plain peer ignores it. */
void ntx_session_holepunch_on_rx(struct ntx_session *s, int pi, const uint8_t *payload, size_t plen) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    ntx_holepunch_msg m;
    if (ntx_holepunch_parse(payload, plen, &m) != 0) return;
    switch (m.msg_type) {
        case NTX_HP_MSG_CONNECT: {
            s->hp_rx_connect++;
            /* an unwanted target (we don't run uTP, or we already have a
             * live conn to that endpoint) MUST ignore the connect and MUST NOT
             * error the relay. */
            int self_declared = (s->cfg && s->cfg->utp) ? 1 : 0;
            int already = 0;
            for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++) {
                if (s->peers[i].fd == -1) continue;
                if (s->peers[i].port != m.port) continue;
                if (!ntx_addr_eq(&s->peers[i].addr, &m.addr)) continue;
                already = 1;
                break;
            }
            if (ntx_holepunch_target_policy(self_declared, already) != NTX_HP_TARGET_DIAL)
                return;
            ntx_session_holepunch_dial(s, s->peer_tts[pi], &m.addr, m.port);
            break;
        }
        case NTX_HP_MSG_ERROR:
            s->hp_rx_error++;
            if (s->cfg && s->cfg->verbose) ntx_diag("ntx: hp error pi=%d code=%u\n", pi, m.err_code);
            break;
        case NTX_HP_MSG_RENDEZVOUS:
            /* Only a relay acts on a rendezvous; a client peer ignores it. */
            s->hp_rx_rendezvous++;
            break;
        default:
            break;
    }
}

