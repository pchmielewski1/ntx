#include <stdio.h>
#include <string.h>
#include <time.h>

#include "ntx_session_internal.h"
#include "../proto/ntx_dht.h"
#include "../proto/ntx_doh.h"
#include "ntx_time.h"

/* stats/UI refresh (ntx_session_stats_refresh + helpers) — split out of ntx_session.c. */

static int stats_trk_pending(const ntx_session *s, int tts_idx) {
    int n = 0;
    for (int slot = 0; slot < NTX_TRK_PENDING; slot++)
        if (s->trk_pending_used[slot] && s->trk_pending_tts[slot] == tts_idx)
            n++;
    return n;
}

static uint32_t stats_smooth5(uint32_t cur, const uint32_t ring[5]) {
    uint64_t sum = cur;
    for (int k = 0; k < 5; k++) sum += ring[k];
    return (uint32_t)(sum / 5);
}

static void stats_fill_phase(struct ntx_session *s, int i, ntx_tts_stat *tt, uint32_t td) {
    ntx_torrent *t = &s->tts[i];
    tt->state = (uint8_t)t->state;
    tt->phase[0] = 0;

    tt->trk_total = (uint16_t)s->trk_n[i];
    tt->trk_pend = (uint16_t)stats_trk_pending(s, i);
    tt->trk_udp_ok = 0;
    tt->trk_dead = 0;
    for (int j = 0; j < s->trk_n[i] && j < NTX_SESSION_MAX_TRK; j++) {
        if (s->trk_fail[i][j] >= NTX_TRK_MAX_FAIL) {
            tt->trk_dead++;
            continue;
        }
        const char *url = s->trk_urls[i][j];
        if (strncmp(url, "udp://", 6) == 0 && s->trk_conn_done[i][j])
            tt->trk_udp_ok++;
    }

    tt->peers_all = 0;
    tt->peers_hs = 0;
    tt->peers_ok = 0;
    tt->peers_unchoked = 0;
    tt->peers_interested = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_tts[pi] != i || s->peers[pi].fd == -1) continue;
        tt->peers_all++;
        if (s->peer_phase[pi] == PH_OK) {
            tt->peers_ok++;
            if (ntx_peer_can_download(&s->peers[pi]))
                tt->peers_unchoked++;
            if (s->peers[pi].int_us)
                tt->peers_interested++;
        } else {
            tt->peers_hs++;
        }
    }
    tt->peers = tt->peers_ok;

    tt->meta_got = 0;
    tt->meta_need = 0;
    if (t->state == NTX_TTS_META) {
        ntx_session_data_meta_progress(i, &tt->meta_got, &tt->meta_need);
        if (tt->meta_need == 0) {
            for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
                if (s->peer_tts[pi] != i || s->peers[pi].fd == -1) continue;
                if (s->peer_meta_size[pi] > 0) {
                    uint32_t np = (s->peer_meta_size[pi] + 16383u) / 16384u;
                    tt->meta_need = (uint16_t)(np > 65535u ? 65535u : np);
                    break;
                }
            }
        }
    }

    const char *phase = "init";
    switch (t->state) {
    case NTX_TTS_PAUSED:
        phase = "pause";
        break;
    case NTX_TTS_DONE:
        if (s->tts_ratio_done[i])
            phase = "ratio-done";
        else
            phase = "seed";
        break;
    case NTX_TTS_META:
        if (tt->meta_need > 0)
            phase = "meta";
        else if (tt->peers_ok > 0)
            phase = "meta-wait";
        else if (tt->peers_hs > 0)
            phase = "hs";
        else if (tt->peers_all > 0)
            phase = "connect";
        else if (tt->trk_pend > 0)
            phase = "trk";
        else if (tt->trk_total > 0)
            phase = "trk-wait";
        else
            phase = "init";
        break;
    case NTX_TTS_VERIFY:
        phase = "verify";
        break;
    case NTX_TTS_DL:
    default:
        if (tt->total > 0 && tt->done >= tt->total)
            phase = "seed";
        else if (td > 0 || tt->partial > 0)
            phase = "dl";
        else if (tt->peers_unchoked > 0)
            phase = "wait";
        else if (tt->peers_ok > 0)
            phase = "choked";
        else if (tt->peers_all > 0)
            phase = "hs";
        else if (tt->trk_pend > 0 || tt->trk_total > 0)
            phase = "trk-wait";
        else
            phase = "stall";
        break;
    }
    snprintf(tt->phase, sizeof tt->phase, "%s", phase);
}

void ntx_session_stats_refresh(struct ntx_session *s, int rotate_ring) {
    ntx_stats *st = &s->s[s->s_idx];
    memset(st, 0, sizeof *st);

    if (rotate_ring) {
        for (int k = 4; k > 0; k--) {
            s->ring_d[k] = s->ring_d[k - 1];
            s->ring_u[k] = s->ring_u[k - 1];
        }
        s->ring_d[0] = s->cur_d;
        s->ring_u[0] = s->cur_u;
        s->cur_d = 0;
        s->cur_u = 0;
    }
    st->down_Bps = stats_smooth5(rotate_ring ? 0 : s->cur_d, s->ring_d);
    st->up_Bps = stats_smooth5(rotate_ring ? 0 : s->cur_u, s->ring_u);

    st->down_total = s->down_total;
    st->up_total = s->up_total;
    st->rx = s->down_total;
    st->tx = s->up_total;
    st->uptime_s = (ntx_mono_ms() - s->up_start) / 1000;
    st->port = ntx_netx_port(s->netx);
    st->dht = s->cfg->dht;
    st->dht_nodes4 = (uint16_t)ntx_dht_node_count(0);
    st->dht_nodes6 = (uint16_t)ntx_dht_node_count(1);
    st->enc = 1;
    st->hash_req_tx = s->hash_req_tx;
    st->hash_req_rx_ok = s->hash_req_rx_ok;
    st->hash_rej = s->hash_rej;
    /* BEP29/BEP55 uTP + shared-sock demux + holepunch */
    st->utp = (uint8_t)(s->cfg && s->cfg->utp ? 1 : 0);
    st->utp_conns = (uint16_t)ntx_netx_utp_conns(s->netx);
    st->utp_v6 = (uint8_t)ntx_netx_utp_v6(s->netx);
    ntx_netx_demux_stats(s->netx, &st->demux_dht, &st->demux_utp, &st->demux_drop);
    st->punch_ok = s->hp_dial_ok;
    st->punch_fail = s->hp_dial_fail;
    int total_peers = 0, conn_peers = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peers[pi].fd != -1) {
            total_peers++;
            if (s->peer_phase[pi] == PH_OK) conn_peers++;
        }
    }
    st->total_peers = total_peers;
    st->conn_peers = conn_peers;
    {
        int busy = 0;
        ntx_doh_status(st->doh, sizeof st->doh, &busy);
        st->doh_busy = busy ? 1 : 0;
        st->doh_ok = (uint16_t)(ntx_doh_ok > 65535u ? 65535u : ntx_doh_ok);
        st->doh_fail = (uint16_t)(ntx_doh_fail > 65535u ? 65535u : ntx_doh_fail);
        st->doh_mitm = (uint16_t)(ntx_doh_mitm_fail > 65535u ? 65535u : ntx_doh_mitm_fail);
    }
    st->n = 0;
    for (int i = 0; i < NTX_SESSION_MAX_TTS; i++) {
        ntx_torrent *t = &s->tts[i];
        if (t->state == NTX_TTS_DEAD) continue;

        uint32_t spd_d, spd_u;
        if (rotate_ring) {
            for (int k = 4; k > 0; k--) {
                s->tts_ring_d[i][k] = s->tts_ring_d[i][k - 1];
                s->tts_ring_u[i][k] = s->tts_ring_u[i][k - 1];
            }
            s->tts_ring_d[i][0] = s->tts_cur_d[i];
            s->tts_ring_u[i][0] = s->tts_cur_u[i];
            s->tts_cur_d[i] = 0;
            s->tts_cur_u[i] = 0;
            spd_d = stats_smooth5(0, s->tts_ring_d[i]);
            spd_u = stats_smooth5(0, s->tts_ring_u[i]);
        } else {
            spd_d = stats_smooth5(s->tts_cur_d[i], s->tts_ring_d[i]);
            spd_u = stats_smooth5(s->tts_cur_u[i], s->tts_ring_u[i]);
        }

        ntx_tts_stat *tt = &st->t[st->n];
        tt->slot = (uint8_t)i; /* JSON-API v1 §5.2/§11.3: control key travels in the object */
        snprintf(tt->name, sizeof tt->name, "%s", t->name);
        memcpy(tt->h, t->info_hash, 20);
        tt->meta_version = t->meta_version;
        tt->hybrid = t->hybrid;
        tt->layers_pending = (uint8_t)(ntx_torrent_layers_pending(t) ? 1 : 0);
        tt->size = t->size;
        tt->done = t->have_n;
        tt->total = t->np;
        tt->partial = 0;
        tt->verify_q = 0;
        if (s->piece_bytes[i]) {
            for (uint32_t j = 0; j < t->np; j++) {
                if (t->have[j]) continue;
                if (s->piece_bytes[i][j] > 0)
                    tt->partial++;
            }
        }
        tt->verify_q = (uint16_t)ntx_session_data_verify_pending(i, t->np);
        if (t->size > 0) {
            /* Progress = verified payload, not wire RX (duplicates/corrupt inflate tts_down). */
            uint64_t have_b = t->verified_B;
            tt->pct = (uint32_t)((have_b * 100) / t->size);
            if (tt->pct > 100) tt->pct = 100;
            if (t->have_n == t->np && t->np > 0) tt->pct = 100;
        } else {
            tt->pct = t->np ? (uint32_t)(100 * (uint64_t)t->have_n / t->np) : 0;
        }
        tt->spd_d = spd_d;
        tt->spd_u = spd_u;
        tt->eta_s = (spd_d > 0 && t->size > t->verified_B)
                        ? (uint32_t)((t->size - t->verified_B) / spd_d)
                        : 0;
        tt->down = t->verified_B;
        tt->up = s->tts_up[i];
        stats_fill_phase(s, i, tt, spd_d);
        st->n++;
    }
    s->s_idx ^= 1;
}
