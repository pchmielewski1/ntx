#include "ntx_session_internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include "ntx_time.h"

/* PE (MSE) session glue (sp_pe_*, sp_setup_phave, ...) — split out of ntx_session_peer.c. */

void sp_pe_set_infohash(struct ntx_session *s, int pi) {
    ntx_pe *pe = &s->pe[pi];
    int ti = s->peer_tts[pi];
    if (ti >= 0 && ti < s->n_tts) {
        ntx_pe_set_infohash(pe, s->tts[ti].info_hash);
        return;
    }
    pe->infohash_cand_n = 0;
    int nactive = 0;
    for (int i = 0; i < s->n_tts; i++) {
        if (s->tts[i].state == NTX_TTS_DEAD) continue;
        if (nactive == 0)
            ntx_pe_set_infohash(pe, s->tts[i].info_hash);
        else if (pe->infohash_cand_n < NTX_PE_INFOHASH_CAND)
            memcpy(pe->infohash_cand[pe->infohash_cand_n++], s->tts[i].info_hash, 20);
        nactive++;
    }
    if (nactive == 0) memset(pe->infohash, 0, 20);
}

void sp_note_peer_fast(struct ntx_session *s, int pi, const uint8_t hs[68]) {
    if (hs[27] & 0x04) s->peer_fast[pi] = 1;
}

int sp_setup_phave(struct ntx_session *s, int pi, int ti) {
    ntx_torrent *t = &s->tts[ti];
    if ((int)t->np > s->peers[pi].phave_n) {
        free(s->peers[pi].phave);
        s->peers[pi].phave = calloc(t->np, 1);
        s->peers[pi].phave_n = (int)t->np;
        s->peers[pi].phave_none = 1;
    }
    return 0;
}

void sp_pe_drive(struct ntx_session *s, int pi) {
    for (int k = 0; k < 64 && s->peer_phase[pi] == PH_PE && !ntx_pe_done(&s->pe[pi]); k++) {
        int st = s->pe[pi].state;
        ntx_session_peer_step(s, pi);
        if (s->peers[pi].fd == -1) return;
        if (s->pe[pi].state != st) {
            s->peers[pi].hs_t0 = ntx_mono_ms();
            if (sp_verbose(s)) {
                char x[64];
                snprintf(x, sizeof x, "%s->%s", sp_pe_st_name(st), sp_pe_st_name(s->pe[pi].state));
                sp_vlog_peer(s, pi, "pe_st", x);
            }
        }
        if (ntx_pe_done(&s->pe[pi])) break;
        if (s->pe[pi].state == st) break;
    }
}

void sp_plaintext_fallback(struct ntx_session *s, int pi) {
    if (!s->cfg || !s->cfg->compat_peers) {
        sp_drop(s, pi, "plaintext_strict");
        return;
    }
    ntx_pe *pe = &s->pe[pi];
    s->peer_plain[pi] = 1;
    s->peer_phase[pi] = PH_BTHS;
    s->peers[pi].st = NTX_PEER_ST_HS;
    s->peers[pi].hs_t0 = ntx_mono_ms();
    size_t n = pe->inn;
    if (n > (size_t)NTX_PEER_BUF) n = NTX_PEER_BUF;
    if (n) {
        memcpy(s->peer_buf[pi], pe->in, n);
        s->peer_buflen[pi] = n;
    }
    pe->inn = 0;
    sp_vlog_peer(s, pi, "plaintext", "compat fallback");
    ntx_session_peer_send_handshake(s, pi);
}

void sp_pe_finish(struct ntx_session *s, int pi) {
    if (s->peer_phase[pi] != PH_PE || !ntx_pe_done(&s->pe[pi])) return;
    if (!s->pe[pi].bt_hs_got) {
        sp_drop(s, pi, "pe_no_hs");
        return;
    }
    if (s->pe[pi].role == NTX_PE_INITIATOR) s->pe_out_ok++;
    {
        char x[80];
        snprintf(x, sizeof x, "role=%d got=%d sent=%d", s->pe[pi].role, s->pe[pi].bt_hs_got,
                 s->pe[pi].bt_hs_sent);
        sp_vlog_peer(s, pi, "pe_ok", x);
    }
    if (sp_promote_peer_ok(s, pi, s->pe[pi].bt_hs)) {
        if (!s->peer_hello_sent[pi]) sp_peer_ok_hello(s, pi);
        sp_peer_arm_io(s, pi);
        return;
    }
    s->peer_phase[pi] = PH_BTHS;
    s->peers[pi].st = NTX_PEER_ST_HS;
    s->peers[pi].hs_t0 = ntx_mono_ms();
    s->peer_buflen[pi] = ntx_pe_drain_to_peer(&s->pe[pi], s->peer_buf[pi], NTX_PEER_BUF);
    {
        char x[64];
        snprintf(x, sizeof x, "bl=%zu b0=%u", s->peer_buflen[pi],
                 s->peer_buflen[pi] ? s->peer_buf[pi][0] : 0);
        sp_vlog_peer(s, pi, "pe_to_bths", x);
    }
    sp_peer_arm_io(s, pi);
    if (!ntx_pe_handshake_sent(&s->pe[pi]))
        ntx_session_peer_send_handshake(s, pi);
}
