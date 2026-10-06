#include "ntx_session_internal.h"

#include "../ui/ntx_diag.h"
#include "ntx_time.h"
#include <arpa/inet.h>
#include <stdio.h>
#include <sys/socket.h>

/* verbose logging (sp_verbose, sp_vlog_*) — split out of ntx_session_peer.c. */

int sp_verbose(const struct ntx_session *s) {
    return s && s->cfg && s->cfg->verbose;
}

void sp_addr_str(const ntx_addr *a, char *out, size_t cap) {
    if (!out || cap == 0) return;
    if (ntx_addr_ntop(a, out, cap) != 0)
        snprintf(out, cap, "?");
}

const char *sp_phase_name(int ph) {
    switch (ph) {
    case PH_PE: return "PE";
    case PH_BTHS: return "BTHS";
    case PH_OK: return "OK";
    default: return "?";
    }
}

/* Must match PE_ST_* in ntx_pe.c (not exported). */
const char *sp_pe_st_name(int st) {
    switch (st) {
    case 0: return "init";
    case 1: return "SEND_DH";
    case 2: return "RECV_DH";
    case 3: return "SEND_PE3";
    case 4: return "SEND_HS";
    case 5: return "RECV_VC";
    case 6: return "RECV_CRYPTO";
    case 7: return "RECV_PAD";
    case 8: return "RECV_SYNCHASH";
    case 9: return "RECV_SKEY";
    case 10: return "RECV_VC_R";
    case 11: return "RECV_CPROVIDE";
    case 12: return "RECV_PADLEN";
    case 13: return "RECV_PADIA";
    case 14: return "SEND_RHS";
    case 15: return "RECV_HS";
    case 16: return "DONE";
    default: return "unk";
    }
}

/* Download-path state for OK peers (verbose). life_ms = time since peer_ok (hs_t0 reused). */
void sp_vlog_dl(const struct ntx_session *s, int pi, const char *evt, const char *extra) {
    if (!sp_verbose(s) || pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    const ntx_peer *p = &s->peers[pi];
    uint64_t now = ntx_mono_ms();
    uint64_t life = p->hs_t0 && now >= p->hs_t0 ? now - p->hs_t0 : 0;
    ntx_diag("ntx: %s pi=%d choke_us=%d we_int=%d int_us=%d we_choke=%d bf_got=%d "
             "phave_none=%d phave=%u/%d life_ms=%llu%s%s\n",
             evt ? evt : "?", pi, p->choke_us, p->we_int, p->int_us, p->we_choke,
             (int)s->peer_bf_got[pi], p->phave_none, (unsigned)sp_phave_count(p), p->phave_n,
             (unsigned long long)life, (extra && extra[0]) ? " " : "", extra ? extra : "");
}

void sp_vlog_peer(const struct ntx_session *s, int pi, const char *evt, const char *extra) {
    if (!sp_verbose(s) || pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    char ip[48];
    sp_addr_str(&s->peers[pi].addr, ip, sizeof ip);
    uint64_t now = ntx_mono_ms();
    uint64_t age_c = s->peers[pi].conn_t0 && now >= s->peers[pi].conn_t0
                         ? now - s->peers[pi].conn_t0
                         : 0;
    uint64_t age_h = s->peers[pi].hs_t0 && now >= s->peers[pi].hs_t0 ? now - s->peers[pi].hs_t0 : 0;
    int pe_st = (s->peer_phase[pi] == PH_PE) ? s->pe[pi].state : -1;
    ntx_diag(
            "ntx: hs %s pi=%d %s:%u ph=%s pe=%s(%d) out=%d plain=%d bl=%zu age_c=%llums age_h=%llums%s%s\n",
            evt, pi, ip, (unsigned)s->peers[pi].port, sp_phase_name(s->peer_phase[pi]),
            pe_st >= 0 ? sp_pe_st_name(pe_st) : "-", pe_st, s->peer_outbound[pi] ? 1 : 0,
            s->peer_plain[pi] ? 1 : 0, s->peer_buflen[pi], (unsigned long long)age_c,
            (unsigned long long)age_h, extra && extra[0] ? " " : "", extra ? extra : "");
}
