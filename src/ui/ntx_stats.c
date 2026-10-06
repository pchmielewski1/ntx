#include "ntx_stats.h"
#include "ntx_ipc.h"

#include <stdio.h>
#include <string.h>

/* JSON Control API v1 emitter (§4, §5, §10, §11).
   Framing: header is rendered last into a small stack scratch and memmove'd
   in front of the body — n is only known after the loop, so the header can
   only carry the honest emitted count (§11.2). Body is bounded to one object
   per 1024 B budget; a non-fitting object stops the loop (never a torn
   object), the line gains "truncated":1 (§5.4). Key order equals this file's
   order (§4); no spaces after ':' or ',' (§10 regression gate). */
#define IPC_HDR_RES 768 /* worst-case header reserve (measured 575 + tail margin) */
#define IPC_TAIL_RES 16 /* "],\"truncated\":1}" = 17 incl. NUL — see tail path */

int ntx_stats_to_json(const ntx_stats *st, char *out, size_t cap) {
    static const char *const MIN_LINE =
        "{\"type\":\"stats\",\"v\":1,\"n\":0,\"torrents\":[],\"truncated\":1}";
    if (!out || cap < 64) return 0;
    size_t bcap = cap > IPC_HDR_RES + IPC_TAIL_RES + 1024
                      ? cap - IPC_HDR_RES - IPC_TAIL_RES
                      : cap / 2; /* degenerate cap: best effort, honesty first */
    size_t pos = 0;
    int emitted = 0, truncated = 0;
    char esc_name[48 * 6 + 1], esc_phase[12 * 6 + 1], esc_doh[8 * 6 + 1], ih[41];
    if (ntx_json_escape(esc_doh, sizeof esc_doh, st->doh[0] ? st->doh : "") < 0)
        esc_doh[0] = 0;

    for (int i = 0; i < st->n && i < 16; i++) {
        const ntx_tts_stat *t = &st->t[i];
        if (ntx_json_escape(esc_name, sizeof esc_name, t->name) < 0) esc_name[0] = 0;
        if (ntx_json_escape(esc_phase, sizeof esc_phase, t->phase) < 0) esc_phase[0] = 0;
        ntx_hex40(ih, t->h);
        int w = snprintf(out + pos, bcap - pos,
                         "%s{\"i\":%u,\"ih\":\"%s\",\"name\":\"%s\",\"state\":%u,\"phase\":\"%s\",\"pct\":%u,\"spd_d\":%u,\"spd_u\":%u,"
                         "\"eta_s\":%u,\"done\":%u,\"total\":%u,\"partial\":%u,\"peers\":%u,"
                         "\"trk_total\":%u,\"trk_pend\":%u,\"trk_udp_ok\":%u,\"trk_dead\":%u,"
                         "\"peers_all\":%u,\"peers_hs\":%u,\"peers_ok\":%u,\"peers_unchoked\":%u,"
                         "\"peers_interested\":%u,"
                         "\"meta_got\":%u,\"meta_need\":%u,\"verify_q\":%u,"
                         "\"meta_version\":%u,\"hybrid\":%u,\"layers_pending\":%u,"
                         "\"size\":%llu,\"down\":%llu,\"up\":%llu}",
                         emitted ? "," : "",
                         (unsigned)t->slot, ih, esc_name, (unsigned)t->state, esc_phase, t->pct, t->spd_d, t->spd_u, t->eta_s,
                         t->done, t->total, t->partial, t->peers,
                         (unsigned)t->trk_total, (unsigned)t->trk_pend, (unsigned)t->trk_udp_ok,
                         (unsigned)t->trk_dead,
                         (unsigned)t->peers_all, (unsigned)t->peers_hs, (unsigned)t->peers_ok,
                         (unsigned)t->peers_unchoked, (unsigned)t->peers_interested, (unsigned)t->meta_got,
                         (unsigned)t->meta_need, (unsigned)t->verify_q,
                         (unsigned)t->meta_version, (unsigned)t->hybrid, (unsigned)t->layers_pending,
                         (unsigned long long)t->size,
                         (unsigned long long)t->down, (unsigned long long)t->up);
        if (w < 0 || (size_t)w >= bcap - pos) { truncated = 1; break; } /* §5.4 */
        pos += (size_t)w;
        emitted++;
    }
    if (emitted < (st->n < 16 ? st->n : 16)) truncated = 1;

    char hdr[IPC_HDR_RES + 1];
    int hn = snprintf(hdr, sizeof hdr,
                      "{\"type\":\"stats\",\"v\":1,\"down_Bps\":%u,\"up_Bps\":%u,\"total_peers\":%u,\"conn_peers\":%u,"
                      "\"down_total\":%llu,\"up_total\":%llu,\"uptime_s\":%llu,\"port\":%u,"
                      "\"dht\":%d,\"enc\":%d,\"doh\":\"%s\",\"doh_busy\":%u,\"doh_ok\":%u,\"doh_fail\":%u,"
                      "\"doh_mitm\":%u,\"hash_req_tx\":%u,\"hash_req_rx_ok\":%u,\"hash_rej\":%u,"
                      "\"utp\":%u,\"utp_conns\":%u,\"utp_v6\":%u,"
                      "\"demux_dht\":%llu,\"demux_utp\":%llu,\"demux_drop\":%llu,"
                      "\"punch_ok\":%u,\"punch_fail\":%u,"
                      "\"n\":%d,\"torrents\":[",
                      st->down_Bps, st->up_Bps, st->total_peers, st->conn_peers,
                      (unsigned long long)st->down_total, (unsigned long long)st->up_total,
                      (unsigned long long)st->uptime_s, (unsigned)st->port, st->dht, st->enc,
                      esc_doh, (unsigned)st->doh_busy, (unsigned)st->doh_ok,
                      (unsigned)st->doh_fail, (unsigned)st->doh_mitm,
                      st->hash_req_tx, st->hash_req_rx_ok, st->hash_rej,
                      (unsigned)st->utp, (unsigned)st->utp_conns, (unsigned)st->utp_v6,
                      (unsigned long long)st->demux_dht, (unsigned long long)st->demux_utp,
                      (unsigned long long)st->demux_drop,
                      st->punch_ok, st->punch_fail, emitted);
    const char *tail = truncated ? "],\"truncated\":1}" : "]}";
    size_t tl = strlen(tail);
    if (hn < 0 || (size_t)hn > IPC_HDR_RES || (size_t)hn + pos + tl + 1 > cap) {
        int mw = snprintf(out, cap, "%s", MIN_LINE); /* §11.2: never a lying line */
        return mw < 0 ? 0 : mw;
    }
    memmove(out + hn, out, pos);
    memcpy(out, hdr, (size_t)hn);
    memcpy(out + hn + pos, tail, tl);
    out[hn + pos + tl] = 0;
    return (int)(hn + pos + tl);
}
