#include <stdint.h>

#include "ntx_session_internal.h"

/* BEP 27 dial/ext policy (design §4).
 *
 * ti == -1 means the peer is not bound to a torrent slot yet (the dial decision
 * and the ext-handshake dispatch both run before sp_match_tts picks a slot).
 * With no slot there is no `private` flag to consult, so the answer is
 * permissive — the same answer a slot whose metainfo is still missing gives.
 * Inbound accepts never come through sp_dial_allowed: BEP 27 restricts
 * initiation only. */

/* Any non-zero integer in `private` means private; BEP 27 defines only 1, so a
 * dubious value errs towards the DHT. A missing key or a non-integer is public.
 * One answer for both paths that learn an info dict: the ut_metadata assembly
 * (ntx_session_meta.c) and the .torrent loader (ntx_session.c). */
int priv_info_is_private(const ntx_be *info) {
    const ntx_be *pv = ntx_be_dict_get(info, "private");
    return (pv && pv->t == NTX_BE_INT && pv->i != 0) ? 1 : 0;
}

static const ntx_torrent *priv_t(const struct ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= s->n_tts || ti >= NTX_SESSION_MAX_TTS) return NULL;
    if (s->tts[ti].state == NTX_TTS_DEAD) return NULL;
    return &s->tts[ti];
}

/* §4.1: never a get_peers/announce_peer for a private hash, not even with --dht. */
int sp_dht_allowed(const struct ntx_session *s, int ti) {
    const ntx_torrent *t = priv_t(s, ti);
    return (s && s->cfg && s->cfg->dht && !(t && t->priv)) ? 1 : 0;
}

/* §4.2/§4.3: ut_pex and ut_holepunch are neither offered nor honoured on a
 * private slot; every other extension (ut_metadata above all) stays available. */
int sp_ext_allowed(const struct ntx_session *s, int ti, int ext_local_id) {
    if (ext_local_id != (int)NTX_EXT_LOCAL_PEX && ext_local_id != (int)NTX_EXT_LOCAL_HOLEPUNCH)
        return 1;
    const ntx_torrent *t = priv_t(s, ti);
    return (t && t->priv) ? 0 : 1;
}

/* §4.4: outbound connections go only to addresses the trackers gave us. */
int sp_dial_allowed(const struct ntx_session *s, int ti, uint8_t src) {
    const ntx_torrent *t = priv_t(s, ti);
    if (t && t->priv) return src == NTX_PSRC_TRACKER ? 1 : 0;
    return 1;
}
