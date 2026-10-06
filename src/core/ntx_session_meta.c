#include "ntx_session_internal.h"
#include "../proto/ntx_utmeta.h"
#include "../proto/ntx_bencode.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_sha256.h"
#include "../ui/ntx_diag.h"

#include <stdlib.h>
#include <string.h>
#include "ntx_time.h"

/* ut_metadata session glue — meta_* / ntx_session_data_meta_* split out of ntx_session_data.c. */

uint8_t *meta_buf[NTX_SESSION_MAX_TTS];
uint8_t *meta_have[NTX_SESSION_MAX_TTS];
size_t meta_len[NTX_SESSION_MAX_TTS];
uint32_t meta_total[NTX_SESSION_MAX_TTS];
uint32_t meta_have_n[NTX_SESSION_MAX_TTS];
uint64_t meta_t0[NTX_SESSION_MAX_TTS];
uint64_t dl_t0[NTX_SESSION_MAX_TTS];

void meta_reset(int i) {
    free(meta_buf[i]);
    free(meta_have[i]);
    meta_buf[i] = NULL;
    meta_have[i] = NULL;
    meta_len[i] = 0;
    meta_total[i] = 0;
    meta_have_n[i] = 0;
}

void meta_reject(struct ntx_session *s, int pi, uint32_t piece) {
    if (!s->peer_meta_id[pi]) return;
    uint8_t payload[64];
    size_t pn = 0;
    if (ntx_ut_metadata_reject_build(payload, &pn, piece) != 0) return;
    uint8_t msg[128];
    size_t mn = ntx_ext_msg_build(msg, sizeof(msg), s->peer_meta_id[pi], payload, pn);
    if (mn) ntx_session_peer_send_raw(s, pi, msg, mn);
}

void meta_retry_all(struct ntx_session *s, int i) {
    meta_reset(i);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_tts[pi] != i) continue;
        s->peer_meta_inflight[pi] = UINT32_MAX;
        s->peer_meta_req[pi] = 0;
        if (s->peer_phase[pi] == PH_OK)
            ntx_session_data_meta_pump_peer(s, pi);
    }
}

static int any32(const uint8_t *p) {
    for (int i = 0; i < 32; i++) if (p[i]) return 1;
    return 0;
}

/* BEP52: gate an assembled info-dict buffer against the torrent's
 * infohash. v2/hybrid (meta_version==2 with a non-zero sha256) verifies
 * SHA-256 against info_hash_v2; otherwise the v1 SHA-1 path. Returns 0 on
 * match, -1 on mismatch. */
static int meta_hash_gate(const ntx_torrent *t, const uint8_t *buf, size_t n) {
    if (t->meta_version == 2 && any32(t->info_hash_v2)) {
        uint8_t h[32];
        ntx_sha256(buf, n, h);
        return memcmp(h, t->info_hash_v2, 32) == 0 ? 0 : -1;
    }
    uint8_t h[20];
    ntx_sha1(buf, n, h);
    return memcmp(h, t->info_hash, 20) == 0 ? 0 : -1;
}

void meta_assemble(struct ntx_session *s, int i) {
    ntx_torrent *t = &s->tts[i];
    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(meta_buf[i], meta_total[i], &be, &consumed, 32, (size_t)NTX_UT_METADATA_MAX) != 0 || be.t != NTX_BE_DICT) {
        ntx_be_free(&be);
        meta_retry_all(s, i);
        return;
    }
    ntx_be_free(&be);
    if (meta_hash_gate(t, meta_buf[i], meta_total[i]) != 0) {
        ntx_diag( "ntx: meta hash mismatch ti=%d bytes=%u\n", i, meta_total[i]);
        meta_retry_all(s, i);
        return;
    }
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: meta assemble ti=%d bytes=%u\n", i, meta_total[i]);
    if (ntx_torrent_set_metainfo(t, meta_buf[i], meta_total[i],
                                  s->cfg && s->cfg->store_dir ? s->cfg->store_dir : "downloads",
                                  NULL) == 0) {
        dl_t0[i] = ntx_mono_ms();
        ntx_session_on_metainfo(s, i);
    }
    meta_reset(i);
    meta_t0[i] = 0;
}

int ext_is_metadata(struct ntx_session *s, int pi, int ext_id) {
    (void)s;
    (void)pi;
    /* Peer sends to us using our advertised ut_metadata ID. */
    return ext_id == (int)NTX_EXT_LOCAL_METADATA;
}

void ntx_session_data_meta_pump_peer(struct ntx_session *s, int pi) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    if (s->peer_phase[pi] != PH_OK) return;
    int i = s->peer_tts[pi];
    if (i < 0 || i >= s->n_tts) return;
    ntx_torrent *t = &s->tts[i];
    if (t->state != NTX_TTS_META) return;
    if (!s->peer_hello_sent[pi] || !s->peer_meta_id[pi] || s->peer_meta_size[pi] == 0) return;
    if (s->peer_meta_req[pi] >= NTX_META_INFLIGHT) return;
    uint32_t npieces = ntx_ut_metadata_npieces(s->peer_meta_size[pi]);
    uint32_t want = UINT32_MAX;
    for (uint32_t k = 0; k < npieces; k++) {
        if (meta_have[i] && meta_have[i][k]) continue;
        if (s->peer_meta_inflight[pi] == k) continue;
        want = k;
        break;
    }
    if (want == UINT32_MAX) return;
    uint8_t payload[64];
    size_t pn = 0;
    if (ntx_ut_metadata_request_build(payload, &pn, want) != 0) return;
    uint8_t msg[128];
    size_t mn = ntx_ext_msg_build(msg, sizeof(msg), s->peer_meta_id[pi], payload, pn);
    if (!mn) return;
    ntx_session_peer_send_raw(s, pi, msg, mn);
    s->peer_meta_req[pi]++;
    s->peer_meta_inflight[pi] = want;
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: meta req pi=%d piece=%u send_id=%u rx_id=%u size=%u\n", pi, want,
                (unsigned)s->peer_meta_id[pi], (unsigned)NTX_EXT_LOCAL_METADATA, s->peer_meta_size[pi]);
}

void ntx_session_data_meta_progress(int tts_idx, uint16_t *got, uint16_t *need) {
    if (got) *got = 0;
    if (need) *need = 0;
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) return;
    if (meta_total[tts_idx] == 0) return;
    uint32_t np = ntx_ut_metadata_npieces(meta_total[tts_idx]);
    if (need) *need = (uint16_t)(np > 65535 ? 65535 : np);
    if (got) *got = (uint16_t)(meta_have_n[tts_idx] > 65535 ? 65535 : meta_have_n[tts_idx]);
}

int ntx_session_data_send_metainfo(struct ntx_session *s, int pi, uint32_t piece) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return -1;
    int i = s->peer_tts[pi];
    if (i < 0 || i >= s->n_tts) return -1;
    ntx_torrent *t = &s->tts[i];
    /* Serving is gated on holding the info dict, not on still being in the
     * metadata-fetch state: a seeder that loaded a .torrent, or that completed
     * a magnet, has the whole info dict and MUST be able to answer BEP9
     * requests, otherwise magnet-only peers can never obtain the metadata. */
    if (!t->have_meta) return -1;
    if (!t->info_raw || t->info_raw_n == 0) return -1;
    uint32_t npieces = ntx_ut_metadata_npieces(t->info_raw_n);
    if (piece >= npieces) return -1;
    uint32_t off = piece * NTX_UT_META_PIECE;
    uint32_t dlen = (uint32_t)(t->info_raw_n - off);
    if (dlen > NTX_UT_META_PIECE) dlen = NTX_UT_META_PIECE;
    uint8_t payload[16512];
    size_t pn = 0;
    if (ntx_ut_metadata_data_build(payload, &pn, piece, t->info_raw_n, t->info_raw + off, dlen) != 0)
        return -1;
    uint8_t msg[16640];
    if (!s->peer_meta_id[pi]) return -1;
    size_t mn = ntx_ext_msg_build(msg, sizeof(msg), s->peer_meta_id[pi], payload, pn);
    if (!mn) return -1;
    ntx_session_peer_send_raw(s, pi, msg, mn);
    return 0;
}
