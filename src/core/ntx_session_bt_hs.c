#include "ntx_session_internal.h"

#include <stdio.h>
#include <string.h>
#include "ntx_time.h"

/* BitTorrent handshake (sp_build_bt_handshake, sp_bths_*, sp_peer_ok_*, ...)
   — split out of ntx_session_peer.c. */

int sp_match_tts(struct ntx_session *s, const uint8_t hash[20]) {
    for (int i = 0; i < s->n_tts; i++) {
        if (s->tts[i].state != NTX_TTS_DEAD && memcmp(s->tts[i].info_hash, hash, 20) == 0)
            return i;
    }
    /* BEP52 mid-connection upgrade RX: a hybrid swarm
     * joined by SHA-1 may answer our HS with the truncated SHA-256(info) hash.
     * Accept it only when the exact v1 match above already failed and the
     * candidate torrent is v2/hybrid with a non-zero v2 root. v1-only torrents
     * carry info_hash_v2 == 0 so this path cannot match them; a v2 answer for a
     * pure-v2 torrent still equals its exact info_hash (first loop). */
    for (int i = 0; i < s->n_tts; i++) {
        if (s->tts[i].state == NTX_TTS_DEAD || s->tts[i].meta_version != 2) continue;
        int any_v2 = 0;
        for (int k = 0; k < 32; k++)
            if (s->tts[i].info_hash_v2[k]) { any_v2 = 1; break; }
        if (any_v2 && memcmp(s->tts[i].info_hash_v2, hash, 20) == 0) return i;
    }
    return -1;
}

int sp_promote_peer_ok(struct ntx_session *s, int pi, const uint8_t hs[68]) {
    if (hs[0] != 19 || memcmp(hs + 1, "BitTorrent protocol", 19) != 0) return 0;
    int ti = sp_match_tts(s, hs + 28);
    if (ti < 0) return 0;
    s->peer_tts[pi] = ti;
    ntx_pe_set_infohash(&s->pe[pi], s->tts[ti].info_hash);
    sp_note_peer_fast(s, pi, hs);
    sp_setup_phave(s, pi, ti);
    size_t n = ntx_pe_drain_to_peer(&s->pe[pi], s->peer_buf[pi], NTX_PEER_BUF);
    if (n >= 68 && s->peer_buf[pi][0] == 19 &&
        memcmp(s->peer_buf[pi] + 1, "BitTorrent protocol", 19) == 0) {
        n -= 68;
        if (n) memmove(s->peer_buf[pi], s->peer_buf[pi] + 68, n);
    }
    s->peer_buflen[pi] = n;
    s->peer_phase[pi] = PH_OK;
    if (s->peers[pi].fd <= -NTX_UTP_VIRT_BASE) s->utp_ok_n++;
    memcpy(s->peers[pi].id, hs + 48, 20); /* BEP55 race tie-break key */
    s->peers[pi].id_set = 1;
    if (ti >= 0 && ti < s->n_tts)
        ntx_pex_tx_on_connected(&s->pex_tx[ti], &s->peers[pi].addr, s->peers[pi].port);
    s->peers[pi].st = NTX_PEER_ST_OK;
    s->peers[pi].hs_t0 = ntx_mono_ms(); /* ok_t0: age_h / life_ms while PH_OK */
    {
        char x[48];
        snprintf(x, sizeof x, "via=pe_promote ti=%d", ti);
        sp_vlog_peer(s, pi, "peer_ok", x);
        sp_vlog_dl(s, pi, "ok_state", "evt=promote");
    }
    ntx_session_holepunch_resolve_race(s, pi); /* BEP55: collapse a dual-dial to one conn */
    return 1;
}

void sp_bths_resync(uint8_t *buf, size_t *bl) {
    while (*bl >= 68) {
        if (buf[0] == 19 && memcmp(buf + 1, "BitTorrent protocol", 19) == 0) return;
        int all_ff = 1;
        for (int i = 0; i < 68; i++) {
            if (buf[i] != (uint8_t)0xff) {
                all_ff = 0;
                break;
            }
        }
        if (all_ff) {
            memmove(buf, buf + 68, *bl - 68);
            *bl -= 68;
            continue;
        }
        size_t off = 1;
        for (; off + 20 <= *bl; off++) {
            if (buf[off] == 19 && memcmp(buf + off + 1, "BitTorrent protocol", 19) == 0) break;
        }
        if (off + 20 <= *bl) {
            memmove(buf, buf + off, *bl - off);
            *bl -= off;
            return;
        }
        break;
    }
}

void sp_build_bt_handshake(struct ntx_session *s, int pi, uint8_t m[68]) {
    int ti = s->peer_tts[pi];
    if (ti < 0) {
        for (int i = 0; i < s->n_tts; i++) {
            if (s->tts[i].state != NTX_TTS_DEAD) {
                ti = i;
                break;
            }
        }
    }
    if (ti < 0 || ti >= s->n_tts) {
        memset(m, 0, 68);
        return;
    }
    m[0] = 19;
    memcpy(m + 1, "BitTorrent protocol", 19);
    memset(m + 20, 0, 8);
    m[25] = 0x10;
    m[27] = 0x04;
    if (s->cfg && s->cfg->dht) m[27] |= 0x01;
    /* BEP52: signal v2 support with the 4th most
     * significant bit (0x10) of the LAST reserved byte (m[27]). The gate is
     * `hybrid || supports_v2`; `supports_v2` is the per-torrent fact that the
     * metainfo carries a v2 root (meta_version == 2, which always implies a
     * non-zero info_hash_v2). `hybrid` is folded in to mirror the spec wording
     * and stay correct if the two flags ever decouple. v1-only torrents
     * (meta_version == 0, info_hash_v2 zero) set neither, so the bit stays
     * clear. Deviation: TX-side mid-connection upgrade (answering a v1 HS
     * with the truncated SHA-256 hash) is a BEP52 MAY and NOT implemented — RX
     * tolerance lives in sp_match_tts; see docs/protocol.md "BEP 52 reserved bit and hash selection". */
    if (s->tts[ti].hybrid || s->tts[ti].meta_version == 2) m[27] |= 0x10;
    memcpy(m + 28, s->tts[ti].info_hash, 20);
    memcpy(m + 48, s->peer_id, 20);
}

void sp_peer_ok_hello(struct ntx_session *s, int pi) {
    if (s->peer_hello_sent[pi] || s->peer_phase[pi] != PH_OK) return;
    s->peer_hello_sent[pi] = 1;
    ntx_torrent *t = &s->tts[s->peer_tts[pi]];
    int ti = s->peer_tts[pi];
    int seeding = (t->state == NTX_TTS_DONE) || (ti >= 0 && ti < s->n_tts && s->tts_ratio_done[ti]);
    ntx_session_peer_send_ext_handshake(s, pi);
    sp_send_our_availability(s, pi);
    if (seeding) {
        ntx_peer_set_we_int(&s->peers[pi], 0);
        ntx_session_peer_send_interest(s, pi, 0);
        if (ti >= 0 && ti < s->n_tts && s->tts_ratio_done[ti]) {
            ntx_peer_set_we_choke(&s->peers[pi], 1);
            ntx_session_peer_send_choke(s, pi, 1);
        } else {
            ntx_peer_set_we_choke(&s->peers[pi], 0);
            ntx_session_peer_send_choke(s, pi, 0);
        }
    } else {
        ntx_peer_set_we_int(&s->peers[pi], 1);
        ntx_session_peer_send_interest(s, pi, 1);
        ntx_peer_set_we_choke(&s->peers[pi], 0);
        ntx_session_peer_send_choke(s, pi, 0);
    }
    ntx_session_peer_out_flush(s, pi);
    if (sp_verbose(s))
        sp_vlog_dl(s, pi, "ok_hello", seeding ? "role=seed" : "role=leech");
    if (s->peer_meta_size[pi] > 0)
        ntx_session_data_meta_pump_peer(s, pi);
    ntx_session_peer_out_flush(s, pi);
}

void sp_peer_ok_poll(struct ntx_session *s, int pi) {
    if (s->peer_phase[pi] != PH_OK) return;
    int fd = s->peers[pi].fd;
    if (fd == -1) return; /* no peer; a live uTP virt fd is negative by design */
    ntx_session_peer_out_flush(s, pi);
    sp_process_msgs(s, pi);
    if (s->peers[pi].fd != fd) return;
    uint8_t *buf = s->peer_buf[pi];
    size_t *bl = &s->peer_buflen[pi];
    if (*bl >= (size_t)NTX_PEER_BUF) return;
    ssize_t r = ntx_netx_read(s->netx, fd, buf + *bl, (size_t)NTX_PEER_BUF - *bl);
    if (r > 0) {
        s->peers[pi].rx_t0 = ntx_mono_ms(); /* idle detection: this path reads too */
        if (!s->peer_plain[pi]) ntx_pe_decrypt(&s->pe[pi], buf + *bl, (size_t)r);
        *bl += (size_t)r;
        sp_process_msgs(s, pi);
    } else if (r == 0) {
        sp_drop(s, pi, "eof");
    }
}

int sp_bths_try(struct ntx_session *s, int pi) {
    if (s->peer_phase[pi] != PH_BTHS) return 0;
    uint8_t *buf = s->peer_buf[pi];
    size_t *bl = &s->peer_buflen[pi];
    sp_bths_resync(buf, bl);
    if (*bl < 68) return 0;
    if (buf[0] != 19 || memcmp(buf + 1, "BitTorrent protocol", 19) != 0) {
        {
            char x[48];
            snprintf(x, sizeof x, "bl=%zu", *bl);
            sp_vlog_peer(s, pi, "bths_bad_magic", x);
        }
        sp_drop(s, pi, "bths_bad_magic");
        return 1;
    }
    int ti = sp_match_tts(s, buf + 28);
    if (ti < 0) {
        sp_vlog_peer(s, pi, "bths_bad_hash", "");
        sp_drop(s, pi, "bths_bad_hash");
        return 1;
    }
    s->peer_tts[pi] = ti;
    sp_note_peer_fast(s, pi, buf);
    sp_setup_phave(s, pi, ti);
    memmove(buf, buf + 68, *bl - 68);
    *bl -= 68;
    s->peer_phase[pi] = PH_OK;
    if (s->peers[pi].fd <= -NTX_UTP_VIRT_BASE) s->utp_ok_n++;
    s->peers[pi].st = NTX_PEER_ST_OK;
    s->peers[pi].hs_t0 = ntx_mono_ms(); /* ok_t0 */
    {
        char x[48];
        snprintf(x, sizeof x, "via=bths ti=%d", ti);
        sp_vlog_peer(s, pi, "peer_ok", x);
        sp_vlog_dl(s, pi, "ok_state", "evt=promote");
    }
    sp_peer_arm_io(s, pi);
    return 1;
}
