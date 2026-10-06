#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/epoll.h>

#include "ntx_session_internal.h"
#include "../net/ntx_addr.h"
#include "../ui/ntx_diag.h"
#include "../proto/ntx_magnet.h"
#include "../proto/ntx_bencode.h"
#include "../proto/ntx_tracker.h"
#include "ntx_time.h"
#include "../proto/ntx_dht.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_rng.h"

static struct ntx_session *sess_g_s;
static char dht_state_path[512];

static void tick_wrapper(void *arg) {
    ntx_session *s = (ntx_session *)arg;
    ntx_session_tick(s);
    ntx_netx_timer(s->netx, 100, tick_wrapper, s);
}

static void accept_wrapper(ntx_netx *n, int peer_fd, void *ctx) {
    ntx_session_accept_cb((ntx_session *)ctx, n, peer_fd, ctx);
}

static void sess_peer_rw_cb(int fd, void *ctx) {
    ntx_session_peer_on_rw(sess_g_s, fd, ctx);
}


static void peer_close_cb(void *ctx) {
    ntx_session_peer_on_close(sess_g_s, ctx);
}

ntx_session *ntx_session_init(ntx_netx *netx, const ntx_config *cfg) {
    if (!netx) return NULL;
    ntx_session *s = calloc(1, sizeof *s);
    if (!s) return NULL;
    s->netx = netx;
    s->cfg = cfg;
    sess_g_s = s;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        s->peers[pi].fd = -1;
        s->peer_tts[pi] = -1;
    }
    for (int i = 0; i < NTX_SESSION_MAX_TTS; i++)
        s->tts[i].state = NTX_TTS_DEAD;
    for (int i = 0; i < NTX_SESSION_MAX_TTS; i++)
        ntx_pex_tx_init(&s->pex_tx[i]);
    memset(s->peer_id, 0, sizeof s->peer_id);
    memcpy(s->peer_id, "-NT0100-", 8);
    ntx_rand_bytes(s->peer_id + 8, 12);
    s->trk_key = ntx_rand_u32();
    if (s->trk_key == 0) s->trk_key = 1;
    s->up_start = ntx_mono_ms();
    ntx_session_trk_init(s);
    ntx_netx_timer(netx, 100, tick_wrapper, s);
    ntx_netx_set_accept(netx, accept_wrapper, s);
    if (cfg && cfg->dht) {
        const char *dir = (cfg->store_dir && cfg->store_dir[0]) ? cfg->store_dir : "downloads";
        int n = snprintf(dht_state_path, sizeof dht_state_path, "%s/ntx_dht_state", dir);
        if (n > 0 && n < (int)sizeof dht_state_path) ntx_dht_set_state_path(dht_state_path);
        ntx_dht_start(netx);
    }
    return s;
}

void ntx_session_free(ntx_session *s) {
    if (!s) return;
    /* The self-rearming tick is the session's own netx registration: cancel it
     * before anything else so a later run_once can never fire tick_wrapper
     * into the freed session (mirrors the peer-slot teardown below). */
    if (s->netx) ntx_netx_timer_cancel(s->netx, tick_wrapper, s);
    if (s->cfg && s->cfg->dht) ntx_dht_stop();
    ntx_session_trk_free(s);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        int fd = s->peers[pi].fd;
        if (fd != -1) {
            /* Symmetric with session_remove/peer_free: release the netx slot for
             * every live peer. For a uTP virt fd this tears the glue slot down
             * (FIN best-effort + disarm cbs/ctx) so a demux tick that runs after
             * the session is freed can never call back into freed memory. */
            ntx_netx_del(s->netx, fd);
            if (fd >= 0) close(fd);
        }
        free(s->peer_buf[pi]);
        free(s->peer_out[pi]);
    }
    for (int i = 0; i < NTX_SESSION_MAX_TTS; i++) {
        if (s->tts[i].state != NTX_TTS_DEAD) ntx_store_close(&s->tts[i].store);
        free(s->piece_bytes[i]);
        free(s->hash_scratch[i]);
        s->hash_scratch[i] = NULL;
        if (s->piece_blk_map[i]) {
            ntx_torrent *t = &s->tts[i];
            if (t->np > 0) {
                for (uint32_t j = 0; j < t->np; j++)
                    free(s->piece_blk_map[i][j]);
            }
            free(s->piece_blk_map[i]);
            s->piece_blk_map[i] = NULL;
        }
        free(s->piece_blk_n[i]);
        s->piece_blk_n[i] = NULL;
    }
    free(s);
    sess_g_s = 0;
}

static void dht_peers_cb(const uint8_t hash[20], const ntx_dht_peer *peers, int n, void *ud) {
    ntx_session *s = ud;
    if (!s) return;
    for (int i = 0; i < s->n_tts; i++) {
        if (memcmp(s->tts[i].info_hash, hash, 20) != 0) continue;
        for (int j = 0; j < n; j++)
            ntx_session_add_peer_from_tracker(s, i, &peers[j].addr, peers[j].port);
        break;
    }
}

int ntx_session_free_slot(const ntx_session *s) {
    for (int k = 0; k < NTX_SESSION_MAX_TTS; k++)
        if (k >= s->n_tts || s->tts[k].state == NTX_TTS_DEAD) return k;
    return -1;
}

int ntx_session_add_magnet(ntx_session *s, const char *url) {
    ntx_magnet m;
    if (ntx_magnet_parse(url, &m) != 0) return -1;
    int i = ntx_session_free_slot(s);
    if (i < 0) return -1;
    ntx_torrent *t = &s->tts[i];
    ntx_session_hash_reset(s, i); /* reuse of a DEAD slot: drop stale hash-exchange state */
    ntx_torrent_init_meta(t, m.info_hash);
    if (m.has_v2) {
        memcpy(t->info_hash_v2, m.ih_v2, 32);
        t->meta_version = 2;
    }
    if (m.has_name) snprintf(t->name, sizeof t->name, "%s", m.name);
    /* BEP12: ws= webseed; as= acceptable source (HTTP) — same use as webseed when ws absent */
    if (m.has_webseed) {
        snprintf(t->webseed, sizeof t->webseed, "%s", m.webseed);
        t->has_webseed = 1;
    } else if (m.has_alt_source) {
        snprintf(t->webseed, sizeof t->webseed, "%s", m.alt_source);
        t->has_webseed = 1;
    }
    s->trk_n[i] = m.n_trackers;
    memset(s->trk_fail[i], 0, sizeof s->trk_fail[i]);
    memset(s->trk_conn_done[i], 0, sizeof s->trk_conn_done[i]);
    for (int j = 0; j < m.n_trackers && j < NTX_SESSION_MAX_TRK; j++)
        snprintf(s->trk_urls[i][j], 512, "%s", m.trackers[j]);
    for (int j = s->trk_n[i] - 1; j > 0; j--) {
        uint32_t r = ntx_rand_u32() % (uint32_t)(j + 1);
        if ((int)r == j) continue; /* self-copy via snprintf would violate restrict */
        char tmp[512];
        memcpy(tmp, s->trk_urls[i][j], sizeof tmp);
        memcpy(s->trk_urls[i][j], s->trk_urls[i][r], sizeof tmp);
        memcpy(s->trk_urls[i][r], tmp, sizeof tmp);
    }
    t->state = NTX_TTS_META;
    if (i >= s->n_tts) s->n_tts = i + 1;
    ntx_session_trk_announce(s, i, NTX_TRACKER_EVENT_STARTED);
    if (s->cfg && s->cfg->dht) ntx_dht_lookup_peers(m.info_hash, dht_peers_cb, s);
    return 0;
}

/* Append one tracker URL to slot i unless it is unsupported, too long, empty or already listed.
 * Only http(s):// and udp:// trackers exist; anything else in a .torrent is ignored. */
static void session_add_tracker(ntx_session *s, int i, const ntx_be *v) {
    if (!v || v->t != NTX_BE_STR || v->sn == 0 || v->sn >= sizeof s->trk_urls[i][0]) return;
    char url[512];
    memcpy(url, v->sp, v->sn);
    url[v->sn] = 0;
    if (strncmp(url, "http://", 7) != 0 && strncmp(url, "https://", 8) != 0 && strncmp(url, "udp://", 6) != 0) return;
    if (strlen(url) != v->sn) return; /* embedded NUL */
    if (s->trk_n[i] >= NTX_SESSION_MAX_TRK) return;
    for (int j = 0; j < s->trk_n[i]; j++)
        if (strcmp(s->trk_urls[i][j], url) == 0) return;
    memcpy(s->trk_urls[i][s->trk_n[i]++], url, v->sn + 1);
}

/* A .torrent lists trackers in "announce" and (BEP12) "announce-list", a list of tiers. All of them are
 * announced to in parallel, so tiers are flattened in order. */
static void session_load_torrent_trackers(ntx_session *s, int i, const ntx_be *root) {
    memset(s->trk_fail[i], 0, sizeof s->trk_fail[i]);
    memset(s->trk_conn_done[i], 0, sizeof s->trk_conn_done[i]);
    session_add_tracker(s, i, ntx_be_dict_get(root, "announce"));
    const ntx_be *al = ntx_be_dict_get(root, "announce-list");
    if (!al || al->t != NTX_BE_LIST) return;
    for (size_t a = 0; a < al->ne; a++) {
        const ntx_be *tier = al->el[a];
        if (!tier) continue;
        if (tier->t == NTX_BE_STR) { /* tolerate a flat list of URLs */
            session_add_tracker(s, i, tier);
            continue;
        }
        if (tier->t != NTX_BE_LIST) continue;
        for (size_t b = 0; b < tier->ne; b++) session_add_tracker(s, i, tier->el[b]);
    }
}

int ntx_session_add_torrent_file(ntx_session *s, const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *buf = malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return -1; }
    ntx_be root;
    size_t consumed = 0;
    int rc = -1;
    if (ntx_be_parse(buf, (size_t)sz, &root, &consumed, 32, 1 << 20) == 0) {
        const ntx_be *info = ntx_be_dict_get(&root, "info");
        if (info && info->end > info->start) {
            const uint8_t *info_sub = buf + info->start;
            size_t info_n = info->end - info->start;
            uint8_t h20[20], h32[32];
            int mv = ntx_torrent_metainfo_hash(info_sub, info_n, h20, h32);
            if (mv < 0) {
                rc = -1;
            } else {
                int i = ntx_session_free_slot(s);
                if (i < 0) {
                    rc = -1;
                } else {
                    ntx_torrent *t = &s->tts[i];
                    ntx_session_hash_reset(s, i); /* reuse of a DEAD slot */
                    if (mv == 2) {
                        /* BEP52: a hybrid .torrent carries v1 "pieces" alongside
                         * meta version 2 and MUST join the v1 swarm, so the 20-byte
                         * info_hash used for tracker announce + wire handshake is the
                         * v1 SHA-1(info). Pure v2 keeps trunc20(SHA-256(info)). */
                        ntx_be info_be;
                        size_t ic = 0;
                        int hybrid = 0;
                        if (ntx_be_parse(info_sub, info_n, &info_be, &ic, 32, (size_t)(1u << 20)) == 0) {
                            hybrid = (ntx_be_dict_get(&info_be, "pieces") != NULL);
                            ntx_be_free(&info_be);
                        }
                        if (hybrid)
                            ntx_sha1(info_sub, info_n, h20);
                        ntx_torrent_init_meta(t, h20);
                        memcpy(t->info_hash_v2, h32, 32);
                        t->meta_version = 2;
                    } else {
                        ntx_torrent_init_meta(t, h20);
                    }
                    int mrc = ntx_torrent_set_metainfo(t, info_sub, info_n,
                                                      s->cfg && s->cfg->store_dir ? s->cfg->store_dir : "downloads",
                                                      ntx_be_dict_get(&root, "piece layers"));
                    if (mrc < 0) {
                        rc = -1;
                    } else {
                        if (i >= s->n_tts) s->n_tts = i + 1;
                        session_load_torrent_trackers(s, i, &root);
                        if (t->state != NTX_TTS_VERIFY)
                            ntx_session_trk_announce(s, i, NTX_TRACKER_EVENT_STARTED);
                        rc = 0;
                    }
                }
            }
        }
    }
    ntx_be_free(&root);
    free(buf);
    return rc;
}

void ntx_session_remove(ntx_session *s, int i) {
    if (i < 0 || i >= NTX_SESSION_MAX_TTS) return;
    ntx_torrent *t = &s->tts[i];
    if (t->state != NTX_TTS_DEAD) ntx_session_trk_stop(s, i);
    ntx_store_close(&t->store);
    free(s->piece_bytes[i]);
    s->piece_bytes[i] = 0;
    if (s->piece_blk_map[i]) {
        if (t->np > 0) {
            for (uint32_t j = 0; j < t->np; j++)
                free(s->piece_blk_map[i][j]);
        }
        free(s->piece_blk_map[i]);
        s->piece_blk_map[i] = NULL;
    }
    free(s->piece_blk_n[i]);
    s->piece_blk_n[i] = NULL;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_tts[pi] == i && s->peers[pi].fd != -1) {
            ntx_netx_del(s->netx, s->peers[pi].fd);
            if (s->peers[pi].fd >= 0) close(s->peers[pi].fd);
            free(s->peer_buf[pi]);
            s->peer_buf[pi] = 0;
            free(s->peer_out[pi]);
            s->peer_out[pi] = 0;
            s->peer_out_len[pi] = 0;
            s->peer_out_off[pi] = 0;
            s->peers[pi].fd = -1;
            s->peer_tts[pi] = -1;
            s->peer_phase[pi] = 0;
        }
    }
    ntx_session_hash_reset(s, i); /* drop scratch/outstanding 21s so a reused slot is clean */
    t->state = NTX_TTS_DEAD;
    memset(s->trk_urls[i], 0, sizeof s->trk_urls[i]);
    s->trk_n[i] = 0;
}

int ntx_session_set_paused(ntx_session *s, int i, int on) {
    if (i < 0 || i >= NTX_SESSION_MAX_TTS) return NTX_PAUSE_E_RANGE;
    ntx_torrent *t = &s->tts[i];
    if (t->state == NTX_TTS_DEAD) return NTX_PAUSE_E_DEAD;
    if (on) {
        /* {META, DL, DONE, VERIFY} are all live states; PAUSED repeats idempotently */
        if (t->state == NTX_TTS_PAUSED) return NTX_PAUSE_OK;
        t->paused_from = (uint8_t)t->state;
        t->state = NTX_TTS_PAUSED;
        return NTX_PAUSE_OK;
    }
    if (t->state != NTX_TTS_PAUSED) return NTX_PAUSE_OK; /* resume from a non-paused state: OK */
    if (t->paused_from == NTX_TTS_VERIFY) {
        t->state = (t->np > 0 && t->have_n < t->np) ? NTX_TTS_DL : NTX_TTS_VERIFY;
        /* Leaving VERIFY early skips ntx_session_data_verify_tick's completion hook, which is what
         * announces the torrent. */
        if (t->state == NTX_TTS_DL) ntx_session_tts_verify_done(s, (uint32_t)i);
    } else
        t->state = (ntx_tts_state)t->paused_from;
    return NTX_PAUSE_OK;
}

/* Legacy toggle (test/t_session.c): DL ⇄ PAUSED, kept as a thin wrapper — one
   implementation (set_paused), two entry points (§6.3). */
void ntx_session_pause(ntx_session *s, int i) {
    if (i < 0 || i >= NTX_SESSION_MAX_TTS) return;
    ntx_torrent *t = &s->tts[i];
    if (t->state == NTX_TTS_PAUSED) (void)ntx_session_set_paused(s, i, 0);
    else if (t->state == NTX_TTS_DL) (void)ntx_session_set_paused(s, i, 1);
}

void ntx_session_snapshot(const ntx_session *s, ntx_stats *dst) {
    *dst = s->s[1 - s->s_idx];
}

void ntx_session_quit(ntx_session *s) {
    s->quit = 1;
    ntx_netx_quit(s->netx);
}

void ntx_session_tick(struct ntx_session *s) {
    s->tick_n++;
    ntx_session_peer_hs_tick(s);
    ntx_session_data_tick(s);
    ntx_session_data_verify_tick(s);
    if ((s->tick_n % 10) == 0) {
        /* Ring rotate stays in the UI path (ntx_main) only — dual rotate zeroed B/s. */
        ntx_session_stats_refresh(s, 0);
        ntx_session_trk_tick(s);
        if ((s->tick_n % 50) == 0)
            ntx_session_trk_boost_peers(s);
    }
    if (s->cfg && s->cfg->verbose && (s->tick_n % 100) == 0) {
        int all = 0, hs = 0, ok = 0, un = 0;
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peers[pi].fd == -1 || s->peer_tts[pi] < 0) continue;
            all++;
            if (s->peer_phase[pi] == PH_OK) {
                ok++;
                if (ntx_peer_can_download(&s->peers[pi])) un++;
            } else
                hs++;
        }
        ntx_diag( "ntx: status peers all=%d hs=%d ok=%d unchoked=%d\n", all, hs, ok, un);
        if (ok < NTX_MIN_OK_PEERS && s->n_tts > 0)
            ntx_session_trk_boost_peers(s);
        if (s->pe_out_ok + s->pe_out_fail > 0)
            ntx_diag( "ntx: pe_out ok=%u fail=%u (%.1f%% fail)\n", s->pe_out_ok, s->pe_out_fail,
                    100.0 * (double)s->pe_out_fail / (double)(s->pe_out_ok + s->pe_out_fail));
    }
    if (s->cfg && s->cfg->dht && (s->tick_n % 100) == 0)
        ntx_dht_tick();
}

int ntx_session_peer_alloc(struct ntx_session *s, int fd, const ntx_addr *addr, uint16_t port, int tts_idx) {
    int pi = -1;
    for (int k = 0; k < NTX_SESSION_MAX_PEERS; k++) {
        if (s->peers[k].fd == -1) { pi = k; break; }
    }
    if (pi < 0) return -1;
    int np = 0;
    if (tts_idx >= 0 && tts_idx < s->n_tts && s->tts[tts_idx].have_meta)
        np = (int)s->tts[tts_idx].np;
    ntx_peer_init(&s->peers[pi], fd, addr, port, np);
    s->peers[pi].fd = fd;
    s->peers[pi].conn_t0 = ntx_mono_ms();
    s->peers[pi].hs_t0 = 0;
    s->peer_tts[pi] = tts_idx;
    s->peer_phase[pi] = PH_PE;
    s->peer_outbound[pi] = 0;
    s->peer_tcp_fb[pi] = 0;
    s->peer_meta_id[pi] = 0;
    s->peer_pex_id[pi] = 0;
    s->peer_holepunch_id[pi] = 0;
    s->peer_meta_size[pi] = 0;
    s->peer_meta_req[pi] = 0;
    s->peer_meta_inflight[pi] = UINT32_MAX;
    s->peer_bf_pending[pi] = 0;
    s->peer_bf_pending_n[pi] = 0;
    s->peer_have_all_pending[pi] = 0;
    s->peer_have_none_pending[pi] = 0;
    s->peer_plain[pi] = 0;
    s->peer_hello_sent[pi] = 0;
    s->peer_bf_got[pi] = 0;
    s->peer_fast[pi] = 0;
    s->upq_n[pi] = 0;
    s->peer_noreq_until[pi] = 0;
    memset(&s->pe[pi], 0, sizeof s->pe[pi]);
    s->peer_buf[pi] = malloc(NTX_PEER_BUF);
    s->peer_buflen[pi] = 0;
    s->peer_out[pi] = malloc(NTX_PEER_OUTBUF);
    s->peer_out_len[pi] = 0;
    s->peer_out_off[pi] = 0;
    return pi;
}

void ntx_session_peer_free(struct ntx_session *s, int pi) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS || s->peers[pi].fd == -1) return;
    int fd = s->peers[pi].fd;
    ntx_netx_del(s->netx, fd);
    if (fd >= 0) close(fd);
    s->peer_meta_req[pi] = 0;
    s->peer_meta_inflight[pi] = UINT32_MAX;
    s->peer_meta_id[pi] = 0;
    s->peer_pex_id[pi] = 0;
    s->peer_meta_size[pi] = 0;
    s->peer_bf_got[pi] = 0;
    s->peer_fast[pi] = 0;
    s->upq_n[pi] = 0;
    s->peer_noreq_until[pi] = 0;
    free(s->peer_bf_pending[pi]);
    s->peer_bf_pending[pi] = 0;
    s->peer_bf_pending_n[pi] = 0;
    s->peer_have_all_pending[pi] = 0;
    s->peer_have_none_pending[pi] = 0;
    free(s->peer_buf[pi]);
    s->peer_buf[pi] = 0;
    free(s->peer_out[pi]);
    s->peer_out[pi] = 0;
    s->peer_out_len[pi] = 0;
    s->peer_out_off[pi] = 0;
    s->peer_plain[pi] = 0;
    s->peer_hello_sent[pi] = 0;
    memset(&s->pe[pi], 0, sizeof s->pe[pi]);
    s->peers[pi].fd = -1;
    s->peer_tts[pi] = -1;
    s->peer_phase[pi] = 0;
    s->peer_outbound[pi] = 0;
    s->peer_tcp_fb[pi] = 0;
}

/* Dial-initiation core shared by the tracker path and the BEP55 holepunch
 * dial: 1 = a dial was launched (slot allocated, route_connect
 * returned a live fd), 0 = refused (dedup, caps, alloc, dead route). The
 * void public entry keeps its historical signature for the 12 tracker/PEX
 * callers that ignore the outcome. */
int ntx_session_add_peer_dial(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port) {
    return ntx_session_add_peer_dial_ex(s, tts_idx, addr, port, 0);
}

static int dial_impl(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port, int force, int tcp) {
    if (!addr || ntx_addr_is_zero(addr) || port == 0) return 0;
    /* Peer addresses come from trackers, PEX, DHT and holepunch messages: all steerable by third
     * parties.  Never let them point us at this host or at link-local/metadata/multicast space. */
    if (ntx_addr_is_special(addr) && !(s->cfg && s->cfg->allow_local_peers)) return 0;
    if (tts_idx < 0 || tts_idx >= s->n_tts) return 0;
    if (s->tts_ratio_done[tts_idx]) return 0;
    ntx_torrent *t = &s->tts[tts_idx];
    int maxp = s->cfg->max_peers;
    if (maxp <= 0) maxp = NTX_SESSION_MAX_PEERS;
    int n = 0, hs = 0, ok = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peers[pi].fd != -1) {
            n++;
            if (s->peer_outbound[pi] && (s->peer_phase[pi] == PH_PE || s->peer_phase[pi] == PH_BTHS)) hs++;
            if (ntx_addr_eq(&s->peers[pi].addr, addr) && s->peers[pi].port == port) return 0;
        }
        if (s->peer_tts[pi] != tts_idx || s->peers[pi].fd == -1) continue;
        if (s->peer_phase[pi] == PH_OK) ok++;
    }
    if (t->state == NTX_TTS_DONE) {
        if (ok >= NTX_SEED_MAX_OK) return 0;
        if (hs >= NTX_SEED_MAX_HS) return 0;
    }
    if (n >= maxp) return 0;
    if (hs >= NTX_MAX_HS_CONNECTING) return 0;
    if (!force && ntx_dial_bo_blocked(&s->dial_bo, addr, port, ntx_mono_ms())) return 0; /* it just failed */
    int pi = ntx_session_peer_alloc(s, -1, addr, port, tts_idx);
    if (pi < 0) return 0;
    s->peer_outbound[pi] = 1;
    s->peer_tcp_fb[pi] = (uint8_t)tcp;
    char ip[48];
    if (ntx_addr_ntop(addr, ip, sizeof ip) != 0) snprintf(ip, sizeof ip, "?");
    if (s->cfg && s->cfg->verbose)
        ntx_diag( "ntx: hs dial pi=%d %s:%u ti=%d hs_inflight=%d\n", pi, ip, (unsigned)port,
                tts_idx, hs + 1);
    ntx_cbs cbs;
    cbs.r = sess_peer_rw_cb;
    cbs.w = sess_peer_rw_cb;
    cbs.cl = peer_close_cb;
    void *dctx = (void *)(intptr_t)(pi + 1);
    if (!tcp && s->utp_miss_n >= NTX_UTP_GIVEUP_MISSES && s->utp_ok_n == 0) tcp = 1; /* uTP is not getting through */
    s->peer_tcp_fb[pi] = (uint8_t)tcp;
    int fd = tcp ? ntx_netx_route_connect_tcp(s->netx, &s->peers[pi].addr, port, dctx, &cbs)
                 : ntx_netx_route_connect(s->netx, &s->peers[pi].addr, port, dctx, &cbs);
    if (!NTX_NETX_IS_LIVE_FD(fd)) {
        free(s->peer_buf[pi]);
        s->peer_buf[pi] = 0;
        free(s->peer_out[pi]);
        s->peer_out[pi] = 0;
        s->peers[pi].fd = -1;
        s->peer_tts[pi] = -1;
        s->peer_phase[pi] = 0;
        s->peer_outbound[pi] = 0;
        s->peer_tcp_fb[pi] = 0;
        return 0;
    }
    s->peers[pi].fd = fd;
    if (ntx_netx_peer_connected(s->netx, fd))
        ntx_session_peer_on_connect(s, fd, (void *)(intptr_t)(pi + 1));
    return 1;
}

int ntx_session_add_peer_dial_ex(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port, int force) {
    return dial_impl(s, tts_idx, addr, port, force, 0);
}

/* TCP retry of an address whose uTP dial got no answer (never held back by the redial back-off). */
int ntx_session_add_peer_dial_tcp(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port) {
    return dial_impl(s, tts_idx, addr, port, 1, 1);
}

void ntx_session_add_peer_from_tracker(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port) {
    (void)ntx_session_add_peer_dial(s, tts_idx, addr, port);
}

static void sess_ready_apply(struct ntx_session *s, int tts_idx) {
    ntx_torrent *t = &s->tts[tts_idx];
    free(s->piece_bytes[tts_idx]);
    s->piece_bytes[tts_idx] = calloc(t->np, sizeof(uint32_t));
    if (ntx_session_data_piece_blk_alloc(s, tts_idx) != 0) {
        free(s->piece_bytes[tts_idx]);
        s->piece_bytes[tts_idx] = NULL;
    }
    ntx_session_data_reset_tts(tts_idx, t->np);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_tts[pi] != tts_idx || s->peers[pi].fd == -1) continue;
        if (s->peer_phase[pi] != PH_OK) continue;
        free(s->peers[pi].phave);
        s->peers[pi].phave = calloc(t->np, 1);
        s->peers[pi].phave_n = (int)t->np;
        s->peers[pi].phave_none = 1;
        /* Apply bitfield / HAVE_ALL / HAVE_NONE received before metainfo was known. */
        if (s->peer_have_all_pending[pi]) {
            for (uint32_t j = 0; j < t->np; j++) {
                ntx_peer_set_phave(&s->peers[pi], j, 1);
                ntx_torrent_on_peer_have(t, j);
            }
            s->peer_have_all_pending[pi] = 0;
            s->peer_have_none_pending[pi] = 0;
            s->peer_bf_got[pi] = 1;
            if (s->cfg && s->cfg->verbose)
                ntx_diag("ntx: meta_apply_have pi=%d kind=have_all phave=%u/%u choke_us=%d\n",
                         pi, (unsigned)t->np, (unsigned)t->np, s->peers[pi].choke_us);
        } else if (s->peer_bf_pending[pi] && s->peer_bf_pending_n[pi]) {
            size_t plen = s->peer_bf_pending_n[pi];
            const uint8_t *payload = s->peer_bf_pending[pi];
            /* a bitfield of the wrong length (BEP3: ceil(np/8) bytes) says nothing reliable: ignore it */
            for (uint32_t j = 0; j < t->np && plen == ((size_t)t->np + 7) / 8; j++) {
                if (j / 8 < plen && (payload[j / 8] >> (7 - j % 8)) & 1) {
                    ntx_peer_set_phave(&s->peers[pi], j, 1);
                    ntx_torrent_on_peer_have(t, j);
                }
            }
            free(s->peer_bf_pending[pi]);
            s->peer_bf_pending[pi] = 0;
            s->peer_bf_pending_n[pi] = 0;
            s->peer_have_none_pending[pi] = 0;
            s->peer_bf_got[pi] = 1;
            if (s->cfg && s->cfg->verbose) {
                uint32_t phn = 0;
                for (uint32_t j = 0; j < t->np; j++)
                    if (ntx_peer_has(&s->peers[pi], j)) phn++;
                ntx_diag("ntx: meta_apply_have pi=%d kind=bitfield phave=%u/%u choke_us=%d\n",
                         pi, (unsigned)phn, (unsigned)t->np, s->peers[pi].choke_us);
            }
        } else if (s->peer_have_none_pending[pi]) {
            for (uint32_t j = 0; j < t->np; j++)
                ntx_peer_set_phave(&s->peers[pi], j, 0);
            s->peer_have_none_pending[pi] = 0;
            s->peer_bf_got[pi] = 1;
            if (s->cfg && s->cfg->verbose)
                ntx_diag("ntx: meta_apply_have pi=%d kind=have_none phave=0/%u choke_us=%d\n",
                         pi, (unsigned)t->np, s->peers[pi].choke_us);
        } else if (s->cfg && s->cfg->verbose) {
            ntx_diag("ntx: meta_apply_have pi=%d kind=await_bf bf_got=%d phave_none=%d "
                     "choke_us=%d\n",
                     pi, (int)s->peer_bf_got[pi], s->peers[pi].phave_none,
                     s->peers[pi].choke_us);
        }
        ntx_session_data_update_peer_interest(s, pi);
        ntx_session_peer_out_flush(s, pi);
    }
}

void ntx_session_on_metainfo(struct ntx_session *s, int tts_idx) {
    if (tts_idx < 0 || tts_idx >= NTX_SESSION_MAX_TTS) return;
    ntx_torrent *t = &s->tts[tts_idx];
    if (t->state == NTX_TTS_VERIFY) {
        sess_ready_apply(s, tts_idx);
        return;
    }
    t->state = NTX_TTS_DL;
    sess_ready_apply(s, tts_idx);
    ntx_session_trk_announce(s, tts_idx, NTX_TRACKER_EVENT_STARTED);
    ntx_session_data_refill(s, tts_idx);
}

void ntx_session_tts_verify_done(struct ntx_session *s, uint32_t i) {
    if (i >= NTX_SESSION_MAX_TTS) return;
    ntx_torrent *t = &s->tts[i];
    if (t->state != NTX_TTS_DL && t->state != NTX_TTS_DONE) return;
    if (t->state == NTX_TTS_DL)
        ntx_session_trk_announce(s, (int)i, NTX_TRACKER_EVENT_STARTED);
    sess_ready_apply(s, (int)i);
    ntx_session_data_refill(s, (int)i);
}

void ntx_session_accept_cb(struct ntx_session *s, ntx_netx *n, int peer_fd, void *ctx) {
    (void)ctx;
    ntx_addr a;
    uint16_t port = 0;
    ntx_addr_clear(&a);
    struct sockaddr_storage ss;
    socklen_t slen = sizeof ss;
    if (getpeername(peer_fd, (struct sockaddr *)&ss, &slen) == 0)
        ntx_addr_from_sockaddr(&a, &port, &ss);
    int same = 0;
    for (int k = 0; k < NTX_SESSION_MAX_PEERS; k++)
        if (s->peers[k].fd != -1 && ntx_addr_eq(&s->peers[k].addr, &a)) same++;
    int pi = same >= NTX_PEER_MAX_PER_ADDR ? -1 : ntx_session_peer_alloc(s, peer_fd, &a, port, -1);
    if (pi < 0) {
        /* A virt (uTP) fd has no real socket to close; release its glue slot so
         * the accepted connection is not leaked when the peer table is full. */
        if (peer_fd < 0) ntx_netx_del(s->netx, peer_fd);
        else close(peer_fd);
        return;
    }
    ntx_session_peer_on_accept(s, n, peer_fd, NULL);
}
