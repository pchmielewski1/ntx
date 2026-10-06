#ifndef NTX_SESSION_INTERNAL_H
#define NTX_SESSION_INTERNAL_H

#include <stdint.h>
#include <stddef.h>
#include "ntx_session.h"
#include "../net/ntx_addr.h"
#include "../proto/ntx_pe.h"
#include "../proto/ntx_ext.h"
#include "ntx_pex_tx.h"
#include "ntx_dial_bo.h"
#include "ntx_hash_msg.h"

enum { PH_PE = 0, PH_BTHS = 1, PH_OK = 2 };

/* A route_connect result is a live connection when it is a real socket fd
 * (>= 0) OR a virt fd issued by the uTP glue (<= -NTX_UTP_VIRT_BASE). The raw
 * connect-failure sentinel is -1, so callers must NOT use `fd < 0` to detect
 * failure — that misclassifies every uTP virt fd as dead and drops the peer.
 * The session layer treats a slot as free only at fd == -1; every liveness test
 * is `fd != -1` so uTP virt peers are counted and driven like real sockets. */
#ifndef NTX_UTP_VIRT_BASE
#define NTX_UTP_VIRT_BASE 1000
#endif
#define NTX_NETX_IS_LIVE_FD(fd) ((fd) >= 0 || (fd) <= -NTX_UTP_VIRT_BASE)

enum {
    MSG_CHOKE = 0, MSG_UNCHOKE = 1, MSG_INTERESTED = 2,
    MSG_NOT_INTERESTED = 3, MSG_HAVE = 4, MSG_BITFIELD = 5, MSG_REQUEST = 6,
    MSG_PIECE = 7, MSG_CANCEL = 8,
    MSG_HAVE_ALL = 14, MSG_HAVE_NONE = 15, MSG_EXT = 20
};

#define NTX_TRK_PENDING 64
#define NTX_PEER_HS_TIMEOUT_S 60
/* An established peer that sends nothing (not even the 2-minute keep-alive) for this long is dropped:
 * otherwise a handful of idle connections pins every peer slot for good. */
#define NTX_PEER_IDLE_TIMEOUT_S 300
/* Most connections we keep from one remote address (NAT / university swarms need several). */
#define NTX_PEER_MAX_PER_ADDR 8
#define NTX_PEER_CONN_TIMEOUT_S 5
#define NTX_PEER_CONN_TIMEOUT_FAST_MS 2500u /* while fewer than NTX_MIN_OK_PEERS peers work */
/* --utp: a uTP dial still unanswered after this long is redone over TCP (most peers have no uTP stack). */
#define NTX_UTP_DIAL_MS 1500u
/* ... and when this many uTP dials missed without a single uTP peer ever working (UDP filtered, or a
 * swarm without uTP) the session stops trying uTP first. */
#define NTX_UTP_GIVEUP_MISSES 40u
#define NTX_MAX_HS_CONNECTING 99
#define NTX_SEED_RATIO_NUM 3
#define NTX_PEER_BUF 262144
#define NTX_PEER_OUTBUF 65536
#define NTX_UPQ_MAX 32 /* deferred block requests per peer */
/* BEP52 outbound hash-exchange queue depth per torrent (bounded, like the
 * piece-request pipeline). */
#define NTX_HASH_OUT_MAX 8

struct ntx_session {
    ntx_netx *netx;
    const ntx_config *cfg;
    uint8_t peer_id[20];
    uint32_t trk_key;
    uint64_t down_total, up_total;
    uint64_t up_start;
    int quit;

    ntx_torrent tts[NTX_SESSION_MAX_TTS];
    int n_tts;
    uint32_t *piece_bytes[NTX_SESSION_MAX_TTS];
    uint8_t **piece_blk_map[NTX_SESSION_MAX_TTS];
    uint16_t *piece_blk_n[NTX_SESSION_MAX_TTS];
    uint64_t tts_down[NTX_SESSION_MAX_TTS], tts_up[NTX_SESSION_MAX_TTS];
    uint8_t tts_ratio_done[NTX_SESSION_MAX_TTS];
    ntx_pex_tx pex_tx[NTX_SESSION_MAX_TTS];
    char trk_urls[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK][512];
    int trk_n[NTX_SESSION_MAX_TTS];

    ntx_peer peers[NTX_SESSION_MAX_PEERS];
    ntx_pe pe[NTX_SESSION_MAX_PEERS];
    int peer_phase[NTX_SESSION_MAX_PEERS];
    int peer_tts[NTX_SESSION_MAX_PEERS];
    uint8_t peer_outbound[NTX_SESSION_MAX_PEERS];
    uint32_t utp_miss_n; /* uTP dials that fell back to TCP */
    uint32_t utp_ok_n;   /* uTP peers that completed the BitTorrent handshake */
    uint8_t peer_tcp_fb[NTX_SESSION_MAX_PEERS]; /* outbound dial that already is the TCP retry of a uTP miss */
    uint8_t *peer_buf[NTX_SESSION_MAX_PEERS];
    size_t peer_buflen[NTX_SESSION_MAX_PEERS];
    uint8_t *peer_out[NTX_SESSION_MAX_PEERS];
    size_t peer_out_len[NTX_SESSION_MAX_PEERS];
    size_t peer_out_off[NTX_SESSION_MAX_PEERS];
    uint8_t peer_meta_id[NTX_SESSION_MAX_PEERS];
    uint8_t peer_pex_id[NTX_SESSION_MAX_PEERS];
    uint8_t peer_holepunch_id[NTX_SESSION_MAX_PEERS];
    uint32_t peer_meta_size[NTX_SESSION_MAX_PEERS];
    uint32_t peer_meta_req[NTX_SESSION_MAX_PEERS];
    uint32_t peer_meta_inflight[NTX_SESSION_MAX_PEERS];
    uint8_t *peer_bf_pending[NTX_SESSION_MAX_PEERS];
    size_t peer_bf_pending_n[NTX_SESSION_MAX_PEERS];
    uint8_t peer_have_all_pending[NTX_SESSION_MAX_PEERS];
    uint8_t peer_have_none_pending[NTX_SESSION_MAX_PEERS];
    uint8_t peer_plain[NTX_SESSION_MAX_PEERS];
    uint8_t peer_hello_sent[NTX_SESSION_MAX_PEERS];
    uint8_t peer_bf_got[NTX_SESSION_MAX_PEERS];
    uint8_t peer_fast[NTX_SESSION_MAX_PEERS];
    uint64_t peer_pex_last_ms[NTX_SESSION_MAX_PEERS];

    ntx_stats s[2];
    int s_idx;
    uint32_t ring_d[5], ring_u[5];
    uint32_t tts_ring_d[NTX_SESSION_MAX_TTS][5], tts_ring_u[NTX_SESSION_MAX_TTS][5];
    uint32_t cur_d, cur_u;
    uint32_t tts_cur_d[NTX_SESSION_MAX_TTS], tts_cur_u[NTX_SESSION_MAX_TTS];
    uint64_t tick_n;

    /* Rate limits: one token bucket per direction ([0] = download, [1] = upload). Tokens are bytes; a
     * transfer is allowed while the bucket is positive and may leave it negative, so limits below one
     * block still make progress at the configured average rate. */
    ntx_dial_bo dial_bo; /* addresses whose outbound attempt just failed */
    int64_t shape_tok[2];
    uint64_t shape_t[2];
    /* Block requests from peers that could not be served yet (rate limit or full output buffer). */
    struct { uint32_t idx, off, len; } upq[NTX_SESSION_MAX_PEERS][NTX_UPQ_MAX];
    uint8_t upq_n[NTX_SESSION_MAX_PEERS];
    uint64_t peer_noreq_until[NTX_SESSION_MAX_PEERS]; /* back off requesting after a reject (ms) */

    int trk_fd;
    int trk_pending[NTX_TRK_PENDING];
    int trk_pending_tts[NTX_TRK_PENDING];
    int trk_pending_trk[NTX_TRK_PENDING];
    int trk_pending_used[NTX_TRK_PENDING];
    uint64_t trk_pending_t0[NTX_TRK_PENDING];
    uint32_t trk_pending_ip[NTX_TRK_PENDING];   /* where the request went (net order); replies must match */
    uint16_t trk_pending_port[NTX_TRK_PENDING]; /* host order */
    uint64_t trk_next[NTX_SESSION_MAX_TTS];
    uint32_t trk_interval[NTX_SESSION_MAX_TTS];
    int trk_conn_done[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK];
    uint64_t trk_conn_id[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK];
    uint64_t trk_conn_t0[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK];
    uint64_t trk_http_due[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK];
    uint8_t trk_http_pending[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK];
    uint8_t trk_udp_pending[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK]; /* announce queued, see trk_pump_udp */
    int trk_http_event[NTX_SESSION_MAX_TTS];
    /* Consecutive fail budget: DNS miss / UDP timeout / HTTP error. At max → skip forever. */
    uint8_t trk_fail[NTX_SESSION_MAX_TTS][NTX_SESSION_MAX_TRK];
    uint32_t pe_out_ok, pe_out_fail;

    /* BEP52 outbound hash exchange: outstanding 21 requests per torrent,
     * the per-torrent scratch buffer accumulating the verified piece-layer
     * slices, and the counters surfaced to the UI. */
    uint8_t hash_out_used[NTX_SESSION_MAX_TTS][NTX_HASH_OUT_MAX];
    ntx_hash_req hash_out_req[NTX_SESSION_MAX_TTS][NTX_HASH_OUT_MAX];
    int32_t hash_out_file[NTX_SESSION_MAX_TTS][NTX_HASH_OUT_MAX];
    int32_t hash_out_peer[NTX_SESSION_MAX_TTS][NTX_HASH_OUT_MAX];
    uint64_t hash_out_t0[NTX_SESSION_MAX_TTS][NTX_HASH_OUT_MAX];
    uint8_t *hash_scratch[NTX_SESSION_MAX_TTS];
    size_t hash_scratch_n[NTX_SESSION_MAX_TTS];
    uint8_t hash_have[NTX_SESSION_MAX_TTS][NTX_TORRENT_MAX_FILES_V2];
    uint8_t hash_tries[NTX_SESSION_MAX_TTS][NTX_TORRENT_MAX_FILES_V2];
    uint8_t hash_rr[NTX_SESSION_MAX_TTS];
    uint8_t hash_ok_seen[NTX_SESSION_MAX_TTS];
    uint64_t hash_stall_t0[NTX_SESSION_MAX_TTS];
    uint32_t hash_req_tx, hash_req_rx_ok, hash_rej, hash_ignore;

    /* BEP55 ut_holepunch counters, surfaced for the
     * punch_ok/punch_fail metrics. */
    uint32_t hp_rx_rendezvous, hp_rx_connect, hp_rx_error;
    uint32_t hp_dial_ok, hp_dial_fail, hp_race_dropped;
};
void ntx_session_tick(struct ntx_session *s);
int ntx_session_peer_alloc(struct ntx_session *s, int fd, const ntx_addr *addr, uint16_t port, int tts_idx);
void ntx_session_peer_free(struct ntx_session *s, int pi);
void ntx_session_add_peer_from_tracker(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port);
/* Dial-initiation core behind add_peer_from_tracker; returns 1 when a dial was
 * launched, 0 when refused (dedup, caps, alloc, dead route). The UI uses the
 * result for the BEP55 punch_ok/punch_fail counters. */
int ntx_session_add_peer_dial(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port);
/* force=1 skips the redial back-off (BEP55: the remote is dialling us at the same time). */
int ntx_session_add_peer_dial_tcp(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port);
int ntx_session_add_peer_dial_ex(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port, int force);
void ntx_session_on_metainfo(struct ntx_session *s, int tts_idx);
void ntx_session_tts_verify_done(struct ntx_session *s, uint32_t i);
void ntx_session_accept_cb(struct ntx_session *s, ntx_netx *n, int peer_fd, void *ctx);

void ntx_session_trk_init(struct ntx_session *s);
void ntx_session_trk_free(struct ntx_session *s);
void ntx_session_trk_announce(struct ntx_session *s, int tts_idx, int event);
void ntx_session_trk_pump_http(struct ntx_session *s, int max);
void ntx_session_trk_pump_udp(struct ntx_session *s);
void ntx_session_trk_stop(struct ntx_session *s, int tts_idx);
void ntx_session_trk_stop_all(struct ntx_session *s);
void ntx_session_trk_tick(struct ntx_session *s);
void ntx_session_trk_boost_peers(struct ntx_session *s);
void ntx_session_trk_on_udp(struct ntx_session *s, int fd, void *ctx);
void ntx_session_trk_on_close(struct ntx_session *s, void *ctx);

void ntx_session_peer_hs_tick(struct ntx_session *s);
void ntx_session_peer_on_rw(struct ntx_session *s, int fd, void *ctx);
void ntx_session_peer_on_close(struct ntx_session *s, void *ctx);
void ntx_session_peer_on_connect(struct ntx_session *s, int fd, void *ctx);
void ntx_session_peer_on_accept(struct ntx_session *s, ntx_netx *n, int peer_fd, void *ctx);
void ntx_session_peer_step(struct ntx_session *s, int pi);
void ntx_session_peer_cull_stale(struct ntx_session *s, int max_drop, uint64_t age_ms);
void ntx_session_peer_send_handshake(struct ntx_session *s, int pi);
void ntx_session_peer_send_ext_handshake(struct ntx_session *s, int pi);
void ntx_session_peer_send_interest(struct ntx_session *s, int pi, int interested);
void ntx_session_peer_send_choke(struct ntx_session *s, int pi, int choked);
void ntx_session_peer_send_bitfield(struct ntx_session *s, int pi);
int ntx_session_peer_send_request(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len);
void ntx_session_peer_send_cancel(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len);
int ntx_session_peer_send_piece(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, const uint8_t *data, uint32_t len);
void ntx_session_peer_send_reject(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len);
int ntx_session_shape_ready(struct ntx_session *s, int up);
void ntx_session_shape_use(struct ntx_session *s, int up, uint64_t n);
void ntx_session_data_on_cancel(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len);
void ntx_session_data_on_reject(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len);
void ntx_session_peer_send_keepalive(struct ntx_session *s, int pi);
void ntx_session_peer_send_have(struct ntx_session *s, int pi, uint32_t idx);
void ntx_session_peer_send_have_all(struct ntx_session *s, int pi);
void ntx_session_peer_process_inbuf(struct ntx_session *s, int pi);
void ntx_session_data_on_pex(struct ntx_session *s, int pi, const uint8_t *payload, size_t plen);
void ntx_session_data_pex_tick(struct ntx_session *s);
int ntx_session_peer_send_raw(struct ntx_session *s, int pi, const uint8_t *buf, size_t n);
int ntx_session_peer_out_flush(struct ntx_session *s, int pi);

#define NTX_MIN_UNCHOKED 5
#define NTX_UNCHOKE_BEST 10
#define NTX_OPT_UNCHOKE_TICKS 300 /* 30 s @ 100 ms tick */
#define NTX_TRK_BOOST_MAX_WAIT_MS 800
#define NTX_TRK_BOOST_URGENT_MS 250
#define NTX_TRK_BOOST_LOW_UN_MS 800
#define NTX_MIN_OK_PEERS 3
#define NTX_SEED_MAX_OK 48   /* stop outbound dials once enough leechers connected */
#define NTX_SEED_MAX_HS 12   /* cap in-flight handshakes while seeding */
#define NTX_PEER_OK_POLL_BATCH 16 /* OK peers polled per 100ms tick (RR, not all 80+) */
#define NTX_TRK_MAX_FAIL 3 /* skip tracker after this many consecutive fails */
#define NTX_PIPE_INFLIGHT NTX_PEER_PIPE_MIN /* minimum; see ntx_peer_pipe_depth */
void ntx_session_data_reset_tts(int tts_idx, uint32_t np);
int ntx_session_data_piece_blk_alloc(struct ntx_session *s, int tts_idx);
void ntx_session_data_on_unchoke(struct ntx_session *s, int pi);
void ntx_session_data_on_choke(struct ntx_session *s, int pi);
void ntx_session_data_refill(struct ntx_session *s, int tts_idx);
void ntx_session_data_update_peer_interest(struct ntx_session *s, int pi);
void ntx_session_data_on_piece(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, const uint8_t *data, uint32_t len);
void ntx_session_data_on_request(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len);
/* Drain up to max_jobs queued piece-hash verifications (ntx_session_data.c). */
void verify_drain(struct ntx_session *s, int max_jobs);
void ntx_session_data_on_ext(struct ntx_session *s, int pi, int ext_id, const uint8_t *payload, size_t plen);
/* BEP55 ut_holepunch: RX classifier + connect/error handler. */
int ext_is_holepunch(struct ntx_session *s, int pi, int ext_id);
void ntx_session_holepunch_on_rx(struct ntx_session *s, int pi, const uint8_t *payload, size_t plen);
/* Dial a uTP connection to a punched endpoint (public route_connect path). */
void ntx_session_holepunch_dial(struct ntx_session *s, int tts_idx, const ntx_addr *addr, uint16_t port);
/* BEP55 race tie-break: drop the loser of a dual-dial to one endpoint. */
int ntx_session_holepunch_resolve_race(struct ntx_session *s, int pi);
void ntx_session_data_tick(struct ntx_session *s);
void ntx_session_data_verify_tick(struct ntx_session *s);
/* BEP52: clear all per-torrent hash-exchange state (scratch, outstanding
 * 21s, per-file tries, stall timer) for a slot being added/reused/freed. */
void ntx_session_hash_reset(struct ntx_session *s, int ti);
void ntx_session_data_meta_pump_peer(struct ntx_session *s, int pi);
int ntx_session_data_send_metainfo(struct ntx_session *s, int pi, uint32_t piece);
void ntx_session_data_meta_progress(int tts_idx, uint16_t *got, uint16_t *need);
uint32_t ntx_session_data_verify_pending(int tts_idx, uint32_t np);

/* Cross-file declarations for the split-out session sources; these functions
   stay non-static because they are called across translation units. */
/* pieceblk (bodies in ntx_pieceblk.c) */
void piece_blk_free_tts(struct ntx_session *s, int tts_idx);
int piece_blk_alloc_tts(struct ntx_session *s, int tts_idx);
void piece_blk_clear(struct ntx_session *s, int tts_idx, uint32_t idx);
void piece_blk_mark(struct ntx_session *s, int tts_idx, uint32_t idx, uint32_t off, uint32_t len);
int piece_all_blocks(const struct ntx_session *s, int tts_idx, uint32_t idx);
int piece_blk_have(const struct ntx_session *s, int tts_idx, uint32_t idx, uint32_t off, uint32_t len);
int piece_block_inflight_count(const struct ntx_session *s, int tts_idx, uint32_t idx, uint32_t off);
uint32_t piece_next_off(const struct ntx_session *s, int tts_idx, uint32_t idx);
uint32_t piece_got_blocks(const struct ntx_session *s, int tts_idx, uint32_t idx);
int piece_block_inflight_any(const struct ntx_session *s, int tts_idx, uint32_t idx,
                             uint32_t off, uint64_t now, int allow_stale);
uint32_t piece_next_off_avail(const struct ntx_session *s, int tts_idx, uint32_t idx,
                              uint64_t now);
int piece_has_inflight(const ntx_peer *p, uint32_t idx);
int piece_has_partial(const struct ntx_session *s, int tts_idx);
int piece_want(const ntx_torrent *t, struct ntx_session *s, int tts_idx, uint32_t idx);
/* meta (bodies in ntx_session_meta.c) */
void meta_reset(int i);
void meta_reject(struct ntx_session *s, int pi, uint32_t piece);
void meta_retry_all(struct ntx_session *s, int i);
void meta_assemble(struct ntx_session *s, int i);
int ext_is_metadata(struct ntx_session *s, int pi, int ext_id);
/* webseed (body in ntx_session_webseed.c) */
void ntx_session_webseed_tick(struct ntx_session *s, int tts_idx);
/* pex (body in ntx_session_pex.c) */
int ext_is_pex(struct ntx_session *s, int pi, int ext_id);
/* helper staying in ntx_session_data.c, called from ntx_session_meta.c */
/* vlog (bodies in ntx_session_vlog.c) */
int sp_verbose(const struct ntx_session *s);
const char *sp_pe_st_name(int st);
void sp_addr_str(const ntx_addr *a, char *out, size_t cap);
const char *sp_phase_name(int ph);
void sp_vlog_dl(const struct ntx_session *s, int pi, const char *evt, const char *extra);
void sp_vlog_peer(const struct ntx_session *s, int pi, const char *evt, const char *extra);
/* pe glue (bodies in ntx_session_pe.c) */
void sp_pe_drive(struct ntx_session *s, int pi);
void sp_plaintext_fallback(struct ntx_session *s, int pi);
void sp_pe_finish(struct ntx_session *s, int pi);
void sp_pe_set_infohash(struct ntx_session *s, int pi);
void sp_note_peer_fast(struct ntx_session *s, int pi, const uint8_t hs[68]);
int sp_setup_phave(struct ntx_session *s, int pi, int ti);
/* bt_hs (bodies in ntx_session_bt_hs.c) */
int sp_match_tts(struct ntx_session *s, const uint8_t hash[20]);
int sp_promote_peer_ok(struct ntx_session *s, int pi, const uint8_t hs[68]);
void sp_bths_resync(uint8_t *buf, size_t *bl);
void sp_build_bt_handshake(struct ntx_session *s, int pi, uint8_t m[68]);
void sp_peer_ok_hello(struct ntx_session *s, int pi);
void sp_peer_ok_poll(struct ntx_session *s, int pi);
/* EPOLLOUT only while outbound bytes pending or during PE/BTHS (avoids idle spin). */
void sp_peer_arm_io(struct ntx_session *s, int pi);
int sp_bths_try(struct ntx_session *s, int pi);
/* helpers staying in ntx_session_peer.c, called from the files above */
void sp_drop(struct ntx_session *s, int pi, const char *why);
void sp_process_msgs(struct ntx_session *s, int pi);
void sp_send_our_availability(struct ntx_session *s, int pi);
uint32_t sp_phave_count(const ntx_peer *p);

#endif
