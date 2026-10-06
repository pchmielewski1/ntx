#ifndef NTX_UTP_H
#define NTX_UTP_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "ntx_netx.h"
#include "ntx_addr.h"

/* uTP v1 (BEP29) — separate UDP socket (not shared with DHT), virt fd
 * like the NTX1 tunnel (fd < 0). See BEP 29.
 * Golden vectors: test/vectors/utp/ (test/scripts/utp_header.py). */

#define NTX_UTP_HDR_LEN 20u
#define NTX_UTP_VER 1u
#define NTX_UTP_ST_DATA 0
#define NTX_UTP_ST_FIN 1
#define NTX_UTP_ST_STATE 2
#define NTX_UTP_ST_RESET 3
#define NTX_UTP_ST_SYN 4
#define NTX_UTP_EXT_SACK 1
#define NTX_UTP_SACK_MAX 2048u
/* CC (BEP29; constants verified 2026-09-04, see test/vectors/utp/cc_constants.txt) */
#define NTX_UTP_TARGET_DELAY_US 100000u
#define NTX_UTP_MAX_CWND_INC_PER_RTT 3
#define NTX_UTP_CC_HISTORY 120
#define NTX_UTP_MIN_PKT 150u
#define NTX_UTP_INIT_TIMEOUT_MS 1000u
#define NTX_UTP_MIN_TIMEOUT_MS 500u
#define NTX_UTP_DUP_ACK_LIMIT 3
#define NTX_UTP_MAX_CONNS 64
/* An inbound SYN costs us a slot plus buffers and is unauthenticated (UDP source addresses are
 * spoofable).  Until the peer's first ST_DATA the slot is "half-open": those are capped (in total and
 * per source address) and reaped after NTX_UTP_HALFOPEN_MS, so a SYN flood cannot pin the table. */
#ifndef NTX_UTP_HALFOPEN_MS
#define NTX_UTP_HALFOPEN_MS 10000u
#endif
#define NTX_UTP_MAX_HALFOPEN (NTX_UTP_MAX_CONNS / 2)
#define NTX_UTP_MAX_HALFOPEN_PER_SRC 8
/* Virt fds: tunnel owns -1..-64; uTP owns -(NTX_UTP_VIRT_BASE + slot). */
#define NTX_UTP_VIRT_BASE 1000

typedef struct {
    uint8_t type; /* 0..4 */
    uint8_t ver; /* 1 */
    uint8_t extension; /* 0 or first extension type */
    uint16_t conn_id;
    uint32_t ts_us;
    uint32_t ts_diff_us; /* 0 = no delay samples yet */
    uint32_t wnd_size; /* advertised receive window, bytes */
    uint16_t seq_nr;
    uint16_t ack_nr;
} ntx_utp_hdr;

/* Parse the 20-byte uTP header (network byte order). n must be >= 20, ver == 1,
 * type <= 4. 0 on success, -1 on invalid input. */
int ntx_utp_hdr_parse(const uint8_t *p, size_t n, ntx_utp_hdr *o);
/* Write the 20-byte header. 0 on success, -1 if cap < 20 or type/ver invalid. */
int ntx_utp_hdr_write(uint8_t *p, size_t cap, const ntx_utp_hdr *h);

/* SACK extension (BEP29). mask: n bytes, n > 0, n % 4 == 0 (32-bit
 * multiple), n <= NTX_UTP_SACK_MAX. First bit = ack_nr + 2 (ack_nr+1 assumed
 * missing); within each byte the LSB is the lower sequence number.
 * out_seqs (cap entries): acked sequence numbers (16-bit wrap) in offset
 * order. 0 on success, -1 if n invalid or more bits set than cap. */
int ntx_utp_parse_sack(const uint8_t *mask, size_t n, uint16_t ack_nr,
                       uint16_t *out_seqs, int *n_acked, int cap);

/* Walk the extension chain: blocks (type u8, len u8, data[len]); a block with
 * type == 0 (len must be 0) terminates the list. out_first: first extension
 * type (0 for empty chain p/n == 0/0); out_payload: pointer just past the
 * terminator (== p + n). 0 on success, -1 if truncated, unterminated, or a
 * terminator with len != 0. */
int ntx_utp_ext_skip(const uint8_t *p, size_t n, int *out_first,
                     const uint8_t **out_payload);

/* ---- congestion control (pure; Q16 fixed point, truncating division) ---- */
typedef struct {
    uint32_t hist[NTX_UTP_CC_HISTORY]; /* sliding base_delay window */
    int hist_n;
    int hist_idx;
} ntx_utp_cc;

void ntx_utp_cc_init(ntx_utp_cc *cc);
/* BEP29: ts_diff_us = this packet's timestamp_difference (0 = no sample:
 * no history update, no window change). base_delay = min of the ring after
 * inserting the sample (no samples yet -> no window change).
 * our_delay = ts_diff - base_delay; off_target = TARGET - our_delay;
 * delay_factor = Q16(off_target / TARGET); window_factor = Q16(outstanding /
 * max_window) (0 when max_window == 0); scaled_gain =
 * (MAX_CWND_INC_PER_RTT * delay_factor * window_factor) >> 32; returns
 * max_window + scaled_gain clamped to >= 0. */
int64_t ntx_utp_cc_update(ntx_utp_cc *cc, uint32_t ts_diff_us,
                          uint32_t outstanding, int64_t max_window);

/* ---- connection state machine (in-memory; packets injected via input) ---- */
#define NTX_UTP_CS_UNINITIALIZED 0
#define NTX_UTP_CS_SYN_SENT 1
#define NTX_UTP_CS_SYN_RECV 2
#define NTX_UTP_CS_CONNECTED 3
#define NTX_UTP_CS_DESTROYING 4

typedef void (*ntx_utp_tx_fn)(const uint8_t *pkt, size_t n, void *ctx); /* wire send */
typedef void (*ntx_utp_rx_fn)(const uint8_t *data, size_t n, void *ctx); /* payload */
typedef void (*ntx_utp_timer_fn)(uint32_t delay_ms, void *ctx); /* schedule probe */
typedef void (*ntx_utp_closed_fn)(void *ctx);
typedef uint64_t (*ntx_utp_clock_fn)(void *ctx); /* µs */

typedef struct {
    const ntx_addr *peer;
    uint16_t peer_port;
    ntx_utp_tx_fn tx;
    ntx_utp_rx_fn rx;
    ntx_utp_timer_fn timer;
    ntx_utp_closed_fn closed;
    ntx_utp_clock_fn clock;
    void *ctx;
} ntx_utp_conn_ops;

typedef struct ntx_utp_conn ntx_utp_conn;

/* Initiator (BEP29): state CS_SYN_SENT, seq_nr = 1, conn_id_recv as given,
 * conn_id_send = conn_id_recv + 1; emits ST_SYN via ops->tx immediately. */
ntx_utp_conn *ntx_utp_conn_initiate(uint16_t conn_id_recv,
                                    const ntx_utp_conn_ops *ops);
/* Acceptor on ST_SYN: conn_id_recv = syn.conn_id + 1, conn_id_send =
 * syn.conn_id, ack_nr = syn.seq_nr, state CS_SYN_RECV; emits the ST_STATE
 * (ACK-only) reply via ops->tx immediately. Acceptors' ST_STATE does not
 * consume a seq_nr (BEP29; matches libtorrent). */
ntx_utp_conn *ntx_utp_conn_accept(uint16_t syn_conn_id, uint16_t syn_seq_nr,
                                  uint32_t syn_ts_us,
                                  const ntx_utp_conn_ops *ops);
void ntx_utp_conn_free(ntx_utp_conn *c);
/* Feed one received packet (header + optional extensions + payload, n >= 20).
 * 0 = consumed, -1 = drop (bad ver/type, truncated ext, unknown state).
 * Handles ST_STATE/ST_DATA/ST_FIN/ST_RESET; SACK parsing + loss detection
 * (3 dup-acks or 3 SACKs past oldest unacked -> retransmit, max_window *= 0.5);
 * rtt/rtt_var update for once-sent packets; timeout = max(rtt + 4*rtt_var,
 * 500) ms, initial 1000 ms, doubled per consecutive timeout; on timeout
 * packet_size = max_window = 150 and one probe packet is allowed. */
int ntx_utp_conn_input(ntx_utp_conn *c, const uint8_t *pkt, size_t n);
/* Queue payload bytes for ST_DATA send. Returns accepted bytes (0..n); 0 when
 * the window (min(max_window, peer wnd_size)) is full. */
size_t ntx_utp_conn_write(ntx_utp_conn *c, const uint8_t *data, size_t n);
/* Close the send direction: flush pending payload then ST_FIN (eof_pkt). */
void ntx_utp_conn_close(ntx_utp_conn *c);
int ntx_utp_conn_state(const ntx_utp_conn *c);
int ntx_utp_conn_connected(const ntx_utp_conn *c);
uint16_t ntx_utp_conn_recv_id(const ntx_utp_conn *c);
/* Call when a timer previously scheduled via ops->timer fires: the SM
 * applies the timeout (retransmit probe) and may schedule the next
 * timer. Safe to call once per scheduled timer. */
void ntx_utp_conn_on_timer(ntx_utp_conn *c);

/* ---- netx glue: separate UDP socket + conn table (BEP29) ---- */
typedef struct ntx_utp ntx_utp;

/* Bind the transport's datagram socket(s) on the netx loop (EPOLLIN). In
 * shared mode it rides the netx-owned per-family owner already bound to this
 * port; standalone mode it binds its own (port; 0 = ephemeral) plus an
 * AF_INET6 sibling on the same number (V6ONLY=1, best effort — IPv6-less hosts
 * keep a v4-only listener). Inbound SYN: allocates a conn, replies
 * ST_STATE; the first ST_DATA from that peer fires accept_cb (netx accept
 * style) with virt fd = -(NTX_UTP_VIRT_BASE + slot). NULL on bind failure
 * (fail-soft: no uTP listen). */
ntx_utp *ntx_utp_listen(ntx_netx *netx, uint16_t port, ntx_cb_accept accept_cb,
                        void *accept_ctx);
void ntx_utp_free(ntx_utp *u);
uint16_t ntx_utp_port(const ntx_utp *u);
/* Live-connection count for the UI (read-only): slots holding an
 * allocated state machine that has not been closed. 0 for NULL. */
int ntx_utp_conn_count(const ntx_utp *u);
/* 1 when the v6 path is live — the AF_INET6 sibling socket is bound or a v6
 * peer slot exists (the utp_v6 flag). 0 for NULL. */
int ntx_utp_v6_live(const ntx_utp *u);
/* Outbound: initiate a conn (SYN) and return its virt fd (negative; usable by
 * ntx_netx_read/write/peer_connected once CONNECTED, like tunnel virt fds).
 * Both families are dialable: the peer's family picks the egress
 * socket. -1 when there is no listen socket, no socket for that family, or
 * the conn table is full — the caller then falls back to raw TCP. */
int ntx_utp_route_connect(ntx_utp *u, const ntx_addr *addr, uint16_t port,
                          void *ctx, const ntx_cbs *cbs);
/* uTP dial through a SOCKS5 UDP ASSOCIATE (RFC1928 §7). The TCP
 * control connection is opened to cfg->proxy_host/port and the relay BND socket
 * carries the framed datagrams; the raw uTP path above stays untouched. v6 DST
 * goes out as ATYP=0x04, so both families are accepted here too. */
int ntx_utp_route_connect_proxy(ntx_utp *u, const ntx_addr *addr,
                                uint16_t port, void *ctx, const ntx_cbs *cbs,
                                const ntx_config *cfg);
/* Virt-fd dispatch (called from ntx_netx for fd < 0 that is not a tunnel fd). */
ssize_t ntx_utp_virt_read(ntx_utp *u, int virt_fd, uint8_t *buf, size_t cap);
ssize_t ntx_utp_virt_write(ntx_utp *u, int virt_fd, const uint8_t *buf, size_t n);
int ntx_utp_virt_connected(ntx_utp *u, int virt_fd);
/* Shared-socket demux entry: the netx recv loop classifies a datagram
 * as uTP and hands it here with the sender's sockaddr; the glue demuxes by
 * (peer addr+port, conn_id) exactly as the standalone listener does. */
void ntx_utp_input(ntx_utp *u, const uint8_t *buf, size_t n,
                   const struct sockaddr_storage *from, socklen_t from_len);
/* Register the session's rw/close callbacks on an accepted virt fd (called via
 * ntx_netx_add when the session arms the peer after accept). 0 ok, -1 bad fd. */
int ntx_utp_bind_fd(ntx_utp *u, int virt_fd, void *ctx, const ntx_cbs *cbs);
/* Tear a virt connection down on the session's behalf (peer drop / close):
 * best-effort FIN then release the slot. Idempotent for an unknown fd. */
void ntx_utp_virt_close(ntx_utp *u, int virt_fd);

#endif
