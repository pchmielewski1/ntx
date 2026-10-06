#include "ntx_session_internal.h"

#include "../ui/ntx_diag.h"
#include "../proto/ntx_btmsg.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <time.h>
#include "ntx_time.h"
#include "../proto/ntx_wire.h"
#include "ntx_hash_msg.h"
#include "ntx_merkle.h"
#include "../crypto/ntx_sha256.h"

/* BEP52 hash-exchange ids — not in the core enum (ntx_session_internal.h).
 * A hash request (21) is answered with hashes (22) or a hash reject (23); a 22/23
 * is only accepted when it correlates with an outstanding 21 we sent. */
enum { MSG_HASH_REQUEST = 21, MSG_HASHES = 22, MSG_HASH_REJECT = 23 };

static struct ntx_session *sp_g_s;

#include "../net/ntx_netx.h"

void sp_process_msgs(struct ntx_session *s, int pi);

void ntx_session_hash_tick(struct ntx_session *s);

void sp_peer_ok_hello(struct ntx_session *s, int pi);

void sp_peer_ok_poll(struct ntx_session *s, int pi);

void sp_peer_arm_io(struct ntx_session *s, int pi) {
    int fd = s->peers[pi].fd;
    if (fd < 0 || !s->netx) return;
    /* EPOLLOUT only when a write is pending. Keeping it for whole PE/BTHS
     * phases busy-spins epoll (writable sockets fire forever). */
    uint32_t ev = EPOLLIN;
    int need_out = 0;
    if (s->peer_out_len[pi] > s->peer_out_off[pi])
        need_out = 1;
    else if (s->peers[pi].conn_t0) /* TCP connect not finished yet */
        need_out = 1;
    else if (s->peer_phase[pi] == PH_PE && s->pe[pi].outn > s->pe[pi].sent)
        need_out = 1;
    if (need_out) ev |= EPOLLOUT;
    ntx_netx_mod(s->netx, fd, ev);
}

uint32_t sp_phave_count(const ntx_peer *p) {
    if (!p || !p->phave || p->phave_n <= 0) return 0;
    uint32_t n = 0;
    for (int i = 0; i < p->phave_n; i++)
        if (p->phave[i]) n++;
    return n;
}

static void sp_hs_dump_stuck(struct ntx_session *s) {
    if (!sp_verbose(s)) return;
    int n_pe = 0, n_bths = 0, n_ok = 0, n_conn = 0;
    int pe_hist[20];
    memset(pe_hist, 0, sizeof pe_hist);
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peers[pi].fd == -1) continue;
        if (s->peer_phase[pi] == PH_OK) {
            n_ok++;
            continue;
        }
        if (s->peers[pi].conn_t0) n_conn++;
        if (s->peer_phase[pi] == PH_PE) {
            n_pe++;
            int st = s->pe[pi].state;
            if (st >= 0 && st < (int)(sizeof pe_hist / sizeof pe_hist[0])) pe_hist[st]++;
        } else if (s->peer_phase[pi] == PH_BTHS)
            n_bths++;
    }
    ntx_diag( "ntx: hs dump stuck pe=%d bths=%d ok=%d still_conn=%d pe_states:", n_pe, n_bths, n_ok,
            n_conn);
    for (int st = 0; st < 17; st++)
        if (pe_hist[st]) ntx_diag( " %s=%d", sp_pe_st_name(st), pe_hist[st]);
    ntx_diag("\n");
    int shown = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS && shown < 12; pi++) {
        if (s->peers[pi].fd == -1 || s->peer_phase[pi] == PH_OK) continue;
        sp_vlog_peer(s, pi, "stuck", "");
        shown++;
    }
}

void sp_drop(struct ntx_session *s, int pi, const char *why) {
    int was_ok = s->peer_phase[pi] == PH_OK;
    int was_unchoke = was_ok && ntx_peer_can_download(&s->peers[pi]);
    int tts = s->peer_tts[pi];
    if (sp_verbose(s)) {
        if (was_ok) {
            char x[96];
            snprintf(x, sizeof x, "why=%s", why ? why : "?");
            sp_vlog_dl(s, pi, "ok_drop", x);
        } else {
            char whybuf[96];
            snprintf(whybuf, sizeof whybuf, "why=%s", why ? why : "?");
            sp_vlog_peer(s, pi, "drop", whybuf);
        }
    }
    if (s->peer_phase[pi] == PH_OK && tts >= 0 && tts < s->n_tts)
        ntx_torrent_on_peer_lost(&s->tts[tts], &s->peers[pi]);
    if (s->peer_phase[pi] == PH_OK && s->peers[pi].n_req > 0)
        ntx_peer_clear_requests(&s->peers[pi]);
    if (was_ok && tts >= 0 && tts < s->n_tts)
        ntx_pex_tx_on_disconnected(&s->pex_tx[tts], &s->peers[pi].addr, s->peers[pi].port);
    /* --utp: a uTP dial that never connected says nothing about TCP reachability, so retry over TCP
     * (below) instead of writing the address off. */
    int utp_miss = s->peer_outbound[pi] && !s->peer_tcp_fb[pi] && !was_ok && s->peers[pi].conn_t0 &&
                   s->peers[pi].fd <= -NTX_UTP_VIRT_BASE && s->cfg && s->cfg->utp && !s->cfg->tunnel;
    ntx_addr miss_addr = s->peers[pi].addr;
    uint16_t miss_port = s->peers[pi].port;
    if (s->peer_outbound[pi] && !utp_miss) { /* redial back-off: remember dead addresses, forget good ones */
        if (was_ok) ntx_dial_bo_ok(&s->dial_bo, &s->peers[pi].addr, s->peers[pi].port);
        else ntx_dial_bo_fail(&s->dial_bo, &s->peers[pi].addr, s->peers[pi].port, ntx_mono_ms());
    }
    ntx_session_peer_free(s, pi);
    if (utp_miss) s->utp_miss_n++;
    if (utp_miss && tts >= 0 && tts < s->n_tts) {
        if (sp_verbose(s)) {
            char x[96];
            snprintf(x, sizeof x, "port=%u", (unsigned)miss_port);
            sp_vlog_peer(s, pi, "utp_miss_tcp_retry", x);
        }
        (void)ntx_session_add_peer_dial_tcp(s, tts, &miss_addr, miss_port);
    }
    if (was_unchoke && tts >= 0 && tts < s->n_tts) {
        int un = 0;
        int partial = 0;
        for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++)
            if (s->peer_phase[i] == PH_OK && ntx_peer_can_download(&s->peers[i])) un++;
        if (s->piece_bytes[tts]) {
            ntx_torrent *t = &s->tts[tts];
            for (uint32_t j = 0; j < t->np; j++)
                if (!t->have[j] && s->piece_bytes[tts][j] > 0) {
                    partial = 1;
                    break;
                }
        }
        s->trk_next[tts] = ntx_mono_ms() + (un == 0 ? 200 : 500);
        if (un == 0 || partial)
            ntx_session_trk_boost_peers(s);
        ntx_session_data_refill(s, tts);
    } else if (tts >= 0 && tts < s->n_tts && s->tts[tts].state == NTX_TTS_DL) {
        ntx_session_data_refill(s, tts);
    }
}

static void sp_rw_cb(int fd, void *ctx) {
    if (sp_g_s) ntx_session_peer_on_rw(sp_g_s, fd, ctx);
}

static void peer_cl_cb(void *ctx) {
    if (sp_g_s) ntx_session_peer_on_close(sp_g_s, ctx);
}

void ntx_session_peer_on_connect(struct ntx_session *s, int fd, void *ctx) {
    sp_g_s = s;
    int pi = (int)(intptr_t)ctx - 1;
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    if (s->peers[pi].fd != fd) return;
    if (s->peer_phase[pi] != PH_PE) {
        ntx_session_peer_out_flush(s, pi);
        return;
    }
    if (fd >= 0) {
        if (!ntx_netx_peer_connected(s->netx, fd)) {
            sp_drop(s, pi, "connect_fail");
            return;
        }
    } else if (!ntx_netx_peer_connected(s->netx, fd)) {
        return;
    }
    if (s->peers[pi].st == NTX_PEER_ST_HS && s->pe[pi].state == 0) {
        s->peers[pi].conn_t0 = 0;
        s->peers[pi].hs_t0 = ntx_mono_ms();
        ntx_pe_init(&s->pe[pi], NTX_PE_INITIATOR, fd);
        ntx_pe_set_netx(&s->pe[pi], s->netx);
        sp_pe_set_infohash(s, pi);
        {
            uint8_t hs[68];
            sp_build_bt_handshake(s, pi, hs);
            ntx_pe_set_bt_handshake(&s->pe[pi], hs);
        }
        sp_peer_arm_io(s, pi);
        sp_vlog_peer(s, pi, "tcp_ok", "pe initiator start");
    }
    sp_pe_drive(s, pi);
    sp_pe_finish(s, pi);
    sp_peer_arm_io(s, pi);
    if (s->peer_phase[pi] != PH_PE)
        ntx_session_peer_on_rw(s, fd, ctx);
}

void ntx_session_peer_on_accept(struct ntx_session *s, ntx_netx *n, int peer_fd, void *ctx) {
    (void)ctx;
    sp_g_s = s;
    int pi = -1;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++) {
        if (s->peers[i].fd == peer_fd) {
            pi = i;
            break;
        }
    }
    if (pi < 0) return;
    s->peers[pi].conn_t0 = 0;
    s->peers[pi].hs_t0 = ntx_mono_ms();
    ntx_pe_init(&s->pe[pi], NTX_PE_RESPONDER, peer_fd);
    ntx_pe_set_netx(&s->pe[pi], s->netx);
    sp_pe_set_infohash(s, pi);
    {
        uint8_t hs[68];
        sp_build_bt_handshake(s, pi, hs);
        ntx_pe_set_bt_handshake(&s->pe[pi], hs);
    }
    ntx_cbs cbs = {sp_rw_cb, sp_rw_cb, peer_cl_cb};
    ntx_netx_add(n, peer_fd, EPOLLIN | EPOLLOUT, (void *)(intptr_t)(pi + 1), &cbs);
    sp_vlog_peer(s, pi, "accept", "pe responder start");
    sp_pe_drive(s, pi);
    sp_pe_finish(s, pi);
    sp_peer_arm_io(s, pi);
    if (s->peer_phase[pi] != PH_PE)
        ntx_session_peer_on_rw(s, peer_fd, (void *)(intptr_t)(pi + 1));
}

void ntx_session_peer_hs_tick(struct ntx_session *s) {
    static int ok_poll_rr;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peers[pi].fd == -1) continue;
        if (s->peer_phase[pi] == PH_PE && s->peers[pi].st == NTX_PEER_ST_HS) {
            int fd = s->peers[pi].fd;
            if (NTX_NETX_IS_LIVE_FD(fd) && ntx_netx_peer_connected(s->netx, fd) && s->pe[pi].state == 0)
                ntx_session_peer_on_connect(s, fd, (void *)(intptr_t)(pi + 1));
        }
        if (s->peer_phase[pi] == PH_PE || s->peer_phase[pi] == PH_BTHS)
            ntx_session_peer_on_rw(s, s->peers[pi].fd, (void *)(intptr_t)(pi + 1));
    }
    /* OK peers: round-robin read (INTERESTED/REQUEST) — polling all 80+ every tick
     * burned CPU; polling none broke seed upload when epoll didn't re-fire. */
    for (int n = 0, scanned = 0; scanned < NTX_SESSION_MAX_PEERS && n < NTX_PEER_OK_POLL_BATCH;
         scanned++) {
        int pi = (ok_poll_rr + scanned) % NTX_SESSION_MAX_PEERS;
        if (s->peers[pi].fd == -1 || s->peer_phase[pi] != PH_OK) continue;
        sp_peer_ok_poll(s, pi);
        n++;
    }
    ok_poll_rr = (ok_poll_rr + NTX_PEER_OK_POLL_BATCH) % NTX_SESSION_MAX_PEERS;
    uint64_t now = ntx_mono_ms();
    uint64_t hs_lim = (uint64_t)NTX_PEER_HS_TIMEOUT_S * 1000u;
    uint64_t conn_lim = (uint64_t)NTX_PEER_CONN_TIMEOUT_S * 1000u;
    {   /* A SYN unanswered for 2.5 s almost never gets through: while few peers work, recycle the slot sooner. */
        int ok_n = 0;
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
            if (s->peers[pi].fd != -1 && s->peer_phase[pi] == PH_OK) ok_n++;
        if (ok_n < NTX_MIN_OK_PEERS) conn_lim = NTX_PEER_CONN_TIMEOUT_FAST_MS;
    }
    int conn_dropped = 0;
    int hs_dropped = 0;
    uint64_t idle_lim = (uint64_t)NTX_PEER_IDLE_TIMEOUT_S * 1000u;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peers[pi].fd != -1 && s->peer_phase[pi] == PH_OK) {
            /* hs_t0 doubles as "became OK at" for PH_OK peers */
            uint64_t ref = s->peers[pi].rx_t0 > s->peers[pi].hs_t0 ? s->peers[pi].rx_t0 : s->peers[pi].hs_t0;
            if (ref && now > ref && now - ref > idle_lim) sp_drop(s, pi, "idle");
            continue;
        }
        if (s->peers[pi].fd == -1) continue;
        if (s->peers[pi].conn_t0) {
            int fd = s->peers[pi].fd;
            if (fd >= 0) {
                int err = 0;
                socklen_t elen = sizeof err;
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
                if (err != 0) {
                    sp_drop(s, pi, "connect_fail");
                    conn_dropped++;
                    continue;
                }
            }
            uint64_t lim = conn_lim;
            if (s->peers[pi].fd <= -NTX_UTP_VIRT_BASE && s->peer_outbound[pi] && !s->peer_tcp_fb[pi] &&
                s->cfg && s->cfg->utp && !s->cfg->tunnel && lim > NTX_UTP_DIAL_MS)
                lim = NTX_UTP_DIAL_MS;
            if (now > s->peers[pi].conn_t0 && now - s->peers[pi].conn_t0 > lim) {
                sp_drop(s, pi, "conn_timeout");
                conn_dropped++;
            }
            continue;
        }
        if (!s->peers[pi].hs_t0) continue;
        if (now > s->peers[pi].hs_t0 && now - s->peers[pi].hs_t0 > hs_lim) {
            sp_drop(s, pi, "hs_timeout");
            hs_dropped++;
        }
    }
    if (conn_dropped || hs_dropped) {
        if (sp_verbose(s)) {
            if (conn_dropped) ntx_diag( "ntx: hs batch conn_timeout=%d\n", conn_dropped);
            if (hs_dropped) ntx_diag( "ntx: hs batch hs_timeout=%d\n", hs_dropped);
        }
        ntx_session_trk_boost_peers(s);
    }
    /* Periodic stuck snapshot (~5 s @ 100 ms tick from session). */
    static uint64_t last_dump;
    if (sp_verbose(s) && (last_dump == 0 || now - last_dump >= 5000)) {
        last_dump = now;
        sp_hs_dump_stuck(s);
    }
    /* BEP52: drive the outbound hash exchange (pump missing 21s, time out
     * outstanding, bounded layers-stall) on every tick. */
    ntx_session_hash_tick(s);
}

/* BEP52: serve an inbound hash request (21) with hashes (22) or a hash
 * reject (23). See BEP 52 (hash request/hashes/hash reject).
 *
 * Every well-framed 21 answers 22 OR 23. Reject (payload identical to the
 * request) when: constraints fail (length pow2>=2, index%length), the pieces
 * root is unknown to this peer's torrent, the file has no piece layer
 * (len <= piece length), the file is not fully downloaded, or the request
 * asks for a layer/proof span beyond the merkle tree. Otherwise build 22:
 * the base-layer span [index, index+length) plus one uncle per present proof
 * layer up to the one nearest the root; the first log2(length)-1 proof layers
 * are omitted from the wire (the requested span already contains them) but
 * still count towards proof_layers. Choke does not gate serving (BEP52: hash
 * requests are allowed while choked). */
static void sp_serve_hash_request(struct ntx_session *s, int pi, const uint8_t *frame, size_t flen) {
    ntx_hash_req req;
    if (ntx_hash_msg_parse_request(frame, flen, &req) != 0) return;
    int ti = s->peer_tts[pi];
    ntx_torrent *t = (ti >= 0 && ti < s->n_tts) ? &s->tts[ti] : NULL;

    /* BEP52: every well-framed 21 answers 22 OR 23 — a constraints violation is
     * a refusal (23), never silence. */
    if (!ntx_hash_req_constraints_ok(&req)) {
        uint8_t rej[5 + NTX_HASH_REQ_PAYLOAD];
        size_t n = ntx_hash_msg_build_reject(rej, sizeof rej, &req);
        if (n) ntx_session_peer_send_raw(s, pi, rej, n);
        return;
    }

    /* Rate gate (like piece requests): each servable 21 reads the
     * whole file and rebuilds its merkle tree, so a peer already at its
     * outstanding-request budget (the same n_req / NTX_PEER_MAX_REQ cap that
     * throttles piece serving) is refused with a 23 rather than driving the
     * per-request CPU/mem amplification. Reuses the existing budget; no new cache. */
    if (ntx_peer_req_count(&s->peers[pi]) >= NTX_PEER_MAX_REQ) {
        uint8_t rej[5 + NTX_HASH_REQ_PAYLOAD];
        size_t n = ntx_hash_msg_build_reject(rej, sizeof rej, &req);
        if (n) ntx_session_peer_send_raw(s, pi, rej, n);
        return;
    }

    int f = -1;
    uint32_t pl_off = 0; /* offset (bytes) of this file inside t->piece_layer */
    if (t && t->meta_version == 2 && t->have_meta) {
        uint32_t acc = 0;
        for (uint32_t i = 0; i < t->v2_nfiles; i++) {
            if (f < 0 && memcmp(t->v2_root[i], req.pieces_root, 32) == 0) {
                f = (int)i;
                pl_off = acc;
            }
            if (t->v2_len_file[i] > t->ps) acc += t->v2_np_file[i] * 32u;
        }
    }
    if (f < 0) {
        uint8_t rej[5 + NTX_HASH_REQ_PAYLOAD];
        size_t n = ntx_hash_msg_build_reject(rej, sizeof rej, &req);
        if (n) ntx_session_peer_send_raw(s, pi, rej, n);
        return;
    }

    uint64_t file_len = t->v2_len_file[f];
    uint32_t npf = t->v2_np_file[f];
    uint32_t fp = t->v2_first_piece[f];
    uint32_t ps = t->ps;
    int serviceable = 0;
    size_t hashes_nbytes = 0;
    uint8_t *hashes = NULL;
    if (file_len > 0 && file_len <= (uint64_t)SIZE_MAX && ps >= NTX_MERKLE_LEAF && npf > 0 &&
        file_len > (uint64_t)ps && t->piece_layer && t->piece_layer_n >= (size_t)pl_off + (size_t)npf * 32) {
        /* All of the file's pieces must be present to recompute its tree. */
        int have_all = t->have != NULL;
        for (uint32_t k = 0; have_all && k < npf; k++)
            if (fp + k >= t->np || !t->have[fp + k]) have_all = 0;
        uint32_t n_leaf = (uint32_t)((file_len + NTX_MERKLE_LEAF - 1) / NTX_MERKLE_LEAF);
        size_t p = 1;
        while (p < n_leaf) p <<= 1;
        uint32_t height = 0;
        { size_t q = p; while (q > 1) { q >>= 1; height++; } }
        uint32_t piece_layer = 0;
        { uint32_t r = ps / NTX_MERKLE_LEAF; while (r > 1) { r >>= 1; piece_layer++; } }
        uint32_t lg = 0;
        { uint32_t r = req.length; while (r > 1) { r >>= 1; lg++; } }
        /* Uncles on the wire: one per proof layer above the omitted floor.
         * The first log2(length)-1 proof layers are contained in the
         * requested span (omitted, still counted in proof_layers); when
         * proof_layers does not reach that floor there are no uncles and the
         * response is just the base span. */
        uint32_t uncles = (req.proof_layers >= lg) ? (req.proof_layers - lg + 1u) : 0u;
        /* The requested span must fit the base layer's width (p >> base_layer
         * slots). index is attacker-controlled and is NOT covered by the
         * constraints check (index % length), so without this bound a legal
         * base/length with a huge index reads past the p-slots tree allocation
         * in the extraction below (and the uncle path). Bounding the base span
         * also bounds the uncle nodes: node = index >> lg < (index + length) >> lg
         * <= width >> lg = width of the deepest proof layer, so node ^ 1 stays in
         * range for every layer up to the root. base_layer is attacker-controlled
         * too, so p >> base_layer (UB once base_layer >= 32) is only evaluated
         * after the cheap geometry guards prove base_layer <= height (< 32). */
        int in_bounds = 0;
        if (have_all && req.base_layer <= height && height >= lg &&
            req.base_layer + lg <= height &&
            (uncles == 0 || req.base_layer + req.proof_layers <= height - 1)) {
            uint32_t base_width = (uint32_t)(p >> req.base_layer);
            in_bounds = (uint64_t)req.index + req.length <= base_width;
        }
        if (in_bounds) {
            hashes_nbytes = ((size_t)req.length + uncles) * 32;
            hashes = malloc(hashes_nbytes ? hashes_nbytes : 1);
            if (hashes) {
                /* Full merkle tree, leaves up to root, p-slots per leaf layer,
                 * balanced with the fold of the zero leaf value (ntx_merkle.c). */
                size_t tot = p * 2 - 1;
                uint8_t *tree = malloc(tot * 32);
                if (tree) {
                    uint8_t *data = malloc((size_t)file_len);
                    int read_ok = data != NULL;
                    if (read_ok) {
                        uint64_t got = 0;
                        for (uint32_t k = 0; read_ok && k < npf; k++) {
                            uint64_t pstart = (uint64_t)k * ps;
                            uint32_t plen_k =
                                (uint32_t)((file_len - pstart < (uint64_t)ps) ? (size_t)(file_len - pstart) : ps);
                            int got_k = ntx_store_read(&t->store, fp + k, 0, data + pstart, plen_k);
                            if (got_k != (int)plen_k) read_ok = 0;
                            got += (uint64_t)(got_k > 0 ? got_k : 0);
                        }
                        if (got != file_len) read_ok = 0;
                    }
                    if (read_ok) {
                        size_t base = 0; /* tree offset (slots) of leaf layer */
                        size_t sz = p;
                        for (size_t i = 0; i < sz; i++) {
                            size_t off = i * NTX_MERKLE_LEAF;
                            size_t len = (off < (size_t)file_len) ? ((size_t)file_len - off) : 0;
                            if (len > NTX_MERKLE_LEAF) len = NTX_MERKLE_LEAF;
                            ntx_sha256(data + off, len, tree + (base + i) * 32);
                        }
                        for (size_t i = n_leaf; i < sz; i++) memset(tree + (base + i) * 32, 0, 32);
                        uint8_t fill[32], tmp[64];
                        memset(fill, 0, 32);
                        for (uint32_t i = 0; i < piece_layer; i++) {
                            memcpy(tmp, fill, 32);
                            memcpy(tmp + 32, fill, 32);
                            ntx_sha256(tmp, 64, fill);
                        }
                        size_t layer_base[64];
                        layer_base[0] = 0;
                        for (uint32_t l = 0; l < height; l++) {
                            size_t parent = base + sz; /* slot 0 of the parent layer */
                            sz >>= 1;
                            for (size_t j = 0; j < sz; j++) {
                                memcpy(tmp, tree + (base + j * 2) * 32, 32);
                                memcpy(tmp + 32, tree + (base + j * 2 + 1) * 32, 32);
                                ntx_sha256(tmp, 64, tree + (parent + j) * 32);
                            }
                            if (l + 1 == piece_layer) { /* overlay canonical stored piece layer */
                                uint32_t np_have = (uint32_t)(t->piece_layer_n - pl_off) / 32u;
                                if (np_have > npf) np_have = npf;
                                for (uint32_t j = 0; j < np_have; j++)
                                    memcpy(tree + (parent + j) * 32, t->piece_layer + pl_off + (size_t)j * 32, 32);
                                for (uint32_t j = np_have; j < sz; j++)
                                    memcpy(tree + (parent + j) * 32, fill, 32);
                            }
                            base = parent;
                            layer_base[l + 1] = parent;
                        }
                        /* Extract the base span and the proof uncles. layer_base is
                         * a slot index; the byte offset is slot * 32. */
                        size_t bl_base = layer_base[req.base_layer] * 32;
                        for (uint32_t i = 0; i < req.length; i++)
                            memcpy(hashes + (size_t)i * 32, tree + bl_base + (size_t)(req.index + i) * 32, 32);
                        uint32_t sub_layer = req.base_layer + lg;
                        uint32_t sub_node = req.index >> lg;
                        size_t wp = (size_t)req.length * 32;
                        for (uint32_t i = lg; i <= req.proof_layers; i++) {
                            uint32_t layer = req.base_layer + i;
                            uint32_t node = sub_node >> (layer - sub_layer);
                            memcpy(hashes + wp, tree + layer_base[layer] * 32 + (size_t)(node ^ 1) * 32, 32);
                            wp += 32;
                        }
                        serviceable = 1;
                    }
                    free(data);
                    free(tree);
                }
            }
        }
    }

    if (serviceable) {
        size_t cap = 5 + NTX_HASH_REQ_PAYLOAD + hashes_nbytes;
        uint8_t *resp = malloc(cap);
        if (resp) {
            size_t n = ntx_hash_msg_build_hashes(resp, cap, &req, hashes, hashes_nbytes);
            if (n) ntx_session_peer_send_raw(s, pi, resp, n);
            free(resp);
        }
    } else {
        uint8_t rej[5 + NTX_HASH_REQ_PAYLOAD];
        size_t n = ntx_hash_msg_build_reject(rej, sizeof rej, &req);
        if (n) ntx_session_peer_send_raw(s, pi, rej, n);
    }
    free(hashes);
}

/* ---- BEP52 outbound hash exchange --------------------------------- *
 *
 * A pure-v2 torrent that got its info dict via BEP9 ut_metadata has no
 * top-level "piece layers" (ut_metadata only carries the info dict), so the
 * piece-length hashes must come from the BEP52 hash exchange: we send a hash
 * request (21) per file that still needs its piece layer, the peer answers
 * with hashes (22) or a hash reject (23). The verified base-layer hashes are
 * folded into a scratch buffer and, once every file has its layer, committed
 * through ntx_torrent_apply_piece_layer (which re-validates against the pieces
 * roots before the bytes are trusted). See BEP 52. */

#define NTX_HASH_TIMEOUT_MS 8000u  /* outstanding 21 older than this is retried */
#define NTX_HASH_STALL_MS   60000u /* no peer at all for this long -> bounded stall */
#define NTX_HASH_TRIES_MAX  6u     /* attempts per file layer before giving up (bounded) */

/* Count OK peers bound to torrent ti that can carry a 21. */
static int sp_hash_ok_peers(struct ntx_session *s, int ti) {
    int n = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_phase[pi] == PH_OK && s->peer_tts[pi] == ti && s->peers[pi].fd != -1) n++;
    return n;
}

/* Clear every per-torrent hash-exchange scratch/state for slot ti (add/reuse/free).
 * The global counters are session totals and intentionally survive. */
void ntx_session_hash_reset(struct ntx_session *s, int ti) {
    if (!s || ti < 0 || ti >= NTX_SESSION_MAX_TTS) return;
    free(s->hash_scratch[ti]);
    s->hash_scratch[ti] = NULL;
    s->hash_scratch_n[ti] = 0;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) s->hash_out_used[ti][k] = 0;
    memset(s->hash_have[ti], 0, sizeof s->hash_have[ti]);
    memset(s->hash_tries[ti], 0, sizeof s->hash_tries[ti]);
    s->hash_rr[ti] = 0;
    s->hash_ok_seen[ti] = 0;
    s->hash_stall_t0[ti] = 0;
}

/* Total bytes of the torrent's piece-layer string (sum of np*32 over the files
 * with len > ps), matching the tt_v2_piece_ok layout. */
static size_t sp_hash_layer_total(const ntx_torrent *t) {
    size_t total = 0;
    for (uint32_t i = 0; i < t->v2_nfiles; i++)
        if (t->v2_len_file[i] > t->ps) total += (size_t)t->v2_np_file[i] * 32;
    return total;
}

/* File offset (bytes) inside the torrent piece-layer string. */
static size_t sp_hash_file_off(const ntx_torrent *t, uint32_t f) {
    size_t off = 0;
    for (uint32_t g = 0; g < f; g++)
        if (t->v2_len_file[g] > t->ps) off += (size_t)t->v2_np_file[g] * 32;
    return off;
}

/* Build the whole-piece-layer 21 header for file f: base_layer = the piece
 * layer, index = 0, length = next_pow2(np) (>= 2), proof_layers = the levels
 * from base_layer+log2(length) up to the root. Returns 1 on a well-formed
 * request, 0 when the geometry is not requestable (single-piece file, degenerate
 * tree). */
static int sp_hash_build_req(const ntx_torrent *t, uint32_t f, ntx_hash_req *r) {
    uint64_t file_len = t->v2_len_file[f];
    uint32_t np = t->v2_np_file[f];
    uint32_t ps = t->ps;
    if (file_len <= (uint64_t)ps || np < 2 || ps < NTX_MERKLE_LEAF) return 0;
    uint32_t n_leaf = (uint32_t)((file_len + NTX_MERKLE_LEAF - 1) / NTX_MERKLE_LEAF);
    uint32_t p = 1;
    while (p < n_leaf) p <<= 1;
    if (p < 2) return 0;
    uint32_t height = 0;
    { uint32_t q = p; while (q > 1) { q >>= 1; height++; } }
    uint32_t piece_layer = 0;
    { uint32_t r2 = ps / NTX_MERKLE_LEAF; while (r2 > 1) { r2 >>= 1; piece_layer++; } }
    uint32_t length = 1;
    while (length < np) length <<= 1;
    if (length < 2) length = 2;
    uint32_t lg = 0;
    { uint32_t r2 = length; while (r2 > 1) { r2 >>= 1; lg++; } }
    if (piece_layer + lg > height) return 0;
    memset(r, 0, sizeof *r);
    memcpy(r->pieces_root, t->v2_root[f], 32);
    r->base_layer = piece_layer;
    r->index = 0;
    r->length = length;
    r->proof_layers = height - piece_layer - 1;
    return ntx_hash_req_constraints_ok(r);
}

/* Free every outstanding 21 slot for torrent ti (peer gone / reset). */
static void sp_hash_clear_out(struct ntx_session *s, int ti) {
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) s->hash_out_used[ti][k] = 0;
}

/* Enqueue + send a 21 per file still missing its piece layer, to OK peers bound
 * to torrent ti. Bounded queue (NTX_HASH_OUT_MAX outstanding), one request per
 * (file) at a time, rate-limited by the shared piece-request budget: a peer at
 * its NTX_PEER_MAX_REQ cap is skipped (the serve side reuses the same cap). */
static void sp_hash_pump(struct ntx_session *s, int ti) {
    ntx_torrent *t = &s->tts[ti];
    if (!ntx_torrent_layers_pending(t) || t->layers_stall) return;
    size_t total = sp_hash_layer_total(t);
    if (total == 0) return;
    if (!s->hash_scratch[ti]) {
        s->hash_scratch[ti] = calloc(1, total);
        if (!s->hash_scratch[ti]) return;
        s->hash_scratch_n[ti] = total;
        memset(s->hash_have[ti], 0, sizeof s->hash_have[ti]);
        sp_hash_clear_out(s, ti);
    }
    int used = 0;
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++)
        if (s->hash_out_used[ti][k]) used++;
    if (used >= NTX_HASH_OUT_MAX) return;

    /* round-robin start peer so a busy peer is not hammered. */
    int start = s->hash_rr[ti] % NTX_SESSION_MAX_PEERS;
    s->hash_rr[ti] = (uint8_t)((s->hash_rr[ti] + 1) % NTX_SESSION_MAX_PEERS);
    int gave_up = 0;
    for (uint32_t f = 0; f < t->v2_nfiles; f++) {
        if (t->v2_len_file[f] <= t->ps) continue; /* single-piece: null-layer path */
        if (s->hash_have[ti][f]) continue;
        int already = 0;
        for (int k = 0; k < NTX_HASH_OUT_MAX; k++)
            if (s->hash_out_used[ti][k] && s->hash_out_file[ti][k] == (int32_t)f) already = 1;
        if (already) continue;
        /* Bounded attempts per file layer: once a file has been asked for
         * NTX_HASH_TRIES_MAX times without completing, stop asking it (so a peer
         * that keeps timing out / rejecting cannot drive 21s forever). */
        if (s->hash_tries[ti][f] >= NTX_HASH_TRIES_MAX) { gave_up = 1; continue; }
        ntx_hash_req req;
        if (!sp_hash_build_req(t, f, &req)) continue;
        int chosen = -1;
        for (int n = 0; n < NTX_SESSION_MAX_PEERS; n++) {
            int pi = (start + n) % NTX_SESSION_MAX_PEERS;
            if (s->peer_phase[pi] != PH_OK || s->peer_tts[pi] != ti) continue;
            if (s->peers[pi].fd == -1) continue;
            if (ntx_peer_req_count(&s->peers[pi]) >= NTX_PEER_MAX_REQ) continue;
            chosen = pi;
            break;
        }
        if (chosen < 0) continue;
        uint8_t frame[5 + NTX_HASH_REQ_PAYLOAD];
        size_t fn = ntx_hash_msg_build_request(frame, sizeof frame, &req);
        if (!fn) continue;
        if (ntx_session_peer_send_raw(s, chosen, frame, fn) != 0) continue;
        int slot = -1;
        for (int k = 0; k < NTX_HASH_OUT_MAX; k++)
            if (!s->hash_out_used[ti][k]) { slot = k; break; }
        if (slot < 0) break;
        s->hash_out_used[ti][slot] = 1;
        s->hash_out_req[ti][slot] = req;
        s->hash_out_file[ti][slot] = (int32_t)f;
        s->hash_out_peer[ti][slot] = chosen;
        s->hash_out_t0[ti][slot] = ntx_mono_ms();
        if (s->hash_tries[ti][f] < NTX_HASH_TRIES_MAX) s->hash_tries[ti][f]++;
        s->hash_req_tx++;
        used++;
        if (used >= NTX_HASH_OUT_MAX) break;
    }
    /* Nothing in flight and at least one needed file hit its attempt cap → the
     * exchange has exhausted the peers it has: bounded stall (re-triable when a
     * genuinely new peer appears, see ntx_session_hash_tick). */
    if (gave_up) {
        int inflight = 0;
        for (int k = 0; k < NTX_HASH_OUT_MAX; k++) if (s->hash_out_used[ti][k]) inflight = 1;
        if (!inflight) t->layers_stall = 1;
    }
}

/* Correlate an inbound 22/23 against an outstanding 21 sent TO THIS PEER (pi),
 * matching the full header (pieces_root, base_layer, index, length,
 * proof_layers). Binding to the source peer stops one peer from satisfying a
 * request we sent to a different one. Returns the slot or -1. */
static int sp_hash_match(struct ntx_session *s, int ti, int peer, const ntx_hash_req *h) {
    for (int k = 0; k < NTX_HASH_OUT_MAX; k++) {
        if (!s->hash_out_used[ti][k]) continue;
        if (s->hash_out_peer[ti][k] != peer) continue;
        ntx_hash_req *o = &s->hash_out_req[ti][k];
        if (memcmp(o->pieces_root, h->pieces_root, 32) != 0) continue;
        if (o->base_layer != h->base_layer || o->index != h->index) continue;
        if (o->length != h->length || o->proof_layers != h->proof_layers) continue;
        return k;
    }
    return -1;
}

/* RX 22: hashes. MUST correlate with an outstanding 21 (carried ruling) — a
 * header that matches nothing is ignored (no ingest trust) + counter. A verified
 * base-layer span is folded into the scratch buffer; when every file has its
 * layer the whole string is committed via apply_piece_layer. A failed proof
 * (-1) drops the request so another peer can be tried. */
static void sp_rx_hashes(struct ntx_session *s, int pi, const uint8_t *frame, size_t flen) {
    int ti = s->peer_tts[pi];
    if (ti < 0 || ti >= s->n_tts) return;
    ntx_torrent *t = &s->tts[ti];
    if (!ntx_torrent_layers_pending(t)) return;
    ntx_hash_req hdr;
    const uint8_t *hashes;
    size_t hn;
    if (ntx_hash_msg_parse_hashes(frame, flen, &hdr, &hashes, &hn) != 0) {
        s->hash_ignore++;
        return;
    }
    int slot = sp_hash_match(s, ti, pi, &hdr);
    if (slot < 0) { /* 22 not matching an outstanding 21 we sent to THIS peer → ignore, no ingest */
        s->hash_ignore++;
        return;
    }
    uint32_t f = (uint32_t)s->hash_out_file[ti][slot];
    if (f >= t->v2_nfiles || t->v2_len_file[f] <= t->ps) {
        s->hash_out_used[ti][slot] = 0;
        s->hash_ignore++;
        return;
    }
    size_t out_cap = (size_t)hdr.length * 32;
    uint8_t *out = malloc(out_cap ? out_cap : 1);
    if (!out) { s->hash_out_used[ti][slot] = 0; return; }
    size_t on = 0;
    int rc = ntx_merkle_ingest_hashes(t->v2_root[f], hdr.base_layer, hdr.index, hdr.length,
                                      hdr.proof_layers, hashes, hn, out, out_cap, &on);
    if (rc != 0) { /* bogus 22: drop, mark request failed (retry via another peer) */
        free(out);
        s->hash_out_used[ti][slot] = 0;
        s->hash_rej++;
        return;
    }
    /* The verified base span is length*32 hashes; only the first np*32 are the
     * real piece hashes (the rest are balance slots). Clamp to the per-file slice
     * so a length > np response cannot overrun into the next file's region, and
     * require the full np slice before trusting the file. */
    size_t need = (size_t)t->v2_np_file[f] * 32;
    if (on > need) on = need;
    if (on < need) { free(out); s->hash_out_used[ti][slot] = 0; s->hash_rej++; return; }
    size_t off = sp_hash_file_off(t, f);
    if (off + on <= s->hash_scratch_n[ti]) {
        memcpy(s->hash_scratch[ti] + off, out, on);
        s->hash_have[ti][f] = 1;
    }
    free(out);
    s->hash_out_used[ti][slot] = 0;
    s->hash_req_rx_ok++;
    /* all files present? commit. */
    int all = 1;
    for (uint32_t g = 0; g < t->v2_nfiles; g++)
        if (t->v2_len_file[g] > t->ps && !s->hash_have[ti][g]) { all = 0; break; }
    if (all) {
        if (ntx_torrent_apply_piece_layer(t, s->hash_scratch[ti], s->hash_scratch_n[ti]) == 0) {
            size_t got = s->hash_scratch_n[ti];
            free(s->hash_scratch[ti]);
            s->hash_scratch[ti] = NULL;
            s->hash_scratch_n[ti] = 0;
            sp_hash_clear_out(s, ti);
            memset(s->hash_tries[ti], 0, sizeof s->hash_tries[ti]);
            if (sp_verbose(s))
                ntx_diag( "ntx: layers acquired ti=%d bytes=%zu\n", ti, got);
        } else {
            /* validation failed: discard the scratch so the exchange restarts clean */
            free(s->hash_scratch[ti]);
            s->hash_scratch[ti] = NULL;
            s->hash_scratch_n[ti] = 0;
            memset(s->hash_have[ti], 0, sizeof s->hash_have[ti]);
        }
    }
}

/* RX 23: hash reject. Correlate with an outstanding 21; a matching reject marks
 * the request failed (slot freed so the pump rotates to the next peer). An
 * unknown 23 is ignored. */
static void sp_rx_reject(struct ntx_session *s, int pi, const uint8_t *frame, size_t flen) {
    int ti = s->peer_tts[pi];
    if (ti < 0 || ti >= s->n_tts) return;
    ntx_torrent *t = &s->tts[ti];
    if (!ntx_torrent_layers_pending(t)) return;
    ntx_hash_req hdr;
    if (ntx_hash_msg_parse_reject(frame, flen, &hdr) != 0) {
        s->hash_ignore++;
        return;
    }
    int slot = sp_hash_match(s, ti, pi, &hdr);
    if (slot < 0) {
        s->hash_ignore++;
        return;
    }
    s->hash_out_used[ti][slot] = 0;
    s->hash_rej++;
}

/* Session-tick driver: pump missing 21s and enforce the bounded timeout/rotate
 * and the layers-stall phase (all peers gone/rejected → bounded, not an infinite
 * meta loop). A bounded stall is re-triable: a genuinely new peer (the OK-peer
 * count rising) re-arms the exchange by clearing the stall and the per-file
 * attempt counters. */
void ntx_session_hash_tick(struct ntx_session *s) {
    uint64_t now = ntx_mono_ms();
    for (int ti = 0; ti < s->n_tts; ti++) {
        ntx_torrent *t = &s->tts[ti];
        if (!ntx_torrent_layers_pending(t)) {
            if (s->hash_scratch[ti]) {
                free(s->hash_scratch[ti]);
                s->hash_scratch[ti] = NULL;
                s->hash_scratch_n[ti] = 0;
            }
            s->hash_stall_t0[ti] = 0;
            s->hash_ok_seen[ti] = 0;
            continue;
        }
        int ok_peers = sp_hash_ok_peers(s, ti);
        if (ok_peers > s->hash_ok_seen[ti]) { /* a new peer appeared → retry a stalled exchange */
            t->layers_stall = 0;
            memset(s->hash_tries[ti], 0, sizeof s->hash_tries[ti]);
            s->hash_stall_t0[ti] = now;
        }
        s->hash_ok_seen[ti] = (uint8_t)(ok_peers > 255 ? 255 : ok_peers);
        if (t->layers_stall) continue;
        if (!s->hash_stall_t0[ti]) s->hash_stall_t0[ti] = now;
        /* timeout outstanding 21s so the pump rotates to another peer. */
        for (int k = 0; k < NTX_HASH_OUT_MAX; k++) {
            if (!s->hash_out_used[ti][k]) continue;
            if (now > s->hash_out_t0[ti][k] &&
                now - s->hash_out_t0[ti][k] > NTX_HASH_TIMEOUT_MS) {
                s->hash_out_used[ti][k] = 0;
                s->hash_rej++;
            }
        }
        if (ok_peers == 0) {
            if (now - s->hash_stall_t0[ti] > NTX_HASH_STALL_MS) {
                t->layers_stall = 1; /* bounded: stop the loop until a peer appears */
                if (sp_verbose(s))
                    ntx_diag( "ntx: layers-stall ti=%d (no peers %ums)\n", ti, NTX_HASH_STALL_MS);
                continue;
            }
        } else {
            s->hash_stall_t0[ti] = now;
        }
        sp_hash_pump(s, ti);
    }
}

void sp_process_msgs(struct ntx_session *s, int pi) {
    if (s->peer_tts[pi] < 0 || s->peer_tts[pi] >= s->n_tts) return;
    if (s->peer_phase[pi] != PH_OK) return;
    uint8_t *buf = s->peer_buf[pi];
    size_t *bl = &s->peer_buflen[pi];
    ntx_torrent *t = &s->tts[s->peer_tts[pi]];
    while (*bl >= 4) {
        uint32_t total_len = ntx_wire_rd32(buf);
        if (total_len == 0) {
            memmove(buf, buf + 4, *bl - 4);
            *bl -= 4;
            continue;
        }
        if (total_len > (uint32_t)(NTX_PEER_BUF - 4)) {
            if (s->cfg && s->cfg->verbose) {
                ntx_diag( "ntx: peer bad len pi=%d len=%u bl=%zu b4=%02x%02x%02x%02x\n", pi, total_len,
                        *bl, buf[0], buf[1], buf[2], buf[3]);
            }
            sp_drop(s, pi, "bad_msg_len");
            return;
        }
        if (*bl < 4 + (size_t)total_len) break;
        uint8_t type = buf[4];
        uint8_t *payload = buf + 5;
        size_t plen = (size_t)total_len - 1;
        switch (type) {
        case MSG_HAVE:
            if (plen >= 4) {
                uint32_t idx = ntx_wire_rd32(payload);
                ntx_peer_set_phave(&s->peers[pi], idx, 1);
                ntx_torrent_on_peer_have(t, idx);
            }
            break;
        case MSG_BITFIELD: {
            ntx_torrent *tt = &s->tts[s->peer_tts[pi]];
            if (!tt->have_meta) {
                s->peer_have_none_pending[pi] = 0;
                free(s->peer_bf_pending[pi]);
                s->peer_bf_pending[pi] = malloc(plen);
                if (s->peer_bf_pending[pi] && plen) {
                    memcpy(s->peer_bf_pending[pi], payload, plen);
                    s->peer_bf_pending_n[pi] = plen;
                } else {
                    s->peer_bf_pending_n[pi] = 0;
                }
                if (sp_verbose(s)) {
                    char x[72];
                    snprintf(x, sizeof x, "kind=bitfield_pending plen=%zu", plen);
                    sp_vlog_dl(s, pi, "peer_have", x);
                }
                break;
            }
            if (plen != ((size_t)tt->np + 7) / 8) { /* BEP3: exactly ceil(np/8) bytes, anything else is broken */
                sp_drop(s, pi, "bad_bitfield_len");
                return;
            }
            for (uint32_t i = 0; i < tt->np; i++) {
                if (i / 8 < plen && (payload[i / 8] >> (7 - i % 8)) & 1) {
                    ntx_peer_set_phave(&s->peers[pi], i, 1);
                    ntx_torrent_on_peer_have(tt, i);
                }
            }
            s->peer_bf_got[pi] = 1;
            if (sp_verbose(s)) {
                char x[72];
                snprintf(x, sizeof x, "kind=bitfield plen=%zu", plen);
                sp_vlog_dl(s, pi, "peer_have", x);
            }
            break;
        }
        case MSG_HAVE_ALL:
            s->peer_fast[pi] = 1;
            if (!t->have_meta) {
                s->peer_have_all_pending[pi] = 1;
                s->peer_have_none_pending[pi] = 0;
                if (sp_verbose(s))
                    sp_vlog_dl(s, pi, "peer_have", "kind=have_all_pending");
                break;
            }
            for (uint32_t i = 0; i < t->np; i++) {
                ntx_peer_set_phave(&s->peers[pi], i, 1);
                ntx_torrent_on_peer_have(t, i);
            }
            s->peer_bf_got[pi] = 1;
            if (sp_verbose(s))
                sp_vlog_dl(s, pi, "peer_have", "kind=have_all");
            break;
        case MSG_HAVE_NONE:
            s->peer_fast[pi] = 1;
            if (!t->have_meta) {
                s->peer_have_all_pending[pi] = 0;
                s->peer_have_none_pending[pi] = 1;
                free(s->peer_bf_pending[pi]);
                s->peer_bf_pending[pi] = 0;
                s->peer_bf_pending_n[pi] = 0;
                if (sp_verbose(s))
                    sp_vlog_dl(s, pi, "peer_have", "kind=have_none_pending");
                break;
            }
            for (uint32_t i = 0; i < t->np; i++) ntx_peer_set_phave(&s->peers[pi], i, 0);
            s->peer_bf_got[pi] = 1;
            if (sp_verbose(s))
                sp_vlog_dl(s, pi, "peer_have", "kind=have_none");
            break;
        case MSG_CHOKE: {
            int prev = s->peers[pi].choke_us;
            ntx_peer_set_choke_us(&s->peers[pi], 1);
            if (sp_verbose(s)) {
                char x[48];
                snprintf(x, sizeof x, "prev_choke_us=%d", prev);
                sp_vlog_dl(s, pi, "choke_rx", x);
            }
            ntx_session_data_on_choke(s, pi);
            break;
        }
        case MSG_UNCHOKE: {
            int prev = s->peers[pi].choke_us;
            ntx_peer_set_choke_us(&s->peers[pi], 0);
            if (sp_verbose(s)) {
                char x[48];
                snprintf(x, sizeof x, "prev_choke_us=%d", prev);
                sp_vlog_dl(s, pi, "unchoke_rx", x);
            }
            ntx_session_data_on_unchoke(s, pi);
            if (s->peer_tts[pi] >= 0 && s->peer_tts[pi] < s->n_tts &&
                s->tts[s->peer_tts[pi]].state == NTX_TTS_DL) {
                int un = 0;
                for (int j = 0; j < NTX_SESSION_MAX_PEERS; j++)
                    if (s->peer_phase[j] == PH_OK && ntx_peer_can_download(&s->peers[j])) un++;
                if (un < NTX_MIN_UNCHOKED) {
                    int ok_n = 0;
                    for (int j = 0; j < NTX_SESSION_MAX_PEERS; j++)
                        if (s->peer_phase[j] == PH_OK && s->peer_tts[j] == s->peer_tts[pi]) ok_n++;
                    if (ok_n < NTX_MIN_OK_PEERS)
                        ntx_session_trk_boost_peers(s);
                }
            }
            break;
        }
        case MSG_INTERESTED:
            ntx_peer_set_int_us(&s->peers[pi], 1);
            {
                int ti = s->peer_tts[pi];
                if (ti >= 0 && ti < s->n_tts && s->tts[ti].state == NTX_TTS_DONE &&
                    !s->tts_ratio_done[ti] && s->peers[pi].we_choke) {
                    ntx_peer_set_we_choke(&s->peers[pi], 0);
                    ntx_session_peer_send_choke(s, pi, 0);
                }
            }
            break;
        case MSG_NOT_INTERESTED:
            ntx_peer_set_int_us(&s->peers[pi], 0);
            break;
        case MSG_REQUEST:
            if (plen >= 12)
                ntx_session_data_on_request(s, pi, ntx_wire_rd32(payload), ntx_wire_rd32(payload + 4), ntx_wire_rd32(payload + 8));
            break;
        case MSG_PIECE:
            /* Only blocks we asked this peer for are data; anything else is dropped before it can touch
             * the store (it would otherwise overwrite pieces we never requested or already have). */
            if (plen >= 8) {
                uint32_t pidx = ntx_wire_rd32(payload), poff = ntx_wire_rd32(payload + 4);
                if (ntx_peer_request_match(&s->peers[pi], pidx, poff, (uint32_t)(plen - 8)))
                    ntx_session_data_on_piece(s, pi, pidx, poff, payload + 8, (uint32_t)(plen - 8));
            }
            break;
        case MSG_CANCEL:
            if (plen >= 12)
                ntx_session_data_on_cancel(s, pi, ntx_wire_rd32(payload), ntx_wire_rd32(payload + 4), ntx_wire_rd32(payload + 8));
            break;
        case MSG_EXT: {
            uint8_t eid;
            const uint8_t *ep;
            size_t eplen;
            if (ntx_ext_msg_parse(buf, 4 + (size_t)total_len, &eid, &ep, &eplen) == 0) {
                if (eid == 0) {
                    uint8_t ids[16];
                    const char *names[16];
                    int n_ext = 0, meta_size = 0;
                    if (ntx_ext_handshake_parse(ep, eplen, ids, 16, names, &n_ext, &meta_size) == 0) {
                        for (int k = 0; k < n_ext; k++) {
                            if (names[k] && strcmp(names[k], NTX_EXT_NAME_UT_METADATA) == 0) {
                                s->peer_meta_id[pi] = ids[k];
                            } else if (names[k] && strcmp(names[k], NTX_EXT_NAME_UT_PEX) == 0) {
                                s->peer_pex_id[pi] = ids[k];
                            } else if (names[k] && strcmp(names[k], NTX_EXT_NAME_UT_HOLEPUNCH) == 0) {
                                s->peer_holepunch_id[pi] = ids[k];
                            }
                        }
                        for (int k = 0; k < n_ext; k++) free((void *)names[k]);
                        s->peer_meta_size[pi] = (uint32_t)meta_size;
                        if (s->cfg && s->cfg->verbose)
                            ntx_diag( "ntx: ext hs pi=%d meta_id=%u meta_size=%d\n", pi, s->peer_meta_id[pi],
                                    meta_size);
                        ntx_session_data_meta_pump_peer(s, pi);
                        ntx_session_peer_out_flush(s, pi);
                    }
                } else {
                    ntx_session_data_on_ext(s, pi, (int)eid, ep, eplen);
                }
            }
            break;
        }
        case MSG_HASH_REQUEST:
            /* Answer a well-framed 21 with hashes (22) or a hash reject
             * (23) (real BEP52 serving). The
             * framed codec re-validates the length prefix + id (defense in
             * depth); the dispatcher has already bounded the frame. */
            sp_serve_hash_request(s, pi, buf, 4 + (size_t)total_len);
            break;
        case MSG_HASHES:
            /* A 22 is only trusted when it correlates with an outstanding
             * 21 we sent — sp_rx_hashes enforces that. */
            sp_rx_hashes(s, pi, buf, 4 + (size_t)total_len);
            break;
        case MSG_HASH_REJECT:
            /* A peer refusing a 21; correlate + rotate to another peer. */
            sp_rx_reject(s, pi, buf, 4 + (size_t)total_len);
            break;
        case 16: /* MSG_REJECT (BEP6): the peer will not serve one of our requests */
            if (plen >= 12)
                ntx_session_data_on_reject(s, pi, ntx_wire_rd32(payload), ntx_wire_rd32(payload + 4), ntx_wire_rd32(payload + 8));
            break;
        case 13: /* MSG_SUGGEST BEP6 — ignore */
        case 17: /* MSG_ALLOWED_FAST */
            break;
        default:
            break;
        }
        memmove(buf, buf + 4 + total_len, *bl - 4 - (size_t)total_len);
        *bl -= 4 + (size_t)total_len;
    }
}

void sp_send_our_availability(struct ntx_session *s, int pi) {
    ntx_torrent *t = &s->tts[s->peer_tts[pi]];
    int have_any = 0;
    if (t->have && t->np > 0) {
        for (uint32_t i = 0; i < t->np; i++) {
            if (t->have[i]) {
                have_any = 1;
                break;
            }
        }
    }
    if (have_any) {
        ntx_session_peer_send_bitfield(s, pi);
        return;
    }
    /* BEP3: skip bitfield when empty. BEP6: HAVE_NONE when fast ext supported. */
    if (s->peer_fast[pi] || !t->have_meta) {
        uint8_t m[5];
        if (ntx_btmsg_build_have_none(m, sizeof m)) ntx_session_peer_send_raw(s, pi, m, 5);
    }
}

void ntx_session_peer_on_rw(struct ntx_session *s, int fd, void *ctx) {
    sp_g_s = s;
    int pi = (int)(intptr_t)ctx - 1;
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    if (s->peers[pi].fd != fd) return;
    if (s->peer_phase[pi] == PH_PE && s->peers[pi].st == NTX_PEER_ST_HS) {
        if (!ntx_netx_peer_connected(s->netx, fd)) {
            /* Failed non-blocking connect: fd stays level-triggered readable/writable
             * forever. Must drop or epoll busy-spins at 100% CPU. */
            int err = 0;
            socklen_t elen = sizeof err;
            if (fd >= 0)
                getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err != 0) {
                sp_drop(s, pi, "connect_fail");
                return;
            }
            /* SO_ERROR already consumed elsewhere, or EOF: still not connected. */
            if (fd >= 0) {
                uint8_t b;
                ssize_t pr = recv(fd, &b, 1, MSG_DONTWAIT | MSG_PEEK);
                if (pr >= 0 || (pr < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR))
                    sp_drop(s, pi, "connect_fail");
            }
            return;
        }
        ntx_session_peer_on_connect(s, fd, ctx);
        if (s->peers[pi].fd != fd) return;
    }
    ntx_session_peer_out_flush(s, pi);
    if (s->peer_phase[pi] == PH_PE) {
        sp_pe_drive(s, pi);
        if (s->peers[pi].fd != fd) return;
        sp_pe_finish(s, pi);
        if (s->peer_phase[pi] == PH_PE) {
            sp_peer_arm_io(s, pi);
            return;
        }
    }
    if (sp_bths_try(s, pi)) {
        if (s->peers[pi].fd != fd) return;
    }
    if (s->peer_phase[pi] == PH_OK && !s->peer_hello_sent[pi]) sp_peer_ok_hello(s, pi);
    if (s->peers[pi].fd != fd) return;
    sp_process_msgs(s, pi);
    if (s->peers[pi].fd != fd) return;
    uint8_t *buf = s->peer_buf[pi];
    size_t *bl = &s->peer_buflen[pi];
    if (*bl >= (size_t)NTX_PEER_BUF) {
        size_t prev = *bl;
        for (int pass = 0; pass < 8 && *bl >= (size_t)NTX_PEER_BUF; pass++) {
            sp_process_msgs(s, pi);
            if (s->peers[pi].fd != fd) return;
            if (*bl < prev) {
                prev = *bl;
                continue;
            }
            break;
        }
        if (*bl >= (size_t)NTX_PEER_BUF) {
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: peer buf full pi=%d bl=%zu req=%d -> drop\n", pi, *bl,
                        s->peers[pi].n_req);
            sp_drop(s, pi, "buf_full");
            return;
        }
    }
    {
        ssize_t r = ntx_netx_read(s->netx, fd, buf + *bl, (size_t)NTX_PEER_BUF - *bl);
        if (r > 0) {
            s->peers[pi].rx_t0 = ntx_mono_ms();
            if (!s->peer_plain[pi]) ntx_pe_decrypt(&s->pe[pi], buf + *bl, (size_t)r);
            *bl += (size_t)r;
        } else if (r == 0) {
            sp_drop(s, pi, "eof");
            return;
        } else {
            if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
                sp_peer_arm_io(s, pi);
                return;
            }
            if (s->cfg && s->cfg->verbose)
                ntx_diag( "ntx: peer read_err pi=%d errno=%d bl=%zu\n", pi, errno, *bl);
            sp_drop(s, pi, "read_err");
            return;
        }
    }
    if (sp_bths_try(s, pi)) {
        if (s->peers[pi].fd != fd) return;
    }
    sp_process_msgs(s, pi);
    if (s->peers[pi].fd == fd) sp_peer_arm_io(s, pi);
}
void ntx_session_peer_cull_stale(struct ntx_session *s, int max_drop, uint64_t age_ms) {
    uint64_t now = ntx_mono_ms();
    int dropped = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS && dropped < max_drop; pi++) {
        if (s->peers[pi].fd == -1 || s->peer_phase[pi] == PH_OK) continue;
        uint64_t t0 = s->peers[pi].hs_t0 ? s->peers[pi].hs_t0 : s->peers[pi].conn_t0;
        if (!t0 || now <= t0 || now - t0 < age_ms) continue;
        sp_drop(s, pi, "stale_hs");
        dropped++;
    }
}

void ntx_session_peer_on_close(struct ntx_session *s, void *ctx) {
    int pi = (int)(intptr_t)ctx - 1;
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    if (s->peers[pi].fd == -1) return;
    sp_drop(s, pi, "close");
}

void ntx_session_peer_step(struct ntx_session *s, int pi) {
    int r = ntx_pe_step(&s->pe[pi]);
    if (r == NTX_PE_PLAIN) {
        if (s->cfg && s->cfg->compat_peers)
            sp_plaintext_fallback(s, pi);
        else
            sp_drop(s, pi, "plaintext_strict");
    } else if (r < 0) {
        ntx_pe *pe = &s->pe[pi];
        if (pe->inn >= 20 && pe->in[0] == 19 && memcmp(pe->in + 1, "BitTorrent protocol", 19) == 0) {
            if (s->cfg && s->cfg->compat_peers) {
                sp_plaintext_fallback(s, pi);
                return;
            }
        }
        {
            char x[80];
            snprintf(x, sizeof x, "st=%s role=%d inn=%zu", sp_pe_st_name(s->pe[pi].state),
                     s->pe[pi].role, (size_t)s->pe[pi].inn);
            sp_vlog_peer(s, pi, "pe_fail", x);
        }
        if (s->pe[pi].role == NTX_PE_INITIATOR) s->pe_out_fail++;
        sp_drop(s, pi, "pe_fail");
    }
}

int ntx_session_peer_out_flush(struct ntx_session *s, int pi) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return 0;
    size_t n = s->peer_out_len[pi];
    if (!n || !s->peer_out[pi]) {
        sp_peer_arm_io(s, pi);
        return 0;
    }
    int fd = s->peers[pi].fd;
    if (fd == -1) return -1;
    while (s->peer_out_off[pi] < n) {
        ssize_t w = ntx_netx_write(s->netx, fd, s->peer_out[pi] + s->peer_out_off[pi], n - s->peer_out_off[pi]);
        if (w > 0) {
            s->peer_out_off[pi] += (size_t)w;
            continue;
        }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) {
            sp_peer_arm_io(s, pi); /* still pending → keep EPOLLOUT */
            return 0;
        }
        return -1;
    }
    s->peer_out_len[pi] = 0;
    s->peer_out_off[pi] = 0;
    sp_peer_arm_io(s, pi); /* drained → drop EPOLLOUT when idle */
    return 0;
}

int ntx_session_peer_send_raw(struct ntx_session *s, int pi, const uint8_t *buf, size_t n) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS || n == 0) return -1;
    int fd = s->peers[pi].fd;
    if (fd == -1) return -1;
    uint8_t stack[512];
    uint8_t *tmp = NULL;
    const uint8_t *out = buf;
    if (!s->peer_plain[pi] && s->peer_phase[pi] != PH_PE) {
        if (n <= sizeof stack) {
            memcpy(stack, buf, n);
            ntx_pe_encrypt(&s->pe[pi], stack, n);
            out = stack;
        } else {
            tmp = malloc(n);
            if (!tmp) return -1;
            memcpy(tmp, buf, n);
            ntx_pe_encrypt(&s->pe[pi], tmp, n);
            out = tmp;
        }
    }
    if (ntx_session_peer_out_flush(s, pi) != 0) {
        free(tmp);
        return -1;
    }
    ssize_t w = ntx_netx_write(s->netx, fd, out, n);
    if (w == (ssize_t)n) {
        free(tmp);
        sp_peer_arm_io(s, pi); /* no backlog → drop EPOLLOUT */
        return 0;
    }
    if (w > 0) {
        out += (size_t)w;
        n -= (size_t)w;
    } else if (w < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) {
        free(tmp);
        return -1;
    }
    if (!s->peer_out[pi]) {
        free(tmp);
        return -1;
    }
    size_t room = NTX_PEER_OUTBUF - s->peer_out_len[pi];
    if (n > room) {
        free(tmp);
        return -1;
    }
    memcpy(s->peer_out[pi] + s->peer_out_len[pi], out, n);
    s->peer_out_len[pi] += n;
    free(tmp);
    sp_peer_arm_io(s, pi); /* buffered → need EPOLLOUT */
    return 0;
}

void ntx_session_peer_send_handshake(struct ntx_session *s, int pi) {
    uint8_t m[68];
    sp_build_bt_handshake(s, pi, m);
    if (m[0] != 19) return;
    ntx_session_peer_send_raw(s, pi, m, 68);
}

void ntx_session_peer_send_ext_handshake(struct ntx_session *s, int pi) {
    ntx_torrent *t = &s->tts[s->peer_tts[pi]];
    /* ut_holepunch is only meaningful over uTP (the connect drives a uTP dial),
     * so advertise it only when uTP is enabled — never claim a capability the
     * stack would not honour (a connect arriving with cfg.utp==0 is ignored). */
    int utp_on = (s->cfg && s->cfg->utp) ? 1 : 0;
    const char *names[3] = {NTX_EXT_NAME_UT_METADATA, NTX_EXT_NAME_UT_PEX, NTX_EXT_NAME_UT_HOLEPUNCH};
    uint8_t ids[3] = {NTX_EXT_LOCAL_METADATA, NTX_EXT_LOCAL_PEX, NTX_EXT_LOCAL_HOLEPUNCH};
    int n_ext = utp_on ? 3 : 2;
    int meta_size = t->have_meta ? (int)t->info_raw_n : 0;
    uint8_t hs[256];
    size_t hsn = 0;
    ntx_ext_handshake_build(hs, &hsn, names, ids, n_ext, meta_size, ntx_netx_port(s->netx), "ntx/" NTX_VERSION);
    if (!hsn) return;
    uint8_t wire[261];
    size_t wn = ntx_ext_msg_build(wire, sizeof(wire), 0, hs, hsn);
    if (wn) ntx_session_peer_send_raw(s, pi, wire, wn);
}

void ntx_session_peer_send_interest(struct ntx_session *s, int pi, int interested) {
    uint8_t m[5];
    if (ntx_btmsg_build_interest(m, sizeof m, interested)) ntx_session_peer_send_raw(s, pi, m, 5);
}

void ntx_session_peer_send_choke(struct ntx_session *s, int pi, int choked) {
    uint8_t m[5];
    if (ntx_btmsg_build_choke(m, sizeof m, choked)) ntx_session_peer_send_raw(s, pi, m, 5);
}

void ntx_session_peer_send_bitfield(struct ntx_session *s, int pi) {
    ntx_torrent *t = &s->tts[s->peer_tts[pi]];
    uint32_t nbytes = (t->np + 7) / 8;
    uint8_t *m = malloc(5 + nbytes);
    if (!m) return;
    memset(m + 5, 0, nbytes);
    for (uint32_t i = 0; i < t->np; i++) {
        if (t->have && t->have[i]) m[5 + i / 8] |= (uint8_t)(1u << (7 - (i % 8)));
    }
    if (ntx_btmsg_build_bitfield(m, 5 + nbytes, m + 5, nbytes))
        ntx_session_peer_send_raw(s, pi, m, 5 + (size_t)nbytes);
    free(m);
}

int ntx_session_peer_send_request(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    uint8_t m[17];
    if (!ntx_btmsg_build_request(m, sizeof m, idx, off, len)) return -1;
    return ntx_session_peer_send_raw(s, pi, m, 17);
}

void ntx_session_peer_send_cancel(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    uint8_t m[17];
    if (ntx_btmsg_build_cancel(m, sizeof m, idx, off, len)) ntx_session_peer_send_raw(s, pi, m, 17);
}

int ntx_session_peer_send_piece(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, const uint8_t *data,
                                uint32_t len) {
    uint8_t m[17 + NTX_PEER_REQ_LEN];
    if (!ntx_btmsg_build_piece(m, sizeof m, idx, off, data, len)) return -1;
    return ntx_session_peer_send_raw(s, pi, m, 13 + (size_t)len);
}

/* BEP6 reject_request (16): same payload as request/cancel. Only valid towards peers that speak the
 * fast extension; anyone else would treat the unknown message id as a protocol error. */
void ntx_session_peer_send_reject(struct ntx_session *s, int pi, uint32_t idx, uint32_t off, uint32_t len) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS || !s->peer_fast[pi]) return;
    uint8_t m[17];
    ntx_wire_wr32(m, 13);
    m[4] = 16;
    ntx_wire_wr32(m + 5, idx);
    ntx_wire_wr32(m + 9, off);
    ntx_wire_wr32(m + 13, len);
    ntx_session_peer_send_raw(s, pi, m, sizeof m);
}

void ntx_session_peer_send_keepalive(struct ntx_session *s, int pi) {
    uint8_t m[4];
    if (ntx_btmsg_build_keepalive(m, sizeof m)) ntx_session_peer_send_raw(s, pi, m, 4);
}

void ntx_session_peer_send_have(struct ntx_session *s, int pi, uint32_t idx) {
    uint8_t m[9];
    if (ntx_btmsg_build_have(m, sizeof m, idx)) ntx_session_peer_send_raw(s, pi, m, 9);
}

void ntx_session_peer_send_have_all(struct ntx_session *s, int pi) {
    uint8_t m[5];
    if (ntx_btmsg_build_have_all(m, sizeof m)) ntx_session_peer_send_raw(s, pi, m, 5);
}

void ntx_session_peer_process_inbuf(struct ntx_session *s, int pi) {
    sp_process_msgs(s, pi);
}
