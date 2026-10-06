#define _GNU_SOURCE
#include "../src/core/ntx_session.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_peer.c"
#include "../src/core/ntx_store.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/proto/ntx_pe.c"
#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_holepunch.c"
#include "../src/proto/ntx_pex.c"
#include "../src/proto/ntx_http.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_magnet.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/core/ntx_session_stats.c"
#include "../src/core/ntx_pieceblk.c"
#include "../src/core/ntx_session_webseed.c"
#include "../src/core/ntx_session_pex.c"
#include "../src/core/ntx_session_meta.c"
#include "../src/core/ntx_session_vlog.c"
#include "../src/core/ntx_session_pe.c"
#include "../src/core/ntx_session_bt_hs.c"
#include "../src/proto/ntx_btmsg.c"
#include "../src/proto/ntx_utmeta.c"
#include "../src/proto/ntx_pe_vc.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char *MAGNET = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Test&tr=udp://tracker.example.com:6969";

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

static ntx_session *mk(ntx_netx **n, const ntx_config *cfg) {
    *n = ntx_netx_init(cfg);
    if (!*n) fail("netx_init");
    ntx_session *s = ntx_session_init(*n, cfg);
    if (!s) fail("session_init");
    return s;
}

static void drop(ntx_session *s, ntx_netx *n) {
    ntx_session_free(s);
    ntx_netx_free(n);
}

static int count_tts(const ntx_session *s, int ti) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_tts[pi] == ti) c++;
    return c;
}

static int count_peers_tts(const ntx_session *s, int ti, const ntx_addr *a) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_tts[pi] == ti && ntx_addr_eq(&s->peers[pi].addr, a)) c++;
    return c;
}

int main(void) {
    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.store_dir = "downloads";
    cfg.port_lo = 6881;
    cfg.port_hi = 6891;
    cfg.max_peers = 50;
    cfg.allow_local_peers = 1; /* these tests talk to 127.0.0.1 */

    ntx_netx *n;
    ntx_session *s = mk(&n, &cfg);
    /* dual listen — v6 fd created, port = v4 port if free else ephemeral (>0). */
    if (n->listen_fd6 < 0) fail("listen_fd6");
    if (n->listen_port6 == 0) fail("listen_port6");
    if (ntx_netx_port6(n) != n->listen_port6) fail("port6_acc");
    drop(s, n);
    printf("PASS init_free\n");

    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("add_magnet");
    if (s->n_tts != 1) fail("add_magnet_n");
    if (s->tts[0].state != NTX_TTS_META) fail("add_magnet_state");
    if (s->trk_n[0] < 1) fail("add_magnet_trk");
    {
        uint16_t p = ntx_netx_port(n);
        if (p < cfg.port_lo || p > cfg.port_hi) fail("listen_port_range");
    }
    drop(s, n);
    printf("PASS add_magnet\n");

    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s,
            "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"
            "&dn=AsOnly&as=http%3A%2F%2Falt.example.com%2Fw") != 0)
        fail("as_webseed_add");
    if (!s->tts[0].has_webseed) fail("as_webseed_flag");
    if (strcmp(s->tts[0].webseed, "http://alt.example.com/w") != 0) fail("as_webseed_url");
    drop(s, n);
    printf("PASS as_as_webseed\n");

    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("snap_add");
    for (int i = 0; i < 10; i++) ntx_session_tick(s);
    ntx_stats st;
    ntx_session_snapshot(s, &st);
    if (st.n < 1) fail("snap_n");
    if (!strstr(st.t[0].name, "Test")) fail("snap_name");
    drop(s, n);
    printf("PASS snapshot\n");

    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("pause_add");
    s->tts[0].state = NTX_TTS_DL;
    ntx_session_pause(s, 0);
    if (s->tts[0].state != NTX_TTS_PAUSED) fail("pause_on");
    ntx_session_pause(s, 0);
    if (s->tts[0].state != NTX_TTS_DL) fail("pause_off");
    drop(s, n);
    printf("PASS pause\n");

    /* ── JSON-API v1 §6.3: set_paused sets a state, it does not remember a toggle ── */
    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("sp_add");
    /* META → pause allowed, paused_from = META */
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK) fail("sp_meta_on");
    if (s->tts[0].state != NTX_TTS_PAUSED || s->tts[0].paused_from != NTX_TTS_META)
        fail("sp_meta_st");
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK) fail("sp_meta_idem"); /* twice = OK */
    if (s->tts[0].state != NTX_TTS_PAUSED) fail("sp_meta_hold");
    if (ntx_session_set_paused(s, 0, 0) != NTX_PAUSE_OK) fail("sp_meta_off");
    if (s->tts[0].state != NTX_TTS_META) fail("sp_meta_back");
    /* DL → remembers DL; resume → DL */
    s->tts[0].state = NTX_TTS_DL;
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK || s->tts[0].paused_from != NTX_TTS_DL)
        fail("sp_dl_on");
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK || s->tts[0].state != NTX_TTS_PAUSED)
        fail("sp_dl_idem");
    if (ntx_session_set_paused(s, 0, 0) != NTX_PAUSE_OK || s->tts[0].state != NTX_TTS_DL)
        fail("sp_dl_back");
    if (ntx_session_set_paused(s, 0, 0) != NTX_PAUSE_OK || s->tts[0].state != NTX_TTS_DL)
        fail("sp_dl_noop"); /* resume from DL = OK, no change (§6.3) */
    /* DONE → pause → resume → DONE */
    s->tts[0].state = NTX_TTS_DONE;
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK || s->tts[0].paused_from != NTX_TTS_DONE)
        fail("sp_done_on");
    if (ntx_session_set_paused(s, 0, 0) != NTX_PAUSE_OK || s->tts[0].state != NTX_TTS_DONE)
        fail("sp_done_back");
    /* VERIFY: missing pieces → DL; complete → VERIFY (§6.3) */
    s->tts[0].state = NTX_TTS_VERIFY;
    s->tts[0].np = 4; s->tts[0].have_n = 1;
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK || s->tts[0].paused_from != NTX_TTS_VERIFY)
        fail("sp_vf_on");
    if (ntx_session_set_paused(s, 0, 0) != NTX_PAUSE_OK || s->tts[0].state != NTX_TTS_DL)
        fail("sp_vf_dl");
    s->tts[0].state = NTX_TTS_VERIFY; s->tts[0].have_n = 4;
    if (ntx_session_set_paused(s, 0, 1) != NTX_PAUSE_OK) fail("sp_vf2_on");
    if (ntx_session_set_paused(s, 0, 0) != NTX_PAUSE_OK || s->tts[0].state != NTX_TTS_VERIFY)
        fail("sp_vf2_vf");
    /* dead and out-of-range slots */
    if (ntx_session_set_paused(s, 9, 1) != NTX_PAUSE_E_DEAD) fail("sp_dead");
    if (ntx_session_set_paused(s, -1, 1) != NTX_PAUSE_E_RANGE) fail("sp_range_lo");
    if (ntx_session_set_paused(s, NTX_SESSION_MAX_TTS, 1) != NTX_PAUSE_E_RANGE) fail("sp_range_hi");
    drop(s, n);
    printf("PASS set_paused\n");

    /* free_slot: the first DEAD one after remove, -1 when full */
    s = mk(&n, &cfg);
    if (ntx_session_free_slot(s) != 0) fail("fs_first");
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("fs_add");
    if (ntx_session_free_slot(s) != 1) fail("fs_second");
    ntx_session_remove(s, 0);
    if (ntx_session_free_slot(s) != 0) fail("fs_reuse"); /* §5.2 rule 2: slot reuse */
    drop(s, n);
    printf("PASS free_slot\n");

    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("remove_add");
    ntx_session_remove(s, 0);
    if (s->tts[0].state != NTX_TTS_DEAD) fail("remove_state");
    drop(s, n);
    printf("PASS remove\n");

    /* add_peer_from_tracker on ntx_addr — validation, v4 dedup, v6 pool. */
    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("addr_magnet");
    ntx_session_add_peer_from_tracker(s, 0, NULL, 6999);
    ntx_addr z; ntx_addr_clear(&z);
    ntx_session_add_peer_from_tracker(s, 0, &z, 6999);
    ntx_addr zv4; ntx_addr_set_v4(&zv4, htonl(0x7f000001));
    ntx_session_add_peer_from_tracker(s, 0, &zv4, 0);
    if (count_tts(s, 0) != 0) fail("addr_validation_none");
    ntx_addr v4; ntx_addr_set_v4(&v4, htonl(0x7f000001));
    ntx_session_add_peer_from_tracker(s, 0, &v4, 6999);
    if (count_peers_tts(s, 0, &v4) != 1) fail("addr_v4_alloc");
    ntx_session_add_peer_from_tracker(s, 0, &v4, 6999);
    if (count_peers_tts(s, 0, &v4) != 1) fail("addr_v4_dedup");
    ntx_addr v6; static const uint8_t v6b[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ntx_addr_set_v6(&v6, v6b);
    ntx_session_add_peer_from_tracker(s, 0, &v6, 6999);
    {
        int found = 0, fdneg = 0, fdpos = 0;
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
            if (s->peer_tts[pi] == 0 && ntx_addr_eq(&s->peers[pi].addr, &v6)) {
                found = 1;
                if (s->peers[pi].fd < 0) fdneg = 1;
                else fdpos = 1;
            }
        if (!found) fail("addr_v6_pool");
        /* v6 peer gets a raw tcp6 connect; soft-skip if ::1 loopback is down. */
        int v6ok = 0, pfd = ntx_sock_tcp6();
        if (pfd >= 0 && ntx_sock_connect_addr(pfd, &v6, 6999) == 0) v6ok = 1;
        if (pfd >= 0) close(pfd);
        /* fix(ipv6): established v6 loopback — peer_connected must see AF_INET6 fd
         * (getpeername on sockaddr_storage; sockaddr_in fails EINVAL on v6). */
        int sv = ntx_sock_tcp6();
        if (sv >= 0) {
            uint16_t sp = ntx_sock_bind6(sv, 0);
            if (sp > 0 && listen(sv, 8) == 0) {
                int cl = ntx_sock_tcp6();
                int est = 0;
                if (cl >= 0 && ntx_sock_connect_addr(cl, &v6, sp) == 0) {
                    struct pollfd pfd2;
                    pfd2.fd = cl; pfd2.events = POLLOUT; pfd2.revents = 0;
                    if (poll(&pfd2, 1, 2000) > 0 && (pfd2.revents & POLLOUT) && !(pfd2.revents & POLLERR)) {
                        int soerr = 0; socklen_t sl2 = sizeof soerr;
                        if (getsockopt(cl, SOL_SOCKET, SO_ERROR, &soerr, &sl2) == 0 && soerr == 0)
                            est = (ntx_netx_peer_connected(s->netx, cl) == 1);
                    }
                }
                if (!est) fail("v6_peer_connected");
                if (cl >= 0) close(cl);
            } else {
                printf("SKIP v6 loopback unavailable (no AF_INET6 ::1)\n");
            }
            close(sv);
        }
        if (v6ok) {
            if (!fdpos) fail("addr_v6_connect");
        } else {
            if (!fdneg) fail("addr_v6_pool_only");
            printf("SKIP v6 loopback unavailable (no AF_INET6 ::1)\n");
        }
    }
    drop(s, n);
    printf("PASS add_peer_addr\n");

    /* UDP announce with v4+v6 → both families land in the peer pool.
     * Parser: the v4 block fills max4 (64), the 18 B tail → peers6.
     * The first v4 entry is real; the rest have port=0 (the session skips them). */
    s = mk(&n, &cfg);
    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("trk15_magnet");
    {
        const int32_t tid = 0x1234;
        /* the reply is only accepted from the address the request went to, so bind the fake tracker first */
        int cfd = socket(AF_INET, SOCK_DGRAM, 0);
        if (cfd < 0) fail("trk15_sock");
        struct sockaddr_in src;
        memset(&src, 0, sizeof src);
        src.sin_family = AF_INET;
        src.sin_addr.s_addr = htonl(0x7f000001);
        socklen_t slen = sizeof src;
        if (bind(cfd, (struct sockaddr *)&src, sizeof src) != 0 ||
            getsockname(cfd, (struct sockaddr *)&src, &slen) != 0)
            fail("trk15_bind");
        trk_store_pending(s, tid, 0, 0, src.sin_addr.s_addr, ntohs(src.sin_port));
        uint8_t resp[20 + NTX_TRACKER_NUMWANT * 6 + 18];
        memset(resp, 0, sizeof resp);
        ntx_wire_wr32(resp + 0, (uint32_t)NTX_TRACKER_ACTION_ANNOUNCE);
        ntx_wire_wr32(resp + 4, (uint32_t)tid);
        ntx_wire_wr32(resp + 8, 1800);
        ntx_wire_wr32(resp + 12, 1);
        ntx_wire_wr32(resp + 16, 1);
        const uint8_t v4ip[4] = {127, 0, 0, 1};
        memcpy(resp + 20, v4ip, 4);
        resp[24] = 0x1B; resp[25] = 0x57; /* 6999 BE */
        const uint8_t v6ip[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
        memcpy(resp + 20 + NTX_TRACKER_NUMWANT * 6, v6ip, 16);
        resp[20 + NTX_TRACKER_NUMWANT * 6 + 16] = 0x1B;
        resp[20 + NTX_TRACKER_NUMWANT * 6 + 17] = 0x56; /* 6998 BE */
        struct sockaddr_in dst;
        socklen_t dlen = sizeof dst;
        if (s->trk_fd < 0 || getsockname(s->trk_fd, (struct sockaddr *)&dst, &dlen) != 0)
            fail("trk15_sockname");
        dst.sin_addr.s_addr = htonl(0x7f000001); /* bind0 → INADDR_ANY; aim at loopback */
        if (sendto(cfd, resp, sizeof resp, 0, (struct sockaddr *)&dst, sizeof dst) !=
            (ssize_t)sizeof resp)
            fail("trk15_send");
        close(cfd);
        ntx_session_trk_on_udp(s, s->trk_fd, s);
ntx_addr a4; ntx_addr_set_v4(&a4, htonl(0x7f000001));
        ntx_addr a6; ntx_addr_set_v6(&a6, v6ip);
        int f4 = 0, f6 = 0;
        for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
            if (s->peer_tts[pi] != 0) continue;
            if (ntx_addr_is_v4(&s->peers[pi].addr) && ntx_addr_eq(&s->peers[pi].addr, &a4) &&
                s->peers[pi].port == 6999)
                f4 = 1;
            if (ntx_addr_is_v6(&s->peers[pi].addr) && ntx_addr_eq(&s->peers[pi].addr, &a6) &&
                s->peers[pi].port == 6998)
                f6 = 1;
        }
        if (!f4) fail("trk15_v4");
        if (!f6) fail("trk15_v6");
    }
    drop(s, n);
    printf("PASS trk_announce_v4v6\n");

    return 0;
}
