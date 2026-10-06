/* These checks age timestamps by subtracting from the monotonic clock, which counts from boot: offset it so a freshly started host cannot underflow. */
#define NTX_MONO_BASE_MS 86400000LL
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
#include "../src/net/ntx_utp.c"
#include "../src/net/ntx_utp_sm.c"
#include "../src/net/ntx_utp_hdr.c"
#include "../src/net/ntx_utp_cc.c"
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
#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

/* --utp used to be exclusive: every dial went out as uTP and a peer without a uTP stack (most of them)
 * simply never answered.  A uTP dial that does not connect within NTX_UTP_DIAL_MS is now redone over TCP,
 * and the failed uTP attempt is not held against the address. */

static int fails;
static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails++;
}

int main(void) {
    ntx_rng_init();
    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.store_dir = "test/.scratch/utpfb/store";
    cfg.port_lo = 6951;
    cfg.port_hi = 6979;
    cfg.max_peers = 50;
    cfg.allow_local_peers = 1;
    cfg.utp = 1;
    ntx_netx *n = ntx_netx_init(&cfg);
    if (!n) { printf("FAIL netx\n"); return 1; }
    struct ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) { printf("FAIL session\n"); return 1; }
    if (ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=FB") != 0) {
        printf("FAIL magnet\n");
        return 1;
    }
    sess_g_s = s;
    sp_g_s = s;

    /* a TCP-only peer: nothing listens on that UDP port, but a TCP socket does */
    int ls = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) || listen(ls, 4)) { printf("FAIL listen\n"); return 1; }
    socklen_t sl = sizeof sa;
    getsockname(ls, (struct sockaddr *)&sa, &sl);
    uint16_t port = ntohs(sa.sin_port);
    fcntl(ls, F_SETFL, fcntl(ls, F_GETFL) | O_NONBLOCK);

    ntx_addr tgt;
    ntx_addr_set_v4(&tgt, htonl(0x7f000001));
    ntx_session_add_peer_from_tracker(s, 0, &tgt, port);
    int pi = -1;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++)
        if (s->peers[i].fd != -1) pi = i;
    check(pi >= 0 && s->peers[pi].fd <= -NTX_UTP_VIRT_BASE, "first_attempt_is_utp");

    /* not yet: the SYN may still be answered */
    s->peers[pi].conn_t0 = ntx_mono_ms() - 1000;
    ntx_session_peer_hs_tick(s);
    check(s->peers[pi].fd <= -NTX_UTP_VIRT_BASE, "utp_kept_while_young");

    s->peers[pi].conn_t0 = ntx_mono_ms() - (NTX_UTP_DIAL_MS + 500);
    ntx_session_peer_hs_tick(s);
    int tp = -1;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++)
        if (s->peers[i].fd >= 0) tp = i;
    check(tp >= 0, "tcp_fallback_dialed");
    if (tp >= 0) {
        check(s->peer_tcp_fb[tp] == 1, "fallback_flagged");
        check(s->peers[tp].port == port && s->peer_outbound[tp], "fallback_same_peer");
        check(s->peers[tp].fd >= 0, "fallback_on_tcp");
    }
    check(!ntx_dial_bo_blocked(&s->dial_bo, &tgt, port, ntx_mono_ms()), "utp_miss_not_backed_off");
    int cs = accept(ls, NULL, NULL);
    check(cs >= 0, "listener_saw_tcp_connect");

    /* a TCP attempt that fails is final and is remembered */
    /* A non-blocking loopback connect can still be in flight: tick until it has completed and started its
     * handshake clock, otherwise that completion would reset the aged hs_t0 below. */
    for (int k = 0; tp >= 0 && s->peers[tp].conn_t0 != 0 && k < 400; k++) {
        ntx_session_peer_hs_tick(s);
        nanosleep(&(struct timespec){0, 5000000}, NULL);
    }
    if (tp >= 0) {
        s->peers[tp].conn_t0 = 0;
        s->peers[tp].hs_t0 = ntx_mono_ms() - 600000; /* connected, never handshook */
        ntx_session_peer_hs_tick(s);
    }
    int still = 0;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++)
        if (s->peers[i].fd != -1) still++;
    check(still == 0, "no_second_fallback");
    check(ntx_dial_bo_blocked(&s->dial_bo, &tgt, port, ntx_mono_ms()), "tcp_failure_backed_off");

    /* after enough misses with no uTP success at all, new dials go straight to TCP */
    s->utp_miss_n = NTX_UTP_GIVEUP_MISSES;
    s->utp_ok_n = 0;
    ntx_dial_bo_ok(&s->dial_bo, &tgt, port);
    ntx_session_add_peer_from_tracker(s, 0, &tgt, port);
    int direct = -1;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++)
        if (s->peers[i].fd != -1) direct = i;
    check(direct >= 0 && s->peers[direct].fd >= 0, "giveup_dials_tcp_first");
    s->utp_ok_n = 1;
    if (direct >= 0) ntx_session_peer_free(s, direct);
    ntx_session_add_peer_from_tracker(s, 0, &tgt, port);
    direct = -1;
    for (int i = 0; i < NTX_SESSION_MAX_PEERS; i++)
        if (s->peers[i].fd != -1) direct = i;
    check(direct >= 0 && s->peers[direct].fd <= -NTX_UTP_VIRT_BASE, "one_uTP_success_keeps_utp_first");

    printf(fails ? "FAIL session_utp_fallback\n" : "PASS session_utp_fallback\n");
    return fails ? 1 : 0;
}
