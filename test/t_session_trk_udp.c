#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include "../src/core/ntx_session.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
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

#include <netinet/in.h>

/* Security audit: UDP tracker replies are matched only by a transaction id.  The id must be
 * unpredictable (it used to count 0,1,2,...) and the reply must come from the address we sent the
 * request to, otherwise any host that can send us a datagram can forge tracker answers. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int udp_sock(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(fd, (struct sockaddr *)&sa, sizeof sa)) return -1;
    socklen_t sl = sizeof sa;
    getsockname(fd, (struct sockaddr *)&sa, &sl);
    *port = ntohs(sa.sin_port);
    return fd;
}

static int pending_used(const ntx_session *s) {
    int n = 0;
    for (int i = 0; i < NTX_TRK_PENDING; i++) n += s->trk_pending_used[i];
    return n;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    ntx_config cfg = {0};
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20] = {9};
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);

    uint16_t our_port, trk_port, evil_port;
    s->trk_fd = udp_sock(&our_port);
    int trk = udp_sock(&trk_port);
    int evil = udp_sock(&evil_port);
    if (s->trk_fd < 0 || trk < 0 || evil < 0) return fail("sockets");
    fcntl(s->trk_fd, F_SETFL, fcntl(s->trk_fd, F_GETFL) | O_NONBLOCK);
    snprintf(s->trk_urls[0][0], sizeof s->trk_urls[0][0], "udp://127.0.0.1:%u", (unsigned)trk_port);
    s->trk_n[0] = 1;

    struct sockaddr_in us;
    memset(&us, 0, sizeof us);
    us.sin_family = AF_INET;
    us.sin_addr.s_addr = htonl(0x7f000001);
    us.sin_port = htons(our_port);

    /* transaction ids: random, not a counter */
    int32_t tids[8];
    for (int i = 0; i < 8; i++) {
        trk_send_connect(s, 0, 0);
        uint8_t req[64];
        ssize_t r = recv(trk, req, sizeof req, 0);
        if (r != 16) return fail("connect_req");
        tids[i] = (int32_t)ntx_wire_rd32(req + 12);
        for (int k = 0; k < NTX_TRK_PENDING; k++) s->trk_pending_used[k] = 0;
    }
    int sequential = 1;
    for (int i = 1; i < 8; i++)
        if (tids[i] != tids[i - 1] + 1) sequential = 0;
    if (sequential || (tids[0] >= 0 && tids[0] < 8)) return fail("tid_predictable");

    /* a forged reply from another address with the right tid is ignored */
    trk_send_connect(s, 0, 0);
    uint8_t req[64];
    if (recv(trk, req, sizeof req, 0) != 16) return fail("connect_req2");
    uint8_t rsp[16] = {0};
    memcpy(rsp + 4, req + 12, 4); /* action 0 = connect, our tid */
    memset(rsp + 8, 0x42, 8);
    if (sendto(evil, rsp, 16, 0, (struct sockaddr *)&us, sizeof us) != 16) return fail("evil_send");
    usleep(20000);
    ntx_session_trk_on_udp(s, s->trk_fd, s);
    if (s->trk_conn_done[0][0]) return fail("forged_reply_accepted");
    if (pending_used(s) != 1) return fail("forged_reply_consumed_pending");

    /* the genuine tracker's reply is accepted */
    if (sendto(trk, rsp, 16, 0, (struct sockaddr *)&us, sizeof us) != 16) return fail("trk_send");
    usleep(20000);
    ntx_session_trk_on_udp(s, s->trk_fd, s);
    if (!s->trk_conn_done[0][0]) return fail("genuine_reply_rejected");

    /* behind a SOCKS proxy / NTX1 tunnel a UDP tracker datagram would leave the host directly */
    {
        ntx_config pcfg = {0};
        pcfg.proxy = 1;
        pcfg.proxy_host = "127.0.0.1";
        pcfg.proxy_port = 1080;
        const ntx_config *saved = s->cfg;
        s->cfg = &pcfg;
        int drained = 0;
        uint8_t junk[128];
        fcntl(trk, F_SETFL, fcntl(trk, F_GETFL) | O_NONBLOCK);
        while (recv(trk, junk, sizeof junk, 0) > 0) drained++;
        trk_send_connect(s, 0, 0);
        s->trk_conn_done[0][0] = 1;
        trk_send_announce_one(s, 0, 0, 0);
        usleep(20000);
        if (recv(trk, junk, sizeof junk, 0) > 0) return fail("udp_tracker_bypasses_proxy");
        s->cfg = saved;
    }

    printf("PASS session_trk_udp\n");
    return 0;
}
