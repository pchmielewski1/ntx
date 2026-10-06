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

/* Start-up latency: announcing used to resolve (blocking DoH, ~0.1 s each) and send to every UDP
 * tracker inside one call, so tracker replies waited in the socket until the whole batch was done.
 * Now announce only queues the trackers; ntx_session_trk_pump_udp() works through them within a time
 * budget per loop iteration, and HTTP(S) trackers (which can block for seconds) go after the UDP ones. */

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
    fcntl(fd, F_SETFL, fcntl(fd, F_GETFL) | O_NONBLOCK);
    return fd;
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

    uint16_t our_port, p0, p1;
    s->trk_fd = udp_sock(&our_port);
    int t0 = udp_sock(&p0), t1 = udp_sock(&p1);
    if (s->trk_fd < 0 || t0 < 0 || t1 < 0) return fail("sockets");
    snprintf(s->trk_urls[0][0], sizeof s->trk_urls[0][0], "udp://127.0.0.1:%u", (unsigned)p0);
    snprintf(s->trk_urls[0][1], sizeof s->trk_urls[0][1], "udp://127.0.0.1:%u", (unsigned)p1);
    snprintf(s->trk_urls[0][2], sizeof s->trk_urls[0][2], "http://127.0.0.1:1/announce");
    s->trk_n[0] = 3;

    uint8_t buf[128];
    uint64_t t_ann = ntx_mono_ms();
    ntx_session_trk_announce(s, 0, NTX_TRACKER_EVENT_STARTED);
    if (recv(t0, buf, sizeof buf, 0) > 0 || recv(t1, buf, sizeof buf, 0) > 0)
        return fail("announce_sends_synchronously");
    if (!s->trk_http_pending[0][2]) return fail("http_not_queued");
    if (s->trk_http_due[0][2] < t_ann + 2000) return fail("http_not_deferred_behind_udp");

    ntx_session_trk_pump_udp(s);
    usleep(20000);
    if (recv(t0, buf, sizeof buf, 0) != 16) return fail("udp0_connect_not_sent");
    if (recv(t1, buf, sizeof buf, 0) != 16) return fail("udp1_connect_not_sent");
    /* nothing left to send: a second pump is a no-op */
    ntx_session_trk_pump_udp(s);
    usleep(20000);
    if (recv(t0, buf, sizeof buf, 0) > 0) return fail("pump_resends");

    /* without UDP trackers the HTTP ones are not held back */
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], sizeof s->trk_urls[0][0], "http://127.0.0.1:1/announce");
    s->trk_http_due[0][0] = 0;
    t_ann = ntx_mono_ms();
    ntx_session_trk_announce(s, 0, NTX_TRACKER_EVENT_NONE);
    if (s->trk_http_due[0][0] > t_ann + 500) return fail("http_deferred_without_udp");

    printf("PASS session_trk_pump\n");
    return 0;
}
