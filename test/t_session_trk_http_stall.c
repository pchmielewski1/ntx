#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
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
#include "../src/core/ntx_share.c"
#include "../src/core/ntx_share_meta.c"
#include "../src/core/ntx_share_out.c"
#include "../src/core/ntx_session_priv.c"
#include "../src/core/ntx_session_portmap.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/proto/ntx_pcp.c"

#include <netinet/in.h>

/* R38: an HTTPS announce is synchronous, so a tracker that accepts the TCP
 * connection and then answers nothing held the whole event loop for as long as the
 * TLS client is willing to wait — measured 30.7 s per announce (the TLS 1.3 attempt
 * times out at its 15 s I/O timeout, the TLS 1.2 fallback does the same), so five
 * dead trackers stalled the loop for minutes and JSON, IPC and every other peer went
 * hungry with it (spec §5.3 caps only the hashing at ~50 ms per iteration).
 *
 * This test is the measurement the plan asked for, kept as the regression gate: the
 * black hole here is a listener on loopback that accepts and never answers —
 * deterministic, no DNS, no internet — with the five pinned share trackers' role
 * played by five https URLs at that one address (127.0.0.1 is in the built-in pin
 * pool, so the real TLS client runs and fails, exactly as it does against a dead
 * host). One loop iteration is one ntx_session_trk_pump_http(s, 1), which is the
 * production per-iteration budget (src/ntx_main.c). The bound it asserts is the one
 * the plan sets: a single iteration must not exceed 1 s.
 *
 * Non-vacuity: the floor assertion (each stalled announce took at least 100 ms)
 * fails if the trap ever stops being a black hole — e.g. someone points it at a
 * closed port, where connect() is refused in microseconds and the test would prove
 * nothing — and the per-tracker strike count proves the fetch really ran and really
 * failed. The measured number is recorded in docs/network.md.
 */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static uint64_t now_us(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)ts.tv_nsec / 1000ull;
}

#define N_TRK 5
#define ITER_LIMIT_MS 1000 /* the plan's bound for one loop iteration */
#define STALL_FLOOR_MS 100 /* below this the "dead tracker" is not stalling us */

static int held[64];
static int n_held;

/* keeps the accept queue empty: a black hole must keep accepting, or the kernel
 * would stop completing handshakes and we would be measuring a backlog, not a stall */
static void drain_accepts(int lfd) {
    for (;;) {
        int c = accept(lfd, NULL, NULL);
        if (c < 0) return;
        if (n_held < (int)(sizeof held / sizeof held[0])) held[n_held++] = c;
        else close(c);
    }
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();

    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
    struct sockaddr_in la;
    memset(&la, 0, sizeof la);
    la.sin_family = AF_INET;
    la.sin_addr.s_addr = htonl(0x7f000001);
    if (bind(lfd, (struct sockaddr *)&la, sizeof la) != 0 || listen(lfd, 128) != 0) return fail("listen");
    socklen_t ll = sizeof la;
    getsockname(lfd, (struct sockaddr *)&la, &ll);
    uint16_t port = ntohs(la.sin_port);
    fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL) | O_NONBLOCK);

    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20] = {9};
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    s->tts[0].state = NTX_TTS_META;
    s->trk_fd = ntx_sock_udp4();
    ntx_sock_bind0(s->trk_fd);
    s->trk_n[0] = N_TRK;
    for (int i = 0; i < N_TRK; i++) {
        snprintf(s->trk_urls[0][i], sizeof s->trk_urls[0][0],
                 "https://127.0.0.1:%u/announce", (unsigned)port);
        s->trk_http_pending[0][i] = 1;
        s->trk_http_due[0][i] = 0;
    }
    s->trk_http_event[0] = NTX_TRACKER_EVENT_NONE;

    uint64_t worst_ms = 0, total_ms = 0;
    for (int i = 0; i < N_TRK; i++) {
        drain_accepts(lfd);
        uint64_t t0 = now_us();
        ntx_session_trk_pump_http(s, 1); /* one loop iteration's worth of announces */
        uint64_t ms = (now_us() - t0 + 999) / 1000;
        printf("announce %d: %llu ms\n", i, (unsigned long long)ms);
        if (ms > worst_ms) worst_ms = ms;
        total_ms += ms;
    }
    printf("5 dead HTTPS trackers: worst iteration %llu ms, total %llu ms\n",
           (unsigned long long)worst_ms, (unsigned long long)total_ms);

    int rc = 0;
    for (int i = 0; i < N_TRK; i++)
        if (s->trk_fail[0][i] == 0) { printf("tracker %d was never contacted\n", i); rc |= fail("trap_never_used"); }
    for (int i = 0; i < N_TRK; i++)
        if (s->trk_http_pending[0][i]) { printf("tracker %d still queued\n", i); rc |= fail("queue_not_drained"); }
    if (n_held < N_TRK) { printf("accepted=%d\n", n_held); rc |= fail("black_hole_did_not_answer_the_tcp"); }
    if (worst_ms < STALL_FLOOR_MS) {
        printf("worst=%llu ms — the trap is not stalling the loop, this proves nothing\n",
               (unsigned long long)worst_ms);
        rc |= fail("stall_below_floor");
    }
    if (worst_ms > ITER_LIMIT_MS) {
        printf("one loop iteration blocked %llu ms (limit %d ms)\n",
               (unsigned long long)worst_ms, ITER_LIMIT_MS);
        rc |= fail("iteration_over_1s");
    }
    if (rc == 0) printf("PASS trk_http_stall bounded (worst %llu ms <= %d ms)\n",
                        (unsigned long long)worst_ms, ITER_LIMIT_MS);
    for (int i = 0; i < n_held; i++) close(held[i]);
    close(lfd);
    ntx_session_free(s);
    ntx_netx_free(n);
    return rc;
}
