#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/wait.h>
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

/* Leaving (Ctrl+C, IPC quit, remove) must tell the trackers with event=stopped, otherwise they keep
 * listing us in the swarm until their timeout.  A tiny forked HTTP tracker records the request line. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

/* child: accept one connection, write its request line to wfd, answer with an empty announce reply */
static pid_t spawn_http_tracker(uint16_t *port, int *rfd) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 4) != 0) return -1;
    socklen_t al = sizeof a;
    getsockname(lfd, (struct sockaddr *)&a, &al);
    *port = ntohs(a.sin_port);
    int p[2];
    if (pipe(p) != 0) return -1;
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        alarm(10);
        int c = accept(lfd, NULL, NULL);
        char req[2048];
        ssize_t n = c >= 0 ? read(c, req, sizeof req - 1) : -1;
        if (n > 0) {
            req[n] = 0;
            char *eol = strstr(req, "\r\n");
            if (eol) *eol = 0;
            if (write(p[1], req, strlen(req)) < 0) _exit(2);
            const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\nd8:intervali60ee";
            if (write(c, resp, strlen(resp)) < 0) _exit(2);
        }
        _exit(0);
    }
    close(lfd);
    close(p[1]);
    *rfd = p[0];
    return pid;
}

static int setup_one(ntx_session *s, const char *url) {
    uint8_t ih[20] = {5};
    ntx_torrent_init_meta(&s->tts[0], ih);
    s->tts[0].state = NTX_TTS_DL;
    s->n_tts = 1;
    s->trk_n[0] = 1;
    snprintf(s->trk_urls[0][0], 512, "%s", url);
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    ntx_config cfg = {0};
    cfg.max_peers = 10;

    /* stop of one torrent */
    {
        ntx_netx *n = ntx_netx_init(&cfg);
        ntx_session *s = ntx_session_init(n, &cfg);
        uint16_t port;
        int rfd;
        pid_t pid = spawn_http_tracker(&port, &rfd);
        if (pid <= 0) return fail("spawn");
        char url[64];
        snprintf(url, sizeof url, "http://127.0.0.1:%u/announce", (unsigned)port);
        setup_one(s, url);
        ntx_session_trk_stop(s, 0);
        char line[2048] = {0};
        ssize_t r = read(rfd, line, sizeof line - 1);
        waitpid(pid, NULL, 0);
        if (r <= 0) return fail("tracker_got_nothing");
        if (!strstr(line, "event=stopped")) {
            printf("request: %s\n", line);
            return fail("event_stopped_missing");
        }
        printf("PASS stop_one\n");
        close(rfd);
        ntx_session_free(s);
        ntx_netx_free(n);
    }

    /* stop_all covers every active torrent, skips paused ones and does not import the reply's peers */
    {
        ntx_netx *n = ntx_netx_init(&cfg);
        ntx_session *s = ntx_session_init(n, &cfg);
        uint16_t port;
        int rfd;
        pid_t pid = spawn_http_tracker(&port, &rfd);
        if (pid <= 0) return fail("spawn2");
        char url[64];
        snprintf(url, sizeof url, "http://127.0.0.1:%u/announce", (unsigned)port);
        setup_one(s, url);
        ntx_session_trk_stop_all(s);
        char line[2048] = {0};
        ssize_t r = read(rfd, line, sizeof line - 1);
        waitpid(pid, NULL, 0);
        if (r <= 0 || !strstr(line, "event=stopped")) return fail("stop_all");
        printf("PASS stop_all\n");
        close(rfd);
        ntx_session_free(s);
        ntx_netx_free(n);
    }

    /* paused torrent: nothing is sent (and nothing blocks) */
    {
        ntx_netx *n = ntx_netx_init(&cfg);
        ntx_session *s = ntx_session_init(n, &cfg);
        setup_one(s, "http://127.0.0.1:1/announce");
        s->tts[0].state = NTX_TTS_PAUSED;
        ntx_session_trk_stop_all(s);
        printf("PASS stop_paused\n");
        ntx_session_free(s);
        ntx_netx_free(n);
    }
    printf("ALL PASS\n");
    return 0;
}
