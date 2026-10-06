/* ntx_http_get_range https:// branch (mock handshake + read
   hook; SOCKS5 proxy — http_connect is already proxy-aware; webseed
   range 206; unified handshake 1.3-first + ALPN http/1.1 only) */
#define NTX_HTTP_TEST_HOOKS
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <time.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls13.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_http.c"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif

/* A real SOCKS5 proxy takes milliseconds to answer.  http_connect used to spin 64 non-blocking steps in
 * microseconds and then give up (and left the socket non-blocking for the HTTP read), so HTTP(S) trackers and
 * DoH never worked through --proxy.  This proxy waits before every reply, then tunnels a canned response. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int recv_all(int fd, uint8_t *b, size_t n) {
    size_t got = 0;
    while (got < n) {
        struct pollfd pf = {fd, POLLIN, 0};
        if (poll(&pf, 1, 3000) <= 0) return -1;
        ssize_t r = recv(fd, b + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static void nap(long ms) {
    struct timespec ts = {ms / 1000, (ms % 1000) * 1000000L};
    nanosleep(&ts, NULL);
}

static volatile int g_ok_connect;

static void *slow_socks(void *arg) {
    int lfd = *(int *)arg;
    int fd = accept(lfd, NULL, NULL);
    if (fd < 0) return NULL;
    uint8_t b[64];
    nap(150);
    if (recv_all(fd, b, 3) != 0) goto out;
    nap(150);
    {
        uint8_t am[2] = {5, 0};
        if (send(fd, am, 2, MSG_NOSIGNAL) != 2) goto out;
    }
    if (recv_all(fd, b, 10) != 0) goto out;
    g_ok_connect = (b[3] == 1);
    nap(150);
    {
        uint8_t ar[10] = {5, 0, 0, 1, 0, 0, 0, 0, 0, 0};
        if (send(fd, ar, 10, MSG_NOSIGNAL) != 10) goto out;
    }
    {
        char rq[1024];
        struct pollfd pf = {fd, POLLIN, 0};
        if (poll(&pf, 1, 3000) <= 0) goto out;
        (void)!recv(fd, rq, sizeof rq, 0);
        nap(100);
        static const char resp[] = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nd8:2e";
        (void)!send(fd, resp, sizeof resp - 1, MSG_NOSIGNAL);
    }
out:
    close(fd);
    return NULL;
}

int main(void) {
    int lfd = ntx_sock_tcp4();
    uint16_t pport = ntx_sock_bind0(lfd);
    if (lfd < 0 || pport == 0 || ntx_sock_listen(lfd, 4) != 0) return fail("listen");
    fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL) & ~O_NONBLOCK); /* the mock proxy thread blocks in accept() */
    pthread_t th;
    pthread_create(&th, NULL, slow_socks, &lfd);
    ntx_http_set_proxy("127.0.0.1", pport);
    uint8_t out[64];
    size_t n = 0;
    int rc = ntx_http_get("http://127.0.0.1:6969/announce", out, sizeof out, &n);
    ntx_http_clear_proxy();
    pthread_join(th, NULL);
    close(lfd);
    if (!g_ok_connect) return fail("proxy never saw CONNECT");
    if (rc != 0 || n != 5 || memcmp(out, "d8:2e", 5) != 0) return fail("slow_proxy_http_get");
    printf("PASS slow_proxy_http_get\n");
    printf("ALL PASS\n");
    return 0;
}
