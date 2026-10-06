/* ntx_http_get_range https:// branch (mock handshake + read
   hook; SOCKS5 proxy — http_connect is already proxy-aware; webseed
   range 206; unified handshake 1.3-first + ALPN http/1.1 only) */
#define NTX_HTTP_TEST_HOOKS
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
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

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int listen4(uint16_t *port_out) {
    int lfd = ntx_sock_tcp4();
    uint16_t p;
    if (lfd < 0) return -1;
    p = ntx_sock_bind0(lfd);
    if (p == 0) { close(lfd); return -1; }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return -1; }
    *port_out = p;
    return lfd;
}

/* Mock handshake: out->fd = sv[0] (socketpair = "tunnel"); the real fd is NOT
   closed here — close(fd) in http_get_range_tls closes it. sv[1] is kept
   static (cleaned up in the test). The mock simulates the state after the unified
   handshake (ntx_tls_handshake_ex): 1.3-first + ALPN http/1.1 only (no h2)
   — last_hs_* is a copy of out->ver/out->alpn from the time of the handshake. */
static int mock_sv[2] = {-1, -1};
static int last_hs_ver;
static char last_hs_alpn[16];

static int mock_hs_tunnel(const char *host, uint16_t port, ntx_tls *out) {
    (void)host;
    (void)port;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, mock_sv) != 0) return NTX_TLS_FAIL;
    out->fd = mock_sv[0];
    out->ready = 1;
    out->leaf_pin_valid = 0;
    out->ver = 13; /* unified handshake: TLS 1.3 (fallback 1.2) */
    {
        uint8_t secret[32];
        memset(secret, 0x42, sizeof secret); /* mock traffic secret: any value works */
        ntx_tls13_dir_init(&out->w13, secret);
        ntx_tls13_dir_init(&out->r13, secret);
    }
    memcpy(out->alpn, "http/1.1", 8); /* ALPN: http/1.1 only (no h2) */
    last_hs_ver = out->ver;
    memcpy(last_hs_alpn, out->alpn, sizeof last_hs_alpn);
    return 0;
}

static void mock_sv_close(void) {
    if (mock_sv[0] >= 0) { close(mock_sv[0]); mock_sv[0] = -1; }
    if (mock_sv[1] >= 0) { close(mock_sv[1]); mock_sv[1] = -1; }
}

/* Read hook: fixture (headers + body) — covers ntx_https_read_response */
static char fx_data[4096];
static size_t fx_off, fx_len;

static ssize_t mock_read_fx(ntx_tls *t, void *buf, size_t n) {
    size_t k;
    (void)t;
    if (fx_off >= fx_len) return 0;
    k = n;
    if (k > fx_len - fx_off) k = fx_len - fx_off;
    memcpy(buf, fx_data + fx_off, k);
    fx_off += k;
    return (ssize_t)k;
}

static void fx_set(const char *hdrs, const uint8_t *body, size_t blen) {
    size_t hlen = strlen(hdrs);
    if (hlen + blen > sizeof fx_data) { fx_len = 0; return; }
    memcpy(fx_data, hdrs, hlen);
    memcpy(fx_data + hlen, body, blen);
    fx_len = hlen + blen;
    fx_off = 0;
}


/* Chunked transfer coding: real HTTPS/HTTP trackers behind proxies answer with it and no Content-Length. */

static int test_dechunk_pure(void) {
    char a[] = "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";
    size_t n = 0;
    if (ntx_http_dechunk(a, sizeof a - 1, &n) != 0 || n != 9 || memcmp(a, "Wikipedia", 9) != 0)
        return fail("dechunk basic");
    char b[] = "3;ext=1\r\nabc\r\n0\r\nX-Trailer: y\r\n\r\n";
    if (ntx_http_dechunk(b, sizeof b - 1, &n) != 0 || n != 3 || memcmp(b, "abc", 3) != 0)
        return fail("dechunk ext+trailer");
    char c[] = "4\r\nWiki\r\n5\r\npe";
    if (ntx_http_dechunk(c, sizeof c - 1, &n) != 1) return fail("dechunk incomplete");
    char d[] = "zz\r\nabc\r\n0\r\n\r\n";
    if (ntx_http_dechunk(d, sizeof d - 1, &n) != -1) return fail("dechunk bad hex");
    char e[] = "3\r\nabcXX0\r\n\r\n";
    if (ntx_http_dechunk(e, sizeof e - 1, &n) != -1) return fail("dechunk missing crlf after data");
    char f[] = "FFFFFFFFF\r\nabc";
    if (ntx_http_dechunk(f, sizeof f - 1, &n) != -1) return fail("dechunk oversize size line");
    char g[] = "0\r\n\r\n";
    if (ntx_http_dechunk(g, sizeof g - 1, &n) != 0 || n != 0) return fail("dechunk empty");
    printf("PASS dechunk pure\n");
    return 0;
}

static int test_https_chunked(void) {
    uint16_t port;
    int lfd = listen4(&port);
    char url[64];
    uint8_t out[64];
    size_t n = 0;
    if (lfd < 0) return fail("chunk listen");
    snprintf(url, sizeof url, "https://127.0.0.1:%u/x", (unsigned)port);
    fx_set("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n", (const uint8_t *)"2\r\nd8\r\n3\r\n:2e\r\n0\r\n\r\n", 20);
    ntx_https_test_set_handshake(mock_hs_tunnel);
    ntx_https_test_set_read(mock_read_fx);
    int rc = ntx_http_get_range(url, 0, 0, out, sizeof out, &n);
    mock_sv_close();
    close(lfd);
    ntx_https_test_reset_hooks();
    if (rc != 0 || n != 5 || memcmp(out, "d8:2e", 5) != 0) return fail("https chunked body decoded");
    printf("PASS https chunked\n");
    return 0;
}

typedef struct {
    int lfd;
    const char *resp;
    size_t rn;
} srv_ctx;

static void *plain_srv(void *arg) {
    srv_ctx *c = arg;
    int fd = accept(c->lfd, NULL, NULL);
    if (fd < 0) return NULL;
    char rq[1024];
    (void)!recv(fd, rq, sizeof rq, 0);
    (void)!send(fd, c->resp, c->rn, MSG_NOSIGNAL);
    close(fd);
    return NULL;
}

static int test_http_chunked(void) {
    uint16_t port;
    int lfd = listen4(&port);
    if (lfd < 0) return fail("http chunk listen");
    fcntl(lfd, F_SETFL, fcntl(lfd, F_GETFL) & ~O_NONBLOCK); /* the server thread blocks in accept() */
    static const char resp[] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
                               "2\r\nd8\r\n3\r\n:2e\r\n0\r\n\r\n";
    srv_ctx c = {lfd, resp, sizeof resp - 1};
    pthread_t th;
    pthread_create(&th, NULL, plain_srv, &c);
    char url[64];
    snprintf(url, sizeof url, "http://127.0.0.1:%u/announce", (unsigned)port);
    uint8_t out[64];
    size_t n = 0;
    int rc = ntx_http_get(url, out, sizeof out, &n);
    pthread_join(th, NULL);
    close(lfd);
    if (rc != 0 || n != 5 || memcmp(out, "d8:2e", 5) != 0) return fail("http chunked body decoded");
    printf("PASS http chunked\n");
    return 0;
}

int main(void) {
    if (test_dechunk_pure()) return 1;
    if (test_https_chunked()) return 1;
    if (test_http_chunked()) return 1;
    printf("ALL PASS\n");
    return 0;
}
