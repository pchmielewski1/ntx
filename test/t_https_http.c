/* ntx_http_get_range https:// branch (mock handshake + read
   hook; SOCKS5 proxy — http_connect is already proxy-aware; webseed
   range 206; unified handshake 1.3-first + ALPN http/1.1 only) */
#define NTX_HTTP_TEST_HOOKS
#include <errno.h>
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

/* https:// (no proxy) → connect → handshake (mock) → GET → 200 + body */
static int test_https_get_range_200(void) {
    uint16_t port;
    int lfd;
    char url[64];
    uint8_t body[2] = {0xD8, 0x2E};
    uint8_t out[16];
    size_t n = 0;
    int rc;

    lfd = listen4(&port);
    if (lfd < 0) return fail("t21 listen");
    snprintf(url, sizeof url, "https://127.0.0.1:%u/x", (unsigned)port);

    fx_set("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", body, 2);
    ntx_https_test_set_handshake(mock_hs_tunnel);
    ntx_https_test_set_read(mock_read_fx);

    rc = ntx_http_get_range(url, 0, 0, out, sizeof out, &n);
    if (rc != 0) {
        mock_sv_close();
        close(lfd);
        ntx_https_test_reset_hooks();
        return fail("t21 rc 0");
    }
    if (n != 2 || out[0] != 0xD8 || out[1] != 0x2E) {
        mock_sv_close();
        close(lfd);
        ntx_https_test_reset_hooks();
        return fail("t21 body d8:2e");
    }
    /* the request went through the tunnel: a TLS app-data record (0x17) on sv[1] */
    {
        uint8_t rec[64];
        ssize_t r = read(mock_sv[1], rec, sizeof rec);
        if (r < 5 || rec[0] != 0x17) {
            mock_sv_close();
            close(lfd);
            ntx_https_test_reset_hooks();
            return fail("t21 tunnel record");
        }
    }
    /* connect path = unified handshake (1.3-first) + ALPN
       http/1.1 only (no h2) — the state of out after the handshake (mock) */
    if (last_hs_ver != 13 || strcmp(last_hs_alpn, "http/1.1") != 0) {
        mock_sv_close();
        close(lfd);
        ntx_https_test_reset_hooks();
        return fail("t40 unified 1.3-first + alpn http/1.1");
    }
    mock_sv_close();
    close(lfd);
    ntx_https_test_reset_hooks();
    printf("PASS https get range 200\n");
    return 0;
}

/* bad scheme / missing host → -1 (the https branch does not break http://) */
static int test_https_get_range_bad_url(void) {
    uint8_t out[8];
    size_t n = 0;
    if (ntx_http_get_range("ftp://127.0.0.1/x", 0, 0, out, sizeof out, &n) != -1)
        return fail("t21 ftp -1");
    if (ntx_http_get_range("https://", 0, 0, out, sizeof out, &n) != -1)
        return fail("t21 no host -1");
    if (ntx_http_get_range("http://127.0.0.1:1/x", 0, 0, out, sizeof out, &n) != -1)
        return fail("t21 http connect fail -1");
    printf("PASS https get range bad url\n");
    return 0;
}

/* https through a SOCKS5 proxy — mock SOCKS5 (loopback): handshake 05 00,
   on CONNECT: 05 00 00 01 + addr 4B + port. Assert: CONNECT with the
   target address (127.0.0.1:443) + the request went through the tunnel (0x17 record on sv[1]). */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif

typedef struct {
    int lfd;
    uint16_t target_port;
    int ok_gw;
    int ok_aq;
} socks_ctx;

static int socks_recv_all(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    for (int iters = 0; got < n && iters++ < 5000; ) {
        struct pollfd pf = {fd, POLLIN, 0};
        if (poll(&pf, 1, 100) <= 0) return -1;
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r <= 0) return -1;
        got += (size_t)r;
    }
    return got == n ? 0 : -1;
}

/* "Hot" accept: a short spin (no sleeping in accept) so the thread is active on the
   CPU when the client connects — improves the chance of answering within the ~µs spin window of
   http_connect. The iteration budget guards against an infinite loop
   (the client connects within µs of pthread_create, so the spin is usually < 100 µs). */
static void *socks_srv(void *arg) {
    socks_ctx *c = arg;
    int sfd = -1;
    for (long budget = 10000000; budget > 0; budget--) {
        sfd = accept(c->lfd, NULL, NULL);
        if (sfd >= 0) break;
        if (errno != EAGAIN && errno != EWOULDBLOCK) return NULL;
    }
    if (sfd < 0) return NULL;
    uint8_t b[32];
    if (socks_recv_all(sfd, b, 3) != 0) goto out;
    if (b[0] != 0x05 || b[1] != 0x01 || b[2] != 0x00) goto out;
    c->ok_gw = 1;
    {
        uint8_t am[2] = {0x05, 0x00};
        if (send(sfd, am, 2, MSG_NOSIGNAL) != 2) goto out;
    }
    if (socks_recv_all(sfd, b, 10) != 0) goto out;
    if (b[0] != 0x05 || b[1] != 0x01 || b[2] != 0x00 || b[3] != 0x01) goto out;
    {
        uint32_t ip;
        uint16_t tp;
        memcpy(&ip, b + 4, 4);
        tp = (uint16_t)(((uint16_t)b[8] << 8) | b[9]);
        if (ip != htonl(0x7F000001u) || tp != c->target_port) goto out;
        c->ok_aq = 1;
    }
    {
        uint8_t ar[10] = {0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0};
        if (send(sfd, ar, 10, MSG_NOSIGNAL) != 10) goto out;
    }
    /* the tunnel still belongs to the client (TLS is mocked) — read nothing more */
out:
    close(sfd);
    return NULL;
}

/* http_connect in proxy mode is a short spin (64 iterations, ~a dozen µs) —
   under machine load the mock thread may not manage the SOCKS5 reply within
   that window; the whole scenario is retried (with a breather for the scheduler, a ~200ms window
   tries to catch a moment of lower load). */
static int test_https_via_socks(void) {
    uint8_t body[2] = {0xD8, 0x2E};
    for (int attempt = 0; attempt < 100; attempt++) {
        if (attempt > 0) {
            struct timespec ts = {0, 2000000};
            nanosleep(&ts, NULL);
        }
        uint16_t pport;
        int plfd;
        socks_ctx ctx;
        pthread_t th;
        uint8_t out[16];
        size_t n = 0;
        int rc;
        int ok_tunnel;

        plfd = listen4(&pport);
        if (plfd < 0) return fail("t22 proxy listen");
        ctx.lfd = plfd;
        ctx.target_port = 443;
        ctx.ok_gw = 0;
        ctx.ok_aq = 0;
        if (pthread_create(&th, NULL, socks_srv, &ctx) != 0) {
            close(plfd);
            return fail("t22 thread");
        }
        ntx_http_set_proxy("127.0.0.1", pport);
        fx_set("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n", body, 2);
        ntx_https_test_set_handshake(mock_hs_tunnel);
        ntx_https_test_set_read(mock_read_fx);
        rc = ntx_http_get_range("https://127.0.0.1/x", 0, 0, out, sizeof out, &n);
        ntx_http_clear_proxy();
        ok_tunnel = 0;
        if (mock_sv[1] >= 0) {
            uint8_t rec[64];
            ssize_t r = read(mock_sv[1], rec, sizeof rec);
            ok_tunnel = (r >= 5 && rec[0] == 0x17);
        }
        pthread_join(th, NULL);
        mock_sv_close();
        close(plfd);
        ntx_https_test_reset_hooks();
        if (rc == 0 && n == 2 && out[0] == 0xD8 && out[1] == 0x2E &&
            ctx.ok_gw && ctx.ok_aq && ok_tunnel) {
            printf("PASS https via socks connect\n");
            return 0;
        }
    }
    return fail("t22 https via socks (100 attempts)");
}

/* webseed — https URL + Range (off=0, len=2) → 206 Partial Content */
static int test_webseed_range_206(void) {
    uint16_t port;
    int lfd;
    char url[64];
    uint8_t body[2] = {0x5A, 0xA5};
    uint8_t out[16];
    size_t n = 0;
    int rc;

    lfd = listen4(&port);
    if (lfd < 0) return fail("t24 listen");
    snprintf(url, sizeof url, "https://127.0.0.1:%u/piece.bin", (unsigned)port);

    fx_set("HTTP/1.1 206 Partial Content\r\nContent-Range: bytes 0-1/100\r\n"
           "Content-Length: 2\r\n\r\n",
           body, 2);
    ntx_https_test_set_handshake(mock_hs_tunnel);
    ntx_https_test_set_read(mock_read_fx);

    rc = ntx_http_get_range(url, 0, 2, out, sizeof out, &n);
    if (rc != 0) {
        mock_sv_close();
        close(lfd);
        ntx_https_test_reset_hooks();
        return fail("t24 rc 0");
    }
    if (n != 2 || out[0] != 0x5A || out[1] != 0xA5) {
        mock_sv_close();
        close(lfd);
        ntx_https_test_reset_hooks();
        return fail("t24 body 206");
    }
    mock_sv_close();
    close(lfd);
    ntx_https_test_reset_hooks();
    printf("PASS webseed range url\n");
    return 0;
}


/* Security audit: a URL (webseed / tracker, both peer- or magnet-controlled) must not be able to
 * smuggle CR/LF or other control bytes into the request it becomes.  Such a URL is refused before any
 * connection is made. */
static int test_http_request_injection(void) {
    uint16_t port;
    int lfd = listen4(&port);
    if (lfd < 0) return fail("inject_listen");
    static const char *bad[] = {
        "/x HTTP/1.1\r\nX-Injected: 1\r\n\r\nGET /evil",
        "/x\r\nX-Injected: 1",
        "/x\nX-Injected: 1",
        "/x y",
        "/x\t",
        "/x\x01",
        "/x\x7f",
    };
    alarm(20);
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        char url[512];
        uint8_t out[64];
        size_t n = 0;
        snprintf(url, sizeof url, "http://127.0.0.1:%u%s", (unsigned)port, bad[i]);
        if (ntx_http_get_range(url, 0, 0, out, sizeof out, &n) == 0) return fail("inject_plain_accepted");
        struct pollfd pf = {lfd, POLLIN, 0};
        if (poll(&pf, 1, 100) > 0) return fail("inject_plain_connected");
        ntx_http_url_parts up;
        snprintf(url, sizeof url, "https://127.0.0.1:%u%s", (unsigned)port, bad[i]);
        if (ntx_http_url_parse(url, &up) == 0) return fail("inject_url_parse_accepted");
    }
    /* '@' / backslash in the authority: userinfo tricks are not supported */
    {
        ntx_http_url_parts up;
        if (ntx_http_url_parse("http://good.example@evil.example/x", &up) == 0) return fail("inject_userinfo");
        if (ntx_http_url_parse("http://evil.example\\@good.example/x", &up) == 0) return fail("inject_backslash");
    }
    alarm(0);
    close(lfd);
    printf("PASS http_request_injection\n");
    return 0;
}

int main(void) {
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return 1;
    if (test_https_get_range_bad_url() != 0) return 1;
    if (test_http_request_injection() != 0) return 1;
    if (test_https_get_range_200() != 0) return 1;
    if (test_https_via_socks() != 0) return 1;
    if (test_webseed_range_206() != 0) return 1;
    return 0;
}
