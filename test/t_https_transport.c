/* ntx_https_connect — handshake + TOFU note (mock handshake hook) */
#define NTX_HTTP_TEST_HOOKS
#include <errno.h>
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
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

/* no hand-typed bytes — the pin comes from the vector on disk */
static int read_pin_vec(uint8_t pin[32]) {
    FILE *f = fopen("test/vectors/tls_spki/test_leaf.pin.hex", "r");
    char hex[65];
    int i;
    if (!f) return 0;
    hex[0] = '\0';
    for (i = 0; i < 64; i++) {
        int c = fgetc(f);
        if (c == EOF || c == '\n' || c == '\r') break;
        hex[i] = (char)c;
    }
    hex[i] = '\0';
    fclose(f);
    if (strlen(hex) != 64u) return 0;
    for (i = 0; i < 32; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) return 0;
        pin[i] = (uint8_t)v;
    }
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

/* mock: a ready ntx_tls on a real fd + leaf_pin from the vector (TOFU path) */
static int mock_hs_to(const char *host, uint16_t port, ntx_tls *out) {
    uint8_t pin[32];
    (void)host;
    (void)port;
    out->ready = 1;
    if (read_pin_vec(pin)) {
        memcpy(out->leaf_pin, pin, 32);
        out->leaf_pin_valid = 1;
    }
    return 0;
}

static int mock_hs_pinfail(const char *host, uint16_t port, ntx_tls *out) {
    (void)host;
    (void)port;
    (void)out;
    return NTX_TLS_PIN_FAIL;
}

static int mock_hs_fail(const char *host, uint16_t port, ntx_tls *out) {
    (void)host;
    (void)port;
    (void)out;
    return NTX_TLS_FAIL;
}

/* 1. first host (npins=0, TOFU on) → connect 0 + TOFU note stored
   2. second connect (npins=1 from TOFU) → no new record (count == 1) */
static int test_handshake_tofu_note(void) {
    const char *binpath = "test/.scratch/tofu_T17b.bin";
    uint8_t pin[32];
    uint8_t out_pins[NTX_HTTPS_PIN_MAX][32];
    int npins = -1;
    ntx_tls tls;
    uint16_t port;
    int lfd;

    if (!read_pin_vec(pin)) return fail("tofu read pin vector");
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST)
        return fail("tofu mkdir");
    unlink(binpath);
    ntx_https_set_tofu_path(binpath);
    ntx_https_tofu_set_enabled(1);
    ntx_https_pin_test_pool_clear();
    ntx_https_pin_set_file(NULL);

    ntx_https_test_set_handshake(mock_hs_to);
    lfd = listen4(&port);
    if (lfd < 0) return fail("tofu listen");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != 0) {
        close(lfd);
        return fail("tofu connect 1st");
    }
    if (tls.fd < 0) { close(lfd); return fail("tofu fd >= 0"); }
    close(tls.fd);
    close(lfd);

    if (ntx_https_pin_lookup("127.0.0.2", 0, out_pins, NTX_HTTPS_PIN_MAX, &npins) != 0)
        return fail("tofu lookup after note");
    if (npins != 1) return fail("tofu npins 1 after note");
    if (memcmp(out_pins[0], pin, 32) != 0) return fail("tofu pin match");

    lfd = listen4(&port);
    if (lfd < 0) return fail("tofu listen2");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != 0) {
        close(lfd);
        return fail("tofu connect 2nd");
    }
    close(tls.fd);
    close(lfd);
    if (ntx_https_tofu_test_count() != 1) return fail("tofu count 1 after 2nd");

    ntx_https_test_reset_hooks();
    printf("PASS handshake tofu note\n");
    return 0;
}

/* pin fail → -2; a plain handshake fail → -1 (fd closed in the production code) */
static int test_handshake_fail_map(void) {
    uint8_t pin[32];
    uint8_t out_pins[NTX_HTTPS_PIN_MAX][32];
    int npins = -1;
    ntx_tls tls;
    uint16_t port;
    int lfd;

    if (!read_pin_vec(pin)) return fail("failmap read pin vector");

    /* host with a pin in the pool → npins=1 (no TOFU note) */
    if (ntx_https_pin_test_pool_add("127.0.0.2", pin) != 1)
        return fail("failmap pool add");
    if (ntx_https_pin_lookup("127.0.0.2", 0, out_pins, NTX_HTTPS_PIN_MAX, &npins) != 0)
        return fail("failmap lookup");
    if (npins != 1) return fail("failmap npins 1");

    ntx_https_test_set_handshake(mock_hs_pinfail);
    lfd = listen4(&port);
    if (lfd < 0) return fail("failmap listen 1");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != -2) {
        close(lfd);
        return fail("failmap rc -2");
    }
    close(lfd);

    ntx_https_test_set_handshake(mock_hs_fail);
    lfd = listen4(&port);
    if (lfd < 0) return fail("failmap listen 2");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != -1) {
        close(lfd);
        return fail("failmap rc -1");
    }
    close(lfd);

    ntx_https_pin_test_pool_clear();
    ntx_https_test_reset_hooks();
    printf("PASS handshake fail map\n");
    return 0;
}

/* mock returns a ready ntx_tls with a pipe fd (the real tcp fd is closed) —
   out->fd is usable for further I/O */
static int pipe_rd = -1;

static int mock_hs_pipe(const char *host, uint16_t port, ntx_tls *out) {
    int real = out->fd;
    int p[2];
    (void)host;
    (void)port;
    if (pipe(p) != 0) return NTX_TLS_FAIL;
    if (real >= 0) close(real);
    pipe_rd = p[0];
    out->fd = p[1];
    out->ready = 1;
    out->leaf_pin_valid = 0;
    return 0;
}

static int test_mock_pipe_fd(void) {
    ntx_tls tls;
    uint16_t port;
    int lfd;
    const char msg[] = "hello";
    char buf[16];

    ntx_https_test_set_handshake(mock_hs_pipe);
    lfd = listen4(&port);
    if (lfd < 0) return fail("pipe listen");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.1", port, &tls) != 0) {
        close(lfd);
        return fail("pipe connect");
    }
    if (tls.fd < 0) { close(lfd); return fail("pipe fd >= 0"); }
    if (write(tls.fd, msg, 5) != 5) { close(lfd); return fail("pipe write"); }
    if (read(pipe_rd, buf, sizeof buf) != 5 || memcmp(buf, msg, 5) != 0) {
        close(lfd);
        return fail("pipe read back");
    }
    close(tls.fd);
    close(pipe_rd);
    pipe_rd = -1;
    close(lfd);
    ntx_https_test_reset_hooks();
    printf("PASS mock pipe fd\n");
    return 0;
}

/* headers up to \r\n\r\n + status line (fixture via the read hook) */
static char fx_data[256];
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

static int test_read_headers(void) {
    ntx_tls tls;
    char buf[128];
    size_t hlen = 0;
    const char *fx = "HTTP/1.1 200 OK\r\nServer: mock\r\nContent-Length: 5\r\n\r\n";

    memset(&tls, 0, sizeof tls);
    tls.ready = 1;
    fx_len = strlen(fx);
    memcpy(fx_data, fx, fx_len);
    fx_off = 0;
    ntx_https_test_set_read(mock_read_fx);

    if (ntx_https_read_headers(&tls, buf, sizeof buf, &hlen) != 0)
        return fail("hdr read");
    if (hlen != fx_len) return fail("hdr len");
    if (memcmp(buf, fx, hlen) != 0) return fail("hdr bytes");
    if (buf[hlen] != '\0') return fail("hdr NUL");
    if (ntx_https_status_code(buf) != 200) return fail("hdr status 200");

    if (ntx_https_status_code("HTTP/1.0 404 Not Found\r\n") != 404)
        return fail("status 404");
    if (ntx_https_status_code("garbage") != -1) return fail("status bad form");
    if (ntx_https_status_code(NULL) != -1) return fail("status null");

    fx_len = 5; /* "HTTP/" without \r\n\r\n → EOF → -1 */
    fx_off = 0;
    if (ntx_https_read_headers(&tls, buf, sizeof buf, &hlen) != -1)
        return fail("hdr eof");

    fx_len = strlen(fx);
    fx_off = 0;
    if (ntx_https_read_headers(&tls, buf, 10, &hlen) != -2)
        return fail("hdr cap");

    ntx_https_test_reset_hooks();
    printf("PASS read headers\n");
    return 0;
}

/* body per Content-Length; 200/206 ok; 404 → -1; CL > delivered → -1 */
static int test_read_response(void) {
    ntx_tls tls;
    char out[256];
    size_t n = 0;
    const char *fx200 = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello";
    const char *fx206 = "HTTP/1.1 206 Partial Content\r\nContent-Length: 3\r\n\r\nabc";
    const char *fx404 = "HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nno";
    const char *fxcl = "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nshort";

    memset(&tls, 0, sizeof tls);
    tls.ready = 1;
    ntx_https_test_set_read(mock_read_fx);

    fx_len = strlen(fx200);
    memcpy(fx_data, fx200, fx_len);
    fx_off = 0;
    if (ntx_https_read_response(&tls, out, sizeof out, &n) != 0)
        return fail("resp 200");
    if (n < 5 || memcmp(out + n - 5, "hello", 5) != 0) return fail("resp body");
    if (out[n] != '\0') return fail("resp NUL");

    fx_len = strlen(fx206);
    memcpy(fx_data, fx206, fx_len);
    fx_off = 0;
    if (ntx_https_read_response(&tls, out, sizeof out, &n) != 0)
        return fail("resp 206");
    if (n < 3 || memcmp(out + n - 3, "abc", 3) != 0) return fail("resp 206 body");

    fx_len = strlen(fx404);
    memcpy(fx_data, fx404, fx_len);
    fx_off = 0;
    if (ntx_https_read_response(&tls, out, sizeof out, &n) != -1)
        return fail("resp 404");

    fx_len = strlen(fxcl);
    memcpy(fx_data, fxcl, fx_len);
    fx_off = 0;
    if (ntx_https_read_response(&tls, out, sizeof out, &n) != -1)
        return fail("resp cl eof");

    fx_len = strlen(fx200);
    memcpy(fx_data, fx200, fx_len);
    fx_off = 0;
    if (ntx_https_read_response(&tls, out, 20, &n) != -2)
        return fail("resp cap");

    /* hostile numbers: no signed overflow (UBSan), and nothing absurd is accepted */
    {
        const char *fxhuge = "HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999\r\n\r\nx";
        const char *fxwrap = "HTTP/1.1 200 OK\r\nContent-Length: 18446744073709551621\r\n\r\nhello";
        fx_len = strlen(fxhuge);
        memcpy(fx_data, fxhuge, fx_len);
        fx_off = 0;
        if (ntx_https_read_response(&tls, out, sizeof out, &n) == 0) return fail("resp cl huge accepted");
        fx_len = strlen(fxwrap);
        memcpy(fx_data, fxwrap, fx_len);
        fx_off = 0;
        if (ntx_https_read_response(&tls, out, sizeof out, &n) == 0) return fail("resp cl wrap accepted");
        if (ntx_https_status_code("HTTP/1.1 99999999999999999999 X\r\n") != -1) return fail("status huge");
    }

    ntx_https_test_reset_hooks();
    printf("PASS read response\n");
    return 0;
}

/* handshake_fd: argument validation + reuse after SOCKS CONNECT (semantics) */
static int test_handshake_fd_args(void) {
    ntx_tls tls;
    int p[2];
    if (pipe(p) != 0) return fail("hf pipe");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_handshake_fd(NULL, 443, p[0], &tls) != -1) return fail("hf null host");
    if (ntx_https_handshake_fd("h", 0, p[0], &tls) != -1) return fail("hf null out");
    if (ntx_https_handshake_fd("h", 443, -1, &tls) != -1) return fail("hf bad fd");
    close(p[0]);
    close(p[1]);
    printf("PASS handshake fd args\n");
    return 0;
}

int main(void) {
    if (test_handshake_fd_args() != 0) return 1;
    if (test_mock_pipe_fd() != 0) return 1;
    if (test_handshake_fail_map() != 0) return 1;
    if (test_read_headers() != 0) return 1;
    if (test_read_response() != 0) return 1;
    if (test_handshake_tofu_note() != 0) return 1;
    return 0;
}
