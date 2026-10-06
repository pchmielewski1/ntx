#include "ntx_https.h"

#include "../net/ntx_addr.h"
#include "../net/ntx_sock.h"
#include "ntx_https_pin.h"

#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

#ifdef NTX_HTTP_TEST_HOOKS
static int (*g_test_handshake)(const char *host, uint16_t port, ntx_tls *out);
static ssize_t (*g_test_read)(ntx_tls *t, void *buf, size_t n);

void ntx_https_test_reset_hooks(void) {
    g_test_handshake = NULL;
    g_test_read = NULL;
}

void ntx_https_test_set_handshake(int (*fn)(const char *host, uint16_t port,
                                            ntx_tls *out)) {
    g_test_handshake = fn;
}

void ntx_https_test_set_read(ssize_t (*fn)(ntx_tls *t, void *buf, size_t n)) {
    g_test_read = fn;
}
#endif

static ssize_t hs_read(ntx_tls *t, void *buf, size_t n) {
#ifdef NTX_HTTP_TEST_HOOKS
    if (g_test_read) return g_test_read(t, buf, n);
#endif
    return ntx_tls_read(t, buf, n);
}

int ntx_https_handshake_fd(const char *host, uint16_t port, int fd, ntx_tls *out) {
    uint8_t pins[NTX_HTTPS_PIN_MAX][32];
    int npins = 0;
    int rc;
    if (!host || fd < 0 || !out) return -1;
    if (ntx_https_pin_lookup(host, port, pins, NTX_HTTPS_PIN_MAX, &npins) == -1) {
        close(fd);
        return -1;
    }
#ifdef NTX_HTTP_TEST_HOOKS
    if (g_test_handshake) {
        /* the mock takes over out->fd (the real fd was set by connect) */
        int real = out->fd;
        rc = g_test_handshake(host, port, out);
        if (rc != NTX_TLS_OK) close(real);
    } else {
        const char *const alpn[1] = {"http/1.1"};
        rc = ntx_tls_handshake_ex(out, fd, host, pins, npins, 15, alpn, 1);
        if (rc != NTX_TLS_OK) close(fd);
    }
#else
    {
        const char *const alpn[1] = {"http/1.1"};
        rc = ntx_tls_handshake_ex(out, fd, host, pins, npins, 15, alpn, 1);
        if (rc != NTX_TLS_OK) close(fd);
    }
#endif
    if (rc != NTX_TLS_OK) return rc == NTX_TLS_PIN_FAIL ? -2 : -1;
    if (npins == 0 && ntx_https_tofu_enabled() && out->leaf_pin_valid)
        ntx_https_tofu_note(host, out->leaf_pin);
    return 0;
}

int ntx_https_connect(const char *host, uint16_t port, ntx_tls *out) {
    ntx_addr a;
    int fd;
    if (!host || !port || !out) return -1;
    {
        uint8_t pins[NTX_HTTPS_PIN_MAX][32];
        int npins = 0;
        if (ntx_https_pin_lookup(host, port, pins, NTX_HTTPS_PIN_MAX, &npins) == -1)
            return -1; /* no pins + TOFU off → early fail before tcp */
    }
    if (ntx_sock_resolve(host, &a) != 0) return -1;
    fd = (a.family == NTX_AF_INET6) ? ntx_sock_tcp6() : ntx_sock_tcp4();
    if (fd < 0) return -1;
    if (ntx_sock_connect_addr(fd, &a, port) != 0) {
        close(fd);
        return -1;
    }
    out->fd = fd;
    return ntx_https_handshake_fd(host, port, fd, out);
}

/* Response headers up to \r\n\r\n (RFC 7230).
   buf: min cap >= hlen+1. 0=ok (buf = headers + NUL, *out_len = hlen),
   -1=I/O or EOF before the end of the headers, -2=headers > cap. */
int ntx_https_read_headers(ntx_tls *t, char *buf, size_t cap, size_t *out_len) {
    size_t off = 0;
    if (!t || !buf || !out_len || cap < 5) return -1;
    for (;;) {
        ssize_t n = hs_read(t, buf + off, 1);
        if (n <= 0) return -1;
        off++;
        if (off >= cap) return -2; /* the NUL would not fit */
        if (off >= 4 && buf[off - 4] == '\r' && buf[off - 3] == '\n' &&
            buf[off - 2] == '\r' && buf[off - 1] == '\n') {
            buf[off] = '\0';
            *out_len = off;
            return 0;
        }
    }
}

/* Content-Length from the headers (case-insensitive); missing/non-numeric → 0 */
static int hdr_ci_find(const char *h, size_t n, const char *needle) {
    size_t nl = strlen(needle);
    size_t i;
    if (n < nl) return -1;
    for (i = 0; i + nl <= n; i++) {
        size_t j;
        for (j = 0; j < nl; j++) {
            char a = h[i + j];
            if (a >= 'A' && a <= 'Z') a = (char)(a + 32);
            if (a != needle[j]) break;
        }
        if (j == nl) return (int)i;
    }
    return -1;
}

static long resp_content_length(const char *h, size_t n) {
    int at = hdr_ci_find(h, n, "content-length:");
    const char *p;
    if (at < 0) return 0;
    p = h + at + (int)strlen("content-length:");
    while (*p == ' ') p++;
    if (!isdigit((unsigned char)*p)) return 0;
    long v = 0;
    while (isdigit((unsigned char)*p)) {
        /* attacker-controlled digits: saturate instead of overflowing (UB); the caller rejects it as too big */
        if (v > (LONG_MAX - 9) / 10) return LONG_MAX;
        v = v * 10 + (*p - '0');
        p++;
    }
    return v;
}

/* Chunked transfer coding (RFC 7230 4.1), decoded in place.  The decoded size never exceeds the encoded
 * size, so writing at the front while reading ahead is safe.  Returns 0 when the terminating chunk and
 * trailers are complete (*out_n = body bytes), 1 when more input is needed, -1 when malformed. */
static int dechunk_run(char *buf, size_t n, size_t *out_n, int commit) {
    size_t r = 0, w = 0;
    for (;;) {
        size_t sz = 0;
        int digits = 0;
        while (r < n && isxdigit((unsigned char)buf[r])) {
            if (++digits > 8) return -1;
            char c = buf[r++];
            sz = (sz << 4) | (size_t)(c <= '9' ? c - '0' : (c | 32) - 'a' + 10);
        }
        if (r >= n) return 1;
        if (!digits) return -1;
        if (buf[r] == ';') { /* chunk extension: skip to end of line */
            while (r < n && buf[r] != '\r') r++;
            if (r >= n) return 1;
        }
        if (buf[r] != '\r') return -1;
        if (r + 1 >= n) return 1;
        if (buf[r + 1] != '\n') return -1;
        r += 2;
        if (sz == 0) { /* trailers, then an empty line */
            for (;;) {
                if (r + 1 >= n) return 1;
                if (buf[r] == '\r' && buf[r + 1] == '\n') {
                    *out_n = w;
                    return 0;
                }
                while (r + 1 < n && !(buf[r] == '\r' && buf[r + 1] == '\n')) r++;
                if (r + 1 >= n) return 1;
                r += 2;
            }
        }
        if (n - r < sz + 2) return 1;
        if (buf[r + sz] != '\r' || buf[r + sz + 1] != '\n') return -1;
        if (commit) memmove(buf + w, buf + r, sz);
        w += sz;
        r += sz + 2;
    }
}

int ntx_http_dechunk(char *buf, size_t n, size_t *out_n) {
    size_t dn = 0;
    int rc = dechunk_run(buf, n, &dn, 0); /* validate first: never leave a half-decoded buffer behind */
    if (rc != 0) return rc;
    rc = dechunk_run(buf, n, out_n, 1);
    return rc;
}

/* Headers + body per Content-Length (no CL → body 0).
   0=ok (status 200/206; out = full response + NUL, *out_n = hlen+body),
   -1=I/O or a status other than 200/206, -2=response > cap. */
int ntx_https_read_response(ntx_tls *t, char *out, size_t cap, size_t *out_n) {
    size_t hlen = 0, got = 0;
    long cl;
    int status;
    int hr;
    if (!t || !out || !out_n || cap < 5) return -1;
    hr = ntx_https_read_headers(t, out, cap, &hlen);
    if (hr != 0) return hr; /* -1 I/O / -2 too large */
    status = ntx_https_status_code(out);
    if (status != 200 && status != 206) return -1;
    if (hdr_ci_find(out, hlen, "transfer-encoding: chunked") >= 0) {
        size_t have = 0, dn = 0;
        for (;;) {
            int dr;
            if (have >= cap - hlen - 1) return -2;
            ssize_t n = hs_read(t, out + hlen + have, cap - hlen - 1 - have);
            if (n <= 0) return -1;
            have += (size_t)n;
            /* dry run: decoding in place only happens once the body is complete */
            dr = dechunk_run(out + hlen, have, &dn, 0);
            if (dr < 0) return -1;
            if (dr == 0) break;
        }
        if (ntx_http_dechunk(out + hlen, have, &dn) != 0) return -1;
        out[hlen + dn] = '\0';
        *out_n = hlen + dn;
        return 0;
    }
    cl = resp_content_length(out, hlen);
    if ((size_t)cl > cap - hlen - 1) return -2;
    while (got < (size_t)cl) {
        ssize_t n = hs_read(t, out + hlen + got, (size_t)cl - got);
        if (n <= 0) return -1;
        got += (size_t)n;
    }
    out[hlen + got] = '\0';
    *out_n = hlen + got;
    return 0;
}

/* Status code from the status line; -1 when malformed */
int ntx_https_status_code(const char *hdrs) {
    int s = 0;
    const char *p;
    if (!hdrs || strncmp(hdrs, "HTTP/", 5) != 0) return -1;
    p = hdrs + 5;
    while (*p && *p != ' ') p++; /* version (e.g. 1.1) */
    if (*p != ' ') return -1;
    p++;
    if (!isdigit((unsigned char)*p)) return -1;
    while (isdigit((unsigned char)*p)) {
        if (s > 9999) return -1; /* not an HTTP status; also keeps s * 10 from overflowing */
        s = s * 10 + (*p - '0');
        p++;
    }
    return s;
}
