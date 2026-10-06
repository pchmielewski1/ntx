#include "ntx_http.h"
#include "ntx_bencode.h"
#include "ntx_tracker.h"
#include "ntx_http_url.h"
#include "ntx_https.h"
#include "../core/ntx_config.h"
#include "../net/ntx_proxy.h"
#include "../net/ntx_sock.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#define HTTP_CONNECT_MS 5000
#define HTTP_IO_MS      5000

static int http_wait_connect(int fd) {
    struct pollfd pfd = {.fd = fd, .events = POLLOUT};
    if (poll(&pfd, 1, HTTP_CONNECT_MS) <= 0) return -1;
    int soerr = 0;
    socklen_t sl = sizeof soerr;
    if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0 || soerr != 0) return -1;
    return 0;
}

/* Back to a blocking socket with receive/send timeouts: the HTTP exchange below is synchronous. */
static void http_set_blocking(int fd) {
    int fl = fcntl(fd, F_GETFL);
    if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    struct timeval tv = {HTTP_IO_MS / 1000, (HTTP_IO_MS % 1000) * 1000};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
}

static int http_tcp_connect_addr(const ntx_addr *addr, uint16_t port) {
    int fd = ntx_addr_is_v6(addr) ? ntx_sock_tcp6() : ntx_sock_tcp4();
    if (fd < 0) return -1;
    if (ntx_sock_connect_addr(fd, addr, port) != 0) {
        close(fd);
        return -1;
    }
    if (http_wait_connect(fd) != 0) {
        close(fd);
        return -1;
    }
    http_set_blocking(fd);
    return fd;
}

static const char *g_http_proxy_host;
static uint16_t g_http_proxy_port;

void ntx_http_set_proxy(const char *host, uint16_t port) {
    g_http_proxy_host = host;
    g_http_proxy_port = port;
}

void ntx_http_clear_proxy(void) {
    g_http_proxy_host = NULL;
    g_http_proxy_port = 0;
}

static int http_connect(const char *host, uint16_t port, int *fd_out) {
    if (g_http_proxy_host && g_http_proxy_port) {
        int fd = ntx_sock_tcp_connect_host(g_http_proxy_host, g_http_proxy_port);
        if (fd < 0) return -1;
        ntx_addr pa;
        if (http_wait_connect(fd) != 0 || ntx_sock_resolve(host, &pa) != 0) {
            close(fd);
            return -1;
        }
        ntx_proxy px;
        ntx_proxy_init(&px, fd, &pa, port, NULL, NULL, NULL, NULL);
        /* The proxy answers in milliseconds, not microseconds: step, and wait for its reply between steps. */
        for (int waited = 0; waited < HTTP_CONNECT_MS; waited += 50) {
            int rc = ntx_proxy_step(&px, 1);
            if (rc < 0) break;
            if (rc == 1) {
                http_set_blocking(fd);
                *fd_out = fd;
                return 0;
            }
            struct pollfd pf = {.fd = fd, .events = POLLIN};
            if (poll(&pf, 1, 50) < 0 && errno != EINTR) break;
        }
        close(fd);
        return -1;
    }
    ntx_addr addr;
    if (ntx_sock_resolve(host, &addr) != 0) return -1;
    int fd = http_tcp_connect_addr(&addr, port);
    if (fd < 0) return -1;
    *fd_out = fd;
    return 0;
}

static const uint8_t *http_memmem(const uint8_t *hay, size_t n, const void *needle, size_t m) {
    if (m == 0) return hay;
    if (m > n) return NULL;
    const uint8_t *nd = (const uint8_t *)needle;
    for (size_t i = 0; i + m <= n; i++) {
        if (memcmp(hay + i, nd, m) == 0) return hay + i;
    }
    return NULL;
}

static long parse_content_length(const uint8_t *hdr, size_t n) {
    const uint8_t *p = http_memmem(hdr, n, "Content-Length:", 15);
    if (!p) return -1;
    p += 15;
    size_t rest = n - (size_t)(p - hdr);
    while (rest > 0 && *p == ' ') {
        p++;
        rest--;
    }
    long v = 0;
    int any = 0;
    while (rest > 0 && *p >= '0' && *p <= '9') {
        if (v > (LONG_MAX - 9) / 10) return -1; /* absurd length from the server: treat as absent, no UB */
        v = v * 10 + (long)(*p - '0');
        p++;
        rest--;
        any = 1;
    }
    return any ? v : -1;
}

static int http_is_chunked(const uint8_t *hdr, size_t n) {
    static const char key[] = "transfer-encoding:";
    for (size_t i = 0; i + sizeof key - 1 <= n; i++) {
        size_t j = 0;
        while (j < sizeof key - 1 && (hdr[i + j] | 32) == (uint8_t)key[j]) j++;
        if (j != sizeof key - 1) continue;
        size_t k = i + j;
        while (k < n && hdr[k] == ' ') k++;
        static const char v[] = "chunked";
        size_t m = 0;
        while (m < sizeof v - 1 && k + m < n && (hdr[k + m] | 32) == (uint8_t)v[m]) m++;
        return m == sizeof v - 1;
    }
    return 0;
}

static long parse_status_code(const uint8_t *hdr, size_t n) {
    if (n < 12 || memcmp(hdr, "HTTP/", 5) != 0) return -1;
    const uint8_t *p = memchr(hdr, ' ', n);
    if (!p) return -1;
    p++;
    long code = 0;
    while ((size_t)(p - hdr) < n && *p >= '0' && *p <= '9') {
        if (code > 9999) return -1;
        code = code * 10 + (*p - '0');
        p++;
    }
    return code;
}

/* Shared GET builder (whole resource or Range: bytes=off..off+len-1).
   0=ok (req = full request + \r\n\r\n), -1=overflow/bad parameters. */
static int http_build_get(const char *path, const char *host_hdr, uint64_t off,
                          uint64_t len, char *req, size_t cap) {
    int rl;
    if (!path || !host_hdr || !req || cap == 0) return -1;
    /* defence in depth: whatever the caller parsed, never put a control byte or space on the wire */
    for (const char *c = path; *c; c++)
        if ((unsigned char)*c <= 0x20 || *c == 0x7f) return -1;
    for (const char *c = host_hdr; *c; c++)
        if ((unsigned char)*c <= 0x20 || *c == 0x7f) return -1;
    if (len > 0)
        rl = snprintf(req, cap,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ntx/" NTX_VERSION "\r\n"
                      "Range: bytes=%llu-%llu\r\nConnection: close\r\n\r\n",
                      path, host_hdr, (unsigned long long)off,
                      (unsigned long long)(off + len - 1));
    else
        rl = snprintf(req, cap,
                      "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: ntx/" NTX_VERSION "\r\n"
                      "Connection: close\r\n\r\n",
                      path, host_hdr);
    if (rl <= 0 || (size_t)rl >= cap) return -1;
    return rl;
}

/* https:// — parse → http_connect (proxy-aware) → handshake on the
   tunnel fd → GET/range via ntx_tls_write → response via
   ntx_https_read_response (status 200/206 + CL). */
static int http_get_range_tls(const char *url, uint64_t off, uint64_t len,
                              uint8_t *out, size_t cap, size_t *out_n) {
    ntx_http_url_parts up;
    ntx_tls tls;
    int fd = -1;
    char *rb = NULL;
    size_t rn = 0;
    int rc = -1;

    if (ntx_http_url_parse(url, &up) != 0) return -1;
    ntx_tls_init(&tls);
    if (http_connect(up.host, up.port, &fd) != 0) return -1;
    if (ntx_https_handshake_fd(up.host, up.port, fd, &tls) != 0) {
        close(fd);
        return -1;
    }
    char host_hdr[320];
    if (up.port == 443)
        snprintf(host_hdr, sizeof host_hdr, "%s", up.host);
    else
        snprintf(host_hdr, sizeof host_hdr, "%s:%u", up.host, (unsigned)up.port);
    char req[2048];
    int rl = http_build_get(up.path, host_hdr, off, len, req, sizeof req);
    if (rl < 0) goto cleanup;
    if (ntx_tls_write(&tls, req, (size_t)rl) != (ssize_t)rl) goto cleanup;
    rb = malloc(cap + 8192);
    if (!rb) goto cleanup;
    if (ntx_https_read_response(&tls, rb, cap + 8192, &rn) != 0) goto cleanup;
    const uint8_t *he = http_memmem((const uint8_t *)rb, rn, "\r\n\r\n", 4);
    if (!he) goto cleanup;
    size_t body_off = (size_t)(he - (const uint8_t *)rb) + 4;
    size_t body_len = rn - body_off;
    if (body_len > cap) body_len = cap;
    memcpy(out, rb + body_off, body_len);
    *out_n = body_len;
    rc = 0;
cleanup:
    free(rb);
    ntx_tls_close(&tls);
    close(fd);
    return rc;
}

int ntx_http_get(const char *url, uint8_t *out, size_t cap, size_t *out_n) {
    return ntx_http_get_range(url, 0, 0, out, cap, out_n);
}

int ntx_http_get_range(const char *url, uint64_t off, uint64_t len, uint8_t *out, size_t cap, size_t *out_n) {
    if (!url || !out || cap == 0) return -1;
    if (strncmp(url, "https://", 8) == 0)
        return http_get_range_tls(url, off, len, out, cap, out_n);
    if (strncmp(url, "http://", 7) != 0) return -1;
    ntx_http_url_parts up;
    if (ntx_http_url_parse(url, &up) != 0) return -1; /* rejects control bytes, userinfo, junk */
    const char *host = up.host;
    uint16_t port = up.port;
    const char *path = up.path;
    char host_hdr[300];
    const char *hb = strchr(host, ':') ? "[" : "", *hc = strchr(host, ':') ? "]" : "";
    if (port == 80)
        snprintf(host_hdr, sizeof host_hdr, "%s%s%s", hb, host, hc);
    else
        snprintf(host_hdr, sizeof host_hdr, "%s%s%s:%u", hb, host, hc, (unsigned)port);
    int fd;
    if (http_connect(host, port, &fd) != 0) return -1;
    char req[2048];
    int rl = http_build_get(path, host_hdr, off, len, req, sizeof req);
    if (rl < 0) {
        close(fd);
        return -1;
    }
    if (send(fd, req, (size_t)rl, 0) != (ssize_t)rl) {
        close(fd);
        return -1;
    }
    const size_t rcap = cap + 8192; /* headers (and chunk framing) come on top of the body */
    uint8_t *buf = malloc(rcap);
    if (!buf) {
        close(fd);
        return -1;
    }
    size_t total = 0;
    for (;;) {
        ssize_t n = recv(fd, buf + total, rcap - total, 0);
        if (n < 0) break;
        if (n == 0) break;
        total += (size_t)n;
        if (total >= 4096) {
            const uint8_t *he = http_memmem(buf, total, "\r\n\r\n", 4);
            if (he) {
                long cl = parse_content_length(buf, (size_t)(he - buf));
                if (cl >= 0 && total >= (size_t)(he - buf) + 4 + (size_t)cl) break;
            }
        }
    }
    close(fd);
    if (total == 0) {
        free(buf);
        return -1;
    }
    const uint8_t *he = http_memmem(buf, total, "\r\n\r\n", 4);
    if (!he) {
        free(buf);
        return -1;
    }
    long status = parse_status_code(buf, (size_t)(he - buf));
    if (status != 200 && status != 206) {
        free(buf);
        return -1;
    }
    size_t body_off = (size_t)(he - buf) + 4;
    size_t body_len = total - body_off;
    if (http_is_chunked(buf, body_off)) {
        size_t dn = 0;
        if (ntx_http_dechunk((char *)buf + body_off, body_len, &dn) != 0 || dn > cap) {
            free(buf);
            return -1;
        }
        memcpy(out, buf + body_off, dn);
        free(buf);
        if (out_n) *out_n = dn;
        return 0;
    }
    long cl = parse_content_length(buf, body_off);
    if (cl >= 0 && (size_t)cl < body_len) body_len = (size_t)cl;
    if (body_len > cap) body_len = cap;
    memcpy(out, buf + body_off, body_len);
    free(buf);
    if (out_n) *out_n = body_len;
    return 0;
}

/* split out of ntx_tracker.c (bodies unchanged, de-static) */

int http_safe_byte(uint8_t b) {
    return (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') ||
           b == '-' || b == '.' || b == '_' || b == '~';
}

void http_put(char *out, size_t cap, size_t *pos, int *ov, const char *s) {
    size_t len = strlen(s);
    if (*ov) return;
    if (*pos + len > cap) {
        *ov = 1;
        return;
    }
    memcpy(out + *pos, s, len);
    *pos += len;
}

void http_put_enc(char *out, size_t cap, size_t *pos, int *ov, const uint8_t *data, size_t n) {
    for (size_t i = 0; i < n; i++) {
        uint8_t b = data[i];
        if (http_safe_byte(b)) {
            char tmp[2] = {(char)b, 0};
            http_put(out, cap, pos, ov, tmp);
        } else {
            char tmp[4];
            snprintf(tmp, sizeof tmp, "%%%02X", (int)b);
            http_put(out, cap, pos, ov, tmp);
        }
    }
}

int http_parse_ipv4(const char *s, size_t n, uint32_t *out) {
    uint32_t parts[4] = {0, 0, 0, 0};
    int idx = 0;
    int cur = 0;
    int have = 0;
    for (size_t i = 0; i < n; i++) {
        char c = s[i];
        if (c == '.') {
            if (!have) return 0;
            if (idx >= 3) return 0;
            parts[idx++] = (uint32_t)cur;
            cur = 0;
            have = 0;
        } else if (c >= '0' && c <= '9') {
            if (cur > 255) return 0;
            cur = cur * 10 + (c - '0');
            have = 1;
        } else {
            return 0;
        }
    }
    if (!have) return 0;
    if (idx != 3) return 0;
    if (cur > 255) return 0;
    parts[3] = (uint32_t)cur;
    *out = (parts[0] << 24) | (parts[1] << 16) | (parts[2] << 8) | parts[3];
    return 1;
}

int http_parse_dict(const ntx_be *be, uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                    uint8_t *ips, uint16_t *ports, int max_peers, char *error, size_t err_cap) {
    return http_parse_dict_ex(be, interval, seeders, leechers, ips, ports, max_peers,
                              NULL, NULL, 0, error, err_cap);
}

int http_parse_dict_ex(const ntx_be *be, uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                       uint8_t *ips, uint16_t *ports, int max_peers,
                       uint8_t ips6[][16], uint16_t *ports6, int max6,
                       char *error, size_t err_cap) {
    const ntx_be *fr = ntx_be_dict_get(be, "failure reason");
    if (fr && fr->t == NTX_BE_STR) {
        if (error && err_cap > 0) {
            size_t c = fr->sn < err_cap - 1 ? fr->sn : err_cap - 1;
            memcpy(error, fr->sp, c);
            error[c] = '\0';
        }
        return -1;
    }
    const ntx_be *iv = ntx_be_dict_get(be, "interval");
    if (iv && iv->t == NTX_BE_INT && interval) *interval = (uint32_t)iv->i;
    const ntx_be *comp = ntx_be_dict_get(be, "complete");
    if (comp && comp->t == NTX_BE_INT && seeders) *seeders = (uint32_t)comp->i;
    const ntx_be *incomp = ntx_be_dict_get(be, "incomplete");
    if (incomp && incomp->t == NTX_BE_INT && leechers) *leechers = (uint32_t)incomp->i;

    int count = 0;
    const ntx_be *peers = ntx_be_dict_get(be, "peers");
    if (peers) {
        if (peers->t == NTX_BE_STR) {
            int c = ntx_tracker_peer_parse_compact(peers->sp, peers->sn, ips, ports, max_peers);
            count = c >= 0 ? c : 0;
        } else if (peers->t == NTX_BE_LIST) {
            for (size_t i = 0; i < peers->ne && count < max_peers; i++) {
                const ntx_be *d = peers->el[i];
                if (!d || d->t != NTX_BE_DICT) continue;
                const ntx_be *ip = ntx_be_dict_get(d, "ip");
                const ntx_be *pt = ntx_be_dict_get(d, "port");
                if (!ip || ip->t != NTX_BE_STR) continue;
                uint32_t addr = 0;
                if (!http_parse_ipv4((const char *)ip->sp, ip->sn, &addr)) continue;
                ips[(size_t)count * 4 + 0] = (uint8_t)(addr >> 24);
                ips[(size_t)count * 4 + 1] = (uint8_t)(addr >> 16);
                ips[(size_t)count * 4 + 2] = (uint8_t)(addr >> 8);
                ips[(size_t)count * 4 + 3] = (uint8_t)addr;
                ports[count] = (pt && pt->t == NTX_BE_INT) ? (uint16_t)pt->i : 0;
                count++;
            }
        }
    }
    if (ips6 && ports6 && max6 > 0) {
        const ntx_be *peers6 = ntx_be_dict_get(be, "peers6");
        if (peers6 && peers6->t == NTX_BE_STR) {
            int c = ntx_tracker_peer_parse_compact6(peers6->sp, peers6->sn, ips6, ports6, max6);
            count += c >= 0 ? c : 0;
        }
    }
    return count;
}
