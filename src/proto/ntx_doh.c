#include "ntx_doh.h"
#include "../ui/ntx_diag.h"
#include "ntx_doh_pins.h"
#include "ntx_h2.h"
#include "ntx_wire.h"
#include "../net/ntx_tls.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

/*
 * DoH A lookup (RFC 8484) over ntx_tls (0xC02B/0xC02F) + SPKI pin pool.
 * Prefer HTTP/2 when ALPN negotiates h2; else HTTP/1.1. Failover across pool.
 */

unsigned ntx_doh_ok;
unsigned ntx_doh_fail;
unsigned ntx_doh_mitm_fail;
int ntx_doh_verbose;

/* Per-step connect/TLS/H2 I/O; pool failover × N entries — room for slow paths. */
#define DOH_IO_TO_SEC 10
static const char *const doh_alpn_list[] = {"h2", "http/1.1"};

static char doh_tag[8];
static int doh_busy;
static void (*doh_ui_kick)(void);

void ntx_doh_set_ui_kick(void (*fn)(void)) {
    doh_ui_kick = fn;
}

void ntx_doh_status(char *tag_out, size_t tag_cap, int *busy_out) {
    if (tag_out && tag_cap > 0) {
        snprintf(tag_out, tag_cap, "%s", doh_tag);
    }
    if (busy_out) *busy_out = doh_busy;
}

static void doh_set_prov(const char *tag, int busy) {
    if (tag && tag[0])
        snprintf(doh_tag, sizeof doh_tag, "%s", tag);
    doh_busy = busy ? 1 : 0;
    if (doh_ui_kick) doh_ui_kick();
}

static uint64_t doh_mono_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) return 0;
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static void doh_vlog_try(const ntx_doh_pin_entry *e, const char *host, const char *why, int err,
                         uint64_t t0_ms) {
    if (!ntx_doh_verbose || !e || !why) return;
    char ip[48];
    struct in_addr a;
    a.s_addr = e->ip_be;
    if (!inet_ntop(AF_INET, &a, ip, sizeof ip)) snprintf(ip, sizeof ip, "?");
    uint64_t ms = 0;
    if (t0_ms) {
        uint64_t now = doh_mono_ms();
        if (now >= t0_ms) ms = now - t0_ms;
    }
    ntx_diag("ntx: doh try host=%s tag=%s sni=%s ip=%s why=%s errno=%d ms=%llu to=%ds\n",
             host ? host : "?", e->tag ? e->tag : "?", e->sni ? e->sni : "?", ip, why, err,
             (unsigned long long)ms, DOH_IO_TO_SEC);
}

static void doh_note_mitm(const char *tag) {
    char t[8];
    snprintf(t, sizeof t, "!%s", tag && tag[0] ? tag : "?");
    ntx_doh_mitm_fail++;
    doh_set_prov(t, 0);
}

/* --- DNS wire (RFC 1035) helpers for DoH dns-message body (RFC 8484) --- */

/* Skip / consume a domain name; handles compression pointers.
 * Returns bytes consumed from *off, or -1. Updates *off past the name. */
static int skip_name(const uint8_t *msg, size_t n, size_t *off) {
    size_t o = *off;
    int jumped = 0;
    size_t consumed = 0;
    int hops = 0;

    for (;;) {
        if (o >= n) return -1;
        uint8_t len = msg[o];
        if ((len & 0xC0) == 0xC0) {
            if (o + 1 >= n) return -1;
            if (!jumped) consumed += 2;
            jumped = 1;
            size_t ptr = (size_t)(((len & 0x3F) << 8) | msg[o + 1]);
            if (ptr >= n) return -1;
            o = ptr;
            if (++hops > 64) return -1;
            continue;
        }
        if (len == 0) {
            if (!jumped) consumed += 1;
            *off += consumed;
            return 0;
        }
        if ((len & 0xC0) != 0) return -1; /* reserved */
        if (o + 1 + len >= n) return -1;
        if (!jumped) consumed += 1 + (size_t)len;
        o += 1 + (size_t)len;
        if (++hops > 128) return -1;
    }
}

/* Encode hostname as QNAME labels. Returns bytes written, or 0 on error. */
static size_t enc_qname(uint8_t *out, size_t cap, const char *host) {
    if (!host || !*host || cap < 2) return 0;
    size_t o = 0;
    const char *p = host;
    while (*p) {
        const char *dot = strchr(p, '.');
        size_t lab = dot ? (size_t)(dot - p) : strlen(p);
        if (lab == 0 || lab > 63) return 0;
        if (o + 1 + lab + 1 > cap) return 0;
        out[o++] = (uint8_t)lab;
        memcpy(out + o, p, lab);
        o += lab;
        if (!dot) break;
        p = dot + 1;
        if (!*p) break; /* trailing dot OK */
    }
    if (o + 1 > cap) return 0;
    out[o++] = 0;
    return o;
}

/* Dotted-quad → network-order IPv4 (same layout as sin_addr.s_addr). */
static int parse_literal4(const char *host, uint32_t *ip_out) {
    if (!host || !ip_out) return -1;
    uint8_t oct[4];
    const char *p = host;
    for (int i = 0; i < 4; i++) {
        if (*p < '0' || *p > '9') return -1;
        unsigned v = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            if (++digits > 3) return -1;
            v = v * 10u + (unsigned)(*p - '0');
            if (v > 255) return -1;
            p++;
        }
        if (digits == 0) return -1;
        oct[i] = (uint8_t)v;
        if (i < 3) {
            if (*p != '.') return -1;
            p++;
        }
    }
    if (*p != '\0') return -1;
    memcpy(ip_out, oct, 4);
    return 0;
}

size_t ntx_doh_build_query_a(uint8_t *out, size_t cap, const char *host, uint16_t id) {
    if (!out || !host || cap < 12) return 0;
    size_t o = 0;
    ntx_wire_wr16(out + o, id); o += 2;
    ntx_wire_wr16(out + o, 0x0100); o += 2; /* RD=1 */
    ntx_wire_wr16(out + o, 1); o += 2;      /* QDCOUNT */
    ntx_wire_wr16(out + o, 0); o += 2;
    ntx_wire_wr16(out + o, 0); o += 2;
    ntx_wire_wr16(out + o, 0); o += 2;
    size_t qn = enc_qname(out + o, cap - o, host);
    if (qn == 0) return 0;
    o += qn;
    if (o + 4 > cap) return 0;
    ntx_wire_wr16(out + o, 1); o += 2; /* QTYPE A */
    ntx_wire_wr16(out + o, 1); o += 2; /* QCLASS IN */
    return o;
}

int ntx_doh_parse_response_a(const uint8_t *msg, size_t n,
                             uint32_t *ips, int max,
                             uint32_t *ttl_out) {
    if (!msg || n < 12 || !ips || max < 1) return -1;
    uint16_t flags = ntx_wire_rd16(msg + 2);
    if ((flags & 0x8000) == 0) return -1; /* must be response */
    {
        unsigned rcode = (unsigned)(flags & 0x000F);
        if (rcode == 3) return 0; /* NXDOMAIN → 0 answers (definitive) */
        if (rcode != 0) return -1; /* other RCODE */
    }
    uint16_t qd = ntx_wire_rd16(msg + 4);
    uint16_t an = ntx_wire_rd16(msg + 6);
    size_t off = 12;

    for (uint16_t i = 0; i < qd; i++) {
        if (skip_name(msg, n, &off) != 0) return -1;
        if (off + 4 > n) return -1;
        off += 4; /* QTYPE + QCLASS */
    }

    int got = 0;
    if (ttl_out) *ttl_out = 0;

    for (uint16_t i = 0; i < an; i++) {
        if (skip_name(msg, n, &off) != 0) return -1;
        if (off + 10 > n) return -1;
        uint16_t typ = ntx_wire_rd16(msg + off);
        uint16_t cls = ntx_wire_rd16(msg + off + 2);
        uint32_t ttl = ntx_wire_rd32(msg + off + 4);
        uint16_t rdlen = ntx_wire_rd16(msg + off + 8);
        off += 10;
        if (off + rdlen > n) return -1;
        if (typ == 1 && cls == 1 && rdlen == 4) {
            if (got < max) {
                uint32_t ip;
                memcpy(&ip, msg + off, 4);
                ips[got] = ip;
                if (got == 0 && ttl_out) *ttl_out = ttl;
                got++;
            }
        }
        off += rdlen;
    }
    return got;
}

size_t ntx_doh_build_query_aaaa(uint8_t *out, size_t cap, const char *host, uint16_t id) {
    if (!out || !host || cap < 12) return 0;
    size_t o = 0;
    ntx_wire_wr16(out + o, id); o += 2;
    ntx_wire_wr16(out + o, 0x0100); o += 2; /* RD=1 */
    ntx_wire_wr16(out + o, 1); o += 2;      /* QDCOUNT */
    ntx_wire_wr16(out + o, 0); o += 2;
    ntx_wire_wr16(out + o, 0); o += 2;
    ntx_wire_wr16(out + o, 0); o += 2;
    size_t qn = enc_qname(out + o, cap - o, host);
    if (qn == 0) return 0;
    o += qn;
    if (o + 4 > cap) return 0;
    ntx_wire_wr16(out + o, 28); o += 2; /* QTYPE AAAA */
    ntx_wire_wr16(out + o, 1); o += 2;  /* QCLASS IN */
    return o;
}

int ntx_doh_parse_response_aaaa(const uint8_t *msg, size_t n,
                                uint8_t ips[][16], int max,
                                uint32_t *ttl_out) {
    if (!msg || n < 12 || !ips || max < 1) return -1;
    uint16_t flags = ntx_wire_rd16(msg + 2);
    if ((flags & 0x8000) == 0) return -1; /* must be response */
    {
        unsigned rcode = (unsigned)(flags & 0x000F);
        if (rcode == 3) return 0; /* NXDOMAIN → 0 answers (definitive) */
        if (rcode != 0) return -1; /* other RCODE */
    }
    uint16_t qd = ntx_wire_rd16(msg + 4);
    uint16_t an = ntx_wire_rd16(msg + 6);
    size_t off = 12;

    for (uint16_t i = 0; i < qd; i++) {
        if (skip_name(msg, n, &off) != 0) return -1;
        if (off + 4 > n) return -1;
        off += 4; /* QTYPE + QCLASS */
    }

    int got = 0;
    if (ttl_out) *ttl_out = 0;

    for (uint16_t i = 0; i < an; i++) {
        if (skip_name(msg, n, &off) != 0) return -1;
        if (off + 10 > n) return -1;
        uint16_t typ = ntx_wire_rd16(msg + off);
        uint16_t cls = ntx_wire_rd16(msg + off + 2);
        uint32_t ttl = ntx_wire_rd32(msg + off + 4);
        uint16_t rdlen = ntx_wire_rd16(msg + off + 8);
        off += 10;
        if (off + rdlen > n) return -1;
        if (typ == 28 && cls == 1 && rdlen == 16) {
            if (got < max) {
                memcpy(ips[got], msg + off, 16);
                if (got == 0 && ttl_out) *ttl_out = ttl;
                got++;
            }
        }
        off += rdlen;
    }
    return got;
}

/* --- hostname cache (TTL clamped [60,3600]; negative = skip pool walk) --- */

#define DOH_CACHE_N 64
#define DOH_TTL_MIN 60u
#define DOH_TTL_MAX 3600u
#define DOH_NEG_TTL 300u /* dead/NXDOMAIN hosts — avoid re-blocking event loop */

static struct {
    char host[256];
    uint8_t addr[16]; /* A: last 4 bytes; AAAA: all 16 */
    uint8_t qtype;    /* 1=A, 28=AAAA */
    time_t exp;
    int neg;
} doh_cache[DOH_CACHE_N];
static int doh_cache_rr;
static size_t doh_last_ok; /* sticky preferred pool entry */

static int cache_get(const char *host, uint16_t qtype, uint8_t addr_out[16]) {
    time_t now = time(NULL);
    for (int i = 0; i < DOH_CACHE_N; i++) {
        if (!doh_cache[i].host[0]) continue;
        if (strcmp(doh_cache[i].host, host) != 0) continue;
        if (doh_cache[i].qtype != qtype) continue; /* A vs AAAA are kept separate */
        if (doh_cache[i].exp && now > doh_cache[i].exp) continue;
        if (doh_cache[i].neg) return -2;
        memcpy(addr_out, doh_cache[i].addr, 16);
        return 0;
    }
    return -1;
}

static void cache_put(const char *host, uint16_t qtype, const uint8_t addr[16], uint32_t ttl,
                      int neg) {
    if (!neg) {
        if (ttl < DOH_TTL_MIN) ttl = DOH_TTL_MIN;
        if (ttl > DOH_TTL_MAX) ttl = DOH_TTL_MAX;
    } else {
        ttl = DOH_NEG_TTL;
    }
    int slot = -1;
    for (int i = 0; i < DOH_CACHE_N; i++) {
        if (doh_cache[i].host[0] && strcmp(doh_cache[i].host, host) == 0 &&
            doh_cache[i].qtype == qtype) {
            slot = i;
            break;
        }
        if (slot < 0 && !doh_cache[i].host[0]) slot = i;
    }
    if (slot < 0) {
        slot = doh_cache_rr++ % DOH_CACHE_N;
    }
    snprintf(doh_cache[slot].host, sizeof doh_cache[slot].host, "%s", host);
    if (addr && !neg) memcpy(doh_cache[slot].addr, addr, 16);
    else memset(doh_cache[slot].addr, 0, 16);
    doh_cache[slot].qtype = (uint8_t)qtype;
    doh_cache[slot].neg = neg ? 1 : 0;
    doh_cache[slot].exp = time(NULL) + (time_t)ttl;
}

static int tcp_connect_timeout(uint32_t ip_be, uint16_t port) {
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return -1;
    struct timeval tv;
    tv.tv_sec = DOH_IO_TO_SEC;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_be;
    sa.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0) {
        close(fd);
        return -1;
    }
    return fd;
}

static int tls_write_all(ntx_tls *t, const void *buf, size_t n) {
    const uint8_t *p = buf;
    while (n > 0) {
        ssize_t w = ntx_tls_write(t, p, n);
        if (w <= 0) return -1;
        p += (size_t)w;
        n -= (size_t)w;
    }
    return 0;
}

static int hdr_ci_eq(const char *a, const char *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        char ca = a[i], cb = b[i];
        if (ca >= 'A' && ca <= 'Z') ca = (char)(ca - 'A' + 'a');
        if (cb >= 'A' && cb <= 'Z') cb = (char)(cb - 'A' + 'a');
        if (ca != cb) return 0;
    }
    return 1;
}

/* Read HTTP/1.1 response; require Content-Length (v1 ignores chunked). */
static int http_read_body(ntx_tls *t, uint8_t *body, size_t cap, size_t *out_len) {
    uint8_t buf[16384];
    size_t n = 0;
    size_t hdr_end = 0;
    long content_len = -1;
    int status = 0;

    while (n < sizeof buf) {
        ssize_t r = ntx_tls_read(t, buf + n, sizeof buf - n);
        if (r <= 0) return -1;
        n += (size_t)r;
        if (!hdr_end) {
            for (size_t i = 0; i + 3 < n; i++) {
                if (buf[i] == '\r' && buf[i + 1] == '\n' &&
                    buf[i + 2] == '\r' && buf[i + 3] == '\n') {
                    hdr_end = i + 4;
                    break;
                }
            }
            if (!hdr_end) continue;

            /* status line */
            if (n < 12 || !hdr_ci_eq((char *)buf, "HTTP/1.", 7)) return -1;
            const char *sp = (const char *)buf;
            while (*sp && *sp != ' ') sp++;
            if (*sp != ' ') return -1;
            status = atoi(sp + 1);
            if (status != 200) return -1;

            /* headers */
            size_t line = 0;
            while (line + 1 < hdr_end - 2) {
                size_t eol = line;
                while (eol + 1 < hdr_end && !(buf[eol] == '\r' && buf[eol + 1] == '\n'))
                    eol++;
                if (eol <= line) break;
                if (eol - line >= 15 &&
                    hdr_ci_eq((char *)buf + line, "Content-Length:", 15)) {
                    const char *v = (const char *)buf + line + 15;
                    while (*v == ' ' || *v == '\t') v++;
                    content_len = atol(v);
                }
                line = eol + 2;
            }
            if (content_len < 0 || (size_t)content_len > cap) return -1;
        }

        size_t have = (n > hdr_end) ? (n - hdr_end) : 0;
        if (have >= (size_t)content_len) {
            memcpy(body, buf + hdr_end, (size_t)content_len);
            *out_len = (size_t)content_len;
            return 0;
        }
        /* need more; if buffer full but body incomplete, fail */
        if (n == sizeof buf) return -1;
    }
    return -1;
}

static int doh_try_entry(const ntx_doh_pin_entry *e, const char *host, uint16_t qtype,
                         const uint8_t *q, size_t qn, uint8_t *addr_out, uint32_t *ttl_out) {
    uint64_t t0 = doh_mono_ms();
    int fd = tcp_connect_timeout(e->ip_be, 443);
    if (fd < 0) {
        doh_vlog_try(e, host, "connect", errno, t0);
        return -1;
    }

    ntx_tls tls;
    ntx_tls_init(&tls);
    int hs = ntx_tls_handshake_ex(&tls, fd, e->sni, e->pins, e->npins, DOH_IO_TO_SEC,
                                  doh_alpn_list, 2);
    if (hs == NTX_TLS_PIN_FAIL) {
        doh_note_mitm(e->tag);
        doh_vlog_try(e, host, "tls_pin", 0, t0);
        ntx_tls_close(&tls);
        close(fd);
        return -1;
    }
    if (hs != NTX_TLS_OK) {
        doh_vlog_try(e, host, "tls_hs", hs, t0);
        ntx_tls_close(&tls);
        close(fd);
        return -1;
    }

    uint8_t body[4096];
    size_t blen = 0;
    int got = -1;

    /* Prefer HTTP/2 when negotiated (or ALPN empty → try h2 first). */
    if (tls.alpn[0] == 0 || strcmp(tls.alpn, "h2") == 0) {
        got = ntx_h2_doh_post(&tls, e->sni, e->path, q, qn, body, sizeof body, &blen);
        if (got != 0 && strcmp(tls.alpn, "h2") == 0) {
            doh_vlog_try(e, host, "h2_post", got, t0);
            ntx_tls_close(&tls);
            close(fd);
            return -1; /* h2-only peer; next pool entry */
        }
    }

    if (got != 0) {
        /* HTTP/1.1 on this connection only if we did not already send h2 preface. */
        if (tls.alpn[0] == 0) {
            /* Preface may have been sent; reopen fresh TLS for 1.1. */
            ntx_tls_close(&tls);
            close(fd);
            fd = tcp_connect_timeout(e->ip_be, 443);
            if (fd < 0) {
                doh_vlog_try(e, host, "connect_http11", errno, t0);
                return -1;
            }
            ntx_tls_init(&tls);
            hs = ntx_tls_handshake_ex(&tls, fd, e->sni, e->pins, e->npins, DOH_IO_TO_SEC,
                                      doh_alpn_list, 2);
            if (hs != NTX_TLS_OK) {
                if (hs == NTX_TLS_PIN_FAIL) doh_note_mitm(e->tag);
                doh_vlog_try(e, host, hs == NTX_TLS_PIN_FAIL ? "tls_pin_http11" : "tls_hs_http11",
                             hs, t0);
                ntx_tls_close(&tls);
                close(fd);
                return -1;
            }
        }
        char req[1024];
        int hn = snprintf(req, sizeof req,
                          "POST %s HTTP/1.1\r\n"
                          "Host: %s\r\n"
                          "Content-Type: application/dns-message\r\n"
                          "Accept: application/dns-message\r\n"
                          "Content-Length: %zu\r\n"
                          "Connection: close\r\n"
                          "\r\n",
                          e->path, e->sni, qn);
        if (hn < 0 || (size_t)hn >= sizeof req) {
            doh_vlog_try(e, host, "http11_req", 0, t0);
            ntx_tls_close(&tls);
            close(fd);
            return -1;
        }
        if (tls_write_all(&tls, req, (size_t)hn) != 0 || tls_write_all(&tls, q, qn) != 0) {
            doh_vlog_try(e, host, "http11_write", errno, t0);
            ntx_tls_close(&tls);
            close(fd);
            return -1;
        }
        blen = 0;
        if (http_read_body(&tls, body, sizeof body, &blen) != 0) {
            doh_vlog_try(e, host, "http11_read", errno, t0);
            ntx_tls_close(&tls);
            close(fd);
            return -1;
        }
        got = 0;
    }

    uint32_t ips4[4];
    uint8_t ips6[4][16];
    uint32_t ttl = 0;
    int na = (qtype == 28) ? ntx_doh_parse_response_aaaa(body, blen, ips6, 4, &ttl)
                           : ntx_doh_parse_response_a(body, blen, ips4, 4, &ttl);
    char alpn_save[16];
    snprintf(alpn_save, sizeof alpn_save, "%s", tls.alpn[0] ? tls.alpn : "http11");
    ntx_tls_close(&tls);
    close(fd);
    if (na < 1) {
        doh_vlog_try(e, host, "dns_parse", na, t0);
        /* na==0: a valid DNS reply without A/AAAA (NODATA/NXDOMAIN) —
           do NOT try further resolvers (AAAA-first × 11 resolvers × ~12 s would hang). */
        return (na == 0) ? -2 : -1;
    }
    memcpy(addr_out, qtype == 28 ? ips6[0] : (const uint8_t *)&ips4[0], qtype == 28 ? 16 : 4);
    if (ttl_out) *ttl_out = ttl;
    if (ntx_doh_verbose) {
        char ip[48];
        if (qtype == 28) {
            struct in6_addr a6;
            memcpy(&a6, ips6[0], 16);
            if (!inet_ntop(AF_INET6, &a6, ip, sizeof ip)) snprintf(ip, sizeof ip, "?");
        } else {
            struct in_addr a;
            a.s_addr = ips4[0];
            if (!inet_ntop(AF_INET, &a, ip, sizeof ip)) snprintf(ip, sizeof ip, "?");
        }
        uint64_t ms = 0, now = doh_mono_ms();
        if (now >= t0) ms = now - t0;
        ntx_diag("ntx: doh ok host=%s tag=%s sni=%s via=%s %s=%s ttl=%u ms=%llu to=%ds\n",
                 host ? host : "?", e->tag ? e->tag : "?", e->sni ? e->sni : "?", alpn_save,
                 qtype == 28 ? "AAAA" : "A", ip, (unsigned)ttl, (unsigned long long)ms,
                 DOH_IO_TO_SEC);
    }
    return 0;
}

static int doh_lookup_qt(const char *host, uint16_t qtype, uint8_t *addr_out) {
    if (!host || !addr_out) return -1;
    if (strlen(host) >= 256) return -1;
    {
        int cg = cache_get(host, qtype, addr_out);
        if (cg == 0) return 0;
        if (cg == -2) {
            ntx_doh_fail++;
            doh_set_prov("!", 0);
            if (ntx_doh_verbose)
                ntx_diag("ntx: doh resolve failed host=%s (neg-cache)"
                         " ok=%u fail=%u mitm=%u\n",
                         host, ntx_doh_ok, ntx_doh_fail, ntx_doh_mitm_fail);
            return -1;
        }
    }

    uint8_t q[512];
    static uint16_t qid = 1;
    size_t qn = (qtype == 28) ? ntx_doh_build_query_aaaa(q, sizeof q, host, qid++)
                              : ntx_doh_build_query_a(q, sizeof q, host, qid++);
    if (qn == 0) {
        ntx_doh_fail++;
        cache_put(host, qtype, NULL, DOH_NEG_TTL, 1);
        doh_set_prov("!", 0);
        if (ntx_doh_verbose)
            ntx_diag("ntx: doh resolve failed host=%s (bad-qname)\n", host);
        return -1;
    }

    uint8_t addr[16];
    uint32_t ttl = 0;
    size_t n = NTX_DOH_PIN_POOL_LEN;
    size_t start = (doh_last_ok < n) ? doh_last_ok : 0;
    uint64_t lookup_t0 = doh_mono_ms();
    if (ntx_doh_verbose)
        ntx_diag("ntx: doh lookup host=%s qtype=%u pool=%zu to=%ds start=%zu\n", host,
                 (unsigned)qtype, n, DOH_IO_TO_SEC, start);
    for (size_t k = 0; k < n; k++) {
        size_t i = (start + k) % n;
        const ntx_doh_pin_entry *e = &ntx_doh_pin_pool[i];
        doh_set_prov(e->tag ? e->tag : "?", 1);
        int tr = doh_try_entry(e, host, qtype, q, qn, addr, &ttl);
        if (tr == 0) {
            cache_put(host, qtype, addr, ttl, 0);
            doh_last_ok = i;
            memcpy(addr_out, addr, qtype == 28 ? 16 : 4);
            ntx_doh_ok++;
            doh_set_prov(e->tag ? e->tag : "?", 0);
            return 0;
        }
        if (tr == -2) {
            /* Definitive NODATA/NXDOMAIN — do not hit all 11 DoH resolvers. */
            break;
        }
    }

    ntx_doh_fail++;
    cache_put(host, qtype, NULL, DOH_NEG_TTL, 1);
    doh_set_prov("!", 0);
    if (ntx_doh_verbose) {
        uint64_t ms = 0, now = doh_mono_ms();
        if (now >= lookup_t0) ms = now - lookup_t0;
        ntx_diag("ntx: doh resolve failed host=%s (pool-exhausted)"
                 " ok=%u fail=%u mitm=%u ms=%llu to=%ds pool=%zu\n",
                 host, ntx_doh_ok, ntx_doh_fail, ntx_doh_mitm_fail, (unsigned long long)ms,
                 DOH_IO_TO_SEC, n);
    }
    return -1;
}

int ntx_doh_lookup_a(const char *host, uint32_t *ip_out) {
    if (!host || !ip_out) return -1;
    if (parse_literal4(host, ip_out) == 0) return 0;
    return doh_lookup_qt(host, 1, (uint8_t *)ip_out);
}

int ntx_doh_lookup_aaaa(const char *host, uint8_t out[16]) {
    return doh_lookup_qt(host, 28, out);
}
