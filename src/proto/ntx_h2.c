#include "ntx_h2.h"
#include "ntx_wire.h"

#include <stdio.h>
#include <string.h>

/* HTTP/2 DoH helper: preface + SETTINGS + one POST stream; collect DATA body. */

enum {
    H2_DATA = 0,
    H2_HEADERS = 1,
    H2_SETTINGS = 4,
    H2_WINDOW_UPDATE = 8,
    H2_GOAWAY = 7
};

static int h2_tls_write_all(ntx_tls *t, const void *buf, size_t n) {
    const uint8_t *p = buf;
    size_t s = 0;
    while (s < n) {
        ssize_t w = ntx_tls_write(t, p + s, n - s);
        if (w <= 0) return -1;
        s += (size_t)w;
    }
    return 0;
}

static int h2_tls_read_full(ntx_tls *t, void *buf, size_t n) {
    uint8_t *p = buf;
    size_t g = 0;
    while (g < n) {
        ssize_t r = ntx_tls_read(t, p + g, n - g);
        if (r <= 0) return -1;
        g += (size_t)r;
    }
    return 0;
}

static int h2_send_frame(ntx_tls *t, uint8_t type, uint8_t flags, uint32_t stream,
                         const uint8_t *payload, size_t len) {
    uint8_t hdr[9];
    if (len > 0xffffffu) return -1;
    ntx_wire_wr24(hdr, (uint32_t)len);
    hdr[3] = type;
    hdr[4] = flags;
    ntx_wire_wr32(hdr + 5, stream & 0x7fffffffu);
    if (h2_tls_write_all(t, hdr, 9) != 0) return -1;
    if (len && h2_tls_write_all(t, payload, len) != 0) return -1;
    return 0;
}

static int h2_recv_frame(ntx_tls *t, uint8_t *type, uint8_t *flags, uint32_t *stream,
                         uint8_t *payload, size_t cap, size_t *len_out) {
    uint8_t hdr[9];
    if (h2_tls_read_full(t, hdr, 9) != 0) return -1;
    uint32_t L = ntx_wire_rd24(hdr);
    if (L > cap || L > 16384) return -1;
    *type = hdr[3];
    *flags = hdr[4];
    *stream = ((uint32_t)hdr[5] << 24) | ((uint32_t)hdr[6] << 16) | ((uint32_t)hdr[7] << 8) |
              (uint32_t)hdr[8];
    *stream &= 0x7fffffffu;
    if (L && h2_tls_read_full(t, payload, L) != 0) return -1;
    *len_out = L;
    return 0;
}

/* HPACK: literal without indexing — new name (0x00) or indexed name. */
static size_t hpack_lit_new(uint8_t *out, size_t cap, const char *name, const char *val) {
    size_t nl = strlen(name), vl = strlen(val);
    if (nl > 127 || vl > 127) return 0;
    size_t need = 1 + 1 + nl + 1 + vl;
    if (need > cap) return 0;
    size_t o = 0;
    out[o++] = 0x00; /* Literal Header Field without Indexing — New Name */
    out[o++] = (uint8_t)nl;
    memcpy(out + o, name, nl);
    o += nl;
    out[o++] = (uint8_t)vl;
    memcpy(out + o, val, vl);
    o += vl;
    return o;
}

static size_t hpack_lit_idx(uint8_t *out, size_t cap, uint8_t idx, const char *val) {
    size_t vl = strlen(val);
    if (vl > 127 || idx > 63) return 0;
    size_t need = 1 + 1 + vl;
    if (need > cap) return 0;
    size_t o = 0;
    out[o++] = (uint8_t)(0x00 | idx); /* without indexing, indexed name */
    out[o++] = (uint8_t)vl;
    memcpy(out + o, val, vl);
    o += vl;
    return o;
}

static size_t hpack_indexed(uint8_t *out, size_t cap, uint8_t idx) {
    if (cap < 1 || idx > 127) return 0;
    out[0] = (uint8_t)(0x80 | idx);
    return 1;
}

/* Build HEADERS block for DoH POST. */
static size_t build_req_headers(uint8_t *out, size_t cap, const char *authority, const char *path,
                                size_t body_len) {
    size_t o = 0, n;
    char clen[16];
    snprintf(clen, sizeof clen, "%zu", body_len);

    /* :method POST = indexed 3 */
    n = hpack_indexed(out + o, cap - o, 3);
    if (!n) return 0;
    o += n;
    /* :scheme https = indexed 7 */
    n = hpack_indexed(out + o, cap - o, 7);
    if (!n) return 0;
    o += n;
    /* :path */
    n = hpack_lit_idx(out + o, cap - o, 4, path);
    if (!n) return 0;
    o += n;
    /* :authority */
    n = hpack_lit_idx(out + o, cap - o, 1, authority);
    if (!n) return 0;
    o += n;
    n = hpack_lit_new(out + o, cap - o, "content-type", "application/dns-message");
    if (!n) return 0;
    o += n;
    n = hpack_lit_new(out + o, cap - o, "accept", "application/dns-message");
    if (!n) return 0;
    o += n;
    n = hpack_lit_new(out + o, cap - o, "content-length", clen);
    if (!n) return 0;
    o += n;
    return o;
}

/* Scan HPACK block for :status (indexed 8=:status 200, or literal). Return HTTP code or -1. */
static int hpack_status(const uint8_t *blk, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t b = blk[i];
        if (b & 0x80) { /* indexed */
            uint8_t idx = b & 0x7f;
            i++;
            if (idx == 8) return 200;  /* :status 200 */
            if (idx == 9) return 204;
            if (idx == 10) return 206;
            if (idx == 11) return 304;
            if (idx == 12) return 400;
            if (idx == 13) return 404;
            if (idx == 14) return 500;
            continue;
        }
        if ((b & 0xc0) == 0x40) { /* literal with incremental indexing */
            uint8_t idx = b & 0x3f;
            i++;
            if (idx == 0) {
                if (i >= n) return -1;
                size_t nl = blk[i] & 0x7f;
                int huff = blk[i] & 0x80;
                i++;
                if (huff || i + nl > n) return -1;
                i += nl;
            }
            if (i >= n) return -1;
            size_t vl = blk[i] & 0x7f;
            int huff = blk[i] & 0x80;
            i++;
            if (i + vl > n) return -1;
            if (idx == 8 || idx == 0) {
                /* might be :status */
                if (!huff && vl >= 3 && vl <= 3) {
                    int code = 0;
                    for (size_t k = 0; k < vl; k++) {
                        if (blk[i + k] < '0' || blk[i + k] > '9') {
                            code = -1;
                            break;
                        }
                        code = code * 10 + (blk[i + k] - '0');
                    }
                    if (code > 0) return code;
                }
            }
            i += vl;
            continue;
        }
        if ((b & 0xf0) == 0x00 || (b & 0xf0) == 0x10) { /* without indexing / never */
            uint8_t idx = b & 0x0f;
            i++;
            if (idx == 0) {
                if (i >= n) return -1;
                size_t nl = blk[i] & 0x7f;
                int huff = blk[i] & 0x80;
                i++;
                if (huff || i + nl > n) return -1;
                int is_status = (nl == 7 && !huff && memcmp(blk + i, ":status", 7) == 0);
                i += nl;
                if (i >= n) return -1;
                size_t vl = blk[i] & 0x7f;
                huff = blk[i] & 0x80;
                i++;
                if (i + vl > n) return -1;
                if (is_status && !huff && vl >= 3) {
                    int code = 0;
                    for (size_t k = 0; k < vl; k++) {
                        if (blk[i + k] < '0' || blk[i + k] > '9') {
                            code = -1;
                            break;
                        }
                        code = code * 10 + (blk[i + k] - '0');
                    }
                    if (code > 0) return code;
                }
                i += vl;
                continue;
            }
            if (i >= n) return -1;
            size_t vl = blk[i] & 0x7f;
            int huff = blk[i] & 0x80;
            i++;
            if (i + vl > n) return -1;
            if (idx == 8 && !huff && vl >= 3) {
                int code = 0;
                for (size_t k = 0; k < vl; k++) {
                    if (blk[i + k] < '0' || blk[i + k] > '9') {
                        code = -1;
                        break;
                    }
                    code = code * 10 + (blk[i + k] - '0');
                }
                if (code > 0) return code;
            }
            i += vl;
            continue;
        }
        /* dynamic table size update 001 */
        if ((b & 0xe0) == 0x20) {
            i++;
            continue;
        }
        return -1;
    }
    return -1;
}

int ntx_h2_doh_post(ntx_tls *tls, const char *authority, const char *path, const uint8_t *req,
                    size_t req_len, uint8_t *resp, size_t resp_cap, size_t *resp_len) {
    if (!tls || !authority || !path || !req || !resp || !resp_len) return -1;
    *resp_len = 0;

    static const char preface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    if (h2_tls_write_all(tls, preface, sizeof preface - 1) != 0) return -1;
    /* empty SETTINGS */
    if (h2_send_frame(tls, H2_SETTINGS, 0, 0, NULL, 0) != 0) return -1;

    uint8_t hdrs[512];
    size_t hlen = build_req_headers(hdrs, sizeof hdrs, authority, path, req_len);
    if (!hlen) return -1;
    /* HEADERS END_HEADERS on stream 1 */
    if (h2_send_frame(tls, H2_HEADERS, 0x04, 1, hdrs, hlen) != 0) return -1;
    /* DATA END_STREAM */
    if (h2_send_frame(tls, H2_DATA, 0x01, 1, req, req_len) != 0) return -1;

    int got_status = 0, status = -1;
    int stream_done = 0;
    size_t body = 0;
    int rounds = 0;
    while (!stream_done && rounds++ < 64) {
        uint8_t type, flags, payload[16384];
        uint32_t stream;
        size_t plen;
        if (h2_recv_frame(tls, &type, &flags, &stream, payload, sizeof payload, &plen) != 0)
            return -1;
        if (type == H2_SETTINGS) {
            if (!(flags & 0x01)) {
                /* ACK server SETTINGS */
                if (h2_send_frame(tls, H2_SETTINGS, 0x01, 0, NULL, 0) != 0) return -1;
            }
            continue;
        }
        if (type == H2_WINDOW_UPDATE) continue;
        if (type == H2_GOAWAY) return -1;
        if (stream != 1) continue;
        if (type == H2_HEADERS) {
            size_t hoff = 0;
            if (flags & 0x20) { /* PADDED */
                if (plen < 1) return -1;
                uint8_t pad = payload[0];
                hoff = 1;
                if ((size_t)1 + pad > plen) return -1;
                plen -= pad;
            }
            if (flags & 0x08) { /* PRIORITY */
                if (hoff + 5 > plen) return -1;
                hoff += 5;
            }
            if (hoff > plen) return -1;
            int st = hpack_status(payload + hoff, plen - hoff);
            if (st > 0) {
                status = st;
                got_status = 1;
            }
            if (flags & 0x01) stream_done = 1;
            continue;
        }
        if (type == H2_DATA) {
            size_t doff = 0;
            size_t dlen = plen;
            if (flags & 0x08) { /* PADDED */
                if (plen < 1) return -1;
                uint8_t pad = payload[0];
                doff = 1;
                if ((size_t)1 + pad > plen) return -1;
                dlen = plen - 1 - pad;
            }
            if (body + dlen > resp_cap) return -1;
            memcpy(resp + body, payload + doff, dlen);
            body += dlen;
            if (flags & 0x01) stream_done = 1;
            continue;
        }
    }
    if (!stream_done || body == 0) return -1;
    /* Accept if status 2xx or status unknown but body looks usable (caller parses DNS). */
    if (got_status && (status < 200 || status > 299)) return -1;
    *resp_len = body;
    return 0;
}
