#include "ntx_magnet.h"

#include <string.h>
#include <strings.h>

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int b32val(char c) {
    if (c >= 'a' && c <= 'z') c = (char)(c - 'a' + 'A');
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= '2' && c <= '7') return c - '2' + 26;
    return -1;
}

static void pct_decode(const char *src, size_t srclen, char *dst, size_t dstcap) {
    size_t o = 0;
    for (size_t i = 0; i < srclen; i++) {
        if (o + 1 >= dstcap) break;
        char c = src[i];
        if (c == '%' && i + 2 < srclen) {
            int hi = hexval(src[i + 1]);
            int lo = hexval(src[i + 2]);
            if (hi >= 0 && lo >= 0) {
                dst[o++] = (char)((hi << 4) | lo);
                i += 2;
                continue;
            }
        }
        dst[o++] = (c == '+') ? ' ' : c;
    }
    dst[o] = 0;
}

static int parse_xt(const char *v, uint8_t *out20) {
    const char *s = v;
    if (strncasecmp(v, "urn:btih:", 9) == 0) s = v + 9;
    size_t n = strlen(s);
    if (n == 40) {
        for (size_t i = 0; i < 20; i++) {
            int hi = hexval(s[2 * i]);
            int lo = hexval(s[2 * i + 1]);
            if (hi < 0 || lo < 0) return -1;
            out20[i] = (uint8_t)((hi << 4) | lo);
        }
        return 0;
    }
    if (n == 32) {
        uint32_t acc = 0;
        int bits = 0;
        int o = 0;
        for (size_t i = 0; i < 32; i++) {
            int d = b32val(s[i]);
            if (d < 0) return -1;
            acc = (acc << 5) | (uint32_t)d;
            bits += 5;
            while (bits >= 8) {
                bits -= 8;
                out20[o++] = (uint8_t)(acc >> bits);
            }
        }
        return o == 20 ? 0 : -1;
    }
    return -1;
}

/* multihash hex: multicodec 0x12 (sha2-256) + 32-byte digest = "1220" + 64 hex chars */
static int parse_btmh(const char *s, uint8_t *out32) {
    size_t n = strlen(s);
    if (n != 68 || memcmp(s, "1220", 4) != 0) return -1;
    for (size_t i = 0; i < 32; i++) {
        int hi = hexval(s[4 + 2 * i]);
        int lo = hexval(s[4 + 2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out32[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void copy_field(const char *src, char *dst, size_t dstcap) {
    size_t n = strlen(src);
    if (n >= dstcap) n = dstcap - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

int ntx_magnet_parse(const char *url, ntx_magnet *out) {
    if (!url || !out) return -1;
    memset(out, 0, sizeof *out);
    if (strncasecmp(url, "magnet:", 7) != 0) return -1;
    const char *q = strchr(url, '?');
    if (!q) return -1;
    const char *p = q + 1;
    int has_btih = 0, has_btmh = 0;
    for (;;) {
        const char *amp = strchr(p, '&');
        size_t len = amp ? (size_t)(amp - p) : strlen(p);
        if (len > 0) {
            const char *eq = memchr(p, '=', len);
            if (eq) {
                size_t klen = (size_t)(eq - p);
                const char *v = eq + 1;
                size_t vlen = len - klen - 1;
                char dec[512];
                if (klen == 2 && memcmp(p, "xt", 2) == 0) {
                    pct_decode(v, vlen, dec, sizeof dec);
                    if (strncasecmp(dec, "urn:btmh:", 9) == 0) {
                        if (has_btmh) return -1;
                        if (parse_btmh(dec + 9, out->ih_v2) != 0) return -1;
                        out->has_v2 = 1;
                        has_btmh = 1;
                    } else {
                        /* btih (urn:btih: or legacy bare hex/base32) — unchanged path */
                        if (has_btih) return -1;
                        if (parse_xt(dec, out->info_hash) != 0) return -1;
                        has_btih = 1;
                    }
                } else if (klen == 2 && memcmp(p, "dn", 2) == 0) {
                    if (!out->has_name) {
                        pct_decode(v, vlen, out->name, sizeof out->name);
                        out->has_name = 1;
                    }
                } else if (klen == 2 && memcmp(p, "tr", 2) == 0) {
                    pct_decode(v, vlen, dec, sizeof dec);
                    int dup = 0;
                    for (int i = 0; i < out->n_trackers; i++)
                        if (strcmp(out->trackers[i], dec) == 0) { dup = 1; break; }
                    if (!dup && out->n_trackers < 32) {
                        copy_field(dec, out->trackers[out->n_trackers], 512);
                        out->n_trackers++;
                    }
                } else if (klen == 2 && memcmp(p, "ws", 2) == 0) {
                    if (!out->has_webseed) {
                        pct_decode(v, vlen, out->webseed, sizeof out->webseed);
                        out->has_webseed = 1;
                    }
                } else if (klen == 2 && memcmp(p, "as", 2) == 0) {
                    if (!out->has_alt_source) {
                        pct_decode(v, vlen, out->alt_source, sizeof out->alt_source);
                        out->has_alt_source = 1;
                    }
                }
            }
        }
        if (!amp) break;
        p = amp + 1;
    }
    if (!has_btih && !has_btmh) return -1;
    if (has_btmh && !has_btih) memcpy(out->info_hash, out->ih_v2, 20);
    return 0;
}
