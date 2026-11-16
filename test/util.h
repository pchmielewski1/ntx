#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static inline void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    for (size_t k = 0; k < n; k++) {
        unsigned v = 0;
        (void)sscanf(hex + 2 * k, "%2x", &v);
        out[k] = (uint8_t)v;
    }
}

static inline uint8_t *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open fail %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(sz > 0 ? (size_t)sz : 1);
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "read fail %s\n", path); exit(1); }
    fclose(f);
    *n = (size_t)sz;
    return b;
}

/* Strict UTF-8 over s[0..n) — the verdict a strict NDJSON decoder (Python, Go,
   Node) makes on an emitted line. R8's witness: no overlong forms, no
   surrogates, nothing above U+10FFFF, no truncated tail. *bad (optional) gets
   the offset of the first undecodable byte. Independent of the shipped
   validator in ntx_share_out.c, which must not be tested against itself. */
static inline int test_utf8_strict(const char *s, size_t n, size_t *bad) {
    const unsigned char *u = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        unsigned char c = u[i];
        int need;
        uint32_t cp;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xC2 && c <= 0xDF) { need = 2; cp = c & 0x1Fu; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 3; cp = c & 0x0Fu; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 4; cp = c & 0x07u; }
        else { if (bad) *bad = i; return 0; }
        if (i + (size_t)need > n) { if (bad) *bad = i; return 0; }
        for (int k = 1; k < need; k++) {
            if (u[i + k] < 0x80 || u[i + k] > 0xBF) { if (bad) *bad = i + (size_t)k; return 0; }
            cp = (cp << 6) | (uint32_t)(u[i + k] & 0x3Fu);
        }
        if (need == 3 && cp < 0x800) { if (bad) *bad = i; return 0; }
        if (need == 4 && cp < 0x10000) { if (bad) *bad = i; return 0; }
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) { if (bad) *bad = i; return 0; }
        i += (size_t)need;
    }
    return 1;
}

#endif
