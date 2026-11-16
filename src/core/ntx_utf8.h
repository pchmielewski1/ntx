#ifndef NTX_UTF8_H
#define NTX_UTF8_H

#include <stddef.h>
#include <string.h>

/* UTF-8 primitives for the places that cut a name by byte count or put one on
 * the wire (R8). A byte cut lands half-way into a multi-byte character, and the
 * JSON emitters wrote those bytes out raw (docs/json-api.md "String encoding"),
 * so a name with non-ASCII made EVERY stats line undecodable to a strict NDJSON
 * parser for the whole share. static-inline header: ntx has no util .c to link
 * and the three consumers (core stats, ui CLI, ui IPC) are separate translation
 * units in the unity build — same shape as ntx_dht_xor.h / ntx_dial_bo.h.
 * Strict by design: the verdict matches what a strict decoder makes. */

/* Byte length of the sequence started by c, or 0 when c cannot start one
 * (0x80-0xBF, 0xC0, 0xC1, 0xF5-0xFF). */
static inline int ntx_utf8_char_len(unsigned char c) {
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) return 2;
    if (c >= 0xE0 && c <= 0xEF) return 3;
    if (c >= 0xF0 && c <= 0xF4) return 4;
    return 0;
}

/* 1 when s[0..n) is a sequence of whole, well-formed characters: no overlong
 * forms, no surrogates, nothing above U+10FFFF, no truncated tail. Expressed as
 * second-byte windows rather than codepoint arithmetic — same verdict, far less
 * code: E0 needs A0-BF (no overlong), ED needs 80-9F (no surrogate), F0 needs
 * 90-BF (no overlong), F4 needs 80-8F (nothing above U+10FFFF). */
static inline int ntx_utf8_valid(const char *s, size_t n) {
    const unsigned char *u = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        unsigned char c = u[i];
        int need = ntx_utf8_char_len(c);
        unsigned char lo = 0x80, hi = 0xBF;
        if (need == 0 || i + (size_t)need > n) return 0;
        if (need == 1) { i++; continue; }
        if (need == 3) { if (c == 0xE0) lo = 0xA0; else if (c == 0xED) hi = 0x9F; }
        else if (need == 4) { if (c == 0xF0) lo = 0x90; else if (c == 0xF4) hi = 0x8F; }
        if (u[i + 1] < lo || u[i + 1] > hi) return 0;
        for (int k = 2; k < need; k++)
            if (u[i + k] < 0x80 || u[i + k] > 0xBF) return 0;
        i += (size_t)need;
    }
    return 1;
}

/* Longest prefix of s[0..n) that is valid UTF-8 and fits in `fit` bytes (the
 * NUL is NOT counted). Stops at the first character that is malformed or does
 * not fit, so the result is always a decodable string, never half a character. */
static inline size_t ntx_utf8_cut(const char *s, size_t n, size_t fit) {
    size_t stem = 0;
    while (stem < n && stem < fit) {
        size_t step = (size_t)ntx_utf8_char_len((unsigned char)s[stem]);
        if (step == 0 || stem + step > n || stem + step > fit) break;
        if (!ntx_utf8_valid(s + stem, step)) break;
        stem += step;
    }
    return stem;
}

/* snprintf(dst, capsz, "%s", src) that never cuts a character: at most
 * capsz-1 bytes, ending on a character boundary. Returns the bytes written. */
static inline size_t ntx_utf8_copy(char *dst, size_t capsz, const char *src) {
    if (!capsz) return 0;
    size_t n = ntx_utf8_cut(src, strlen(src), capsz - 1);
    memcpy(dst, src, n);
    dst[n] = 0;
    return n;
}

/* Length of the well-formed sequence starting at s[0] when it lies wholly
 * within s[0..n), else 0 (bad lead, truncated tail, overlong, surrogate). */
static inline size_t ntx_utf8_seq_ok(const char *s, size_t n) {
    int need = ntx_utf8_char_len((unsigned char)s[0]);
    if (need == 0 || (size_t)need > n) return 0;
    return ntx_utf8_valid(s, (size_t)need) ? (size_t)need : 0;
}

/* Bytes of the ill-formed subsequence starting at s[0], maximal-subpart style:
 * the lead byte plus the continuation bytes that follow it, never more than the
 * lead announced. Always >= 1, so a bad byte always makes progress. */
static inline size_t ntx_utf8_bad_len(const char *s, size_t n) {
    int need = ntx_utf8_char_len((unsigned char)s[0]);
    size_t lim = need > 0 ? (size_t)need : 1;
    size_t k = 1;
    while (k < lim && k < n && (unsigned char)s[k] >= 0x80 && (unsigned char)s[k] <= 0xBF) k++;
    return k;
}

#endif
