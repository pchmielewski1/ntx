#include "ntx_aes.h"
#include <string.h>

/* AES-128 with a 256-byte S-box table. Everything except the S-box lookup is free of
 * secret-dependent branches and indexing: MixColumns uses a masked xtime, and GHASH is the
 * carry-less multiply emulated with integer multiplications (see ghash_block). The S-box
 * lookup itself is indexed by secret state bytes, i.e. cache-line-granular timing is NOT
 * hidden (a constant-time S-box costs an order of magnitude in speed). */

static const uint8_t aes_sbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

static uint8_t xtime(uint8_t x) {
    return (uint8_t)((x << 1) ^ (0x1B & (0u - (unsigned)(x >> 7))));
}

static void aes_key_expand(const uint8_t key[16], uint8_t rk[176]) {
    static const uint8_t rcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36};
    memcpy(rk, key, 16);
    for (int i = 4; i < 44; i++) {
        uint8_t t[4];
        memcpy(t, rk + 4 * (i - 1), 4);
        if (i % 4 == 0) {
            uint8_t tmp = t[0];
            t[0] = (uint8_t)(aes_sbox[t[1]] ^ rcon[i / 4 - 1]);
            t[1] = aes_sbox[t[2]];
            t[2] = aes_sbox[t[3]];
            t[3] = aes_sbox[tmp];
        }
        for (int j = 0; j < 4; j++) rk[4 * i + j] = (uint8_t)(rk[4 * (i - 4) + j] ^ t[j]);
    }
}

/* SubBytes + ShiftRows (state is column-major: byte r of column c is s[r + 4c]). */
static void sub_shift(uint8_t t[16], const uint8_t s[16]) {
    t[0]  = aes_sbox[s[0]];  t[1]  = aes_sbox[s[5]];  t[2]  = aes_sbox[s[10]]; t[3]  = aes_sbox[s[15]];
    t[4]  = aes_sbox[s[4]];  t[5]  = aes_sbox[s[9]];  t[6]  = aes_sbox[s[14]]; t[7]  = aes_sbox[s[3]];
    t[8]  = aes_sbox[s[8]];  t[9]  = aes_sbox[s[13]]; t[10] = aes_sbox[s[2]];  t[11] = aes_sbox[s[7]];
    t[12] = aes_sbox[s[12]]; t[13] = aes_sbox[s[1]];  t[14] = aes_sbox[s[6]];  t[15] = aes_sbox[s[11]];
}

static void aes_encrypt_block(const uint8_t rk[176], const uint8_t in[16], uint8_t out[16]) {
    uint8_t st[16], t[16];
    for (int i = 0; i < 16; i++) st[i] = (uint8_t)(in[i] ^ rk[i]);
    for (int round = 1; round < 10; round++) {
        sub_shift(t, st);
        for (int c = 0; c < 4; c++) {
            uint8_t a0 = t[4 * c], a1 = t[4 * c + 1], a2 = t[4 * c + 2], a3 = t[4 * c + 3];
            uint8_t all = (uint8_t)(a0 ^ a1 ^ a2 ^ a3);
            /* b_r = a_r ^ all ^ xtime(a_r ^ a_{r+1})  ==  2a_r ^ 3a_{r+1} ^ a_{r+2} ^ a_{r+3} */
            st[4 * c]     = (uint8_t)(a0 ^ all ^ xtime((uint8_t)(a0 ^ a1)) ^ rk[round * 16 + 4 * c]);
            st[4 * c + 1] = (uint8_t)(a1 ^ all ^ xtime((uint8_t)(a1 ^ a2)) ^ rk[round * 16 + 4 * c + 1]);
            st[4 * c + 2] = (uint8_t)(a2 ^ all ^ xtime((uint8_t)(a2 ^ a3)) ^ rk[round * 16 + 4 * c + 2]);
            st[4 * c + 3] = (uint8_t)(a3 ^ all ^ xtime((uint8_t)(a3 ^ a0)) ^ rk[round * 16 + 4 * c + 3]);
        }
    }
    sub_shift(t, st);
    for (int i = 0; i < 16; i++) out[i] = (uint8_t)(t[i] ^ rk[160 + i]);
}

/* ---- CTR (64-bit big-endian counter in the low half; used by the tunnel) ---- */

static void aes_ctr_inc(uint8_t ctr[16]) {
    for (int i = 15; i >= 8; i--) {
        if (++ctr[i] != 0) break;
    }
}

void ntx_aes128_ctr_init(ntx_aes128_ctr *c, const uint8_t key[16], const uint8_t ctr0[16]) {
    aes_key_expand(key, c->rk);
    memcpy(c->ctr, ctr0, 16);
    c->left = 0;
}

void ntx_aes128_ctr_xcrypt(ntx_aes128_ctr *c, uint8_t *buf, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (c->left == 0) {
            aes_encrypt_block(c->rk, c->ctr, c->ks);
            aes_ctr_inc(c->ctr);
            c->left = 16;
        }
        buf[i] = (uint8_t)(buf[i] ^ c->ks[16 - c->left]);
        c->left--;
    }
}

/* ---- GHASH: constant-time carry-less multiplication ----------------------------
 * bmul64 multiplies two 64-bit polynomials over GF(2) (low 64 bits of the product) using
 * only integer multiplications: operands are split into 4 interleaved bit classes so the
 * ordinary carries of each partial product land in the "holes" and are masked off. No
 * branches, no table lookups. The high half comes from the same routine on bit-reversed
 * operands (Karatsuba over 3 products). */

static uint64_t bmul64(uint64_t x, uint64_t y) {
    uint64_t x0 = x & 0x1111111111111111ull, x1 = x & 0x2222222222222222ull;
    uint64_t x2 = x & 0x4444444444444444ull, x3 = x & 0x8888888888888888ull;
    uint64_t y0 = y & 0x1111111111111111ull, y1 = y & 0x2222222222222222ull;
    uint64_t y2 = y & 0x4444444444444444ull, y3 = y & 0x8888888888888888ull;
    uint64_t z0 = (x0 * y0) ^ (x1 * y3) ^ (x2 * y2) ^ (x3 * y1);
    uint64_t z1 = (x0 * y1) ^ (x1 * y0) ^ (x2 * y3) ^ (x3 * y2);
    uint64_t z2 = (x0 * y2) ^ (x1 * y1) ^ (x2 * y0) ^ (x3 * y3);
    uint64_t z3 = (x0 * y3) ^ (x1 * y2) ^ (x2 * y1) ^ (x3 * y0);
    return (z0 & 0x1111111111111111ull) | (z1 & 0x2222222222222222ull) |
           (z2 & 0x4444444444444444ull) | (z3 & 0x8888888888888888ull);
}

static uint64_t rev64(uint64_t x) {
    x = ((x & 0x5555555555555555ull) << 1) | ((x >> 1) & 0x5555555555555555ull);
    x = ((x & 0x3333333333333333ull) << 2) | ((x >> 2) & 0x3333333333333333ull);
    x = ((x & 0x0F0F0F0F0F0F0F0Full) << 4) | ((x >> 4) & 0x0F0F0F0F0F0F0F0Full);
    x = ((x & 0x00FF00FF00FF00FFull) << 8) | ((x >> 8) & 0x00FF00FF00FF00FFull);
    x = ((x & 0x0000FFFF0000FFFFull) << 16) | ((x >> 16) & 0x0000FFFF0000FFFFull);
    return (x << 32) | (x >> 32);
}

static uint64_t ld64be(const uint8_t *p) {
    uint64_t v = 0;
    for (int i = 0; i < 8; i++) v = (v << 8) | p[i];
    return v;
}

static void st64be(uint8_t *p, uint64_t v) {
    for (int i = 7; i >= 0; i--) {
        p[i] = (uint8_t)v;
        v >>= 8;
    }
}

typedef struct {
    uint64_t h0, h1, h0r, h1r, h2, h2r; /* hash key words (h1 = first 8 bytes) and bit-reversals */
    uint64_t y0, y1;                    /* accumulator (y1 = first 8 bytes) */
} ghash_t;

static void ghash_init(ghash_t *g, const uint8_t h[16]) {
    g->h1 = ld64be(h);
    g->h0 = ld64be(h + 8);
    g->h0r = rev64(g->h0);
    g->h1r = rev64(g->h1);
    g->h2 = g->h0 ^ g->h1;
    g->h2r = g->h0r ^ g->h1r;
    g->y0 = g->y1 = 0;
}

/* y = (y ^ block) * H in GF(2^128) with the GCM bit order. */
static void ghash_block(ghash_t *g, const uint8_t blk[16]) {
    uint64_t y1 = g->y1 ^ ld64be(blk), y0 = g->y0 ^ ld64be(blk + 8);
    uint64_t y0r = rev64(y0), y1r = rev64(y1);
    uint64_t y2 = y0 ^ y1, y2r = y0r ^ y1r;

    uint64_t z0 = bmul64(y0, g->h0), z1 = bmul64(y1, g->h1), z2 = bmul64(y2, g->h2);
    uint64_t z0h = bmul64(y0r, g->h0r), z1h = bmul64(y1r, g->h1r), z2h = bmul64(y2r, g->h2r);
    z2 ^= z0 ^ z1;
    z2h ^= z0h ^ z1h;
    z0h = rev64(z0h) >> 1;
    z1h = rev64(z1h) >> 1;
    z2h = rev64(z2h) >> 1;

    uint64_t v0 = z0, v1 = z0h ^ z2, v2 = z1 ^ z2h, v3 = z1h;
    /* GCM's reflected bit order: shift the 256-bit product left by one, then reduce
     * modulo x^128 + x^7 + x^2 + x + 1. */
    v3 = (v3 << 1) | (v2 >> 63);
    v2 = (v2 << 1) | (v1 >> 63);
    v1 = (v1 << 1) | (v0 >> 63);
    v0 = (v0 << 1);
    v2 ^= v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7);
    v1 ^= (v0 << 63) ^ (v0 << 62) ^ (v0 << 57);
    v3 ^= v1 ^ (v1 >> 1) ^ (v1 >> 2) ^ (v1 >> 7);
    v2 ^= (v1 << 63) ^ (v1 << 62) ^ (v1 << 57);
    g->y0 = v2;
    g->y1 = v3;
}

/* Absorb data, zero-padding the last partial block. */
static void ghash_update(ghash_t *g, const uint8_t *p, size_t n) {
    uint8_t blk[16];
    while (n >= 16) {
        ghash_block(g, p);
        p += 16;
        n -= 16;
    }
    if (n) {
        memset(blk, 0, 16);
        memcpy(blk, p, n);
        ghash_block(g, blk);
    }
}

static void ghash_final(ghash_t *g, size_t aadn, size_t n, uint8_t y[16]) {
    uint8_t blk[16];
    st64be(blk, (uint64_t)aadn * 8);
    st64be(blk + 8, (uint64_t)n * 8);
    ghash_block(g, blk);
    st64be(y, g->y1);
    st64be(y + 8, g->y0);
}

/* ---- GCM ---------------------------------------------------------------------- */

/* NIST SP 800-38D: |P| <= 2^39 - 256 bits, so the 32-bit block counter never wraps. */
#define GCM_MAX_BYTES (((uint64_t)1 << 36) - 32)

static void gcm_inc32(uint8_t ctr[16]) {
    for (int i = 15; i >= 12; i--) {
        if (++ctr[i] != 0) break;
    }
}

static void gcm_j0(const uint8_t nonce[12], uint8_t j0[16]) {
    memcpy(j0, nonce, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;
}

/* out = in ^ keystream(J0+1, ...). in == out is fine (each block is read before it is written). */
static void gcm_ctr(const ntx_aes128_gcm *g, const uint8_t nonce[12], const uint8_t *in, uint8_t *out, size_t n) {
    uint8_t ctr[16], ks[16];
    gcm_j0(nonce, ctr);
    for (size_t o = 0; o < n; o += 16) {
        gcm_inc32(ctr);
        aes_encrypt_block(g->rk, ctr, ks);
        size_t m = n - o < 16 ? n - o : 16;
        for (size_t i = 0; i < m; i++) out[o + i] = (uint8_t)(in[o + i] ^ ks[i]);
    }
}

static void gcm_tag(const ntx_aes128_gcm *g, const uint8_t nonce[12], const uint8_t *aad, size_t aadn,
                    const uint8_t *ct, size_t n, uint8_t tag[16]) {
    ghash_t gh;
    uint8_t y[16], j0[16], e[16];
    ghash_init(&gh, g->h);
    ghash_update(&gh, aad, aadn);
    ghash_update(&gh, ct, n);
    ghash_final(&gh, aadn, n, y);
    gcm_j0(nonce, j0);
    aes_encrypt_block(g->rk, j0, e);
    for (int i = 0; i < 16; i++) tag[i] = (uint8_t)(y[i] ^ e[i]);
}

void ntx_aes128_gcm_init(ntx_aes128_gcm *g, const uint8_t key[16]) {
    aes_key_expand(key, g->rk);
    uint8_t z[16];
    memset(z, 0, 16);
    aes_encrypt_block(g->rk, z, g->h);
}

int ntx_aes128_gcm_seal(const ntx_aes128_gcm *g, const uint8_t nonce[12],
                        const uint8_t *aad, size_t aadn,
                        const uint8_t *pt, size_t n,
                        uint8_t *ct, uint8_t tag[16]) {
    if ((uint64_t)n > GCM_MAX_BYTES) return 0;
    if (n) gcm_ctr(g, nonce, pt, ct, n);
    gcm_tag(g, nonce, aad, aadn, ct, n, tag);
    return 1;
}

int ntx_aes128_gcm_open(const ntx_aes128_gcm *g, const uint8_t nonce[12],
                        const uint8_t *aad, size_t aadn,
                        const uint8_t *ct, size_t n,
                        uint8_t *pt, const uint8_t tag[16]) {
    if ((uint64_t)n > GCM_MAX_BYTES) return 0;
    /* Authenticate first, decrypt only afterwards: unauthenticated plaintext is never
     * written, and pt == ct (in place) is safe because the tag is computed from ct before
     * ct is overwritten. */
    uint8_t t[16];
    gcm_tag(g, nonce, aad, aadn, ct, n, t);
    uint8_t d = 0;
    for (int i = 0; i < 16; i++) d = (uint8_t)(d | (t[i] ^ tag[i]));
    if (d != 0) return 0;
    if (n) gcm_ctr(g, nonce, ct, pt, n);
    return 1;
}
