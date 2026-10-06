#include "ntx_p256.h"

#include "ntx_bignum.h"

#include <string.h>

static const uint8_t P[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static const uint8_t N[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51};
static const uint8_t A[32] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFC};
static const uint8_t GX[32] = {
    0x6B, 0x17, 0xD1, 0xF2, 0xE1, 0x2C, 0x42, 0x47, 0xF8, 0xBC, 0xE6, 0xE5, 0x63, 0xA4, 0x40, 0xF2,
    0x77, 0x03, 0x7D, 0x81, 0x2D, 0xEB, 0x33, 0xA0, 0xF4, 0xA1, 0x39, 0x45, 0xD8, 0x98, 0xC2, 0x96};
static const uint8_t GY[32] = {
    0x4F, 0xE3, 0x42, 0xE2, 0xFE, 0x1A, 0x7F, 0x9B, 0x8E, 0xE7, 0xEB, 0x4A, 0x7C, 0x0F, 0x9E, 0x16,
    0x2B, 0xCE, 0x33, 0x57, 0x6B, 0x31, 0x5E, 0xCE, 0xCB, 0xB6, 0x40, 0x68, 0x37, 0xBF, 0x51, 0xF5};
static const uint8_t ONE[32] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

typedef struct {
    int inf;
    uint8_t X[32], Y[32], Z[32];
} jpt;

static int is_zero(const uint8_t a[32]) {
    uint8_t z = 0;
    for (int i = 0; i < 32; i++) z |= a[i];
    return z == 0;
}

static void fe_add(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    /* a, b < p  =>  a + b < 2p, so one masked conditional subtraction suffices
     * (R7: no data-dependent loop). r may alias a or b. */
    uint8_t t[32], d[32];
    unsigned c = 0, br = 0;
    for (int i = 31; i >= 0; i--) {
        unsigned s = (unsigned)a[i] + b[i] + c;
        t[i] = (uint8_t)s;
        c = s >> 8;
    }
    for (int i = 31; i >= 0; i--) {
        int v = (int)t[i] - (int)P[i] - (int)br;
        d[i] = (uint8_t)v;
        br = (v < 0);
    }
    uint8_t mask = (uint8_t)(0u - (c | (br ^ 1u))); /* sum >= p */
    for (int i = 0; i < 32; i++) r[i] = (uint8_t)((d[i] & mask) | (t[i] & (uint8_t)~mask));
}

static void fe_sub(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    if (ntx_bn_cmp(a, b, 32) >= 0) ntx_bn_sub(r, 32, a, b);
    else {
        uint8_t t[32];
        ntx_bn_sub(t, 32, P, b);
        fe_add(r, t, a);
    }
}

static void fe_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    ntx_bn_mulmod(r, 32, a, b, P);
}

static void fe_sqr(uint8_t r[32], const uint8_t a[32]) { fe_mul(r, a, a); }

static void fe_inv(uint8_t r[32], const uint8_t a[32]) {
    static const uint8_t E[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFD};
    ntx_bn_modexp(r, 32, a, E, 32, P);
}

static void sc_mul(uint8_t r[32], const uint8_t a[32], const uint8_t b[32]) {
    ntx_bn_mulmod(r, 32, a, b, N);
}

static void sc_inv(uint8_t r[32], const uint8_t a[32]) {
    static const uint8_t E[32] = {
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x4F};
    ntx_bn_modexp(r, 32, a, E, 32, N);
}

static void sc_mod(uint8_t r[32], const uint8_t a[32]) { ntx_bn_mod(r, 32, a, N); }

static int sc_ok(const uint8_t a[32]) {
    return !is_zero(a) && ntx_bn_cmp(a, N, 32) < 0;
}

/* Jacobian double (a=-3): from HAC / common formulas. */
static void j_dbl(jpt *r, const jpt *p) {
    if (p->inf || is_zero(p->Y)) {
        r->inf = 1;
        memset(r->X, 0, 32);
        memset(r->Y, 0, 32);
        memset(r->Z, 0, 32);
        return;
    }
    uint8_t delta[32], gamma[32], beta[32], alpha[32], t1[32], t2[32], t3[32];
    fe_sqr(delta, p->Z);                    /* Z^2 */
    fe_sqr(gamma, p->Y);                    /* Y^2 */
    fe_mul(beta, p->X, gamma);              /* X*Y^2 */
    fe_sub(t1, p->X, delta);
    fe_add(t2, p->X, delta);
    fe_mul(alpha, t1, t2);
    fe_add(t1, alpha, alpha);
    fe_add(alpha, t1, alpha);               /* alpha = 3*(X-Z^2)*(X+Z^2) = 3X^2+aZ^4 with a=-3 */
    fe_sqr(r->X, alpha);
    fe_add(t1, beta, beta);
    fe_add(t1, t1, t1);
    fe_add(t2, t1, t1);                     /* 8*beta */
    fe_sub(r->X, r->X, t2);
    fe_add(t1, p->Y, p->Y);
    fe_mul(r->Z, t1, p->Z);
    fe_add(t1, beta, beta);
    fe_add(t1, t1, t1);                     /* 4*beta */
    fe_sub(t1, t1, r->X);
    fe_mul(t2, alpha, t1);
    fe_sqr(t3, gamma);
    fe_add(t1, t3, t3);
    fe_add(t1, t1, t1);
    fe_add(t1, t1, t1);                     /* 8*Y^4 */
    fe_sub(r->Y, t2, t1);
    r->inf = 0;
}

/* Jacobian add: r = p + q (q affine Z=1 allowed; general q). */
static void j_add(jpt *r, const jpt *p, const jpt *q) {
    if (p->inf) {
        *r = *q;
        return;
    }
    if (q->inf) {
        *r = *p;
        return;
    }
    uint8_t z1z1[32], z2z2[32], u1[32], u2[32], s1[32], s2[32], h[32], r_[32], t1[32], t2[32];
    fe_sqr(z1z1, p->Z);
    fe_sqr(z2z2, q->Z);
    fe_mul(u1, p->X, z2z2);
    fe_mul(u2, q->X, z1z1);
    fe_mul(t1, q->Z, z2z2);
    fe_mul(s1, p->Y, t1);
    fe_mul(t1, p->Z, z1z1);
    fe_mul(s2, q->Y, t1);
    fe_sub(h, u2, u1);
    fe_sub(r_, s2, s1);
    if (is_zero(h)) {
        if (is_zero(r_)) {
            j_dbl(r, p);
            return;
        }
        r->inf = 1;
        memset(r->X, 0, 32);
        memset(r->Y, 0, 32);
        memset(r->Z, 0, 32);
        return;
    }
    uint8_t hh[32], hhh[32], v[32];
    fe_sqr(hh, h);
    fe_mul(hhh, h, hh);
    fe_mul(v, u1, hh);
    fe_sqr(r->X, r_);
    fe_sub(r->X, r->X, hhh);
    fe_sub(r->X, r->X, v);
    fe_sub(r->X, r->X, v);
    fe_sub(t1, v, r->X);
    fe_mul(t1, r_, t1);
    fe_mul(t2, s1, hhh);
    fe_sub(r->Y, t1, t2);
    fe_mul(t1, p->Z, q->Z);
    fe_mul(r->Z, t1, h);
    r->inf = 0;
    (void)A;
}

static void j_from_affine(jpt *r, const uint8_t x[32], const uint8_t y[32]) {
    r->inf = 0;
    memcpy(r->X, x, 32);
    memcpy(r->Y, y, 32);
    memcpy(r->Z, ONE, 32);
}

static void j_to_affine(uint8_t x[32], uint8_t y[32], const jpt *p) {
    if (p->inf) {
        memset(x, 0, 32);
        memset(y, 0, 32);
        return;
    }
    uint8_t zinv[32], z2[32], z3[32];
    fe_inv(zinv, p->Z);
    fe_sqr(z2, zinv);
    fe_mul(z3, z2, zinv);
    fe_mul(x, p->X, z2);
    fe_mul(y, p->Y, z3);
}

static void j_mul(jpt *r, const jpt *p, const uint8_t k[32]) {
    jpt acc, base, tmp;
    acc.inf = 1;
    memset(acc.X, 0, 32);
    memset(acc.Y, 0, 32);
    memset(acc.Z, 0, 32);
    base = *p;
    for (int bi = 0; bi < 256; bi++) {
        j_dbl(&tmp, &acc);
        acc = tmp;
        if ((k[bi / 8] >> (7 - (bi % 8))) & 1) {
            j_add(&tmp, &acc, &base);
            acc = tmp;
        }
    }
    *r = acc;
}

/* Curve coefficient b of y^2 = x^3 - 3x + b (FIPS 186-4 D.1.2.3). */
static const uint8_t CURVE_B[32] = {
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B};

int ntx_p256_point_on_curve(const uint8_t x[32], const uint8_t y[32]) {
    if (!x || !y) return 0;
    /* Coordinates must be canonical field elements. */
    if (ntx_bn_cmp(x, P, 32) >= 0 || ntx_bn_cmp(y, P, 32) >= 0) return 0;
    uint8_t lhs[32], rhs[32], x3[32], t[32];
    fe_sqr(lhs, y);                 /* y^2 */
    fe_sqr(t, x);
    fe_mul(x3, t, x);               /* x^3 */
    fe_add(t, x, x);
    fe_add(t, t, x);                /* 3x */
    fe_sub(rhs, x3, t);             /* x^3 - 3x */
    fe_add(rhs, rhs, CURVE_B);      /* x^3 - 3x + b */
    return memcmp(lhs, rhs, 32) == 0;
}

int ntx_p256_ecdsa_verify_sha256(const uint8_t qx[32], const uint8_t qy[32], const uint8_t r[32],
                                 const uint8_t s[32], const uint8_t hash[32]) {
    if (!qx || !qy || !r || !s || !hash) return 0;
    if (!sc_ok(r) || !sc_ok(s)) return 0;
    /* R1: reject public keys that are not on the curve (invalid-curve attacks)
     * or are not canonical; the point at infinity (0,0) fails this too. */
    if (!ntx_p256_point_on_curve(qx, qy)) return 0;

    uint8_t e[32], w[32], u1[32], u2[32];
    sc_mod(e, hash);
    sc_inv(w, s);
    sc_mul(u1, e, w);
    sc_mul(u2, r, w);

    jpt G, Q, R1, R2, R;
    j_from_affine(&G, GX, GY);
    j_from_affine(&Q, qx, qy);
    j_mul(&R1, &G, u1);
    j_mul(&R2, &Q, u2);
    j_add(&R, &R1, &R2);
    if (R.inf) return 0;

    uint8_t rx[32], ry[32], v[32];
    j_to_affine(rx, ry, &R);
    (void)ry;
    sc_mod(v, rx);
    return ntx_bn_cmp(v, r, 32) == 0;
}

static int p256_der_tl(const uint8_t *p, size_t n, size_t *hdr, size_t *len) {
    if (n < 2) return -1;
    if (!(p[1] & 0x80)) {
        *hdr = 2;
        *len = p[1];
        return (*hdr + *len <= n) ? 0 : -1;
    }
    size_t nl = (size_t)(p[1] & 0x7f);
    if (nl < 1 || nl > 2 || 2 + nl > n) return -1;
    size_t L = 0;
    for (size_t i = 0; i < nl; i++) L = (L << 8) | p[2 + i];
    *hdr = 2 + nl;
    *len = L;
    return (*hdr + *len <= n) ? 0 : -1;
}

static int int_to_32(const uint8_t *p, size_t len, uint8_t out[32]) {
    while (len > 0 && p[0] == 0) {
        p++;
        len--;
    }
    if (len > 32) return -1;
    memset(out, 0, 32);
    memcpy(out + (32 - len), p, len);
    return 0;
}

int ntx_p256_sig_from_der(const uint8_t *der, size_t der_len, uint8_t r[32], uint8_t s[32]) {
    size_t hdr, len;
    if (!der || !r || !s) return -1;
    if (der_len < 1 || der[0] != 0x30) return -1;
    if (p256_der_tl(der, der_len, &hdr, &len) != 0) return -1;
    if (hdr + len != der_len) return -1;
    const uint8_t *p = der + hdr;
    size_t rem = len;
    if (rem < 1 || p[0] != 0x02) return -1;
    size_t h2, l2;
    if (p256_der_tl(p, rem, &h2, &l2) != 0) return -1;
    if (int_to_32(p + h2, l2, r) != 0) return -1;
    p += h2 + l2;
    rem -= h2 + l2;
    if (rem < 1 || p[0] != 0x02) return -1;
    if (p256_der_tl(p, rem, &h2, &l2) != 0) return -1;
    if (h2 + l2 != rem) return -1;
    return int_to_32(p + h2, l2, s);
}

/* DER of AlgorithmIdentifier { id-ecPublicKey (1.2.840.10045.2.1), prime256v1 (1.2.840.10045.3.1.7) }. */
static const uint8_t SPKI_P256_ALG[21] = {
    0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07};

int ntx_p256_pubkey_from_spki(const uint8_t *spki, size_t spki_len, uint8_t qx[32], uint8_t qy[32]) {
    size_t hdr, len;
    if (!spki || !qx || !qy || spki_len < 50) return -1;
    if (spki[0] != 0x30) return -1;
    if (p256_der_tl(spki, spki_len, &hdr, &len) != 0) return -1;
    if (hdr + len != spki_len) return -1; /* no trailing bytes */
    const uint8_t *p = spki + hdr;
    /* SEQUENCE { AlgorithmIdentifier, BIT STRING { 0x00, 0x04, X, Y } } - nothing else. The
     * algorithm and curve OIDs are compared exactly, so a P-384 or secp256k1 key (same
     * framing, different curve) is not silently read as P-256 coordinates. */
    if (len != sizeof SPKI_P256_ALG + 4 + 64) return -1;
    if (memcmp(p, SPKI_P256_ALG, sizeof SPKI_P256_ALG) != 0) return -1;
    p += sizeof SPKI_P256_ALG;
    if (p[0] != 0x03 || p[1] != 0x42 || p[2] != 0x00 || p[3] != 0x04) return -1;
    memcpy(qx, p + 4, 32);
    memcpy(qy, p + 36, 32);
    return 0;
}
