#include "ntx_bignum.h"

#include "ntx_ct.h"

#include <string.h>

int ntx_bn_cmp(const uint8_t *a, const uint8_t *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; i++) {
        if (a[i] > b[i])
            return 1;
        if (a[i] < b[i])
            return -1;
    }
    return 0;
}

static void bn_sub_be(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t n)
{
    int borrow = 0;
    size_t i;
    for (i = n; i-- > 0;) {
        int av = (int)a[i] - borrow;
        borrow = av < (int)b[i];
        r[i] = (uint8_t)(av - (int)b[i]);
    }
}

static void bn_add_be(uint8_t *r, const uint8_t *a, const uint8_t *b, size_t n)
{
    unsigned carry = 0;
    size_t i;
    for (i = n; i-- > 0;) {
        unsigned s = (unsigned)a[i] + (unsigned)b[i] + carry;
        r[i] = (uint8_t)(s & 0xFFu);
        carry = s >> 8;
    }
}

void ntx_bn_add(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *b)
{
    bn_add_be(r, a, b, n);
}

void ntx_bn_sub(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *b)
{
    bn_sub_be(r, a, b, n);
}

/* ---- Montgomery core ------------------------------------------------------ */

void ntx_mont_from_be(const ntx_mont *c, uint32_t *limbs, const uint8_t *be, size_t len)
{
    for (unsigned i = 0; i < c->n; i++) {
        uint32_t v = 0;
        for (unsigned k = 0; k < 4; k++) {
            size_t j = 4 * (size_t)i + k; /* byte index from the least significant end */
            if (j < len)
                v |= (uint32_t)be[len - 1 - j] << (8 * k);
        }
        limbs[i] = v;
    }
}

void ntx_mont_to_be(const ntx_mont *c, uint8_t *be, size_t len, const uint32_t *limbs)
{
    for (size_t j = 0; j < len; j++) {
        size_t li = j / 4;
        uint32_t v = li < c->n ? limbs[li] : 0;
        be[len - 1 - j] = (uint8_t)(v >> (8 * (j % 4)));
    }
}

/* r = t - m if t >= m (t has n+1 limbs), else t. Branch-free; r may alias t. */
static void bnm_cond_sub(const ntx_mont *c, uint32_t *r, const uint32_t *t)
{
    unsigned n = c->n;
    uint32_t d[NTX_MONT_MAX_LIMBS];
    uint64_t borrow = 0;
    for (unsigned j = 0; j < n; j++) {
        uint64_t s = (uint64_t)t[j] - c->m[j] - borrow;
        d[j] = (uint32_t)s;
        borrow = (s >> 32) & 1;
    }
    uint32_t hi = t[n];
    uint32_t nz = (hi | (0u - hi)) >> 31;           /* 1 iff the extra limb is set */
    uint32_t use_d = nz | (uint32_t)(borrow ^ 1u);  /* t >= m */
    uint32_t mask = 0u - use_d;
    for (unsigned j = 0; j < n; j++)
        r[j] = (d[j] & mask) | (t[j] & ~mask);
}

/* CIOS Montgomery multiplication. r may alias a or b. */
void ntx_mont_mul(const ntx_mont *c, uint32_t *r, const uint32_t *a, const uint32_t *b)
{
    unsigned n = c->n;
    uint32_t t[NTX_MONT_MAX_LIMBS + 2];
    memset(t, 0, (n + 2) * sizeof t[0]);
    for (unsigned i = 0; i < n; i++) {
        uint64_t carry = 0, s;
        for (unsigned j = 0; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)a[j] * b[i] + carry;
            t[j] = (uint32_t)s;
            carry = s >> 32;
        }
        s = (uint64_t)t[n] + carry;
        t[n] = (uint32_t)s;
        t[n + 1] = (uint32_t)(s >> 32);

        uint32_t q = t[0] * c->n0;
        s = (uint64_t)t[0] + (uint64_t)q * c->m[0];
        carry = s >> 32;
        for (unsigned j = 1; j < n; j++) {
            s = (uint64_t)t[j] + (uint64_t)q * c->m[j] + carry;
            t[j - 1] = (uint32_t)s;
            carry = s >> 32;
        }
        s = (uint64_t)t[n] + carry;
        t[n - 1] = (uint32_t)s;
        t[n] = t[n + 1] + (uint32_t)(s >> 32);
    }
    bnm_cond_sub(c, r, t);
}

int ntx_mont_init(ntx_mont *c, const uint8_t *mod, size_t len)
{
    if (!mod || len == 0 || len > NTX_BN_MAX || !(mod[len - 1] & 1u))
        return -1;
    c->n = (unsigned)((len + 3) / 4);
    memset(c->m, 0, sizeof c->m);
    memset(c->rr, 0, sizeof c->rr);
    ntx_mont_from_be(c, c->m, mod, len);
    if (c->n == 1 && c->m[0] < 3)
        return -1;

    /* -m^-1 mod 2^32 by Newton iteration (m is odd). */
    uint32_t inv = c->m[0];
    for (int i = 0; i < 5; i++)
        inv *= 2u - c->m[0] * inv;
    c->n0 = 0u - inv;

    /* R^2 mod m: start at 2^(bits(m)-1) (< m) and double up to 2^(64 n). */
    unsigned top = c->n;
    while (top > 1 && c->m[top - 1] == 0)
        top--;
    unsigned tb = 0;
    for (uint32_t v = c->m[top - 1]; v; v >>= 1)
        tb++;                                    /* bits in the top non-zero limb */
    unsigned bits = (top - 1) * 32 + tb;         /* bit length of m */
    uint32_t x[NTX_MONT_MAX_LIMBS + 1];
    memset(x, 0, sizeof x);
    x[(bits - 1) / 32] = 1u << ((bits - 1) % 32);
    for (unsigned k = bits - 1; k < 64u * c->n; k++) {
        uint32_t carry = 0;
        for (unsigned j = 0; j <= c->n; j++) {
            uint32_t nc = x[j] >> 31;
            x[j] = (x[j] << 1) | carry;
            carry = nc;
        }
        bnm_cond_sub(c, x, x);
        x[c->n] = 0;
    }
    memcpy(c->rr, x, c->n * sizeof x[0]);
    return 0;
}

void ntx_mont_exp(const ntx_mont *c, uint8_t *r, size_t len_out,
                  const uint8_t *base, size_t base_len,
                  const uint8_t *exp, size_t exp_len)
{
    unsigned n = c->n;
    uint32_t b[NTX_MONT_MAX_LIMBS], bm[NTX_MONT_MAX_LIMBS];
    uint32_t acc[NTX_MONT_MAX_LIMBS], one[NTX_MONT_MAX_LIMBS];

    memset(one, 0, n * sizeof one[0]);
    one[0] = 1;
    ntx_mont_from_be(c, b, base, base_len);
    ntx_mont_mul(c, bm, b, c->rr);      /* base * R   (base < R, rr < m  =>  result < m) */
    ntx_mont_mul(c, acc, one, c->rr);   /* 1 * R mod m */

    int started = 0;
    for (size_t i = 0; i < exp_len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            int on = (exp[i] >> bit) & 1;
            if (!started) {
                if (!on)
                    continue;
                started = 1;
            } else {
                ntx_mont_mul(c, acc, acc, acc);
            }
            if (on)
                ntx_mont_mul(c, acc, acc, bm);
        }
    }
    ntx_mont_mul(c, acc, acc, one);     /* leave the Montgomery domain */
    ntx_mont_to_be(c, r, len_out, acc);
}

/* Same result as ntx_mont_exp, but for a SECRET exponent (DH): every exponent bit costs one
 * squaring and one multiplication, and the product is kept or dropped with a mask, so
 * neither control flow nor memory addressing depends on the exponent. Leading zero bits are
 * processed too; only exp_len (public) matters. The modulus and base are public. */
void ntx_mont_exp_ct(const ntx_mont *c, uint8_t *r, size_t len_out,
                     const uint8_t *base, size_t base_len,
                     const uint8_t *exp, size_t exp_len)
{
    unsigned n = c->n;
    uint32_t b[NTX_MONT_MAX_LIMBS], bm[NTX_MONT_MAX_LIMBS];
    uint32_t acc[NTX_MONT_MAX_LIMBS], tmp[NTX_MONT_MAX_LIMBS], one[NTX_MONT_MAX_LIMBS];

    memset(one, 0, n * sizeof one[0]);
    one[0] = 1;
    ntx_mont_from_be(c, b, base, base_len);
    ntx_mont_mul(c, bm, b, c->rr);      /* base * R */
    ntx_mont_mul(c, acc, one, c->rr);   /* 1 * R mod m */

    for (size_t i = 0; i < exp_len; i++) {
        for (int bit = 7; bit >= 0; bit--) {
            ntx_mont_mul(c, acc, acc, acc);
            ntx_mont_mul(c, tmp, acc, bm);
            uint32_t mask = 0u - (uint32_t)((exp[i] >> bit) & 1);
            for (unsigned j = 0; j < n; j++)
                acc[j] = (tmp[j] & mask) | (acc[j] & ~mask);
        }
    }
    ntx_mont_mul(c, acc, acc, one);     /* leave the Montgomery domain */
    ntx_mont_to_be(c, r, len_out, acc);
    ntx_wipe(acc, sizeof acc);
    ntx_wipe(tmp, sizeof tmp);
    ntx_wipe(bm, sizeof bm);
    ntx_wipe(b, sizeof b);
}

/* ---- public byte-array API ------------------------------------------------
 * The modulus must be odd and >= 3 (every RSA, P-256 and DH modulus is). Anything else
 * fails closed: the result is n zero bytes. Operands may be any n-byte value, including
 * values >= the modulus. */

void ntx_bn_mod(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *m)
{
    ntx_mont c;
    if (ntx_mont_init(&c, m, n) != 0) {
        memset(r, 0, n);
        return;
    }
    uint32_t al[NTX_MONT_MAX_LIMBS], one[NTX_MONT_MAX_LIMBS];
    memset(one, 0, c.n * sizeof one[0]);
    one[0] = 1;
    ntx_mont_from_be(&c, al, a, n);
    ntx_mont_mul(&c, al, al, c.rr);  /* a*R mod m  (a < R, rr < m) */
    ntx_mont_mul(&c, al, al, one);   /* a mod m */
    ntx_mont_to_be(&c, r, n, al);
}

void ntx_bn_mulmod(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *b, const uint8_t *m)
{
    ntx_mont c;
    if (ntx_mont_init(&c, m, n) != 0) {
        memset(r, 0, n);
        return;
    }
    uint32_t al[NTX_MONT_MAX_LIMBS], bl[NTX_MONT_MAX_LIMBS];
    ntx_mont_from_be(&c, al, a, n);
    ntx_mont_from_be(&c, bl, b, n);
    ntx_mont_mul(&c, al, al, c.rr);  /* a*R mod m: reduces a, even if a >= m */
    ntx_mont_mul(&c, al, al, bl);    /* (a*R)*b*R^-1 = a*b mod m  (a*R mod m < m, b < R) */
    ntx_mont_to_be(&c, r, n, al);
}

void ntx_bn_modexp(uint8_t *r, size_t n, const uint8_t *base, const uint8_t *exp, size_t explen,
                   const uint8_t *mod)
{
    ntx_mont c;
    if (ntx_mont_init(&c, mod, n) != 0) {
        memset(r, 0, n);
        return;
    }
    ntx_mont_exp(&c, r, n, base, n, exp, explen);
}
