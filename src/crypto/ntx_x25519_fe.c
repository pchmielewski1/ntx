#include "ntx_x25519_fe.h"

/* 5×51-bit little-endian limbs; value = Σ v[i]·2^(51·i) mod (2^255−19). */
#define MASK51 ((1ULL << 51) - 1)

static void fe_carry(ntx_fe *f)
{
    uint64_t c;
    c = f->v[0] >> 51; f->v[0] &= MASK51; f->v[1] += c;
    c = f->v[1] >> 51; f->v[1] &= MASK51; f->v[2] += c;
    c = f->v[2] >> 51; f->v[2] &= MASK51; f->v[3] += c;
    c = f->v[3] >> 51; f->v[3] &= MASK51; f->v[4] += c;
    c = f->v[4] >> 51; f->v[4] &= MASK51; f->v[0] += 19ULL * c;
    c = f->v[0] >> 51; f->v[0] &= MASK51; f->v[1] += c;
}

static uint64_t load_le64(const uint8_t *p)
{
    uint64_t x = 0;
    for (int i = 0; i < 8; i++) x |= (uint64_t)p[i] << (8 * i);
    return x;
}

void ntx_fe_from_bytes(ntx_fe *f, const uint8_t b[32])
{
    uint64_t t0 = load_le64(b);
    uint64_t t1 = load_le64(b + 6);
    uint64_t t2 = load_le64(b + 12);
    uint64_t t3 = load_le64(b + 19);
    uint64_t t4 = load_le64(b + 24);
    f->v[0] = t0 & MASK51;
    f->v[1] = (t1 >> 3) & MASK51;
    f->v[2] = (t2 >> 6) & MASK51;
    f->v[3] = (t3 >> 1) & MASK51;
    f->v[4] = (t4 >> 12) & MASK51;
}

void ntx_fe_to_bytes(uint8_t b[32], const ntx_fe *h)
{
    ntx_fe f = *h;
    fe_carry(&f);
    fe_carry(&f);

    /* Fully reduce to [0, p). */
    ntx_fe t;
    uint64_t c;
    t.v[0] = f.v[0] + 19;
    c = t.v[0] >> 51; t.v[0] &= MASK51;
    t.v[1] = f.v[1] + c; c = t.v[1] >> 51; t.v[1] &= MASK51;
    t.v[2] = f.v[2] + c; c = t.v[2] >> 51; t.v[2] &= MASK51;
    t.v[3] = f.v[3] + c; c = t.v[3] >> 51; t.v[3] &= MASK51;
    t.v[4] = f.v[4] + c; c = t.v[4] >> 51;
    /* If c != 0, f+19 >= 2^255 so f >= p; take t with top bit cleared. */
    uint64_t mask = (uint64_t)(-(int64_t)c);
    f.v[0] = (f.v[0] & ~mask) | (t.v[0] & mask);
    f.v[1] = (f.v[1] & ~mask) | (t.v[1] & mask);
    f.v[2] = (f.v[2] & ~mask) | (t.v[2] & mask);
    f.v[3] = (f.v[3] & ~mask) | (t.v[3] & mask);
    f.v[4] = (f.v[4] & ~mask) | ((t.v[4] & MASK51) & mask);

    uint64_t r0 = f.v[0] | (f.v[1] << 51);
    uint64_t r1 = (f.v[1] >> 13) | (f.v[2] << 38);
    uint64_t r2 = (f.v[2] >> 26) | (f.v[3] << 25);
    uint64_t r3 = (f.v[3] >> 39) | (f.v[4] << 12);
    for (int i = 0; i < 8; i++) b[i]      = (uint8_t)(r0 >> (8 * i));
    for (int i = 0; i < 8; i++) b[8 + i]  = (uint8_t)(r1 >> (8 * i));
    for (int i = 0; i < 8; i++) b[16 + i] = (uint8_t)(r2 >> (8 * i));
    for (int i = 0; i < 8; i++) b[24 + i] = (uint8_t)(r3 >> (8 * i));
}

void ntx_fe_set_u64(ntx_fe *f, uint64_t x)
{
    f->v[0] = x;
    f->v[1] = 0;
    f->v[2] = 0;
    f->v[3] = 0;
    f->v[4] = 0;
}

void ntx_fe_add(ntx_fe *r, const ntx_fe *a, const ntx_fe *b)
{
    r->v[0] = a->v[0] + b->v[0];
    r->v[1] = a->v[1] + b->v[1];
    r->v[2] = a->v[2] + b->v[2];
    r->v[3] = a->v[3] + b->v[3];
    r->v[4] = a->v[4] + b->v[4];
}

void ntx_fe_sub(ntx_fe *r, const ntx_fe *a, const ntx_fe *b)
{
    /* a - b + 2p to stay non-negative before carry */
    r->v[0] = (a->v[0] + 0xFFFFFFFFFFFDAULL) - b->v[0];
    r->v[1] = (a->v[1] + 0xFFFFFFFFFFFFEULL) - b->v[1];
    r->v[2] = (a->v[2] + 0xFFFFFFFFFFFFEULL) - b->v[2];
    r->v[3] = (a->v[3] + 0xFFFFFFFFFFFFEULL) - b->v[3];
    r->v[4] = (a->v[4] + 0xFFFFFFFFFFFFEULL) - b->v[4];
    fe_carry(r);
}

void ntx_fe_mul(ntx_fe *r, const ntx_fe *a, const ntx_fe *b)
{
    __uint128_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];
    __uint128_t b0 = b->v[0], b1 = b->v[1], b2 = b->v[2], b3 = b->v[3], b4 = b->v[4];
    __uint128_t b1_19 = b1 * 19, b2_19 = b2 * 19, b3_19 = b3 * 19, b4_19 = b4 * 19;

    __uint128_t c0 = a0*b0 + a1*b4_19 + a2*b3_19 + a3*b2_19 + a4*b1_19;
    __uint128_t c1 = a0*b1 + a1*b0    + a2*b4_19 + a3*b3_19 + a4*b2_19;
    __uint128_t c2 = a0*b2 + a1*b1    + a2*b0    + a3*b4_19 + a4*b3_19;
    __uint128_t c3 = a0*b3 + a1*b2    + a2*b1    + a3*b0    + a4*b4_19;
    __uint128_t c4 = a0*b4 + a1*b3    + a2*b2    + a3*b1    + a4*b0;

    uint64_t c;
    r->v[0] = (uint64_t)c0 & MASK51; c = (uint64_t)(c0 >> 51);
    c1 += c;
    r->v[1] = (uint64_t)c1 & MASK51; c = (uint64_t)(c1 >> 51);
    c2 += c;
    r->v[2] = (uint64_t)c2 & MASK51; c = (uint64_t)(c2 >> 51);
    c3 += c;
    r->v[3] = (uint64_t)c3 & MASK51; c = (uint64_t)(c3 >> 51);
    c4 += c;
    r->v[4] = (uint64_t)c4 & MASK51; c = (uint64_t)(c4 >> 51);
    r->v[0] += c * 19;
    c = r->v[0] >> 51; r->v[0] &= MASK51; r->v[1] += c;
}

void ntx_fe_sq(ntx_fe *r, const ntx_fe *a)
{
    ntx_fe_mul(r, a, a);
}

/* r = a^(p-2) = a^(2^255-21) via ref10 addition chain. */
void ntx_fe_inv(ntx_fe *r, const ntx_fe *a)
{
    ntx_fe t0, t1, t2, t3;
    int i;

    ntx_fe_sq(&t0, a);
    ntx_fe_sq(&t1, &t0);
    ntx_fe_sq(&t1, &t1);
    ntx_fe_mul(&t1, a, &t1);
    ntx_fe_mul(&t0, &t0, &t1);
    ntx_fe_sq(&t2, &t0);
    ntx_fe_mul(&t1, &t1, &t2);
    ntx_fe_sq(&t2, &t1);
    for (i = 1; i < 5; i++) ntx_fe_sq(&t2, &t2);
    ntx_fe_mul(&t1, &t2, &t1);
    ntx_fe_sq(&t2, &t1);
    for (i = 1; i < 10; i++) ntx_fe_sq(&t2, &t2);
    ntx_fe_mul(&t2, &t2, &t1);
    ntx_fe_sq(&t3, &t2);
    for (i = 1; i < 20; i++) ntx_fe_sq(&t3, &t3);
    ntx_fe_mul(&t2, &t3, &t2);
    ntx_fe_sq(&t2, &t2);
    for (i = 1; i < 10; i++) ntx_fe_sq(&t2, &t2);
    ntx_fe_mul(&t1, &t2, &t1);
    ntx_fe_sq(&t2, &t1);
    for (i = 1; i < 50; i++) ntx_fe_sq(&t2, &t2);
    ntx_fe_mul(&t2, &t2, &t1);
    ntx_fe_sq(&t3, &t2);
    for (i = 1; i < 100; i++) ntx_fe_sq(&t3, &t3);
    ntx_fe_mul(&t2, &t3, &t2);
    ntx_fe_sq(&t2, &t2);
    for (i = 1; i < 50; i++) ntx_fe_sq(&t2, &t2);
    ntx_fe_mul(&t1, &t2, &t1);
    ntx_fe_sq(&t1, &t1);
    for (i = 1; i < 5; i++) ntx_fe_sq(&t1, &t1);
    ntx_fe_mul(r, &t1, &t0);
}
