#include "ntx_x25519.h"
#include "ntx_x25519_fe.h"
#include "ntx_ct.h"
#include <string.h>

static void fe_cswap(ntx_fe *a, ntx_fe *b, unsigned int swap)
{
    uint64_t mask = (uint64_t)(-(int64_t)swap);
    for (int i = 0; i < 5; i++) {
        uint64_t t = mask & (a->v[i] ^ b->v[i]);
        a->v[i] ^= t;
        b->v[i] ^= t;
    }
}

int ntx_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32])
{
    uint8_t e[32];
    memcpy(e, scalar, 32);
    e[0]  &= 248;
    e[31] &= 127;
    e[31] |= 64;

    ntx_fe x1, x2, z2, x3, z3;
    ntx_fe A, AA, B, BB, C, D, E, DA, CB;
    ntx_fe a24;
    uint8_t ub[32];

    memcpy(ub, u, 32);
    ub[31] &= 127; /* RFC 7748: ignore MSB of u */
    ntx_fe_from_bytes(&x1, ub);
    ntx_fe_set_u64(&x2, 1);
    ntx_fe_set_u64(&z2, 0);
    x3 = x1;
    ntx_fe_set_u64(&z3, 1);
    ntx_fe_set_u64(&a24, 121665);

    unsigned int swap = 0;
    for (int pos = 254; pos >= 0; pos--) {
        unsigned int bit = (e[pos / 8] >> (pos & 7)) & 1;
        swap ^= bit;
        fe_cswap(&x2, &x3, swap);
        fe_cswap(&z2, &z3, swap);
        swap = bit;

        /* RFC 7748 Montgomery ladder step */
        ntx_fe_add(&A, &x2, &z2);
        ntx_fe_sq(&AA, &A);
        ntx_fe_sub(&B, &x2, &z2);
        ntx_fe_sq(&BB, &B);
        ntx_fe_sub(&E, &AA, &BB);
        ntx_fe_add(&C, &x3, &z3);
        ntx_fe_sub(&D, &x3, &z3);
        ntx_fe_mul(&DA, &D, &A);
        ntx_fe_mul(&CB, &C, &B);
        ntx_fe_add(&x3, &DA, &CB);
        ntx_fe_sq(&x3, &x3);
        ntx_fe_sub(&z3, &DA, &CB);
        ntx_fe_sq(&z3, &z3);
        ntx_fe_mul(&z3, &x1, &z3);
        ntx_fe_mul(&x2, &AA, &BB);
        ntx_fe_mul(&z2, &E, &a24);
        ntx_fe_add(&z2, &AA, &z2);
        ntx_fe_mul(&z2, &E, &z2);
    }
    fe_cswap(&x2, &x3, swap);
    fe_cswap(&z2, &z3, swap);

    ntx_fe_inv(&z2, &z2);
    ntx_fe_mul(&x2, &x2, &z2);
    ntx_fe_to_bytes(out, &x2);

    /* RFC 7748 §6.1 / RFC 8446 §7.4.2: a peer that sends a low-order point
     * (u = 0, 1, p-1, p, p+1, ...) forces an all-zero shared secret. Report it so
     * the caller can abort the handshake. Folded without data-dependent branches. */
    uint8_t acc = 0;
    for (int i = 0; i < 32; i++) acc |= out[i];

    /* The clamped scalar and the ladder registers are secret-dependent: don't leave them on the stack. */
    ntx_wipe(e, sizeof e);
    ntx_wipe(&x2, sizeof x2); ntx_wipe(&z2, sizeof z2);
    ntx_wipe(&x3, sizeof x3); ntx_wipe(&z3, sizeof z3);
    ntx_wipe(&A, sizeof A);   ntx_wipe(&B, sizeof B);   ntx_wipe(&C, sizeof C);
    ntx_wipe(&D, sizeof D);   ntx_wipe(&E, sizeof E);   ntx_wipe(&AA, sizeof AA);
    ntx_wipe(&BB, sizeof BB); ntx_wipe(&DA, sizeof DA); ntx_wipe(&CB, sizeof CB);
    return acc == 0 ? -1 : 0;
}

void ntx_x25519_base(uint8_t out[32], const uint8_t scalar[32])
{
    static const uint8_t nine[32] = { 9 };
    ntx_x25519(out, scalar, nine);
}
