#ifndef NTX_BIGNUM_H
#define NTX_BIGNUM_H
#include <stdint.h>
#include <stddef.h>
/* Big-endian unsigned integers, max 512 bytes (4096 bits). Buffers are exactly n bytes.
 *
 * ntx_bn_cmp/mod/mulmod/modexp are for PUBLIC values only (signature verification:
 * RSA, ECDSA): ntx_bn_modexp scans its exponent with data-dependent branches.
 * Secret exponents (DH) use ntx_mont_exp_ct below; X25519 has its own field code.
 *
 * Everything is built on one 32-bit-limb Montgomery core, so the modulus must be odd
 * and >= 3 (every RSA, P-256 and DH modulus is). Any other modulus fails closed: the
 * result is n zero bytes. Operands may be >= the modulus. */
#define NTX_BN_MAX 512

void ntx_bn_add(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *b);
void ntx_bn_sub(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *b);
int  ntx_bn_cmp(const uint8_t *a, const uint8_t *b, size_t n);
void ntx_bn_mod(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *m);
void ntx_bn_mulmod(uint8_t *r, size_t n, const uint8_t *a, const uint8_t *b, const uint8_t *m);
void ntx_bn_modexp(uint8_t *r, size_t n, const uint8_t *base, const uint8_t *exp, size_t explen, const uint8_t *mod);

/* ---- Montgomery core (odd modulus) -------------------------------------------
 * Values live in little-endian 32-bit limbs, n limbs each, and must be < 2^(32 n).
 * ntx_mont_mul computes a*b*R^-1 mod m with R = 2^(32 n); it needs a*b < m*R (true
 * whenever one operand is < m). The multiplication itself is branch-free and
 * indexes memory only by public loop counters. */
#define NTX_MONT_MAX_LIMBS (NTX_BN_MAX / 4)

typedef struct {
    unsigned n;                         /* limbs */
    uint32_t n0;                        /* -m^-1 mod 2^32 */
    uint32_t m[NTX_MONT_MAX_LIMBS];     /* modulus */
    uint32_t rr[NTX_MONT_MAX_LIMBS];    /* R^2 mod m */
} ntx_mont;

/* mod: big-endian, len bytes. Returns 0, or -1 if mod is even, < 3 or too long. */
int  ntx_mont_init(ntx_mont *c, const uint8_t *mod, size_t len);
void ntx_mont_mul(const ntx_mont *c, uint32_t *r, const uint32_t *a, const uint32_t *b);
/* r = base^exp mod m as len_out big-endian bytes (len_out >= bytes of m), base_len <= 4n.
 * Left-to-right square-and-multiply: the exponent must be PUBLIC. */
void ntx_mont_exp(const ntx_mont *c, uint8_t *r, size_t len_out,
                  const uint8_t *base, size_t base_len,
                  const uint8_t *exp, size_t exp_len);
/* Same result as ntx_mont_exp, for a SECRET exponent: square-and-always-multiply with a
 * masked select; no branch or memory index depends on the exponent bits (only on exp_len).
 * Wipes its temporaries. */
void ntx_mont_exp_ct(const ntx_mont *c, uint8_t *r, size_t len_out,
                     const uint8_t *base, size_t base_len,
                     const uint8_t *exp, size_t exp_len);
/* big-endian bytes <-> n little-endian limbs (zero padded / must fit). */
void ntx_mont_from_be(const ntx_mont *c, uint32_t *limbs, const uint8_t *be, size_t len);
void ntx_mont_to_be(const ntx_mont *c, uint8_t *be, size_t len, const uint32_t *limbs);
#endif
