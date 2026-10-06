#ifndef NTX_X25519_FE_H
#define NTX_X25519_FE_H
#include <stdint.h>
/* Field element mod p = 2^255-19; 5×51-bit little-endian limbs in uint64_t. */
typedef struct { uint64_t v[5]; } ntx_fe;

void ntx_fe_from_bytes(ntx_fe *f, const uint8_t b[32]);
void ntx_fe_to_bytes(uint8_t b[32], const ntx_fe *f);
void ntx_fe_add(ntx_fe *r, const ntx_fe *a, const ntx_fe *b);
void ntx_fe_sub(ntx_fe *r, const ntx_fe *a, const ntx_fe *b);
void ntx_fe_mul(ntx_fe *r, const ntx_fe *a, const ntx_fe *b);
void ntx_fe_sq(ntx_fe *r, const ntx_fe *a);
void ntx_fe_inv(ntx_fe *r, const ntx_fe *a);
void ntx_fe_set_u64(ntx_fe *f, uint64_t x);
#endif
