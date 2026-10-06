#ifndef NTX_RC4_H
#define NTX_RC4_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint8_t S[256];
    uint8_t i, j;
    uint32_t disc;
    uint8_t invalid; /* set when init was given an unusable key */
} ntx_rc4;

/* Returns 0 on success, -1 for a NULL key or klen == 0. A context whose init
 * failed is poisoned: ntx_rc4_xor() then zeroes the buffer instead of
 * passing plaintext through. */
int ntx_rc4_init(ntx_rc4 *r, const uint8_t *key, uint16_t klen);
void ntx_rc4_xor(ntx_rc4 *r, uint8_t *buf, size_t n);
int ntx_rc4_init_bep9(ntx_rc4 *r, const uint8_t *key, uint16_t klen);

#endif
