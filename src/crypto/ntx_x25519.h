#ifndef NTX_X25519_H
#define NTX_X25519_H

#include <stdint.h>

/* Returns 0 on success, -1 if the shared secret is all-zero (peer sent a
 * low-order point). On -1 callers MUST abort the key exchange. */
int ntx_x25519(uint8_t out[32], const uint8_t scalar[32], const uint8_t u[32]);
void ntx_x25519_base(uint8_t out[32], const uint8_t scalar[32]); /* u = 9 */

#endif
