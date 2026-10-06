#ifndef NTX_RNG_H
#define NTX_RNG_H
#include <stdint.h>
#include <stddef.h>

int ntx_rng_init(void);
void ntx_rand_bytes(void *buf, size_t n);
uint32_t ntx_rand_u32(void);

#endif
