#ifndef NTX_SHA256_H
#define NTX_SHA256_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t h[8]; uint64_t n; uint8_t buf[64]; size_t bufn; } ntx_sha256_ctx;

void ntx_sha256_init(ntx_sha256_ctx *c);
void ntx_sha256_update(ntx_sha256_ctx *c, const void *p, size_t n);
void ntx_sha256_final(ntx_sha256_ctx *c, uint8_t out[32]);
void ntx_sha256(const void *p, size_t n, uint8_t out[32]);

#endif
