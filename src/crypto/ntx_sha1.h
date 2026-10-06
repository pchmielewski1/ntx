#ifndef NTX_SHA1_H
#define NTX_SHA1_H
#include <stdint.h>
#include <stddef.h>

typedef struct { uint32_t h[5]; uint64_t n; uint8_t buf[64]; size_t bufn; } ntx_sha1_ctx;

void ntx_sha1_init(ntx_sha1_ctx *c);
void ntx_sha1_update(ntx_sha1_ctx *c, const void *p, size_t n);
void ntx_sha1_final(ntx_sha1_ctx *c, uint8_t out[20]);
void ntx_sha1(const void *p, size_t n, uint8_t out[20]);

#endif
