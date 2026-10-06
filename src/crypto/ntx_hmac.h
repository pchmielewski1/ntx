#ifndef NTX_HMAC_H
#define NTX_HMAC_H

#include <stdint.h>
#include <stddef.h>
#include "ntx_sha256.h"

/* One-shot. key may be NULL only with klen == 0 (HMAC of the empty key). */
void ntx_hmac_sha1(const uint8_t *key, size_t klen, const void *msg, size_t n, uint8_t out[20]);
void ntx_hmac_sha256(const uint8_t *key, size_t klen, const void *msg, size_t n, uint8_t out[32]);

/* Incremental HMAC-SHA256. A keyed context can be copied (plain struct assignment) to
 * start many MACs under one key without redoing the key schedule - HKDF-Expand and the
 * TLS 1.2 PRF do exactly that. _final() wipes the context it is given. */
typedef struct {
    ntx_sha256_ctx in;  /* inner hash, already fed K ^ ipad */
    ntx_sha256_ctx out; /* outer hash, already fed K ^ opad */
} ntx_hmac_sha256_ctx;

void ntx_hmac_sha256_init(ntx_hmac_sha256_ctx *c, const uint8_t *key, size_t klen);
void ntx_hmac_sha256_update(ntx_hmac_sha256_ctx *c, const void *msg, size_t n);
void ntx_hmac_sha256_final(ntx_hmac_sha256_ctx *c, uint8_t out[32]);

#endif
