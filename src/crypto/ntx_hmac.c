#include "ntx_hmac.h"
#include "ntx_ct.h"
#include "ntx_sha1.h"
#include "ntx_sha256.h"
#include <string.h>

/* The key block is K (zero padded to 64 bytes) or H(K) for keys longer than 64 bytes. */

void ntx_hmac_sha1(const uint8_t *key, size_t klen, const void *msg, size_t n, uint8_t out[20]) {
    uint8_t k[64], pad[64], inner[20];
    memset(k, 0, sizeof k);
    if (klen > 64) ntx_sha1(key, klen, k); /* 20 bytes, rest stays zero */
    else if (klen) memcpy(k, key, klen);

    ntx_sha1_ctx c;
    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    ntx_sha1_init(&c);
    ntx_sha1_update(&c, pad, 64);
    ntx_sha1_update(&c, msg, n);
    ntx_sha1_final(&c, inner);
    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x5C);
    ntx_sha1_init(&c);
    ntx_sha1_update(&c, pad, 64);
    ntx_sha1_update(&c, inner, 20);
    ntx_sha1_final(&c, out);

    ntx_wipe(k, sizeof k);
    ntx_wipe(pad, sizeof pad);
    ntx_wipe(inner, sizeof inner);
    ntx_wipe(&c, sizeof c);
}

void ntx_hmac_sha256_init(ntx_hmac_sha256_ctx *c, const uint8_t *key, size_t klen) {
    uint8_t k[64], pad[64];
    memset(k, 0, sizeof k);
    if (klen > 64) ntx_sha256(key, klen, k); /* 32 bytes, rest stays zero */
    else if (klen) memcpy(k, key, klen);

    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x36);
    ntx_sha256_init(&c->in);
    ntx_sha256_update(&c->in, pad, 64);
    for (int i = 0; i < 64; i++) pad[i] = (uint8_t)(k[i] ^ 0x5C);
    ntx_sha256_init(&c->out);
    ntx_sha256_update(&c->out, pad, 64);

    ntx_wipe(k, sizeof k);
    ntx_wipe(pad, sizeof pad);
}

void ntx_hmac_sha256_update(ntx_hmac_sha256_ctx *c, const void *msg, size_t n) {
    ntx_sha256_update(&c->in, msg, n);
}

void ntx_hmac_sha256_final(ntx_hmac_sha256_ctx *c, uint8_t out[32]) {
    uint8_t inner[32];
    ntx_sha256_final(&c->in, inner);
    ntx_sha256_update(&c->out, inner, 32);
    ntx_sha256_final(&c->out, out);
    ntx_wipe(inner, sizeof inner);
    ntx_wipe(c, sizeof *c);
}

void ntx_hmac_sha256(const uint8_t *key, size_t klen, const void *msg, size_t n, uint8_t out[32]) {
    ntx_hmac_sha256_ctx c;
    ntx_hmac_sha256_init(&c, key, klen);
    ntx_hmac_sha256_update(&c, msg, n);
    ntx_hmac_sha256_final(&c, out);
}
