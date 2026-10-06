#ifndef NTX_AES_H
#define NTX_AES_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint8_t rk[176];
    uint8_t ctr[16];
    uint8_t ks[16];
    int left;
} ntx_aes128_ctr;

void ntx_aes128_ctr_init(ntx_aes128_ctr *c, const uint8_t key[16], const uint8_t ctr0[16]);
void ntx_aes128_ctr_xcrypt(ntx_aes128_ctr *c, uint8_t *buf, size_t n);

typedef struct { uint8_t rk[176]; uint8_t h[16]; } ntx_aes128_gcm;

void ntx_aes128_gcm_init(ntx_aes128_gcm *g, const uint8_t key[16]);
/* NONCE CONTRACT: a (key, nonce) pair must NEVER be used for two different
 * plaintexts - reuse breaks both confidentiality and authenticity. Uniqueness is
 * the caller's job: derive the nonce from a per-key counter that is consumed
 * before use and is never allowed to wrap (see rec_send in ntx_tls_rec.c, and
 * the TLS 1.3 record code in ntx_tls13.c). Return values: seal/open return 1 on
 * success and 0 on failure (open: authentication failure).
 * open verifies the tag BEFORE decrypting and writes nothing to pt on failure.
 * In-place operation (ct == pt) is allowed. n is limited to 2^36-32 bytes.
 * Side channels: MixColumns and GHASH are constant-time; the S-box is a 256-byte
 * table, so AES is NOT cache-timing safe against a co-resident attacker. */
int  ntx_aes128_gcm_seal(const ntx_aes128_gcm *g, const uint8_t nonce[12],
                         const uint8_t *aad, size_t aadn,
                         const uint8_t *pt, size_t n,
                         uint8_t *ct, uint8_t tag[16]);
int  ntx_aes128_gcm_open(const ntx_aes128_gcm *g, const uint8_t nonce[12],
                         const uint8_t *aad, size_t aadn,
                         const uint8_t *ct, size_t n,
                         uint8_t *pt, const uint8_t tag[16]);

#endif
