#ifndef NTX_HKDF_H
#define NTX_HKDF_H

#include <stdint.h>
#include <stddef.h>

/* PRK = HMAC-SHA256(salt, IKM); RFC 5869 §2.2. salt NULL/0 → 32×0x00. */
void ntx_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len, uint8_t out[32]);

/* HKDF-Expand(PRK, info, L): okm = T(1)||T(2)||... ; T(i) = HMAC(PRK, T(i-1) || info || i).
 * L is 1..NTX_HKDF_MAX_OKM (255 * HashLen, RFC 5869 sec. 2.3). No heap use; intermediate
 * blocks and the keyed state are wiped. Returns 0, or -1 for L = 0, L too large, or a NULL
 * prk / okm / (info with info_len != 0). */
#define NTX_HKDF_MAX_OKM (255u * 32u)
int ntx_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                    size_t L, uint8_t *okm);

#endif
