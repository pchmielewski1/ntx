#include "ntx_hkdf.h"
#include "ntx_ct.h"
#include "ntx_hmac.h"
#include <string.h>

void ntx_hkdf_extract(const uint8_t *salt, size_t salt_len,
                      const uint8_t *ikm, size_t ikm_len, uint8_t out[32]) {
    uint8_t zero[32];
    if (!salt || salt_len == 0) {
        memset(zero, 0, sizeof zero);
        salt = zero;
        salt_len = sizeof zero;
    }
    ntx_hmac_sha256(salt, salt_len, ikm, ikm_len, out);
}

int ntx_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len,
                    size_t L, uint8_t *okm) {
    if (!prk || !okm) return -1;
    if (L == 0 || L > NTX_HKDF_MAX_OKM) return -1;
    if (!info && info_len != 0) return -1;

    ntx_hmac_sha256_ctx base, c;
    ntx_hmac_sha256_init(&base, prk, 32); /* key schedule once, copied per block */
    uint8_t t[32];
    size_t tlen = 0, done = 0;
    for (unsigned i = 1; done < L; i++) {
        uint8_t ctr = (uint8_t)i;
        c = base;
        if (tlen) ntx_hmac_sha256_update(&c, t, tlen);
        if (info_len) ntx_hmac_sha256_update(&c, info, info_len);
        ntx_hmac_sha256_update(&c, &ctr, 1);
        ntx_hmac_sha256_final(&c, t);
        tlen = 32;
        size_t n = L - done < 32 ? L - done : 32;
        memcpy(okm + done, t, n);
        done += n;
    }
    ntx_wipe(t, sizeof t);
    ntx_wipe(&base, sizeof base);
    return 0;
}
