#ifndef NTX_P256_H
#define NTX_P256_H

#include <stddef.h>
#include <stdint.h>

/* 1 iff (x,y) are canonical field elements (< p) satisfying y^2 = x^3 - 3x + b. */
int ntx_p256_point_on_curve(const uint8_t x[32], const uint8_t y[32]);

/* ECDSA P-256 (secp256r1) verify over SHA-256 digest. 1=ok, 0=bad.
 * Rejects public keys that are not on the curve. */
int ntx_p256_ecdsa_verify_sha256(const uint8_t qx[32], const uint8_t qy[32],
                                 const uint8_t r[32], const uint8_t s[32],
                                 const uint8_t hash[32]);

/* SPKI id-ecPublicKey + prime256v1 → X,Y. 0=ok, -1=fail. */
int ntx_p256_pubkey_from_spki(const uint8_t *spki, size_t spki_len,
                              uint8_t qx[32], uint8_t qy[32]);

/* ECDSA signature DER SEQUENCE { INTEGER r, INTEGER s }. 0=ok, -1=fail. */
int ntx_p256_sig_from_der(const uint8_t *der, size_t der_len,
                          uint8_t r[32], uint8_t s[32]);

#endif
