#ifndef NTX_RSA_PKCS1_H
#define NTX_RSA_PKCS1_H

#include <stddef.h>
#include <stdint.h>

/*
 * RSA PKCS#1 v1.5 signature verification with SHA-256.
 *
 * n, e, sig are big-endian unsigned integers (MSB first).
 * n_len must equal sig_len (modulus byte length, e.g. 256 for RSA-2048).
 * e_len is typically 3 (0x01 0x00 0x01 = 65537).
 * digest is the 32-byte SHA-256 hash of the signed message.
 *
 * Returns 1 if the signature is a valid EMSA-PKCS1-v1_5 encoding of
 * DigestInfo(SHA-256, digest), else 0.
 */
int ntx_rsa_pkcs1_verify_sha256(const uint8_t *n, size_t n_len,
                                const uint8_t *e, size_t e_len,
                                const uint8_t *sig, size_t sig_len,
                                const uint8_t digest[32]);

/*
 * RSASSA-PSS verification (RFC 8017 sec. 8.1.2 / 9.1.2) with SHA-256, MGF1-SHA256
 * and a 32-byte salt - the parameters TLS 1.3 mandates for rsa_pss_rsae_sha256
 * (RFC 8446 sec. 4.2.3). mhash is SHA-256 of the signed message.
 * Same conventions as the PKCS#1 verifier above. Returns 1 if valid, else 0.
 */
int ntx_rsa_pss_verify_sha256(const uint8_t *n, size_t n_len,
                              const uint8_t *e, size_t e_len,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t mhash[32]);

#endif
