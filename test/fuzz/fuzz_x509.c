/* Signature/DER parsers underpinning certificate verification (checklist
   poz. 6): PKCS#1 v1.5 + RSA-PSS verify (arbitrary n,e from input) and the
   ECDSA sig-DER / P-256 SPKI parsers. Layout: data[0]=mode, then payload. */
#include "../../src/crypto/ntx_bignum.c"
#include "../../src/crypto/ntx_sha256.c"
#include "../../src/crypto/ntx_rsa_pkcs1.c"
#include "../../src/crypto/ntx_p256.c"
#include "../../src/ui/ntx_diag.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    if (len < 2) return 0;
    uint8_t mode = data[0] & 3;
    const uint8_t *p = data + 1;
    size_t n = len - 1;
    static const uint8_t e3[3] = {0x01, 0x00, 0x01};
    if (mode == 0 || mode == 1) {
        if (n < 34) return 0;
        size_t half = (n - 32) / 2;
        if (half < 1 || half > 512 || n < 2 * half + 32) return 0;
        const uint8_t *mod = p, *sig = p + half, *dg = p + 2 * half;
        if (mode == 0) (void)ntx_rsa_pkcs1_verify_sha256(mod, half, e3, 3, sig, half, dg);
        else (void)ntx_rsa_pss_verify_sha256(mod, half, e3, 3, sig, half, dg);
        return 0;
    }
    if (mode == 2) {
        uint8_t r[32], s[32];
        (void)ntx_p256_sig_from_der(p, n, r, s);
        return 0;
    }
    uint8_t qx[32], qy[32];
    (void)ntx_p256_pubkey_from_spki(p, n, qx, qy);
    return 0;
}
