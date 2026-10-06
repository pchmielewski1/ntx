#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/ui/ntx_diag.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int a = hex_nibble(hex[i * 2]);
        int b = hex_nibble(hex[i * 2 + 1]);
        if (a < 0 || b < 0) {
            fprintf(stderr, "bad hex\n");
            exit(1);
        }
        out[i] = (uint8_t)((a << 4) | b);
    }
}

int main(void) {
    uint8_t qx[32], qy[32], r[32], s[32], h[32], r2[32], s2[32];
    hex_to_bytes("f50b530908b6feb23ced7a7cb90a3c0bcad11c34517fce18e1b0b7f6a1143027", qx, 32);
    hex_to_bytes("31323a0b38319b91f90f758ab4fd1d6b255be008465e651926629dc7a333ce53", qy, 32);
    hex_to_bytes("79fce88d363589070fc2f65a1a844e33237e0be481e8dad1d196a024e9608a93", h, 32);
    hex_to_bytes("914d52011344b43cf280b169a35f31ac8b47a5f9b3e2bae709897974969e33ba", r, 32);
    hex_to_bytes("ec499be92f70d359c6671c06575979dee9b8ade36b23c648f26aab2f3c1dd35b", s, 32);

    if (!ntx_p256_ecdsa_verify_sha256(qx, qy, r, s, h)) {
        fprintf(stderr, "FAIL positive verify\n");
        return 1;
    }
    printf("PASS p256-ecdsa-verify\n");

    h[0] ^= 1;
    if (ntx_p256_ecdsa_verify_sha256(qx, qy, r, s, h)) {
        fprintf(stderr, "FAIL negative verify\n");
        return 1;
    }
    printf("PASS p256-ecdsa-verify-bad-hash\n");
    h[0] ^= 1;

    static const uint8_t der[] = {
        0x30, 0x46, 0x02, 0x21, 0x00, 0x91, 0x4d, 0x52, 0x01, 0x13, 0x44, 0xb4, 0x3c, 0xf2, 0x80, 0xb1,
        0x69, 0xa3, 0x5f, 0x31, 0xac, 0x8b, 0x47, 0xa5, 0xf9, 0xb3, 0xe2, 0xba, 0xe7, 0x09, 0x89, 0x79,
        0x74, 0x96, 0x9e, 0x33, 0xba, 0x02, 0x21, 0x00, 0xec, 0x49, 0x9b, 0xe9, 0x2f, 0x70, 0xd3, 0x59,
        0xc6, 0x67, 0x1c, 0x06, 0x57, 0x59, 0x79, 0xde, 0xe9, 0xb8, 0xad, 0xe3, 0x6b, 0x23, 0xc6, 0x48,
        0xf2, 0x6a, 0xab, 0x2f, 0x3c, 0x1d, 0xd3, 0x5b};
    if (ntx_p256_sig_from_der(der, sizeof der, r2, s2) != 0 || memcmp(r, r2, 32) || memcmp(s, s2, 32)) {
        fprintf(stderr, "FAIL sig der\n");
        return 1;
    }
    printf("PASS p256-sig-der\n");

    static const uint8_t spki[] = {
        0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0xf5, 0x0b, 0x53, 0x09, 0x08,
        0xb6, 0xfe, 0xb2, 0x3c, 0xed, 0x7a, 0x7c, 0xb9, 0x0a, 0x3c, 0x0b, 0xca, 0xd1, 0x1c, 0x34, 0x51,
        0x7f, 0xce, 0x18, 0xe1, 0xb0, 0xb7, 0xf6, 0xa1, 0x14, 0x30, 0x27, 0x31, 0x32, 0x3a, 0x0b, 0x38,
        0x31, 0x9b, 0x91, 0xf9, 0x0f, 0x75, 0x8a, 0xb4, 0xfd, 0x1d, 0x6b, 0x25, 0x5b, 0xe0, 0x08, 0x46,
        0x5e, 0x65, 0x19, 0x26, 0x62, 0x9d, 0xc7, 0xa3, 0x33, 0xce, 0x53};
    uint8_t qx2[32], qy2[32];
    if (ntx_p256_pubkey_from_spki(spki, sizeof spki, qx2, qy2) != 0 || memcmp(qx, qx2, 32) ||
        memcmp(qy, qy2, 32)) {
        fprintf(stderr, "FAIL spki\n");
        return 1;
    }
    printf("PASS p256-spki\n");

    /* R1: public keys must lie on the curve and be canonical. */
    if (!ntx_p256_point_on_curve(GX, GY) || !ntx_p256_point_on_curve(qx, qy)) {
        fprintf(stderr, "FAIL on-curve-positive\n");
        return 1;
    }
    uint8_t bad[32];
    memcpy(bad, GY, 32);
    bad[31] ^= 1; /* (Gx, Gy+-1): off the curve */
    uint8_t zero[32] = {0};
    if (ntx_p256_point_on_curve(GX, bad) || ntx_p256_point_on_curve(zero, zero) ||
        ntx_p256_point_on_curve(P, GY) /* x == p: not canonical */) {
        fprintf(stderr, "FAIL on-curve-negative\n");
        return 1;
    }
    /* A valid-looking signature must not verify under an off-curve key. */
    memcpy(bad, qy, 32);
    bad[31] ^= 1;
    if (ntx_p256_ecdsa_verify_sha256(qx, bad, r, s, h)) {
        fprintf(stderr, "FAIL verify-off-curve-key\n");
        return 1;
    }
    printf("PASS p256-on-curve\n");
    return 0;
}
