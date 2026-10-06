/* RSASSA-PKCS1-v1_5 / SHA-256 verification against OpenSSL-made vectors
 * (test/scripts/rsa_pkcs1_vectors.py): 1024..4096-bit keys, tampered digests and
 * signatures, signatures >= n, SHA-384 signatures, and degenerate keys (e = 0/1/2,
 * even modulus) for which the encoded message itself would "verify" arithmetically. */
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("test/vectors/rsa_pkcs1/vectors.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open test/vectors/rsa_pkcs1/vectors.txt (run from repo root)\n"); return 1; }
    static char line[4096], nh[1100], eh[1100], dh[100], sh[1100], label[64];
    int ln = 0, nok = 0, nbad = 0, failed = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        int want;
        if (sscanf(line, "%1099s %1099s %99s %1099s %d %63s", nh, eh, dh, sh, &want, label) != 6) {
            fprintf(stderr, "FAIL parse line %d\n", ln); failed = 1; break;
        }
        uint8_t n[NTX_BN_MAX], e[NTX_BN_MAX], sig[NTX_BN_MAX], dg[32];
        size_t nl = strlen(nh) / 2, el = strlen(eh) / 2, sl = strlen(sh) / 2;
        hex_to_bytes(nh, n, nl); hex_to_bytes(eh, e, el); hex_to_bytes(sh, sig, sl); hex_to_bytes(dh, dg, 32);
        int got = ntx_rsa_pkcs1_verify_sha256(n, nl, e, el, sig, sl, dg);
        if (got != want) { fprintf(stderr, "FAIL line %d (%s): got %d want %d\n", ln, label, got, want); failed = 1; }
        if (want) nok++; else nbad++;
    }
    fclose(f);
    if (failed) return 1;
    if (nok < 12 || nbad < 50) { fprintf(stderr, "FAIL too few vectors (%d/%d)\n", nok, nbad); return 1; }
    printf("PASS rsa-pkcs1-kat (ok=%d bad=%d)\n", nok, nbad);
    return 0;
}
