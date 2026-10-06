/* RSASSA-PSS (SHA-256, MGF1-SHA256, salt 32) verification, needed for TLS 1.3
 * rsa_pss_rsae_sha256 CertificateVerify. Vectors: test/scripts/rsa_pss_vectors.py. */
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("test/vectors/rsa_pss/vectors.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open vectors (run from repo root)\n"); return 1; }
    static char line[16384];
    int n_ok = 0, n_bad = 0, ln = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        static char nh[2048], eh[64], mh[128], sh[2048], label[64];
        int exp;
        if (sscanf(line, "%2047s %63s %127s %2047s %d %63s", nh, eh, mh, sh, &exp, label) != 6) {
            fprintf(stderr, "FAIL parse line %d\n", ln);
            return 1;
        }
        size_t nl = strlen(nh) / 2, el = strlen(eh) / 2, sl = strlen(sh) / 2;
        static uint8_t n[512], e[16], sig[512];
        uint8_t m[32];
        hex_to_bytes(nh, n, nl);
        hex_to_bytes(eh, e, el);
        hex_to_bytes(sh, sig, sl);
        hex_to_bytes(mh, m, 32);
        int got = ntx_rsa_pss_verify_sha256(n, nl, e, el, sig, sl, m);
        if (got != exp) {
            fprintf(stderr, "FAIL %s (line %d): got %d want %d\n", label, ln, got, exp);
            return 1;
        }
        if (exp) n_ok++; else n_bad++;
    }
    fclose(f);
    if (n_ok < 9 || n_bad < 12) { fprintf(stderr, "FAIL too few vectors (%d/%d)\n", n_ok, n_bad); return 1; }
    printf("PASS rsa-pss-verify (%d valid, %d invalid)\n", n_ok, n_bad);

    /* argument hygiene */
    uint8_t z[32] = {0};
    if (ntx_rsa_pss_verify_sha256(NULL, 256, z, 3, z, 256, z) != 0) { fprintf(stderr, "FAIL null\n"); return 1; }
    printf("PASS rsa-pss-args\n");
    return 0;
}
