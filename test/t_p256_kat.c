/* ECDSA P-256 verify + SPKI parsing against vectors made by OpenSSL via the
 * `cryptography` package (test/scripts/p256_vectors.py). Valid signatures (also in the
 * high-s form, which plain ECDSA accepts), tampered hashes/signatures, r/s out of range,
 * keys that are wrong, off-curve or non-canonical, and SPKI blobs with the wrong curve,
 * algorithm OID, point format, trailing bytes or unused bits. */
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(void) {
    FILE *f = fopen("test/vectors/p256/vectors.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open test/vectors/p256/vectors.txt (run from repo root)\n"); return 1; }
    static char line[1024];
    int ln = 0, nsig_ok = 0, nsig_bad = 0, nspki_ok = 0, nspki_bad = 0, failed = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        char op[8], a[512], b[512], c[512], d[512], e[512], label[64];
        int want;
        if (strncmp(line, "ecdsa ", 6) == 0) {
            if (sscanf(line, "%7s %511s %511s %511s %511s %511s %d %63s", op, a, b, c, d, e, &want, label) != 8) {
                fprintf(stderr, "FAIL parse line %d\n", ln); failed = 1; break;
            }
            uint8_t qx[32], qy[32], h[32], r[32], s[32];
            hex_to_bytes(a, qx, 32); hex_to_bytes(b, qy, 32); hex_to_bytes(c, h, 32);
            hex_to_bytes(d, r, 32); hex_to_bytes(e, s, 32);
            int got = ntx_p256_ecdsa_verify_sha256(qx, qy, r, s, h);
            if (got != want) { fprintf(stderr, "FAIL ecdsa line %d (%s): got %d want %d\n", ln, label, got, want); failed = 1; }
            if (want) nsig_ok++; else nsig_bad++;
        } else if (strncmp(line, "spki ", 5) == 0) {
            if (sscanf(line, "%7s %511s %d %63s", op, a, &want, label) != 4) {
                fprintf(stderr, "FAIL parse line %d\n", ln); failed = 1; break;
            }
            size_t n = strlen(a) / 2;
            uint8_t der[256], qx[32], qy[32];
            hex_to_bytes(a, der, n);
            int got = ntx_p256_pubkey_from_spki(der, n, qx, qy) == 0;
            if (got != want) { fprintf(stderr, "FAIL spki line %d (%s): got %d want %d\n", ln, label, got, want); failed = 1; }
            if (want) nspki_ok++; else nspki_bad++;
        }
    }
    fclose(f);
    if (failed) return 1;
    if (nsig_ok < 40 || nsig_bad < 200 || nspki_ok < 1 || nspki_bad < 8) {
        fprintf(stderr, "FAIL too few vectors\n");
        return 1;
    }
    printf("PASS p256-kat (sig ok=%d bad=%d, spki ok=%d bad=%d)\n", nsig_ok, nsig_bad, nspki_ok, nspki_bad);
    return 0;
}
