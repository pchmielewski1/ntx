/* Known-answer tests for ntx_bn_mod / ntx_bn_mulmod / ntx_bn_modexp and the Montgomery
 * core (ntx_mont_exp / ntx_mont_exp_ct).
 * Vectors: test/scripts/bignum_vectors.py (Python big integers). Covers odd moduli,
 * leading-zero moduli, operands >= modulus, exponent 0, real P-256 p/n and a 4096-bit
 * modulus, and the moduli the core must refuse (even, 0, 1, 2 -> all-zero result). */
#include "../src/crypto/ntx_bignum.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what, int line) {
    fprintf(stderr, "FAIL %s (vector line %d)\n", what, line);
    return 1;
}

int main(void) {
    FILE *f = fopen("test/vectors/bignum/vectors.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open test/vectors/bignum/vectors.txt (run from repo root)\n"); return 1; }
    static char line[8192];
    int ln = 0, nmodexp = 0, nmulmod = 0, nmod = 0, nreject = 0, nct = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        char op[16];
        static char s1[2048], s2[2048], s3[2048], s4[2048];
        unsigned nb;
        uint8_t a[NTX_BN_MAX], b[NTX_BN_MAX], m[NTX_BN_MAX], want[NTX_BN_MAX], got[NTX_BN_MAX];
        if (sscanf(line, "%15s %u", op, &nb) != 2 || nb == 0 || nb > NTX_BN_MAX) { fclose(f); return fail("parse", ln); }
        if (strcmp(op, "modexp") == 0) {
            if (sscanf(line, "%*s %*u %2047s %2047s %2047s %2047s", s1, s2, s3, s4) != 4) { fclose(f); return fail("parse", ln); }
            size_t elen = strlen(s2) / 2;
            uint8_t e[NTX_BN_MAX];
            hex_to_bytes(s1, a, nb); hex_to_bytes(s2, e, elen); hex_to_bytes(s3, m, nb); hex_to_bytes(s4, want, nb);
            ntx_bn_modexp(got, nb, a, e, elen, m);
            if (memcmp(got, want, nb) != 0) { fclose(f); return fail("modexp", ln); }
            nmodexp++;
            /* the secret-exponent ladder must agree with the public one */
            ntx_mont c;
            if (ntx_mont_init(&c, m, nb) != 0) { fclose(f); return fail("mont-init", ln); }
            memset(got, 0xA5, sizeof got);
            ntx_mont_exp_ct(&c, got, nb, a, nb, e, elen);
            if (memcmp(got, want, nb) != 0) { fclose(f); return fail("modexp-ct", ln); }
            nct++;
        } else if (strcmp(op, "mulmod") == 0) {
            if (sscanf(line, "%*s %*u %2047s %2047s %2047s %2047s", s1, s2, s3, s4) != 4) { fclose(f); return fail("parse", ln); }
            hex_to_bytes(s1, a, nb); hex_to_bytes(s2, b, nb); hex_to_bytes(s3, m, nb); hex_to_bytes(s4, want, nb);
            ntx_bn_mulmod(got, nb, a, b, m);
            if (memcmp(got, want, nb) != 0) { fclose(f); return fail("mulmod", ln); }
            /* r may alias an operand */
            memcpy(got, a, nb);
            ntx_bn_mulmod(got, nb, got, b, m);
            if (memcmp(got, want, nb) != 0) { fclose(f); return fail("mulmod-alias", ln); }
            nmulmod++;
        } else if (strcmp(op, "mod") == 0) {
            if (sscanf(line, "%*s %*u %2047s %2047s %2047s", s1, s2, s3) != 3) { fclose(f); return fail("parse", ln); }
            hex_to_bytes(s1, a, nb); hex_to_bytes(s2, m, nb); hex_to_bytes(s3, want, nb);
            ntx_bn_mod(got, nb, a, m);
            if (memcmp(got, want, nb) != 0) { fclose(f); return fail("mod", ln); }
            memcpy(got, a, nb);
            ntx_bn_mod(got, nb, got, m);
            if (memcmp(got, want, nb) != 0) { fclose(f); return fail("mod-alias", ln); }
            nmod++;
        } else if (strcmp(op, "reject") == 0) {
            if (sscanf(line, "%*s %*u %2047s", s1) != 1) { fclose(f); return fail("parse", ln); }
            hex_to_bytes(s1, m, nb);
            memset(a, 0x5A, nb);
            memset(b, 0x3C, nb);
            uint8_t zero[NTX_BN_MAX], e1[1] = { 3 };
            memset(zero, 0, nb);
            memset(got, 0xA5, nb);
            ntx_bn_mod(got, nb, a, m);
            if (memcmp(got, zero, nb) != 0) { fclose(f); return fail("reject-mod", ln); }
            memset(got, 0xA5, nb);
            ntx_bn_mulmod(got, nb, a, b, m);
            if (memcmp(got, zero, nb) != 0) { fclose(f); return fail("reject-mulmod", ln); }
            memset(got, 0xA5, nb);
            ntx_bn_modexp(got, nb, a, e1, 1, m);
            if (memcmp(got, zero, nb) != 0) { fclose(f); return fail("reject-modexp", ln); }
            nreject++;
        } else {
            fclose(f);
            return fail("unknown op", ln);
        }
    }
    fclose(f);
    if (nmodexp < 50 || nmulmod < 50 || nmod < 30 || nreject < 8 || nct != nmodexp) {
        fprintf(stderr, "FAIL too few vectors (%d/%d/%d/%d/%d)\n", nmodexp, nmulmod, nmod, nreject, nct);
        return 1;
    }
    printf("PASS bignum-kat (modexp=%d mulmod=%d mod=%d reject=%d ct=%d)\n", nmodexp, nmulmod, nmod, nreject, nct);
    return 0;
}
