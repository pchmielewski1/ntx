/* R3/R8: known-answer + cross-check tests for the constant-time DH modexp.
 * Vectors come from test/scripts/dh_kat.py (Python pow(), independent code);
 * the generic ntx_bn_modexp serves as a second, in-tree reference. */
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *what, int line) {
    fprintf(stderr, "FAIL %s (vector line %d)\n", what, line);
    return 1;
}

static int test_vectors(void) {
    FILE *f = fopen("test/vectors/dh/kat.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open test/vectors/dh/kat.txt (run from repo root)\n"); return 1; }
    char line[1024];
    int n = 0, ln = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        char e_hex[64], b_hex[256], r_hex[256];
        if (sscanf(line, "%63s %255s %255s", e_hex, b_hex, r_hex) != 3) { fclose(f); return fail("parse", ln); }
        uint8_t e[20], b[NTX_DH_KEY_LEN], want[NTX_DH_KEY_LEN], got[NTX_DH_KEY_LEN], ref[NTX_DH_KEY_LEN];
        hex_to_bytes(e_hex, e, sizeof e);
        hex_to_bytes(b_hex, b, sizeof b);
        hex_to_bytes(r_hex, want, sizeof want);
        umodexp(got, b, e, sizeof e);
        if (memcmp(got, want, sizeof got) != 0) { fclose(f); return fail("python-kat", ln); }
        /* second reference: generic bignum modexp (~0.4 s per call, so sampled) */
        if (n % 10 == 0) {
            ntx_bn_modexp(ref, NTX_DH_KEY_LEN, b, e, sizeof e, ntx_dh_prime);
            if (memcmp(got, ref, sizeof got) != 0) { fclose(f); return fail("bn_modexp-crosscheck", ln); }
        }
        n++;
    }
    fclose(f);
    if (n < 50) { fprintf(stderr, "FAIL too few vectors (%d)\n", n); return 1; }
    printf("PASS dh-kat (%d vectors)\n", n);
    return 0;
}

static int test_exchange(void) {
    /* Two parties, real ntx_dh API: both sides must derive the same secret. */
    for (int round = 0; round < 8; round++) {
        ntx_dh a, b;
        ntx_dh_init(&a);
        ntx_dh_init(&b);
        if (ntx_dh_compute_secret(&a, b.local_key) != 0 || ntx_dh_compute_secret(&b, a.local_key) != 0)
            return fail("exchange-compute", round);
        if (memcmp(a.shared_secret, b.shared_secret, NTX_DH_KEY_LEN) != 0) return fail("exchange-equal", round);
    }
    printf("PASS dh-exchange\n");
    return 0;
}

static int all_zero(const uint8_t *p, size_t n) {
    uint8_t acc = 0;
    for (size_t i = 0; i < n; i++) acc |= p[i];
    return acc == 0;
}

static int test_rejects_bad_peer_keys(void) {
    uint8_t bad[5][NTX_DH_KEY_LEN];
    memset(bad[0], 0, NTX_DH_KEY_LEN);                          /* 0 */
    memset(bad[1], 0, NTX_DH_KEY_LEN);
    bad[1][NTX_DH_KEY_LEN - 1] = 1;                             /* 1 */
    memcpy(bad[2], ntx_dh_prime, NTX_DH_KEY_LEN);               /* p */
    memcpy(bad[3], ntx_dh_prime, NTX_DH_KEY_LEN);
    bad[3][NTX_DH_KEY_LEN - 1]--;                               /* p-1 */
    memset(bad[4], 0xff, NTX_DH_KEY_LEN);                       /* > p */
    for (int i = 0; i < 5; i++) {
        ntx_dh a;                                               /* a fresh object per key */
        ntx_dh_init(&a);
        if (ntx_dh_compute_secret(&a, bad[i]) == 0) return fail("reject-bad-key", i);
    }
    printf("PASS dh-reject-bad-keys\n");
    return 0;
}

/* The secret exponent must not outlive its use, and a spent object must fail closed. */
static int test_secret_lifecycle(void) {
    ntx_dh a, b;
    ntx_dh_init(&a);
    ntx_dh_init(&b);
    if (all_zero(a.local_secret, sizeof a.local_secret)) return fail("secret-init-nonzero", 0);
    if (ntx_dh_compute_secret(&a, b.local_key) != 0) return fail("secret-compute", 0);
    if (!all_zero(a.local_secret, sizeof a.local_secret)) return fail("secret-wiped-after-compute", 0);
    if (all_zero(a.shared_secret, NTX_DH_KEY_LEN)) return fail("shared-set", 0);

    uint8_t before[NTX_DH_KEY_LEN];
    memcpy(before, a.shared_secret, sizeof before);
    ntx_dh c;
    ntx_dh_init(&c);
    if (ntx_dh_compute_secret(&a, c.local_key) == 0) return fail("second-compute-accepted", 0);
    if (memcmp(before, a.shared_secret, sizeof before) != 0) return fail("second-compute-clobbered-shared", 0);

    uint8_t key_before[NTX_DH_KEY_LEN];
    memcpy(key_before, a.local_key, sizeof key_before);
    ntx_dh_scrub(&a);
    if (!all_zero(a.shared_secret, NTX_DH_KEY_LEN)) return fail("scrub-shared", 0);
    if (!all_zero(a.local_secret, sizeof a.local_secret)) return fail("scrub-secret", 0);
    if (memcmp(key_before, a.local_key, sizeof key_before) != 0) return fail("scrub-kept-public-key", 0);

    /* an invalid peer key kills the object: secret gone, later (valid) keys refused */
    ntx_dh d;
    ntx_dh_init(&d);
    uint8_t zero[NTX_DH_KEY_LEN];
    memset(zero, 0, sizeof zero);
    if (ntx_dh_compute_secret(&d, zero) == 0) return fail("invalid-accepted", 0);
    if (!all_zero(d.local_secret, sizeof d.local_secret)) return fail("secret-wiped-after-invalid", 0);
    if (ntx_dh_compute_secret(&d, b.local_key) == 0) return fail("dead-object-accepted", 0);
    printf("PASS dh-secret-lifecycle\n");
    return 0;
}

int main(void) {
    if (test_vectors()) return 1;
    if (test_exchange()) return 1;
    if (test_rejects_bad_peer_keys()) return 1;
    if (test_secret_lifecycle()) return 1;
    return 0;
}
