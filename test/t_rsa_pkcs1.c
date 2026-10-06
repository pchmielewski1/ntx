#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *load_hex_file(const char *path, size_t expect_bytes)
{
    size_t n;
    uint8_t *raw = read_file(path, &n);
    /* Strip trailing whitespace/newlines from hex text. */
    while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r' || raw[n - 1] == ' '))
        n--;
    if (n != expect_bytes * 2) {
        fprintf(stderr, "bad hex len %s: got %zu want %zu\n", path, n, expect_bytes * 2);
        exit(1);
    }
    uint8_t *out = malloc(expect_bytes);
    if (!out)
        exit(1);
    /* Temporarily NUL-terminate for hex_to_bytes / ensure clean parse */
    {
        char *hex = malloc(n + 1);
        if (!hex)
            exit(1);
        memcpy(hex, raw, n);
        hex[n] = '\0';
        hex_to_bytes(hex, out, expect_bytes);
        free(hex);
    }
    free(raw);
    return out;
}

int main(void)
{
    const char *base = "test/vectors/rsa_pkcs1_sha256";
    char path[256];
    uint8_t *n, *e, *sig, *digest, *msg;
    size_t msg_len;
    uint8_t digest_calc[32];
    int ok;

    snprintf(path, sizeof path, "%s/n.hex", base);
    n = load_hex_file(path, 256);
    snprintf(path, sizeof path, "%s/e.hex", base);
    e = load_hex_file(path, 3);
    snprintf(path, sizeof path, "%s/sig.hex", base);
    sig = load_hex_file(path, 256);
    snprintf(path, sizeof path, "%s/digest.hex", base);
    digest = load_hex_file(path, 32);

    snprintf(path, sizeof path, "%s/msg.bin", base);
    msg = read_file(path, &msg_len);
    ntx_sha256(msg, msg_len, digest_calc);
    if (memcmp(digest_calc, digest, 32) != 0) {
        fprintf(stderr, "FAIL digest != SHA256(msg.bin)\n");
        return 1;
    }
    printf("PASS digest-matches-msg\n");

    ok = ntx_rsa_pkcs1_verify_sha256(n, 256, e, 3, sig, 256, digest);
    if (ok != 1) {
        fprintf(stderr, "FAIL positive verify (got %d)\n", ok);
        return 1;
    }
    printf("PASS rsa-pkcs1-verify\n");

    digest[0] ^= 1;
    ok = ntx_rsa_pkcs1_verify_sha256(n, 256, e, 3, sig, 256, digest);
    if (ok != 0) {
        fprintf(stderr, "FAIL negative verify (got %d)\n", ok);
        return 1;
    }
    printf("PASS rsa-pkcs1-verify-bad-digest\n");

    free(n);
    free(e);
    free(sig);
    free(digest);
    free(msg);
    return 0;
}
