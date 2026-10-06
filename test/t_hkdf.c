#include <assert.h>
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"

static int hexval(int c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bin(const char *hex, uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) {
        int hi = hexval((unsigned char)hex[2 * i]);
        int lo = hexval((unsigned char)hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 1;
}

static int load_expected_hex(const char *path, uint8_t *out, size_t n) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char buf[512];
    size_t got = fread(buf, 1, sizeof buf - 1, f);
    fclose(f);
    buf[got] = '\0';
    char hex[512];
    size_t hl = 0;
    for (size_t i = 0; i < got; i++) {
        char c = buf[i];
        if ((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))
            hex[hl++] = (char)tolower((unsigned char)c);
    }
    if (hl != 2 * n) return 0;
    return hex_to_bin(hex, out, n);
}

int main(void) {
    uint8_t ikm[22];
    for (int i = 0; i < 22; i++) ikm[i] = 0x0b;
    uint8_t salt13[13];
    for (int i = 0; i < 13; i++) salt13[i] = (uint8_t)i;

    uint8_t exp[32];
    assert(load_expected_hex("test/vectors/hkdf/extract1.expected", exp, 32));

    uint8_t prk[32];
    ntx_hkdf_extract(salt13, 13, ikm, 22, prk);
    if (memcmp(prk, exp, 32) != 0) {
        printf("FAIL rfc5869-case1-extract\n");
        for (int i = 0; i < 32; i++) printf("%02x", prk[i]);
        putchar(10);
        exit(1);
    }
    printf("PASS rfc5869-case1-extract\n");

    uint8_t prk_nosalt[32];
    ntx_hkdf_extract(NULL, 0, ikm, 22, prk_nosalt);
    assert(memcmp(prk_nosalt, prk, 32) != 0);
    printf("PASS empty-salt-differs\n");

    uint8_t prk2[32];
    ntx_hkdf_extract(salt13, 13, ikm, 22, prk2);
    assert(memcmp(prk2, prk, 32) == 0);
    printf("PASS determinism\n");

    /* HKDF-Expand, RFC 5869 A.1 case 1: salt=00..0c, info=f0..f9, L=42. */
    uint8_t info1[10] = {0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9};
    uint8_t okm42[42];
    assert(ntx_hkdf_expand(prk, info1, 10, 42, okm42) == 0);
    uint8_t exp42[42];
    assert(load_expected_hex("test/vectors/hkdf/expand1.expected", exp42, 42));
    if (memcmp(okm42, exp42, 42) != 0) {
        printf("FAIL rfc5869-case1-expand\n");
        for (int i = 0; i < 42; i++) printf("%02x", okm42[i]);
        putchar(10);
        exit(1);
    }
    printf("PASS rfc5869-case1-expand\n");

    uint8_t okm64[64];
    assert(ntx_hkdf_expand(prk, info1, 10, 64, okm64) == 0);
    uint8_t exp64[64];
    assert(load_expected_hex("test/vectors/hkdf/expand1_64.expected", exp64, 64));
    assert(memcmp(okm64, exp64, 64) == 0);
    printf("PASS rfc5869-case1-expand64\n");

    uint8_t scratch[100];
    assert(ntx_hkdf_expand(prk, info1, 10, 0, scratch) == -1);
    assert(ntx_hkdf_expand(prk, info1, 10, NTX_HKDF_MAX_OKM + 1, scratch) == -1);
    assert(ntx_hkdf_expand(prk, info1, 10, 100, scratch) == 0);
    printf("PASS expand-edges\n");

    uint8_t okm_null[32], okm_empty[32];
    assert(ntx_hkdf_expand(prk, NULL, 0, 32, okm_null) == 0);
    assert(ntx_hkdf_expand(prk, (const uint8_t *)"", 0, 32, okm_empty) == 0);
    assert(memcmp(okm_null, okm_empty, 32) == 0);
    uint8_t exp32[32];
    assert(load_expected_hex("test/vectors/hkdf/expand1_32noinfo.expected", exp32, 32));
    assert(memcmp(okm_null, exp32, 32) == 0);
    printf("PASS expand-null-info\n");

    assert(ntx_hkdf_expand(NULL, info1, 10, 32, scratch) == -1);
    printf("PASS expand-prk-null\n");

    return 0;
}
