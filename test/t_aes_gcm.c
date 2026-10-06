#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto/ntx_aes.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

static void check(const char *name, const uint8_t *got, const uint8_t *exp, size_t n) {
    if (memcmp(got, exp, n) != 0) {
        printf("FAIL %s", name);
        putchar(10);
        for (size_t k = 0; k < n; k++) printf("%02X ", got[k]);
        putchar(10);
        exit(1);
    }
    printf("PASS %s", name);
    putchar(10);
}

static void check_int(const char *name, int got, int exp) {
    if (got != exp) {
        printf("FAIL %s (got %d want %d)", name, got, exp);
        putchar(10);
        exit(1);
    }
    printf("PASS %s", name);
    putchar(10);
}

int main(void) {
    uint8_t key[16], nonce[12], aad[64], pt[64], ct[64], out[64], tag[16], exp[64];
    ntx_aes128_gcm g;

    hex_to_bytes("00000000000000000000000000000000", key, 16);
    hex_to_bytes("000000000000000000000000", nonce, 12);
    ntx_aes128_gcm_init(&g, key);
    hex_to_bytes("58e2fccefa7e3061367f1d57a4e7455a", exp, 16);
    ntx_aes128_gcm_seal(&g, nonce, NULL, 0, NULL, 0, NULL, tag);
    check("gcm1-nist-empty", tag, exp, 16);

    hex_to_bytes("00000000000000000000000000000000", pt, 16);
    ntx_aes128_gcm_seal(&g, nonce, NULL, 0, pt, 16, ct, tag);
    hex_to_bytes("0388dace60b6a392f328c2b971b2fe78", exp, 16);
    check("gcm2-nist-ct", ct, exp, 16);
    hex_to_bytes("ab6e47d42cec13bdf53a67b21257bddf", exp, 16);
    check("gcm2-nist-tag", tag, exp, 16);

    hex_to_bytes("feffe9928665731c4d9bbf12e44b09e8", key, 16);
    hex_to_bytes("cafebabefacedbaddecaf888", nonce, 12);
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", pt, 16);
    ntx_aes128_gcm_init(&g, key);
    ntx_aes128_gcm_seal(&g, nonce, NULL, 0, pt, 16, ct, tag);
    hex_to_bytes("77c7d6b894988813c3216a25e6ca960c", exp, 16);
    check("gcm3-nist-ct", ct, exp, 16);
    hex_to_bytes("306bfe5c03a4b37bad75481df921e575", exp, 16);
    check("gcm3-nist-tag", tag, exp, 16);

    hex_to_bytes("00000000000000000000000000000000", aad, 16);
    ntx_aes128_gcm_seal(&g, nonce, aad, 16, pt, 16, ct, tag);
    hex_to_bytes("77c7d6b894988813c3216a25e6ca960c", exp, 16);
    check("gcm4-nist-ct", ct, exp, 16);
    hex_to_bytes("350a21341eacd6f0015eb0a66dbcddaa", exp, 16);
    check("gcm4-nist-tag", tag, exp, 16);

    hex_to_bytes("feedfacedeadbeeffeedfacedeadbeefabaddad2feedfacedeadbeeffeedfacedeadbeefabaddad2feedfacedeadbeeffeedfacedeadbeefabaddad2", aad, 60);
    ntx_aes128_gcm_seal(&g, nonce, aad, 60, pt, 16, ct, tag);
    hex_to_bytes("77c7d6b894988813c3216a25e6ca960c", exp, 16);
    check("gcm5-nist-ct", ct, exp, 16);
    hex_to_bytes("636dd61ada48ad46aa2e87b2e30fa60b", exp, 16);
    check("gcm5-nist-tag", tag, exp, 16);

    hex_to_bytes("000102030405060708090a0b0c0d0e0f", pt, 16);
    ntx_aes128_gcm_seal(&g, nonce, NULL, 0, pt, 16, ct, tag);
    check_int("gcm6-open-valid", ntx_aes128_gcm_open(&g, nonce, NULL, 0, ct, 16, out, tag), 1);
    check("gcm6-open-plaintext", out, pt, 16);

    tag[0] = (uint8_t)(tag[0] ^ 0x01);
    check_int("gcm7-open-corrupt", ntx_aes128_gcm_open(&g, nonce, NULL, 0, ct, 16, out, tag), 0);

    uint8_t m20[20], a5[5] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE};
    for (int i = 0; i < 20; i++) m20[i] = (uint8_t)(i * 7 + 3);
    ntx_aes128_gcm_seal(&g, nonce, a5, 5, m20, 20, ct, tag);
    check_int("gcm8-roundtrip-open", ntx_aes128_gcm_open(&g, nonce, a5, 5, ct, 20, out, tag), 1);
    check("gcm8-roundtrip-plaintext", out, m20, 20);

    return 0;
}
