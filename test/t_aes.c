#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_sha1.c"
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

int main(void) {
    uint8_t key[16], ctr0[16], pt[64], ct[64], exp[64];
    ntx_aes128_ctr c;

    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("f0f1f2f3f4f5f6f7f8f9facb03060401", ctr0, 16);

    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", pt, 16);
    hex_to_bytes("20c3c9807bba2ba5e82603012a32af4a", exp, 16);
    ntx_aes128_ctr_init(&c, key, ctr0);
    memcpy(ct, pt, 16);
    ntx_aes128_ctr_xcrypt(&c, ct, 16);
    check("aes1-1block", ct, exp, 16);

    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", pt, 16);
    hex_to_bytes("ae2d8a571e03ac9c9eb76fac45af8e51", pt + 16, 16);
    hex_to_bytes("30c81c46a35ce411e5fbc1191a0a52ef", pt + 32, 16);
    hex_to_bytes("f69f2445df4f9b17ad2b417be66c3710", pt + 48, 16);
    hex_to_bytes("20c3c9807bba2ba5e82603012a32af4a", exp, 16);
    hex_to_bytes("b9c685b03147622b3f60e240bbe064c5", exp + 16, 16);
    hex_to_bytes("94647d69f1738fb750b42c9d0a0c7844", exp + 32, 16);
    hex_to_bytes("cc7498784938b3caf0ecf9c28c5654fe", exp + 48, 16);
    ntx_aes128_ctr_init(&c, key, ctr0);
    memcpy(ct, pt, 64);
    ntx_aes128_ctr_xcrypt(&c, ct, 64);
    check("aes1-4blocks", ct, exp, 64);

    ntx_aes128_ctr_init(&c, key, ctr0);
    memcpy(ct, pt, 64);
    ntx_aes128_ctr_xcrypt(&c, ct, 64);
    ntx_aes128_ctr_init(&c, key, ctr0);
    ntx_aes128_ctr_xcrypt(&c, ct, 64);
    check("aes1-roundtrip-64", ct, pt, 64);

    uint8_t m20[20], e20[20];
    for (int i = 0; i < 20; i++) m20[i] = (uint8_t)(i * 7 + 3);
    ntx_aes128_ctr_init(&c, key, ctr0);
    memcpy(e20, m20, 20);
    ntx_aes128_ctr_xcrypt(&c, e20, 20);
    ntx_aes128_ctr_init(&c, key, ctr0);
    ntx_aes128_ctr_xcrypt(&c, e20, 20);
    check("aes1-roundtrip-20", e20, m20, 20);

    return 0;
}
