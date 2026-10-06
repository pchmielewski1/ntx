#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
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
    uint8_t out[20], exp[20];
    uint8_t key0b[20];
    for (int i = 0; i < 20; i++) key0b[i] = 0x0b;
    ntx_hmac_sha1(key0b, 20, "Hi There", strlen("Hi There"), out);
    hex_to_bytes("b617318655057264e28bc0b6fb378c8ef146be00", exp, 20);
    check("hmac-1", out, exp, 20);

    ntx_hmac_sha1((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", strlen("what do ya want for nothing?"), out);
    hex_to_bytes("effcdf6ae5eb2fa2d27416d5f184df9c259a7c79", exp, 20);
    check("hmac-2", out, exp, 20);

    uint8_t keyaa[20];
    for (int i = 0; i < 20; i++) keyaa[i] = 0xaa;
    uint8_t msgdd[50];
    for (int i = 0; i < 50; i++) msgdd[i] = 0xdd;
    ntx_hmac_sha1(keyaa, 20, msgdd, 50, out);
    hex_to_bytes("125d7342b9ac11cd91a39af48aa17b4f63f175d3", exp, 20);
    check("hmac-3", out, exp, 20);

    uint8_t key0c[20];
    for (int i = 0; i < 20; i++) key0c[i] = 0x0c;
    ntx_hmac_sha1(key0c, 20, "Test With Truncation", strlen("Test With Truncation"), out);
    hex_to_bytes("4c1a03424b55e07fe7f27be1d58bb9324a9a5a04", exp, 20);
    check("hmac-4", out, exp, 20);

    uint8_t keyaa80[80];
    for (int i = 0; i < 80; i++) keyaa80[i] = 0xaa;
    const char *m5 = "Test Using Larger Than Block-Size Key - Hash Key First";
    ntx_hmac_sha1(keyaa80, 80, m5, strlen(m5), out);
    hex_to_bytes("aa4ae5e15272d00e95705637ce8a3b55ed402112", exp, 20);
    check("hmac-5", out, exp, 20);

    return 0;
}
