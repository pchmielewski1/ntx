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
    uint8_t out[32], exp[32];

    uint8_t key0b[20];
    for (int i = 0; i < 20; i++) key0b[i] = 0x0b;
    ntx_hmac_sha256(key0b, 20, "Hi There", strlen("Hi There"), out);
    hex_to_bytes("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", exp, 32);
    check("hmac256-1", out, exp, 32);

    ntx_hmac_sha256((const uint8_t *)"Jefe", 4, "what do ya want for nothing?", strlen("what do ya want for nothing?"), out);
    hex_to_bytes("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", exp, 32);
    check("hmac256-2", out, exp, 32);

    uint8_t keyaa[20];
    for (int i = 0; i < 20; i++) keyaa[i] = 0xaa;
    uint8_t msgdd[50];
    for (int i = 0; i < 50; i++) msgdd[i] = 0xdd;
    ntx_hmac_sha256(keyaa, 20, msgdd, 50, out);
    hex_to_bytes("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe", exp, 32);
    check("hmac256-3", out, exp, 32);

    uint8_t key0c[50];
    for (int i = 0; i < 50; i++) key0c[i] = 0x0c;
    ntx_hmac_sha256(key0c, 50, "Test Using Truncation", strlen("Test Using Truncation"), out);
    hex_to_bytes("b6ef5a5dea46a5258c4179c7139708b0edc97770058df5dc465b704821af36f8", exp, 32);
    check("hmac256-4", out, exp, 32);

    uint8_t keyaa80[80];
    for (int i = 0; i < 80; i++) keyaa80[i] = 0xaa;
    const char *m5 = "Test Using Larger Than Block-Size Key - Hash Key First";
    ntx_hmac_sha256(keyaa80, 80, m5, strlen(m5), out);
    hex_to_bytes("6953025ed96f0c09f80a96f78e6538dbe2e7b820e3dd970e7ddd39091b32352f", exp, 32);
    check("hmac256-5", out, exp, 32);

    uint8_t key131[131];
    for (int i = 0; i < 131; i++) key131[i] = (uint8_t)(i % 25) + 1;
    const char *m6 = "Test Using Larger Than Block-Size Key And Data Larger Than Block-Size";
    ntx_hmac_sha256(key131, 131, m6, strlen(m6), out);
    hex_to_bytes("1762a3cbc1726349611aaba8ce065f40b781a35a943186a30b5ad78238bb8573", exp, 32);
    check("hmac256-6", out, exp, 32);

    return 0;
}
