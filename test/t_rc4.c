#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/crypto/ntx_rc4.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

static int load_file(const char *path, uint8_t *buf, size_t cap) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(buf, 1, cap, f);
    fclose(f);
    return (int)n;
}

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
    uint8_t key[32], pt[64], ct[64], exp[64];
    uint8_t ks[16];
    uint8_t ks1040[1040];
    ntx_rc4 r;

    assert(load_file("test/vectors/rc4/key1.bin", key, sizeof key) == 3);
    assert(load_file("test/vectors/rc4/pt1.bin", pt, sizeof pt) == 9);
    hex_to_bytes("BBF316E8D940AF0AD3", exp, 9);
    ntx_rc4_init(&r, key, 3);
    memcpy(ct, pt, 9);
    ntx_rc4_xor(&r, ct, 9);
    check("key1-pt1", ct, exp, 9);
    ntx_rc4_init(&r, key, 3);
    ntx_rc4_xor(&r, ct, 9);
    check("key1-pt1-roundtrip", ct, pt, 9);

    assert(load_file("test/vectors/rc4/key2.bin", key, sizeof key) == 4);
    assert(load_file("test/vectors/rc4/pt2.bin", pt, sizeof pt) == 5);
    hex_to_bytes("1021BF0420", exp, 5);
    ntx_rc4_init(&r, key, 4);
    memcpy(ct, pt, 5);
    ntx_rc4_xor(&r, ct, 5);
    check("key2-pt2", ct, exp, 5);
    ntx_rc4_init(&r, key, 4);
    ntx_rc4_xor(&r, ct, 5);
    check("key2-pt2-roundtrip", ct, pt, 5);

    assert(load_file("test/vectors/rc4/key3.bin", key, sizeof key) == 6);
    assert(load_file("test/vectors/rc4/pt3.bin", pt, sizeof pt) == 14);
    hex_to_bytes("45A01F645FC35B383552544B9BF5", exp, 14);
    ntx_rc4_init(&r, key, 6);
    memcpy(ct, pt, 14);
    ntx_rc4_xor(&r, ct, 14);
    check("key3-pt3", ct, exp, 14);
    ntx_rc4_init(&r, key, 6);
    ntx_rc4_xor(&r, ct, 14);
    check("key3-pt3-roundtrip", ct, pt, 14);

    assert(load_file("test/vectors/rc4/key4.bin", key, sizeof key) == 5);
    memset(ks, 0, sizeof ks);
    ntx_rc4_init(&r, key, 5);
    ntx_rc4_xor(&r, ks, 16);
    hex_to_bytes("B2396305F03DC027CCC3524A0A1118A8", exp, 16);
    check("key4-ks", ks, exp, 16);

    assert(load_file("test/vectors/rc4/key5.bin", key, sizeof key) == 16);
    memset(ks, 0, sizeof ks);
    ntx_rc4_init(&r, key, 16);
    ntx_rc4_xor(&r, ks, 16);
    hex_to_bytes("9AC7CC9A609D1EF7B2932899CDE41B97", exp, 16);
    check("key5-ks", ks, exp, 16);

    memset(ks1040, 0, sizeof ks1040);
    ntx_rc4_init(&r, key, 16);
    ntx_rc4_xor(&r, ks1040, 1040);
    hex_to_bytes("BDF0324E6083DCC6D3CEDD3CA8C53C16", exp, 16);
    check("key5-ks1024", ks1040 + 1024, exp, 16);

    memset(ks, 0, sizeof ks);
    ntx_rc4_init_bep9(&r, key, 16);
    ntx_rc4_xor(&r, ks, 16);
    hex_to_bytes("BDF0324E6083DCC6D3CEDD3CA8C53C16", exp, 16);
    check("key5-bep9-discard", ks, exp, 16);

    /* R6: zero-length / NULL key must be rejected (no division by zero) and the
     * poisoned context must not pass plaintext through. */
    {
        uint8_t data[8] = {1, 2, 3, 4, 5, 6, 7, 8};
        uint8_t zeros[8] = {0};
        if (ntx_rc4_init(&r, key, 0) != -1 || ntx_rc4_init_bep9(&r, key, 0) != -1 ||
            ntx_rc4_init(&r, NULL, 16) != -1) {
            printf("FAIL rc4-bad-key-rc\n");
            return 1;
        }
        ntx_rc4_xor(&r, data, sizeof data);
        check("rc4-bad-key-fails-closed", data, zeros, sizeof data);
        /* and a good re-init recovers the context */
        if (ntx_rc4_init(&r, key, 16) != 0) {
            printf("FAIL rc4-reinit\n");
            return 1;
        }
        printf("PASS rc4-reinit\n");
    }

    return 0;
}
