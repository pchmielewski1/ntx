#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_dht_xor.h"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static void fill20(uint8_t *buf, uint8_t v) {
    for (int i = 0; i < 20; i++) buf[i] = v;
}

static int test_xor_known(void) {
    uint8_t a[20], b[20], out[20], exp[20];
    fill20(a, 0xFF);
    fill20(b, 0x00);
    ntx_dht_xor(a, b, out);
    fill20(exp, 0xFF);
    if (memcmp(out, exp, 20) != 0) return fail("xor-known-ff00");
    fill20(a, 0x80);
    fill20(b, 0x7F);
    ntx_dht_xor(a, b, out);
    if (memcmp(out, exp, 20) != 0) return fail("xor-known-807f");
    for (int i = 0; i < 20; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)(i ^ 0xA5);
    }
    ntx_dht_xor(a, b, out);
    fill20(exp, 0xA5);
    if (memcmp(out, exp, 20) != 0) return fail("xor-known-mixed");
    return 0;
}

static int test_prefix_identical(void) {
    uint8_t a[20], b[20];
    for (int i = 0; i < 20; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }
    if (ntx_dht_prefix_len(a, b) != 20) return fail("prefix-identical");
    return 0;
}

static int test_prefix_diff_at_5(void) {
    uint8_t a[20], b[20];
    for (int i = 0; i < 20; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }
    b[5] = (uint8_t)(b[5] ^ 0x40);
    if (ntx_dht_prefix_len(a, b) != 5) return fail("prefix-diff-at-5");
    return 0;
}

static int test_prefix_diff_at_0(void) {
    uint8_t a[20], b[20];
    for (int i = 0; i < 20; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }
    b[0] = (uint8_t)(b[0] ^ 0x01);
    if (ntx_dht_prefix_len(a, b) != 0) return fail("prefix-diff-at-0");
    return 0;
}

static int test_prefix_diff_last(void) {
    uint8_t a[20], b[20];
    for (int i = 0; i < 20; i++) {
        a[i] = (uint8_t)i;
        b[i] = (uint8_t)i;
    }
    b[19] = (uint8_t)(b[19] ^ 0x01);
    if (ntx_dht_prefix_len(a, b) != 19) return fail("prefix-diff-last");
    return 0;
}

static int test_cmp_self_a(void) {
    uint8_t self[20], a[20], b[20];
    for (int i = 0; i < 20; i++) self[i] = (uint8_t)(0xC0 + i);
    memcpy(a, self, 20);
    a[0] = (uint8_t)(a[0] ^ 0x01);
    memcpy(b, self, 20);
    b[0] = (uint8_t)(b[0] ^ 0x02);
    if (ntx_dht_id_cmp_xor(a, b, self) >= 0) return fail("cmp-self-a");
    if (ntx_dht_id_cmp_xor(b, a, self) <= 0) return fail("cmp-self-a-rev");
    if (ntx_dht_id_cmp_xor(self, self, self) != 0) return fail("cmp-self-eq-self");
    if (ntx_dht_id_cmp_xor(a, a, self) != 0) return fail("cmp-self-eq-nonself");
    return 0;
}

static int test_cmp_prefix_wins(void) {
    uint8_t self[20], a[20], b[20];
    for (int i = 0; i < 20; i++) self[i] = (uint8_t)(0x10 + i);
    memcpy(a, self, 20);
    a[1] = (uint8_t)(a[1] ^ 0xFF);
    memcpy(b, self, 20);
    b[0] = (uint8_t)(b[0] ^ 0x01);
    if (ntx_dht_id_cmp_xor(a, b, self) >= 0) return fail("cmp-prefix-wins");
    return 0;
}

int main(void) {
    if (test_xor_known() != 0) return 1;
    printf("PASS xor-known\n");
    if (test_prefix_identical() != 0) return 1;
    printf("PASS prefix-identical\n");
    if (test_prefix_diff_at_5() != 0) return 1;
    printf("PASS prefix-diff-at-5\n");
    if (test_prefix_diff_at_0() != 0) return 1;
    printf("PASS prefix-diff-at-0\n");
    if (test_prefix_diff_last() != 0) return 1;
    printf("PASS prefix-diff-last\n");
    if (test_cmp_self_a() != 0) return 1;
    printf("PASS cmp-self-a\n");
    if (test_cmp_prefix_wins() != 0) return 1;
    printf("PASS cmp-prefix-wins\n");
    return 0;
}
