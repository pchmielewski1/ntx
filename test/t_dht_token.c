#include <stdio.h>
#include <string.h>

#include "../src/net/ntx_addr.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/proto/ntx_dht_token.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static void fill_secret(ntx_dht_token_ctx *c, uint8_t v) {
    for (int i = 0; i < 20; i++) c->secret[i] = v;
}

static int test_issue_deterministic(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u;
    uint8_t o1[8], o2[8];
    ntx_dht_token_issue(&c, &a, sec, o1);
    ntx_dht_token_issue(&c, &a, sec, o2);
    if (memcmp(o1, o2, 8) != 0) return fail("issue-deterministic");
    return 0;
}

static int test_issue_v4_vs_v6(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a4, a6;
    ntx_addr_set_v4(&a4, 0x01020304);
    uint8_t v6[16] = {0};
    v6[15] = 1;
    ntx_addr_set_v6(&a6, v6);
    uint32_t sec = 600u * 7u;
    uint8_t o4[8], o6[8];
    ntx_dht_token_issue(&c, &a4, sec, o4);
    ntx_dht_token_issue(&c, &a6, sec, o6);
    if (memcmp(o4, o6, 8) == 0) return fail("issue-v4-v6-differ");
    return 0;
}

static int test_issue_secret_change(void) {
    ntx_dht_token_ctx c1, c2;
    fill_secret(&c1, 0x42);
    fill_secret(&c2, 0x43);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u;
    uint8_t o1[8], o2[8];
    ntx_dht_token_issue(&c1, &a, sec, o1);
    ntx_dht_token_issue(&c2, &a, sec, o2);
    if (memcmp(o1, o2, 8) == 0) return fail("issue-secret-change");
    return 0;
}

static int test_issue_bucket_change(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint8_t o1[8], o2[8];
    ntx_dht_token_issue(&c, &a, 600u * 7u, o1);
    ntx_dht_token_issue(&c, &a, 600u * 8u, o2);
    if (memcmp(o1, o2, 8) == 0) return fail("issue-bucket-change");
    return 0;
}

static int test_init_smoke(void) {
    ntx_dht_token_ctx c1, c2;
    ntx_dht_token_init(&c1);
    ntx_dht_token_init(&c2);
    if (memcmp(c1.secret, c2.secret, 20) == 0) return fail("init-smoke-secrets");
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x0A000001);
    uint8_t o[8];
    ntx_dht_token_issue(&c1, &a, 1234567890u, o);
    return 0;
}

static int test_verify_current(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u;
    uint8_t tok[8];
    ntx_dht_token_issue(&c, &a, sec, tok);
    if (ntx_dht_token_verify(&c, &a, sec, tok) != 1) return fail("verify-current");
    return 0;
}

static int test_verify_prev_bucket(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u;
    uint8_t tok[8];
    ntx_dht_token_issue(&c, &a, sec, tok);
    if (ntx_dht_token_verify(&c, &a, sec + 600u, tok) != 1)
        return fail("verify-prev-bucket");
    return 0;
}

static int test_verify_two_buckets_back(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u;
    uint8_t tok[8];
    ntx_dht_token_issue(&c, &a, sec, tok);
    if (ntx_dht_token_verify(&c, &a, sec + 1200u, tok) != 0)
        return fail("verify-two-back");
    return 0;
}

static int test_verify_wrong_addr(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a4, a6;
    ntx_addr_set_v4(&a4, 0x01020304);
    uint8_t v6[16] = {0};
    v6[15] = 1;
    ntx_addr_set_v6(&a6, v6);
    uint32_t sec = 600u * 7u;
    uint8_t tok[8];
    ntx_dht_token_issue(&c, &a4, sec, tok);
    if (ntx_dht_token_verify(&c, &a6, sec, tok) != 0)
        return fail("verify-wrong-addr");
    return 0;
}

static int test_verify_wrong_secret(void) {
    ntx_dht_token_ctx c1, c2;
    fill_secret(&c1, 0x42);
    fill_secret(&c2, 0x43);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u;
    uint8_t tok[8];
    ntx_dht_token_issue(&c1, &a, sec, tok);
    if (ntx_dht_token_verify(&c2, &a, sec, tok) != 0)
        return fail("verify-wrong-secret");
    return 0;
}

static int test_verify_same_bucket(void) {
    ntx_dht_token_ctx c;
    fill_secret(&c, 0x42);
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    uint32_t sec = 600u * 7u + 300u;
    uint8_t tok[8];
    ntx_dht_token_issue(&c, &a, sec, tok);
    if (ntx_dht_token_verify(&c, &a, sec - 1u, tok) != 1)
        return fail("verify-same-bucket");
    return 0;
}

int main(void) {
    if (test_issue_deterministic() != 0) return 1;
    printf("PASS issue-deterministic\n");
    if (test_issue_v4_vs_v6() != 0) return 1;
    printf("PASS issue-v4-v6-differ\n");
    if (test_issue_secret_change() != 0) return 1;
    printf("PASS issue-secret-change\n");
    if (test_issue_bucket_change() != 0) return 1;
    printf("PASS issue-bucket-change\n");
    if (test_init_smoke() != 0) return 1;
    printf("PASS init-smoke\n");
    if (test_verify_current() != 0) return 1;
    printf("PASS verify-current\n");
    if (test_verify_prev_bucket() != 0) return 1;
    printf("PASS verify-prev-bucket\n");
    if (test_verify_two_buckets_back() != 0) return 1;
    printf("PASS verify-two-back\n");
    if (test_verify_wrong_addr() != 0) return 1;
    printf("PASS verify-wrong-addr\n");
    if (test_verify_wrong_secret() != 0) return 1;
    printf("PASS verify-wrong-secret\n");
    if (test_verify_same_bucket() != 0) return 1;
    printf("PASS verify-same-bucket\n");
    return 0;
}
