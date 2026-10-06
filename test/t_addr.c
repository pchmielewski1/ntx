#include <stdio.h>
#include <string.h>

#include <arpa/inet.h>

#include "../src/net/ntx_addr.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

int main(void) {
    ntx_addr a, b;

    ntx_addr_clear(&a);
    ntx_addr_set_v4(&a, htonl(0x7F000001u));
    ntx_addr_set_v4(&b, htonl(0x7F000001u));
    check(ntx_addr_is_v4(&a), "setv4-isv4");
    check(!ntx_addr_is_v6(&a), "setv4-notv6");
    check(ntx_addr_eq(&a, &b), "setv4-eq");
    ntx_addr_set_v4(&b, htonl(0x08080808u));
    check(!ntx_addr_eq(&a, &b), "setv4-neq");

    uint8_t v6a[16] = {0};
    uint8_t v6b[16] = {0};
    v6a[15] = 1;
    v6b[15] = 1;
    ntx_addr_set_v6(&a, v6a);
    ntx_addr_set_v6(&b, v6b);
    check(ntx_addr_is_v6(&a), "setv6-isv6");
    check(!ntx_addr_is_v4(&a), "setv6-notv4");
    check(ntx_addr_eq(&a, &b), "setv6-eq");
    v6b[0] = 1;
    ntx_addr_set_v6(&b, v6b);
    check(!ntx_addr_eq(&a, &b), "setv6-neq");

    char buf[64];
    ntx_addr_set_v4(&a, htonl(0x7F000001u));
    check(ntx_addr_ntop(&a, buf, sizeof buf) == 0 && strcmp(buf, "127.0.0.1") == 0,
          "ntop-v4");
    ntx_addr_set_v6(&a, v6a);
    check(ntx_addr_ntop(&a, buf, sizeof buf) == 0 && strcmp(buf, "::1") == 0, "ntop-v6");

    ntx_addr_set_v4(&a, 0u);
    check(ntx_addr_is_zero(&a), "iszero-v4");
    ntx_addr_set_v4(&a, htonl(0x01010101u));
    check(!ntx_addr_is_zero(&a), "iszero-v4-nonzero");
    uint8_t z6[16] = {0};
    ntx_addr_set_v6(&a, z6);
    check(ntx_addr_is_zero(&a), "iszero-v6");
    ntx_addr_set_v6(&a, v6a);
    check(!ntx_addr_is_zero(&a), "iszero-v6-nonzero");

    ntx_addr_set_v4(&a, htonl(0x7F000001u));
    ntx_addr_set_v6(&b, v6a);
    check(!ntx_addr_eq(&a, &b), "eq-cross-family");

    /* ntx_addr_is_special: addresses a remote peer / tracker must not be able to make us dial */
    {
        struct { const char *ip; int special; } v4[] = {
            {"0.0.0.0", 1}, {"0.1.2.3", 1}, {"127.0.0.1", 1}, {"127.255.255.254", 1},
            {"169.254.169.254", 1}, {"169.254.0.1", 1}, {"224.0.0.1", 1}, {"239.255.255.250", 1},
            {"240.0.0.1", 1}, {"255.255.255.255", 1},
            {"8.8.8.8", 0}, {"1.1.1.1", 0}, {"192.168.1.10", 0}, {"10.0.0.5", 0}, {"172.16.0.9", 0},
            {"100.64.0.1", 0}, {"169.253.0.1", 0}, {"223.255.255.255", 0},
        };
        for (size_t k = 0; k < sizeof v4 / sizeof v4[0]; k++) {
            struct in_addr ia;
            inet_pton(AF_INET, v4[k].ip, &ia);
            ntx_addr_set_v4(&a, ia.s_addr);
            char nm[64];
            snprintf(nm, sizeof nm, "special-v4-%s", v4[k].ip);
            check(ntx_addr_is_special(&a) == v4[k].special, nm);
        }
        struct { const char *ip; int special; } v6[] = {
            {"::", 1}, {"::1", 1}, {"fe80::1", 1}, {"febf::1", 1}, {"ff02::1", 1}, {"ff00::", 1},
            {"::ffff:127.0.0.1", 1}, {"::ffff:169.254.169.254", 1}, {"::ffff:0.0.0.0", 1},
            {"::127.0.0.1", 1},
            {"2001:4860:4860::8888", 0}, {"fc00::1", 0}, {"fd12:3456::1", 0}, {"::ffff:8.8.8.8", 0},
            {"fec0::1", 0},
        };
        for (size_t k = 0; k < sizeof v6 / sizeof v6[0]; k++) {
            uint8_t raw[16];
            inet_pton(AF_INET6, v6[k].ip, raw);
            ntx_addr_set_v6(&a, raw);
            char nm[64];
            snprintf(nm, sizeof nm, "special-v6-%s", v6[k].ip);
            check(ntx_addr_is_special(&a) == v6[k].special, nm);
        }
    }

    return fails ? 1 : 0;
}
