#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_bencode.c"
#include "../src/proto/ntx_pex.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static const uint8_t V4_A[4] = { 0x0a, 0x00, 0x00, 0x02 }; /* 10.0.0.2 */
static const uint8_t V6_A[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x07 }; /* 2001:db8::7 */
static const uint8_t V6_D[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x08 }; /* 2001:db8::8 */

/* d 5:added 6:<v4:6881> 6:added6 18:<v6a:6881> 8:dropped6 18:<v6d:6882> e */
static size_t build_payload_full(uint8_t *out) {
    uint8_t *p = out;
    *p++ = 'd';
    memcpy(p, "5:added", 7); p += 7;
    memcpy(p, "6:", 2); p += 2;
    memcpy(p, V4_A, 4); p += 4;
    p[0] = 0x1a; p[1] = 0xe1; p += 2; /* 6881 BE */
    memcpy(p, "6:added6", 8); p += 8;
    memcpy(p, "18:", 3); p += 3;
    memcpy(p, V6_A, 16); p += 16;
    p[0] = 0x1a; p[1] = 0xe1; p += 2; /* 6881 BE */
    memcpy(p, "8:dropped6", 10); p += 10;
    memcpy(p, "18:", 3); p += 3;
    memcpy(p, V6_D, 16); p += 16;
    p[0] = 0x1a; p[1] = 0xe2; p += 2; /* 6882 BE */
    *p++ = 'e';
    return (size_t)(p - out);
}

/* d 5:added 6:<v4:6881> 7:dropped 6:<v4b:6882> e */
static size_t build_payload_v4only(uint8_t *out) {
    uint8_t *p = out;
    *p++ = 'd';
    memcpy(p, "5:added", 7); p += 7;
    memcpy(p, "6:", 2); p += 2;
    memcpy(p, V4_A, 4); p += 4;
    p[0] = 0x1a; p[1] = 0xe1; p += 2; /* 6881 BE */
    memcpy(p, "7:dropped", 9); p += 9;
    memcpy(p, "6:", 2); p += 2;
    static const uint8_t v4b[4] = { 0x0a, 0x00, 0x00, 0x03 };
    memcpy(p, v4b, 4); p += 4;
    p[0] = 0x1a; p[1] = 0xe2; p += 2; /* 6882 BE */
    *p++ = 'e';
    return (size_t)(p - out);
}

/* d 6:added6 0: e */
static size_t build_payload_empty6(uint8_t *out) {
    uint8_t *p = out;
    *p++ = 'd';
    memcpy(p, "6:added6", 8); p += 8;
    memcpy(p, "0:", 2); p += 2;
    *p++ = 'e';
    return (size_t)(p - out);
}

/* d 6:added6 20:<v6a:6881 + 2 junk> e — incomplete trailing record must be skipped */
static size_t build_payload_short6(uint8_t *out) {
    uint8_t *p = out;
    *p++ = 'd';
    memcpy(p, "6:added6", 8); p += 8;
    memcpy(p, "20:", 3); p += 3;
    memcpy(p, V6_A, 16); p += 16;
    p[0] = 0x1a; p[1] = 0xe1; p += 2; /* 6881 BE */
    p[0] = 0xff; p[1] = 0xff; p += 2;
    *p++ = 'e';
    return (size_t)(p - out);
}

static int test_parse_ex_full(void) {
    uint8_t buf[256];
    size_t n = build_payload_full(buf);
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    uint8_t a6ip[4][16], d6ip[4][16];
    uint16_t a6port[4], d6port[4];
    int na6 = -1, nd6 = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 4) != 0) return fail("ex_parse");
    if (na != 1 || nd != 0) return fail("ex_v4_counts");
    if (na6 != 1 || nd6 != 1) return fail("ex_v6_counts");
    uint32_t exp4;
    memcpy(&exp4, V4_A, 4);
    if (aip[0] != exp4) return fail("ex_v4_ip");
    if (apt[0] != 6881) return fail("ex_v4_port");
    if (memcmp(a6ip[0], V6_A, 16) != 0) return fail("ex_v6_added_ip");
    if (a6port[0] != 6881) return fail("ex_v6_added_port");
    if (memcmp(d6ip[0], V6_D, 16) != 0) return fail("ex_v6_dropped_ip");
    if (d6port[0] != 6882) return fail("ex_v6_dropped_port");
    return 0;
}

static int test_parse_ex_no_v6(void) {
    uint8_t buf[256];
    size_t n = build_payload_v4only(buf);
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    uint8_t a6ip[4][16], d6ip[4][16];
    uint16_t a6port[4], d6port[4];
    int na6 = 99, nd6 = 99;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 4) != 0) return fail("ex_parse");
    if (na != 1 || nd != 1) return fail("ex_v4_counts");
    if (na6 != 0 || nd6 != 0) return fail("ex_v6_counts");
    uint32_t exp4;
    memcpy(&exp4, V4_A, 4);
    if (aip[0] != exp4 || apt[0] != 6881) return fail("ex_v4_added");
    if (dport[0] != 6882) return fail("ex_v4_dropped_port");
    /* legacy API on same payload: v4 behaviour unchanged */
    uint32_t aip2[4], dip2[4];
    uint16_t apt2[4], dport2[4];
    int na2 = -1, nd2 = -1;
    if (ntx_pex_parse(buf, n, aip2, apt2, &na2, dip2, dport2, &nd2, 4) != 0) return fail("legacy_parse");
    if (na2 != 1 || nd2 != 1) return fail("legacy_counts");
    if (aip2[0] != exp4 || apt2[0] != 6881) return fail("legacy_added");
    return 0;
}

static int test_parse_empty_added6(void) {
    uint8_t buf[64];
    size_t n = build_payload_empty6(buf);
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na, nd;
    uint8_t a6ip[4][16];
    uint16_t a6port[4];
    int na6 = 99;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, 0, 0, 0, 4) != 0) return fail("ex_parse");
    if (na != 0 || nd != 0) return fail("ex_v4_counts");
    if (na6 != 0) return fail("ex_v6_counts");
    return 0;
}

static int test_legacy_ignores_v6(void) {
    uint8_t buf[256];
    size_t n = build_payload_full(buf);
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    if (ntx_pex_parse(buf, n, aip, apt, &na, dip, dport, &nd, 4) != 0) return fail("legacy_parse");
    if (na != 1 || nd != 0) return fail("legacy_counts");
    return 0;
}

static int test_build_added_roundtrip(void) {
    uint8_t buf[64];
    size_t n = 0;
    uint32_t ip;
    memcpy(&ip, V4_A, 4);
    if (ntx_pex_build_added(buf, sizeof buf, &n, ip, 6881) != 0) return fail("build4");
    if (n != 17) return fail("build4_len");
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         0, 0, 0, 0, 0, 0, 0) != 0) return fail("rt_parse");
    if (na != 1 || nd != 0) return fail("rt_v4_counts");
    if (aip[0] != ip || apt[0] != 6881) return fail("rt_v4_vals");
    return 0;
}

static int test_build_added6_roundtrip(void) {
    uint8_t buf[64];
    size_t n = 0;
    if (ntx_pex_build_added6(buf, sizeof buf, &n, V6_A, 6881) != 0) return fail("build6");
    if (n != 31) return fail("build6_len");
    if (buf[0] != 'd' || buf[n - 1] != 'e') return fail("build6_dict");
    if (memcmp(buf + 1, "6:added6", 8) != 0) return fail("build6_key");
    if (memcmp(buf + 9, "18:", 3) != 0) return fail("build6_vallen");
    if (ntx_pex_build_added6(buf, 30, &n, V6_A, 6881) != -1) return fail("build6_cap");
    if (ntx_pex_build_added6(0, sizeof buf, &n, V6_A, 6881) != -1) return fail("build6_null");
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    uint8_t a6ip[4][16], d6ip[4][16];
    uint16_t a6port[4], d6port[4];
    int na6 = -1, nd6 = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 4) != 0) return fail("rt_parse");
    if (na != 0 || nd != 0) return fail("rt_v4_counts");
    if (na6 != 1 || nd6 != 0) return fail("rt_v6_counts");
    if (memcmp(a6ip[0], V6_A, 16) != 0) return fail("rt_v6_ip");
    if (a6port[0] != 6881) return fail("rt_v6_port");
    return 0;
}

static int contains(const uint8_t *buf, size_t n, const char *s) {
    size_t slen = strlen(s);
    if (slen > n) return 0;
    for (size_t i = 0; i + slen <= n; i++)
        if (memcmp(buf + i, s, slen) == 0) return 1;
    return 0;
}

/* merge two single-key dicts: d <inner_a> e + d <inner_b> e -> d <inner_a><inner_b> e */
static size_t merge_dicts(const uint8_t *a, size_t an, const uint8_t *b, size_t bn, uint8_t *out) {
    out[0] = 'd';
    memcpy(out + 1, a + 1, an - 2);
    memcpy(out + 1 + (an - 2), b + 1, bn - 2);
    out[1 + (an - 2) + (bn - 2)] = 'e';
    return 1 + (an - 2) + (bn - 2) + 1;
}

static int test_build_mixed(void) {
    uint8_t v4[64], v6[64], mix[128];
    size_t n4 = 0, n6 = 0;
    uint32_t ip;
    memcpy(&ip, V4_A, 4);
    if (ntx_pex_build_added(v4, sizeof v4, &n4, ip, 6881) != 0) return fail("build4");
    if (ntx_pex_build_added6(v6, sizeof v6, &n6, V6_A, 6882) != 0) return fail("build6");
    size_t nm = merge_dicts(v4, n4, v6, n6, mix);
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    uint8_t a6ip[4][16], d6ip[4][16];
    uint16_t a6port[4], d6port[4];
    int na6 = -1, nd6 = -1;
    if (ntx_pex_parse_ex(mix, nm, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 4) != 0) return fail("mix_parse");
    if (na != 1 || na6 != 1) return fail("mix_counts");
    if (aip[0] != ip || apt[0] != 6881) return fail("mix_v4");
    if (memcmp(a6ip[0], V6_A, 16) != 0 || a6port[0] != 6882) return fail("mix_v6");
    if (!contains(mix, nm, "6:added6")) return fail("mix_key6");
    if (!contains(mix, nm, "5:added")) return fail("mix_key4");
    return 0;
}

static int test_parse_short_record(void) {
    uint8_t buf[64];
    size_t n = build_payload_short6(buf);
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na, nd;
    uint8_t a6ip[4][16];
    uint16_t a6port[4];
    int na6 = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, 0, 0, 0, 4) != 0) return fail("ex_parse");
    if (na6 != 1) return fail("ex_v6_counts");
    if (memcmp(a6ip[0], V6_A, 16) != 0) return fail("ex_v6_ip");
    if (a6port[0] != 6881) return fail("ex_v6_port");
    return 0;
}

static int test_build_dropped_roundtrip(void) {
    uint8_t buf[64];
    size_t n = 0;
    uint32_t ip;
    memcpy(&ip, V4_A, 4);
    if (ntx_pex_build_dropped(buf, sizeof buf, &n, ip, 6882) != 0) return fail("drop_build");
    if (n != 19) return fail("drop_len");
    if (buf[0] != 'd' || buf[n - 1] != 'e') return fail("drop_dict");
    if (memcmp(buf + 1, "7:dropped", 9) != 0) return fail("drop_key");
    if (memcmp(buf + 10, "6:", 2) != 0) return fail("drop_vallen");
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         0, 0, 0, 0, 0, 0, 0) != 0) return fail("drop_parse");
    if (na != 0 || nd != 1) return fail("drop_counts");
    if (dip[0] != ip || dport[0] != 6882) return fail("drop_vals");
    if (ntx_pex_build_dropped(buf, 18, &n, ip, 6882) != -1) return fail("drop_cap");
    if (ntx_pex_build_dropped(0, sizeof buf, &n, ip, 6882) != -1) return fail("drop_null");
    return 0;
}

static int test_build_dropped6_roundtrip(void) {
    uint8_t buf[64];
    size_t n = 0;
    if (ntx_pex_build_dropped6(buf, sizeof buf, &n, V6_D, 6882) != 0) return fail("drop6_build");
    if (n != 33) return fail("drop6_len");
    if (buf[0] != 'd' || buf[n - 1] != 'e') return fail("drop6_dict");
    if (memcmp(buf + 1, "8:dropped6", 10) != 0) return fail("drop6_key");
    if (memcmp(buf + 11, "18:", 3) != 0) return fail("drop6_vallen");
    if (ntx_pex_build_dropped6(buf, 32, &n, V6_D, 6882) != -1) return fail("drop6_cap");
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    uint8_t a6ip[4][16], d6ip[4][16];
    uint16_t a6port[4], d6port[4];
    int na6 = -1, nd6 = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 4) != 0) return fail("drop6_parse");
    if (na != 0 || nd != 0) return fail("drop6_v4_counts");
    if (na6 != 0 || nd6 != 1) return fail("drop6_v6_counts");
    if (memcmp(d6ip[0], V6_D, 16) != 0) return fail("drop6_ip");
    if (d6port[0] != 6882) return fail("drop6_port");
    return 0;
}

static int test_build_msg_v4(void) {
    uint8_t buf[256];
    size_t n = 0;
    uint32_t a4[2];
    uint16_t ap4[2];
    uint32_t d4[1];
    uint16_t dp4[1];
    static const uint8_t v4b[4] = { 0x0a, 0x00, 0x00, 0x03 };
    memcpy(&a4[0], V4_A, 4);
    memcpy(&a4[1], v4b, 4);
    ap4[0] = 6881; ap4[1] = 6883;
    memcpy(&d4[0], v4b, 4);
    dp4[0] = 6882;
    if (ntx_pex_build_msg(buf, sizeof buf, &n, a4, ap4, 2, 0, 0, 0, d4, dp4, 1, 0, 0, 0) != 0)
        return fail("msg_build");
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4, 0, 0, 0, 0, 0, 0, 0) != 0)
        return fail("msg_parse");
    if (na != 2 || nd != 1) return fail("msg_counts");
    if (aip[0] != a4[0] || apt[0] != 6881) return fail("msg_a0");
    if (aip[1] != a4[1] || apt[1] != 6883) return fail("msg_a1");
    if (dip[0] != d4[0] || dport[0] != 6882) return fail("msg_d0");
    return 0;
}

static int test_build_msg_mixed(void) {
    uint8_t buf[256];
    size_t n = 0;
    uint32_t a4[1];
    uint16_t ap4[1];
    uint8_t a6[1][16];
    uint16_t ap6[1];
    uint8_t d6[1][16];
    uint16_t dp6[1];
    memcpy(&a4[0], V4_A, 4);
    ap4[0] = 6881;
    memcpy(a6[0], V6_A, 16);
    ap6[0] = 6881;
    memcpy(d6[0], V6_D, 16);
    dp6[0] = 6882;
    if (ntx_pex_build_msg(buf, sizeof buf, &n, a4, ap4, 1, a6, ap6, 1, 0, 0, 0, d6, dp6, 1) != 0)
        return fail("mix_build");
    uint32_t aip[4], dip[4];
    uint16_t apt[4], dport[4];
    int na = -1, nd = -1;
    uint8_t a6ip[4][16], d6ip[4][16];
    uint16_t a6port[4], d6port[4];
    int na6 = -1, nd6 = -1;
    if (ntx_pex_parse_ex(buf, n, aip, apt, &na, dip, dport, &nd, 4,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 4) != 0)
        return fail("mix_parse");
    if (na != 1 || na6 != 1 || nd6 != 1) return fail("mix_counts");
    if (nd != 0) return fail("mix_nd");
    if (aip[0] != a4[0] || apt[0] != 6881) return fail("mix_a4");
    if (memcmp(a6ip[0], V6_A, 16) != 0 || a6port[0] != 6881) return fail("mix_a6");
    if (memcmp(d6ip[0], V6_D, 16) != 0 || d6port[0] != 6882) return fail("mix_d6");
    return 0;
}

static int test_build_msg_empty(void) {
    uint8_t buf[64];
    size_t n = 0;
    if (ntx_pex_build_msg(buf, sizeof buf, &n, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0) != -1)
        return fail("empty_ret");
    return 0;
}

static int test_build_msg_cap(void) {
    uint8_t buf[256];
    size_t n = 0;
    uint32_t a4[1];
    uint16_t ap4[1];
    memcpy(&a4[0], V4_A, 4);
    ap4[0] = 6881;
    if (ntx_pex_build_msg(buf, sizeof buf, &n, a4, ap4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0) != 0)
        return fail("cap_build");
    if (n == 0) return fail("cap_zero");
    uint8_t buf2[256];
    size_t n2 = 0;
    if (ntx_pex_build_msg(buf2, n - 1, &n2, a4, ap4, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0) != -1)
        return fail("cap_small");
    return 0;
}

static int test_build_msg_exact(void) {
    uint8_t buf[256], buf2[256];
    size_t n = 0;
    uint32_t a4[2];
    uint16_t ap4[2];
    uint32_t d4[1];
    uint16_t dp4[1];
    static const uint8_t v4b[4] = { 0x0a, 0x00, 0x00, 0x03 };
    memcpy(&a4[0], V4_A, 4);
    memcpy(&a4[1], v4b, 4);
    ap4[0] = 6881; ap4[1] = 6883;
    memcpy(&d4[0], v4b, 4);
    dp4[0] = 6882;
    if (ntx_pex_build_msg(buf, sizeof buf, &n, a4, ap4, 2, 0, 0, 0, d4, dp4, 1, 0, 0, 0) != 0)
        return fail("exact_build");
    if (n == 0) return fail("exact_zero");
    size_t n2 = 0;
    if (ntx_pex_build_msg(buf2, n, &n2, a4, ap4, 2, 0, 0, 0, d4, dp4, 1, 0, 0, 0) != 0)
        return fail("exact_fit");
    if (n2 != n) return fail("exact_len");
    if (memcmp(buf, buf2, n) != 0) return fail("exact_bytes");
    return 0;
}

int main(void) {
    if (test_parse_ex_full() != 0) return 1;
    printf("PASS pex_parse_ex_full\n");
    if (test_parse_ex_no_v6() != 0) return 1;
    printf("PASS pex_parse_ex_no_v6\n");
    if (test_parse_empty_added6() != 0) return 1;
    printf("PASS pex_parse_empty_added6\n");
    if (test_legacy_ignores_v6() != 0) return 1;
    printf("PASS pex_legacy_ignores_v6\n");
    if (test_parse_short_record() != 0) return 1;
    printf("PASS pex_parse_short_record\n");
    if (test_build_added_roundtrip() != 0) return 1;
    printf("PASS pex_build_added_roundtrip\n");
    if (test_build_added6_roundtrip() != 0) return 1;
    printf("PASS pex_build_added6_roundtrip\n");
    if (test_build_mixed() != 0) return 1;
    printf("PASS pex_build_mixed\n");
    if (test_build_dropped_roundtrip() != 0) return 1;
    printf("PASS pex_build_dropped_roundtrip\n");
    if (test_build_dropped6_roundtrip() != 0) return 1;
    printf("PASS pex_build_dropped6_roundtrip\n");
    if (test_build_msg_v4() != 0) return 1;
    printf("PASS pex_build_msg_v4\n");
    if (test_build_msg_mixed() != 0) return 1;
    printf("PASS pex_build_msg_mixed\n");
    if (test_build_msg_empty() != 0) return 1;
    printf("PASS pex_build_msg_empty\n");
    if (test_build_msg_cap() != 0) return 1;
    printf("PASS pex_build_msg_cap\n");
    if (test_build_msg_exact() != 0) return 1;
    printf("PASS pex_build_msg_exact\n");
    return 0;
}
