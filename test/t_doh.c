#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/net/ntx_tls.c"
#include "../src/ui/ntx_diag.c"
#include "../src/proto/ntx_h2.c"
#include "../src/proto/ntx_doh.c"

/* split-out module sources, included directly */
#include "../src/net/ntx_tls_rec.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

/* Hand-built DNS response: example.com A 93.184.216.34, TTL 3600, compressed name.
 * Also mirrored at test/vectors/doh/a_example.bin */
static const uint8_t FIX_RESP[] = {
    /* Header: id=0x1234, QR=1 RD=1 RA=1, qd=1 an=1 */
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    /* Question: example.com */
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x01, 0x00, 0x01,
    /* Answer: pointer to name @12, A IN TTL=3600 RDLEN=4 93.184.216.34 */
    0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x04,
    93, 184, 216, 34
};

/* Hand-built DNS response: example.com AAAA ::1, TTL 3600, compressed name. */
static const uint8_t FIX_RESP_AAAA[] = {
    /* Header: id=0x1234, QR=1 RD=1 RA=1, qd=1 an=1 */
    0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    /* Question: example.com, QTYPE AAAA (28), QCLASS IN */
    0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
    0x00, 0x1c, 0x00, 0x01,
    /* Answer: pointer @12, AAAA IN TTL=3600 RDLEN=16, RDATA ::1 */
    0xc0, 0x0c, 0x00, 0x1c, 0x00, 0x01, 0x00, 0x00, 0x0e, 0x10, 0x00, 0x10,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1
};

static void check(const char *name, int ok) {
    if (!ok) {
        printf("FAIL %s\n", name);
        exit(1);
    }
    printf("PASS %s\n", name);
}

int main(void) {
    uint8_t q[512];
    size_t qn = ntx_doh_build_query_a(q, sizeof q, "example.com", 0x1234);
    check("build-len", qn > 12);
    check("build-id", q[0] == 0x12 && q[1] == 0x34);
    check("build-flags-rd", q[2] == 0x01 && q[3] == 0x00);
    check("build-qdcount", q[4] == 0 && q[5] == 1);
    /* last 4 bytes of question: QTYPE A, QCLASS IN */
    check("build-qtype-qclass",
          q[qn - 4] == 0 && q[qn - 3] == 1 && q[qn - 2] == 0 && q[qn - 1] == 1);

    uint32_t ips[4], ttl = 0;
    int n = ntx_doh_parse_response_a(FIX_RESP, sizeof FIX_RESP, ips, 4, &ttl);
    check("parse-count", n == 1);
    check("parse-ttl", ttl == 3600);
    uint8_t *b = (uint8_t *)&ips[0];
    check("parse-ip", b[0] == 93 && b[1] == 184 && b[2] == 216 && b[3] == 34);

    size_t fn = 0;
    uint8_t *fmsg = read_file("test/vectors/doh/a_example.bin", &fn);
    ttl = 0;
    n = ntx_doh_parse_response_a(fmsg, fn, ips, 4, &ttl);
    free(fmsg);
    check("parse-file-count", n == 1);
    check("parse-file-ttl", ttl == 3600);
    b = (uint8_t *)&ips[0];
    check("parse-file-ip", b[0] == 93 && b[1] == 184 && b[2] == 216 && b[3] == 34);

    size_t qn6 = ntx_doh_build_query_aaaa(q, sizeof q, "example.com", 0x1234);
    check("build6-len", qn6 > 12);
    check("build6-id", q[0] == 0x12 && q[1] == 0x34);
    check("build6-flags-rd", q[2] == 0x01 && q[3] == 0x00);
    check("build6-qdcount", q[4] == 0 && q[5] == 1);
    /* last 4 bytes of question: QTYPE AAAA (28), QCLASS IN */
    check("build6-qtype-qclass",
          q[qn6 - 4] == 0 && q[qn6 - 3] == 28 && q[qn6 - 2] == 0 && q[qn6 - 1] == 1);

    uint8_t ips6[4][16];
    uint32_t ttl6 = 0;
    int n6 = ntx_doh_parse_response_aaaa(FIX_RESP_AAAA, sizeof FIX_RESP_AAAA, ips6, 4, &ttl6);
    check("parse6-count", n6 == 1);
    check("parse6-ttl", ttl6 == 3600);
    int zero_ok = 1;
    for (int i = 0; i < 15; i++) zero_ok = zero_ok && ips6[0][i] == 0;
    check("parse6-ip-::1", zero_ok && ips6[0][15] == 1);

    /* A-record response must yield 0 AAAA records */
    ttl6 = 99;
    n6 = ntx_doh_parse_response_aaaa(FIX_RESP, sizeof FIX_RESP, ips6, 4, &ttl6);
    check("parse6-ignores-a", n6 == 0 && ttl6 == 0);

    uint32_t lit = 0;
    check("literal-ok", ntx_doh_lookup_a("1.2.3.4", &lit) == 0);
    b = (uint8_t *)&lit;
    check("literal-bytes", b[0] == 1 && b[1] == 2 && b[2] == 3 && b[3] == 4);

    /* lookup_aaaa links + arg validation (no network: pool walk not reached) */
    uint8_t a6[16];
    check("aaaa-null-host", ntx_doh_lookup_aaaa(NULL, a6) == -1);
    check("aaaa-null-out", ntx_doh_lookup_aaaa("example.com", NULL) == -1);

#ifdef NTX_TEST_LIVE_DOH
    uint32_t live = 0;
    check("live-cloudflare", ntx_doh_lookup_a("cloudflare.com", &live) == 0);
    check("live-nonzero", live != 0);
#endif
    return 0;
}
