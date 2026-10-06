#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_http.c" /* pre-include */
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/net/ntx_sock.c" /* (dependency of ntx_http.c) */
#include "../src/net/ntx_proxy.c" /* (dependency of ntx_http.c) */
#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/ui/ntx_diag.c"

static int g_fail;

static void expect(const char *name, int ok) {
    if (ok) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); g_fail = 1; }
}

static void put_peer(uint8_t *p, uint8_t a, uint8_t b, uint8_t c, uint8_t d, uint16_t port) {
    p[0] = a; p[1] = b; p[2] = c; p[3] = d;
    ntx_wire_wr16(p + 4, port);
}

static void put_peer6(uint8_t *p, const uint8_t ip[16], uint16_t port) {
    memcpy(p, ip, 16);
    ntx_wire_wr16(p + 16, port);
}

int main(void) {
    uint8_t info_hash[20], peer_id[20];
    for (int i = 0; i < 20; i++) {
        info_hash[i] = (uint8_t)(0xA0 + i);
        peer_id[i] = (uint8_t)(0x10 + i);
    }

    uint8_t areq[98];
    ntx_tracker_udp_announce_build(areq, 0x1122334455667788ULL, 0x12345678,
                                   info_hash, peer_id, 1000, 2000, 3000,
                                   NTX_TRACKER_EVENT_NONE, 0xDEADBEEFu, 6881);
    expect("announce-build",
           sizeof(areq) == 98 &&
           rd64(areq + 0) == 0x1122334455667788ULL &&
           ntx_wire_rd32(areq + 8) == 1 &&
           ntx_wire_rd32(areq + 12) == 0x12345678 &&
           memcmp(areq + 16, info_hash, 20) == 0 &&
           memcmp(areq + 36, peer_id, 20) == 0 &&
           rd64(areq + 56) == 1000 &&
           rd64(areq + 64) == 2000 &&
           rd64(areq + 72) == 3000 &&
           ntx_wire_rd32(areq + 80) == 0 &&
           ntx_wire_rd32(areq + 84) == 0 &&
           ntx_wire_rd32(areq + 88) == 0xDEADBEEF &&
           ntx_wire_rd32(areq + 92) == 200 &&
           ntx_wire_rd16(areq + 96) == 6881);

    uint8_t creq[16];
    ntx_tracker_udp_connect_build(creq, 0xCAFEBABE);
    static const uint8_t magic[8] = {0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80};
    expect("connect-build",
           sizeof(creq) == 16 &&
           memcmp(creq, magic, 8) == 0 &&
           ntx_wire_rd32(creq + 8) == 0 &&
           ntx_wire_rd32(creq + 12) == 0xCAFEBABE);

    uint8_t cresp[16];
    ntx_wire_wr32(cresp + 0, 0);
    ntx_wire_wr32(cresp + 4, 0xCAFEBABE);
    wr64(cresp + 8, 0x1234567890ABCDEFULL);
    int32_t tid;
    uint64_t cid;
    expect("connect-parse",
           ntx_tracker_udp_connect_parse(cresp, sizeof(cresp), &tid, &cid) == 0 &&
           tid == (int32_t)0xCAFEBABE &&
           cid == 0x1234567890ABCDEFULL);

    uint8_t aresp[20 + 18];
    ntx_wire_wr32(aresp + 0, 1);
    ntx_wire_wr32(aresp + 4, 0x12345678);
    ntx_wire_wr32(aresp + 8, 1800);
    ntx_wire_wr32(aresp + 12, 5);
    ntx_wire_wr32(aresp + 16, 3);
    put_peer(aresp + 20, 1, 2, 3, 4, 6881);
    put_peer(aresp + 26, 5, 6, 7, 8, 6882);
    put_peer(aresp + 32, 9, 10, 11, 12, 6883);
    uint8_t ips[10 * 4];
    uint16_t ports[10];
    uint32_t interval, leechers, seeders;
    int np = ntx_tracker_udp_announce_parse(aresp, sizeof(aresp), &tid, &interval, &leechers, &seeders, ips, ports, 10);
    expect("announce-parse",
           np == 3 &&
           tid == 0x12345678 &&
           interval == 1800 &&
           leechers == 5 &&
           seeders == 3 &&
           ips[0] == 1 && ips[1] == 2 && ips[2] == 3 && ips[3] == 4 && ports[0] == 6881 &&
           ips[4] == 5 && ips[5] == 6 && ips[6] == 7 && ips[7] == 8 && ports[1] == 6882 &&
           ips[8] == 9 && ips[9] == 10 && ips[10] == 11 && ips[11] == 12 && ports[2] == 6883);

    uint8_t compact[18];
    put_peer(compact + 0, 1, 2, 3, 4, 6881);
    put_peer(compact + 6, 5, 6, 7, 8, 6882);
    put_peer(compact + 12, 9, 10, 11, 12, 6883);
    np = ntx_tracker_peer_parse_compact(compact, sizeof(compact), ips, ports, 10);
    expect("compact-parse",
           np == 3 &&
           ips[0] == 1 && ips[1] == 2 && ips[2] == 3 && ips[3] == 4 && ports[0] == 6881 &&
           ips[4] == 5 && ips[5] == 6 && ips[6] == 7 && ips[7] == 8 && ports[1] == 6882 &&
           ips[8] == 9 && ips[9] == 10 && ips[10] == 11 && ips[11] == 12 && ports[2] == 6883);

    expect("announce-parse-short",
           ntx_tracker_udp_announce_parse(aresp, 19, &tid, &interval, &leechers, &seeders, ips, ports, 10) == -1);

    uint8_t aerr[20];
    ntx_wire_wr32(aerr + 0, 3);
    ntx_wire_wr32(aerr + 4, 0x12345678);
    expect("announce-parse-badaction",
           ntx_tracker_udp_announce_parse(aerr, sizeof(aerr), &tid, &interval, &leechers, &seeders, ips, ports, 10) == -1);

    expect("compact-parse-badlen",
           ntx_tracker_peer_parse_compact(compact, 7, ips, ports, 10) == -1);

    uint8_t ips6[10][16];
    uint16_t ports6[10];
    uint8_t v6buf[36 + 4];
    static const uint8_t loop6[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
    uint8_t v6b[16];
    memset(v6b, 0, sizeof(v6b));
    v6b[15] = 2;
    put_peer6(v6buf + 0, loop6, 6881);
    put_peer6(v6buf + 18, v6b, 6882);

    int n6 = ntx_tracker_peer_parse_compact6(v6buf, 18, ips6, ports6, 10);
    expect("compact6-parse-single",
           n6 == 1 && ips6[0][15] == 1 && ports6[0] == 6881);

    n6 = ntx_tracker_peer_parse_compact6(v6buf, 36, ips6, ports6, 10);
    expect("compact6-parse-two",
           n6 == 2 &&
           ips6[0][15] == 1 && ports6[0] == 6881 &&
           ips6[1][15] == 2 && ports6[1] == 6882);

    n6 = ntx_tracker_peer_parse_compact6(v6buf, 20, ips6, ports6, 10);
    expect("compact6-parse-tail-ignored",
           n6 == 1 && ips6[0][15] == 1 && ports6[0] == 6881);

    n6 = ntx_tracker_peer_parse_compact6(v6buf, 36, ips6, ports6, 1);
    expect("compact6-parse-max1",
           n6 == 1 && ips6[0][15] == 1 && ports6[0] == 6881);

    /* UDP announce with a peers6 tail (rem%18==0 after the v4 block) */
    uint8_t aresp6[20 + 6 + 18];
    ntx_wire_wr32(aresp6 + 0, 1);
    ntx_wire_wr32(aresp6 + 4, 0x12345678);
    ntx_wire_wr32(aresp6 + 8, 1800);
    ntx_wire_wr32(aresp6 + 12, 5);
    ntx_wire_wr32(aresp6 + 16, 3);
    put_peer(aresp6 + 20, 1, 2, 3, 4, 6881);
    static const uint8_t db8_5[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 5};
    put_peer6(aresp6 + 26, db8_5, 6881);
    uint8_t ips4b[4];
    uint16_t ports4b[1];
    uint8_t ips6b[4][16];
    uint16_t ports6b[4];
    int n4 = 0, n6x = 0;
    int rc = ntx_tracker_udp_announce_parse_ex(aresp6, sizeof(aresp6), &tid, &interval, &leechers, &seeders,
                                               ips4b, ports4b, 1, &n4,
                                               ips6b, ports6b, 4, &n6x);
    expect("announce-parse-ex-mixed",
           rc == 1 && n4 == 1 && n6x == 1 &&
           ips4b[0] == 1 && ips4b[1] == 2 && ips4b[2] == 3 && ips4b[3] == 4 && ports4b[0] == 6881 &&
           ips6b[0][0] == 0x20 && ips6b[0][1] == 0x01 && ips6b[0][2] == 0x0d && ips6b[0][3] == 0xb8 &&
           ips6b[0][15] == 5 && ports6b[0] == 6881);

    n4 = 0; n6x = 0;
    rc = ntx_tracker_udp_announce_parse_ex(aresp, sizeof(aresp), &tid, &interval, &leechers, &seeders,
                                           ips, ports, 10, &n4,
                                           ips6b, ports6b, 4, &n6x);
    expect("announce-parse-ex-v4only",
           rc == 3 && n4 == 3 && n6x == 0);

    uint8_t aresp_tail[20 + 12 + 5];
    ntx_wire_wr32(aresp_tail + 0, 1);
    ntx_wire_wr32(aresp_tail + 4, 0x12345678);
    ntx_wire_wr32(aresp_tail + 8, 1800);
    ntx_wire_wr32(aresp_tail + 12, 5);
    ntx_wire_wr32(aresp_tail + 16, 3);
    put_peer(aresp_tail + 20, 1, 2, 3, 4, 6881);
    put_peer(aresp_tail + 26, 5, 6, 7, 8, 6882);
    for (int i = 0; i < 5; i++) aresp_tail[32 + i] = (uint8_t)(0xE0 + i);
    n4 = 0; n6x = 0;
    rc = ntx_tracker_udp_announce_parse_ex(aresp_tail, sizeof(aresp_tail), &tid, &interval, &leechers, &seeders,
                                           ips, ports, 10, &n4,
                                           ips6b, ports6b, 4, &n6x);
    expect("announce-parse-ex-tail-ignored",
           rc == 2 && n4 == 2 && n6x == 0 &&
           ips[0] == 1 && ips[1] == 2 && ips[2] == 3 && ips[3] == 4 && ports[0] == 6881 &&
           ips[4] == 5 && ips[5] == 6 && ips[6] == 7 && ips[7] == 8 && ports[1] == 6882);

    n4 = 0;
    rc = ntx_tracker_udp_announce_parse_ex(aresp6, sizeof(aresp6), &tid, &interval, &leechers, &seeders,
                                           ips4b, ports4b, 1, &n4,
                                           NULL, NULL, 0, NULL);
    expect("announce-parse-ex-nov6",
           rc == 1 && n4 == 1 && ips4b[0] == 1 && ports4b[0] == 6881);

    np = ntx_tracker_udp_announce_parse(aresp6, sizeof(aresp6), &tid, &interval, &leechers, &seeders, ips, ports, 10);
    expect("announce-parse-legacy-mixed", np == 4);

    return g_fail ? 1 : 0;
}
