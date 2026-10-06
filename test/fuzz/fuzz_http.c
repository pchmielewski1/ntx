/* No global state: url parser is pure, ntx_be_free releases the tree each iteration. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../src/ui/ntx_diag.c"
#include "../../src/crypto/ntx_sha1.c"
#include "../../src/crypto/ntx_sha256.c"
#include "../../src/crypto/ntx_hmac.c"
#include "../../src/crypto/ntx_hkdf.c"
#include "../../src/crypto/ntx_aes.c"
#include "../../src/crypto/ntx_rng.c"
#include "../../src/crypto/ntx_x25519_fe.c"
#include "../../src/crypto/ntx_x25519.c"
#include "../../src/crypto/ntx_bignum.c"
#include "../../src/crypto/ntx_p256.c"
#include "../../src/crypto/ntx_rsa_pkcs1.c"
#include "../../src/net/ntx_tls_rec.c"
#include "../../src/net/ntx_tls.c"
#include "../../src/net/ntx_tls13.c"
#include "../../src/net/ntx_addr.c"
#include "../../src/net/ntx_sock.c"
#include "../../src/net/ntx_proxy.c"
#include "../../src/proto/ntx_http_url.c"
#include "../../src/proto/ntx_https.c"
#include "../../src/proto/ntx_https_pin.c"
#include "../../src/proto/ntx_bencode.c"
#include "../../src/proto/ntx_tracker.c"
#include "../../src/proto/ntx_http.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    uint8_t buf[4352];
    size_t n = len < sizeof buf - 1 ? len : sizeof buf - 1;
    ntx_http_url_parts parts;
    uint32_t ip, interval, seeders, leechers;
    uint8_t ips4[256];
    uint16_t ports4[64];
    uint8_t ips6[32][16];
    uint16_t ports6[32];
    char err[128];
    ntx_be be;
    size_t consumed = 0;

    memcpy(buf, data, n);
    buf[n] = 0;
    ntx_http_url_parse((const char *)buf, &parts);
    http_parse_ipv4((const char *)buf, n, &ip);
    if (ntx_be_parse(data, len, &be, &consumed, 32, (size_t)(1 << 20)) == 0) {
        http_parse_dict(&be, &interval, &seeders, &leechers, ips4, ports4, 64, err, sizeof err);
        http_parse_dict_ex(&be, &interval, &seeders, &leechers, ips4, ports4, 64,
                           ips6, ports6, 32, err, sizeof err);
        ntx_be_free(&be);
    }
    return 0;
}
