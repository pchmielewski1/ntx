/* ntx_sock.c excluded: its weak DoH stubs redefine ntx_doh.c symbols in one TU;
   the 6 ntx_sock stubs below are link-only (parse paths never call them). */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "../../src/proto/ntx_tracker.c"
#include "../../src/proto/ntx_http.c"
#include "../../src/proto/ntx_http_url.c"
#include "../../src/proto/ntx_https.c"
#include "../../src/proto/ntx_https_pin.c"
#include "../../src/net/ntx_tls.c"
#include "../../src/net/ntx_tls_rec.c"
#include "../../src/net/ntx_tls13.c"
#include "../../src/crypto/ntx_hkdf.c"
#include "../../src/crypto/ntx_x25519_fe.c"
#include "../../src/crypto/ntx_x25519.c"
#include "../../src/crypto/ntx_bignum.c"
#include "../../src/crypto/ntx_p256.c"
#include "../../src/crypto/ntx_rsa_pkcs1.c"
#include "../../src/crypto/ntx_aes.c"
#include "../../src/crypto/ntx_hmac.c"
#include "../../src/crypto/ntx_rng.c"
#include "../../src/crypto/ntx_sha1.c"
#include "../../src/crypto/ntx_sha256.c"
#include "../../src/net/ntx_proxy.c"
#include "../../src/net/ntx_addr.c"
#include "../../src/proto/ntx_doh.c"
#include "../../src/proto/ntx_h2.c"
#include "../../src/proto/ntx_bencode.c"
#include "../../src/ui/ntx_diag.c"

int ntx_sock_tcp4(void) { return -1; }
int ntx_sock_tcp6(void) { return -1; }
int ntx_sock_connect_addr(int fd, const ntx_addr *addr, uint16_t port) {
    (void)fd; (void)addr; (void)port; return -1;
}
int ntx_sock_resolve(const char *host, ntx_addr *out) { (void)host; (void)out; return -1; }
int ntx_sock_tcp_connect_host(const char *host, uint16_t port) { (void)host; (void)port; return -1; }
uint16_t ntx_sock_local_port(int fd) { (void)fd; return 0; }

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    int32_t tid;
    uint64_t conn_id;
    uint32_t interval, seeders, leechers, ttl;
    uint32_t doh_ips4[64];
    uint8_t ips4[256];
    uint16_t ports4[64];
    uint8_t ips6[32][16];
    uint16_t ports6[32];
    uint8_t doh_ips6[32][16];
    int n4, n6;
    char err[128];

    ntx_tracker_udp_connect_parse(data, len, &tid, &conn_id);
    ntx_tracker_udp_announce_parse_ex(data, len, &tid, &interval, &leechers, &seeders,
                                      ips4, ports4, 64, &n4, ips6, ports6, 32, &n6);
    ntx_tracker_peer_parse_compact(data, len, ips4, ports4, 64);
    ntx_tracker_peer_parse_compact6(data, len, ips6, ports6, 32);
    ntx_tracker_http_parse_ex(data, len, &tid, &interval, &seeders, &leechers,
                              ips4, ports4, 64, ips6, ports6, 32, err, sizeof err);
    ntx_doh_parse_response_a(data, len, doh_ips4, 64, &ttl);
    ntx_doh_parse_response_aaaa(data, len, doh_ips6, 32, &ttl);
    return 0;
}
