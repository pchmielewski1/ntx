#include <arpa/inet.h>
#include <assert.h>
#include <stdio.h>
#include <string.h>

#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"

int main(void) {
    uint8_t req[19];
    ntx_addr a4;
    ntx_addr_set_v4(&a4, htonl(0x0A000001));
    size_t n = tnl_open_req(&a4, 6881, req, sizeof req);
    assert(n == 7);
    assert(req[0] == 1);
    assert(req[1] == 0x0A && req[2] == 0x00 && req[3] == 0x00 && req[4] == 0x01);
    assert(req[5] == 0x1A && req[6] == 0xE1);

    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    ntx_addr a6;
    ntx_addr_set_v6(&a6, v6);
    n = tnl_open_req(&a6, 6881, req, sizeof req);
    assert(n == 19);
    assert(req[0] == 3);
    assert(memcmp(req + 1, v6, 16) == 0);
    assert(req[1] == 0x20 && req[4] == 0xb8 && req[16] == 0x01);
    assert(req[17] == 0x1A && req[18] == 0xE1);

    printf("PASS\n");
    return 0;
}
