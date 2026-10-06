#include "ntx_dht_token.h"
#include <string.h>
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_rng.h"
#include "../crypto/ntx_ct.h"

void ntx_dht_token_init(ntx_dht_token_ctx *c) {
    ntx_rand_bytes(c->secret, sizeof(c->secret));
}

static void build(const ntx_dht_token_ctx *c, const ntx_addr *addr,
                  uint32_t bucket, uint8_t out8[8]) {
    uint8_t buf[20 + 16 + 1 + 4];
    size_t n = 0;
    memcpy(buf + n, c->secret, 20);
    n += 20;
    if (addr->family == NTX_AF_INET6) {
        memcpy(buf + n, addr->u.v6, 16);
        n += 16;
    } else {
        memcpy(buf + n, &addr->u.v4, 4);
        n += 4;
    }
    buf[n++] = addr->family;
    buf[n++] = (uint8_t)(bucket >> 24);
    buf[n++] = (uint8_t)(bucket >> 16);
    buf[n++] = (uint8_t)(bucket >> 8);
    buf[n++] = (uint8_t)bucket;
    uint8_t digest[20];
    ntx_sha1(buf, n, digest);
    memcpy(out8, digest, NTX_DHT_TOKEN_LEN);
}

void ntx_dht_token_issue(const ntx_dht_token_ctx *c, const ntx_addr *addr,
                         uint32_t unix_sec, uint8_t out[8]) {
    build(c, addr, unix_sec / NTX_DHT_TOKEN_WINDOW_S, out);
}

int ntx_dht_token_verify(const ntx_dht_token_ctx *c, const ntx_addr *addr,
                         uint32_t unix_sec, const uint8_t tok[8]) {
    uint32_t b = unix_sec / NTX_DHT_TOKEN_WINDOW_S;
    uint8_t cur[8], prev[8];
    build(c, addr, b, cur);
    build(c, addr, b - 1, prev);
    /* both compares always run: no early exit that leaks which window matched / how far */
    return ntx_ct_eq(cur, tok, NTX_DHT_TOKEN_LEN) | ntx_ct_eq(prev, tok, NTX_DHT_TOKEN_LEN);
}
