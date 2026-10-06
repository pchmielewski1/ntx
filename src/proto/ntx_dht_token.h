#ifndef NTX_DHT_TOKEN_H
#define NTX_DHT_TOKEN_H
#include <stdint.h>
#include "../net/ntx_addr.h"

#define NTX_DHT_TOKEN_LEN 8
#define NTX_DHT_TOKEN_WINDOW_S 600u

typedef struct { uint8_t secret[20]; } ntx_dht_token_ctx;

void ntx_dht_token_init(ntx_dht_token_ctx *c);
void ntx_dht_token_issue(const ntx_dht_token_ctx *c, const ntx_addr *addr,
                         uint32_t unix_sec, uint8_t out[8]);
int ntx_dht_token_verify(const ntx_dht_token_ctx *c, const ntx_addr *addr,
                         uint32_t unix_sec, const uint8_t tok[8]);

#endif
