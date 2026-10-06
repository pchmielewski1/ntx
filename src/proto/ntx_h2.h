#ifndef NTX_H2_H
#define NTX_H2_H

#include "../net/ntx_tls.h"

#include <stddef.h>
#include <stdint.h>

/* Minimal HTTP/2 DoH POST (one stream). 0=ok, -1=fail. */
int ntx_h2_doh_post(ntx_tls *tls, const char *authority, const char *path,
                    const uint8_t *req, size_t req_len, uint8_t *resp, size_t resp_cap,
                    size_t *resp_len);

#endif
