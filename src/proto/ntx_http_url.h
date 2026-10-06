#ifndef NTX_HTTP_URL_H
#define NTX_HTTP_URL_H

#include <stdint.h>

typedef struct {
  char host[256];
  uint16_t port;
  const char *path; /* points into the original url buffer — url must outlive parts */
  int is_tls;       /* 0=http 1=https */
} ntx_http_url_parts;

int ntx_http_url_parse(const char *url, ntx_http_url_parts *out);
/* 0=ok; -1=bad scheme/host */

#endif
