#ifndef NTX_HTTP_H
#define NTX_HTTP_H

#include <stddef.h>
#include <stdint.h>

#include "ntx_bencode.h"

int ntx_http_get(const char *url, uint8_t *out, size_t cap, size_t *out_n);
int ntx_http_get_range(const char *url, uint64_t off, uint64_t len, uint8_t *out, size_t cap, size_t *out_n);
void ntx_http_set_proxy(const char *host, uint16_t port);
void ntx_http_clear_proxy(void);

/* Implemented in ntx_http.c: ntx_http_parse_tracker_dict/ipv4 + ntx_http_put(_enc) */
int http_safe_byte(uint8_t b);
void http_put(char *out, size_t cap, size_t *pos, int *ov, const char *s);
void http_put_enc(char *out, size_t cap, size_t *pos, int *ov, const uint8_t *data, size_t n);
int http_parse_ipv4(const char *s, size_t n, uint32_t *out);
int http_parse_dict(const ntx_be *be, uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                    uint8_t *ips, uint16_t *ports, int max_peers, char *error, size_t err_cap);
/* IPv6: v4 peers + optional peers6 (stride 18). NULL ips6/ports6 or max6<=0 -> ignore peers6.
   Returns total peer count (v4 + v6); -1 on "failure reason". */
int http_parse_dict_ex(const ntx_be *be, uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                       uint8_t *ips, uint16_t *ports, int max_peers,
                       uint8_t ips6[][16], uint16_t *ports6, int max6,
                       char *error, size_t err_cap);
#endif
