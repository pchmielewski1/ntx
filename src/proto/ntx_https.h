#ifndef NTX_HTTPS_H
#define NTX_HTTPS_H

#include <stdint.h>
#include "../net/ntx_tls.h"

/* resolve → tcp connect → pin lookup (early fail: TOFU off + 0 pins)
   → ntx_tls_handshake_ex(alpn={"http/1.1"}) + TOFU note (first contact with a host).
   0=ok (out ready), -1=fail (resolve/connect/pin/handshake),
   -2=pin fail (NTX_TLS_PIN_FAIL). */
int ntx_https_connect(const char *host, uint16_t port, ntx_tls *out);

/* fd already connected (direct or after SOCKS CONNECT): pin lookup +
   ntx_tls_handshake_ex(alpn={"http/1.1"}) + TOFU note (first contact with a host).
   0=ok (out ready), -1=fail (pin/handshake), -2=pin fail. */
int ntx_https_handshake_fd(const char *host, uint16_t port, int fd, ntx_tls *out);

/* Response headers up to \r\n\r\n (RFC 7230).
   0=ok (buf = headers + NUL, *out_len = hlen), -1=I/O/EOF, -2=headers > cap. */
int ntx_https_read_headers(ntx_tls *t, char *buf, size_t cap, size_t *out_len);

/* Status code from the status line; -1 when malformed */
int ntx_https_status_code(const char *hdrs);

/* Headers + body per Content-Length (no CL → body 0).
   0=ok (status 200/206; out = full response + NUL, *out_n = hlen+body),
   -1=I/O or other status, -2=response > cap. */
int ntx_https_read_response(ntx_tls *t, char *out, size_t cap, size_t *out_n);

/* Decode a chunked body in place. 0=complete (*out_n = body bytes), 1=need more input, -1=malformed.
   The buffer is left untouched unless the result is 0. */
int ntx_http_dechunk(char *buf, size_t n, size_t *out_n);

#ifdef NTX_HTTP_TEST_HOOKS
void ntx_https_test_reset_hooks(void);
void ntx_https_test_set_handshake(int (*fn)(const char *host, uint16_t port,
                                            ntx_tls *out));
void ntx_https_test_set_read(ssize_t (*fn)(ntx_tls *t, void *buf, size_t n));
#endif

#endif
