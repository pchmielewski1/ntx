#ifndef NTX_TLS_H
#define NTX_TLS_H

#include "../crypto/ntx_aes.h"
#include "ntx_tls13.h"

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

enum { NTX_TLS_OK = 0, NTX_TLS_FAIL = -1, NTX_TLS_PIN_FAIL = -2 };

/* TLS 1.2 client — ECDHE+AES-128-GCM with RSA (0xC02F) or ECDSA P-256 (0xC02B). */
typedef struct ntx_tls {
    int fd;
    int ready;
    int ver; /* 12 | 13 — negotiated version; dispatches read/write */
    uint64_t seq_r, seq_w;
    uint8_t client_key[16], server_key[16];
    uint8_t client_iv[4], server_iv[4];
    ntx_aes128_gcm gcm_w, gcm_r;
    ntx_tls13_dir w13, r13; /* TLS 1.3 record protection (ver == 13) */
    uint8_t app_buf[16384];
    size_t app_len, app_off;
    char peer_ip[48];
    char sni[256];
    char alpn[16]; /* "" / "h2" / "http/1.1" after handshake */
    uint16_t cipher; /* 0xC02B or 0xC02F */
    uint8_t master[48];
    uint8_t leaf_pin[32]; /* SHA-256(SPKI) of the leaf after the handshake */
    int leaf_pin_valid;
} ntx_tls;

void ntx_tls_init(ntx_tls *t);

/* Extended handshake. Tries TLS 1.3 first (RFC 8446, see ntx_tls13.h) and falls
 * back to TLS 1.2 on a fresh connection if the server does not speak 1.3 (see
 * NTX_TLS13_LIVE in ntx_tls.c). The SPKI pin is verified before any app data.
 * alpn_list/nalpn: preferred protocols (e.g. "h2","http/1.1"); the negotiated
 * one is in t->alpn after the handshake. */
int ntx_tls_handshake_ex(ntx_tls *t, int fd, const char *sni,
                         const uint8_t pins[][32], int npins, int io_timeout_sec,
                         const char *const alpn_list[], int nalpn);

/* When non-zero, pin miss prints full MITM line to stderr. Default 0 (CLI one-line). */
extern int ntx_tls_pin_stderr;

ssize_t ntx_tls_write(ntx_tls *t, const void *buf, size_t n);
ssize_t ntx_tls_read(ntx_tls *t, void *buf, size_t n);
void ntx_tls_close(ntx_tls *t); /* wipe secrets; does not close fd */

/* Leaf cert DER → SHA-256(SPKI). 0=ok, -1=parse fail. For offline pin tests. */
int ntx_tls_spki_sha256(const uint8_t *cert_der, size_t cert_len, uint8_t out[32]);

/* Leaf cert DER → SubjectPublicKeyInfo (pointer into the cert). 0=ok, -1. */
int ntx_tls_spki_from_cert(const uint8_t *cert_der, size_t cert_len,
                           const uint8_t **spki, size_t *spki_len);

/* RSA SPKI → modulus/exponent (pointers into spki). 0=ok, -1=parse. */
int ntx_tls_rsa_pub_from_spki(const uint8_t *spki, size_t spki_len,
                              const uint8_t **n_out, size_t *n_len,
                              const uint8_t **e_out, size_t *e_len);

/* Implemented in ntx_tls_rec.c: ntx_tls_rec_* (records+PRF) */
typedef struct {
    int enc;
    uint64_t *seq;
    ntx_aes128_gcm *gcm;
    const uint8_t *fixed_iv4;
} tls_dir;


int io_read(int fd, void *buf, size_t n);
int io_write(int fd, const void *buf, size_t n);
void tls12_prf(const uint8_t *secret, size_t slen, const char *label,
               const uint8_t *seed, size_t seed_len, uint8_t *out, size_t out_len);
void to_hex(char *dst, size_t dstsz, const uint8_t *b, size_t n);
void peer_ip_str(int fd, char *out, size_t outsz);
void sock_timeouts(int fd, int sec);
int rec_send(ntx_tls *t, uint8_t type, const uint8_t *body, size_t body_len, tls_dir *d);
int rec_recv(ntx_tls *t, uint8_t *type_out, uint8_t *buf, size_t cap, size_t *out_len,
             tls_dir *d);

/* test hook: fixed client key material for TLS 1.3 (default NULL = random). */
void ntx_tls13_test_set_keys(const uint8_t priv[32], const uint8_t cr[32]);
void ntx_tls13_test_clear_keys(void);

#endif
