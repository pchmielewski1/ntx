#ifndef NTX_TLS13_H
#define NTX_TLS13_H

/*
 * TLS 1.3 client building blocks (RFC 8446), restricted to what ntx needs:
 *   - cipher suite TLS_AES_128_GCM_SHA256 (0x1301)
 *   - key exchange x25519 (no HelloRetryRequest, no PSK / 0-RTT)
 *   - server auth: ecdsa_secp256r1_sha256 (0x0403) or rsa_pss_rsae_sha256 (0x0804);
 *     trust comes from the SPKI pin / TOFU in ntx_tls.c, not from a CA chain
 *
 * Everything here is pure (memory in, memory out) so that it can be checked
 * against an independent reference (test/scripts/tls13_ref.py). The handshake
 * driver and socket I/O live in ntx_tls.c.
 */

#include "../crypto/ntx_aes.h"

#include <stddef.h>
#include <stdint.h>

/* Handshake message types (RFC 8446 section 4). */
enum {
    NTX_HS13_CLIENT_HELLO = 1,
    NTX_HS13_SERVER_HELLO = 2,
    NTX_HS13_NEW_SESSION_TICKET = 4,
    NTX_HS13_ENCRYPTED_EXTENSIONS = 8,
    NTX_HS13_CERTIFICATE = 11,
    NTX_HS13_CERTIFICATE_REQUEST = 13,
    NTX_HS13_CERTIFICATE_VERIFY = 15,
    NTX_HS13_FINISHED = 20,
    NTX_HS13_KEY_UPDATE = 24
};

#define NTX_TLS13_MAX_PLAINTEXT 16384u
/* ciphertext = content + inner type byte + up to 255 padding + 16 tag (section 5.2) */
#define NTX_TLS13_MAX_CIPHERTEXT (16384u + 256u)

/* ---- key schedule (RFC 8446 section 7.1) -------------------------------- */

/* HKDF-Expand-Label(secret, label, context, out_len); label WITHOUT the "tls13 "
 * prefix. 0 = ok, -1 = bad argument. */
int ntx_tls13_expand_label(const uint8_t secret[32], const char *label,
                           const uint8_t *ctx, size_t ctx_len,
                           uint8_t *out, size_t out_len);

/* Derive-Secret(secret, label, Transcript-Hash) = Expand-Label(secret, label, hash, 32). */
int ntx_tls13_derive_secret(const uint8_t secret[32], const char *label,
                            const uint8_t transcript_hash[32], uint8_t out[32]);

/* write_key (16) and write_iv (12) of a traffic secret (section 7.3). */
int ntx_tls13_traffic_keys(const uint8_t secret[32], uint8_t key[16], uint8_t iv[12]);

/* ecdhe + Hash(ClientHello..ServerHello) -> handshake_secret and the two
 * handshake traffic secrets ("c hs traffic" / "s hs traffic"). */
int ntx_tls13_hs_secrets(const uint8_t ecdhe[32], const uint8_t h_ch_sh[32],
                         uint8_t hs_secret[32], uint8_t c_hs[32], uint8_t s_hs[32]);

/* handshake_secret + Hash(ClientHello..server Finished) -> application traffic
 * secrets ("c ap traffic" / "s ap traffic"). */
int ntx_tls13_app_secrets(const uint8_t hs_secret[32], const uint8_t h_ch_sfin[32],
                          uint8_t c_ap[32], uint8_t s_ap[32]);

/* Finished.verify_data = HMAC(finished_key, transcript_hash), finished_key =
 * Expand-Label(base_secret, "finished", "", 32) (section 4.4.4). */
int ntx_tls13_finished_data(const uint8_t base_secret[32], const uint8_t transcript_hash[32],
                            uint8_t out[32]);

/* ---- record protection (RFC 8446 section 5) ----------------------------- */

typedef struct {
    ntx_aes128_gcm gcm;
    uint8_t iv[12];
    uint8_t secret[32]; /* kept for KeyUpdate */
    uint64_t seq;
    int active;
} ntx_tls13_dir;

/* Derive key/iv from a traffic secret and reset the sequence number to 0. */
int ntx_tls13_dir_init(ntx_tls13_dir *d, const uint8_t secret[32]);
/* KeyUpdate: secret' = Expand-Label(secret, "traffic upd", "", 32); seq = 0. */
int ntx_tls13_dir_update(ntx_tls13_dir *d);
void ntx_tls13_dir_wipe(ntx_tls13_dir *d);

/* Build one protected record: header(5) || AEAD(content || inner_type). Needs
 * cap >= n + 22. Refuses to seal under a sequence number that would wrap. */
int ntx_tls13_seal(ntx_tls13_dir *d, uint8_t inner_type, const uint8_t *content, size_t n,
                   uint8_t *rec_out, size_t cap, size_t *rec_len);

/* Open one record given its 5-byte header and body. On success writes the
 * content (padding stripped) to out and its type to *inner_type. cap must be
 * >= body_len. 0 = ok, -1 = bad record / authentication failure. The sequence
 * number only advances on success. */
int ntx_tls13_open(ntx_tls13_dir *d, const uint8_t hdr[5], const uint8_t *body, size_t body_len,
                   uint8_t *out, size_t cap, size_t *out_len, uint8_t *inner_type);

/* ---- handshake messages -------------------------------------------------- */

/* ClientHello handshake message (type 1 + u24 length + body) offering only
 * TLS_AES_128_GCM_SHA256 / x25519 / {ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256}.
 * sid is the 32-byte legacy_session_id (middlebox compatibility, echoed by the
 * server). Returns the message length, or 0 if cap is too small / bad input. */
size_t ntx_tls13_client_hello(uint8_t *out, size_t cap, const char *sni,
                              const uint8_t cr[32], const uint8_t sid[32],
                              const uint8_t x25519_pub[32],
                              const char *const alpn[], int nalpn);

struct ntx_tls13_sh {
    uint8_t server_random[32];
    uint8_t key_share_pub[32];
};

#define NTX_TLS13_SH_OK 0
#define NTX_TLS13_SH_BAD (-1)  /* malformed or unsupported parameters */
#define NTX_TLS13_SH_V12 1     /* no supported_versions: server speaks TLS 1.2 or older */
#define NTX_TLS13_SH_HRR 2     /* HelloRetryRequest (we only offer x25519 - fall back) */

/* ServerHello (type 2) validation per RFC 8446 section 4.1.3: version, echoed
 * session id, cipher 0x1301, null compression, supported_versions = 0x0304,
 * key_share x25519; any other extension is rejected. */
int ntx_tls13_parse_server_hello(const uint8_t *msg, size_t len, const uint8_t sid[32],
                                 struct ntx_tls13_sh *out);

/* EncryptedExtensions (type 8): negotiated ALPN (empty string if none). */
int ntx_tls13_parse_ee(const uint8_t *msg, size_t len, char alpn_out[16]);

/* Certificate (type 11): requires an empty certificate_request_context and a
 * well-formed list; returns the leaf (first) certificate DER inside msg. */
int ntx_tls13_parse_cert(const uint8_t *msg, size_t len, const uint8_t **leaf, size_t *leaf_len);

/* CertificateVerify (type 15). transcript_hash = Hash(ClientHello..Certificate).
 * Signed content: 64 x 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 || hash.
 * 0 = ok, -1 = parse / unsupported scheme, -2 = bad signature. */
int ntx_tls13_certverify(const uint8_t *msg, size_t len, const uint8_t *leaf_der,
                         size_t leaf_len, const uint8_t transcript_hash[32]);

/* Server Finished (type 20, 4 + 32 bytes), transcript_hash = Hash(CH..CertificateVerify).
 * 0 = ok, -1 = parse or wrong verify_data. */
int ntx_tls13_finished_verify(const uint8_t *msg, size_t len, const uint8_t server_hs_secret[32],
                              const uint8_t transcript_hash[32]);

/* KeyUpdate (type 24): *request_update = 0/1. 0 = ok, -1 = malformed. */
int ntx_tls13_parse_key_update(const uint8_t *msg, size_t len, int *request_update);

#endif
