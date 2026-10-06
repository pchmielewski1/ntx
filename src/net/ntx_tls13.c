#include "ntx_tls13.h"

#include "ntx_tls.h"

#include "../crypto/ntx_aes.h"
#include "../crypto/ntx_hkdf.h"
#include "../crypto/ntx_hmac.h"
#include "../crypto/ntx_p256.h"
#include "../crypto/ntx_rsa_pkcs1.h"
#include "../crypto/ntx_sha256.h"
#include "../proto/ntx_wire.h"

#include <string.h>

/* RFC 8446 section 4.1.3: ServerHello.random of a HelloRetryRequest. */
static const uint8_t HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C};

static int ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(a[i] ^ b[i]);
    return d == 0;
}

/* ---- key schedule ------------------------------------------------------- */

int ntx_tls13_expand_label(const uint8_t secret[32], const char *label, const uint8_t *ctx,
                           size_t ctx_len, uint8_t *out, size_t out_len) {
    if (!secret || !label || !out || out_len == 0 || out_len > 64) return -1;
    size_t ll = strlen(label);
    if (ll == 0 || ll > 32 || ctx_len > 64 || (ctx_len && !ctx)) return -1;

    uint8_t info[2 + 1 + 6 + 32 + 1 + 64];
    size_t n = 0;
    ntx_wire_wr16(info + n, (uint16_t)out_len);
    n += 2;
    info[n++] = (uint8_t)(6 + ll);
    memcpy(info + n, "tls13 ", 6);
    n += 6;
    memcpy(info + n, label, ll);
    n += ll;
    info[n++] = (uint8_t)ctx_len;
    if (ctx_len) {
        memcpy(info + n, ctx, ctx_len);
        n += ctx_len;
    }
    return ntx_hkdf_expand(secret, info, n, out_len, out);
}

int ntx_tls13_derive_secret(const uint8_t secret[32], const char *label,
                            const uint8_t transcript_hash[32], uint8_t out[32]) {
    if (!transcript_hash) return -1;
    return ntx_tls13_expand_label(secret, label, transcript_hash, 32, out, 32);
}

int ntx_tls13_traffic_keys(const uint8_t secret[32], uint8_t key[16], uint8_t iv[12]) {
    if (ntx_tls13_expand_label(secret, "key", NULL, 0, key, 16) != 0) return -1;
    if (ntx_tls13_expand_label(secret, "iv", NULL, 0, iv, 12) != 0) return -1;
    return 0;
}

static void empty_hash(uint8_t out[32]) {
    ntx_sha256("", 0, out);
}

int ntx_tls13_hs_secrets(const uint8_t ecdhe[32], const uint8_t h_ch_sh[32], uint8_t hs_secret[32],
                         uint8_t c_hs[32], uint8_t s_hs[32]) {
    if (!ecdhe || !h_ch_sh || !hs_secret || !c_hs || !s_hs) return -1;
    static const uint8_t zeros[32] = {0};
    uint8_t early[32], eh[32], derived[32];
    int rc = -1;
    /* early_secret = HKDF-Extract(salt=0, IKM=0^32): we never use a PSK. */
    ntx_hkdf_extract(NULL, 0, zeros, 32, early);
    empty_hash(eh);
    if (ntx_tls13_derive_secret(early, "derived", eh, derived) != 0) goto out;
    ntx_hkdf_extract(derived, 32, ecdhe, 32, hs_secret);
    if (ntx_tls13_derive_secret(hs_secret, "c hs traffic", h_ch_sh, c_hs) != 0) goto out;
    if (ntx_tls13_derive_secret(hs_secret, "s hs traffic", h_ch_sh, s_hs) != 0) goto out;
    rc = 0;
out:
    memset(early, 0, sizeof early);
    memset(derived, 0, sizeof derived);
    return rc;
}

int ntx_tls13_app_secrets(const uint8_t hs_secret[32], const uint8_t h_ch_sfin[32],
                          uint8_t c_ap[32], uint8_t s_ap[32]) {
    if (!hs_secret || !h_ch_sfin || !c_ap || !s_ap) return -1;
    static const uint8_t zeros[32] = {0};
    uint8_t eh[32], derived[32], master[32];
    int rc = -1;
    empty_hash(eh);
    if (ntx_tls13_derive_secret(hs_secret, "derived", eh, derived) != 0) goto out;
    ntx_hkdf_extract(derived, 32, zeros, 32, master);
    if (ntx_tls13_derive_secret(master, "c ap traffic", h_ch_sfin, c_ap) != 0) goto out;
    if (ntx_tls13_derive_secret(master, "s ap traffic", h_ch_sfin, s_ap) != 0) goto out;
    rc = 0;
out:
    memset(derived, 0, sizeof derived);
    memset(master, 0, sizeof master);
    return rc;
}

int ntx_tls13_finished_data(const uint8_t base_secret[32], const uint8_t transcript_hash[32],
                            uint8_t out[32]) {
    if (!base_secret || !transcript_hash || !out) return -1;
    uint8_t fk[32];
    if (ntx_tls13_expand_label(base_secret, "finished", NULL, 0, fk, 32) != 0) return -1;
    ntx_hmac_sha256(fk, 32, transcript_hash, 32, out);
    memset(fk, 0, sizeof fk);
    return 0;
}

/* ---- record protection -------------------------------------------------- */

int ntx_tls13_dir_init(ntx_tls13_dir *d, const uint8_t secret[32]) {
    if (!d || !secret) return -1;
    uint8_t key[16];
    if (ntx_tls13_traffic_keys(secret, key, d->iv) != 0) return -1;
    ntx_aes128_gcm_init(&d->gcm, key);
    memset(key, 0, sizeof key);
    memcpy(d->secret, secret, 32);
    d->seq = 0;
    d->active = 1;
    return 0;
}

int ntx_tls13_dir_update(ntx_tls13_dir *d) {
    if (!d || !d->active) return -1;
    uint8_t next[32];
    if (ntx_tls13_expand_label(d->secret, "traffic upd", NULL, 0, next, 32) != 0) return -1;
    int rc = ntx_tls13_dir_init(d, next);
    memset(next, 0, sizeof next);
    return rc;
}

void ntx_tls13_dir_wipe(ntx_tls13_dir *d) {
    if (d) memset(d, 0, sizeof *d);
}

/* nonce = write_iv XOR (seq as big-endian, left-padded to 12 bytes). */
static void make_nonce(const ntx_tls13_dir *d, uint8_t nonce[12]) {
    memcpy(nonce, d->iv, 12);
    for (int i = 0; i < 8; i++) nonce[4 + i] ^= (uint8_t)(d->seq >> (56 - 8 * i));
}

int ntx_tls13_seal(ntx_tls13_dir *d, uint8_t inner_type, const uint8_t *content, size_t n,
                   uint8_t *rec_out, size_t cap, size_t *rec_len) {
    if (!d || !d->active || !rec_out || !rec_len || (n && !content)) return -1;
    if (n > NTX_TLS13_MAX_PLAINTEXT || cap < n + 22) return -1;
    /* The nonce is derived from seq; never reuse a (key, nonce) pair (RFC 8446 5.3). */
    if (d->seq == UINT64_MAX) return -1;

    size_t clen = n + 1 + 16;
    rec_out[0] = 23; /* opaque_type = application_data */
    rec_out[1] = 3;
    rec_out[2] = 3;
    ntx_wire_wr16(rec_out + 3, (uint16_t)clen);

    /* TLSInnerPlaintext = content || type (no padding) */
    uint8_t *ct = rec_out + 5;
    if (n) memcpy(ct, content, n);
    ct[n] = inner_type;

    uint8_t nonce[12];
    make_nonce(d, nonce);
    if (!ntx_aes128_gcm_seal(&d->gcm, nonce, rec_out, 5, ct, n + 1, ct, ct + n + 1)) return -1;
    d->seq++;
    *rec_len = 5 + clen;
    return 0;
}

int ntx_tls13_open(ntx_tls13_dir *d, const uint8_t hdr[5], const uint8_t *body, size_t body_len,
                   uint8_t *out, size_t cap, size_t *out_len, uint8_t *inner_type) {
    if (!d || !d->active || !hdr || !body || !out || !out_len || !inner_type) return -1;
    if (hdr[0] != 23 || hdr[1] != 3 || hdr[2] != 3) return -1;
    if (body_len < 17 || body_len > NTX_TLS13_MAX_CIPHERTEXT) return -1;
    if (ntx_wire_rd16(hdr + 3) != body_len) return -1;
    size_t pn = body_len - 16;
    if (cap < pn) return -1;
    if (d->seq == UINT64_MAX) return -1;

    uint8_t nonce[12];
    make_nonce(d, nonce);
    if (!ntx_aes128_gcm_open(&d->gcm, nonce, hdr, 5, body, pn, out, body + pn)) return -1;
    d->seq++;

    /* strip zero padding; the last non-zero byte is the real content type */
    size_t i = pn;
    while (i > 0 && out[i - 1] == 0) i--;
    if (i == 0) return -1; /* all zero: no content type (section 5.4: unexpected_message) */
    *inner_type = out[i - 1];
    *out_len = i - 1;
    if (*out_len > NTX_TLS13_MAX_PLAINTEXT) return -1;
    return 0;
}

/* ---- handshake messages ------------------------------------------------- */

/* Extension block lookup (u16 id, u16 len, data). Rejects truncated blocks. */
static const uint8_t *ext_find(const uint8_t *exts, size_t ext_len, uint16_t id, size_t *dlen) {
    size_t o = 0;
    while (o + 4 <= ext_len) {
        uint16_t eid = ntx_wire_rd16(exts + o);
        uint16_t el = ntx_wire_rd16(exts + o + 2);
        if (o + 4 + (size_t)el > ext_len) return NULL;
        if (eid == id) {
            *dlen = el;
            return exts + o + 4;
        }
        o += 4 + (size_t)el;
    }
    return NULL;
}

/* 1 if the extension block is well formed (exactly covers ext_len, no duplicates). */
static int ext_block_ok(const uint8_t *exts, size_t ext_len) {
    size_t o = 0;
    uint16_t seen[16];
    int ns = 0;
    while (o < ext_len) {
        if (o + 4 > ext_len) return 0;
        uint16_t eid = ntx_wire_rd16(exts + o);
        uint16_t el = ntx_wire_rd16(exts + o + 2);
        if (o + 4 + (size_t)el > ext_len) return 0;
        for (int i = 0; i < ns; i++)
            if (seen[i] == eid) return 0;
        if (ns < 16) seen[ns++] = eid;
        o += 4 + (size_t)el;
    }
    return 1;
}

size_t ntx_tls13_client_hello(uint8_t *out, size_t cap, const char *sni, const uint8_t cr[32],
                              const uint8_t sid[32], const uint8_t x25519_pub[32],
                              const char *const alpn[], int nalpn) {
    if (!out || !cr || !sid || !x25519_pub) return 0;
    size_t sn = (sni && sni[0]) ? strlen(sni) : 0;
    if (sn > 255) return 0;
    size_t plen = 0;
    for (int i = 0; i < nalpn; i++) {
        if (!alpn || !alpn[i]) return 0;
        size_t L = strlen(alpn[i]);
        if (L == 0 || L > 255) return 0;
        plen += 1 + L;
    }
    if (plen > 65000) return 0;

    /* 4 hdr + 2 ver + 32 random + 33 sid + 4 suites + 2 comp + 2 ext len
       + groups 8 + sigalgs 10 + supported_versions 7 + key_share 42 */
    size_t need = 146;
    if (sn) need += 9 + sn;
    if (nalpn > 0) need += 6 + plen;
    if (cap < need) return 0;

    size_t o = 0;
    out[o++] = NTX_HS13_CLIENT_HELLO;
    o += 3; /* u24 length, patched below */
    ntx_wire_wr16(out + o, 0x0303); /* legacy_version */
    o += 2;
    memcpy(out + o, cr, 32);
    o += 32;
    out[o++] = 32; /* legacy_session_id (random, echoed by the server) */
    memcpy(out + o, sid, 32);
    o += 32;
    ntx_wire_wr16(out + o, 2); /* cipher_suites */
    o += 2;
    ntx_wire_wr16(out + o, 0x1301); /* TLS_AES_128_GCM_SHA256 */
    o += 2;
    out[o++] = 1; /* legacy_compression_methods = { null } */
    out[o++] = 0;

    size_t ext_at = o;
    o += 2;
    size_t ext_start = o;

    if (sn) { /* server_name */
        ntx_wire_wr16(out + o, 0x0000);
        ntx_wire_wr16(out + o + 2, (uint16_t)(5 + sn));
        ntx_wire_wr16(out + o + 4, (uint16_t)(3 + sn));
        out[o + 6] = 0; /* host_name */
        ntx_wire_wr16(out + o + 7, (uint16_t)sn);
        memcpy(out + o + 9, sni, sn);
        o += 9 + sn;
    }
    /* supported_groups: x25519 */
    ntx_wire_wr16(out + o, 0x000A);
    ntx_wire_wr16(out + o + 2, 4);
    ntx_wire_wr16(out + o + 4, 2);
    ntx_wire_wr16(out + o + 6, 0x001D);
    o += 8;
    /* signature_algorithms: ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256 */
    ntx_wire_wr16(out + o, 0x000D);
    ntx_wire_wr16(out + o + 2, 6);
    ntx_wire_wr16(out + o + 4, 4);
    ntx_wire_wr16(out + o + 6, 0x0403);
    ntx_wire_wr16(out + o + 8, 0x0804);
    o += 10;
    /* supported_versions: TLS 1.3 only */
    ntx_wire_wr16(out + o, 0x002B);
    ntx_wire_wr16(out + o + 2, 3);
    out[o + 4] = 2;
    ntx_wire_wr16(out + o + 5, 0x0304);
    o += 7;
    /* key_share: one x25519 share */
    ntx_wire_wr16(out + o, 0x0033);
    ntx_wire_wr16(out + o + 2, 38);
    ntx_wire_wr16(out + o + 4, 36);
    ntx_wire_wr16(out + o + 6, 0x001D);
    ntx_wire_wr16(out + o + 8, 32);
    memcpy(out + o + 10, x25519_pub, 32);
    o += 42;
    if (nalpn > 0) { /* ALPN */
        ntx_wire_wr16(out + o, 0x0010);
        ntx_wire_wr16(out + o + 2, (uint16_t)(2 + plen));
        ntx_wire_wr16(out + o + 4, (uint16_t)plen);
        o += 6;
        for (int i = 0; i < nalpn; i++) {
            size_t L = strlen(alpn[i]);
            out[o++] = (uint8_t)L;
            memcpy(out + o, alpn[i], L);
            o += L;
        }
    }

    ntx_wire_wr16(out + ext_at, (uint16_t)(o - ext_start));
    ntx_wire_wr24(out + 1, (uint32_t)(o - 4));
    return o;
}

int ntx_tls13_parse_server_hello(const uint8_t *msg, size_t len, const uint8_t sid[32],
                                 struct ntx_tls13_sh *out) {
    if (!msg || !sid || !out || len < 4 || msg[0] != NTX_HS13_SERVER_HELLO) return NTX_TLS13_SH_BAD;
    size_t blen = ntx_wire_rd24(msg + 1);
    if (4 + blen != len || blen < 38) return NTX_TLS13_SH_BAD;
    const uint8_t *b = msg + 4;
    if (ntx_wire_rd16(b) != 0x0303) return NTX_TLS13_SH_BAD;
    memcpy(out->server_random, b + 2, 32);
    size_t o = 34;
    size_t sidl = b[o++];
    if (o + sidl + 3 > blen) return NTX_TLS13_SH_BAD;
    const uint8_t *sid_echo = b + o;
    o += sidl;
    uint16_t cipher = ntx_wire_rd16(b + o);
    o += 2;
    uint8_t comp = b[o++];
    if (o == blen) return NTX_TLS13_SH_V12; /* TLS 1.2 ServerHello without extensions */
    if (o + 2 > blen) return NTX_TLS13_SH_BAD;
    size_t elen = ntx_wire_rd16(b + o);
    o += 2;
    if (o + elen != blen) return NTX_TLS13_SH_BAD;
    const uint8_t *exts = b + o;
    if (!ext_block_ok(exts, elen)) return NTX_TLS13_SH_BAD;

    size_t dl = 0;
    const uint8_t *sv = ext_find(exts, elen, 0x002B, &dl);
    if (!sv) return NTX_TLS13_SH_V12;
    if (dl != 2 || ntx_wire_rd16(sv) != 0x0304) return NTX_TLS13_SH_BAD;

    /* from here on this must be a valid TLS 1.3 ServerHello */
    if (ct_eq(out->server_random, HRR_RANDOM, 32)) return NTX_TLS13_SH_HRR;
    if (sidl != 32 || !ct_eq(sid_echo, sid, 32)) return NTX_TLS13_SH_BAD;
    if (cipher != 0x1301 || comp != 0) return NTX_TLS13_SH_BAD;

    /* only supported_versions and key_share are legal in a ServerHello we can accept */
    size_t p = 0;
    while (p < elen) {
        uint16_t eid = ntx_wire_rd16(exts + p);
        if (eid != 0x002B && eid != 0x0033) return NTX_TLS13_SH_BAD;
        p += 4 + (size_t)ntx_wire_rd16(exts + p + 2);
    }
    const uint8_t *ks = ext_find(exts, elen, 0x0033, &dl);
    if (!ks || dl != 36) return NTX_TLS13_SH_BAD;
    if (ntx_wire_rd16(ks) != 0x001D || ntx_wire_rd16(ks + 2) != 32) return NTX_TLS13_SH_BAD;
    memcpy(out->key_share_pub, ks + 4, 32);
    return NTX_TLS13_SH_OK;
}

int ntx_tls13_parse_ee(const uint8_t *msg, size_t len, char alpn_out[16]) {
    if (!msg || !alpn_out || len < 6 || msg[0] != NTX_HS13_ENCRYPTED_EXTENSIONS) return -1;
    size_t blen = ntx_wire_rd24(msg + 1);
    if (4 + blen != len) return -1;
    size_t elen = ntx_wire_rd16(msg + 4);
    if (2 + elen != blen) return -1;
    const uint8_t *exts = msg + 6;
    if (!ext_block_ok(exts, elen)) return -1;
    alpn_out[0] = 0;
    size_t dl = 0;
    const uint8_t *a = ext_find(exts, elen, 0x0010, &dl);
    if (!a) return 0;
    if (dl < 4) return -1;
    size_t ll = ntx_wire_rd16(a);
    if (ll + 2 != dl) return -1;
    size_t nl = a[2];
    if (nl == 0 || nl + 1 != ll || nl >= 16) return -1; /* exactly one protocol name */
    memcpy(alpn_out, a + 3, nl);
    alpn_out[nl] = 0;
    return 0;
}

int ntx_tls13_parse_cert(const uint8_t *msg, size_t len, const uint8_t **leaf, size_t *leaf_len) {
    if (!msg || !leaf || !leaf_len || len < 8 || msg[0] != NTX_HS13_CERTIFICATE) return -1;
    size_t blen = ntx_wire_rd24(msg + 1);
    if (4 + blen != len) return -1;
    if (msg[4] != 0) return -1; /* certificate_request_context must be empty for server auth */
    size_t list = ntx_wire_rd24(msg + 5);
    if (1 + 3 + list != blen || list < 5) return -1;
    const uint8_t *p = msg + 8;
    size_t left = list;
    const uint8_t *first = NULL;
    size_t first_len = 0;
    while (left) {
        if (left < 3) return -1;
        size_t cl = ntx_wire_rd24(p);
        p += 3;
        left -= 3;
        if (cl == 0 || cl + 2 > left) return -1;
        const uint8_t *der = p;
        p += cl;
        left -= cl;
        size_t xl = ntx_wire_rd16(p);
        p += 2;
        left -= 2;
        if (xl > left) return -1;
        p += xl;
        left -= xl;
        if (!first) {
            first = der;
            first_len = cl;
        }
    }
    if (!first) return -1;
    *leaf = first;
    *leaf_len = first_len;
    return 0;
}

int ntx_tls13_certverify(const uint8_t *msg, size_t len, const uint8_t *leaf_der, size_t leaf_len,
                         const uint8_t H[32]) {
    if (!msg || !leaf_der || !H || len < 8 || msg[0] != NTX_HS13_CERTIFICATE_VERIFY) return -1;
    size_t blen = ntx_wire_rd24(msg + 1);
    if (4 + blen != len || blen < 4) return -1;
    uint16_t sigalg = ntx_wire_rd16(msg + 4);
    size_t siglen = ntx_wire_rd16(msg + 6);
    if (4 + siglen != blen) return -1;
    const uint8_t *sig = msg + 8;

    uint8_t sm[64 + 33 + 1 + 32];
    memset(sm, 0x20, 64);
    memcpy(sm + 64, "TLS 1.3, server CertificateVerify", 33);
    sm[97] = 0;
    memcpy(sm + 98, H, 32);
    uint8_t digest[32];
    ntx_sha256(sm, sizeof sm, digest);

    const uint8_t *spki;
    size_t spki_len;
    if (ntx_tls_spki_from_cert(leaf_der, leaf_len, &spki, &spki_len) != 0) return -1;

    if (sigalg == 0x0403) { /* ecdsa_secp256r1_sha256 */
        uint8_t qx[32], qy[32], r[32], s[32];
        if (ntx_p256_pubkey_from_spki(spki, spki_len, qx, qy) != 0) return -1;
        if (ntx_p256_sig_from_der(sig, siglen, r, s) != 0) return -1;
        return ntx_p256_ecdsa_verify_sha256(qx, qy, r, s, digest) ? 0 : -2;
    }
    if (sigalg == 0x0804) { /* rsa_pss_rsae_sha256 */
        const uint8_t *mod, *exp;
        size_t mod_len, exp_len;
        if (ntx_tls_rsa_pub_from_spki(spki, spki_len, &mod, &mod_len, &exp, &exp_len) != 0)
            return -1;
        if (siglen != mod_len) return -1;
        return ntx_rsa_pss_verify_sha256(mod, mod_len, exp, exp_len, sig, siglen, digest) ? 0 : -2;
    }
    return -1; /* we only advertised 0x0403 and 0x0804 */
}

int ntx_tls13_finished_verify(const uint8_t *msg, size_t len, const uint8_t server_hs_secret[32],
                              const uint8_t transcript_hash[32]) {
    if (!msg || len != 36 || msg[0] != NTX_HS13_FINISHED) return -1;
    if (ntx_wire_rd24(msg + 1) != 32) return -1;
    uint8_t expect[32];
    if (ntx_tls13_finished_data(server_hs_secret, transcript_hash, expect) != 0) return -1;
    int ok = ct_eq(expect, msg + 4, 32);
    memset(expect, 0, sizeof expect);
    return ok ? 0 : -1;
}

int ntx_tls13_parse_key_update(const uint8_t *msg, size_t len, int *request_update) {
    if (!msg || !request_update || len != 5 || msg[0] != NTX_HS13_KEY_UPDATE) return -1;
    if (ntx_wire_rd24(msg + 1) != 1 || msg[4] > 1) return -1;
    *request_update = msg[4];
    return 0;
}
