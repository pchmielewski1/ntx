#include "ntx_rsa_pkcs1.h"

#include "ntx_bignum.h"
#include "ntx_sha256.h"

#include <string.h>

/* DER DigestInfo prefix for SHA-256 (RFC 8017 / RFC 3447):
 * 30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20 */
static const uint8_t sha256_digestinfo_prefix[19] = {
    0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01,
    0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20
};

/* Sanity-check a public key before doing arithmetic with it. A genuine RSA modulus is
 * odd and a usable public exponent is odd and >= 3. e = 1 is the dangerous one: the
 * encoded message itself then "verifies" as a signature, i.e. anyone can forge. (Trust
 * in the key still comes from the SPKI pin; this only refuses degenerate keys.) */
static int rsa_pubkey_ok(const uint8_t *n, size_t n_len, const uint8_t *e, size_t e_len)
{
    if (!(n[n_len - 1] & 1u) || !(e[e_len - 1] & 1u))
        return 0;
    for (size_t i = 0; i + 1 < e_len; i++)
        if (e[i])
            return 1;
    return e[e_len - 1] >= 3;
}

int ntx_rsa_pkcs1_verify_sha256(const uint8_t *n, size_t n_len,
                                const uint8_t *e, size_t e_len,
                                const uint8_t *sig, size_t sig_len,
                                const uint8_t digest[32])
{
    uint8_t em[NTX_BN_MAX];
    size_t t_len, ps_len, i;
    const uint8_t *t;

    if (!n || !e || !sig || !digest)
        return 0;
    if (n_len == 0 || n_len > NTX_BN_MAX || n_len != sig_len)
        return 0;
    if (e_len == 0 || e_len > NTX_BN_MAX)
        return 0;
    if (!rsa_pubkey_ok(n, n_len, e, e_len))
        return 0;
    /* Signature must be strictly less than modulus. */
    if (ntx_bn_cmp(sig, n, n_len) >= 0)
        return 0;

    ntx_bn_modexp(em, n_len, sig, e, e_len, n);

    /* EMSA-PKCS1-v1_5: 0x00 || 0x01 || PS || 0x00 || T
     * T = DigestInfo = prefix (19) || digest (32) = 51 bytes
     * PS = at least eight 0xFF bytes */
    t_len = sizeof(sha256_digestinfo_prefix) + 32;
    if (n_len < 11 + t_len)
        return 0;
    ps_len = n_len - 3 - t_len;
    if (ps_len < 8)
        return 0;

    /* R7: compare the whole encoded message in one pass (no early exit, so the
     * position of the first mismatch is not observable). */
    {
        uint8_t diff = em[0] | (uint8_t)(em[1] ^ 0x01);
        for (i = 0; i < ps_len; i++)
            diff |= (uint8_t)(em[2 + i] ^ 0xFF);
        diff |= em[2 + ps_len];
        t = em + 3 + ps_len;
        for (i = 0; i < sizeof(sha256_digestinfo_prefix); i++)
            diff |= (uint8_t)(t[i] ^ sha256_digestinfo_prefix[i]);
        for (i = 0; i < 32; i++)
            diff |= (uint8_t)(t[sizeof(sha256_digestinfo_prefix) + i] ^ digest[i]);
        return diff == 0;
    }
}

/* MGF1 with SHA-256 (RFC 8017 appendix B.2.1): out_len bytes from seed. */
static void mgf1_sha256(uint8_t *out, size_t out_len, const uint8_t *seed, size_t seed_len)
{
    uint8_t buf[32 + 4];
    uint8_t h[32];
    size_t off = 0;
    uint32_t ctr = 0;
    /* seed_len is always 32 here (the hash H). */
    memcpy(buf, seed, seed_len);
    while (off < out_len) {
        buf[seed_len + 0] = (uint8_t)(ctr >> 24);
        buf[seed_len + 1] = (uint8_t)(ctr >> 16);
        buf[seed_len + 2] = (uint8_t)(ctr >> 8);
        buf[seed_len + 3] = (uint8_t)ctr;
        ntx_sha256(buf, seed_len + 4, h);
        size_t take = out_len - off < 32 ? out_len - off : 32;
        memcpy(out + off, h, take);
        off += take;
        ctr++;
    }
}

int ntx_rsa_pss_verify_sha256(const uint8_t *n, size_t n_len,
                              const uint8_t *e, size_t e_len,
                              const uint8_t *sig, size_t sig_len,
                              const uint8_t mhash[32])
{
    enum { HLEN = 32, SLEN = 32 };
    uint8_t em_full[NTX_BN_MAX];
    uint8_t db[NTX_BN_MAX];
    uint8_t mp[8 + HLEN + SLEN];
    uint8_t h2[HLEN];
    size_t i;

    memset(db, 0, sizeof db);
    if (!n || !e || !sig || !mhash)
        return 0;
    if (n_len == 0 || n_len > NTX_BN_MAX || n_len != sig_len)
        return 0;
    if (e_len == 0 || e_len > NTX_BN_MAX)
        return 0;
    if (!rsa_pubkey_ok(n, n_len, e, e_len))
        return 0;
    if (ntx_bn_cmp(sig, n, n_len) >= 0)
        return 0;

    /* modBits: bit length of n; require a normal (leading byte set) modulus size. */
    size_t lead = 0;
    while (lead < n_len && n[lead] == 0)
        lead++;
    if (lead == n_len)
        return 0;
    unsigned top = n[lead], topbits = 0;
    while (top) {
        topbits++;
        top >>= 1;
    }
    size_t mod_bits = (n_len - lead - 1) * 8 + topbits;
    size_t em_bits = mod_bits - 1;
    size_t em_len = (em_bits + 7) / 8;
    if (em_len < HLEN + SLEN + 2 || em_len > n_len)
        return 0;

    ntx_bn_modexp(em_full, n_len, sig, e, e_len, n);

    const uint8_t *em = em_full + (n_len - em_len);
    for (i = 0; i < n_len - em_len; i++) { /* leading bytes above emLen must be zero */
        if (em_full[i] != 0)
            return 0;
    }
    if (em[em_len - 1] != 0xBC)
        return 0;

    size_t db_len = em_len - HLEN - 1;
    const uint8_t *masked = em;
    const uint8_t *h = em + db_len;
    unsigned unused_bits = (unsigned)(8 * em_len - em_bits); /* 0..7 */
    if (unused_bits && (masked[0] >> (8 - unused_bits)) != 0)
        return 0;

    mgf1_sha256(db, db_len, h, HLEN);
    for (i = 0; i < db_len; i++)
        db[i] ^= masked[i];
    if (unused_bits)
        db[0] &= (uint8_t)(0xFFu >> unused_bits);

    size_t ps_len = db_len - SLEN - 1;
    uint8_t diff = 0;
    for (i = 0; i < ps_len; i++)
        diff |= db[i];
    diff |= (uint8_t)(db[ps_len] ^ 0x01);
    if (diff != 0)
        return 0;

    memset(mp, 0, 8);
    memcpy(mp + 8, mhash, HLEN);
    memcpy(mp + 8 + HLEN, db + db_len - SLEN, SLEN);
    ntx_sha256(mp, sizeof mp, h2);
    diff = 0;
    for (i = 0; i < HLEN; i++)
        diff |= (uint8_t)(h2[i] ^ h[i]);
    return diff == 0;
}
