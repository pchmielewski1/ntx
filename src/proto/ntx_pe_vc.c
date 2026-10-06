#include "ntx_pe.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_rc4.h"
#include "../crypto/ntx_dh.h"
#include "../crypto/ntx_rng.h"

#include <string.h>

/* MSE vc/crypto layer (pe_build_dh_out, pe_compute_skey_obf, pe_derive_rc4, ...)
   — split out of ntx_pe.c. */

void pe_rc4_copy(ntx_rc4 *dst, const ntx_rc4 *src) {
    memcpy(dst, src, sizeof *dst);
}

void pe_xor20(uint8_t *dst, const uint8_t *a, const uint8_t *b) {
    for (int i = 0; i < 20; i++) dst[i] = a[i] ^ b[i];
}

void pe_derive_rc4(ntx_pe *pe) {
    static const char keyA[] = "keyA";
    static const char keyB[] = "keyB";
    uint8_t send_key[20], recv_key[20];
    uint8_t buf[4 + NTX_DH_KEY_LEN + 20];

    memcpy(buf, keyA, 4);
    memcpy(buf + 4, pe->secret_buf, NTX_DH_KEY_LEN);
    memcpy(buf + 4 + NTX_DH_KEY_LEN, pe->infohash, 20);
    if (pe->role == NTX_PE_INITIATOR)
        ntx_sha1(buf, sizeof buf, send_key);
    else
        ntx_sha1(buf, sizeof buf, recv_key);

    memcpy(buf, keyB, 4);
    memcpy(buf + 4, pe->secret_buf, NTX_DH_KEY_LEN);
    memcpy(buf + 4 + NTX_DH_KEY_LEN, pe->infohash, 20);
    if (pe->role == NTX_PE_INITIATOR)
        ntx_sha1(buf, sizeof buf, recv_key);
    else
        ntx_sha1(buf, sizeof buf, send_key);

    /* Fixed 20-byte SHA-1 keys: init cannot fail here (only klen == 0 does). */
    (void)ntx_rc4_init_bep9(&pe->send_rc4, send_key, 20);
    (void)ntx_rc4_init_bep9(&pe->recv_rc4, recv_key, 20);
}

void pe_build_dh_out(ntx_pe *pe) {
    ntx_dh_export_key(pe->dh.local_key, pe->out);
    int pad = (int)(ntx_rand_u32() % 512);
    ntx_rand_bytes(pe->out + NTX_DH_KEY_LEN, (size_t)pad);
    pe->outn = NTX_DH_KEY_LEN + (size_t)pad;
    pe->sent = 0;
}

void pe_rc4_discard(ntx_pe *pe, size_t n) {
    uint8_t junk[256];
    while (n > 0) {
        size_t chunk = n > sizeof junk ? sizeof junk : n;
        ntx_rc4_xor(&pe->recv_rc4, junk, chunk);
        n -= chunk;
    }
}

int pe_verify_vc(const uint8_t *p) {
    for (int i = 0; i < 8; i++)
        if (p[i] != 0) return 0;
    return 1;
}

void pe_compute_skey_obf(const ntx_pe *pe, uint8_t out[20]) {
    static const char req2[] = "req2";
    static const char req3[] = "req3";
    uint8_t req2h[20], req3h[20];
    ntx_sha1_ctx c;
    ntx_sha1_init(&c);
    ntx_sha1_update(&c, req2, 4);
    ntx_sha1_update(&c, pe->infohash, 20);
    ntx_sha1_final(&c, req2h);
    ntx_sha1_init(&c);
    ntx_sha1_update(&c, req3, 4);
    ntx_sha1_update(&c, pe->secret_buf, NTX_DH_KEY_LEN);
    ntx_sha1_final(&c, req3h);
    pe_xor20(out, req2h, req3h);
}

int pe_verify_skey_hash(const ntx_pe *pe, const uint8_t *obf, const uint8_t hash[20]) {
    static const char req2[] = "req2";
    static const char req3[] = "req3";
    uint8_t req2h[20], req3h[20], expect[20];
    ntx_sha1_ctx c;
    ntx_sha1_init(&c);
    ntx_sha1_update(&c, req2, 4);
    ntx_sha1_update(&c, hash, 20);
    ntx_sha1_final(&c, req2h);
    ntx_sha1_init(&c);
    ntx_sha1_update(&c, req3, 4);
    ntx_sha1_update(&c, pe->secret_buf, NTX_DH_KEY_LEN);
    ntx_sha1_final(&c, req3h);
    pe_xor20(expect, req2h, req3h);
    return memcmp(obf, expect, 20) == 0;
}

int pe_verify_skey(ntx_pe *pe, const uint8_t *obf) {
    if (pe_verify_skey_hash(pe, obf, pe->infohash)) return 1;
    for (int i = 0; i < pe->infohash_cand_n; i++)
        if (pe_verify_skey_hash(pe, obf, pe->infohash_cand[i]) == 1) {
            memcpy(pe->infohash, pe->infohash_cand[i], 20);
            return 1;
        }
    return 0;
}

void pe_compute_sync_hash(ntx_pe *pe) {
    static const char req1[] = "req1";
    ntx_sha1_ctx hc;
    ntx_sha1_init(&hc);
    ntx_sha1_update(&hc, req1, 4);
    ntx_sha1_update(&hc, pe->secret_buf, NTX_DH_KEY_LEN);
    ntx_sha1_final(&hc, pe->sync_hash);
}

