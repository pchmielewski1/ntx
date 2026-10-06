#include "ntx_rc4.h"

static void ntx_rc4_byte(ntx_rc4 *r, uint8_t *out) {
    r->i = (uint8_t)(r->i + 1);
    r->j = (uint8_t)(r->j + r->S[r->i]);
    uint8_t t = r->S[r->i];
    r->S[r->i] = r->S[r->j];
    r->S[r->j] = t;
    *out = r->S[(r->S[r->i] + r->S[r->j]) & 0xFF];
}

int ntx_rc4_init(ntx_rc4 *r, const uint8_t *key, uint16_t klen) {
    if (!key || klen == 0) { /* R6: key[x % 0] would divide by zero */
        for (int x = 0; x < 256; x++) r->S[x] = 0;
        r->i = 0;
        r->j = 0;
        r->disc = 0;
        r->invalid = 1;
        return -1;
    }
    r->invalid = 0;
    for (int x = 0; x < 256; x++) {
        r->S[x] = (uint8_t)x;
    }
    uint8_t j = 0;
    for (int x = 0; x < 256; x++) {
        j = (uint8_t)(j + r->S[x] + key[x % klen]);
        uint8_t t = r->S[x];
        r->S[x] = r->S[j];
        r->S[j] = t;
    }
    r->i = 0;
    r->j = 0;
    r->disc = 0;
    return 0;
}

void ntx_rc4_xor(ntx_rc4 *r, uint8_t *buf, size_t n) {
    if (r->invalid) { /* fail closed: never emit data that looks encrypted but is not */
        for (size_t k = 0; k < n; k++) buf[k] = 0;
        return;
    }
    for (uint32_t d = 0; d < r->disc; d++) {
        uint8_t b;
        ntx_rc4_byte(r, &b);
    }
    r->disc = 0;
    for (size_t k = 0; k < n; k++) {
        uint8_t b;
        ntx_rc4_byte(r, &b);
        buf[k] ^= b;
    }
}

int ntx_rc4_init_bep9(ntx_rc4 *r, const uint8_t *key, uint16_t klen) {
    int rc = ntx_rc4_init(r, key, klen);
    if (rc == 0) r->disc = 1024;
    return rc;
}
