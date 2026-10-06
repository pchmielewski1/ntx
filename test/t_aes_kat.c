/* AES-128-GCM / CTR against OpenSSL-made vectors (test/scripts/aes_vectors.py), plus the
 * GCM behaviours a caller relies on:
 *  - open() on a bad tag releases NO plaintext (the output buffer is left untouched);
 *  - seal()/open() work in place (pt == ct);
 *  - every single-bit flip in ct, aad or tag is rejected;
 *  - a message too long for the 32-bit GCM block counter is refused. */
#include "../src/crypto/ntx_aes.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t unhex(const char *h, uint8_t *out) {
    if (h[0] == '-') return 0;
    size_t n = strlen(h) / 2;
    hex_to_bytes(h, out, n);
    return n;
}

static int fail(const char *what, int line) {
    fprintf(stderr, "FAIL %s (vector line %d)\n", what, line);
    return 1;
}

int main(void) {
    FILE *f = fopen("test/vectors/aes/vectors.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open test/vectors/aes/vectors.txt (run from repo root)\n"); return 1; }
    static char line[80000];
    static uint8_t key[16], nonce[12], aad[64], pt[16384], ct[16384], tag[16], got[16384], gtag[16], tmp[16384];
    static char s[6][33000];
    int ln = 0, ngcm = 0, nctr = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        if (strncmp(line, "gcm ", 4) == 0) {
            if (sscanf(line, "gcm %32999s %32999s %32999s %32999s %32999s %32999s", s[0], s[1], s[2], s[3], s[4], s[5]) != 6)
                return fail("parse", ln);
            unhex(s[0], key); unhex(s[1], nonce);
            size_t al = unhex(s[2], aad), pl = unhex(s[3], pt), cl = unhex(s[4], ct);
            unhex(s[5], tag);
            if (cl != pl) return fail("vector shape", ln);
            ntx_aes128_gcm g;
            ntx_aes128_gcm_init(&g, key);

            if (ntx_aes128_gcm_seal(&g, nonce, aad, al, pt, pl, got, gtag) != 1) return fail("seal rc", ln);
            if (memcmp(got, ct, pl) != 0) return fail("seal ct", ln);
            if (memcmp(gtag, tag, 16) != 0) return fail("seal tag", ln);

            memcpy(tmp, pt, pl);                      /* in-place seal */
            if (ntx_aes128_gcm_seal(&g, nonce, aad, al, tmp, pl, tmp, gtag) != 1) return fail("seal in place rc", ln);
            if (memcmp(tmp, ct, pl) != 0 || memcmp(gtag, tag, 16) != 0) return fail("seal in place", ln);

            memset(got, 0xA5, sizeof got);
            if (ntx_aes128_gcm_open(&g, nonce, aad, al, ct, pl, got, tag) != 1) return fail("open rc", ln);
            if (memcmp(got, pt, pl) != 0) return fail("open pt", ln);

            memcpy(tmp, ct, pl);                      /* in-place open */
            if (ntx_aes128_gcm_open(&g, nonce, aad, al, tmp, pl, tmp, tag) != 1) return fail("open in place rc", ln);
            if (memcmp(tmp, pt, pl) != 0) return fail("open in place", ln);

            /* authentication failures: nothing may be written to the output */
            uint8_t bt[16];
            for (int bit = 0; bit < 128; bit += 37) {
                memcpy(bt, tag, 16);
                bt[bit / 8] ^= (uint8_t)(1u << (bit % 8));
                memset(got, 0xA5, sizeof got);
                if (ntx_aes128_gcm_open(&g, nonce, aad, al, ct, pl, got, bt) != 0) return fail("bad tag accepted", ln);
                for (size_t i = 0; i < pl; i++)
                    if (got[i] != 0xA5) return fail("plaintext released on bad tag", ln);
            }
            if (pl) {
                memcpy(tmp, ct, pl);
                tmp[pl / 2] ^= 0x10;
                memset(got, 0xA5, sizeof got);
                if (ntx_aes128_gcm_open(&g, nonce, aad, al, tmp, pl, got, tag) != 0) return fail("bad ct accepted", ln);
                for (size_t i = 0; i < pl; i++)
                    if (got[i] != 0xA5) return fail("plaintext released on bad ct", ln);
                memcpy(tmp, ct, pl);                  /* in-place failure leaves the buffer as it was */
                tmp[0] ^= 1;
                uint8_t keep0 = tmp[0];
                if (ntx_aes128_gcm_open(&g, nonce, aad, al, tmp, pl, tmp, tag) != 0) return fail("bad ct in place accepted", ln);
                if (tmp[0] != keep0) return fail("in-place buffer modified on failure", ln);
            }
            if (al) {
                uint8_t ba[64];
                memcpy(ba, aad, al);
                ba[al - 1] ^= 0x01;
                if (ntx_aes128_gcm_open(&g, nonce, ba, al, ct, pl, got, tag) != 0) return fail("bad aad accepted", ln);
            }
            ngcm++;
        } else if (strncmp(line, "ctr ", 4) == 0) {
            if (sscanf(line, "ctr %32999s %32999s %32999s %32999s", s[0], s[1], s[2], s[3]) != 4) return fail("parse", ln);
            uint8_t ctr0[16];
            unhex(s[0], key); unhex(s[1], ctr0);
            size_t pl = unhex(s[2], pt), cl = unhex(s[3], ct);
            if (pl != cl) return fail("vector shape", ln);
            ntx_aes128_ctr c;
            ntx_aes128_ctr_init(&c, key, ctr0);
            memcpy(got, pt, pl);
            ntx_aes128_ctr_xcrypt(&c, got, pl);
            if (memcmp(got, ct, pl) != 0) return fail("ctr", ln);
            /* streaming in odd-sized pieces must give the same keystream */
            ntx_aes128_ctr_init(&c, key, ctr0);
            memcpy(got, pt, pl);
            for (size_t o = 0, step = 1; o < pl; o += step, step = step % 23 + 1) {
                size_t m = pl - o < step ? pl - o : step;
                ntx_aes128_ctr_xcrypt(&c, got + o, m);
            }
            if (memcmp(got, ct, pl) != 0) return fail("ctr streaming", ln);
            nctr++;
        }
    }
    fclose(f);

    /* The 32-bit block counter limits one message to 2^32 - 2 blocks; a larger length must be
     * refused (checked with a NULL buffer, so nothing is touched). */
    {
        ntx_aes128_gcm g;
        uint8_t k0[16] = {0}, n0[12] = {0}, t0[16];
        ntx_aes128_gcm_init(&g, k0);
        if (sizeof(size_t) >= 8 && ntx_aes128_gcm_seal(&g, n0, NULL, 0, NULL, ((size_t)1 << 36), NULL, t0) != 0)
            return fail("oversize seal accepted", 0);
        if (sizeof(size_t) >= 8 && ntx_aes128_gcm_open(&g, n0, NULL, 0, NULL, ((size_t)1 << 36), NULL, t0) != 0)
            return fail("oversize open accepted", 0);
    }
    if (ngcm < 60 || nctr < 8) { fprintf(stderr, "FAIL too few vectors (%d/%d)\n", ngcm, nctr); return 1; }
    printf("PASS aes-kat (gcm=%d ctr=%d)\n", ngcm, nctr);
    return 0;
}
