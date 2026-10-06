/* HMAC-SHA1/-SHA256 (one-shot and incremental), HKDF-Expand (including outputs well past 100
 * bytes and the RFC 5869 limit of 255*32) and the TLS 1.2 PRF (labels/seeds longer than the
 * old 128-byte scratch limit), against Python-made vectors (test/scripts/mac_vectors.py). */
#include "../src/net/ntx_tls_rec.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/ui/ntx_diag.c"
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
    FILE *f = fopen("test/vectors/mac/vectors.txt", "r");
    if (!f) { fprintf(stderr, "FAIL open test/vectors/mac/vectors.txt (run from repo root)\n"); return 1; }
    static char line[20000], s[5][17000];
    static uint8_t a[8200], b[8200], c[8200], got[8200];
    int ln = 0, n1 = 0, n256 = 0, nk = 0, nprf = 0;
    while (fgets(line, sizeof line, f)) {
        ln++;
        if (line[0] == '#' || line[0] == '\n') continue;
        if (strncmp(line, "hmac1 ", 6) == 0 || strncmp(line, "hmac256 ", 8) == 0) {
            int is1 = line[4] == '1';
            if (sscanf(line, "%*s %16999s %16999s %16999s", s[0], s[1], s[2]) != 3) return fail("parse", ln);
            size_t kl = unhex(s[0], a), ml = unhex(s[1], b);
            unhex(s[2], c);
            size_t ol = is1 ? 20 : 32;
            if (is1) ntx_hmac_sha1(kl ? a : NULL, kl, b, ml, got);
            else ntx_hmac_sha256(kl ? a : NULL, kl, b, ml, got);
            if (memcmp(got, c, ol) != 0) return fail(is1 ? "hmac-sha1" : "hmac-sha256", ln);
            if (!is1) { /* incremental, in awkward pieces, must agree with the one-shot result */
                ntx_hmac_sha256_ctx h;
                ntx_hmac_sha256_init(&h, kl ? a : NULL, kl);
                for (size_t o = 0, step = 1; o < ml; o += step, step = step % 29 + 1) {
                    size_t m = ml - o < step ? ml - o : step;
                    ntx_hmac_sha256_update(&h, b + o, m);
                }
                ntx_hmac_sha256_final(&h, got);
                if (memcmp(got, c, 32) != 0) return fail("hmac-sha256-incremental", ln);
            }
            if (is1) n1++; else n256++;
        } else if (strncmp(line, "hkdf ", 5) == 0) {
            int L;
            if (sscanf(line, "hkdf %16999s %16999s %d %16999s", s[0], s[1], &L, s[2]) != 4) return fail("parse", ln);
            unhex(s[0], a);
            size_t il = unhex(s[1], b);
            unhex(s[2], c);
            memset(got, 0xEE, sizeof got);
            if (ntx_hkdf_expand(a, il ? b : NULL, il, (size_t)L, got) != 0) return fail("hkdf rc", ln);
            if (memcmp(got, c, (size_t)L) != 0) return fail("hkdf okm", ln);
            if (got[L] != 0xEE) return fail("hkdf overran the output", ln);
            nk++;
        } else if (strncmp(line, "prf ", 4) == 0) {
            int L;
            static char lab[2000];
            if (sscanf(line, "prf %16999s %1999s %16999s %d %16999s", s[0], lab, s[1], &L, s[2]) != 5) return fail("parse", ln);
            size_t sl = unhex(s[0], a);
            uint8_t lb[1000];
            size_t ll = unhex(lab, lb);
            lb[ll] = 0;
            size_t seedl = unhex(s[1], b);
            unhex(s[2], c);
            memset(got, 0xEE, sizeof got);
            tls12_prf(a, sl, (const char *)lb, b, seedl, got, (size_t)L);
            if (memcmp(got, c, (size_t)L) != 0) return fail("tls12 prf", ln);
            if (got[L] != 0xEE) return fail("prf overran the output", ln);
            nprf++;
        }
    }
    fclose(f);

    /* HKDF-Expand limits (RFC 5869 sec. 2.3: L <= 255 * HashLen) and argument errors. */
    {
        uint8_t prk[32] = {1}, okm[255 * 32 + 1];
        if (ntx_hkdf_expand(prk, NULL, 0, 255 * 32, okm) != 0) return fail("hkdf 8160 refused", 0);
        if (ntx_hkdf_expand(prk, NULL, 0, 255 * 32 + 1, okm) != -1) return fail("hkdf 8161 accepted", 0);
        if (ntx_hkdf_expand(prk, NULL, 0, 0, okm) != -1) return fail("hkdf L=0 accepted", 0);
        if (ntx_hkdf_expand(NULL, NULL, 0, 32, okm) != -1) return fail("hkdf NULL prk accepted", 0);
        if (ntx_hkdf_expand(prk, NULL, 5, 32, okm) != -1) return fail("hkdf NULL info with length accepted", 0);
        if (ntx_hkdf_expand(prk, NULL, 0, 32, NULL) != -1) return fail("hkdf NULL okm accepted", 0);
    }
    if (n1 < 80 || n256 < 80 || nk < 50 || nprf < 40) {
        fprintf(stderr, "FAIL too few vectors (%d/%d/%d/%d)\n", n1, n256, nk, nprf);
        return 1;
    }
    printf("PASS mac-kat (hmac1=%d hmac256=%d hkdf=%d prf=%d)\n", n1, n256, nk, nprf);
    return 0;
}
