/* TLS 1.3 building blocks (src/net/ntx_tls13.c) against an independent Python
 * reference (test/scripts/tls13_ref.py -> test/vectors/tls13/kat.txt), plus
 * negative/edge cases for every parser and for the record layer in ntx_tls.c
 * (post-handshake KeyUpdate / NewSessionTicket / alerts).
 *
 * End-to-end handshakes are covered by t_tls_golden.c (frozen server streams)
 * and test/tls13_interop.sh (live OpenSSL).
 */
#define NTX_TLS13_LIVE 1
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls13.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

static int g_fail;

#define CHECK(cond, name)                                  \
    do {                                                   \
        if (!(cond)) {                                     \
            printf("FAIL %s (line %d)\n", name, __LINE__); \
            g_fail = 1;                                    \
        }                                                  \
    } while (0)

/* ---- kat.txt ------------------------------------------------------------ */
#define MAXKV 256
static char *g_k[MAXKV], *g_v[MAXKV];
static int g_n;

static void load_kat(void) {
    size_t n;
    uint8_t *raw = read_file("test/vectors/tls13/kat.txt", &n);
    char *s = malloc(n + 1);
    if (!s) exit(1);
    memcpy(s, raw, n);
    s[n] = 0;
    free(raw);
    for (char *line = strtok(s, "\n"); line && g_n < MAXKV; line = strtok(NULL, "\n")) {
        if (line[0] == '#') continue;
        char *eq = strchr(line, '=');
        if (!eq) continue;
        *eq = 0;
        g_k[g_n] = line;
        g_v[g_n++] = eq + 1;
    }
}

static const char *kv(const char *k) {
    for (int i = 0; i < g_n; i++)
        if (!strcmp(g_k[i], k)) return g_v[i];
    printf("FAIL missing kat key %s\n", k);
    exit(1);
}

/* decode hex value; returns malloc'd buffer (never NULL), length in *len */
static uint8_t *kb(const char *k, size_t *len) {
    const char *h = kv(k);
    size_t n = strlen(h) / 2;
    uint8_t *b = malloc(n ? n : 1);
    if (!b) exit(1);
    hex_to_bytes(h, b, n);
    if (len) *len = n;
    return b;
}

static int kb_eq(const char *k, const uint8_t *got, size_t n) {
    size_t l;
    uint8_t *e = kb(k, &l);
    int ok = (l == n) && memcmp(e, got, n) == 0;
    free(e);
    return ok;
}

/* ---- tests -------------------------------------------------------------- */

static void test_key_schedule(void) {
    size_t n;
    uint8_t *ecdhe = kb("ecdhe", &n), *h_sh = kb("h_ch_sh", NULL), *h_fin = kb("h_sfin", NULL);
    uint8_t hs[32], c_hs[32], s_hs[32], c_ap[32], s_ap[32];
    CHECK(ntx_tls13_hs_secrets(ecdhe, h_sh, hs, c_hs, s_hs) == 0, "hs_secrets rc");
    CHECK(kb_eq("hs_secret", hs, 32), "hs_secret");
    CHECK(kb_eq("c_hs", c_hs, 32), "c_hs");
    CHECK(kb_eq("s_hs", s_hs, 32), "s_hs");
    CHECK(ntx_tls13_app_secrets(hs, h_fin, c_ap, s_ap) == 0, "app_secrets rc");
    CHECK(kb_eq("c_ap", c_ap, 32), "c_ap");
    CHECK(kb_eq("s_ap", s_ap, 32), "s_ap");

    uint8_t key[16], iv[12];
    CHECK(ntx_tls13_traffic_keys(c_hs, key, iv) == 0, "traffic_keys rc");
    CHECK(kb_eq("c_hs_key", key, 16) && kb_eq("c_hs_iv", iv, 12), "c_hs key/iv");
    CHECK(ntx_tls13_traffic_keys(s_hs, key, iv) == 0 && kb_eq("s_hs_key", key, 16) && kb_eq("s_hs_iv", iv, 12),
          "s_hs key/iv");
    CHECK(ntx_tls13_traffic_keys(s_ap, key, iv) == 0 && kb_eq("s_ap_key", key, 16) && kb_eq("s_ap_iv", iv, 12),
          "s_ap key/iv");

    ntx_tls13_dir d;
    CHECK(ntx_tls13_dir_init(&d, s_ap) == 0, "dir_init");
    d.seq = 99;
    CHECK(ntx_tls13_dir_update(&d) == 0, "dir_update rc");
    CHECK(kb_eq("s_ap_next", d.secret, 32) && d.seq == 0, "KeyUpdate secret + seq reset");
    ntx_tls13_dir_wipe(&d);
    CHECK(!d.active && ntx_tls13_dir_update(&d) != 0, "dir_wipe disables");
    free(ecdhe);
    free(h_sh);
    free(h_fin);
}

static void test_expand_label(void) {
    uint8_t *sec = kb("el_secret", NULL);
    for (int i = 0; i < 5; i++) {
        char k[32];
        snprintf(k, sizeof k, "el%d_label", i);
        const char *label = kv(k);
        snprintf(k, sizeof k, "el%d_ctx", i);
        size_t cl;
        uint8_t *ctx = kb(k, &cl);
        snprintf(k, sizeof k, "el%d_len", i);
        size_t n = (size_t)atoi(kv(k));
        uint8_t out[64];
        snprintf(k, sizeof k, "el%d_out", i);
        CHECK(ntx_tls13_expand_label(sec, label, ctx, cl, out, n) == 0 && kb_eq(k, out, n), "expand_label vector");
        free(ctx);
    }
    uint8_t out[64], z[1] = { 0 };
    CHECK(ntx_tls13_expand_label(sec, "key", NULL, 0, out, 0) != 0, "expand len 0");
    CHECK(ntx_tls13_expand_label(sec, "key", NULL, 0, out, 65) != 0, "expand len 65");
    CHECK(ntx_tls13_expand_label(sec, NULL, NULL, 0, out, 16) != 0, "expand null label");
    CHECK(ntx_tls13_expand_label(sec, "", NULL, 0, out, 16) != 0, "expand empty label");
    CHECK(ntx_tls13_expand_label(sec, "key", NULL, 5, out, 16) != 0, "expand ctx without ptr");
    CHECK(ntx_tls13_expand_label(NULL, "key", z, 1, out, 16) != 0, "expand null secret");
    free(sec);
}

static void test_finished(void) {
    uint8_t *base = kb("fin_base", NULL), *th = kb("fin_th", NULL);
    size_t ml;
    uint8_t *msg = kb("fin_msg", &ml);
    uint8_t v[32];
    CHECK(ntx_tls13_finished_data(base, th, v) == 0 && memcmp(v, msg + 4, 32) == 0, "finished_data");
    CHECK(ml == 36 && ntx_tls13_finished_verify(msg, ml, base, th) == 0, "finished_verify ok");
    for (size_t i = 0; i < 36; i++) {
        uint8_t m2[36];
        memcpy(m2, msg, 36);
        m2[i] ^= 0x01;
        CHECK(ntx_tls13_finished_verify(m2, 36, base, th) != 0, "finished bitflip rejected");
    }
    CHECK(ntx_tls13_finished_verify(msg, 35, base, th) != 0, "finished short");
    CHECK(ntx_tls13_finished_verify(msg, 37, base, th) != 0, "finished long");
    uint8_t th2[32];
    memcpy(th2, th, 32);
    th2[0] ^= 1;
    CHECK(ntx_tls13_finished_verify(msg, ml, base, th2) != 0, "finished wrong transcript");
    free(base);
    free(th);
    free(msg);
}

static void test_records(void) {
    uint8_t *sec = kb("rec_secret", NULL);
    for (int i = 0; i < 6; i++) {
        char k[32];
        snprintf(k, sizeof k, "rec%d_type", i);
        uint8_t typ = (uint8_t)atoi(kv(k));
        snprintf(k, sizeof k, "rec%d_pt", i);
        size_t pn;
        uint8_t *pt = kb(k, &pn);
        snprintf(k, sizeof k, "rec%d_pad", i);
        int pad = atoi(kv(k));
        snprintf(k, sizeof k, "rec%d_seq", i);
        uint64_t seq = strtoull(kv(k), NULL, 10);
        snprintf(k, sizeof k, "rec%d_out", i);
        size_t on;
        uint8_t *expect = kb(k, &on);

        ntx_tls13_dir w, r;
        ntx_tls13_dir_init(&w, sec);
        ntx_tls13_dir_init(&r, sec);
        w.seq = r.seq = seq;
        uint8_t rec[16384 + 64];
        size_t rl;
        if (pad == 0) {
            CHECK(ntx_tls13_seal(&w, typ, pt, pn, rec, sizeof rec, &rl) == 0, "seal rc");
            CHECK(rl == on && memcmp(rec, expect, on) == 0, "seal matches reference");
            CHECK(w.seq == seq + 1, "seal advances seq");
        }
        /* open the reference record (also covers padding, which seal never emits) */
        uint8_t out[16640];
        size_t ol;
        uint8_t ityp = 0;
        CHECK(ntx_tls13_open(&r, expect, expect + 5, on - 5, out, sizeof out, &ol, &ityp) == 0, "open rc");
        CHECK(ityp == typ && ol == pn && (pn == 0 || memcmp(out, pt, pn) == 0), "open content");
        CHECK(r.seq == seq + 1, "open advances seq");
        /* tamper: every region must be rejected and must not consume a sequence number */
        for (size_t j = 0; j < on; j += (on > 40 ? 7 : 1)) {
            uint8_t bad[400];
            if (on > sizeof bad) break;
            memcpy(bad, expect, on);
            bad[j] ^= 0x80;
            ntx_tls13_dir r2;
            ntx_tls13_dir_init(&r2, sec);
            r2.seq = seq;
            int rc = ntx_tls13_open(&r2, bad, bad + 5, on - 5, out, sizeof out, &ol, &ityp);
            CHECK(rc != 0, "tampered record rejected");
            CHECK(r2.seq == seq, "failed open does not advance seq");
        }
        free(pt);
        free(expect);
    }

    /* limits */
    ntx_tls13_dir d;
    uint8_t big[16384 + 64], rec[16384 + 64];
    size_t rl;
    memset(big, 'a', sizeof big);
    ntx_tls13_dir_init(&d, sec);
    CHECK(ntx_tls13_seal(&d, 23, big, 16384, rec, sizeof rec, &rl) == 0 && rl == 5 + 16384 + 1 + 16, "seal max plaintext");
    CHECK(ntx_tls13_seal(&d, 23, big, 16385, rec, sizeof rec, &rl) != 0, "seal oversize");
    CHECK(ntx_tls13_seal(&d, 23, big, 100, rec, 100 + 21, &rl) != 0, "seal small cap");
    d.seq = UINT64_MAX;
    CHECK(ntx_tls13_seal(&d, 23, big, 10, rec, sizeof rec, &rl) != 0, "seal refuses wrap (nonce reuse)");
    CHECK(d.seq == UINT64_MAX, "seal wrap leaves seq");

    /* all-zero inner plaintext has no content type -> must be rejected */
    {
        ntx_tls13_dir w, r;
        ntx_tls13_dir_init(&w, sec);
        ntx_tls13_dir_init(&r, sec);
        uint8_t zeros[20] = { 0 }, ct[20], tag[16], hdr[5] = { 23, 3, 3, 0, 36 }, body[36], out[64];
        uint8_t nonce[12];
        memcpy(nonce, w.iv, 12);
        CHECK(ntx_aes128_gcm_seal(&w.gcm, nonce, hdr, 5, zeros, 20, ct, tag), "raw gcm seal");
        memcpy(body, ct, 20);
        memcpy(body + 20, tag, 16);
        uint8_t ityp;
        size_t ol;
        CHECK(ntx_tls13_open(&r, hdr, body, 36, out, sizeof out, &ol, &ityp) != 0, "all-zero inner rejected");
    }
    /* header sanity */
    {
        ntx_tls13_dir r;
        ntx_tls13_dir_init(&r, sec);
        uint8_t hdr[5] = { 22, 3, 3, 0, 17 }, body[17] = { 0 }, out[64];
        uint8_t ityp;
        size_t ol;
        CHECK(ntx_tls13_open(&r, hdr, body, 17, out, sizeof out, &ol, &ityp) != 0, "plaintext type rejected");
        hdr[0] = 23;
        CHECK(ntx_tls13_open(&r, hdr, body, 16, out, sizeof out, &ol, &ityp) != 0, "short body rejected");
        hdr[4] = 18;
        CHECK(ntx_tls13_open(&r, hdr, body, 17, out, sizeof out, &ol, &ityp) != 0, "length mismatch rejected");
    }
    free(sec);
}

static void test_client_hello(void) {
    uint8_t *cr = kb("cr", NULL), *sid = kb("sid", NULL), *pub = kb("cpub", NULL);
    uint8_t out[1024];
    static const char *const a1[] = { "http/1.1" };
    static const char *const a2[] = { "h2", "http/1.1" };
    size_t n = ntx_tls13_client_hello(out, sizeof out, "tls13-mock", cr, sid, pub, a1, 1);
    CHECK(n > 0 && kb_eq("ch_alpn", out, n), "client_hello (sni+alpn)");
    size_t need = n;
    CHECK(ntx_tls13_client_hello(out, need - 1, "tls13-mock", cr, sid, pub, a1, 1) == 0, "client_hello cap-1");
    CHECK(ntx_tls13_client_hello(out, need, "tls13-mock", cr, sid, pub, a1, 1) == need, "client_hello exact cap");
    n = ntx_tls13_client_hello(out, sizeof out, "tls13-mock", cr, sid, pub, NULL, 0);
    CHECK(n > 0 && kb_eq("ch_noalpn", out, n), "client_hello (no alpn)");
    n = ntx_tls13_client_hello(out, sizeof out, NULL, cr, sid, pub, a2, 2);
    CHECK(n > 0 && kb_eq("ch_nosni", out, n), "client_hello (no sni, h2+http/1.1)");
    CHECK(ntx_tls13_client_hello(out, sizeof out, "x", NULL, sid, pub, NULL, 0) == 0, "client_hello null random");
    CHECK(ntx_tls13_client_hello(out, sizeof out, "x", cr, NULL, pub, NULL, 0) == 0, "client_hello null sid");
    char longname[300];
    memset(longname, 'a', sizeof longname);
    longname[299] = 0;
    CHECK(ntx_tls13_client_hello(out, sizeof out, longname, cr, sid, pub, NULL, 0) == 0, "client_hello sni too long");
    free(cr);
    free(sid);
    free(pub);
}

/* offsets inside a ServerHello message built by the reference */
#define SH_VER 4
#define SH_RANDOM 6
#define SH_SIDLEN 38
#define SH_SID 39
#define SH_CIPHER 71
#define SH_COMP 73
#define SH_EXTLEN 74
#define SH_EXT0 76

static void test_server_hello(void) {
    size_t n;
    uint8_t *sh = kb("sh", &n), *sid = kb("sid", NULL), *spub = kb("spub", NULL);
    struct ntx_tls13_sh o;
    CHECK(ntx_tls13_parse_server_hello(sh, n, sid, &o) == NTX_TLS13_SH_OK, "sh ok");
    CHECK(memcmp(o.key_share_pub, spub, 32) == 0 && memcmp(o.server_random, sh + SH_RANDOM, 32) == 0, "sh fields");

    uint8_t m[512];
    int rc;
#define MUT(stmt, want, name)                                         \
    do {                                                              \
        memcpy(m, sh, n);                                             \
        size_t ml = n;                                                \
        (void)ml;                                                     \
        stmt;                                                         \
        rc = ntx_tls13_parse_server_hello(m, ml, sid, &o);            \
        CHECK(rc == (want), name);                                    \
    } while (0)
    MUT(m[SH_VER + 1] = 0x02, NTX_TLS13_SH_BAD, "sh legacy_version");
    MUT(m[SH_SIDLEN] = 0, NTX_TLS13_SH_BAD, "sh sid len 0");
    MUT(m[SH_SID + 5] ^= 1, NTX_TLS13_SH_BAD, "sh sid not echoed");
    MUT(m[SH_CIPHER + 1] = 0x02, NTX_TLS13_SH_BAD, "sh wrong cipher");
    MUT(m[SH_COMP] = 1, NTX_TLS13_SH_BAD, "sh compression");
    MUT(m[0] = 8, NTX_TLS13_SH_BAD, "sh wrong type");
    MUT(ml = n - 1, NTX_TLS13_SH_BAD, "sh truncated");
    MUT(m[3] ^= 1, NTX_TLS13_SH_BAD, "sh length mismatch");
    MUT(m[SH_EXT0 + 5] = 0x03, NTX_TLS13_SH_BAD, "sh supported_versions != 1.3");
    MUT(m[SH_EXT0 + 3] = 3, NTX_TLS13_SH_BAD, "sh supported_versions length");
    MUT(m[SH_EXT0 + 6 + 5] = 0x17, NTX_TLS13_SH_BAD, "sh key_share group");
    MUT(m[SH_EXT0 + 6 + 3] = 0x23, NTX_TLS13_SH_BAD, "sh key_share length");
    MUT(m[SH_EXT0 + 1] = 0x2a, NTX_TLS13_SH_V12, "sh without supported_versions -> 1.2");
    {
        static const uint8_t hrr[32] = {
            0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
            0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C };
        MUT(memcpy(m + SH_RANDOM, hrr, 32), NTX_TLS13_SH_HRR, "sh HelloRetryRequest detected");
    }
    /* extra extension -> reject (extension block 'cover' must stay exact) */
    {
        memcpy(m, sh, n);
        m[n] = 0x00; m[n + 1] = 0x15; m[n + 2] = 0x00; m[n + 3] = 0x00;
        size_t ml = n + 4;
        m[3] = (uint8_t)(ml - 4);
        m[SH_EXTLEN + 1] = (uint8_t)(m[SH_EXTLEN + 1] + 4);
        CHECK(ntx_tls13_parse_server_hello(m, ml, sid, &o) == NTX_TLS13_SH_BAD, "sh unexpected extension");
    }
    /* duplicate extension -> reject */
    {
        memcpy(m, sh, n);
        memcpy(m + n, sh + SH_EXT0, 6); /* second supported_versions */
        size_t ml = n + 6;
        m[3] = (uint8_t)(ml - 4);
        m[SH_EXTLEN + 1] = (uint8_t)(m[SH_EXTLEN + 1] + 6);
        CHECK(ntx_tls13_parse_server_hello(m, ml, sid, &o) == NTX_TLS13_SH_BAD, "sh duplicate extension");
    }
    /* a plain TLS 1.2 ServerHello (no extensions at all) */
    {
        memset(m, 0, sizeof m);
        m[0] = 2;
        m[4] = 3;
        m[5] = 3;
        m[SH_SIDLEN] = 0;
        m[39] = 0xC0;
        m[40] = 0x2F;
        m[41] = 0;
        size_t ml = 42;
        m[3] = (uint8_t)(ml - 4);
        CHECK(ntx_tls13_parse_server_hello(m, ml, sid, &o) == NTX_TLS13_SH_V12, "sh TLS1.2 without extensions");
    }
    /* every truncation of the valid message is rejected (never accepted, no OOB) */
    for (size_t k = 0; k < n; k++) {
        memcpy(m, sh, n);
        m[1] = 0;
        m[2] = (uint8_t)(k > 4 ? (k - 4) >> 8 : 0);
        m[3] = (uint8_t)(k > 4 ? (k - 4) & 255 : 0);
        CHECK(ntx_tls13_parse_server_hello(m, k, sid, &o) != NTX_TLS13_SH_OK, "sh truncation rejected");
    }
    CHECK(ntx_tls13_parse_server_hello(NULL, n, sid, &o) != NTX_TLS13_SH_OK, "sh null");
    free(sh);
    free(sid);
    free(spub);
}

static void test_ee(void) {
    size_t n;
    uint8_t *ee = kb("ee_alpn", &n);
    char alpn[16] = "junk";
    CHECK(ntx_tls13_parse_ee(ee, n, alpn) == 0 && !strcmp(alpn, "http/1.1"), "ee alpn");
    uint8_t m[64];
    size_t n2;
    uint8_t *none = kb("ee_none", &n2);
    CHECK(ntx_tls13_parse_ee(none, n2, alpn) == 0 && alpn[0] == 0, "ee without alpn");
    CHECK(ntx_tls13_parse_ee(ee, n - 1, alpn) != 0, "ee truncated");
    memcpy(m, ee, n);
    m[0] = 11;
    CHECK(ntx_tls13_parse_ee(m, n, alpn) != 0, "ee wrong type");
    memcpy(m, ee, n);
    m[5] ^= 1; /* ext block length */
    CHECK(ntx_tls13_parse_ee(m, n, alpn) != 0, "ee ext length mismatch");
    memcpy(m, ee, n);
    m[10] = 20; /* protocol name length beyond list */
    CHECK(ntx_tls13_parse_ee(m, n, alpn) != 0, "ee alpn name length");
    {
        /* EE advertising two protocols: a server must select exactly one */
        static const uint8_t two[] = { 8, 0, 0, 0x13, 0, 0x11, 0, 0x10, 0, 0x0d, 0, 0x0b, 0, 2, 'h', '2', 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
        uint8_t t2[sizeof two];
        memcpy(t2, two, sizeof two);
        t2[3] = (uint8_t)(sizeof two - 4);
        t2[5] = (uint8_t)(sizeof two - 6);
        t2[7] = 0x10;
        CHECK(ntx_tls13_parse_ee(t2, sizeof t2, alpn) != 0, "ee two alpn names rejected");
    }
    free(ee);
    free(none);
}

static void test_cert_and_verify(void) {
    const char *kinds[2] = { "ec", "rsa" };
    for (int k = 0; k < 2; k++) {
        char key[32];
        size_t cn, dn, vn;
        snprintf(key, sizeof key, "cert_%s", kinds[k]);
        uint8_t *cert = kb(key, &cn);
        snprintf(key, sizeof key, "leaf_%s_der", kinds[k]);
        uint8_t *der = kb(key, &dn);
        snprintf(key, sizeof key, "cv_%s", kinds[k]);
        uint8_t *cv = kb(key, &vn);
        snprintf(key, sizeof key, "th_cert_%s", kinds[k]);
        uint8_t *th = kb(key, NULL);
        snprintf(key, sizeof key, "leaf_%s_pin", kinds[k]);

        const uint8_t *leaf;
        size_t ll;
        CHECK(ntx_tls13_parse_cert(cert, cn, &leaf, &ll) == 0, "parse_cert rc");
        CHECK(ll == dn && memcmp(leaf, der, dn) == 0, "parse_cert leaf");
        uint8_t pin[32];
        CHECK(ntx_tls_spki_sha256(leaf, ll, pin) == 0 && kb_eq(key, pin, 32), "leaf SPKI pin");

        CHECK(ntx_tls13_certverify(cv, vn, der, dn, th) == 0, "certverify valid");
        uint8_t th2[32];
        memcpy(th2, th, 32);
        th2[31] ^= 1;
        CHECK(ntx_tls13_certverify(cv, vn, der, dn, th2) == -2, "certverify wrong transcript");
        /* every signature byte matters */
        for (size_t i = 8; i < vn; i += (vn > 100 ? 13 : 17)) { /* ECDSA verify is slow in-tree: few samples */
            uint8_t bad[400];
            if (vn > sizeof bad) break;
            memcpy(bad, cv, vn);
            bad[i] ^= 0x01;
            int rc = ntx_tls13_certverify(bad, vn, der, dn, th);
            CHECK(rc != 0, "certverify corrupted signature rejected");
        }
        uint8_t bad[400];
        if (vn <= sizeof bad) {
            memcpy(bad, cv, vn);
            bad[0] = 14; /* TLS 1.2 server_hello_done: the type the old code wrongly used */
            CHECK(ntx_tls13_certverify(bad, vn, der, dn, th) != 0, "certverify type 14 rejected");
            memcpy(bad, cv, vn);
            bad[5] = 0x06;
            bad[4] = 0x08; /* rsa_pkcs1 / pss_pss variants: not offered */
            CHECK(ntx_tls13_certverify(bad, vn, der, dn, th) != 0, "certverify unoffered sigalg");
            memcpy(bad, cv, vn);
            CHECK(ntx_tls13_certverify(bad, vn - 1, der, dn, th) != 0, "certverify truncated");
        }
        /* signature by the other key type's certificate must not verify */
        snprintf(key, sizeof key, "leaf_%s_der", kinds[1 - k]);
        size_t odn;
        uint8_t *oder = kb(key, &odn);
        CHECK(ntx_tls13_certverify(cv, vn, oder, odn, th) != 0, "certverify with other cert");
        free(oder);

        /* Certificate message structure */
        uint8_t m[2048];
        if (cn <= sizeof m) {
            memcpy(m, cert, cn);
            m[4] = 1;
            CHECK(ntx_tls13_parse_cert(m, cn, &leaf, &ll) != 0, "cert non-empty request context rejected");
            memcpy(m, cert, cn);
            m[0] = 15;
            CHECK(ntx_tls13_parse_cert(m, cn, &leaf, &ll) != 0, "cert wrong type");
            CHECK(ntx_tls13_parse_cert(cert, cn - 1, &leaf, &ll) != 0, "cert truncated");
            memcpy(m, cert, cn);
            m[8] = m[9] = m[10] = 0; /* leaf length 0 */
            CHECK(ntx_tls13_parse_cert(m, cn, &leaf, &ll) != 0, "cert zero-length leaf");
            memcpy(m, cert, cn);
            m[cn - 1] = 5; /* per-entry extensions length overruns the list */
            CHECK(ntx_tls13_parse_cert(m, cn, &leaf, &ll) != 0, "cert extension overrun");
            /* certificate list that is exactly empty */
            static const uint8_t empty[] = { 11, 0, 0, 4, 0, 0, 0, 0 };
            CHECK(ntx_tls13_parse_cert(empty, sizeof empty, &leaf, &ll) != 0, "cert empty list rejected");
        }
        free(cert);
        free(der);
        free(cv);
        free(th);
    }
}

static void test_key_update_msg(void) {
    int req = -1;
    static const uint8_t k0[] = { 24, 0, 0, 1, 0 }, k1[] = { 24, 0, 0, 1, 1 };
    static const uint8_t k2[] = { 24, 0, 0, 1, 2 }, k3[] = { 24, 0, 0, 2, 0, 0 }, k4[] = { 24, 0, 0, 1 };
    CHECK(ntx_tls13_parse_key_update(k0, 5, &req) == 0 && req == 0, "key_update not requested");
    CHECK(ntx_tls13_parse_key_update(k1, 5, &req) == 0 && req == 1, "key_update requested");
    CHECK(ntx_tls13_parse_key_update(k2, 5, &req) != 0, "key_update bad value");
    CHECK(ntx_tls13_parse_key_update(k3, 6, &req) != 0, "key_update bad length");
    CHECK(ntx_tls13_parse_key_update(k4, 4, &req) != 0, "key_update truncated");
}

/* ---- ntx_tls_read / ntx_tls_write on an established connection ----------- */

static int send_rec(int fd, ntx_tls13_dir *d, uint8_t typ, const uint8_t *p, size_t n) {
    uint8_t rec[16384 + 64];
    size_t rl;
    if (ntx_tls13_seal(d, typ, p, n, rec, sizeof rec, &rl) != 0) return -1;
    return io_write(fd, rec, rl);
}

static int recv_rec(int fd, ntx_tls13_dir *d, uint8_t *typ, uint8_t *out, size_t cap, size_t *n) {
    uint8_t hdr[5], body[16640];
    if (io_read(fd, hdr, 5) != 0) return -1;
    size_t bl = ((size_t)hdr[3] << 8) | hdr[4];
    if (bl > sizeof body || io_read(fd, body, bl) != 0) return -1;
    return ntx_tls13_open(d, hdr, body, bl, out, cap, n, typ);
}

static void make_conn(ntx_tls *t, int sv[2], ntx_tls13_dir *srv_w, ntx_tls13_dir *srv_r) {
    uint8_t c_ap[32], s_ap[32];
    memset(c_ap, 0x11, 32);
    memset(s_ap, 0x22, 32);
    CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sv) == 0, "socketpair");
    ntx_tls_init(t);
    t->fd = sv[0];
    t->ver = 13;
    t->ready = 1;
    ntx_tls13_dir_init(&t->w13, c_ap);
    ntx_tls13_dir_init(&t->r13, s_ap);
    ntx_tls13_dir_init(srv_w, s_ap); /* server writes with s_ap, reads with c_ap */
    ntx_tls13_dir_init(srv_r, c_ap);
}

static void test_connection(void) {
    int sv[2];
    ntx_tls t;
    ntx_tls13_dir sw, sr;
    make_conn(&t, sv, &sw, &sr);
    uint8_t buf[20000], tmp[20000];
    uint8_t typ;
    size_t n;

    /* basic write: server must be able to decrypt and sees type 23 */
    CHECK(ntx_tls_write(&t, "ping", 4) == 4, "write 4");
    CHECK(recv_rec(sv[1], &sr, &typ, tmp, sizeof tmp, &n) == 0 && typ == 23 && n == 4 && !memcmp(tmp, "ping", 4), "server reads write");

    /* writes larger than one record are truncated to a record, caller loops */
    memset(buf, 'z', sizeof buf);
    CHECK(ntx_tls_write(&t, buf, 20000) == 16384, "write caps at 16384");
    CHECK(recv_rec(sv[1], &sr, &typ, tmp, sizeof tmp, &n) == 0 && n == 16384, "server reads 16384");

    /* NewSessionTicket is ignored, data still delivered */
    uint8_t nst[] = { 4, 0, 0, 9, 0, 0, 0x1c, 0x20, 1, 2, 3, 4, 0 };
    CHECK(send_rec(sv[1], &sw, 22, nst, sizeof nst) == 0, "send NST");
    CHECK(send_rec(sv[1], &sw, 23, (const uint8_t *)"hello", 5) == 0, "send data");
    CHECK(ntx_tls_read(&t, buf, 3) == 3 && !memcmp(buf, "hel", 3), "read part 1");
    CHECK(ntx_tls_read(&t, buf, 10) == 2 && !memcmp(buf, "lo", 2), "read part 2 (buffered)");

    /* KeyUpdate(update_requested): client rekeys read, answers with KeyUpdate and rekeys write */
    uint8_t ku1[] = { 24, 0, 0, 1, 1 };
    CHECK(send_rec(sv[1], &sw, 22, ku1, 5) == 0, "send KeyUpdate(req)");
    ntx_tls13_dir_update(&sw); /* server's own sending keys also change after it sent KeyUpdate */
    CHECK(send_rec(sv[1], &sw, 23, (const uint8_t *)"after-ku", 8) == 0, "send data under new keys");
    CHECK(ntx_tls_read(&t, buf, sizeof buf) == 8 && !memcmp(buf, "after-ku", 8), "read after KeyUpdate");
    /* the client's reply KeyUpdate(not requested) is under its OLD key */
    CHECK(recv_rec(sv[1], &sr, &typ, tmp, sizeof tmp, &n) == 0 && typ == 22 && n == 5 && tmp[0] == 24 && tmp[4] == 0, "client answers KeyUpdate");
    ntx_tls13_dir_update(&sr);
    CHECK(ntx_tls_write(&t, "new-key", 7) == 7, "write after rekey");
    CHECK(recv_rec(sv[1], &sr, &typ, tmp, sizeof tmp, &n) == 0 && n == 7 && !memcmp(tmp, "new-key", 7), "server decrypts with updated key");

    /* KeyUpdate(update_not_requested): no reply */
    uint8_t ku0[] = { 24, 0, 0, 1, 0 };
    CHECK(send_rec(sv[1], &sw, 22, ku0, 5) == 0, "send KeyUpdate(no req)");
    ntx_tls13_dir_update(&sw);
    CHECK(send_rec(sv[1], &sw, 23, (const uint8_t *)"x", 1) == 0, "send after ku0");
    CHECK(ntx_tls_read(&t, buf, sizeof buf) == 1, "read after ku0");

    /* legacy CCS between records is ignored */
    {
        static const uint8_t ccs[6] = { 20, 3, 3, 0, 1, 1 };
        CHECK(io_write(sv[1], ccs, 6) == 0 && send_rec(sv[1], &sw, 23, (const uint8_t *)"y", 1) == 0, "send ccs+data");
        CHECK(ntx_tls_read(&t, buf, sizeof buf) == 1 && buf[0] == 'y', "ccs ignored");
    }
    /* user_canceled warning is ignored, close_notify ends the stream with 0 */
    {
        uint8_t uc[2] = { 1, 90 }, cn[2] = { 1, 0 };
        CHECK(send_rec(sv[1], &sw, 21, uc, 2) == 0 && send_rec(sv[1], &sw, 23, (const uint8_t *)"z", 1) == 0, "send user_canceled");
        CHECK(ntx_tls_read(&t, buf, sizeof buf) == 1, "user_canceled ignored");
        CHECK(send_rec(sv[1], &sw, 21, cn, 2) == 0, "send close_notify");
        CHECK(ntx_tls_read(&t, buf, sizeof buf) == 0, "close_notify -> 0");
    }
    ntx_tls_close(&t);
    CHECK(!t.w13.active && !t.r13.active, "close wipes 1.3 state");
    close(sv[0]);
    close(sv[1]);

    /* fatal conditions */
    struct {
        const char *name;
        uint8_t typ;
        uint8_t body[8];
        size_t n;
    } bad[] = {
        { "fatal alert", 21, { 2, 40 }, 2 },
        { "unexpected handshake message (Certificate)", 22, { 11, 0, 0, 0 }, 4 },
        { "KeyUpdate bad value", 22, { 24, 0, 0, 1, 7 }, 5 },
        { "truncated handshake message", 22, { 4, 0, 0, 200, 1 }, 5 },
        { "bad alert length", 21, { 1 }, 1 },
    };
    for (size_t i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        make_conn(&t, sv, &sw, &sr);
        CHECK(send_rec(sv[1], &sw, bad[i].typ, bad[i].body, bad[i].n) == 0, "send bad");
        CHECK(ntx_tls_read(&t, buf, sizeof buf) == -1, bad[i].name);
        ntx_tls_close(&t);
        close(sv[0]);
        close(sv[1]);
    }
    /* plaintext application_data record and tampered ciphertext */
    make_conn(&t, sv, &sw, &sr);
    {
        static const uint8_t plain[] = { 22, 3, 3, 0, 4, 1, 2, 3, 4 };
        CHECK(io_write(sv[1], plain, sizeof plain) == 0, "send plaintext hs");
        CHECK(ntx_tls_read(&t, buf, sizeof buf) == -1, "plaintext record after handshake rejected");
    }
    ntx_tls_close(&t);
    close(sv[0]);
    close(sv[1]);
    make_conn(&t, sv, &sw, &sr);
    {
        uint8_t rec[64];
        size_t rl;
        CHECK(ntx_tls13_seal(&sw, 23, (const uint8_t *)"data", 4, rec, sizeof rec, &rl) == 0, "seal");
        rec[rl - 1] ^= 1;
        CHECK(io_write(sv[1], rec, rl) == 0, "send tampered");
        CHECK(ntx_tls_read(&t, buf, sizeof buf) == -1, "tampered record rejected");
    }
    ntx_tls_close(&t);
    close(sv[0]);
    close(sv[1]);
}

int main(void) {
    load_kat();
    test_key_schedule();
    test_expand_label();
    test_finished();
    test_records();
    test_client_hello();
    test_server_hello();
    test_ee();
    test_cert_and_verify();
    test_key_update_msg();
    test_connection();
    if (g_fail) return 1;
    printf("PASS tls13-key-schedule\n");
    printf("PASS tls13-records\n");
    printf("PASS tls13-messages\n");
    printf("PASS tls13-connection\n");
    printf("ALL PASS\n");
    return 0;
}
