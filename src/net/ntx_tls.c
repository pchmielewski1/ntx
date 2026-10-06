#include "ntx_tls.h"

#include "ntx_addr.h"
#include "ntx_sock.h"
#include "ntx_tls13.h"

#include "../ui/ntx_diag.h"
#include "../crypto/ntx_hkdf.h"
#include "../crypto/ntx_hmac.h"
#include "../crypto/ntx_p256.h"
#include "../crypto/ntx_rng.h"
#include "../crypto/ntx_rsa_pkcs1.h"
#include "../crypto/ntx_ct.h"
#include "../crypto/ntx_sha256.h"
#include "../crypto/ntx_x25519.h"
#include "../proto/ntx_wire.h"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#if defined(__GNUC__) || defined(__clang__)
/* Tests that include ntx_tls.c without ntx_tls13.c / ntx_sock.c (parse-only or
   mock-handshake suites) still link: the TLS 1.3 path is not executed there.
   The production binary resolves these to the strong definitions. */
#pragma weak ntx_tls13_client_hello
#pragma weak ntx_tls13_parse_server_hello
#pragma weak ntx_tls13_parse_ee
#pragma weak ntx_tls13_parse_cert
#pragma weak ntx_tls13_certverify
#pragma weak ntx_tls13_finished_verify
#pragma weak ntx_tls13_finished_data
#pragma weak ntx_tls13_parse_key_update
#pragma weak ntx_tls13_hs_secrets
#pragma weak ntx_tls13_app_secrets
#pragma weak ntx_tls13_dir_init
#pragma weak ntx_tls13_dir_update
#pragma weak ntx_tls13_seal
#pragma weak ntx_tls13_open
#pragma weak ntx_sock_tcp4
#pragma weak ntx_sock_tcp6
#pragma weak ntx_sock_connect_addr
#pragma weak ntx_addr_is_v6
#pragma weak ntx_addr_from_sockaddr
#endif

#define VER12 0x0303u
#define CS_C02B 0xC02Bu /* ECDHE_ECDSA_AES_128_GCM_SHA256 */
#define CS_C02F 0xC02Fu /* ECDHE_RSA_AES_128_GCM_SHA256 */
#define REC_CCS 20
#define REC_ALERT 21
#define REC_HS 22
#define REC_APP 23
#define HS_CH 1
#define HS_SH 2
#define HS_NST 4
#define HS_CERT 11
#define HS_SKX 12
#define HS_CERT_REQ 13
#define HS_SHD 14
#define HS_CKE 16
#define HS_FIN 20
#define HS_CERT_STATUS 22

#define MAX_HS_ACC 65536
#define MAX_PT 16384
#define HS13_CS 0x1301u /* TLS_AES_128_GCM_SHA256 */
#define HS13_FALLBACK (-3) /* internal: not a TLS 1.3 server -> close + reconnect + TLS 1.2 */

/* Switch for the TLS 1.3 path (with fallback to 1.2). On by default; build with
   -DNTX_TLS13_LIVE=0 to get a TLS 1.2-only client. */
#ifndef NTX_TLS13_LIVE
#define NTX_TLS13_LIVE 1
#endif

int ntx_tls_pin_stderr;

/* ---- minimal DER ---- */
static int der_tl(const uint8_t *p, size_t n, size_t *hdr, size_t *len) {
    if (n < 2) return -1;
    if (!(p[1] & 0x80)) {
        *hdr = 2;
        *len = p[1];
        return (*hdr + *len <= n) ? 0 : -1;
    }
    size_t nl = (size_t)(p[1] & 0x7f);
    if (nl < 1 || nl > 3 || 2 + nl > n) return -1;
    size_t L = 0;
    for (size_t i = 0; i < nl; i++) L = (L << 8) | p[2 + i];
    *hdr = 2 + nl;
    *len = L;
    return (*hdr + *len <= n) ? 0 : -1;
}

static int der_tag(const uint8_t *p, size_t n, uint8_t tag, size_t *hdr, size_t *len) {
    if (n < 1 || p[0] != tag) return -1;
    return der_tl(p, n, hdr, len);
}

static int der_skip(const uint8_t **pp, size_t *n) {
    size_t hdr, len;
    if (*n < 1) return -1;
    if (der_tl(*pp, *n, &hdr, &len) != 0) return -1;
    *pp += hdr + len;
    *n -= hdr + len;
    return 0;
}

static int find_spki(const uint8_t *cert, size_t cert_len, const uint8_t **spki, size_t *spki_len) {
    size_t hdr, len;
    const uint8_t *p = cert;
    size_t n = cert_len;
    if (der_tag(p, n, 0x30, &hdr, &len) != 0) return -1;
    p += hdr;
    n = len;
    if (der_tag(p, n, 0x30, &hdr, &len) != 0) return -1;
    const uint8_t *tbs = p + hdr;
    size_t tn = len;
    if (tn >= 1 && tbs[0] == 0xa0) {
        if (der_skip(&tbs, &tn) != 0) return -1;
    }
    for (int i = 0; i < 5; i++) {
        if (der_skip(&tbs, &tn) != 0) return -1;
    }
    if (der_tag(tbs, tn, 0x30, &hdr, &len) != 0) return -1;
    *spki = tbs;
    *spki_len = hdr + len;
    return 0;
}

int ntx_tls_spki_sha256(const uint8_t *cert_der, size_t cert_len, uint8_t out[32]) {
    const uint8_t *spki;
    size_t spki_len;
    if (!cert_der || !out || find_spki(cert_der, cert_len, &spki, &spki_len) != 0) return -1;
    ntx_sha256(spki, spki_len, out);
    return 0;
}

static int rsa_from_spki(const uint8_t *spki, size_t spki_len,
                         const uint8_t **n_out, size_t *n_len,
                         const uint8_t **e_out, size_t *e_len) {
    size_t hdr, len;
    const uint8_t *p = spki;
    size_t rem = spki_len;
    if (der_tag(p, rem, 0x30, &hdr, &len) != 0) return -1;
    p += hdr;
    rem = len;
    {   /* AlgorithmIdentifier must name rsaEncryption (1.2.840.113549.1.1.1) */
        static const uint8_t rsa_oid[11] = { 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
        size_t ah, al;
        if (der_tag(p, rem, 0x30, &ah, &al) != 0 || al < sizeof rsa_oid ||
            memcmp(p + ah, rsa_oid, sizeof rsa_oid) != 0)
            return -1;
    }
    if (der_skip(&p, &rem) != 0) return -1; /* AlgorithmIdentifier */
    if (der_tag(p, rem, 0x03, &hdr, &len) != 0) return -1;
    p += hdr;
    if (len < 1 || p[0] != 0x00) return -1;
    p += 1;
    rem = len - 1;
    if (der_tag(p, rem, 0x30, &hdr, &len) != 0) return -1;
    p += hdr;
    rem = len;
    if (der_tag(p, rem, 0x02, &hdr, &len) != 0) return -1;
    const uint8_t *mod = p + hdr;
    size_t mlen = len;
    if (mlen > 0 && mod[0] == 0x00) {
        mod++;
        mlen--;
    }
    p += hdr + len;
    rem -= hdr + len;
    if (der_tag(p, rem, 0x02, &hdr, &len) != 0) return -1;
    const uint8_t *exp = p + hdr;
    size_t elen = len;
    if (elen > 0 && exp[0] == 0x00) {
        exp++;
        elen--;
    }
    if (mlen == 0 || mlen > 512 || elen == 0 || elen > 8) return -1;
    *n_out = mod;
    *n_len = mlen;
    *e_out = exp;
    *e_len = elen;
    return 0;
}

int ntx_tls_spki_from_cert(const uint8_t *cert_der, size_t cert_len,
                           const uint8_t **spki, size_t *spki_len) {
    return find_spki(cert_der, cert_len, spki, spki_len);
}

int ntx_tls_rsa_pub_from_spki(const uint8_t *spki, size_t spki_len,
                              const uint8_t **n_out, size_t *n_len,
                              const uint8_t **e_out, size_t *e_len) {
    return rsa_from_spki(spki, spki_len, n_out, n_len, e_out, e_len);
}

static void pin_fail_alert(const char *ip, const char *sni, const uint8_t got[32],
                           const uint8_t pins[][32], int npins) {
    if (!ntx_tls_pin_stderr) return;
    char ghex[65];
    char exp[512];
    to_hex(ghex, sizeof ghex, got, 32);
    size_t eo = 0;
    exp[0] = 0;
    for (int i = 0; i < npins; i++) {
        char h[65];
        to_hex(h, sizeof h, pins[i], 32);
        size_t hl = strlen(h);
        if (eo + hl + 2 >= sizeof exp) break;
        if (i) exp[eo++] = '|';
        memcpy(exp + eo, h, hl);
        eo += hl;
        exp[eo] = 0;
    }
    ntx_diag( "ntx: TLS MITM/pin fail ip=%s sni=%s got=%s expected=%s\n",
            (ip && ip[0]) ? ip : "?", (sni && sni[0]) ? sni : "?", ghex,
            exp[0] ? exp : "(none)");
}

static int pins_match(const uint8_t got[32], const uint8_t pins[][32], int npins) {
    if (npins < 1 || !pins) return 0;
    for (int i = 0; i < npins; i++)
        if (memcmp(got, pins[i], 32) == 0) return 1;
    return 0;
}

static int hs_send(ntx_tls *t, uint8_t hstype, const uint8_t *body, size_t blen,
                   ntx_sha256_ctx *hs, tls_dir *d) {
    uint8_t msg[4096];
    if (4 + blen > sizeof msg) return -1;
    msg[0] = hstype;
    ntx_wire_wr24(msg + 1, (uint32_t)blen);
    if (blen) memcpy(msg + 4, body, blen);
    ntx_sha256_update(hs, msg, 4 + blen);
    return rec_send(t, REC_HS, msg, 4 + blen, d);
}

void ntx_tls_init(ntx_tls *t) {
    if (t) memset(t, 0, sizeof *t), t->fd = -1;
}

void ntx_tls_close(ntx_tls *t) {
    if (!t) return;
    memset(t->client_key, 0, sizeof t->client_key);
    memset(t->server_key, 0, sizeof t->server_key);
    memset(t->client_iv, 0, sizeof t->client_iv);
    memset(t->server_iv, 0, sizeof t->server_iv);
    memset(t->master, 0, sizeof t->master);
    memset(t->leaf_pin, 0, sizeof t->leaf_pin);
    t->leaf_pin_valid = 0;
    memset(&t->gcm_w, 0, sizeof t->gcm_w);
    memset(&t->gcm_r, 0, sizeof t->gcm_r);
    memset(&t->w13, 0, sizeof t->w13);
    memset(&t->r13, 0, sizeof t->r13);
    t->ready = 0;
    t->app_len = t->app_off = 0;
}

ssize_t ntx_tls_write(ntx_tls *t, const void *buf, size_t n) {
    if (!t || !t->ready || !buf) return -1;
    if (n == 0) return 0;
    if (n > MAX_PT) n = MAX_PT;
    if (t->ver == 13) {
        uint8_t rec[NTX_TLS13_MAX_PLAINTEXT + 22];
        size_t rl;
        if (ntx_tls13_seal(&t->w13, REC_APP, buf, n, rec, sizeof rec, &rl) != 0) return -1;
        if (io_write(t->fd, rec, rl) != 0) return -1;
        return (ssize_t)n;
    }
    tls_dir w = { 1, &t->seq_w, &t->gcm_w, t->client_iv };
    if (rec_send(t, REC_APP, buf, n, &w) != 0) return -1;
    return (ssize_t)n;
}

/* Read one application-data record from a TLS 1.3 connection into t->app_buf,
 * transparently handling post-handshake messages (RFC 8446 section 4.6):
 * NewSessionTicket is ignored (no resumption), KeyUpdate rekeys the read side
 * (and ours if the peer asks), alerts end the stream. Returns the number of
 * bytes, 0 on close_notify, -1 on error. */
static ssize_t read13(ntx_tls *t) {
    for (;;) {
        uint8_t hdr[5], body[NTX_TLS13_MAX_CIPHERTEXT], pt[NTX_TLS13_MAX_CIPHERTEXT];
        if (io_read(t->fd, hdr, 5) != 0) return -1;
        size_t bl = ntx_wire_rd16(hdr + 3);
        if (bl > sizeof body) return -1;
        if (bl && io_read(t->fd, body, bl) != 0) return -1;
        if (hdr[0] == REC_CCS) continue; /* legacy compatibility record: ignore */
        if (hdr[0] != REC_APP) return -1; /* plaintext alerts etc. are not valid here */
        size_t pl;
        uint8_t ityp;
        if (ntx_tls13_open(&t->r13, hdr, body, bl, pt, sizeof pt, &pl, &ityp) != 0) return -1;
        if (ityp == REC_APP) {
            if (pl == 0) continue;
            memcpy(t->app_buf, pt, pl);
            return (ssize_t)pl;
        }
        if (ityp == REC_ALERT) {
            if (pl != 2) return -1;
            if (pt[1] == 0) return 0;              /* close_notify */
            if (pt[0] == 1 && pt[1] == 90) continue; /* user_canceled (warning) */
            return -1;
        }
        if (ityp != REC_HS || pl == 0) return -1;
        size_t off = 0;
        while (off < pl) {
            if (pl - off < 4) return -1;
            size_t ml = 4 + (size_t)ntx_wire_rd24(pt + off + 1);
            if (ml > pl - off) return -1;
            const uint8_t *m = pt + off;
            if (m[0] == HS_NST) {
                /* ignored */
            } else if (m[0] == NTX_HS13_KEY_UPDATE) {
                int req;
                if (ntx_tls13_parse_key_update(m, ml, &req) != 0) return -1;
                if (ntx_tls13_dir_update(&t->r13) != 0) return -1;
                if (req) {
                    static const uint8_t ku[5] = { NTX_HS13_KEY_UPDATE, 0, 0, 1, 0 };
                    uint8_t rec[5 + sizeof ku + 1 + 16];
                    size_t rl;
                    if (ntx_tls13_seal(&t->w13, REC_HS, ku, sizeof ku, rec, sizeof rec, &rl) != 0 ||
                        io_write(t->fd, rec, rl) != 0)
                        return -1;
                    if (ntx_tls13_dir_update(&t->w13) != 0) return -1;
                }
            } else {
                return -1; /* e.g. late CertificateRequest: not negotiated */
            }
            off += ml;
        }
    }
}

ssize_t ntx_tls_read(ntx_tls *t, void *buf, size_t n) {
    if (!t || !t->ready || !buf) return -1;
    if (t->app_off < t->app_len) {
        size_t have = t->app_len - t->app_off;
        size_t take = have < n ? have : n;
        memcpy(buf, t->app_buf + t->app_off, take);
        t->app_off += take;
        if (t->app_off >= t->app_len) t->app_off = t->app_len = 0;
        return (ssize_t)take;
    }
    size_t L;
    if (t->ver == 13) {
        ssize_t r = read13(t);
        if (r <= 0) return r;
        L = (size_t)r;
    } else {
        tls_dir r = { 1, &t->seq_r, &t->gcm_r, t->server_iv };
        uint8_t typ;
        if (rec_recv(t, &typ, t->app_buf, sizeof t->app_buf, &L, &r) != 0)
            return -1;
        if (typ != REC_APP) return -1;
    }
    t->app_len = L;
    t->app_off = 0;
    size_t take = L < n ? L : n;
    memcpy(buf, t->app_buf, take);
    t->app_off = take;
    if (t->app_off >= t->app_len) t->app_off = t->app_len = 0;
    return (ssize_t)take;
}

static size_t make_client_hello(uint8_t *out, size_t cap, const char *sni,
                                const uint8_t cr[32],
                                const char *const alpn[], int nalpn) {
    if (cap < 320) return 0;
    size_t o = 0;
    ntx_wire_wr16(out + o, VER12);
    o += 2;
    memcpy(out + o, cr, 32);
    o += 32;
    out[o++] = 0; /* session_id */
    ntx_wire_wr16(out + o, 4);
    o += 2;
    /* Prefer RSA (fast) then ECDSA — OpenDNS picks RSA; Quad9 still selects ECDSA. */
    ntx_wire_wr16(out + o, CS_C02F);
    o += 2;
    ntx_wire_wr16(out + o, CS_C02B);
    o += 2;
    out[o++] = 1;
    out[o++] = 0;
    size_t elen_at = o;
    ntx_wire_wr16(out + o, 0);
    o += 2;
    size_t e0 = o;
    size_t sn = sni ? strlen(sni) : 0;
    if (sn > 0 && sn < 256) {
        ntx_wire_wr16(out + o, 0);
        o += 2;
        ntx_wire_wr16(out + o, (uint16_t)(5 + sn));
        o += 2;
        ntx_wire_wr16(out + o, (uint16_t)(3 + sn));
        o += 2;
        out[o++] = 0;
        ntx_wire_wr16(out + o, (uint16_t)sn);
        o += 2;
        memcpy(out + o, sni, sn);
        o += sn;
    }
    /* supported_groups: x25519 + secp256r1 (Quad9 requires P-256 listed) */
    ntx_wire_wr16(out + o, 10);
    o += 2;
    ntx_wire_wr16(out + o, 6);
    o += 2;
    ntx_wire_wr16(out + o, 4);
    o += 2;
    ntx_wire_wr16(out + o, 0x001d);
    o += 2;
    ntx_wire_wr16(out + o, 0x0017);
    o += 2;
    /* ec_point_formats */
    ntx_wire_wr16(out + o, 11);
    o += 2;
    ntx_wire_wr16(out + o, 2);
    o += 2;
    out[o++] = 1;
    out[o++] = 0;
    /* signature_algorithms: ecdsa_secp256r1_sha256, rsa_pkcs1_sha256 */
    ntx_wire_wr16(out + o, 13);
    o += 2;
    ntx_wire_wr16(out + o, 6);
    o += 2;
    ntx_wire_wr16(out + o, 4);
    o += 2;
    ntx_wire_wr16(out + o, 0x0403);
    o += 2;
    ntx_wire_wr16(out + o, 0x0401);
    o += 2;
    /* renegotiation_info (empty RI) */
    ntx_wire_wr16(out + o, 0xff01);
    o += 2;
    ntx_wire_wr16(out + o, 1);
    o += 2;
    out[o++] = 0;
    /* ALPN (RFC 7301): ext 16, u16 list len, then u8 len + name per protocol;
       omitted when nalpn == 0 */
    if (nalpn > 0 && alpn) {
        size_t plen = 0;
        for (int i = 0; i < nalpn; i++) plen += 1 + strlen(alpn[i]);
        ntx_wire_wr16(out + o, 16);
        o += 2;
        ntx_wire_wr16(out + o, (uint16_t)(2 + plen));
        o += 2;
        ntx_wire_wr16(out + o, (uint16_t)plen);
        o += 2;
        for (int i = 0; i < nalpn; i++) {
            size_t L = strlen(alpn[i]);
            out[o++] = (uint8_t)L;
            memcpy(out + o, alpn[i], L);
            o += L;
        }
    }
    ntx_wire_wr16(out + elen_at, (uint16_t)(o - e0));
    return o;
}

static int ntx_tls_handshake_12(ntx_tls *t, int fd, const char *sni,
                                const uint8_t pins[][32], int npins,
                                int io_timeout_sec,
                                const char *const alpn[], int nalpn,
                                int tls13_capable) {
    if (!t || fd < 0) return NTX_TLS_FAIL;
    ntx_tls_close(t);
    memset(t, 0, sizeof *t);
    t->fd = fd;
    t->ver = 12;
    if (sni) {
        size_t n = strlen(sni);
        if (n >= sizeof t->sni) n = sizeof t->sni - 1;
        memcpy(t->sni, sni, n);
    }
    peer_ip_str(fd, t->peer_ip, sizeof t->peer_ip);
    sock_timeouts(fd, io_timeout_sec);

    uint8_t client_random[32], server_random[32];
    ntx_rand_bytes(client_random, 32);

    ntx_sha256_ctx hs;
    ntx_sha256_init(&hs);

    uint8_t ch[512];
    size_t ch_len = make_client_hello(ch, sizeof ch, t->sni, client_random,
                                      alpn, nalpn);
    if (!ch_len) return NTX_TLS_FAIL;
    tls_dir plain = { 0, NULL, NULL, NULL };
    if (hs_send(t, HS_CH, ch, ch_len, &hs, &plain) != 0) return NTX_TLS_FAIL;

    uint8_t acc[MAX_HS_ACC];
    size_t acc_len = 0;
    int got_sh = 0, got_cert = 0, got_skx = 0, got_shd = 0, pinned = 0;
    /* Server flight order (RFC 5246 7.4): ServerHello, Certificate, ServerKeyExchange,
       ServerHelloDone - each exactly once. */
    enum { S_SH, S_CERT, S_SKX, S_SHD, S_DONE } fl = S_SH;
    uint8_t leaf[16384];
    size_t leaf_len = 0;
    const uint8_t *spki = NULL;
    size_t spki_len = 0;
    uint8_t peer_yx[32];
    uint8_t skx_params[36];
    uint16_t chosen_cs = 0;

    while (!got_shd) {
        uint8_t typ, rec[18432];
        size_t rlen;
        if (rec_recv(t, &typ, rec, sizeof rec, &rlen, &plain) != 0) return NTX_TLS_FAIL;
        if (typ != REC_HS) return NTX_TLS_FAIL;
        if (acc_len + rlen > sizeof acc) return NTX_TLS_FAIL;
        memcpy(acc + acc_len, rec, rlen);
        acc_len += rlen;

        size_t off = 0;
        while (off + 4 <= acc_len) {
            uint8_t mt = acc[off];
            uint32_t ml = ntx_wire_rd24(acc + off + 1);
            if (off + 4 + ml > acc_len) break;
            ntx_sha256_update(&hs, acc + off, 4 + ml);
            const uint8_t *body = acc + off + 4;

            if (mt == HS_SH) {
                if (fl != S_SH || ml < 38) return NTX_TLS_FAIL;
                fl = S_CERT;
                if (ntx_wire_rd16(body) != VER12) return NTX_TLS_FAIL;
                memcpy(server_random, body + 2, 32);
                /* RFC 8446 4.1.3: a TLS 1.3-capable client that is handed TLS 1.2 must refuse
                   a server_random ending in "DOWNGRD\x01" (it WOULD have spoken 1.3, so
                   somebody pushed us down). The value is covered by the ServerKeyExchange
                   signature, so it cannot be stripped in transit. */
                if (tls13_capable && ntx_ct_eq(server_random + 24, "DOWNGRD\x01", 8)) return NTX_TLS_FAIL;
                uint8_t sidl = body[34];
                if ((size_t)35 + sidl + 3 > ml) return NTX_TLS_FAIL;
                const uint8_t *cp = body + 35 + sidl;
                chosen_cs = ntx_wire_rd16(cp);
                if ((chosen_cs != CS_C02B && chosen_cs != CS_C02F) || cp[2] != 0) return NTX_TLS_FAIL;
                t->cipher = chosen_cs;
                /* optional extensions after cipher+comp */
                size_t sh_off = (size_t)(cp - body) + 3;
                t->alpn[0] = 0;
                if (sh_off + 2 <= ml) {
                    uint16_t elen = ntx_wire_rd16(body + sh_off);
                    sh_off += 2;
                    if (sh_off + elen > ml) return NTX_TLS_FAIL;
                    size_t eend = sh_off + elen;
                    while (sh_off + 4 <= eend) {
                        uint16_t et = ntx_wire_rd16(body + sh_off);
                        uint16_t el = ntx_wire_rd16(body + sh_off + 2);
                        sh_off += 4;
                        if (sh_off + el > eend) return NTX_TLS_FAIL;
                        if (et == 16 && el >= 3) { /* ALPN */
                            uint16_t list = ntx_wire_rd16(body + sh_off);
                            if (2 + list > el) return NTX_TLS_FAIL;
                            if (list >= 1) {
                                uint8_t pl = body[sh_off + 2];
                                if ((size_t)3 + pl <= el && pl > 0 && pl < sizeof t->alpn) {
                                    memcpy(t->alpn, body + sh_off + 3, pl);
                                    t->alpn[pl] = 0;
                                }
                            }
                        }
                        sh_off += el;
                    }
                }
                got_sh = 1;
            } else if (mt == HS_CERT) {
                if (fl != S_CERT || ml < 3) return NTX_TLS_FAIL;
                fl = S_SKX;
                uint32_t list = ntx_wire_rd24(body);
                if (3 + list > ml || list < 3) return NTX_TLS_FAIL;
                uint32_t c0 = ntx_wire_rd24(body + 3);
                if (6 + c0 > ml || c0 == 0 || c0 > sizeof leaf) return NTX_TLS_FAIL;
                memcpy(leaf, body + 6, c0);
                leaf_len = c0;
                if (find_spki(leaf, leaf_len, &spki, &spki_len) != 0) return NTX_TLS_FAIL;
                uint8_t pin[32];
                ntx_sha256(spki, spki_len, pin);
                memcpy(t->leaf_pin, pin, 32);
                t->leaf_pin_valid = 1;
                /* npins == 0 is the TOFU mode (ntx_https_handshake_fd): no pin to
                   enforce, the caller records t->leaf_pin after a successful handshake. */
                if (npins >= 1 && !pins_match(pin, pins, npins)) {
                    pin_fail_alert(t->peer_ip, t->sni, pin, pins, npins);
                    ntx_tls_close(t);
                    t->fd = fd; /* preserve fd for caller */
                    return NTX_TLS_PIN_FAIL;
                }
                pinned = 1;
                got_cert = 1;
            } else if (mt == HS_SKX) {
                if (fl != S_SKX || ml < 36 + 4) return NTX_TLS_FAIL;
                fl = S_SHD;
                if (body[0] != 3 || ntx_wire_rd16(body + 1) != 0x001d || body[3] != 32) return NTX_TLS_FAIL;
                memcpy(peer_yx, body + 4, 32);
                memcpy(skx_params, body, 36);
                const uint8_t *sigp = body + 36;
                size_t srem = ml - 36;
                if (srem < 4) return NTX_TLS_FAIL;
                uint8_t hash_alg = sigp[0], sig_alg = sigp[1];
                uint16_t sig_len = ntx_wire_rd16(sigp + 2);
                if ((size_t)4 + sig_len > srem) return NTX_TLS_FAIL;
                const uint8_t *sig = sigp + 4;
                uint8_t tosign[32 + 32 + 36], dig[32];
                memcpy(tosign, client_random, 32);
                memcpy(tosign + 32, server_random, 32);
                memcpy(tosign + 64, skx_params, 36);
                ntx_sha256(tosign, sizeof tosign, dig);
                if (chosen_cs == CS_C02F) {
                    if (hash_alg != 4 || sig_alg != 1) return NTX_TLS_FAIL;
                    const uint8_t *rn, *re;
                    size_t rn_len, re_len;
                    if (!spki || rsa_from_spki(spki, spki_len, &rn, &rn_len, &re, &re_len) != 0)
                        return NTX_TLS_FAIL;
                    if (sig_len != rn_len) return NTX_TLS_FAIL;
                    if (!ntx_rsa_pkcs1_verify_sha256(rn, rn_len, re, re_len, sig, sig_len, dig))
                        return NTX_TLS_FAIL;
                } else if (chosen_cs == CS_C02B) {
                    if (hash_alg != 4 || sig_alg != 3) return NTX_TLS_FAIL;
                    uint8_t qx[32], qy[32], rr[32], ss[32];
                    if (!spki || ntx_p256_pubkey_from_spki(spki, spki_len, qx, qy) != 0)
                        return NTX_TLS_FAIL;
                    if (ntx_p256_sig_from_der(sig, sig_len, rr, ss) != 0) return NTX_TLS_FAIL;
                    if (!ntx_p256_ecdsa_verify_sha256(qx, qy, rr, ss, dig)) return NTX_TLS_FAIL;
                } else {
                    return NTX_TLS_FAIL;
                }
                got_skx = 1;
            } else if (mt == HS_SHD) {
                if (fl != S_SHD || ml != 0) return NTX_TLS_FAIL;
                fl = S_DONE;
                got_shd = 1;
            } else if (mt == HS_CERT_STATUS && fl == S_SKX) {
                /* unsolicited (we sent no status_request) but harmless: ignore, already hashed */
            } else {
                /* CertificateRequest (client auth) and anything unexpected. */
                return NTX_TLS_FAIL;
            }
            off += 4 + ml;
        }
        if (off) {
            memmove(acc, acc + off, acc_len - off);
            acc_len -= off;
        }
    }

    if (!got_sh || !got_cert || !got_skx || !pinned) return NTX_TLS_FAIL;
    if (acc_len != 0) return NTX_TLS_FAIL; /* nothing may follow ServerHelloDone */

    uint8_t priv[32], pub[32], shared[32];
    ntx_rand_bytes(priv, 32);
    ntx_x25519_base(pub, priv);
    int x_rc = ntx_x25519(shared, priv, peer_yx);
    ntx_wipe(priv, sizeof priv);
    if (x_rc != 0) {
        ntx_wipe(shared, sizeof shared);
        return NTX_TLS_FAIL;
    }

    uint8_t seed[64];
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    tls12_prf(shared, 32, "master secret", seed, 64, t->master, 48);
    ntx_wipe(shared, sizeof shared);

    memcpy(seed, server_random, 32);
    memcpy(seed + 32, client_random, 32);
    uint8_t kb[40];
    tls12_prf(t->master, 48, "key expansion", seed, 64, kb, 40);
    memcpy(t->client_key, kb + 0, 16);
    memcpy(t->server_key, kb + 16, 16);
    memcpy(t->client_iv, kb + 32, 4);
    memcpy(t->server_iv, kb + 36, 4);
    ntx_wipe(kb, sizeof kb);
    ntx_aes128_gcm_init(&t->gcm_w, t->client_key);
    ntx_aes128_gcm_init(&t->gcm_r, t->server_key);
    t->seq_w = t->seq_r = 0;

    uint8_t cke[33];
    cke[0] = 32;
    memcpy(cke + 1, pub, 32);
    if (hs_send(t, HS_CKE, cke, 33, &hs, &plain) != 0) return NTX_TLS_FAIL;

    uint8_t ccs = 1;
    if (rec_send(t, REC_CCS, &ccs, 1, &plain) != 0) return NTX_TLS_FAIL;

    uint8_t hs_hash[32], verify[12];
    {
        ntx_sha256_ctx tmp = hs;
        ntx_sha256_final(&tmp, hs_hash);
    }
    tls12_prf(t->master, 48, "client finished", hs_hash, 32, verify, 12);
    tls_dir enc_w = { 1, &t->seq_w, &t->gcm_w, t->client_iv };
    if (hs_send(t, HS_FIN, verify, 12, &hs, &enc_w) != 0) return NTX_TLS_FAIL;

    tls_dir enc_r = { 1, &t->seq_r, &t->gcm_r, t->server_iv };
    int got_sccs = 0, got_sfin = 0;
    while (!got_sfin) {
        uint8_t typ, rec[18432];
        size_t rlen;
        tls_dir *rd = got_sccs ? &enc_r : &plain;
        if (rec_recv(t, &typ, rec, sizeof rec, &rlen, rd) != 0) return NTX_TLS_FAIL;
        if (typ == REC_CCS) {
            if (rlen != 1 || rec[0] != 1) return NTX_TLS_FAIL;
            got_sccs = 1;
            continue;
        }
        if (typ != REC_HS) return NTX_TLS_FAIL;
        size_t off = 0;
        while (off + 4 <= rlen) {
            uint8_t mt = rec[off];
            uint32_t ml = ntx_wire_rd24(rec + off + 1);
            if (off + 4 + ml > rlen) return NTX_TLS_FAIL;
            if (mt == HS_NST) {
                ntx_sha256_update(&hs, rec + off, 4 + ml);
            } else if (mt == HS_FIN) {
                if (!got_sccs || ml != 12) return NTX_TLS_FAIL;
                uint8_t sh[32], expect[12];
                {
                    ntx_sha256_ctx tmp = hs;
                    ntx_sha256_final(&tmp, sh);
                }
                tls12_prf(t->master, 48, "server finished", sh, 32, expect, 12);
                if (!ntx_ct_eq(expect, rec + off + 4, 12)) return NTX_TLS_FAIL;
                ntx_sha256_update(&hs, rec + off, 4 + ml);
                got_sfin = 1;
            } else {
                return NTX_TLS_FAIL;
            }
            off += 4 + ml;
        }
        if (off != rlen) return NTX_TLS_FAIL;
    }

    if (nalpn == 1 && alpn && alpn[0] && strcmp(alpn[0], "http/1.1") == 0 && t->alpn[0] == 0)
        memcpy(t->alpn, "http/1.1", 9); /* server without ALPN → default http/1.1 */
    t->ready = 1;
    return NTX_TLS_OK;
}

/* Test hook: fixed client key material for the TLS 1.3 path (default NULL = random). */
static const uint8_t *s_test_priv, *s_test_cr;

void ntx_tls13_test_set_keys(const uint8_t priv[32], const uint8_t cr[32]) {
    s_test_priv = priv;
    s_test_cr = cr;
}

void ntx_tls13_test_clear_keys(void) {
    s_test_priv = NULL;
    s_test_cr = NULL;
}

/* Read one raw record (header + fragment). Alerts must stay distinguishable
   from I/O errors for the 1.2 fallback decision, so this does no decryption. */
static int rd_record13(int fd, uint8_t hdr[5], uint8_t *body, size_t cap, size_t *blen) {
    if (io_read(fd, hdr, 5) != 0) return -1;
    size_t L = ntx_wire_rd16(hdr + 3);
    if (L > cap) return -1;
    if (L && io_read(fd, body, L) != 0) return -1;
    *blen = L;
    return 0;
}

struct hs13_buf {
    uint8_t ch[1024];
    uint8_t body[NTX_TLS13_MAX_CIPHERTEXT];
    uint8_t pt[NTX_TLS13_MAX_CIPHERTEXT];
    uint8_t acc[MAX_HS_ACC];
    uint8_t leaf[16384];
};

/* TLS 1.3 client handshake (RFC 8446 section 2):
 *   ClientHello -> ServerHello (plaintext) -> [CCS] -> EncryptedExtensions,
 *   Certificate, CertificateVerify, Finished (handshake keys) -> client
 *   Finished -> application keys. The transcript is the SHA-256 of all
 *   handshake messages. Pin / TOFU is decided at the Certificate message.
 * Returns HS13_FALLBACK when the server is not (usable as) TLS 1.3: alert, I/O
 * error on the first flight, ServerHello without supported_versions, HRR. */
static int ntx_tls_handshake_13(ntx_tls *t, int fd, const char *sni, const uint8_t pins[][32],
                                int npins, int io_timeout_sec, const char *const alpn[],
                                int nalpn) {
    if (!t || fd < 0) return NTX_TLS_FAIL;
    ntx_tls_close(t);
    memset(t, 0, sizeof *t);
    t->fd = fd;
    t->ver = 13;
    if (sni) {
        size_t n = strlen(sni);
        if (n >= sizeof t->sni) n = sizeof t->sni - 1;
        memcpy(t->sni, sni, n);
    }
    peer_ip_str(fd, t->peer_ip, sizeof t->peer_ip);
    sock_timeouts(fd, io_timeout_sec);

    struct hs13_buf *w = malloc(sizeof *w);
    if (!w) return NTX_TLS_FAIL;

    uint8_t priv[32], pub[32], cr[32], sid[32];
    uint8_t shared[32], hs_secret[32], c_hs[32], s_hs[32], c_ap[32], s_ap[32];
    uint8_t H[32], h_sfin[32];
    char alpn_neg[16] = { 0 };
    ntx_sha256_ctx tr;
    int rc = NTX_TLS_FAIL;

    if (s_test_priv) memcpy(priv, s_test_priv, 32);
    else ntx_rand_bytes(priv, 32);
    ntx_x25519_base(pub, priv);
    if (s_test_cr) {
        memcpy(cr, s_test_cr, 32);
        ntx_sha256(cr, 32, sid); /* deterministic for golden replay only */
    } else {
        ntx_rand_bytes(cr, 32);
        ntx_rand_bytes(sid, 32);
    }

    size_t ch_len = ntx_tls13_client_hello(w->ch, sizeof w->ch, t->sni, cr, sid, pub, alpn, nalpn);
    if (!ch_len) goto done;
    {
        tls_dir plain = { 0, NULL, NULL, NULL };
        if (rec_send(t, REC_HS, w->ch, ch_len, &plain) != 0) goto done;
    }
    ntx_sha256_init(&tr);
    ntx_sha256_update(&tr, w->ch, ch_len);

    /* ---- ServerHello ---- */
    uint8_t hdr[5];
    size_t blen;
    if (rd_record13(fd, hdr, w->body, sizeof w->body, &blen) != 0) {
        rc = HS13_FALLBACK;
        goto done;
    }
    if (hdr[0] == REC_ALERT) {
        rc = HS13_FALLBACK;
        goto done;
    }
    if (hdr[0] != REC_HS || blen < 4) goto done;
    size_t sh_len = 4 + (size_t)ntx_wire_rd24(w->body + 1);
    if (sh_len > blen) goto done;
    struct ntx_tls13_sh sh;
    int shrc = ntx_tls13_parse_server_hello(w->body, sh_len, sid, &sh);
    if (shrc == NTX_TLS13_SH_V12 || shrc == NTX_TLS13_SH_HRR) {
        rc = HS13_FALLBACK;
        goto done;
    }
    if (shrc != NTX_TLS13_SH_OK || sh_len != blen) goto done;
    ntx_sha256_update(&tr, w->body, sh_len);

    if (ntx_x25519(shared, priv, sh.key_share_pub) != 0) goto done;
    memset(priv, 0, sizeof priv);
    {
        ntx_sha256_ctx tmp = tr;
        ntx_sha256_final(&tmp, H);
    }
    if (ntx_tls13_hs_secrets(shared, H, hs_secret, c_hs, s_hs) != 0) goto done;
    if (ntx_tls13_dir_init(&t->r13, s_hs) != 0 || ntx_tls13_dir_init(&t->w13, c_hs) != 0) goto done;

    /* middlebox compatibility (RFC 8446 appendix D.4): one CCS after the CH/SH */
    {
        static const uint8_t ccs[6] = { REC_CCS, 3, 3, 0, 1, 1 };
        if (io_write(fd, ccs, sizeof ccs) != 0) goto done;
    }

    /* ---- encrypted server flight ---- */
    enum { ST_EE, ST_CERT, ST_CV, ST_FIN, ST_DONE } state = ST_EE;
    size_t acc_n = 0, leaf_len = 0;
    int ccs_seen = 0;
    while (state != ST_DONE) {
        if (rd_record13(fd, hdr, w->body, sizeof w->body, &blen) != 0) goto done;
        if (hdr[0] == REC_CCS) {
            if (blen != 1 || w->body[0] != 1 || ++ccs_seen > 8) goto done;
            continue;
        }
        if (hdr[0] != REC_APP) goto done;
        size_t pl;
        uint8_t ityp;
        if (ntx_tls13_open(&t->r13, hdr, w->body, blen, w->pt, sizeof w->pt, &pl, &ityp) != 0)
            goto done;
        if (ityp != REC_HS || pl == 0 || acc_n + pl > sizeof w->acc) goto done;
        memcpy(w->acc + acc_n, w->pt, pl);
        acc_n += pl;

        size_t off = 0;
        while (state != ST_DONE && acc_n - off >= 4) {
            size_t ml = 4 + (size_t)ntx_wire_rd24(w->acc + off + 1);
            if (ml > sizeof w->acc) goto done;
            if (acc_n - off < ml) break;
            const uint8_t *m = w->acc + off;
            if (state == ST_EE && m[0] == NTX_HS13_ENCRYPTED_EXTENSIONS) {
                if (ntx_tls13_parse_ee(m, ml, alpn_neg) != 0) goto done;
                state = ST_CERT;
            } else if (state == ST_CERT && m[0] == NTX_HS13_CERTIFICATE) {
                const uint8_t *der;
                size_t dl;
                if (ntx_tls13_parse_cert(m, ml, &der, &dl) != 0 || dl > sizeof w->leaf) goto done;
                uint8_t lp[32];
                if (ntx_tls_spki_sha256(der, dl, lp) != 0) goto done;
                if (npins >= 1 && !pins_match(lp, pins, npins)) {
                    pin_fail_alert(t->peer_ip, t->sni, lp, pins, npins);
                    rc = NTX_TLS_PIN_FAIL;
                    goto done;
                }
                memcpy(t->leaf_pin, lp, 32);
                t->leaf_pin_valid = 1;
                memcpy(w->leaf, der, dl);
                leaf_len = dl;
                state = ST_CV;
            } else if (state == ST_CV && m[0] == NTX_HS13_CERTIFICATE_VERIFY) {
                ntx_sha256_ctx tmp = tr;
                ntx_sha256_final(&tmp, H);
                if (ntx_tls13_certverify(m, ml, w->leaf, leaf_len, H) != 0) goto done;
                state = ST_FIN;
            } else if (state == ST_FIN && m[0] == NTX_HS13_FINISHED) {
                ntx_sha256_ctx tmp = tr;
                ntx_sha256_final(&tmp, H);
                if (ntx_tls13_finished_verify(m, ml, s_hs, H) != 0) goto done;
                ntx_sha256_update(&tr, m, ml);
                tmp = tr;
                ntx_sha256_final(&tmp, h_sfin);
                state = ST_DONE;
                off += ml;
                break;
            } else {
                goto done; /* unexpected / unsupported (e.g. CertificateRequest) */
            }
            ntx_sha256_update(&tr, m, ml);
            off += ml;
        }
        if (state == ST_DONE) {
            if (acc_n != off) goto done; /* nothing may follow Finished under handshake keys */
        } else {
            memmove(w->acc, w->acc + off, acc_n - off);
            acc_n -= off;
        }
    }
    if (!t->leaf_pin_valid) goto done;

    /* ---- client Finished, then application keys ---- */
    {
        uint8_t fin[36], rec[36 + 22];
        size_t rl;
        fin[0] = NTX_HS13_FINISHED;
        ntx_wire_wr24(fin + 1, 32);
        if (ntx_tls13_finished_data(c_hs, h_sfin, fin + 4) != 0) goto done;
        if (ntx_tls13_seal(&t->w13, REC_HS, fin, sizeof fin, rec, sizeof rec, &rl) != 0) goto done;
        if (io_write(fd, rec, rl) != 0) goto done;
    }
    if (ntx_tls13_app_secrets(hs_secret, h_sfin, c_ap, s_ap) != 0) goto done;
    if (ntx_tls13_dir_init(&t->w13, c_ap) != 0 || ntx_tls13_dir_init(&t->r13, s_ap) != 0) goto done;

    if (alpn_neg[0]) memcpy(t->alpn, alpn_neg, strlen(alpn_neg) + 1);
    else if (nalpn == 1 && alpn && alpn[0] && strcmp(alpn[0], "http/1.1") == 0)
        memcpy(t->alpn, "http/1.1", 9); /* server without ALPN: same convention as TLS 1.2 */
    t->cipher = HS13_CS;
    t->ready = 1;
    rc = NTX_TLS_OK;

done:
    memset(priv, 0, sizeof priv);
    memset(shared, 0, sizeof shared);
    memset(hs_secret, 0, sizeof hs_secret);
    memset(c_hs, 0, sizeof c_hs);
    memset(s_hs, 0, sizeof s_hs);
    memset(c_ap, 0, sizeof c_ap);
    memset(s_ap, 0, sizeof s_ap);
    memset(w, 0, sizeof *w);
    free(w);
    if (rc != NTX_TLS_OK) {
        ntx_tls_close(t);
        t->fd = fd; /* the caller still owns the fd */
    }
    return rc;
}

/* Fallback to TLS 1.2: close + reconnect + the regular 1.2 path (same pin, same
 * peer IP:port from getpeername). A second ClientHello on the same connection
 * is NOT an option - a server that rejected the 1.3 hello may already have
 * dropped state, and ntx_tls_handshake_12 assumes a fresh connection.
 * MUST NOT call ntx_sock_resolve(sni): DoH -> TLS -> fallback -> resolve(sni)
 * would recurse into DoH. Reconnect only to the address we were already
 * connected to. */
static int tls13_fallback(ntx_tls *t, int fd, const char *sni, const uint8_t pins[][32],
                          int npins, int io_timeout_sec, const char *const alpn[], int nalpn) {
    uint16_t port = 0;
    ntx_addr addr;
    struct sockaddr_storage ss;
    socklen_t sl = sizeof ss;
    memset(&addr, 0, sizeof addr);
    if (getpeername(fd, (struct sockaddr *)&ss, &sl) != 0 ||
        ntx_addr_from_sockaddr(&addr, &port, &ss) != 0 || port == 0) {
        close(fd);
        return NTX_TLS_FAIL;
    }
    close(fd);
    if (!sni) return NTX_TLS_FAIL;
    int nfd = ntx_addr_is_v6(&addr) ? ntx_sock_tcp6() : ntx_sock_tcp4();
    if (nfd < 0) return NTX_TLS_FAIL;
    if (ntx_sock_connect_addr(nfd, &addr, port) != 0) {
        close(nfd);
        return NTX_TLS_FAIL;
    }
    struct pollfd pfd = { .fd = nfd, .events = POLLOUT };
    if (poll(&pfd, 1, 5000) <= 0) {
        close(nfd);
        return NTX_TLS_FAIL;
    }
    int soerr = 0;
    socklen_t sl2 = sizeof soerr;
    if (getsockopt(nfd, SOL_SOCKET, SO_ERROR, &soerr, &sl2) != 0 || soerr != 0) {
        close(nfd);
        return NTX_TLS_FAIL;
    }
    int fl = fcntl(nfd, F_GETFL);
    if (fl >= 0) fcntl(nfd, F_SETFL, fl & ~O_NONBLOCK);
    /* Callers keep using the descriptor number they passed in (and close it on
       failure), so hand the new connection back under that same number. */
    if (nfd != fd) {
        if (dup2(nfd, fd) < 0) {
            close(nfd);
            return NTX_TLS_FAIL;
        }
        close(nfd);
        nfd = fd;
    }
    t->fd = nfd;
    return ntx_tls_handshake_12(t, nfd, sni, pins, npins, io_timeout_sec, alpn, nalpn, 1);
}

int ntx_tls_handshake_ex(ntx_tls *t, int fd, const char *sni, const uint8_t pins[][32], int npins,
                         int io_timeout_sec, const char *const alpn_list[], int nalpn) {
    if (!t || fd < 0) return NTX_TLS_FAIL;
    /* Test binaries without ntx_tls13.c (weak symbol, address 0): TLS 1.2 only. */
    if (!NTX_TLS13_LIVE || !ntx_tls13_client_hello)
        return ntx_tls_handshake_12(t, fd, sni, pins, npins, io_timeout_sec, alpn_list, nalpn, 0);
    int rc = ntx_tls_handshake_13(t, fd, sni, pins, npins, io_timeout_sec, alpn_list, nalpn);
    if (rc == HS13_FALLBACK)
        return tls13_fallback(t, fd, sni, pins, npins, io_timeout_sec, alpn_list, nalpn);
    return rc;
}
