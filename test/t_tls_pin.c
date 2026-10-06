#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_hkdf.c"
/* Mock ALPN/fallback tests exercise 1.3→1.2 path (production: LIVE=0). */
#define NTX_TLS13_LIVE 1
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls13.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "util.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static void expect_hex(const char *name, const uint8_t *got, const char *hex) {
    uint8_t exp[32];
    if (strlen(hex) != 64) {
        fprintf(stderr, "FAIL %s bad expected hex len\n", name);
        exit(1);
    }
    hex_to_bytes(hex, exp, 32);
    if (memcmp(got, exp, 32) != 0) {
        fprintf(stderr, "FAIL %s\n  got ", name);
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n  want %s\n", hex);
        exit(1);
    }
    printf("PASS %s\n", name);
}

static char *load_hex_line(const char *path) {
    size_t n;
    uint8_t *raw = read_file(path, &n);
    while (n > 0 && (raw[n - 1] == '\n' || raw[n - 1] == '\r' || raw[n - 1] == ' '))
        n--;
    char *s = malloc(n + 1);
    if (!s) exit(1);
    memcpy(s, raw, n);
    s[n] = 0;
    free(raw);
    return s;
}

/* ---- T14: mock TLS 1.2 server (loopback) — ALPN behavior of handshake_ex ---- */

static size_t der_int(uint8_t *out, const uint8_t v[32]) {
    size_t i = 0;
    while (i < 31 && v[i] == 0) i++;
    int pad = (v[i] & 0x80) != 0;
    out[0] = 0x02;
    out[1] = (uint8_t)(32 - i + (pad ? 1 : 0));
    size_t o = 2;
    if (pad) out[o++] = 0;
    memcpy(out + o, v + i, 32 - i);
    return o + (32 - i);
}

static int p256_sign_ecdsa(const uint8_t d[32], const uint8_t hash[32],
                           uint8_t der[72], size_t *der_len) {
    for (int attempt = 0; attempt < 64; attempt++) {
        uint8_t k[32];
        do {
            ntx_rand_bytes(k, 32);
        } while (!sc_ok(k));
        jpt G, R;
        j_from_affine(&G, GX, GY);
        j_mul(&R, &G, k);
        if (R.inf) continue;
        uint8_t rx[32], ry[32];
        j_to_affine(rx, ry, &R);
        uint8_t r[32], e[32], rd[32], t[32], ki[32], s[32];
        sc_mod(r, rx);
        if (is_zero(r)) continue;
        sc_mod(e, hash);
        sc_mul(rd, r, d);
        uint8_t e33[33], rd33[33], n33[33], t33[33];
        e33[0] = 0;
        memcpy(e33 + 1, e, 32);
        rd33[0] = 0;
        memcpy(rd33 + 1, rd, 32);
        n33[0] = 0;
        memcpy(n33 + 1, N, 32);
        ntx_bn_add(t33, 33, e33, rd33);
        if (ntx_bn_cmp(t33, n33, 33) >= 0) ntx_bn_sub(t33, 33, t33, n33);
        memcpy(t, t33 + 1, 32);
        sc_inv(ki, k);
        sc_mul(s, ki, t);
        if (is_zero(s)) continue;
        uint8_t ir[35], isig[35];
        size_t lr = der_int(ir, r);
        size_t ls = der_int(isig, s);
        if (2 + lr + ls > 72) continue;
        der[0] = 0x30;
        der[1] = (uint8_t)(lr + ls);
        memcpy(der + 2, ir, lr);
        memcpy(der + 2 + lr, isig, ls);
        *der_len = 2 + lr + ls;
        return 0;
    }
    return -1;
}

/* Minimal self-signed-looking cert: TBS{version,serial,sigalg,issuer,validity,subject,SPKI} */
static size_t build_cert(uint8_t *out, const uint8_t qx[32], const uint8_t qy[32]) {
    uint8_t tbs[256];
    size_t o = 0;
    tbs[o++] = 0xa0; tbs[o++] = 0x03; tbs[o++] = 0x02; tbs[o++] = 0x01; tbs[o++] = 0x02;
    tbs[o++] = 0x02; tbs[o++] = 0x01; tbs[o++] = 0x01;
    tbs[o++] = 0x30; tbs[o++] = 0x0c;
    tbs[o++] = 0x06; tbs[o++] = 0x08;
    tbs[o++] = 0x2a; tbs[o++] = 0x86; tbs[o++] = 0x48; tbs[o++] = 0xce;
    tbs[o++] = 0x3d; tbs[o++] = 0x04; tbs[o++] = 0x03; tbs[o++] = 0x02;
    tbs[o++] = 0x05; tbs[o++] = 0x00;
    tbs[o++] = 0x30; tbs[o++] = 0x03; tbs[o++] = 0x31; tbs[o++] = 0x01; tbs[o++] = 0x00;
    tbs[o++] = 0x30; tbs[o++] = 0x18;
    tbs[o++] = 0x17; tbs[o++] = 0x0a;
    memcpy(tbs + o, "2601010000", 10); o += 10;
    tbs[o++] = 0x17; tbs[o++] = 0x0a;
    memcpy(tbs + o, "2701010000", 10); o += 10;
    tbs[o++] = 0x30; tbs[o++] = 0x03; tbs[o++] = 0x31; tbs[o++] = 0x01; tbs[o++] = 0x00;
    tbs[o++] = 0x30; tbs[o++] = 0x59;
    tbs[o++] = 0x30; tbs[o++] = 0x13;
    tbs[o++] = 0x06; tbs[o++] = 0x07;
    tbs[o++] = 0x2a; tbs[o++] = 0x86; tbs[o++] = 0x48; tbs[o++] = 0xce;
    tbs[o++] = 0x3d; tbs[o++] = 0x02; tbs[o++] = 0x01;
    tbs[o++] = 0x06; tbs[o++] = 0x08;
    tbs[o++] = 0x2a; tbs[o++] = 0x86; tbs[o++] = 0x48; tbs[o++] = 0xce;
    tbs[o++] = 0x3d; tbs[o++] = 0x03; tbs[o++] = 0x01; tbs[o++] = 0x07;
    tbs[o++] = 0x03; tbs[o++] = 0x42; tbs[o++] = 0x00; tbs[o++] = 0x04;
    memcpy(tbs + o, qx, 32); o += 32;
    memcpy(tbs + o, qy, 32); o += 32;
    size_t tbs_len = o;
    o = 0;
    size_t outer_len = tbs_len + (tbs_len >= 128 ? 3 : 2) + 17;
    out[o++] = 0x30;
    if (outer_len >= 128) {
        out[o++] = 0x81;
        out[o++] = (uint8_t)outer_len;
    } else {
        out[o++] = (uint8_t)outer_len;
    }
    out[o++] = 0x30;
    if (tbs_len >= 128) {
        out[o++] = 0x81;
        out[o++] = (uint8_t)tbs_len;
    } else {
        out[o++] = (uint8_t)tbs_len;
    }
    memcpy(out + o, tbs, tbs_len);
    o += tbs_len;
    out[o++] = 0x30; out[o++] = 0x0c;
    out[o++] = 0x06; out[o++] = 0x08;
    out[o++] = 0x2a; out[o++] = 0x86; out[o++] = 0x48; out[o++] = 0xce;
    out[o++] = 0x3d; out[o++] = 0x04; out[o++] = 0x03; out[o++] = 0x02;
    out[o++] = 0x05; out[o++] = 0x00;
    out[o++] = 0x03; out[o++] = 0x01; out[o++] = 0x00;
    return o;
}

/* Misbehaving-server switches for the TLS 1.2 mock (set in the parent before fork). */
static int g_mock_sentinel;  /* server_random ends in "DOWNGRD\x01" (RFC 8446 4.1.3) */
static int g_mock_dup_cert;  /* Certificate message sent twice */

typedef struct {
    int fd;
    const uint8_t *cert;
    size_t cert_len;
    const uint8_t *p256_d;
    const uint8_t *x25519_priv;
    int sh_alpn;
    int ok;
} mock_srv_t;

static void mock_srv_run(mock_srv_t *m) {
    ntx_tls st;
    memset(&st, 0, sizeof st);
    st.fd = m->fd;
    tls_dir plain = { 0, NULL, NULL, NULL };
    ntx_sha256_ctx hs;
    ntx_sha256_init(&hs);

    uint8_t typ, rec[18432];
    size_t rlen;
    if (rec_recv(&st, &typ, rec, sizeof rec, &rlen, &plain) != 0) return;
    if (typ != 22 || rlen < 43 || rec[0] != 1) return;
    uint8_t client_random[32];
    memcpy(client_random, rec + 6, 32);
    ntx_sha256_update(&hs, rec, rlen);

    uint8_t server_random[32];
    ntx_rand_bytes(server_random, 32);
    if (g_mock_sentinel) memcpy(server_random + 24, "DOWNGRD\x01", 8);

    uint8_t msg[18432];
    size_t o = 0;
    size_t sh_len = 38 + (m->sh_alpn ? 17 : 0);
    msg[o++] = 2;
    ntx_wire_wr24(msg + o, (uint32_t)sh_len); o += 3;
    ntx_wire_wr16(msg + o, 0x0303); o += 2;
    memcpy(msg + o, server_random, 32); o += 32;
    msg[o++] = 0;
    ntx_wire_wr16(msg + o, 0xC02B); o += 2;
    msg[o++] = 0;
    if (m->sh_alpn) {
        ntx_wire_wr16(msg + o, 15); o += 2;
        ntx_wire_wr16(msg + o, 16); o += 2;
        ntx_wire_wr16(msg + o, 11); o += 2;
        ntx_wire_wr16(msg + o, 9); o += 2;
        msg[o++] = 8;
        memcpy(msg + o, "http/1.1", 8); o += 8;
    }
    uint32_t clist = 3 + (uint32_t)m->cert_len;
    size_t cert_msg_start = o;
    msg[o++] = 11;
    ntx_wire_wr24(msg + o, 3 + clist); o += 3;
    ntx_wire_wr24(msg + o, clist); o += 3;
    ntx_wire_wr24(msg + o, (uint32_t)m->cert_len); o += 3;
    memcpy(msg + o, m->cert, m->cert_len); o += m->cert_len;
    if (g_mock_dup_cert) {
        size_t cl = o - cert_msg_start;
        memcpy(msg + o, msg + cert_msg_start, cl);
        o += cl;
    }
    uint8_t xpub[32];
    ntx_x25519_base(xpub, m->x25519_priv);
    uint8_t skx_params[36];
    skx_params[0] = 3;
    ntx_wire_wr16(skx_params + 1, 0x001d);
    skx_params[3] = 32;
    memcpy(skx_params + 4, xpub, 32);
    uint8_t tosign[100];
    memcpy(tosign, client_random, 32);
    memcpy(tosign + 32, server_random, 32);
    memcpy(tosign + 64, skx_params, 36);
    uint8_t dig[32];
    ntx_sha256(tosign, sizeof tosign, dig);
    uint8_t der[72];
    size_t der_len = 0;
    if (p256_sign_ecdsa(m->p256_d, dig, der, &der_len) != 0) return;
    msg[o++] = 12;
    ntx_wire_wr24(msg + o, (uint32_t)(40 + der_len)); o += 3;
    memcpy(msg + o, skx_params, 36); o += 36;
    msg[o++] = 4;
    msg[o++] = 3;
    ntx_wire_wr16(msg + o, (uint16_t)der_len); o += 2;
    memcpy(msg + o, der, der_len); o += der_len;
    msg[o++] = 14;
    ntx_wire_wr24(msg + o, 0); o += 3;
    ntx_sha256_update(&hs, msg, o);
    if (rec_send(&st, 22, msg, o, &plain) != 0) return;

    if (rec_recv(&st, &typ, rec, sizeof rec, &rlen, &plain) != 0) return;
    if (typ != 22 || rlen != 37 || rec[0] != 16) return;
    uint8_t client_pub[32];
    memcpy(client_pub, rec + 5, 32);
    ntx_sha256_update(&hs, rec, rlen);

    uint8_t shared[32];
    ntx_x25519(shared, m->x25519_priv, client_pub);
    uint8_t seed[64];
    memcpy(seed, client_random, 32);
    memcpy(seed + 32, server_random, 32);
    uint8_t master[48];
    tls12_prf(shared, 32, "master secret", seed, 64, master, 48);
    memset(shared, 0, sizeof shared);
    memcpy(seed, server_random, 32);
    memcpy(seed + 32, client_random, 32);
    uint8_t kb[40];
    tls12_prf(master, 48, "key expansion", seed, 64, kb, 40);
    uint8_t wkey[16], wiv[4], rkey[16], riv[4];
    memcpy(wkey, kb + 16, 16); /* server writes with server_key */
    memcpy(rkey, kb, 16);      /* server reads with client_key */
    memcpy(wiv, kb + 36, 4);
    memcpy(riv, kb + 32, 4);
    memset(kb, 0, sizeof kb);
    ntx_aes128_gcm gw, gr;
    ntx_aes128_gcm_init(&gw, wkey);
    ntx_aes128_gcm_init(&gr, rkey);
    uint64_t seqw = 0, seqr = 0;
    tls_dir wr = { 1, &seqw, &gw, wiv };
    tls_dir rd = { 1, &seqr, &gr, riv };

    if (rec_recv(&st, &typ, rec, sizeof rec, &rlen, &plain) != 0) return;
    if (typ != 20 || rlen != 1 || rec[0] != 1) return;
    if (rec_recv(&st, &typ, rec, sizeof rec, &rlen, &rd) != 0) return;
    if (typ != 22 || rlen != 16 || rec[0] != 20) return;
    uint8_t hs_hash[32], verify[12];
    ntx_sha256_ctx tmp = hs;
    ntx_sha256_final(&tmp, hs_hash);
    tls12_prf(master, 48, "client finished", hs_hash, 32, verify, 12);
    if (memcmp(verify, rec + 4, 12) != 0) return;
    ntx_sha256_update(&hs, rec, rlen);
    tmp = hs;
    ntx_sha256_final(&tmp, hs_hash);
    uint8_t ccs = 1;
    if (rec_send(&st, 20, &ccs, 1, &plain) != 0) return;
    tls12_prf(master, 48, "server finished", hs_hash, 32, verify, 12);
    uint8_t finmsg[16];
    finmsg[0] = 20;
    ntx_wire_wr24(finmsg + 1, 12);
    memcpy(finmsg + 4, verify, 12);
    if (rec_send(&st, 22, finmsg, 16, &wr) != 0) return;
    m->ok = 1;
}

/* T38a/b: after a 1.3 ClientHello the mock ("1.2" server) answers with a fatal alert and
   closes the connection — the client must connect a SECOND time (fallback:
   close + reconnect + 1.2). */
static void mock_reject_13(int fd) {
    if (fd < 0) return;
    ntx_tls st;
    memset(&st, 0, sizeof st);
    st.fd = fd;
    tls_dir plain = { 0, NULL, NULL, NULL };
    uint8_t typ, rec[18432];
    size_t rlen;
    if (rec_recv(&st, &typ, rec, sizeof rec, &rlen, &plain) == 0 && typ == 22) {
        /* alert: fatal (1), protocol_version (0x46) */
        uint8_t alert[7] = { 21, 0x03, 0x03, 0x00, 0x02, 0x01, 0x46 };
        io_write(fd, alert, sizeof alert);
    }
    close(fd);
}

/* D3a pin-set: pin_slot 0/1 = real pin at key[0]/key[1] of a 2-key set
   (expect NTX_TLS_OK); pin_slot 2 = no key matches (expect NTX_TLS_PIN_FAIL). */
static void run_alpn_case(const char *name, int sh_alpn, int pin_slot, int expect_rc) {
    uint8_t d[32];
    do {
        ntx_rand_bytes(d, 32);
    } while (!sc_ok(d));
    jpt G, Q;
    j_from_affine(&G, GX, GY);
    j_mul(&Q, &G, d);
    uint8_t qx[32], qy[32];
    j_to_affine(qx, qy, &Q);
    uint8_t cert[256];
    size_t cert_len = build_cert(cert, qx, qy);
    uint8_t pin[32];
    if (ntx_tls_spki_sha256(cert, cert_len, pin) != 0) {
        printf("FAIL %s cert build\n", name);
        exit(1);
    }
    uint8_t pins[2][32];
    memset(pins[0], 0x11, 32);
    memset(pins[1], 0x22, 32);
    if (pin_slot >= 0 && pin_slot < 2) memcpy(pins[pin_slot], pin, 32);
    uint8_t xp[32];
    ntx_rand_bytes(xp, 32);

    /* TCP loopback: the mock accepts TWO connections — #1 (1.3 CH → alert),
       #2 (full 1.2). The fallback reconnects to the peer IP from getpeername
       (no DoH resolve of the SNI). */
    int lfd = ntx_sock_tcp4();
    if (lfd < 0) {
        printf("FAIL %s listen\n", name);
        exit(1);
    }
    uint16_t port = ntx_sock_bind0(lfd);
    if (port == 0 || ntx_sock_listen(lfd, 8) != 0) {
        printf("FAIL %s bind\n", name);
        exit(1);
    }
    {
        int fl = fcntl(lfd, F_GETFL);
        if (fl >= 0) fcntl(lfd, F_SETFL, fl & ~O_NONBLOCK);
    }
    pid_t pid = fork();
    if (pid < 0) {
        printf("FAIL %s fork\n", name);
        exit(1);
    }
    if (pid == 0) {
        int c1 = ntx_sock_accept4(lfd);
        {
            int fl = fcntl(c1, F_GETFL);
            if (fl >= 0) fcntl(c1, F_SETFL, fl & ~O_NONBLOCK);
        }
        mock_reject_13(c1);
        int c2 = ntx_sock_accept4(lfd);
        {
            int fl = fcntl(c2, F_GETFL);
            if (fl >= 0) fcntl(c2, F_SETFL, fl & ~O_NONBLOCK);
        }
        mock_srv_t m = { c2, cert, cert_len, d, xp, sh_alpn, 0 };
        mock_srv_run(&m);
        _exit(m.ok ? 0 : 1);
    }
    close(lfd);
    int fd = ntx_sock_tcp4();
    if (fd < 0) {
        printf("FAIL %s connect\n", name);
        exit(1);
    }
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001u);
    sa.sin_port = htons(port);
    if (connect(fd, (struct sockaddr *)&sa, sizeof sa) != 0 &&
        errno != EINPROGRESS) {
        printf("FAIL %s connect\n", name);
        exit(1);
    }
    struct pollfd pfd = { .fd = fd, .events = POLLOUT };
    if (poll(&pfd, 1, 5000) <= 0) {
        printf("FAIL %s connect-wait\n", name);
        exit(1);
    }
    {
        int fl = fcntl(fd, F_GETFL);
        if (fl >= 0) fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    ntx_tls t;
    ntx_tls_init(&t);
    const char *alpn1[] = { "http/1.1" };
    /* pin_slot == -2: TOFU mode (npins == 0) - connect succeeds and reports the leaf pin */
    int rc = ntx_tls_handshake_ex(&t, fd, "127.0.0.1", pins, pin_slot == -2 ? 0 : 2, 5, alpn1, 1);
    /* close before waitpid: on PIN_FAIL the mock child blocks in rec_recv */
    if (t.fd >= 0) close(t.fd);
    int status = 0;
    waitpid(pid, &status, 0);
    int srv_ok = WIFEXITED(status) && WEXITSTATUS(status) == 0;
    if (rc != expect_rc ||
        (expect_rc == NTX_TLS_OK && (!srv_ok || !t.ready || strcmp(t.alpn, "http/1.1") != 0))) {
        printf("FAIL %s rc=%d expect=%d srv_ok=%d ready=%d alpn='%s'\n",
               name, rc, expect_rc, srv_ok, t.ready, t.alpn);
        exit(1);
    }
    if (pin_slot == -2 && (!t.leaf_pin_valid || memcmp(t.leaf_pin, pin, 32) != 0)) {
        printf("FAIL %s leaf pin not reported\n", name);
        exit(1);
    }
    printf("PASS %s\n", name);
}

int main(void) {
    size_t der_len;
    uint8_t *der;
    uint8_t pin[32];
    char *want;

    der = read_file("test/vectors/tls_spki/test_leaf.der", &der_len);
    want = load_hex_line("test/vectors/tls_spki/test_leaf.pin.hex");
    if (ntx_tls_spki_sha256(der, der_len, pin) != 0) {
        fprintf(stderr, "FAIL spki extract test_leaf\n");
        exit(1);
    }
    expect_hex("spki-test-leaf", pin, want);
    free(der);
    free(want);

    {
        uint8_t wrong[32];
        memset(wrong, 0xab, 32);
        if (memcmp(pin, wrong, 32) == 0) {
            fprintf(stderr, "FAIL unexpected pin collide\n");
            exit(1);
        }
        printf("PASS pin-mismatch-detectable\n");
    }

    der = read_file("test/vectors/tls_spki/google_rsa_leaf.der", &der_len);
    want = load_hex_line("test/vectors/tls_spki/google_rsa_leaf.pin.hex");
    if (ntx_tls_spki_sha256(der, der_len, pin) != 0) {
        fprintf(stderr, "FAIL spki extract google_rsa\n");
        exit(1);
    }
    expect_hex("spki-google-rsa-leaf", pin, want);

    {
        uint8_t pins[2][32];
        memset(pins[0], 0x11, 32);
        memset(pins[1], 0x22, 32);
        int match = 0;
        for (int i = 0; i < 2; i++)
            if (memcmp(pin, pins[i], 32) == 0) match = 1;
        if (match) {
            fprintf(stderr, "FAIL wrong pins matched google leaf\n");
            exit(1);
        }
        printf("PASS wrong-pins-no-match\n");
        if (NTX_TLS_PIN_FAIL != -2) {
            fprintf(stderr, "FAIL PIN_FAIL constant\n");
            exit(1);
        }
        printf("PASS pin-fail-constant\n");
    }

    {
        /* D3a: pin-set (npins keys/host) — leaf accepted iff it matches
           any key; an all-zero (unused) slot never matches. */
        uint8_t k1[32], k2[32], set[3][32], zset[1][32];
        memset(k1, 0x11, 32);
        memset(k2, 0x22, 32);
        memset(zset[0], 0, 32);
        memcpy(set[0], pin, 32);
        memcpy(set[1], k1, 32);
        memcpy(set[2], k2, 32);
        if (pins_match(pin, set, 3) != 1) {
            fprintf(stderr, "FAIL pinset-key0-match\n");
            exit(1);
        }
        printf("PASS pinset-key0-match\n");
        memcpy(set[0], k1, 32);
        memcpy(set[1], pin, 32);
        if (pins_match(pin, set, 3) != 1) {
            fprintf(stderr, "FAIL pinset-key1-match\n");
            exit(1);
        }
        printf("PASS pinset-key1-match\n");
        memcpy(set[0], k1, 32);
        memcpy(set[1], k2, 32);
        memcpy(set[2], zset[0], 32);
        if (pins_match(pin, set, 3) != 0) {
            fprintf(stderr, "FAIL pinset-none-match\n");
            exit(1);
        }
        printf("PASS pinset-none-match\n");
        if (pins_match(pin, zset, 1) != 0) {
            fprintf(stderr, "FAIL pinset-allzero-never\n");
            exit(1);
        }
        printf("PASS pinset-allzero-never\n");
    }

    free(der);
    free(want);

    {
        uint8_t junk[8] = { 0x30, 0x02, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06 };
        uint8_t out[32];
        if (ntx_tls_spki_sha256(junk, sizeof junk, out) == 0) {
            fprintf(stderr, "FAIL expected parse fail on junk\n");
            exit(1);
        }
        printf("PASS spki-junk-reject\n");
    }

    run_alpn_case("alpn-ex-http11-no-sh-alpn", 0, 0, NTX_TLS_OK);
    run_alpn_case("alpn-ex-http11-sh-alpn", 1, 0, NTX_TLS_OK);
    run_alpn_case("pinset-key1-e2e", 1, 1, NTX_TLS_OK);
    run_alpn_case("pinset-nomatch-e2e", 1, 2, NTX_TLS_PIN_FAIL);
    run_alpn_case("tofu-no-pins-e2e", 1, -2, NTX_TLS_OK);

    /* A TLS 1.3-capable client that ends up on 1.2 must refuse a server that signals
       "I would have done 1.3" (RFC 8446 4.1.3): the signed sentinel in server_random. */
    g_mock_sentinel = 1;
    run_alpn_case("tls12-downgrade-sentinel-rejected", 1, 0, NTX_TLS_FAIL);
    g_mock_sentinel = 0;
    /* Handshake messages must arrive once and in order. */
    g_mock_dup_cert = 1;
    run_alpn_case("tls12-duplicate-certificate-rejected", 1, 0, NTX_TLS_FAIL);
    g_mock_dup_cert = 0;
    run_alpn_case("tls12-still-ok-after-negatives", 1, 0, NTX_TLS_OK);

    {
        /* rsa_from_spki must only accept rsaEncryption keys (1.2.840.113549.1.1.1). */
        size_t clen;
        uint8_t *cert = read_file("test/vectors/tls_spki/google_rsa_leaf.der", &clen);
        const uint8_t *spki;
        size_t spki_len;
        if (ntx_tls_spki_from_cert(cert, clen, &spki, &spki_len) != 0) {
            fprintf(stderr, "FAIL rsa-oid spki extract\n");
            exit(1);
        }
        uint8_t copy[1024];
        if (spki_len > sizeof copy) { fprintf(stderr, "FAIL rsa-oid spki too big\n"); exit(1); }
        memcpy(copy, spki, spki_len);
        const uint8_t *n, *e;
        size_t nl, el;
        if (ntx_tls_rsa_pub_from_spki(copy, spki_len, &n, &nl, &e, &el) != 0) {
            fprintf(stderr, "FAIL rsa-oid positive\n");
            exit(1);
        }
        static const uint8_t oid[9] = { 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01 };
        size_t at = 0;
        while (at + 9 <= spki_len && memcmp(copy + at, oid, 9) != 0) at++;
        if (at + 9 > spki_len) { fprintf(stderr, "FAIL rsa-oid not found in test SPKI\n"); exit(1); }
        copy[at + 8] = 0x0a; /* some other 1.2.840.113549.1.1.x algorithm */
        if (ntx_tls_rsa_pub_from_spki(copy, spki_len, &n, &nl, &e, &el) == 0) {
            fprintf(stderr, "FAIL rsa-oid wrong-algorithm accepted\n");
            exit(1);
        }
        printf("PASS rsa-spki-oid-checked\n");
        free(cert);
    }

    printf("ALL t_tls_pin PASS\n");
    return 0;
}
