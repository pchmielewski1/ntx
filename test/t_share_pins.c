/* Task B3 (§6.1): share-tracker hosts are pinned through the built-in share
   pool, never reach TOFU, and a pin mismatch on an https GET surfaces as
   NTX_HTTP_E_PIN. TLS layer = mock handshake (NTX_HTTP_TEST_HOOKS), loopback
   only — no DNS, no internet. */
#define NTX_HTTP_TEST_HOOKS
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls13.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_http.c"

#include "../src/proto/ntx_share_trackers.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

#define TOFU_PATH "/tmp/ntx_b3_tofu.bin"

/* P = the pinned SPKI of the injected share tracker, Q = the TOFU/MITM key */
static const uint8_t PIN_P[32] = {
    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
    0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
    0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f };
static const uint8_t PIN_Q[32] = {
    0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b,
    0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7,
    0xa8, 0xa9, 0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

static ntx_share_tracker g_trk;

static int listen4(uint16_t *port_out) {
    int lfd = ntx_sock_tcp4();
    uint16_t p;
    if (lfd < 0) return -1;
    p = ntx_sock_bind0(lfd);
    if (p == 0) { close(lfd); return -1; }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return -1; }
    *port_out = p;
    return lfd;
}

/* the "server" presents a key other than the pinned one -> pin mismatch */
static int hs_pin_fail(const char *host, uint16_t port, ntx_tls *out) {
    (void)host;
    (void)port;
    (void)out;
    return NTX_TLS_PIN_FAIL;
}

static int inject_trk(void) {
    memset(&g_trk, 0, sizeof g_trk);
    g_trk.url = "https://trk.example/announce";
    g_trk.host = "trk.example";
    g_trk.npins = 1;
    memcpy(g_trk.pins[0], PIN_P, 32);
    ntx_share_trackers_test_set(&g_trk, 1);
    return 0;
}

/* Share-pool pin wins over TOFU; the host never enters TOFU; other hosts do. */
static int test_share_pool_never_tofu(void) {
    uint8_t out[NTX_HTTPS_PIN_MAX][32];
    int n = -1;
    char ev[2048];

    if (inject_trk() != 0) return fail("inject trk");
    ntx_https_tofu_set_enabled(1);
    unlink(TOFU_PATH);
    ntx_https_set_tofu_path(TOFU_PATH);
    /* poison the TOFU store with Q for the same host, persisted to file */
    if (ntx_https_tofu_test_add("trk.example", PIN_Q, 1000) != 1) return fail("tofu seed Q");
    ntx_https_tofu_test_save();
    ntx_https_set_tofu_path(NULL); /* drop the in-memory store */
    ntx_https_set_tofu_path(TOFU_PATH); /* reload: the file alone holds Q */
    if (ntx_https_tofu_test_count() != 1) return fail("tofu file reloaded");
    ntx_https_tofu_test_events_reset();

    if (ntx_https_pin_lookup("trk.example", 443, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("lookup rc 0");
    if (n != 1 || memcmp(out[0], PIN_P, 32) != 0) return fail("pool pin P beats TOFU Q");

    if (ntx_https_tofu_note("trk.example", PIN_Q) != -1) return fail("tofu_note share host -1");
    if (ntx_https_tofu_test_count() != 1) return fail("no new TOFU record for share host");
    if (ntx_https_tofu_test_events(ev, sizeof ev) > 0 && strstr(ev, "trk.example") != NULL)
        return fail("events without trk.example");

    /* TOFU stays reachable for hosts outside the share pool (control) */
    if (ntx_https_tofu_note("plain.host", PIN_Q) != 1) return fail("tofu_note normal host 1");
    if (ntx_https_pin_lookup("plain.host", 443, out, NTX_HTTPS_PIN_MAX, &n) != 0 ||
        n != 1 || memcmp(out[0], PIN_Q, 32) != 0) return fail("tofu pin for normal host");
    if (ntx_https_tofu_test_events(ev, sizeof ev) <= 0 || strstr(ev, "plain.host") == NULL)
        return fail("events contain plain.host");

    /* TOFU disabled: the share host is still pinned (never the -1 fail) */
    ntx_https_tofu_set_enabled(0);
    if (ntx_https_pin_lookup("trk.example", 443, out, NTX_HTTPS_PIN_MAX, &n) != 0 ||
        n != 1 || memcmp(out[0], PIN_P, 32) != 0) return fail("pinned with TOFU off");
    ntx_https_tofu_set_enabled(1);

    ntx_share_trackers_test_set(NULL, -1);
    ntx_https_set_tofu_path(NULL);
    unlink(TOFU_PATH);
    printf("PASS share pool pin, never TOFU\n");
    return 0;
}

/* Pin mismatch on https GET -> NTX_HTTP_E_PIN from both entry points. */
static int test_http_e_pin(void) {
    uint16_t port;
    int lfd, rc;
    char url[128];
    uint8_t out[64];
    size_t n = 0;

    lfd = listen4(&port);
    if (lfd < 0) return fail("e_pin listen");
    snprintf(url, sizeof url, "https://127.0.0.1:%u/announce?info_hash=%%30%%31", (unsigned)port);
    ntx_https_test_set_handshake(hs_pin_fail);
    rc = ntx_http_get(url, out, sizeof out, &n);
    if (rc != NTX_HTTP_E_PIN) {
        ntx_https_test_reset_hooks();
        close(lfd);
        return fail("ntx_http_get E_PIN");
    }
    rc = ntx_http_get_range(url, 0, 16, out, sizeof out, &n);
    ntx_https_test_reset_hooks();
    close(lfd);
    if (rc != NTX_HTTP_E_PIN) return fail("ntx_http_get_range E_PIN");
    printf("PASS NTX_HTTP_E_PIN surfaced\n");
    return 0;
}

int main(void) {
    int rc = 0;
    rc |= test_share_pool_never_tofu();
    rc |= test_http_e_pin();
    if (rc == 0) printf("PASS t_share_pins\n");
    return rc;
}
