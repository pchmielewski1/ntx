/* TOFU — MITM demonstration + LRU experiment (33 hosts).
   Three states:
   1) first contact with a host = trust (new pin, event "new:", accept),
   2) same host, different leaf SPKI = pin mismatch -> reject (rc == -2),
   3) LRU eviction (pool full, 33+ other hosts) -> a repeat contact is
      accepted as a new pin (event "new:" again, accept).
   Deterministic: loopback only (127.0.0.x), no DNS and no internet.
   TLS layer = mock handshake (NTX_HTTP_TEST_HOOKS hook, same pattern as
   mock_hs_ok in test/t_https_pin.c): presents a controlled leaf SPKI
   and verifies pins like ntx_tls_handshake_ex (match -> OK,
   mismatch -> NTX_TLS_PIN_FAIL, no pin -> TOFU accept).
   The production path ntx_https_connect -> ntx_https_handshake_fd ->
   ntx_https_tofu_note runs in full (real TCP sockets). */
#define NTX_HTTP_TEST_HOOKS
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"

#define A1_HOST "127.0.0.2" /* H — outside the built-in pool (127.0.0.1) */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

/* 64 hex chars from the .hex vector -> 32 bytes (no hand-typed bytes) */
static int read_hex_vec(const char *path, char hex[65], uint8_t bin[32]) {
    FILE *f;
    int i;
    f = fopen(path, "r");
    if (!f) return 0;
    for (i = 0; i < 64; i++) {
        int c = fgetc(f);
        if (c == EOF || c == '\n' || c == '\r') break;
        hex[i] = (char)c;
    }
    hex[i] = '\0';
    fclose(f);
    if (strlen(hex) != 64u) return 0;
    if (hex_to_bin(hex, bin, 32) != 0) return 0;
    return 1;
}

/* The "server" presents this leaf SPKI (SHA-256(SPKI)) in the handshake. */
static const uint8_t *g_leaf;

/* TLS layer mock: pin verification as in ntx_tls_handshake_ex.
   the lookup is the same as in ntx_https_handshake_fd (read-only, deterministic). */
static int mock_tofu_hs(const char *host, uint16_t port, ntx_tls *out) {
    uint8_t pins[NTX_HTTPS_PIN_MAX][32];
    int npins = 0;
    (void)port;
    if (ntx_https_pin_lookup(host, 0, pins, NTX_HTTPS_PIN_MAX, &npins) != 0)
        return NTX_TLS_FAIL; /* TOFU off + no pin — TOFU is always on here */
    if (npins > 0) {
        int i;
        for (i = 0; i < npins; i++)
            if (memcmp(pins[i], g_leaf, 32) == 0) {
                out->ready = 1;
                out->leaf_pin_valid = 1;
                memcpy(out->leaf_pin, g_leaf, 32);
                return NTX_TLS_OK;
            }
        return NTX_TLS_PIN_FAIL; /* MITM: leaf != pinned SPKI */
    }
    /* no pin (TOFU signal) -> accept the presented leaf */
    out->ready = 1;
    out->leaf_pin_valid = 1;
    memcpy(out->leaf_pin, g_leaf, 32);
    return NTX_TLS_OK;
}

/* accept with retry (non-blocking connect — same pattern as test/t_https_pin.c) */
static int accept_retry(int lfd, int tries) {
    for (int i = 0; i < tries; i++) {
        int c = ntx_sock_accept4(lfd);
        if (c >= 0) return c;
        nanosleep(&(struct timespec){0, 20 * 1000 * 1000}, NULL);
    }
    return -1;
}

static int listen_port(int *out_lfd, uint16_t *out_port) {
    int lfd = ntx_sock_tcp4();
    if (lfd < 0) return -1;
    uint16_t port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return -1; }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return -1; }
    *out_lfd = lfd;
    *out_port = port;
    return 0;
}

/* State 1: first contact = trust (new TOFU pin, accept) */
static int test_state1_first_contact(const uint8_t pinA[32]) {
    ntx_tls tls;
    int lfd, c;
    uint16_t port;
    char ev[8192];
    char host[128];
    uint8_t rpin[32];
    uint32_t rseen;
    uint8_t out[NTX_HTTPS_PIN_MAX][32];
    int n = -1;

    g_leaf = pinA;
    ntx_https_tofu_test_events_reset();
    if (listen_port(&lfd, &port) != 0) return fail("s1 listen");

    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect(A1_HOST, port, &tls) != 0) {
        close(lfd);
        return fail("s1 first contact must be accepted");
    }
    c = accept_retry(lfd, 50);
    if (c < 0) { close(tls.fd); close(lfd); return fail("s1 accept"); }
    close(c);
    close(tls.fd);
    close(lfd);

    if (!tls.leaf_pin_valid) return fail("s1 leaf_pin_valid");
    if (memcmp(tls.leaf_pin, pinA, 32) != 0) return fail("s1 leaf pin A");

    /* TOFU note fired: exactly 1 new:H event (the stderr marker
       "ntx: TOFU new pin:" comes from the same tofu_new_pin_marker) */
    if (ntx_https_tofu_test_events(ev, sizeof ev) <= 0)
        return fail("s1 events nonempty");
    if (strcmp(ev, "new:127.0.0.2;") != 0) return fail("s1 events new:H");

    /* store: 1 record, H, pinA */
    if (ntx_https_tofu_test_count() != 1) return fail("s1 count 1");
    if (ntx_https_tofu_test_get(0, host, rpin, &rseen) != 0)
        return fail("s1 get");
    if (strcmp(host, A1_HOST) != 0) return fail("s1 host");
    if (memcmp(rpin, pinA, 32) != 0) return fail("s1 pin A");

    /* lookup returns the pinned SPKI */
    if (ntx_https_pin_lookup(A1_HOST, 443, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("s1 lookup");
    if (n != 1) return fail("s1 npins 1");
    if (memcmp(out[0], pinA, 32) != 0) return fail("s1 lookup pin A");
    printf("PASS state1 first contact = trust (new pin, accepted)\n");
    return 0;
}

/* State 2: MITM — same host, different leaf SPKI -> pin mismatch -> reject */
static int test_state2_mitm(const uint8_t pinA[32], const uint8_t pinB[32]) {
    ntx_tls tls;
    int lfd, c;
    uint16_t port;
    char ev[8192];
    char host[128];
    uint8_t rpin[32];
    uint32_t rseen;
    uint8_t out[NTX_HTTPS_PIN_MAX][32];
    int n = -1;

    if (ntx_https_tofu_test_events(ev, sizeof ev) <= 0)
        return fail("s2 events baseline");
    if (strcmp(ev, "new:127.0.0.2;") != 0) return fail("s2 baseline events");

    g_leaf = pinB; /* MITM: a different leaf for the same host */
    if (listen_port(&lfd, &port) != 0) return fail("s2 listen");

    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect(A1_HOST, port, &tls) != -2) {
        close(lfd);
        return fail("s2 changed leaf must be rejected (-2 pin fail)");
    }
    /* client fd closed in ntx_https_handshake_fd (PIN_FAIL) */
    c = accept_retry(lfd, 50);
    if (c >= 0) close(c);
    close(lfd);

    /* no new TOFU event; the store is untouched (still pinA) */
    if (ntx_https_tofu_test_events(ev, sizeof ev) <= 0)
        return fail("s2 events after");
    if (strcmp(ev, "new:127.0.0.2;") != 0)
        return fail("s2 no new event on mismatch");
    if (ntx_https_tofu_test_count() != 1) return fail("s2 count stays 1");
    if (ntx_https_tofu_test_get(0, host, rpin, &rseen) != 0)
        return fail("s2 get");
    if (strcmp(host, A1_HOST) != 0) return fail("s2 host");
    if (memcmp(rpin, pinA, 32) != 0) return fail("s2 pin still A");
    if (ntx_https_pin_lookup(A1_HOST, 443, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("s2 lookup");
    if (n != 1) return fail("s2 npins 1");
    if (memcmp(out[0], pinA, 32) != 0) return fail("s2 lookup still A");
    printf("PASS state2 leaf change = pin mismatch (rejected, store intact)\n");
    return 0;
}

/* State 3: LRU eviction (33 other hosts) -> a repeat contact = a new pin */
static int test_state3_lru_evict(const uint8_t pinA[32],
                                 const uint8_t pinC[32]) {
    ntx_tls tls;
    int lfd, c;
    uint16_t port;
    char ev[8192];
    char host[128];
    uint8_t rpin[32];
    uint32_t rseen;
    uint8_t out[NTX_HTTPS_PIN_MAX][32];
    uint8_t fill[32];
    uint8_t *fillptr;
    int n = -1, i, k, j;

    /* H now has seen=time(NULL) (note from state 1). The test hook makes
       the time deterministic (same pattern as test_tofu_lru): seen=1 -> H = LRU victim (min seen). */
    ntx_https_tofu_test_events_reset(); /* count only the events from state 3 */
    if (ntx_https_tofu_test_add(A1_HOST, pinA, 1u) != 1)
        return fail("s3 H seen=1");

    /* 31 fillers 127.0.0.3..127.0.0.33, seen 2..32 -> pool full (32) */
    for (k = 0; k < 31; k++) {
        char h[16];
        int oct = 3 + k;
        for (j = 0; j < 32; j++)
            fill[j] = (uint8_t)(pinA[j] + (uint8_t)oct);
        fillptr = fill;
        snprintf(h, sizeof h, "127.0.0.%d", oct);
        if (ntx_https_tofu_test_add(h, fillptr, (uint32_t)(k + 2)) != 1)
            return fail("s3 fill add");
    }
    if (ntx_https_tofu_test_count() != 32)
        return fail("s3 pool full 32");

    /* the 32nd and 33rd other host (33 in total: .3..35) -> 2 LRU evictions */
    for (j = 0; j < 32; j++)
        fill[j] = (uint8_t)(pinA[j] + 34u);
    if (ntx_https_tofu_test_add("127.0.0.34", fill, 33u) != 1)
        return fail("s3 add 34"); /* evict min seen = H */
    for (j = 0; j < 32; j++)
        fill[j] = (uint8_t)(pinA[j] + 35u);
    if (ntx_https_tofu_test_add("127.0.0.35", fill, 34u) != 1)
        return fail("s3 add 35"); /* evict 127.0.0.3 (seen=2) */
    if (ntx_https_tofu_test_count() != 32)
        return fail("s3 count stays 32");

    /* assertions on the events: evict:H + evict:.3, 33×new, evict before new */
    if (ntx_https_tofu_test_events(ev, sizeof ev) <= 0)
        return fail("s3 events nonempty");
    {
        const char *pe = strstr(ev, "evict:127.0.0.2;");
        const char *pf = strstr(ev, "evict:127.0.0.3;");
        const char *pn = strstr(ev, "new:127.0.0.34;");
        const char *p;
        int nnew = 0, nevict = 0;
        if (!pe) return fail("s3 evict:H event");
        if (!pf) return fail("s3 evict:.3 event");
        if (!pn) return fail("s3 new:.34 event");
        if (pe > pn) return fail("s3 evict before new");
        for (p = ev; (p = strstr(p, "new:")) != NULL; p += 4)
            nnew++;
        for (p = ev; (p = strstr(p, "evict:")) != NULL; p += 6)
            nevict++;
        if (nnew != 33) return fail("s3 33 new events");
        if (nevict != 2) return fail("s3 2 evict events");
    }

    /* H is not in the store; lookup = TOFU signal (no pin) */
    {
        int found = 0;
        for (i = 0; i < 32; i++) {
            if (ntx_https_tofu_test_get(i, host, rpin, &rseen) != 0)
                return fail("s3 get");
            if (strcmp(host, A1_HOST) == 0)
                found = 1;
        }
        if (found) return fail("s3 H evicted from store");
    }
    if (ntx_https_pin_lookup(A1_HOST, 443, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("s3 lookup tofu signal");
    if (n != 0) return fail("s3 npins 0 after evict");

    /* repeat contact: H is accepted again as a new pin (leaf C) */
    ntx_https_tofu_test_events_reset();
    g_leaf = pinC;
    if (listen_port(&lfd, &port) != 0) return fail("s3 re listen");
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect(A1_HOST, port, &tls) != 0) {
        close(lfd);
        return fail("s3 re-contact must be accepted (new pin)");
    }
    c = accept_retry(lfd, 50);
    if (c < 0) { close(tls.fd); close(lfd); return fail("s3 re accept"); }
    close(c);
    close(tls.fd);
    close(lfd);

    if (!tls.leaf_pin_valid) return fail("s3 re leaf valid");
    if (memcmp(tls.leaf_pin, pinC, 32) != 0) return fail("s3 re leaf pin C");
    if (ntx_https_tofu_test_events(ev, sizeof ev) <= 0)
        return fail("s3 re events nonempty");
    /* pool full: re-adding H evicts min seen (127.0.0.4, seen=3;
       127.0.0.3 was already evicted when .35 was added), then new:H —
       an exact, deterministic sequence */
    if (strcmp(ev, "evict:127.0.0.4;new:127.0.0.2;") != 0)
        return fail("s3 re new:H again");

    /* store: H with pinC, seen ~ now (unix time from tofu_note) */
    {
        int found = 0;
        int64_t d;
        for (i = 0; i < 32; i++) {
            if (ntx_https_tofu_test_get(i, host, rpin, &rseen) != 0)
                return fail("s3 re get");
            if (strcmp(host, A1_HOST) == 0) {
                found = 1;
                if (memcmp(rpin, pinC, 32) != 0)
                    return fail("s3 re-pinned C");
                d = (int64_t)rseen - (int64_t)time(NULL);
                if (d < 0) d = -d;
                if (d > 5) return fail("s3 re seen ~ now");
            }
        }
        if (!found) return fail("s3 H back in store");
    }
    if (ntx_https_pin_lookup(A1_HOST, 443, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("s3 re lookup");
    if (n != 1) return fail("s3 re npins 1");
    if (memcmp(out[0], pinC, 32) != 0) return fail("s3 re lookup pin C");
    printf("PASS state3 LRU evict (33 hosts) -> re-contact = new pin\n");
    return 0;
}

int main(void) {
    char hex[65];
    uint8_t base[32], pinA[32], pinB[32], pinC[32];
    int j;

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, base))
        return fail("read pin vector");
    for (j = 0; j < 32; j++) {
        pinA[j] = base[j];
        pinB[j] = (uint8_t)(base[j] + 0x55u);
        pinC[j] = (uint8_t)(base[j] + 0xAAu);
    }
    if (memcmp(pinA, pinB, 32) == 0 || memcmp(pinA, pinC, 32) == 0 ||
        memcmp(pinB, pinC, 32) == 0)
        return fail("distinct leaf SPKIs");

    /* clean initial conditions */
    if (ntx_https_tofu_enabled() != 1) return fail("tofu default on");
    if (ntx_https_tofu_test_count() != 0) return fail("tofu starts empty");
    ntx_https_tofu_test_events_reset();

    ntx_https_test_set_handshake(mock_tofu_hs);

    if (test_state1_first_contact(pinA) != 0) return 1;
    if (test_state2_mitm(pinA, pinB) != 0) return 1;
    if (test_state3_lru_evict(pinA, pinC) != 0) return 1;

    /* the pin file is replaced atomically and is private to the user */
    {
        const char *path = "test/.scratch/tofu_atomic.bin";
        struct stat st;
        char tmp[300];
        mkdir("test/.scratch", 0755);
        unlink(path);
        snprintf(tmp, sizeof tmp, "%s.tmp", path);
        unlink(tmp);
        ntx_https_set_tofu_path(path);
        if (ntx_https_tofu_test_add("persist.example", pinA, 1) != 1) return fail("persist add");
        ntx_https_tofu_test_save();
        if (stat(path, &st) != 0) return fail("persist file missing");
        if ((st.st_mode & 077) != 0) return fail("persist file mode not private");
        if (stat(tmp, &st) == 0) return fail("persist tmp left behind");
        ntx_https_set_tofu_path(path); /* reload from disk */
        if (ntx_https_tofu_test_count() != 1) return fail("persist reload");
        unlink(path);
    }

    ntx_https_set_tofu_path(NULL);
    if (ntx_https_tofu_test_count() != 0) return fail("cleanup count");
    ntx_https_test_reset_hooks();
    printf("ALL PASS\n");
    return 0;
}
