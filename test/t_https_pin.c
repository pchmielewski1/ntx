/* ntx_https_pin — host match (exact + wildcard, case-insensitive) */
/* pin file load (host + 64 hex; pin bytes from test/vectors/tls_spki/test_leaf.pin.hex) */
/* lookup order pool → file (test pool = virtual-pool test hook) */
/* TOFU — record struct (compile-only) + enabled by default */
/* TOFU — ntx_https_tofu_note po handshake (seen = unix time) */
/* ntx_https_connect — tcp connect v4/v6 (resolve literal + connect) */
/* ntx_https_connect — pin lookup before tcp (early fail: TOFU off + 0 pins) */
/* TOFU events — explicit new-pin marker (stderr) + LRU evict log (test hook) */
#define NTX_HTTP_TEST_HOOKS
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
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

_Static_assert(sizeof(ntx_tofu_rec) == 164, "tofu rec layout");

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

/* mock handshake — a ready ntx_tls on a real fd (TCP transport tests) */
static int mock_hs_ok(const char *host, uint16_t port, ntx_tls *out) {
    (void)host;
    (void)port;
    out->ready = 1;
    out->leaf_pin_valid = 0;
    return 0;
}

static int test_exact(void) {
    if (host_match("example.com", "example.com") != 1) return fail("exact same");
    if (host_match("example.com", "other.com") != 0) return fail("exact diff");
    printf("PASS exact\n");
    return 0;
}

static int test_wildcard(void) {
    if (host_match("*.example.com", "sub.example.com") != 1) return fail("wild sub");
    if (host_match("*.example.com", "a.b.example.com") != 1) return fail("wild deep sub");
    if (host_match("*.example.com", "example.com") != 0) return fail("wild apex");
    if (host_match("*.example.com", "example.org") != 0) return fail("wild other suffix");
    printf("PASS wildcard\n");
    return 0;
}

static int test_case(void) {
    if (host_match("EXAMPLE.COM", "example.com") != 1) return fail("case pattern");
    if (host_match("example.com", "EXAMPLE.COM") != 1) return fail("case host");
    if (host_match("*.EXAMPLE.COM", "Sub.example.com") != 1) return fail("case wild");
    printf("PASS case\n");
    return 0;
}

/* pin file load — the pin is read from the .hex vector (no hand-typed bytes) */
static int test_pin_file(void) {
    const char *hexpath = "test/vectors/tls_spki/test_leaf.pin.hex";
    const char *dotfile = "test/.scratch/pins_T8.txt";
    char hex[65];
    uint8_t exp[32];
    uint8_t out[4][32];
    int n = -1;
    int i;
    FILE *f;

    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST)
        return fail("mkdir .scratch");

    f = fopen(hexpath, "r");
    if (!f) return fail("open hex vector");
    hex[0] = '\0';
    for (i = 0; i < 64; i++) {
        int c = fgetc(f);
        if (c == EOF || c == '\n' || c == '\r') break;
        hex[i] = (char)c;
    }
    hex[i] = '\0';
    fclose(f);
    if (strlen(hex) != 64u) return fail("hex vector len");
    if (hex_to_bin(hex, exp, 32) != 0) return fail("hex vector decode");

    f = fopen(dotfile, "w");
    if (!f) return fail("open dotfile");
    fprintf(f, "test.example %s\n", hex);
    fprintf(f, "# test\n");
    fprintf(f, "\n");
    fprintf(f, "bad.example 123\n");
    fclose(f);

    ntx_https_pin_set_file(dotfile);
    if (ntx_https_pin_lookup("test.example", 0, out, 4, &n) != 0)
        return fail("lookup hit");
    if (n != 1) return fail("npins == 1");
    if (memcmp(out[0], exp, 32) != 0) return fail("pin bytes == vector");

    /* miss + TOFU on by default → signal 0/npins=0 (TOFU after the certificate) */
    if (ntx_https_pin_lookup("bad.example", 0, out, 4, &n) != 0)
        return fail("bad line skipped");
    if (n != 0) return fail("bad line npins 0");
    if (ntx_https_pin_lookup("unknown", 0, out, 4, &n) != 0)
        return fail("unknown miss");
    if (n != 0) return fail("unknown npins 0");

    ntx_https_pin_set_file(NULL);
    if (ntx_https_pin_lookup("test.example", 0, out, 4, &n) != 0)
        return fail("NULL file miss");
    if (n != 0) return fail("NULL file npins 0");

    unlink(dotfile);
    printf("PASS pin file\n");
    return 0;
}

/* read 64 hex chars from the .hex vector → 32 bytes (no hand-typed bytes) */
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

/* lookup order pool → file; the test pool acts as a virtual pool (hook) */
static int test_lookup_order(void) {
    const char *dotfile = "test/.scratch/pins_T9.txt";
    char hexA[65], hexB[65];
    uint8_t pinA[32], pinB[32];
    uint8_t out[4][32];
    int n = -1;
    FILE *f;

    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST)
        return fail("mkdir .scratch");

    /* pinA = test_leaf, pinB = google_rsa_leaf — both loaded from disk */
    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hexA, pinA))
        return fail("read pinA vector");
    if (!read_hex_vec("test/vectors/tls_spki/google_rsa_leaf.pin.hex", hexB, pinB))
        return fail("read pinB vector");

    f = fopen(dotfile, "w");
    if (!f) return fail("open dotfile");
    fprintf(f, "test.example %s\nother.example %s\n", hexA, hexB);
    fclose(f);

    ntx_https_pin_set_file(dotfile);

    /* pool hit before file: pinB from the pool, pinA from the file must NOT appear */
    if (ntx_https_pin_test_pool_add("test.example", pinB) != 1)
        return fail("pool add");
    if (ntx_https_pin_lookup("test.example", 0, out, 4, &n) != 0)
        return fail("pool hit");
    if (n != 1) return fail("pool hit npins 1");
    if (memcmp(out[0], pinB, 32) != 0) return fail("pool hit pinB");

    /* file on a pool miss */
    if (ntx_https_pin_lookup("other.example", 0, out, 4, &n) != 0)
        return fail("file hit");
    if (n != 1) return fail("file hit npins 1");
    if (memcmp(out[0], pinB, 32) != 0) return fail("file hit pinB");

    /* clear pool → file again (pinA) */
    ntx_https_pin_test_pool_clear();
    if (ntx_https_pin_lookup("test.example", 0, out, 4, &n) != 0)
        return fail("file after clear");
    if (n != 1) return fail("file after clear npins 1");
    if (memcmp(out[0], pinA, 32) != 0) return fail("file after clear pinA");

    /* wildcard w pool */
    if (ntx_https_pin_test_pool_add("*.example.com", pinA) != 1)
        return fail("pool add wild");
    if (ntx_https_pin_lookup("x.example.com", 0, out, 4, &n) != 0)
        return fail("wild pool hit");
    if (n != 1) return fail("wild pool npins 1");
    if (memcmp(out[0], pinA, 32) != 0) return fail("wild pool pinA");

    ntx_https_pin_test_pool_clear();
    ntx_https_pin_set_file(NULL);
    unlink(dotfile);
    printf("PASS lookup order\n");
    return 0;
}

/* built-in pool — 1 test entry 127.0.0.1 (loopback/dev); pin ==
   the contents of test/vectors/tls_spki/test_leaf.pin.hex (no hand-typed bytes) */
static int test_builtin_pool(void) {
    char hex[65];
    uint8_t exp[32];
    uint8_t out[NTX_HTTPS_PIN_MAX][32];
    int n = -1;

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, exp))
        return fail("builtin read pin vector");
    if (ntx_https_pin_lookup("127.0.0.1", 0, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("builtin lookup rc 0");
    if (n < 1) return fail("builtin npins >= 1");
    if (memcmp(out[0], exp, 32) != 0) return fail("builtin pin == vector");
    printf("PASS builtin pool\n");
    return 0;
}

/* TOFU — load/save a single record (bin: host[128] zeropad + pin[32] + seen u32 LE) */
static int test_tofu_roundtrip(void) {
    const char *binpath = "test/.scratch/tofu_test.bin";
    char hex[65];
    uint8_t pin[32];
    uint8_t rec[164];
    char host[128];
    uint8_t rpin[32];
    uint32_t rseen;
    FILE *f;

    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST)
        return fail("mkdir .scratch");
    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, pin))
        return fail("read pin vector");

    if (ntx_https_tofu_test_count() != 0)
        return fail("tofu starts empty");
    ntx_https_set_tofu_path(binpath);
    if (ntx_https_tofu_test_add("track.example", pin, 7) != 1)
        return fail("tofu add");
    ntx_https_tofu_test_save();

    /* on-disk check: 164B, zero-padded host, pin, seen LE */
    f = fopen(binpath, "rb");
    if (!f) return fail("open bin");
    if (fread(rec, 1, 164, f) != 164) return fail("bin size 164");
    fclose(f);
    {
        char exp_host[128];
        memset(exp_host, 0, sizeof exp_host);
        memcpy(exp_host, "track.example", 13);
        if (memcmp(rec, exp_host, 128) != 0) return fail("disk host zeropad");
        if (memcmp(rec + 128, pin, 32) != 0) return fail("disk pin");
        if (rec[160] != 0x07 || rec[161] != 0x00 ||
            rec[162] != 0x00 || rec[163] != 0x00)
            return fail("disk seen LE 07 00 00 00");
    }

    /* roundtrip: clear → reload from disk */
    ntx_https_set_tofu_path(NULL);
    if (ntx_https_tofu_test_count() != 0) return fail("clear count");
    ntx_https_set_tofu_path(binpath);
    if (ntx_https_tofu_test_count() != 1) return fail("reload count 1");
    if (ntx_https_tofu_test_get(0, host, rpin, &rseen) != 0)
        return fail("get 0");
    if (strcmp(host, "track.example") != 0) return fail("reload host");
    if (host[13] != '\0') return fail("reload host NUL");
    if (memcmp(rpin, pin, 32) != 0) return fail("reload pin");
    if (rseen != 7u) return fail("reload seen");
    if (ntx_https_tofu_test_get(1, host, rpin, &rseen) != -1)
        return fail("get out of range");

    unlink(binpath);
    ntx_https_set_tofu_path(NULL);
    printf("PASS tofu roundtrip\n");
    return 0;
}

/* TOFU LRU — max 32, evict min seen; deterministic pins:
   pin_i[j] = (base_pin[j] + offset) z base z test_leaf.pin.hex */
static int test_tofu_lru(void) {
    char hex[65];
    uint8_t base[32];
    uint8_t pin[32];
    char rhost[128];
    uint8_t rpin[32];
    uint32_t rseen;
    int i, j;

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, base))
        return fail("lru read pin vector");

    /* 32 records h00..h31: pin_i[j] = base[j] + i, seen = i + 1 */
    for (i = 0; i < 32; i++) {
        char host[128];
        for (j = 0; j < 32; j++)
            pin[j] = (uint8_t)(base[j] + (uint8_t)i);
        snprintf(host, sizeof host, "h%02d.example", i);
        if (ntx_https_tofu_test_add(host, pin, (uint32_t)(i + 1)) != 1)
            return fail("lru fill add");
    }
    if (ntx_https_tofu_test_count() != 32)
        return fail("lru fill count 32");

    /* 33-ty: h99 (pin99[j] = base[j] + 99, seen=33) → evict h00 (seen=1) */
    for (j = 0; j < 32; j++)
        pin[j] = (uint8_t)(base[j] + 99u);
    if (ntx_https_tofu_test_add("h99.example", pin, 33u) != 1)
        return fail("lru add 33rd");
    if (ntx_https_tofu_test_count() != 32)
        return fail("lru count stays 32");

    {
        int found99 = 0, found31 = 0;
        for (i = 0; i < 32; i++) {
            if (ntx_https_tofu_test_get(i, rhost, rpin, &rseen) != 0)
                return fail("lru get");
            if (strcmp(rhost, "h00.example") == 0)
                return fail("lru h00 still present");
            if (strcmp(rhost, "h99.example") == 0) {
                found99 = 1;
                if (rseen != 33u) return fail("lru h99 seen");
                for (j = 0; j < 32; j++)
                    if (rpin[j] != (uint8_t)(base[j] + 99u))
                        return fail("lru h99 pin");
            }
            if (strcmp(rhost, "h31.example") == 0) {
                found31 = 1;
                if (rseen != 32u) return fail("lru h31 seen");
            }
        }
        if (!found99) return fail("lru h99 missing");
        if (!found31) return fail("lru h31 missing");
    }

    /* the last one added (h99) is at the end of the table */
    if (ntx_https_tofu_test_get(31, rhost, rpin, &rseen) != 0)
        return fail("lru get last");
    if (strcmp(rhost, "h99.example") != 0)
        return fail("lru h99 at end");

    /* update h31: new pin (base[j] + 64), seen=34 → count 32, MRU at the end */
    for (j = 0; j < 32; j++)
        pin[j] = (uint8_t)(base[j] + 64u);
    if (ntx_https_tofu_test_add("h31.example", pin, 34u) != 1)
        return fail("lru update add");
    if (ntx_https_tofu_test_count() != 32)
        return fail("lru update count 32");
    if (ntx_https_tofu_test_get(31, rhost, rpin, &rseen) != 0)
        return fail("lru get last 2");
    if (strcmp(rhost, "h31.example") != 0)
        return fail("lru h31 at end (MRU)");
    if (rseen != 34u) return fail("lru h31 seen updated");
    for (j = 0; j < 32; j++)
        if (rpin[j] != (uint8_t)(base[j] + 64u))
            return fail("lru h31 pin updated");
    if (ntx_https_tofu_test_get(30, rhost, rpin, &rseen) != 0)
        return fail("lru get 30");
    if (strcmp(rhost, "h99.example") != 0)
        return fail("lru h99 shifted to 30");

    ntx_https_set_tofu_path(NULL);
    if (ntx_https_tofu_test_count() != 0)
        return fail("lru cleanup");
    printf("PASS tofu LRU\n");
    return 0;
}

/* TOFU — record struct (compile-only) + enabled by default */
static int test_tofu_state(void) {
    if (ntx_https_tofu_enabled() != 1) return fail("tofu default enabled");
    ntx_https_tofu_set_enabled(0);
    if (ntx_https_tofu_enabled() != 0) return fail("tofu disabled");
    ntx_https_tofu_set_enabled(1);
    if (ntx_https_tofu_enabled() != 1) return fail("tofu re-enabled");
    printf("PASS tofu state\n");
    return 0;
}

/* TOFU — lookup (default on): miss + on → signal 0/npins=0; a host in TOFU
   → pin; TOFU off → miss = -1. Pins are deterministic, from test_leaf.pin.hex. */
static int test_tofu_lookup(void) {
    char hex[65];
    uint8_t pin[32];
    uint8_t out[4][32];
    int n = -1;

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, pin))
        return fail("tofu lookup read pin vector");

    /* 1. default enabled (set_enabled was not called) + host without pins → 0, npins 0 */
    if (ntx_https_tofu_enabled() != 1) return fail("tofu lookup default on");
    if (ntx_https_pin_lookup("nofpin.example", 0, out, 4, &n) != 0)
        return fail("tofu miss signal");
    if (n != 0) return fail("tofu miss npins 0");

    /* 2. stored host → pin */
    if (ntx_https_tofu_test_add("t.example", pin, 1) != 1)
        return fail("tofu lookup add");
    if (ntx_https_pin_lookup("t.example", 0, out, 4, &n) != 0)
        return fail("tofu hit");
    if (n != 1) return fail("tofu hit npins 1");
    if (memcmp(out[0], pin, 32) != 0) return fail("tofu hit pin");

    /* 3. TOFU off + host in TOFU → -1 (TOFU off does not use TOFU) */
    ntx_https_tofu_set_enabled(0);
    if (ntx_https_pin_lookup("t.example", 0, out, 4, &n) != -1)
        return fail("tofu off hit fail");
    if (n != 0) return fail("tofu off hit npins 0");

    /* 4. TOFU off + host with nothing → -1 */
    if (ntx_https_pin_lookup("nofpin.example", 0, out, 4, &n) != -1)
        return fail("tofu off miss fail");
    if (n != 0) return fail("tofu off miss npins 0");

    /* 5. on again → signal 0/npins=0 + cleanup */
    ntx_https_tofu_set_enabled(1);
    if (ntx_https_pin_lookup("nofpin.example", 0, out, 4, &n) != 0)
        return fail("tofu re-enabled signal");
    if (n != 0) return fail("tofu re-enabled npins 0");

    ntx_https_set_tofu_path(NULL);
    if (ntx_https_tofu_test_count() != 0)
        return fail("tofu lookup cleanup");
    printf("PASS tofu lookup\n");
    return 0;
}

/* TOFU — note after the handshake: seen = unix time; after note
   lookup returns the pin; a second note with a different pin → MRU update (count 1). */
static int test_tofu_note(void) {
    char hex[65];
    uint8_t pin[32];
    uint8_t out[4][32];
    int n = -1;
    int j;

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, pin))
        return fail("note read pin vector");

    /* 1. note → lookup returns the pin */
    if (ntx_https_tofu_note("note.example", pin) != 1)
        return fail("note add");
    if (ntx_https_pin_lookup("note.example", 443, out, 4, &n) != 0)
        return fail("note lookup");
    if (n != 1) return fail("note npins 1");
    if (memcmp(out[0], pin, 32) != 0) return fail("note pin");

    /* 2. seen ≈ now */
    {
        char host[128];
        uint8_t rpin[32];
        uint32_t rseen;
        int64_t d;
        if (ntx_https_tofu_test_get(0, host, rpin, &rseen) != 0)
            return fail("note get 0");
        if (strcmp(host, "note.example") != 0) return fail("note host");
        d = (int64_t)rseen - (int64_t)time(NULL);
        if (d < 0) d = -d;
        if (d > 5) return fail("note seen ~ now");
    }

    /* 3. second note with a different pin → count 1, lookup returns the NEW pin (MRU) */
    for (j = 0; j < 32; j++)
        pin[j] = (uint8_t)(pin[j] + 1u);
    if (ntx_https_tofu_note("note.example", pin) != 1)
        return fail("note re-add");
    if (ntx_https_tofu_test_count() != 1)
        return fail("note count stays 1");
    if (ntx_https_pin_lookup("note.example", 443, out, 4, &n) != 0)
        return fail("note lookup 2");
    if (n != 1) return fail("note npins 1 (2)");
    if (memcmp(out[0], pin, 32) != 0) return fail("note new pin");

    /* 4. cleanup */
    ntx_https_set_tofu_path(NULL);
    if (ntx_https_tofu_test_count() != 0)
        return fail("note cleanup");
    printf("PASS tofu note\n");
    return 0;
}

/* TOFU events — new-pin exactly once per host; LRU evict when the
   store is full (NTX_TOFU_MAX+1 hosts → victim = min seen) */
static int test_tofu_events(void) {
    char hex[65];
    uint8_t base[32];
    uint8_t pin[32];
    char ev[8192];
    int i, j, n;

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, base))
        return fail("events read pin vector");

    ntx_https_tofu_test_events_reset();

    /* 1. second note for the same host → exactly 1 new event */
    for (j = 0; j < 32; j++)
        pin[j] = (uint8_t)(base[j] + 1u);
    if (ntx_https_tofu_note("ev.example", pin) != 1)
        return fail("events note 1");
    if (ntx_https_tofu_note("ev.example", pin) != 1)
        return fail("events note 2");
    n = ntx_https_tofu_test_events(ev, sizeof ev);
    if (n != 15) return fail("events len 15");
    if (strcmp(ev, "new:ev.example;") != 0)
        return fail("events single new");

    /* 2. fill do 32 (ev00..ev30, seen=2..32) + 33-ty (ev99, seen=33) →
       evict LRU = ev00 (seen=2; ev.example ma seen=time(NULL) >> 32) */
    for (i = 0; i < 31; i++) {
        char host[128];
        for (j = 0; j < 32; j++)
            pin[j] = (uint8_t)(base[j] + (uint8_t)(i + 2));
        snprintf(host, sizeof host, "ev%02d.example", i);
        if (ntx_https_tofu_test_add(host, pin, (uint32_t)(i + 2)) != 1)
            return fail("events fill add");
    }
    if (ntx_https_tofu_test_count() != 32)
        return fail("events fill count 32");
    for (j = 0; j < 32; j++)
        pin[j] = (uint8_t)(base[j] + 99u);
    if (ntx_https_tofu_test_add("ev99.example", pin, 33u) != 1)
        return fail("events add 33rd");
    if (ntx_https_tofu_test_count() != 32)
        return fail("events count stays 32");

    /* 3. 33×new + 1×evict; evict(ev00) before new(ev99); reset clears the log */
    n = ntx_https_tofu_test_events(ev, sizeof ev);
    if (n <= 0) return fail("events nonempty");
    {
        const char *pe = strstr(ev, "evict:ev00.example;");
        const char *pn = strstr(ev, "new:ev99.example;");
        const char *p;
        int nnew = 0, nevict = 0;
        if (!pe || !pn) return fail("events evict+new present");
        if (pe > pn) return fail("events evict before new");
        for (p = ev; (p = strstr(p, "new:")) != NULL; p += 4)
            nnew++;
        for (p = ev; (p = strstr(p, "evict:")) != NULL; p += 6)
            nevict++;
        if (nnew != 33) return fail("events 33 new");
        if (nevict != 1) return fail("events 1 evict");
    }
    ntx_https_tofu_test_events_reset();
    if (ntx_https_tofu_test_events(ev, sizeof ev) != 0)
        return fail("events reset");

    /* 4. cleanup */
    ntx_https_set_tofu_path(NULL);
    if (ntx_https_tofu_test_count() != 0)
        return fail("events cleanup");
    printf("PASS tofu events\n");
    return 0;
}

/* ntx_https_connect — TCP v4/v6 (resolve literal + connect; no pin/TLS) */

/* accept with retry — connect is non-blocking (EINPROGRESS), so after
   ntx_https_connect==0 the connection may not be in the accept queue yet. */
static int accept_retry(int lfd, int tries) {
    for (int i = 0; i < tries; i++) {
        int c = ntx_sock_accept4(lfd);
        if (c >= 0) return c;
        nanosleep(&(struct timespec){0, 20 * 1000 * 1000}, NULL);
    }
    return -1;
}

static int test_https_tcp(void) {
    ntx_tls tls;

    ntx_https_test_set_handshake(mock_hs_ok);

    /* 6: NULL args → -1 */
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect(NULL, 443, &tls) != -1) return fail("tcp null host");
    if (ntx_https_connect("127.0.0.1", 0, &tls) != -1) return fail("tcp zero port");
    if (ntx_https_connect("127.0.0.1", 443, NULL) != -1) return fail("tcp null out");

    /* 1: v4 loopback — connect == 0, fd >= 0, accept on the other side */
    int lfd = ntx_sock_tcp4();
    if (lfd < 0) return fail("tcp listen socket");
    uint16_t port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return fail("tcp bind0"); }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return fail("tcp listen"); }
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.1", port, &tls) != 0) {
        close(lfd);
        return fail("tcp connect v4");
    }
    if (tls.fd < 0) { close(lfd); return fail("tcp fd >= 0"); }
    int c = accept_retry(lfd, 50);
    if (c < 0) { close(tls.fd); close(lfd); return fail("tcp accept"); }
    close(c);
    close(tls.fd);
    close(lfd);

    /* 3: closed port — connect cannot succeed. Retry 2× after 50ms
       (flaky). A non-blocking connect reports the refusal either synchronously
       (ECONNREFUSED → -1) or as EINPROGRESS (rc==0) — in which case the
       actual refusal is verified via poll + SO_ERROR. */
    lfd = ntx_sock_tcp4();
    if (lfd < 0) return fail("closed listen socket");
    port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return fail("closed bind0"); }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return fail("closed listen"); }
    close(lfd); /* port closed */
    {
        int failed = 0;
        for (int attempt = 0; attempt < 3 && !failed; attempt++) {
            memset(&tls, 0, sizeof tls);
            int rc = ntx_https_connect("127.0.0.1", port, &tls);
            if (rc == -1) {
                failed = 1;
            } else if (rc == 0) {
                struct pollfd p;
                p.fd = tls.fd;
                p.events = POLLOUT;
                p.revents = 0;
                if (poll(&p, 1, 2000) > 0) {
                    int soerr = 0;
                    socklen_t sl = sizeof soerr;
                    if (getsockopt(tls.fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) == 0 &&
                        soerr == ECONNREFUSED)
                        failed = 1;
                }
                close(tls.fd);
            }
            if (!failed && attempt < 2)
                nanosleep(&(struct timespec){0, 50 * 1000 * 1000}, NULL);
        }
        if (!failed) return fail("closed port must fail");
    }

    /* 4: bad host (256.1.1.1) — resolve fail → -1 */
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("256.1.1.1", 443, &tls) != -1)
        return fail("bad host resolve");

    /* 5: IPv6 loopback — connect ::1 (skipped with a note if there is no v6) */
    int lfd6 = ntx_sock_tcp6();
    if (lfd6 < 0) {
        printf("PASS (skip: no v6) tcp ipv6\n");
    } else {
        uint16_t p6 = ntx_sock_bind6(lfd6, 0);
        if (p6 == 0) {
            close(lfd6);
            printf("PASS (skip: no v6 loopback) tcp ipv6\n");
        } else {
            if (ntx_sock_listen(lfd6, 8) != 0) {
                close(lfd6);
                return fail("v6 listen");
            }
            memset(&tls, 0, sizeof tls);
            if (ntx_https_connect("::1", p6, &tls) != 0) {
                close(lfd6);
                return fail("tcp connect v6");
            }
            if (tls.fd < 0) { close(lfd6); return fail("v6 fd >= 0"); }
            int c6 = accept_retry(lfd6, 50);
            if (c6 < 0) { close(tls.fd); close(lfd6); return fail("v6 accept"); }
            close(c6);
            close(tls.fd);
            close(lfd6);
        }
    }

    ntx_https_test_reset_hooks();
    printf("PASS tcp\n");
    return 0;
}

/* ntx_https_connect — pin lookup BEFORE tcp:
   TOFU on (default) → signal 0/npins=0 → connect == 0;
   TOFU off + no pins → -1 before tcp; a pin in the test pool → lookup == 0 (direct API). */
static int test_https_pin_early(void) {
    ntx_tls tls;
    char hex[65];
    uint8_t pin[32];
    uint8_t out[NTX_HTTPS_PIN_MAX][32];
    int n = -1;
    int lfd;
    uint16_t port;

    ntx_https_test_set_handshake(mock_hs_ok);

    if (!read_hex_vec("test/vectors/tls_spki/test_leaf.pin.hex", hex, pin))
        return fail("early read pin vector");

    /* 1. Default (TOFU on): host without pins → the TOFU signal does not block → 0 */
    if (ntx_https_tofu_enabled() != 1) return fail("early tofu default on");
    lfd = ntx_sock_tcp4();
    if (lfd < 0) return fail("early listen socket");
    port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return fail("early bind0"); }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return fail("early listen"); }
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != 0) {
        close(lfd);
        return fail("early tofu on connect");
    }
    if (tls.fd < 0) { close(lfd); return fail("early fd >= 0"); }
    {
        int c = accept_retry(lfd, 50);
        if (c < 0) { close(tls.fd); close(lfd); return fail("early accept"); }
        close(c);
    }
    close(tls.fd);
    close(lfd);

    /* 2. TOFU off + host without pins (no pool/file/TOFU) → -1 BEFORE tcp
       (the port is listening — had connect proceeded, it would return 0) */
    ntx_https_tofu_set_enabled(0);
    lfd = ntx_sock_tcp4();
    if (lfd < 0) return fail("early off listen socket");
    port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return fail("early off bind0"); }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return fail("early off listen"); }
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != -1) {
        close(lfd);
        return fail("early tofu off no pin must fail");
    }
    close(lfd);

    /* 3. Pin w test pool (p.example) + TOFU off:
       (a) direct lookup API == 0, npins 1 (connect to p.example is impossible — DNS)
       (b) connect("127.0.0.1") with TOFU off == -1 (no pin for this host) */
    if (ntx_https_pin_test_pool_add("p.example", pin) != 1)
        return fail("early pool add");
    if (ntx_https_pin_lookup("p.example", 443, out, NTX_HTTPS_PIN_MAX, &n) != 0)
        return fail("early pool lookup");
    if (n != 1) return fail("early pool npins 1");
    if (memcmp(out[0], pin, 32) != 0) return fail("early pool pin");
    lfd = ntx_sock_tcp4();
    if (lfd < 0) return fail("early pool listen socket");
    port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return fail("early pool bind0"); }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return fail("early pool listen"); }
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != -1) {
        close(lfd);
        return fail("early tofu off 127.0.0.2 no pin");
    }
    close(lfd);

    /* 4. Restore enabled==1 → connect("127.0.0.1") returns 0 again */
    ntx_https_tofu_set_enabled(1);
    lfd = ntx_sock_tcp4();
    if (lfd < 0) return fail("early re listen socket");
    port = ntx_sock_bind0(lfd);
    if (port == 0) { close(lfd); return fail("early re bind0"); }
    if (ntx_sock_listen(lfd, 8) != 0) { close(lfd); return fail("early re listen"); }
    memset(&tls, 0, sizeof tls);
    if (ntx_https_connect("127.0.0.2", port, &tls) != 0) {
        close(lfd);
        return fail("early re-enabled connect");
    }
    {
        int c = accept_retry(lfd, 50);
        if (c < 0) { close(tls.fd); close(lfd); return fail("early re accept"); }
        close(c);
    }
    close(tls.fd);
    close(lfd);

    /* 5. cleanup */
    ntx_https_pin_test_pool_clear();
    ntx_https_tofu_set_enabled(1);
    if (ntx_https_tofu_enabled() != 1) return fail("early cleanup enabled");
    ntx_https_test_reset_hooks();
    printf("PASS pin early\n");
    return 0;
}

int main(void) {
    if (test_exact() != 0) return 1;
    if (test_wildcard() != 0) return 1;
    if (test_case() != 0) return 1;
    if (test_pin_file() != 0) return 1;
    if (test_lookup_order() != 0) return 1;
    if (test_builtin_pool() != 0) return 1;
    if (test_tofu_roundtrip() != 0) return 1;
    if (test_tofu_lru() != 0) return 1;
    if (test_tofu_lookup() != 0) return 1;
    if (test_tofu_note() != 0) return 1;
    if (test_tofu_events() != 0) return 1;
    if (test_tofu_state() != 0) return 1;
    if (test_https_tcp() != 0) return 1;
    if (test_https_pin_early() != 0) return 1;
    return 0;
}
