#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_magnet.c"
#include "../src/ui/ntx_diag.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

static int eq20(const uint8_t *a, const char *hex) {
    for (int i = 0; i < 20; i++) {
        int hi, lo;
        if (sscanf(hex + 2 * i, "%1x%1x", &hi, &lo) != 2) return 0;
        if (a[i] != (uint8_t)((hi << 4) | lo)) return 0;
    }
    return 1;
}

static int eq32(const uint8_t *a, const char *hex) {
    for (int i = 0; i < 32; i++) {
        int hi, lo;
        if (sscanf(hex + 2 * i, "%1x%1x", &hi, &lo) != 2) return 0;
        if (a[i] != (uint8_t)((hi << 4) | lo)) return 0;
    }
    return 1;
}

static int manifest_val(const char *path, const char *key, char *buf, size_t cap) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[512];
    int found = 0;
    size_t klen = strlen(key);
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, klen) == 0) {
            char *v = line + klen;
            while (*v == ' ') v++;
            size_t n = strlen(v);
            while (n && (v[n - 1] == '\n' || v[n - 1] == '\r')) v[--n] = 0;
            if (n >= cap) n = cap - 1;
            memcpy(buf, v, n);
            buf[n] = 0;
            found = 1;
            break;
        }
    }
    fclose(f);
    return found ? 0 : -1;
}

static int manifest_magnet_url(const char *path, const char *fixture, const char *kind,
                               char *buf, size_t cap) {
    char key[64];
    snprintf(key, sizeof key, "magnet: %s %s", fixture, kind);
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    char line[1024];
    int seen_key = 0, got = 0;
    while (fgets(line, sizeof line, f)) {
        if (seen_key) {
            size_t n = strlen(line);
            while (n && (line[n - 1] == '\n' || line[n - 1] == '\r')) line[--n] = 0;
            if (n >= cap) n = cap - 1;
            memcpy(buf, line, n);
            buf[n] = 0;
            got = 1;
            break;
        }
        if (strncmp(line, key, strlen(key)) == 0) seen_key = 1;
    }
    fclose(f);
    return got ? 0 : -1;
}

static void test_real(void) {
    const char *url =
        "magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        "&dn=Test+Torrent%20File"
        "&tr=http%3A%2F%2Ftracker.example.com%2Fannounce"
        "&tr=udp%3A%2F%2Ftracker2.example.com%3A6969"
        "&tr=http%3A%2F%2Ftracker.example.com%2Fannounce"
        "&ws=http%3A%2F%2Fwebseed.example.com"
        "&as=http%3A%2F%2Falt.example.com"
        "&kd=whatever&x=extra";
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "real-magnet-rc");
    check(eq20(m.info_hash, "a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"), "real-magnet-hash");
    check(m.n_trackers == 2, "real-magnet-ntrackers");
    check(strcmp(m.trackers[0], "http://tracker.example.com/announce") == 0, "real-magnet-tr0");
    check(strcmp(m.trackers[1], "udp://tracker2.example.com:6969") == 0, "real-magnet-tr1");
    check(m.has_name && strcmp(m.name, "Test Torrent File") == 0, "real-magnet-name");
    check(m.has_webseed && strcmp(m.webseed, "http://webseed.example.com") == 0, "real-magnet-webseed");
    check(m.has_alt_source && strcmp(m.alt_source, "http://alt.example.com") == 0, "real-magnet-altsource");
}

static void test_percent_decode(void) {
    const char *url = "magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678&dn=100%25+Done";
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "pctdecode-rc");
    check(strcmp(m.name, "100% Done") == 0, "pctdecode-name");
}

static void test_base32(void) {
    const char *url = "magnet:?xt=urn:btih:ABCDEFGHIJKLMNOPQRSTUVWXYZ234567&dn=b32";
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "base32-rc");
    check(eq20(m.info_hash, "00443214c74254b635cf84653a56d7c675be77df"), "base32-hash");
}

static void test_missing_xt(void) {
    ntx_magnet m;
    check(ntx_magnet_parse("magnet:?dn=NoHash&tr=http%3A%2F%2Fx", &m) == -1, "missing-xt");
    check(ntx_magnet_parse("magnet:?xt=urn:btih:tooshort&dn=x", &m) == -1, "bad-xt");
}

static void test_tracker_cap(void) {
    char url[16384];
    snprintf(url, sizeof url, "magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678");
    for (int i = 0; i < 40; i++) {
        char part[128];
        snprintf(part, sizeof part, "&tr=http://t%d.example.com/announce", i);
        strcat(url, part);
    }
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "cap-rc");
    check(m.n_trackers == 32, "cap-ntrackers");
    check(strcmp(m.trackers[31], "http://t31.example.com/announce") == 0, "cap-last");
}

static void test_dedup(void) {
    const char *url =
        "magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        "&tr=http%3A%2F%2Fa.example.com"
        "&tr=http%3A%2F%2Fa.example.com"
        "&tr=http%3A%2F%2Fa.example.com";
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "dedup-rc");
    check(m.n_trackers == 1, "dedup-count");
    check(strcmp(m.trackers[0], "http://a.example.com") == 0, "dedup-value");
}

static void test_as_only(void) {
    const char *url =
        "magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        "&as=http%3A%2F%2Falt-only.example.com%2Ffile";
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "as-only-rc");
    check(!m.has_webseed, "as-only-no-ws");
    check(m.has_alt_source && strcmp(m.alt_source, "http://alt-only.example.com/file") == 0,
          "as-only-altsource");
}

static void test_btmh_only(void) {
    const char *path = "test/vectors/bep52/single_16k/manifest.txt";
    char ih_full[80], ih_trunc[64], url[512];
    check(manifest_val(path, "ih_full:", ih_full, sizeof ih_full) == 0, "btmh-fix-ihfull");
    check(manifest_val(path, "ih_trunc:", ih_trunc, sizeof ih_trunc) == 0, "btmh-fix-ihtrunc");
    check(manifest_magnet_url(path, "single_16k", "btmh_only", url, sizeof url) == 0,
          "btmh-fix-url");
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "btmh-rc");
    check(m.has_v2 == 1, "btmh-hasv2");
    check(eq32(m.ih_v2, ih_full), "btmh-ihv2");
    check(eq20(m.info_hash, ih_trunc), "btmh-ihtrunc");
}

static void test_dual_single(void) {
    const char *path = "test/vectors/bep52/single_16k/manifest.txt";
    char ih_full[80], ih_trunc[64], url[512];
    manifest_val(path, "ih_full:", ih_full, sizeof ih_full);
    manifest_val(path, "ih_trunc:", ih_trunc, sizeof ih_trunc);
    manifest_magnet_url(path, "single_16k", "dual", url, sizeof url);
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "dual-single-rc");
    check(m.has_v2 == 1, "dual-single-hasv2");
    check(eq32(m.ih_v2, ih_full), "dual-single-ihv2");
    check(eq20(m.info_hash, ih_trunc), "dual-single-ihtrunc");
}

static void test_dual_hybrid(void) {
    const char *path = "test/vectors/bep52/hybrid_ok/manifest.txt";
    char ih_full[80], ih_sha1[64], url[512];
    manifest_val(path, "ih_full:", ih_full, sizeof ih_full);
    manifest_val(path, "ih_sha1:", ih_sha1, sizeof ih_sha1);
    manifest_magnet_url(path, "hybrid_ok", "dual", url, sizeof url);
    ntx_magnet m;
    int rc = ntx_magnet_parse(url, &m);
    check(rc == 0, "dual-hybrid-rc");
    check(m.has_v2 == 1, "dual-hybrid-hasv2");
    check(eq32(m.ih_v2, ih_full), "dual-hybrid-ihv2");
    check(eq20(m.info_hash, ih_sha1), "dual-hybrid-ihsha1");
}

static void test_btmh_reject(void) {
    ntx_magnet m;
    const char *bad_codec =
        "magnet:?xt=urn:btmh:1200a1b2c3d4e5f60718293a4b5c6d7e8f901234567890abcdef";
    check(ntx_magnet_parse(bad_codec, &m) == -1, "btmh-bad-codec");
    const char *other_codec =
        "magnet:?xt=urn:btmh:1210a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        "90abcdef1234567890abcdefef";
    check(ntx_magnet_parse(other_codec, &m) == -1, "btmh-other-codec");
    const char *short_len =
        "magnet:?xt=urn:btmh:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    check(ntx_magnet_parse(short_len, &m) == -1, "btmh-short");
    const char *nonhex =
        "magnet:?xt=urn:btmh:1220a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        "90abcdef1234567890abcdefzz";
    check(ntx_magnet_parse(nonhex, &m) == -1, "btmh-nonhex");
    const char *dup_btmh =
        "magnet:?xt=urn:btmh:12207d1eb831bb31f0ff6bf20b1e393087d6af9e6c94"
        "321e09e880df7d0a1d5d3b41"
        "&xt=urn:btmh:12207d1eb831bb31f0ff6bf20b1e393087d6af9e6c94"
        "321e09e880df7d0a1d5d3b41";
    check(ntx_magnet_parse(dup_btmh, &m) == -1, "btmh-dup");
    const char *dup_btih =
        "magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678"
        "&xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    check(ntx_magnet_parse(dup_btih, &m) == -1, "btih-dup");
}

static void test_v1_no_v2(void) {
    ntx_magnet m;
    int rc = ntx_magnet_parse("magnet:?xt=urn:btih:a1b2c3d4e5f60718293a4b5c6d7e8f9012345678",
                              &m);
    check(rc == 0, "v1only-rc");
    check(m.has_v2 == 0, "v1only-no-v2");
}

int main(void) {
    test_real();
    test_percent_decode();
    test_base32();
    test_missing_xt();
    test_tracker_cap();
    test_dedup();
    test_as_only();
    test_btmh_only();
    test_dual_single();
    test_dual_hybrid();
    test_btmh_reject();
    test_v1_no_v2();
    return fails ? 1 : 0;
}
