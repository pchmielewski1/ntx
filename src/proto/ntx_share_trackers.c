#include <stddef.h>
#include <string.h>

#include "ntx_share_trackers.h"

/* Built-in HTTPS share tracker table (design §6.2). Hosts/pins come from the
 * Task 0 survey in docs/network.md; `make pins-update` rewrites the generated
 * block below and keeps the previous pin while a new one is rolled out.
 * --share is gated off below NTX_SHARE_MIN_TRACKERS usable hosts. */

#define STRK_MAX 16

/* Raw form of one row: pins as hex so pins-update can rewrite them textually. */
typedef struct {
    const char *url, *host;
    const char *pins[NTX_HTTPS_PIN_MAX];
} strk_raw;

#ifdef NTX_SHARE_TRACKERS_INC
#include NTX_SHARE_TRACKERS_INC
#else
/* BEGIN GENERATED (make pins-update) — survey 2026-11-08, docs/network.md */
static const strk_raw strk_raw_tab[] = {
    {"https://tracker.pmman.tech:443/announce", "tracker.pmman.tech",
     {"2f7626b32aeffb4442ce9253fd9fffbe037408da90e6f2bbc7d89a77b16cc5f2", "8a219385c7334700275ece920c3753bda8450637c04241ece7b5c09e14a54251", 0, 0}},
    {"https://tracker.7471.top:443/announce", "tracker.7471.top",
     {"c9c26afbf190405d98a328c6fb758ddb92d0e6697f4b3ca6aed8c9a6a13478ef", "2830ed22c79e6ca1e066fe0dd79997c3f9646d83eca106d40c070de3354a6023", 0, 0}},
    {"https://tracker.zhuqiy.com:443/announce", "tracker.zhuqiy.com",
     {"1e96051cb0cb3bdd8486d18997e2336d06b58235dc2b341c82384bceaa85c079", "dc85dd79e42a13eb7f0e0dd0e264f42c4291a86a26ee303e623e930b04176386", 0, 0}},
    {"https://1337.abcvg.info:443/announce", "1337.abcvg.info",
     {"e1e5e48f542eee53816db2bba6c398c867d9e755ff615956763fa7dc8b8bf332", "7d57ae6ebdd6015aaad6f04b56c86f789a6c7949930ca405ce07f3684e20c1e3", 0, 0}},
    {"https://tracker.yume-hatsuyuki.moe:443/announce", "tracker.yume-hatsuyuki.moe",
     {"8c30b82302fe1b70a8007ae1ed5cbb0b256e5ae4185880d22ecd78466c67b956", "5bfc4a4a6371a802d59ce90d8fe0f3c79da1695f5faddb10ca368df6a8c48939", 0, 0}},
};
/* END GENERATED */
#endif

static ntx_share_tracker strk_builtin[STRK_MAX];
static int strk_builtin_n = -1; /* -1 = hex not decoded yet */
static const ntx_share_tracker *strk_test; /* test override, see test_set */
static int strk_test_n, strk_test_on;

/* hex → bin, shape mirrors hex_nibble/hex_to_bin in ntx_https_pin.c: the length
 * is validated once, before the 32 bytes are decoded. strk_ prefix is required —
 * the unity tests include both files into one translation unit. */
static int strk_hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int strk_hex32(uint8_t out[32], const char *hex) {
    size_t i;
    if (!hex || strlen(hex) != 2 * 32) return -1; /* exactly 64 hex chars */
    for (i = 0; i < 32; i++) {
        int hi = strk_hex_nibble(hex[2 * i]), lo = strk_hex_nibble(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static void strk_builtin_init(void) {
    size_t i, n = sizeof strk_raw_tab / sizeof strk_raw_tab[0];
    if (n > STRK_MAX) n = STRK_MAX;
    for (i = 0; i < n; i++) {
        int k;
        strk_builtin[i].url = strk_raw_tab[i].url;
        strk_builtin[i].host = strk_raw_tab[i].host;
        strk_builtin[i].npins = 0;
        for (k = 0; k < NTX_HTTPS_PIN_MAX; k++) {
            if (!strk_raw_tab[i].pins[k]) break;
            if (strk_hex32(strk_builtin[i].pins[k], strk_raw_tab[i].pins[k]) != 0) break;
            strk_builtin[i].npins++;
        }
        if (strk_builtin[i].npins == 0) break; /* fail closed: never list an unpinned host */
    }
    strk_builtin_n = (int)i;
}

static const ntx_share_tracker *strk_view(int *n) {
    if (strk_test_on) {
        *n = strk_test_n;
        return strk_test;
    }
    if (strk_builtin_n < 0) strk_builtin_init();
    *n = strk_builtin_n;
    return strk_builtin;
}

int ntx_share_tracker_count(void) {
    int n;
    (void)strk_view(&n);
    return n;
}

const ntx_share_tracker *ntx_share_tracker_get(int i) {
    int n;
    const ntx_share_tracker *v = strk_view(&n);
    return (i >= 0 && i < n) ? &v[i] : NULL;
}

int ntx_share_available(void) {
    return ntx_share_tracker_count() >= NTX_SHARE_MIN_TRACKERS;
}

void ntx_share_trackers_test_set(const ntx_share_tracker *v, int n) {
    if (n < 0) { /* restore the built-in list */
        strk_test_on = 0;
        return;
    }
    strk_test = v;
    strk_test_n = (n > STRK_MAX) ? STRK_MAX : n;
    strk_test_on = 1;
}
