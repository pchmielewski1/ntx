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
     {"2f7626b32aeffb4442ce9253fd9fffbe037408da90e6f2bbc7d89a77b16cc5f2", 0, 0, 0}},
    {"https://tracker.nekomi.cn:443/announce", "tracker.nekomi.cn",
     {"ea5a2911ef5dec9974a4ec7827a53e0e6f7271e52eec9d6c813b54f4cad3951c", 0, 0, 0}},
    {"https://004430.xyz:443/announce", "004430.xyz",
     {"28a92d93877090215d4fd55236f2a35f01137adb3fa5e4ec5f45701df94473d3", 0, 0, 0}},
    {"https://tracker.7471.top:443/announce", "tracker.7471.top",
     {"c9c26afbf190405d98a328c6fb758ddb92d0e6697f4b3ca6aed8c9a6a13478ef", 0, 0, 0}},
    {"https://tracker.zhuqiy.com:443/announce", "tracker.zhuqiy.com",
     {"1e96051cb0cb3bdd8486d18997e2336d06b58235dc2b341c82384bceaa85c079", 0, 0, 0}},
    {"https://1337.abcvg.info:443/announce", "1337.abcvg.info",
     {"e1e5e48f542eee53816db2bba6c398c867d9e755ff615956763fa7dc8b8bf332", 0, 0, 0}},
    {"https://tracker.yume-hatsuyuki.moe:443/announce", "tracker.yume-hatsuyuki.moe",
     {"8c30b82302fe1b70a8007ae1ed5cbb0b256e5ae4185880d22ecd78466c67b956", 0, 0, 0}},
};
/* END GENERATED */
#endif

static ntx_share_tracker strk_builtin[STRK_MAX];
static int strk_builtin_n = -1; /* -1 = hex not decoded yet */
static const ntx_share_tracker *strk_test; /* test override, see test_set */
static int strk_test_n, strk_test_on;

static int strk_hex32(uint8_t out[32], const char *hex) {
    int i;
    if (!hex) return -1;
    for (i = 0; i < 32; i++) {
        int hi = (uint8_t)hex[2 * i], lo = (uint8_t)hex[2 * i + 1], h, l;
        h = (hi >= '0' && hi <= '9') ? hi - '0' : (hi | 0x20) - 'a' + 10;
        l = (lo >= '0' && lo <= '9') ? lo - '0' : (lo | 0x20) - 'a' + 10;
        if (h < 0 || h > 15 || l < 0 || l > 15 || hex[2 * i + 2] != 0) return -1;
        out[i] = (uint8_t)((h << 4) | l);
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
