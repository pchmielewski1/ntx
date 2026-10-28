/* Test-side timeout scaling for TCG (qemu) runs.
 *
 * ts_ms(base_ms) returns base_ms * scale, where scale is read once from the
 * NTX_TEST_TIMEOUT_SCALE environment variable on first use (getenv + strtol,
 * fully parsed). A missing, empty, non-numeric, or <1 value yields scale 1,
 * so native runs are neutral. Tests that need TCG headroom wrap their
 * sleeps/waits/windows in ts_ms(...); assertions themselves stay unscaled. */
#ifndef NTX_TEST_TSCALE_H
#define NTX_TEST_TSCALE_H

#include <errno.h>
#include <stdlib.h>

static inline long ntx_test_timeout_scale(void) {
    static int parsed;
    static long scale = 1;
    if (!parsed) {
        const char *env = getenv("NTX_TEST_TIMEOUT_SCALE");
        if (env && *env) {
            char *end = NULL;
            errno = 0;
            long v = strtol(env, &end, 10);
            if (errno == 0 && end && *end == '\0' && v >= 1)
                scale = v;
        }
        parsed = 1;
    }
    return scale;
}

static inline long ts_ms(long base_ms) {
    return base_ms * ntx_test_timeout_scale();
}

#endif /* NTX_TEST_TSCALE_H */
