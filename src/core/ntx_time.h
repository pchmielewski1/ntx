#ifndef NTX_TIME_H
#define NTX_TIME_H

#include <stdint.h>
#include <time.h>

/* Monotonic clock, ms (CLOCK_MONOTONIC). CLOCK_MONOTONIC counts from boot, so on a freshly started host it is
 * small. Tests that age a timestamp by subtracting from it define NTX_MONO_BASE_MS (an offset added to every
 * reading) so that the subtraction cannot underflow; production builds leave it at 0. */
#ifndef NTX_MONO_BASE_MS
#define NTX_MONO_BASE_MS 0
#endif
static inline uint64_t ntx_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000 + (uint64_t)(int64_t)(NTX_MONO_BASE_MS);
}

#endif
