#ifndef NTX_TIME_H
#define NTX_TIME_H

#include <stdint.h>
#include <time.h>

/* Monotonic clock, ms (CLOCK_MONOTONIC). */
static inline uint64_t ntx_mono_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

#endif
