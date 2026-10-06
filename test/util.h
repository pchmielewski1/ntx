#ifndef TEST_UTIL_H
#define TEST_UTIL_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static inline void hex_to_bytes(const char *hex, uint8_t *out, size_t n) {
    for (size_t k = 0; k < n; k++) {
        unsigned v = 0;
        (void)sscanf(hex + 2 * k, "%2x", &v);
        out[k] = (uint8_t)v;
    }
}

static inline uint8_t *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) { fprintf(stderr, "open fail %s\n", path); exit(1); }
    fseek(f, 0, SEEK_END);
    long sz = ftell(f);
    fseek(f, 0, SEEK_SET);
    uint8_t *b = malloc(sz > 0 ? (size_t)sz : 1);
    if (fread(b, 1, (size_t)sz, f) != (size_t)sz) { fprintf(stderr, "read fail %s\n", path); exit(1); }
    fclose(f);
    *n = (size_t)sz;
    return b;
}

#endif
