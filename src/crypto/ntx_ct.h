#ifndef NTX_CT_H
#define NTX_CT_H

#include <stddef.h>
#include <stdint.h>

/* Small constant-time helpers shared by the crypto and TLS code. Header-only on
 * purpose: several test binaries #include individual .c files, so a new .c
 * translation unit would break their link lines. */

/* Overwrite n bytes in a way the compiler may not drop as a dead store. Use it for
 * keys, secrets, PRKs and anything derived from them before the buffer goes out of
 * scope; a plain memset() before return is routinely optimised away. */
static inline void ntx_wipe(void *p, size_t n) {
    volatile uint8_t *v = (volatile uint8_t *)p;
    while (n--) *v++ = 0;
}

/* 1 iff a[0..n) == b[0..n). Always reads all n bytes; no early exit. */
static inline int ntx_ct_eq(const void *a, const void *b, size_t n) {
    const volatile uint8_t *x = (const volatile uint8_t *)a;
    const volatile uint8_t *y = (const volatile uint8_t *)b;
    uint8_t d = 0;
    for (size_t i = 0; i < n; i++) d |= (uint8_t)(x[i] ^ y[i]);
    return d == 0;
}

#endif
