#ifndef NTX_DHT_XOR_H
#define NTX_DHT_XOR_H

#include <stdint.h>
#include <string.h>

/* XOR of two 20-byte node IDs (BEP5): out[i] = a[i] ^ b[i] */
static inline void ntx_dht_xor(const uint8_t a[20], const uint8_t b[20], uint8_t out[20]) {
    for (int i = 0; i < 20; i++) out[i] = (uint8_t)(a[i] ^ b[i]);
}

/* Compare XOR distances to self: <0 → a is closer to self; 0 → ids identical; >0 → b is closer.
   Distance = lexicographic order of the 20-byte XOR (memcmp of the xors). */
static inline int ntx_dht_id_cmp_xor(const uint8_t a[20], const uint8_t b[20], const uint8_t self[20]) {
    uint8_t xa[20], xb[20];
    for (int i = 0; i < 20; i++) {
        xa[i] = (uint8_t)(a[i] ^ self[i]);
        xb[i] = (uint8_t)(b[i] ^ self[i]);
    }
    return memcmp(xa, xb, 20);
}

/* Number of leading EQUAL bytes of two ids (0..20) — the common prefix length. */
static inline int ntx_dht_prefix_len(const uint8_t a[20], const uint8_t b[20]) {
    int n = 0;
    while (n < 20 && a[n] == b[n]) n++;
    return n;
}

#endif
