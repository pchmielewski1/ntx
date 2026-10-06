#ifndef NTX_MAGNET_H
#define NTX_MAGNET_H

#include <stdint.h>

typedef struct {
    uint8_t info_hash[20]; /* btih value, or trunc20(ih_v2) when only btmh (used for tracker/handshake) */
    uint8_t ih_v2[32]; /* full sha2-256 infohash when a btmh xt param is present */
    int has_v2; /* 1 if a btmh xt param was parsed */
    char name[512];
    char trackers[32][512];
    int n_trackers;
    char webseed[512];
    char alt_source[512];
    int has_name, has_webseed, has_alt_source;
} ntx_magnet;

int ntx_magnet_parse(const char *url, ntx_magnet *out);

#endif
