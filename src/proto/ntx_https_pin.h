#ifndef NTX_HTTPS_PIN_H
#define NTX_HTTPS_PIN_H

#include <stddef.h>
#include <stdint.h>
#include "ntx_https_pins.h"

/*
 * HTTPS SPKI pin API + TOFU.
 * Pool definitions: ntx_https_pin.c. Lookup order: pool → file → TOFU.
 */

void ntx_https_pin_set_file(const char *path);
void ntx_https_set_tofu_path(const char *path);
void ntx_https_tofu_set_enabled(int on);  /* default 1 */
int  ntx_https_tofu_enabled(void);

/* TOFU note after the handshake — seen = unix time */
int  ntx_https_tofu_note(const char *host, const uint8_t pin[32]); /* 1=ok, -1=bad host */
int  ntx_https_pin_lookup(const char *host, uint16_t port,
    uint8_t out_pins[][32], int max_pins, int *out_npins);

/* test hook: virtual pool entries (in addition to the built-in pool) */
int  ntx_https_pin_test_pool_add(const char *host, const uint8_t pin[32]); /* 1=ok, -1=full */
void ntx_https_pin_test_pool_clear(void);

/* test hooks: TOFU load/save (LRU eviction) */
int  ntx_https_tofu_test_add(const char *host, const uint8_t pin[32], uint32_t seen); /* 1=ok, -1=full/bad host */
void ntx_https_tofu_test_save(void);
int  ntx_https_tofu_test_count(void);
int  ntx_https_tofu_test_get(int i, char host[128], uint8_t pin[32], uint32_t *seen); /* 0 ok, -1 idx */
int  ntx_https_tofu_test_events(char *buf, size_t n); /* 0=none, >0=number of bytes copied ("new:host;evict:host;...") */
void ntx_https_tofu_test_events_reset(void);

#endif
