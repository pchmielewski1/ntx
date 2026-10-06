#ifndef NTX_HTTPS_PINS_H
#define NTX_HTTPS_PINS_H

#include <stdint.h>

/*
 * HTTPS SPKI pins — SHA-256(leaf SubjectPublicKeyInfo DER), 32 bytes each.
 * host: exact match or "*.suffix" wildcard. sni: NULL → use host.
 * Match: OR — memcmp(pin, entry->pins[i], 32) == 0 for any i.
 * Definitions of the pool live in ntx_https_pin.c.
 */

#define NTX_HTTPS_PIN_MAX 4

typedef struct {
  const char *host; /* exact or "*.suffix" */
  const char *sni;  /* NULL → host */
  int npins;
  uint8_t pins[NTX_HTTPS_PIN_MAX][32];
} ntx_https_pin_entry;

extern const ntx_https_pin_entry ntx_https_pin_pool[];
extern const int ntx_https_pin_pool_len;

#endif
