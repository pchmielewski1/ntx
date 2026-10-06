#ifndef NTX_DH_H
#define NTX_DH_H

#include <stdint.h>

#define NTX_DH_KEY_LEN 96

typedef struct {
    uint8_t local_secret[20];
    uint8_t local_key[NTX_DH_KEY_LEN];
    uint8_t shared_secret[NTX_DH_KEY_LEN];
    int ok;
    int spent;      /* local_secret has been used up (or the peer key was invalid) */
} ntx_dh;

void ntx_dh_init(ntx_dh *dh);
void ntx_dh_export_key(const uint8_t key[NTX_DH_KEY_LEN], uint8_t out[NTX_DH_KEY_LEN]);
/* One-shot: returns 0 and fills shared_secret on the first call with a valid peer key,
 * then wipes local_secret. Any later call (and any call after an invalid key, which also
 * wipes the secret) returns -1 and leaves shared_secret untouched. */
int ntx_dh_compute_secret(ntx_dh *dh, const uint8_t remote[NTX_DH_KEY_LEN]);
/* Wipe local_secret and shared_secret (call once the shared secret has been copied out).
 * local_key is public and stays; the object is spent afterwards. */
void ntx_dh_scrub(ntx_dh *dh);
void ntx_dh_export_shared(const ntx_dh *dh, uint8_t out[NTX_DH_KEY_LEN]);

#endif
