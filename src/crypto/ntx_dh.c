#include "ntx_dh.h"
#include "ntx_bignum.h"
#include "ntx_ct.h"
#include "ntx_rng.h"

#include <string.h>

static const uint8_t ntx_dh_prime[NTX_DH_KEY_LEN] = {
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xc9, 0x0f, 0xda, 0xa2,
    0x21, 0x68, 0xc2, 0x34, 0xc4, 0xc6, 0x62, 0x8b, 0x80, 0xdc, 0x1c, 0xd1,
    0x29, 0x02, 0x4e, 0x08, 0x8a, 0x67, 0xcc, 0x74, 0x02, 0x0b, 0xbe, 0xa6,
    0x3b, 0x13, 0x9b, 0x22, 0x51, 0x4a, 0x08, 0x79, 0x8e, 0x34, 0x04, 0xdd,
    0xef, 0x95, 0x19, 0xb3, 0xcd, 0x3a, 0x43, 0x1b, 0x30, 0x2b, 0x0a, 0x6d,
    0xf2, 0x5f, 0x14, 0x37, 0x4f, 0xe1, 0x35, 0x6d, 0x6d, 0x51, 0xc2, 0x45,
    0xe4, 0x85, 0xb5, 0x76, 0x62, 0x5e, 0x7e, 0xc6, 0xf4, 0x4c, 0x42, 0xe9,
    0xa6, 0x3a, 0x36, 0x21, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x05, 0x63,
};

static uint8_t ntx_dh_pm1[NTX_DH_KEY_LEN];

static int ucmp_be(const uint8_t *a, const uint8_t *b, size_t n) {
    for (size_t i = 0; i < n; i++) {
        if (a[i] > b[i]) return 1;
        if (a[i] < b[i]) return -1;
    }
    return 0;
}

/* ---- Modular exponentiation (R3) -----------------------------------------
 * The exponent (our DH secret) is secret, so it goes through the shared Montgomery core's
 * constant-time ladder (ntx_mont_exp_ct). The modulus and the base are public. */
static ntx_mont dh_mont;

static void umodexp(uint8_t r[NTX_DH_KEY_LEN], const uint8_t *base,
                    const uint8_t *exp, size_t elen) {
    static int ready;
    if (!ready) {
        /* The prime is odd and 768 bits: init cannot fail; if it ever did, fail closed. */
        if (ntx_mont_init(&dh_mont, ntx_dh_prime, NTX_DH_KEY_LEN) != 0) {
            memset(r, 0, NTX_DH_KEY_LEN);
            return;
        }
        ready = 1;
    }
    ntx_mont_exp_ct(&dh_mont, r, NTX_DH_KEY_LEN, base, NTX_DH_KEY_LEN, exp, elen);
}

static int uvalid_dh_key(const uint8_t k[NTX_DH_KEY_LEN]) {
    uint8_t two[NTX_DH_KEY_LEN];
    memset(two, 0, NTX_DH_KEY_LEN);
    two[NTX_DH_KEY_LEN - 1] = 2;
    if (ucmp_be(k, two, NTX_DH_KEY_LEN) < 0) return 0;
    if (ucmp_be(k, ntx_dh_pm1, NTX_DH_KEY_LEN) >= 0) return 0;
    return 1;
}

static void dh_init_tables(void) {
    static int done;
    if (done) return;
    memcpy(ntx_dh_pm1, ntx_dh_prime, NTX_DH_KEY_LEN);
    for (int i = NTX_DH_KEY_LEN - 1; i >= 0; i--) {
        if (ntx_dh_pm1[i] > 0) {
            ntx_dh_pm1[i]--;
            break;
        }
        ntx_dh_pm1[i] = 0xff;
    }
    done = 1;
}

void ntx_dh_export_key(const uint8_t key[NTX_DH_KEY_LEN], uint8_t out[NTX_DH_KEY_LEN]) {
    memcpy(out, key, NTX_DH_KEY_LEN);
}

void ntx_dh_init(ntx_dh *dh) {
    dh_init_tables();
    memset(dh, 0, sizeof *dh);
    ntx_rand_bytes(dh->local_secret, sizeof dh->local_secret);
    uint8_t two[NTX_DH_KEY_LEN];
    memset(two, 0, NTX_DH_KEY_LEN);
    two[NTX_DH_KEY_LEN - 1] = 2;
    umodexp(dh->local_key, two, dh->local_secret, sizeof dh->local_secret);
    dh->ok = 1;
}

int ntx_dh_compute_secret(ntx_dh *dh, const uint8_t remote[NTX_DH_KEY_LEN]) {
    if (dh->spent) return -1; /* the exponent is gone: a second call would silently compute 2^0 */
    dh->spent = 1;
    if (!uvalid_dh_key(remote)) {
        dh->ok = 0;
        ntx_wipe(dh->local_secret, sizeof dh->local_secret);
        return -1;
    }
    umodexp(dh->shared_secret, remote, dh->local_secret, sizeof dh->local_secret);
    ntx_wipe(dh->local_secret, sizeof dh->local_secret);
    return 0;
}

void ntx_dh_scrub(ntx_dh *dh) {
    ntx_wipe(dh->local_secret, sizeof dh->local_secret);
    ntx_wipe(dh->shared_secret, sizeof dh->shared_secret);
    dh->spent = 1;
}

void ntx_dh_export_shared(const ntx_dh *dh, uint8_t out[NTX_DH_KEY_LEN]) {
    ntx_dh_export_key(dh->shared_secret, out);
}
