#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void check(const char *name, const uint8_t got[32], const char *exp_hex)
{
    uint8_t exp[32];
    hex_to_bytes(exp_hex, exp, 32);
    if (memcmp(got, exp, 32) != 0) {
        fprintf(stderr, "FAIL %s: ", name);
        for (int i = 0; i < 32; i++) fprintf(stderr, "%02x", got[i]);
        fprintf(stderr, "\n");
        exit(1);
    }
    printf("PASS %s\n", name);
}

int main(void)
{
    uint8_t out[32], alice_pub[32], bob_pub[32], shared_a[32], shared_b[32];
    uint8_t alice_scalar[32], bob_scalar[32];

    /* RFC 7748 §5.2 / §6.1 key exchange */
    hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                 alice_scalar, 32);
    hex_to_bytes("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                 bob_scalar, 32);

    ntx_x25519_base(alice_pub, alice_scalar);
    check("rfc7748-5.2-alice-pub", alice_pub,
          "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

    ntx_x25519_base(bob_pub, bob_scalar);
    check("rfc7748-5.2-bob-pub", bob_pub,
          "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

    ntx_x25519(shared_a, alice_scalar, bob_pub);
    check("rfc7748-5.2-shared-alice", shared_a,
          "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    ntx_x25519(shared_b, bob_scalar, alice_pub);
    check("rfc7748-5.2-shared-bob", shared_b,
          "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

    /* RFC 7748 §6.1 scalar * u (first vector) */
    {
        uint8_t sc[32], u[32];
        hex_to_bytes("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
                     sc, 32);
        hex_to_bytes("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
                     u, 32);
        ntx_x25519(out, sc, u);
        check("rfc7748-6.1-0", out,
              "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    }

    /* RFC 7748 §6.1 second vector */
    {
        uint8_t sc[32], u[32];
        hex_to_bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                     sc, 32);
        hex_to_bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                     u, 32);
        ntx_x25519(out, sc, u);
        check("rfc7748-6.1-1", out,
              "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    }

    /* R5: ordinary exchanges report success... */
    {
        uint8_t sc[32], u[32];
        hex_to_bytes("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
                     sc, 32);
        hex_to_bytes("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
                     u, 32);
        if (ntx_x25519(out, sc, u) != 0) {
            fprintf(stderr, "FAIL x25519-ok-rc\n");
            return 1;
        }
        printf("PASS x25519-ok-rc\n");
    }

    /* ...and every small-order / non-canonical point (all-zero result) is rejected. */
    {
        static const char *low[] = {
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        };
        uint8_t sc[32], u[32];
        hex_to_bytes("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                     sc, 32);
        for (size_t i = 0; i < sizeof low / sizeof low[0]; i++) {
            hex_to_bytes(low[i], u, 32);
            if (ntx_x25519(out, sc, u) != -1) {
                fprintf(stderr, "FAIL x25519-low-order-%zu\n", i);
                return 1;
            }
        }
        printf("PASS x25519-low-order\n");
    }

    return 0;
}
