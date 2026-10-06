/* No global state: ntx_be_free releases the tree each iteration; safe to repeat. */
#include <stddef.h>
#include <stdint.h>

#include "../../src/proto/ntx_bencode.c"
#include "../../src/ui/ntx_diag.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    ntx_be b;
    size_t consumed = 0;
    if (ntx_be_parse(data, len, &b, &consumed, 32, (size_t)(1 << 20)) == 0)
        ntx_be_free(&b);
    return 0;
}
