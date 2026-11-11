static const strk_raw strk_raw_tab[] = {
    {"https://127.0.0.1:443/announce", "127.0.0.1",
     {"0000000000000000000000000000000000000000000000000000000000000000", 0, 0, 0}},
    {"https://localhost:443/announce", "localhost",
     {"0000000000000000000000000000000000000000000000000000000000000000", 0, 0, 0}},
};
/* Test-only table: this banner marks the binary (release.yml greps for it) and
 * is printed at start so a stray test build cannot be mistaken for a release.
 * ponytail: __attribute__((constructor)) is gcc/clang-only and this file is
 * never compiled into a release; upgrade path if another toolchain needs it is
 * an explicit call from a test main. */
#include <stdio.h>
__attribute__((constructor)) static void strk_test_banner(void) {
    fputs("NTX-TEST-TRACKERS: built with -DNTX_SHARE_TRACKERS_INC\n", stderr);
}
