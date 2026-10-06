/* Request pipeline depth follows the peer's measured throughput. */
#include <stdio.h>
#include <string.h>
#include "../src/core/ntx_peer.h"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

int main(void) {
    ntx_peer p;
    memset(&p, 0, sizeof p);
    p.hs_t0 = 10000;
    if (ntx_peer_pipe_depth(&p, 10500) != NTX_PEER_PIPE_MIN) return fail("new_peer_min");
    p.down_B = 0;
    if (ntx_peer_pipe_depth(&p, 20000) != NTX_PEER_PIPE_MIN) return fail("idle_peer_min");
    p.down_B = 100 * 1024 * 10; /* ~100 KB/s over 10 s */
    int slow = ntx_peer_pipe_depth(&p, 20000);
    if (slow < NTX_PEER_PIPE_MIN || slow > 48) return fail("slow_peer_stays_small");
    p.down_B = 600 * 1024 * 10; /* ~600 KB/s */
    int mid = ntx_peer_pipe_depth(&p, 20000);
    if (mid <= slow || mid >= NTX_PEER_MAX_REQ) return fail("mid_peer_in_between");
    p.down_B = 3ull * 1024 * 1024 * 10; /* ~3 MB/s */
    if (ntx_peer_pipe_depth(&p, 20000) != NTX_PEER_MAX_REQ) return fail("fast_peer_capped_at_max");
    p.hs_t0 = 0;
    if (ntx_peer_pipe_depth(&p, 20000) != NTX_PEER_PIPE_MIN) return fail("no_ok_time_min");
    printf("PASS pipe_depth\nALL PASS\n");
    return 0;
}
