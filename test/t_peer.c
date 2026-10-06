/* These checks age timestamps by subtracting from the monotonic clock, which counts from boot: offset it so a freshly started host cannot underflow. */
#define NTX_MONO_BASE_MS 86400000LL
#include "../src/core/ntx_peer.c"
#include "../src/net/ntx_addr.c"
#include "../src/ui/ntx_diag.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

int main(void) {
    ntx_peer p;
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x7f000001);
    ntx_peer_init(&p, 5, &a, 6881, 10);
    if (p.st != 0) fail("init_st");
    if (p.n_req != 0) fail("init_nreq");
    if (!ntx_addr_is_v4(&p.addr) || p.addr.u.v4 != 0x7f000001) fail("init_addr_v4");
    printf("PASS init\n");

    ntx_peer p2;
    ntx_addr a6;
    static const uint8_t v6[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ntx_addr_set_v6(&a6, v6);
    ntx_peer_init(&p2, 5, &a6, 6881, 10);
    if (!ntx_addr_is_v6(&p2.addr) || !ntx_addr_eq(&p2.addr, &a6)) fail("init_addr_v6");
    ntx_peer_free(&p2);
    printf("PASS init_addr\n");

    ntx_peer_set_phave(&p, 0, 1);
    ntx_peer_set_phave(&p, 1, 1);
    if (ntx_peer_has(&p, 0) != 1) fail("phave0");
    if (ntx_peer_has(&p, 1) != 1) fail("phave1");
    if (ntx_peer_has(&p, 2) != 0) fail("phave2");
    printf("PASS phave\n");

    if (p.choke_us != 1 || p.we_choke != 1 || p.int_us != 0 || p.we_int != 0) fail("states_default_choked");
    ntx_peer_set_choke_us(&p, 0);
    ntx_peer_set_we_choke(&p, 0);
    ntx_peer_set_we_int(&p, 1);
    if (ntx_peer_can_download(&p) != 1) fail("can_download_on");
    ntx_peer_set_choke_us(&p, 1);
    if (ntx_peer_can_download(&p) != 0) fail("can_download_off");
    ntx_peer_set_int_us(&p, 1);
    if (ntx_peer_can_send(&p) != 1) fail("can_send_on");
    ntx_peer_set_we_choke(&p, 1);
    if (ntx_peer_can_send(&p) != 0) fail("can_send_off");
    printf("PASS choking\n");

    if (ntx_peer_request(&p, 0, 0, 16384, 1000) != 0) fail("req1");
    if (ntx_peer_request(&p, 1, 0, 16384, 1000) != 0) fail("req2");
    if (ntx_peer_req_count(&p) != 2) fail("count2");
    printf("PASS requests\n");

    for (int i = 2; i < NTX_PEER_MAX_REQ; i++)
        if (ntx_peer_request(&p, (uint32_t)i, 0, 16384, 1000) != 0) fail("req_fill");
    if (ntx_peer_req_count(&p) != NTX_PEER_MAX_REQ) fail("count_full");
    if (ntx_peer_request(&p, 99, 0, 16384, 1000) != -1) fail("req_full");
    printf("PASS req_full\n");

    uint64_t now = 41000;
    for (int i = 0; i < p.n_req; i++) p.req_t0[i] = now - 1000;
    p.req_t0[0] = now - 40000;
    if (ntx_peer_timeout(&p, now) != 1) fail("timeout_n");
    if (ntx_peer_req_count(&p) != NTX_PEER_MAX_REQ - 1) fail("timeout_count");
    printf("PASS timeout\n");

    ntx_peer_request(&p, 7, 32768, 16384, now);
    if (ntx_peer_req_count(&p) != NTX_PEER_MAX_REQ) fail("req_add");
    ntx_peer_request_done(&p, 7, 32768);
    if (ntx_peer_req_count(&p) != NTX_PEER_MAX_REQ - 1) fail("req_done");
    ntx_peer_clear_requests(&p);
    if (ntx_peer_req_count(&p) != 0) fail("req_clear");
    printf("PASS req_done\n");

    ntx_peer_free(&p);
    printf("PASS free\n");
    return 0;
}
