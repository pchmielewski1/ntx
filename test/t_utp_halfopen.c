/* Security audit: unauthenticated uTP SYNs must not be able to pin every connection slot.
 * A SYN only allocates a half-open slot; the first ST_DATA promotes it.  Half-open slots are capped
 * (total and per source address) and reaped after NTX_UTP_HALFOPEN_MS, so a spoofed-source SYN flood
 * can neither exhaust the table nor keep it exhausted. */
#define NTX_UTP_HALFOPEN_MS 120

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/net/ntx_utp.c"
#include "../src/net/ntx_utp_sm.c"
#include "../src/net/ntx_utp_hdr.c"
#include "../src/net/ntx_utp_cc.c"
#include "../src/ui/ntx_diag.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"

static int g_fails;
static int g_accepts;

static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) g_fails++;
}

static void accept_cb(ntx_netx *n, int vfd, void *ctx) {
    (void)n; (void)vfd; (void)ctx;
    g_accepts++;
}

static void send_pkt(ntx_utp *u, uint8_t type, uint16_t conn_id, uint16_t seq, uint32_t ip_host, uint16_t port,
                     const uint8_t *payload, size_t plen) {
    uint8_t pkt[64];
    ntx_utp_hdr h = {0};
    h.type = type; h.ver = 1; h.conn_id = conn_id; h.wnd_size = 65536; h.seq_nr = seq;
    ntx_utp_hdr_write(pkt, sizeof pkt, &h);
    if (plen) memcpy(pkt + NTX_UTP_HDR_LEN, payload, plen);
    struct sockaddr_storage ss;
    memset(&ss, 0, sizeof ss);
    struct sockaddr_in *sa_p = (struct sockaddr_in *)&ss;
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(ip_host);
    sa.sin_port = htons(port);
    *sa_p = sa;
    ntx_utp_input(u, pkt, NTX_UTP_HDR_LEN + plen, &ss, sizeof sa);
}

static void spin(ntx_netx *n, int ms) {
    struct timespec t0, t1;
    clock_gettime(CLOCK_MONOTONIC, &t0);
    do {
        ntx_netx_run_once(n, 10);
        clock_gettime(CLOCK_MONOTONIC, &t1);
    } while ((t1.tv_sec - t0.tv_sec) * 1000 + (t1.tv_nsec - t0.tv_nsec) / 1000000 < ms);
}

int main(void) {
    ntx_rng_init();
    ntx_netx *netx = ntx_netx_init(NULL);
    ntx_utp *u = ntx_utp_listen(netx, 0, accept_cb, NULL);
    if (!netx || !u) { printf("FAIL setup\n"); return 1; }

    /* many sources, one SYN each: the half-open table is bounded below the slot count */
    for (uint32_t i = 0; i < 200; i++)
        send_pkt(u, NTX_UTP_ST_SYN, (uint16_t)(1000 + i), 1, 0x7f000000u + 0x100u + i, (uint16_t)(20000 + i), NULL, 0);
    int c = ntx_utp_conn_count(u);
    check(c > 0 && c <= NTX_UTP_MAX_CONNS / 2, "syn-flood-bounded-below-table");

    /* the reaper frees them */
    spin(netx, NTX_UTP_HALFOPEN_MS + 250);
    check(ntx_utp_conn_count(u) == 0, "half-open-reaped");

    /* one source cannot take them all */
    for (uint32_t i = 0; i < 40; i++)
        send_pkt(u, NTX_UTP_ST_SYN, (uint16_t)(3000 + 2 * i), 1, 0x7f000002u, (uint16_t)(30000 + i), NULL, 0);
    c = ntx_utp_conn_count(u);
    check(c > 0 && c <= 8, "per-source-cap");
    spin(netx, NTX_UTP_HALFOPEN_MS + 250);
    check(ntx_utp_conn_count(u) == 0, "per-source-reaped");

    /* a real peer (SYN then ST_DATA) is promoted and survives the reaper */
    send_pkt(u, NTX_UTP_ST_SYN, 5000, 1, 0x7f000003u, 40000, NULL, 0);
    check(ntx_utp_conn_count(u) == 1, "syn-allocates");
    send_pkt(u, NTX_UTP_ST_DATA, 5001, 2, 0x7f000003u, 40000, (const uint8_t *)"hello", 5);
    check(g_accepts == 1, "data-promotes-and-accepts");
    spin(netx, NTX_UTP_HALFOPEN_MS + 250);
    check(ntx_utp_conn_count(u) == 1, "established-survives-reaper");

    ntx_utp_free(u);
    ntx_netx_free(netx);
    return g_fails ? 1 : 0;
}
