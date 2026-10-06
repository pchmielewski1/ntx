#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/net/ntx_netx.c"
#include "../src/proto/ntx_pe.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/proto/ntx_pe_vc.c"

static struct {
    ntx_netx *netx;
    ntx_pe client;
    ntx_pe server;
    uint8_t infohash[20];
    int client_done, server_done;
    int client_data_sent, server_data_ok;
    uint8_t payload[16];
    uint8_t enc[16];
    uint8_t server_recv[16];
} g;

static void maybe_quit(void) {
    if (g.client_done && g.server_done && g.server_data_ok)
        ntx_netx_quit(g.netx);
}

static void client_cb(int fd, void *ctx) {
    (void)ctx;
    if (!g.client_done) {
        int rc = ntx_pe_step(&g.client);
        if (rc < 0) ntx_netx_quit(g.netx);
        if (rc == 1) {
            g.client_done = 1;
            memcpy(g.enc, g.payload, 16);
            ntx_pe_encrypt(&g.client, g.enc, 16);
            ssize_t w = send(fd, g.enc, 16, 0);
            if (w == 16) g.client_data_sent = 1;
        }
    }
}

static void server_cb(int fd, void *ctx) {
    (void)ctx;
    if (!g.server_done) {
        int rc = ntx_pe_step(&g.server);
        if (rc == 1) g.server_done = 1;
        else if (rc < 0) ntx_netx_quit(g.netx);
    }
    if (g.server_done && !g.server_data_ok) {
        uint8_t buf[16];
        ssize_t r = recv(fd, buf, 16, 0);
        if (r == 16) {
            memcpy(g.server_recv, buf, 16);
            ntx_pe_decrypt(&g.server, buf, 16);
            g.server_data_ok = (memcmp(buf, g.payload, 16) == 0);
            maybe_quit();
        }
    }
}

static void server_accept(ntx_netx *n, int peer_fd, void *ctx) {
    (void)ctx;
        ntx_pe_init(&g.server, NTX_PE_RESPONDER, peer_fd);
        ntx_pe_set_netx(&g.server, n);
        ntx_pe_set_infohash(&g.server, g.infohash);
    {
        uint8_t hs[68];
        hs[0] = 19;
        memcpy(hs + 1, "BitTorrent protocol", 19);
        memset(hs + 20, 0, 8);
        hs[25] = 0x10;
        memcpy(hs + 28, g.infohash, 20);
        memset(hs + 48, '+', 20);
        ntx_pe_set_bt_handshake(&g.server, hs);
    }
    ntx_cbs cbs;
    memset(&cbs, 0, sizeof cbs);
    cbs.r = server_cb;
    cbs.w = server_cb;
    ntx_netx_add(n, peer_fd, EPOLLIN | EPOLLOUT, NULL, &cbs);
    server_cb(peer_fd, NULL);
}

static void timeout_cb(void *arg) {
    (void)arg;
    ntx_netx_quit(g.netx);
}

int main(void) {
    int trials = 8;
    for (int trial = 0; trial < trials; trial++) {
        ntx_rng_init();
        for (int i = 0; i < 20; i++) g.infohash[i] = (uint8_t)(i * 11 + 5 + trial);
        for (int i = 0; i < 16; i++) g.payload[i] = (uint8_t)(i * 7 + 3 + trial);

        g.client_done = g.server_done = g.client_data_sent = g.server_data_ok = 0;
        memset(&g.client, 0, sizeof g.client);
        memset(&g.server, 0, sizeof g.server);

        g.netx = ntx_netx_init(NULL);
        ntx_netx_set_accept(g.netx, server_accept, NULL);
        uint16_t port = ntx_netx_port(g.netx);

        ntx_cbs ccbs;
        memset(&ccbs, 0, sizeof ccbs);
        ccbs.r = client_cb;
        ccbs.w = client_cb;
        ntx_addr la;
        ntx_addr_set_v4(&la, htonl(0x7f000001));
        int cfd = ntx_netx_route_connect(g.netx, &la, port, NULL, &ccbs);
        assert(cfd >= 0);
        ntx_pe_init(&g.client, NTX_PE_INITIATOR, cfd);
        ntx_pe_set_netx(&g.client, g.netx);
        ntx_pe_set_infohash(&g.client, g.infohash);
        {
            uint8_t hs[68];
            hs[0] = 19;
            memcpy(hs + 1, "BitTorrent protocol", 19);
            memset(hs + 20, 0, 8);
            hs[25] = 0x10;
            memcpy(hs + 28, g.infohash, 20);
            memset(hs + 48, '-', 20);
            ntx_pe_set_bt_handshake(&g.client, hs);
        }

        /* Instant connect may have fired EPOLLOUT before pe_init; kick MSE send. */
        client_cb(cfd, NULL);

        ntx_netx_timer(g.netx, 30000, timeout_cb, NULL);
        ntx_netx_run(g.netx);

        if (!g.client_done || !g.server_done || !g.server_data_ok) {
            printf("FAIL pe-loopback trial=%d (c=%d s=%d data=%d)\n", trial, g.client_done, g.server_done,
                   g.server_data_ok);
            ntx_netx_free(g.netx);
            return 1;
        }
        /* Handshake secrets must be gone once MSE has finished: the DH exponent, the DH
           shared secret and the copy PE keeps for the SKEY/HASH computations. */
        {
            ntx_pe *ends[2] = { &g.client, &g.server };
            for (int e = 0; e < 2; e++) {
                uint8_t acc = 0;
                for (size_t i = 0; i < sizeof ends[e]->dh.local_secret; i++) acc |= ends[e]->dh.local_secret[i];
                for (size_t i = 0; i < sizeof ends[e]->dh.shared_secret; i++) acc |= ends[e]->dh.shared_secret[i];
                for (size_t i = 0; i < sizeof ends[e]->secret_buf; i++) acc |= ends[e]->secret_buf[i];
                if (acc != 0) {
                    printf("FAIL pe-secrets-wiped trial=%d side=%d\n", trial, e);
                    ntx_netx_free(g.netx);
                    return 1;
                }
            }
        }
        ntx_netx_free(g.netx);
    }
    printf("PASS pe-loopback\n");
    return 0;
}
