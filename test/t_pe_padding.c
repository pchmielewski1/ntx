#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/proto/ntx_pe.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/proto/ntx_pe_vc.c"

enum {
    T_PE_ST_SEND_DH = 1,
    T_PE_ST_RECV_SYNCHASH = 8,
    T_PE_ST_RECV_VC = 5,
};

static void set_bt_hs(ntx_pe *pe, const uint8_t ih[20], char pid_fill) {
    uint8_t hs[68];
    hs[0] = 19;
    memcpy(hs + 1, "BitTorrent protocol", 19);
    memset(hs + 20, 0, 8);
    hs[25] = 0x10;
    memcpy(hs + 28, ih, 20);
    memset(hs + 48, (unsigned char)pid_fill, 20);
    ntx_pe_set_bt_handshake(pe, hs);
}

static void set_nonblock(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    assert(fl >= 0);
    assert(fcntl(fd, F_SETFL, fl | O_NONBLOCK) == 0);
}

static ssize_t write_all(int fd, const void *data, size_t n) {
    const uint8_t *p = data;
    size_t left = n;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            return -1;
        }
        p += (size_t)w;
        left -= (size_t)w;
    }
    return (ssize_t)n;
}

static int run_split_padding_trial(int target_pad) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return 0;
    set_nonblock(fds[0]);
    set_nonblock(fds[1]);

    ntx_pe client, server;
    memset(&client, 0, sizeof client);
    memset(&server, 0, sizeof server);
    uint8_t ih[20];
    for (int i = 0; i < 20; i++) ih[i] = (uint8_t)(i * 13 + target_pad);

    ntx_pe_init(&client, NTX_PE_INITIATOR, fds[0]);
    ntx_pe_init(&server, NTX_PE_RESPONDER, fds[1]);
    ntx_pe_set_infohash(&client, ih);
    ntx_pe_set_infohash(&server, ih);
    set_bt_hs(&client, ih, '-');
    set_bt_hs(&server, ih, '+');

    int split_done = 0;
    int idle = 0;
    for (int steps = 0; steps < 50000; steps++) {
        if (client.done && server.done) {
            assert(client.plain_in == 0);
            assert(server.plain_in == 0);
            close(fds[0]);
            close(fds[1]);
            return split_done;
        }
        if (client.failed || server.failed) break;

        if (!split_done && server.state == T_PE_ST_SEND_DH && server.sent == 0 && server.outn >= NTX_DH_KEY_LEN) {
            server.outn = (size_t)NTX_DH_KEY_LEN + (size_t)target_pad;
            memset(server.out + NTX_DH_KEY_LEN, 0xA5, (size_t)target_pad);
            split_done = 1;

            if (write_all(fds[1], server.out, NTX_DH_KEY_LEN) < 0) break;
            if (ntx_pe_step(&client) < 0) break;

            for (int i = 0; i < target_pad; i++) {
                if (write_all(fds[1], server.out + NTX_DH_KEY_LEN + (size_t)i, 1) < 0) break;
                if (ntx_pe_step(&client) < 0) break;
            }

            server.sent = server.outn;
            if (ntx_pe_step(&server) < 0) break;
            idle = 0;
            continue;
        }

        int rc = ntx_pe_step(&client);
        if (rc < 0) break;
        int rs = ntx_pe_step(&server);
        if (rs < 0) break;
        if (rc == 0 && rs == 0) {
            if (++idle > 5000) break;
        } else
            idle = 0;
    }

    close(fds[0]);
    close(fds[1]);
    return 0;
}

static int run_coalesced_synchash(void) {
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) return 0;
    set_nonblock(fds[0]);
    set_nonblock(fds[1]);

    ntx_pe client, server;
    memset(&client, 0, sizeof client);
    memset(&server, 0, sizeof server);
    uint8_t ih[20];
    for (int i = 0; i < 20; i++) ih[i] = (uint8_t)(i * 17 + 3);

    ntx_pe_init(&client, NTX_PE_INITIATOR, fds[0]);
    ntx_pe_init(&server, NTX_PE_RESPONDER, fds[1]);
    ntx_pe_set_infohash(&client, ih);
    ntx_pe_set_infohash(&server, ih);
    set_bt_hs(&client, ih, '-');
    set_bt_hs(&server, ih, '+');

    int saw_coalesced = 0;
    for (int steps = 0; steps < 200000; steps++) {
        if (client.done && server.done) break;

        if (!client.failed && !client.done && client.state < T_PE_ST_RECV_VC)
            if (ntx_pe_step(&client) < 0) goto fail;

        if (server.state == T_PE_ST_RECV_SYNCHASH && server.inn > 0)
            saw_coalesced = 1;

        if (!server.done && !server.failed)
            if (ntx_pe_step(&server) < 0) goto fail;
        if (!client.done && !client.failed)
            if (ntx_pe_step(&client) < 0) goto fail;
    }

    if (client.done && server.done) {
        assert(client.plain_in == 0);
        assert(server.plain_in == 0);
        close(fds[0]);
        close(fds[1]);
        if (!saw_coalesced) {
            printf("FAIL pe-coalesced (no buffered synchash bytes)\n");
            return 0;
        }
        return 1;
    }

fail:
    close(fds[0]);
    close(fds[1]);
    return 0;
}

static int test_take_remainder_plain(void) {
    ntx_pe pe;
    memset(&pe, 0, sizeof pe);
    pe.inn = 8;
    pe.plain_in = 3;
    memcpy(pe.in, "plainenc", 8);
    uint8_t out[8];
    size_t n = ntx_pe_take_remainder(&pe, out, 2);
    if (n != 2 || memcmp(out, "pl", 2) != 0 || pe.plain_in != 1 || pe.inn != 6) return 0;
    n = ntx_pe_take_remainder(&pe, out, 8);
    if (n != 6 || pe.plain_in != 0 || pe.inn != 0) return 0;
    return 1;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();

    if (!test_take_remainder_plain()) {
        printf("FAIL pe-take-remainder-plain\n");
        return 1;
    }
    printf("PASS pe-take-remainder-plain\n");

    static const int pads[] = {0, 1, 255, 511};
    for (size_t i = 0; i < sizeof pads / sizeof pads[0]; i++) {
        if (!run_split_padding_trial(pads[i])) {
            printf("FAIL pe-padding-split pad=%d\n", pads[i]);
            return 1;
        }
        printf("PASS pe-padding-split pad=%d\n", pads[i]);
    }

    if (!run_coalesced_synchash()) {
        printf("FAIL pe-coalesced-synchash\n");
        return 1;
    }
    printf("PASS pe-coalesced-synchash\n");
    return 0;
}
