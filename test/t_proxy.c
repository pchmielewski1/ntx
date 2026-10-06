#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_sock.c"
#include "../src/ui/ntx_diag.c"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0x4000
#endif

static int proxy_test_recv_all(int fd, uint8_t *buf, size_t n) {
    size_t got = 0;
    int iters = 0;
    while (got < n && iters++ < 2000) {
        ssize_t r = recv(fd, buf + got, n - got, 0);
        if (r > 0) {
            got += (size_t)r;
            continue;
        }
        if (r < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            struct pollfd pf = {fd, POLLIN, 0};
            if (poll(&pf, 1, 100) <= 0) return -1;
            continue;
        }
        return -1;
    }
    return got == n ? 0 : -1;
}

static int proxy_test_loopback(void) {
    uint32_t target_ip = htonl(0x0A000001);
    uint16_t target_port = 6881;
    ntx_addr target;
    ntx_addr_set_v4(&target, target_ip);

    int lfd = ntx_sock_tcp4();
    assert(lfd >= 0);
    uint16_t lport = ntx_sock_bind0(lfd);
    assert(lport != 0);
    assert(ntx_sock_listen(lfd, 16) == 0);

    int cfd = ntx_sock_tcp4();
    assert(cfd >= 0);
    assert(ntx_sock_connect4(cfd, htonl(INADDR_LOOPBACK), lport) == 0);

    ntx_proxy p;
    ntx_proxy_init(&p, cfd, &target, target_port, NULL, NULL, NULL, NULL);

    uint8_t sbuf[64];
    size_t slen = 0;
    int sst = 0;
    int sfd = -1;
    int ok_gw = 0;
    int ok_aq = 0;

    struct pollfd pf[3] = {
        {lfd, POLLIN, 0},
        {cfd, POLLIN | POLLOUT, 0},
        {-1, 0, 0},
    };

    int done = 0;
    int iters = 0;
    while (!done && iters++ < 2000) {
        int pr = poll(pf, 3, 100);
        assert(pr >= 0);
        if (pr == 0) continue;
        if (sfd < 0 && (pf[0].revents & POLLIN)) {
            sfd = ntx_sock_accept4(lfd);
            assert(sfd >= 0);
            pf[2].fd = sfd;
            pf[2].events = POLLIN;
        }
        if (sfd >= 0 && (pf[2].revents & POLLIN)) {
            ssize_t r = recv(sfd, sbuf + slen, sizeof sbuf - slen, 0);
            if (r > 0) slen += (size_t)r;
            if (sst == 0 && slen >= 3) {
                assert(sbuf[0] == 0x05 && sbuf[1] == 0x01 && sbuf[2] == 0x00);
                ok_gw = 1;
                uint8_t am[2] = {0x05, 0x00};
                assert(send(sfd, am, 2, MSG_NOSIGNAL) == 2);
                slen = 0;
                sst = 1;
            } else if (sst == 1 && slen >= 10) {
                assert(sbuf[0] == 0x05 && sbuf[1] == 0x01 && sbuf[2] == 0x00 && sbuf[3] == 0x01);
                uint32_t rip;
                memcpy(&rip, sbuf + 4, 4);
                uint16_t rport = (uint16_t)(((uint16_t)sbuf[8] << 8) | sbuf[9]);
                assert(rip == target_ip);
                assert(rport == target_port);
                ok_aq = 1;
                uint8_t ar[10] = {0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                assert(send(sfd, ar, 10, MSG_NOSIGNAL) == 10);
                sst = 2;
            }
        }
        if (pf[1].revents & (POLLIN | POLLOUT)) {
            int rc = ntx_proxy_step(&p, (pf[1].revents & POLLIN) != 0);
            assert(rc >= 0);
            if (rc == 1) done = 1;
        }
    }
    assert(done);
    assert(ntx_proxy_done(&p));
    assert(ok_gw);
    assert(ok_aq);
    assert(ntx_proxy_local_port(cfd) != 0);

    close(sfd);
    close(cfd);
    close(lfd);
    return 0;
}

static int proxy_test_fail(void) {
    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    assert(fcntl(sp[0], F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(sp[1], F_SETFL, O_NONBLOCK) == 0);

    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0xC0A80102));
    ntx_proxy p;
    ntx_proxy_init(&p, sp[0], &pa, 1337, NULL, NULL, NULL, NULL);
    assert(ntx_proxy_step(&p, 0) == 0);

    uint8_t gw[3];
    assert(proxy_test_recv_all(sp[1], gw, 3) == 0);
    assert(gw[0] == 0x05 && gw[1] == 0x01 && gw[2] == 0x00);

    uint8_t am[2] = {0x05, 0x00};
    assert(send(sp[1], am, 2, MSG_NOSIGNAL) == 2);
    assert(ntx_proxy_step(&p, 1) == 0);

    uint8_t aq[10];
    assert(proxy_test_recv_all(sp[1], aq, 10) == 0);
    assert(aq[0] == 0x05 && aq[1] == 0x01 && aq[2] == 0x00 && aq[3] == 0x01);
    uint32_t rip;
    memcpy(&rip, aq + 4, 4);
    assert(rip == htonl(0xC0A80102));
    assert(aq[8] == 0x05 && aq[9] == 0x39);

    uint8_t ar[10] = {0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    assert(send(sp[1], ar, 10, MSG_NOSIGNAL) == 10);
    assert(ntx_proxy_step(&p, 1) == -1);
    assert(!ntx_proxy_done(&p));

    close(sp[0]);
    close(sp[1]);
    return 0;
}

static int proxy_test_v6(void) {
    uint8_t v6[16] = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01};
    ntx_addr target;
    ntx_addr_set_v6(&target, v6);
    uint16_t target_port = 6881;

    int sp[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM, 0, sp) == 0);
    assert(fcntl(sp[0], F_SETFL, O_NONBLOCK) == 0);
    assert(fcntl(sp[1], F_SETFL, O_NONBLOCK) == 0);

    ntx_proxy p;
    ntx_proxy_init(&p, sp[0], &target, target_port, NULL, NULL, NULL, NULL);
    assert(ntx_proxy_step(&p, 0) == 0);

    uint8_t gw[3];
    assert(proxy_test_recv_all(sp[1], gw, 3) == 0);
    assert(gw[0] == 0x05 && gw[1] == 0x01 && gw[2] == 0x00);

    uint8_t am[2] = {0x05, 0x00};
    assert(send(sp[1], am, 2, MSG_NOSIGNAL) == 2);
    assert(ntx_proxy_step(&p, 1) == 0);

    uint8_t aq[22];
    assert(proxy_test_recv_all(sp[1], aq, 22) == 0);
    assert(aq[0] == 0x05 && aq[1] == 0x01 && aq[2] == 0x00 && aq[3] == 0x04);
    assert(memcmp(aq + 4, v6, 16) == 0);
    assert(aq[4] == 0x20 && aq[7] == 0xb8 && aq[19] == 0x01);
    assert(aq[20] == (uint8_t)(target_port >> 8) && aq[21] == (uint8_t)(target_port & 0xFF));

    uint8_t ar[22];
    memset(ar, 0, sizeof ar);
    ar[0] = 0x05;
    ar[1] = 0x00;
    ar[3] = 0x04;
    assert(send(sp[1], ar, 22, MSG_NOSIGNAL) == 22);
    assert(ntx_proxy_step(&p, 1) == 1);
    assert(ntx_proxy_done(&p));

    close(sp[0]);
    close(sp[1]);
    return 0;
}

static int proxy_test_udp_framing(void) {
    ntx_addr dst;
    uint8_t data[4] = {0x21, 0x00, 0xBE, 0xEF};
    uint8_t out[64];
    ntx_addr_set_v4(&dst, htonl(0x0A000001));

    int n = ntx_proxy_udp_encap(&dst, 6881, data, sizeof data, out, sizeof out);
    assert(n == 14);
    assert(out[0] == 0x00 && out[1] == 0x00 && out[2] == 0x00 && out[3] == 0x01);
    assert(memcmp(out + 4, &dst.u.v4, 4) == 0);
    assert(out[8] == (uint8_t)(6881 >> 8) && out[9] == (uint8_t)(6881 & 0xFF));
    assert(memcmp(out + 10, data, sizeof data) == 0);

    ntx_addr got;
    uint16_t port = 0;
    const uint8_t *got_data = NULL;
    size_t got_len = 0;
    assert(ntx_proxy_udp_decap(out, (size_t)n, &got, &port, &got_data, &got_len) == 0);
    assert(ntx_addr_is_v4(&got));
    assert(got.u.v4 == dst.u.v4);
    assert(port == 6881);
    assert(got_len == sizeof data);
    assert(memcmp(got_data, data, got_len) == 0);

    out[2] = 0x01; /* FRAG != 0 => drop */
    assert(ntx_proxy_udp_decap(out, (size_t)n, &got, &port, &got_data, &got_len) < 0);
    assert(out[2] != 0 && out[3] == 0x01);
    out[2] = 0x00;

    out[0] = 0x01; /* RSV != 0 => reject */
    assert(ntx_proxy_udp_decap(out, (size_t)n, &got, &port, &got_data, &got_len) < 0);
    assert((out[0] != 0 || out[1] != 0) && out[2] == 0);
    out[0] = 0x00;

    out[3] = 0x03; /* domain ATYP avoided for peer IPs => reject */
    assert(ntx_proxy_udp_decap(out, (size_t)n, &got, &port, &got_data, &got_len) < 0);
    assert(out[2] == 0 && out[3] == 0x03);
    out[3] = 0x09; /* unknown ATYP => reject, distinct from the FRAG drop */
    assert(ntx_proxy_udp_decap(out, (size_t)n, &got, &port, &got_data, &got_len) < 0);
    assert(out[2] == 0 && out[3] == 0x09);

    return 0;
}

int main(void) {
    proxy_test_loopback();
    proxy_test_fail();
    proxy_test_v6();
    proxy_test_udp_framing();
    printf("PASS\n");
    return 0;
}
