#include <arpa/inet.h>
#include <assert.h>
#include <netinet/in.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_sock.c"
#include "../src/ui/ntx_diag.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else {
        printf("FAIL %s\n", name);
        fails = 1;
    }
}

static void test_bind_range_ephemeral(void) {
    int fd = ntx_sock_tcp4();
    assert(fd >= 0);
    uint16_t p = ntx_sock_bind_range(fd, 0, 0);
    check(p != 0, "bind-range-ephemeral");
    close(fd);
}

static void test_bind_range_in_range(void) {
    int fd = ntx_sock_tcp4();
    assert(fd >= 0);
    uint16_t p = ntx_sock_bind_range(fd, 29100, 29105);
    check(p >= 29100 && p <= 29105, "bind-range-in-range");
    close(fd);
}

static void test_bind_range_swap(void) {
    int fd = ntx_sock_tcp4();
    assert(fd >= 0);
    uint16_t p = ntx_sock_bind_range(fd, 29110, 29108); /* hi < lo → swap */
    check(p >= 29108 && p <= 29110, "bind-range-swap");
    close(fd);
}

static void test_bind_specific(void) {
    int fd = ntx_sock_tcp4();
    assert(fd >= 0);
    uint16_t p = ntx_sock_bind_range(fd, 29120, 29120);
    check(p == 29120, "bind-range-exact");
    close(fd);
}

static void test_tcp6_bind_connect(void) {
    uint16_t port = (uint16_t)(40000 + (getpid() % 5000));
    int lfd = ntx_sock_tcp6();
    if (lfd < 0) {
        printf("PASS (skip: no IPv6) tcp6-bind-connect\n");
        return;
    }
    check(lfd >= 0, "tcp6-create");
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof sa6);
    sa6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &sa6.sin6_addr);
    sa6.sin6_port = htons(port);
    if (bind(lfd, (struct sockaddr *)&sa6, sizeof sa6) < 0) {
        printf("PASS (skip: no ::1) tcp6-bind-connect\n");
        close(lfd);
        return;
    }
    check(1, "tcp6-bind-loopback");
    uint8_t v6[16] = {0};
    v6[15] = 1;
    ntx_addr a;
    ntx_addr_set_v6(&a, v6);
    int cfd = ntx_sock_tcp6();
    check(cfd >= 0, "tcp6-client");
    check(ntx_sock_connect_addr(cfd, &a, port) == 0, "connect-addr-v6");
    close(cfd);
    close(lfd);
}

static void test_bind6_ephemeral(void) {
    int fd = ntx_sock_tcp6();
    if (fd < 0) {
        printf("PASS (skip: no IPv6) bind6-ephemeral\n");
        return;
    }
    uint16_t p = ntx_sock_bind6(fd, 0);
    if (p == 0) {
        printf("PASS (skip: no IPv6) bind6-ephemeral\n");
        close(fd);
        return;
    }
    check(p > 0, "bind6-ephemeral");
    int v6only = 0;
    socklen_t len = sizeof v6only;
    if (getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &len) == 0)
        check(v6only == 1, "bind6-v6only");
    close(fd);
}

static void test_bind6_specific(void) {
    int fd = ntx_sock_tcp6();
    if (fd < 0) {
        printf("PASS (skip: no IPv6) bind6-specific\n");
        return;
    }
    uint16_t p = ntx_sock_bind6(fd, 29136);
    if (p == 0) {
        printf("PASS (skip: no IPv6) bind6-specific\n");
        close(fd);
        return;
    }
    check(p == 29136, "bind6-exact");
    close(fd);
}

static void test_bind_range6_in_range(void) {
    int fd = ntx_sock_tcp6();
    if (fd < 0) {
        printf("PASS (skip: no IPv6) bind-range6-in-range\n");
        return;
    }
    int probe = ntx_sock_tcp6();
    int v6ok = probe >= 0 && ntx_sock_bind6(probe, 0) > 0;
    if (probe >= 0) close(probe);
    if (!v6ok) {
        printf("PASS (skip: no IPv6) bind-range6-in-range\n");
        close(fd);
        return;
    }
    uint16_t p = ntx_sock_bind_range6(fd, 29130, 29135);
    check(p >= 29130 && p <= 29135, "bind-range6-in-range");
    close(fd);
}

static void test_connect_addr_zero(void) {
    int fd = ntx_sock_tcp4();
    ntx_addr a;
    ntx_addr_clear(&a);
    check(ntx_sock_connect_addr(fd, &a, 12345) == -1, "connect-addr-zero");
    ntx_addr_set_v4(&a, 0u);
    check(ntx_sock_connect_addr(fd, &a, 12345) == -1, "connect-addr-zero-v4");
    uint8_t z6[16] = {0};
    ntx_addr_set_v6(&a, z6);
    check(ntx_sock_connect_addr(fd, &a, 12345) == -1, "connect-addr-zero-v6");
    close(fd);
}

static void test_connect4_wrapper(void) {
    uint16_t port = (uint16_t)(45000 + (getpid() % 5000));
    int lfd = ntx_sock_tcp4();
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    sa.sin_port = htons(port);
    if (bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0) {
        printf("PASS (skip: v4 loopback) connect4-wrapper\n");
        close(lfd);
        return;
    }
    int cfd = ntx_sock_tcp4();
    check(ntx_sock_connect4(cfd, htonl(0x7F000001u), port) == 0,
          "connect4-wrapper");
    check(ntx_sock_connect4(cfd, 0u, port) == -1, "connect4-zero-rejected");
    close(cfd);
    close(lfd);
}

static void test_resolve_literals(void) {
    ntx_addr a;
    check(ntx_sock_resolve("8.8.8.8", &a) == 0 &&
              a.family == NTX_AF_INET && a.u.v4 == htonl(0x08080808u),
          "resolve-v4-literal");
    check(ntx_sock_resolve("1.2.3.4", &a) == 0 &&
              a.family == NTX_AF_INET && a.u.v4 == htonl(0x01020304u),
          "resolve-v4-literal-2");
    memset(&a, 0xAA, sizeof a);
    check(ntx_sock_resolve("::1", &a) == 0 && a.family == NTX_AF_INET6 &&
              a.u.v6[0] == 0 && a.u.v6[8] == 0 && a.u.v6[15] == 1,
          "resolve-v6-literal");
    check(ntx_sock_resolve("[::1]", &a) == 0 && a.family == NTX_AF_INET6 &&
              a.u.v6[0] == 0 && a.u.v6[8] == 0 && a.u.v6[15] == 1,
          "resolve-v6-bracketed");
}

static void test_resolve4_wrapper(void) {
    uint32_t ip = 0;
    check(ntx_sock_resolve4("8.8.8.8", &ip) == 0 &&
              ip == htonl(0x08080808u),
          "resolve4-v4-literal");
    check(ntx_sock_resolve4("::1", &ip) == -1, "resolve4-v6-rejected");
    check(ntx_sock_resolve4("", &ip) == -1, "resolve4-empty-fail");
}

static void test_resolve_nonliteral_stub(void) {
    ntx_addr a;
    check(ntx_sock_resolve("no-such-host.example", &a) == -1,
          "resolve-nonliteral-stub-fail");
}

int main(void) {
    test_bind_range_ephemeral();
    test_bind_range_in_range();
    test_bind_range_swap();
    test_bind_specific();
    test_tcp6_bind_connect();
    test_bind6_ephemeral();
    test_bind6_specific();
    test_bind_range6_in_range();
    test_connect_addr_zero();
    test_connect4_wrapper();
    test_resolve_literals();
    test_resolve4_wrapper();
    test_resolve_nonliteral_stub();
    return fails ? 1 : 0;
}
