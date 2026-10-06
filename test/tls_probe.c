/* tls_probe: connect to host:port, run the real ntx TLS handshake (TLS 1.3 first,
 * with fallback to 1.2), send a tiny HTTP/1.0 request and print what happened.
 * Build with -DNTX_TLS13_LIVE=1 (or once the default is on, plain). Used by test/tls13_interop.sh against `openssl s_server` and, manually, against
 * real servers:
 *
 *   tls_probe HOST PORT [SNI] [--pin HEX64] [--alpn NAME] [--tofu]
 *
 * Output (stdout): "tls ver=13 alpn=http/1.1 pin=<hex>" then "status: <first line>"
 * Exit code: 0 ok, 2 handshake failed, 3 pin mismatch, 4 I/O error.
 */
#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/net/ntx_tls.h"
#include "../src/ui/ntx_diag.h"

static int hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "usage: %s HOST PORT [SNI] [--pin HEX64] [--alpn NAME]\n", argv[0]);
        return 1;
    }
    const char *host = argv[1], *port = argv[2];
    const char *sni = host;
    const char *alpn = NULL;
    uint8_t pin[1][32];
    int npins = 0;
    for (int i = 3; i < argc; i++) {
        if (!strcmp(argv[i], "--pin") && i + 1 < argc) {
            const char *h = argv[++i];
            if (strlen(h) != 64) return 1;
            for (int k = 0; k < 32; k++) {
                int a = hexval(h[2 * k]), b = hexval(h[2 * k + 1]);
                if (a < 0 || b < 0) return 1;
                pin[0][k] = (uint8_t)(a * 16 + b);
            }
            npins = 1;
        } else if (!strcmp(argv[i], "--alpn") && i + 1 < argc) {
            alpn = argv[++i];
        } else if (argv[i][0] != '-') {
            sni = argv[i];
        }
    }

    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(host, port, &hints, &res) != 0 || !res) {
        fprintf(stderr, "resolve failed\n");
        return 4;
    }
    int fd = socket(res->ai_family, res->ai_socktype, 0);
    if (fd < 0 || connect(fd, res->ai_addr, res->ai_addrlen) != 0) {
        fprintf(stderr, "connect failed\n");
        return 4;
    }
    freeaddrinfo(res);

    ntx_tls t;
    ntx_tls_init(&t);
    const char *alpn_list[1] = { alpn };
    int rc = ntx_tls_handshake_ex(&t, fd, sni, (const uint8_t(*)[32])pin, npins, 10, alpn_list,
                                  alpn ? 1 : 0);
    if (rc == NTX_TLS_PIN_FAIL) {
        printf("pin mismatch\n");
        return 3;
    }
    if (rc != NTX_TLS_OK) {
        printf("handshake failed (%d)\n", rc);
        return 2;
    }
    printf("tls ver=%d alpn=%s pin=", t.ver, t.alpn);
    for (int i = 0; i < 32; i++) printf("%02x", t.leaf_pin[i]);
    printf("\n");

    char req[512];
    int rl = snprintf(req, sizeof req, "GET / HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n\r\n", sni);
    if (ntx_tls_write(&t, req, (size_t)rl) != rl) {
        printf("write failed\n");
        return 4;
    }
    char buf[4096];
    size_t got = 0;
    for (;;) {
        ssize_t n = ntx_tls_read(&t, buf + got, sizeof buf - 1 - got);
        if (n <= 0) break;
        got += (size_t)n;
        if (memchr(buf, '\n', got) || got >= sizeof buf - 1) break;
    }
    buf[got] = 0;
    char *nl = strchr(buf, '\r');
    if (!nl) nl = strchr(buf, '\n');
    if (nl) *nl = 0;
    printf("status: %s\n", buf);
    ntx_tls_close(&t);
    close(fd);
    return got ? 0 : 4;
}
