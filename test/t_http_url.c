/* T1: ntx_http_url — parse http://; T2/T3: https+port, IPv6 */
#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_http_url.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int test_http_path(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("http://host/path", &p) != 0) return fail("http parse");
    if (strcmp(p.host, "host") != 0) return fail("http host");
    if (p.port != 80) return fail("http port");
    if (p.is_tls != 0) return fail("http is_tls");
    if (strcmp(p.path, "/path") != 0) return fail("http path");
    printf("PASS http_path\n");
    return 0;
}

static int test_http_no_path(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("http://host", &p) != 0) return fail("http nopath parse");
    if (strcmp(p.host, "host") != 0) return fail("http nopath host");
    if (p.port != 80) return fail("http nopath port");
    if (p.is_tls != 0) return fail("http nopath is_tls");
    if (strcmp(p.path, "/") != 0) return fail("http nopath path");
    printf("PASS http_no_path\n");
    return 0;
}

static int test_https_default(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("https://tracker.example/announce", &p) != 0)
        return fail("https parse");
    if (strcmp(p.host, "tracker.example") != 0) return fail("https host");
    if (p.port != 443) return fail("https port");
    if (p.is_tls != 1) return fail("https is_tls");
    if (strcmp(p.path, "/announce") != 0) return fail("https path");
    printf("PASS https_default\n");
    return 0;
}

static int test_explicit_port(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("https://host:8443/x", &p) != 0)
        return fail("port parse");
    if (strcmp(p.host, "host") != 0) return fail("port host");
    if (p.port != 8443) return fail("port value");
    if (p.is_tls != 1) return fail("port is_tls");
    if (strcmp(p.path, "/x") != 0) return fail("port path");

    if (ntx_http_url_parse("http://host:8080", &p) != 0) return fail("http port parse");
    if (p.port != 8080) return fail("http port value");
    if (p.is_tls != 0) return fail("http port is_tls");
    if (strcmp(p.path, "/") != 0) return fail("http port path");
    printf("PASS explicit_port\n");
    return 0;
}

static int test_ipv6(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("https://[::1]:8443/foo", &p) != 0)
        return fail("ipv6 parse");
    if (strcmp(p.host, "::1") != 0) return fail("ipv6 host");
    if (p.port != 8443) return fail("ipv6 port");
    if (p.is_tls != 1) return fail("ipv6 is_tls");
    if (strcmp(p.path, "/foo") != 0) return fail("ipv6 path");

    if (ntx_http_url_parse("http://[fe80::1]", &p) != 0) return fail("ipv6 plain parse");
    if (strcmp(p.host, "fe80::1") != 0) return fail("ipv6 plain host");
    if (p.port != 80) return fail("ipv6 plain port");
    if (strcmp(p.path, "/") != 0) return fail("ipv6 plain path");
    printf("PASS ipv6\n");
    return 0;
}

static int test_bad(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("ftp://host", &p) == 0) return fail("bad scheme");
    if (ntx_http_url_parse("http://", &p) == 0) return fail("empty host");
    if (ntx_http_url_parse("http:///path", &p) == 0) return fail("empty host2");
    if (ntx_http_url_parse("http://host:99999", &p) == 0) return fail("port overflow");
    if (ntx_http_url_parse("http://host:", &p) == 0) return fail("empty port");
    if (ntx_http_url_parse("http://ho st", &p) == 0) return fail("space host");
    if (ntx_http_url_parse("http://[::1", &p) == 0) return fail("unclosed ipv6");
    if (ntx_http_url_parse("http://[", &p) == 0) return fail("empty ipv6");

    char url[300];
    memcpy(url, "http://", 7);
    for (int i = 0; i < 256; i++) url[7 + i] = 'a';
    url[7 + 256] = '\0';
    if (ntx_http_url_parse(url, &p) == 0) return fail("host too long");
    printf("PASS bad\n");
    return 0;
}

static int test_query(void) {
    ntx_http_url_parts p;
    if (ntx_http_url_parse("http://host?x=1", &p) != 0) return fail("query parse");
    if (strcmp(p.path, "?x=1") != 0) return fail("query path");
    if (p.port != 80) return fail("query port");
    printf("PASS query\n");
    return 0;
}

int main(void) {
    if (test_http_path() != 0) return 1;
    if (test_http_no_path() != 0) return 1;
    if (test_https_default() != 0) return 1;
    if (test_explicit_port() != 0) return 1;
    if (test_ipv6() != 0) return 1;
    if (test_bad() != 0) return 1;
    if (test_query() != 0) return 1;
    return 0;
}
