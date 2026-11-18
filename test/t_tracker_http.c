#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_http.c" /* pre-include */
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/net/ntx_sock.c" /* (dependency of ntx_http.c) */
#include "../src/net/ntx_proxy.c" /* (dependency of ntx_http.c) */
#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/ui/ntx_diag.c"

#include "../src/proto/ntx_share_trackers.c"

static int g_fail;

static void expect(const char *name, int ok) {
    if (ok) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); g_fail = 1; }
}

static const uint8_t dict_body[] = {
    'd',
    '5', ':', 'p', 'e', 'e', 'r', 's',
    '1', '2', ':',
    0x01, 0x02, 0x03, 0x04, 0x1A, 0xE1,
    0x05, 0x06, 0x07, 0x08, 0x1A, 0xE2,
    '8', ':', 'i', 'n', 't', 'e', 'r', 'v', 'a', 'l',
    'i', '1', '8', '0', '0', 'e',
    '8', ':', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'e',
    'i', '3', 'e',
    '1', '0', ':', 'i', 'n', 'c', 'o', 'm', 'p', 'l', 'e', 't', 'e',
    'i', '5', 'e',
    'e'
};

static const uint8_t fail_body[] = {
    'd',
    '1', '4', ':', 'f', 'a', 'i', 'l', 'u', 'r', 'e', ' ', 'r', 'e', 'a', 's', 'o', 'n',
    '9', ':', 'N', 'o', 't', ' ', 'f', 'o', 'u', 'n', 'd',
    'e'
};

static const uint8_t raw_body[] = {
    0x01, 0x02, 0x03, 0x04, 0x1A, 0xE1,
    0x05, 0x06, 0x07, 0x08, 0x1A, 0xE2
};

static const uint8_t junk_body[] = {
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07
};

/* d 5:peers 6:<1.2.3.4:6881> 6:peers6 18:<2001:db8::9:6881 BE> e */
static const uint8_t v6_body[] = {
    'd',
    '5', ':', 'p', 'e', 'e', 'r', 's',
    '6', ':',
    0x01, 0x02, 0x03, 0x04, 0x1A, 0xE1,
    '6', ':', 'p', 'e', 'e', 'r', 's', '6',
    '1', '8', ':',
    0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    0x1A, 0xE1,
    'e'
};

/* d 6:peers6 18:<2001:db8::9:6881 BE> e */
static const uint8_t v6_only_body[] = {
    'd',
    '6', ':', 'p', 'e', 'e', 'r', 's', '6',
    '1', '8', ':',
    0x20, 0x01, 0x0D, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09,
    0x1A, 0xE1,
    'e'
};

/* d 6:peers6 0: e */
static const uint8_t v6_empty_body[] = {
    'd',
    '6', ':', 'p', 'e', 'e', 'r', 's', '6',
    '0', ':',
    'e'
};

static int parse_be(const uint8_t *b, size_t n, ntx_be *out) {
    size_t c = 0;
    return ntx_be_parse(b, n, out, &c, 16, n) == 0 && out->t == NTX_BE_DICT;
}

/* ---- S31 / R41 (decision D3): the ANNOUNCE parser tolerates trailing whitespace.
 *
 * opentracker-style servers end the announce dictionary with "e\r\n"; ntx_be_parse
 * requires the input to be consumed exactly (p.pos != n -> error), so such a reply
 * used to count as a tracker failure (docs/network.md: tr.nyacat.pw, open.ftorrent.com,
 * tracker.foreverpirates.co). The trim lives in ntx_tracker_http_parse_ex and NEVER in
 * ntx_be_parse: the strict end-of-input of ntx_be_parse is what makes the raw info
 * subtree that --share hashes unambiguous (S26/R35 in ntx_share.c requires consumed == rd
 * on a .torrent, whose hash IS the link). A .torrent is the access key, an HTTP reply is not.
 *
 * Tolerated trailing byte set: CR (0x0D), LF (0x0A) and space (0x20) — exactly what the
 * plan names. A TAB is not tolerated (no surveyed tracker pads with one, so the set stays
 * as small as the evidence). Everything else is unchanged: whitespace INSIDE the document
 * is still invalid bencode, a trailing '}' or any other non-whitespace byte is still
 * rejected, and a body that is whitespace only is still rejected — the trimmed document
 * is zero-length, which ntx_be_parse does not accept as a successful parse. */

static int r41_parse(const uint8_t *body, size_t n, const char *tail, size_t tn,
                     uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                     uint8_t *ips, uint16_t *ports, char *err, size_t err_cap) {
    uint8_t tmp[512];
    int32_t tid = 0;
    if (n + tn > sizeof tmp) return -2;
    memcpy(tmp, body, n);
    if (tn) memcpy(tmp + n, tail, tn);
    if (err_cap) err[0] = '\0';
    return ntx_tracker_http_parse_ex(tmp, n + tn, &tid, interval, seeders, leechers,
                                     ips, ports, 10, NULL, NULL, 0, err, err_cap);
}

static void expect_np(const char *name, int got, int want, const char *err) {
    if (got == want) { printf("PASS %s\n", name); return; }
    printf("FAIL %s (got=%d want=%d err=\"%s\")\n", name, got, want, err);
    g_fail = 1;
}

static void test_r41_trailing_whitespace(void) {
    uint8_t ips[64];
    uint16_t ports[16];
    uint32_t interval, seeders, leechers;
    char err[128];
    int np;

    /* The three accepted reply shapes from the survey, plus the mixed padding. */
    static const struct { const char *tag; const char *tail; size_t n; } good[] = {
        { "crlf", "\r\n", 2 },        { "crlf-crlf", "\r\n\r\n", 4 },
        { "lf", "\n", 1 },            { "spaces", "   ", 3 },
        { "mixed", " \r\n ", 4 },
    };
    for (size_t k = 0; k < sizeof good / sizeof good[0]; k++) {
        char tag[64];
        snprintf(tag, sizeof tag, "http-parse-trailing-%s", good[k].tag);
        np = r41_parse(dict_body, sizeof dict_body, good[k].tail, good[k].n,
                       &interval, &seeders, &leechers, ips, ports, err, sizeof err);
        if (np != 2) { expect_np(tag, np, 2, err); continue; }
        expect(tag, interval == 1800 && seeders == 3 && leechers == 5 &&
               ips[0] == 1 && ips[1] == 2 && ips[2] == 3 && ips[3] == 4 && ports[0] == 6881 &&
               ips[4] == 5 && ips[5] == 6 && ips[6] == 7 && ips[7] == 8 && ports[1] == 6882 &&
               err[0] == '\0');
    }

    /* Every byte the trim must NOT swallow. */
    static const struct { const char *tag; const char *tail; size_t n; } bad[] = {
        { "brace", "}", 1 },          { "second-doc", "e", 1 },
        { "nul", "\x00", 1 },         { "tab", "\t", 1 },
        { "junk", "xx", 2 },          { "brace-crlf", "}\r\n ", 4 },
    };
    /* The tail lengths are chosen so that sizeof dict_body + n is never a multiple of 6:
     * below the bencode path there is a fallback that reads a length-multiple-of-6 body as
     * raw compact peers, and a tail that lands on that alignment is answered by the
     * fallback, not by the trim (pre-existing behaviour, unrelated to R41). */
    for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        char tag[64];
        snprintf(tag, sizeof tag, "http-parse-trailing-%s", bad[k].tag);
        np = r41_parse(dict_body, sizeof dict_body, bad[k].tail, bad[k].n,
                       &interval, &seeders, &leechers, ips, ports, err, sizeof err);
        expect_np(tag, np, -1, err);
    }

    /* Whitespace INSIDE the document is still invalid bencode: a space in the middle of
     * the interval integer, and a space between two dict entries. */
    {
        uint8_t tmp[512];
        int32_t tid = 0;
        size_t mid = 0;
        while (dict_body[mid] != '1' || dict_body[mid + 1] != '8') mid++; /* "i1800e" */
        memcpy(tmp, dict_body, mid);
        tmp[mid] = ' ';
        memcpy(tmp + mid + 1, dict_body + mid, sizeof dict_body - mid);
        expect_np("http-parse-inner-space-in-int",
                  ntx_tracker_http_parse_ex(tmp, sizeof dict_body + 1, &tid, &interval, &seeders,
                                            &leechers, ips, ports, 10, NULL, NULL, 0,
                                            err, sizeof err), -1, err);
        memcpy(tmp, dict_body, mid);
        tmp[mid] = ' ';
        memcpy(tmp + mid + 1, dict_body + mid, sizeof dict_body - mid);
        memcpy(tmp + sizeof dict_body + 1, " \r\n", 3);
        expect_np("http-parse-inner-space-trailing-crlf",
                  ntx_tracker_http_parse_ex(tmp, sizeof dict_body + 4, &tid, &interval, &seeders,
                                            &leechers, ips, ports, 10, NULL, NULL, 0,
                                            err, sizeof err), -1, err);
    }

    /* A body of nothing but whitespace is not a response: trimmed it is a zero-length
     * document, which must not be reported as a successful parse. */
    static const struct { const char *tag; const char *body; size_t n; } blank[] = {
        { "crlf-only", "\r\n", 2 },   { "spaces-only", "   ", 3 },
        { "mixed-only", " \r\n\t ", 5 },
        /* Length a multiple of 6: below the bencode path there is a fallback that reads
         * such a body as raw compact peers, so pre-fix these were ACCEPTED as one and two
         * garbage peers. The trimmed-to-nothing reply must be rejected before that. */
        { "six-spaces", "      ", 6 }, { "twelve", " \r\n \r\n \r\n \r\n", 12 },
    };
    for (size_t k = 0; k < sizeof blank / sizeof blank[0]; k++) {
        char tag[64];
        snprintf(tag, sizeof tag, "http-parse-blank-%s", blank[k].tag);
        np = r41_parse((const uint8_t *)blank[k].body, 0, blank[k].body, blank[k].n,
                       &interval, &seeders, &leechers, ips, ports, err, sizeof err);
        expect_np(tag, np, -1, err);
    }

    /* Guard on the untouched edge: an empty body keeps its existing verdict (the bencode
     * path fails, the compact path sees 0 % 6 and reports zero peers, not -1). */
    np = r41_parse((const uint8_t *)"", 0, "", 0, &interval, &seeders, &leechers,
                   ips, ports, err, sizeof err);
    expect_np("http-parse-empty-body-unchanged", np, 0, err);
}

static void test_http_connect_v4_loopback(void) {
    uint16_t port = (uint16_t)(40000 + (getpid() % 5000));
    int lfd = ntx_sock_tcp4();
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    inet_pton(AF_INET, "127.0.0.1", &sa.sin_addr);
    sa.sin_port = htons(port);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof sa) < 0 ||
        listen(lfd, 8) < 0) {
        if (lfd >= 0) close(lfd);
        printf("PASS (skip: v4 loopback) http-connect-v4\n");
        return;
    }
    int fd = -1;
    expect("http-connect-v4", http_connect("127.0.0.1", port, &fd) == 0 && fd >= 0);
    if (fd >= 0) close(fd);
    close(lfd);
}

static void test_http_connect_v6_loopback(void) {
    uint16_t port = (uint16_t)(45000 + (getpid() % 5000));
    int lfd = ntx_sock_tcp6();
    struct sockaddr_in6 sa6;
    memset(&sa6, 0, sizeof sa6);
    sa6.sin6_family = AF_INET6;
    inet_pton(AF_INET6, "::1", &sa6.sin6_addr);
    sa6.sin6_port = htons(port);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa6, sizeof sa6) < 0 ||
        listen(lfd, 8) < 0) {
        if (lfd >= 0) close(lfd);
        printf("PASS (skip: no IPv6) http-connect-v6\n");
        return;
    }
    int fd = -1;
    expect("http-connect-v6", http_connect("::1", port, &fd) == 0 && fd >= 0);
    if (fd >= 0) close(fd);
    fd = -1;
    expect("http-connect-v6-bracket", http_connect("[::1]", port, &fd) == 0 && fd >= 0);
    if (fd >= 0) close(fd);
    close(lfd);
}

static void test_http_connect_resolve_fail(void) {
    int fd = -1;
    expect("http-connect-resolve-fail",
           http_connect("no-such-host.example", 80, &fd) == -1);
}

int main(void) {
    uint8_t info_hash[20], peer_id[20], tracker_id[8];
    for (int i = 0; i < 20; i++) info_hash[i] = (uint8_t)(0xA0 + i);
    memset(peer_id, 0, sizeof peer_id);
    memcpy(peer_id, "ntx/1.0", 7);
    memset(tracker_id, 0, sizeof tracker_id);

    char url[512];
    size_t len = ntx_tracker_http_url_build(url, sizeof url, "http://tracker.example.com/announce",
                                            info_hash, peer_id, 6881, 1000, 2000, 3000,
                                            NTX_TRACKER_EVENT_STARTED, tracker_id, 0xDEADBEEFu);
    expect("url-build-len",
           len > 0 && len == strlen(url) &&
           strstr(url, "info_hash=%A0%A1%A2%A3%A4%A5%A6%A7%A8%A9%AA%AB%AC%AD%AE%AF%B0%B1%B2%B3") != NULL &&
           strstr(url, "compact=1") != NULL &&
           strstr(url, "numwant=200") != NULL &&
           strstr(url, "user_agent=ntx/1.0") != NULL &&
           strstr(url, "port=6881") != NULL &&
           strstr(url, "event=started") != NULL);

    char url0[512];
    size_t len0 = ntx_tracker_http_url_build(url0, sizeof url0, "http://tracker.example.com/announce",
                                             info_hash, peer_id, 6881, 1000, 2000, 3000,
                                             NTX_TRACKER_EVENT_NONE, tracker_id, 0xDEADBEEFu);
    expect("url-build-noevent",
           len0 > 0 && len0 == strlen(url0) && strstr(url0, "event=") == NULL);

    uint8_t ips[64];
    uint16_t ports[16];
    int32_t tid;
    uint32_t interval, seeders, leechers;
    char err[128];
    int np = ntx_tracker_http_parse(dict_body, sizeof dict_body, &tid, &interval, &seeders, &leechers,
                                    ips, ports, 10, err, sizeof err);
    expect("http-parse-dict",
           np == 2 &&
           interval == 1800 &&
           seeders == 3 &&
           leechers == 5 &&
           ips[0] == 1 && ips[1] == 2 && ips[2] == 3 && ips[3] == 4 && ports[0] == 6881 &&
           ips[4] == 5 && ips[5] == 6 && ips[6] == 7 && ips[7] == 8 && ports[1] == 6882);

    err[0] = '\0';
    np = ntx_tracker_http_parse(fail_body, sizeof fail_body, &tid, &interval, &seeders, &leechers,
                                ips, ports, 10, err, sizeof err);
    expect("http-parse-failure",
           np == -1 && strstr(err, "Not found") != NULL);

    np = ntx_tracker_http_parse(raw_body, sizeof raw_body, &tid, &interval, &seeders, &leechers,
                                ips, ports, 10, err, sizeof err);
    expect("http-parse-raw",
           np == 2 &&
           ips[0] == 1 && ips[1] == 2 && ips[2] == 3 && ips[3] == 4 && ports[0] == 6881 &&
           ips[4] == 5 && ips[5] == 6 && ips[6] == 7 && ips[7] == 8 && ports[1] == 6882);

    np = ntx_tracker_http_parse(junk_body, sizeof junk_body, &tid, &interval, &seeders, &leechers,
                                 ips, ports, 10, err, sizeof err);
    expect("http-parse-error", np == -1);

    uint8_t i4[64];
    uint16_t p4[16];
    uint8_t i6[16][16];
    uint16_t p6[16];
    ntx_be be;

    if (parse_be(v6_body, sizeof v6_body, &be)) {
        int n = http_parse_dict_ex(&be, &interval, &seeders, &leechers, i4, p4, 10, i6, p6, 10, err, sizeof err);
        expect("http-parse-dict-v6",
               n == 2 &&
               i4[0] == 1 && i4[1] == 2 && i4[2] == 3 && i4[3] == 4 && p4[0] == 6881 &&
               i6[0][0] == 0x20 && i6[0][1] == 0x01 && i6[0][2] == 0x0D && i6[0][3] == 0xB8 &&
               i6[0][15] == 0x09 && p6[0] == 6881);
        ntx_be_free(&be);
    } else {
        expect("http-parse-dict-v6", 0);
    }

    if (parse_be(v6_only_body, sizeof v6_only_body, &be)) {
        int n = http_parse_dict_ex(&be, &interval, &seeders, &leechers, i4, p4, 10, i6, p6, 10, err, sizeof err);
        expect("http-parse-dict6-only",
               n == 1 &&
               i6[0][0] == 0x20 && i6[0][3] == 0xB8 && i6[0][15] == 0x09 && p6[0] == 6881);
        ntx_be_free(&be);
    } else {
        expect("http-parse-dict6-only", 0);
    }

    if (parse_be(v6_empty_body, sizeof v6_empty_body, &be)) {
        int n = http_parse_dict_ex(&be, &interval, &seeders, &leechers, i4, p4, 10, i6, p6, 10, err, sizeof err);
        expect("http-parse-dict6-empty", n == 0);
        ntx_be_free(&be);
    } else {
        expect("http-parse-dict6-empty", 0);
    }

    if (parse_be(v6_body, sizeof v6_body, &be)) {
        int n = http_parse_dict(&be, &interval, &seeders, &leechers, i4, p4, 10, err, sizeof err);
        expect("http-parse-dict-ignores-v6", n == 1 && i4[0] == 1 && p4[0] == 6881);
        ntx_be_free(&be);
    } else {
        expect("http-parse-dict-ignores-v6", 0);
    }

    test_r41_trailing_whitespace();

    test_http_connect_v4_loopback();
    test_http_connect_v6_loopback();
    test_http_connect_resolve_fail();

    return g_fail ? 1 : 0;
}
