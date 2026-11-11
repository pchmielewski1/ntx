/* B6: ntx_sock_resolve must not hand out AAAA when the host has no usable
 * IPv6 route. Every share tracker is Cloudflare-fronted and publishes AAAA, so
 * an AAAA-first resolver without an A fallback is unreachable on an IPv4-only
 * machine. The gate is a ::/0 line in /proc/net/ipv6_route, read once (cached);
 * ntx_sock_test_set_route_file6() points it at a fixture and resets the cache,
 * so both halves run in one process. No threads, no blocking network. */
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* ntx_sock.c carries weak fallback DEFINITIONS of the DoH lookups; this TU
 * supplies its own strong pair, so compile the weak ones out. */
#define NTX_SOCK_TEST_STRONG_DOH
#include "../src/net/ntx_sock.c"
#undef NTX_SOCK_TEST_STRONG_DOH

/* Test hook in ntx_sock.c (NULL => /proc/net/ipv6_route); resets the cache. */
void ntx_sock_test_set_route_file6(const char *path);

static int fails;
static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else {
        printf("FAIL %s\n", name);
        fails = 1;
    }
}

/* --------------------------------------------------------------- DoH stubs */

static const char *const HOST_BOTH = "both.example"; /* AAAA + A */
static const char *const HOST_NONE = "none.example"; /* neither    */
static const uint8_t AAAA_REC[16] = { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0,
                                      0, 0, 0, 0, 0, 0, 0xc0, 0xa8 };
static const uint32_t A_REC = 0xCB007101u; /* 203.0.113.1, host order here */

static int aaaa_calls, a_calls;

int ntx_doh_lookup_aaaa(const char *host, uint8_t out[16]) {
    aaaa_calls++;
    if (!host || strcmp(host, HOST_BOTH) != 0) return -1;
    memcpy(out, AAAA_REC, 16);
    return 0;
}

int ntx_doh_lookup_a(const char *host, uint32_t *ip_out) {
    a_calls++;
    if (!host || strcmp(host, HOST_BOTH) != 0) return -1;
    *ip_out = htonl(A_REC);
    return 0;
}

/* ---------------------------------------------------------------- fixtures */

#define NO_ROUTE6 "test/.scratch/sock_route4/no_v6_route"
#define WITH_ROUTE6 "test/.scratch/sock_route4/v6_default"
#define BLACKHOLE_ROUTE6 "test/.scratch/sock_route4/v6_blackhole"
#define MISSING_ROUTE6 "test/.scratch/sock_route4/definitely_absent"

/* Real /proc/net/ipv6_route layout (9 fields, hex):
 * <dst> <dlen> <nexthop> <glen> <src> <metric> <refcnt> <use> <flags> <dev>.
 * Every line below carries usable flags (RTF_UP=1) and a sane metric, so a gate
 * that forgets the flags/metric check still passes this fixture by accident. */
static const char NO_ROUTE6_TEXT[] =
    "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    "00000000000000000000000000000001 80 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 lo\n"
    /* trap: prefix length 0 on a NON-zero destination is not the default route */
    "20010db8000000000000000000000000 00 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    /* trap: all-zero dst at the WRONG prefix length — only ::/0 is a default */
    "00000000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    "00000000000000000000000000000000 80 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    /* trap: ::1 with prefix 0 — a dst[0]=='0' / startswith test reads this as :: */
    "00000000000000000000000000000001 00 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 lo\n";

static const char WITH_ROUTE6_TEXT[] =
    "fe800000000000000000000000000000 40 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 00000100 00000001 00000000 00000001 eth0\n"
    /* real RA-learned default: <dst> <dlen> <nexthop> <glen> <src> <metric>
     * <refcnt> <use> <flags=RTF_UP> <dev> */
    "00000000000000000000000000000000 00 fe80000000000000d6ba3bfffefe074a 00 "
    "00000000000000000000000000000000 00000400 00000002 00000000 00000001 eth0\n";

/* Verbatim from /proc/net/ipv6_route on the development host (no IPv6 route):
 * networkd keeps an unreachable ::/0 on lo. A gate that only looks at "dst is ::
 * and plen is 0" reads this host as IPv6-capable and keeps the bug alive. */
static const char BLACKHOLE_ROUTE6_TEXT[] =
    "00000000000000000000000000000000 00 00000000000000000000000000000000 00 "
    "00000000000000000000000000000000 ffffffff 00000001 00000000 00200200 lo\n";

static int write_fixture(const char *path, const char *text) {
    FILE *f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "open fail %s: %s\n", path, strerror(errno));
        return -1;
    }
    fputs(text, f);
    fclose(f);
    return 0;
}

static int prepare(void) {
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return -1;
    if (mkdir("test/.scratch/sock_route4", 0755) != 0 && errno != EEXIST) return -1;
    if (write_fixture(NO_ROUTE6, NO_ROUTE6_TEXT) != 0) return -1;
    if (write_fixture(WITH_ROUTE6, WITH_ROUTE6_TEXT) != 0) return -1;
    if (write_fixture(BLACKHOLE_ROUTE6, BLACKHOLE_ROUTE6_TEXT) != 0) return -1;
    return 0;
}

static int is_v4(const ntx_addr *a, uint32_t net) {
    return a->family == NTX_AF_INET && a->u.v4 == net;
}

static int is_rec_v6(const ntx_addr *a) {
    return a->family == NTX_AF_INET6 && memcmp(a->u.v6, AAAA_REC, 16) == 0;
}

/* ------------------------------------------------------------------- cases */

/* 1 — no ::/0 in the route file: straight to A, AAAA is not even asked for. */
static void case_no_v6_route_falls_back_to_a(void) {
    aaaa_calls = a_calls = 0;
    ntx_sock_test_set_route_file6(NO_ROUTE6);
    ntx_addr a;
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_v4(&a, htonl(A_REC)),
          "no-v6-route-returns-A");
    check(a_calls == 1 && aaaa_calls == 0, "no-v6-route-never-asks-AAAA");
    /* cached read: a second resolve must not re-read the file (same answer). */
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_v4(&a, htonl(A_REC)) &&
              a_calls == 2 && aaaa_calls == 0,
          "no-v6-route-answer-stays-cached");
}

/* 2 — ::/0 present: today's AAAA preference is preserved, A is never asked. */
static void case_v6_route_keeps_aaaa(void) {
    aaaa_calls = a_calls = 0;
    ntx_sock_test_set_route_file6(WITH_ROUTE6);
    ntx_addr a;
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_rec_v6(&a),
          "v6-route-keeps-AAAA-preference");
    check(aaaa_calls == 1 && a_calls == 0, "v6-route-never-asks-A");
}

/* 3 — literals resolve identically under either route file, DoH untouched. */
static void case_literals_ignore_the_route_file(void) {
    const char *routes[2] = { NO_ROUTE6, WITH_ROUTE6 };
    for (int r = 0; r < 2; r++) {
        aaaa_calls = a_calls = 0;
        ntx_sock_test_set_route_file6(routes[r]);
        ntx_addr a;
        check(ntx_sock_resolve("1.2.3.4", &a) == 0 &&
                  is_v4(&a, htonl(0x01020304u)),
              "literal-v4-unaffected");
        check(ntx_sock_resolve("[2001:db8::1]", &a) == 0 &&
                  a.family == NTX_AF_INET6 && a.u.v6[0] == 0x20 &&
                  a.u.v6[1] == 0x01 && a.u.v6[2] == 0x0d && a.u.v6[3] == 0xb8 &&
                  a.u.v6[15] == 0x01,
              "literal-v6-bracketed-unaffected");
        check(ntx_sock_resolve("2001:db8::1", &a) == 0 &&
                  a.family == NTX_AF_INET6 && a.u.v6[15] == 0x01,
              "literal-v6-bare-unaffected");
        check(aaaa_calls == 0 && a_calls == 0, "literals-never-hit-DoH");
    }
}

/* 4 — host with neither record: -1 under both route files. */
static void case_no_record_fails(void) {
    const char *routes[2] = { NO_ROUTE6, WITH_ROUTE6 };
    for (int r = 0; r < 2; r++) {
        aaaa_calls = a_calls = 0;
        ntx_sock_test_set_route_file6(routes[r]);
        ntx_addr a;
        check(ntx_sock_resolve(HOST_NONE, &a) == -1, "no-record-returns-minus-1");
    }
}

/* 5 — the unreachable ::/0 networkd leaves on an IPv4-only host is not a route. */
static void case_blackhole_default_is_no_route(void) {
    aaaa_calls = a_calls = 0;
    ntx_sock_test_set_route_file6(BLACKHOLE_ROUTE6);
    ntx_addr a;
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_v4(&a, htonl(A_REC)),
          "blackhole-v6-default-falls-back-to-A");
    check(aaaa_calls == 0, "blackhole-v6-default-never-asks-AAAA");
}

/* 6 — unreadable route file (no IPv6 support at all) behaves as "no route", and
 * stays that way: the answer must be CACHED on the open-failure path too, so a
 * second resolve does not re-read (and does not fail open to AAAA). */
static void case_missing_route_file_is_no_route(void) {
    aaaa_calls = a_calls = 0;
    ntx_sock_test_set_route_file6(MISSING_ROUTE6);
    ntx_addr a;
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_v4(&a, htonl(A_REC)),
          "missing-route-file-falls-back-to-A");
    check(aaaa_calls == 0, "missing-route-file-never-asks-AAAA");
    /* Same again: caching the failure is what keeps AAAA from being tried on
     * the second call (sock_route6_cached = ok, not f ? ok : -1/1). */
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_v4(&a, htonl(A_REC)) &&
              aaaa_calls == 0,
          "missing-route-file-stays-cached-on-2nd-resolve");
}

/* 7 — the file is read ONCE: mutating the fixture under a live cache must not
 * change the answer. (A gate that re-reads per resolve flips v6 -> v4 here.) */
#define MUTABLE_ROUTE6 "test/.scratch/sock_route4/mutable"

static void case_route_file_read_once(void) {
    if (write_fixture(MUTABLE_ROUTE6, WITH_ROUTE6_TEXT) != 0) {
        check(0, "mutable-fixture-write");
        return;
    }
    aaaa_calls = a_calls = 0;
    ntx_sock_test_set_route_file6(MUTABLE_ROUTE6);
    ntx_addr a;
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_rec_v6(&a),
          "read-once-first-resolve-is-v6");
    if (write_fixture(MUTABLE_ROUTE6, NO_ROUTE6_TEXT) != 0) {
        check(0, "mutable-fixture-rewrite");
        return;
    }
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_rec_v6(&a) &&
              aaaa_calls == 2 && a_calls == 0,
          "read-once-rewrite-under-live-cache-changes-nothing");
}

/* 8 — the hook copies the path: the caller's buffer may be gone by the next
 * resolve (a hook that stored the pointer would read clobbered stack here). */
static void case_hook_copies_the_path(void) {
    char buf[64];
    snprintf(buf, sizeof buf, "%s", WITH_ROUTE6);
    aaaa_calls = a_calls = 0;
    ntx_sock_test_set_route_file6(buf);
    memset(buf, 'X', sizeof buf); /* caller's string dies */
    ntx_addr a;
    check(ntx_sock_resolve(HOST_BOTH, &a) == 0 && is_rec_v6(&a) &&
              aaaa_calls == 1 && a_calls == 0,
          "hook-copies-path-after-buffer-clobbered");
}

int main(void) {
    if (prepare() != 0) {
        printf("FAIL fixture-setup\n");
        return 1;
    }
    case_no_v6_route_falls_back_to_a();
    case_v6_route_keeps_aaaa();
    case_literals_ignore_the_route_file();
    case_no_record_fails();
    case_blackhole_default_is_no_route();
    case_missing_route_file_is_no_route();
    case_route_file_read_once();
    case_hook_copies_the_path();
    ntx_sock_test_set_route_file6(NULL); /* leave the hook off for any re-use */
    if (!fails) printf("PASS sock-route4\n");
    else printf("FAIL sock-route4\n");
    return fails ? 1 : 0;
}
