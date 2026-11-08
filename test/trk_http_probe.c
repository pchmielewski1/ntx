#define _GNU_SOURCE
#include "../src/proto/ntx_http.h"
#include "../src/proto/ntx_tracker.h"
#include "../src/crypto/ntx_rng.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

/* Fixed info-hash for the no-argument (legacy) mode. */
static const uint8_t ih[20] = {
    0x94, 0xe4, 0x1e, 0xa2, 0x41, 0xf8, 0x11, 0x52, 0x98, 0x24,
    0x22, 0xb2, 0x4e, 0x5c, 0x25, 0xa0, 0x97, 0x42, 0x43, 0x31
};

static void mk_peer_id(uint8_t out[20], char slot) {
    memset(out, '0', 20);
    out[0] = '-'; out[1] = 'N'; out[2] = 'T'; out[3] = 'X'; out[4] = (uint8_t)slot;
}

typedef struct {
    uint8_t ips4[256];
    uint16_t ports4[64];
    uint8_t ips6[64][16];
    uint16_t ports6[64];
} peer_list;

/* One HTTP(S) announce. Returns peer count (>=0) or -1 with a reason in err.
 * left/uploaded select the role: a seeder (left=0) is what the tracker must remember
 * and hand back to the second announce. peers6 is parsed too — a Cloudflare-fronted
 * tracker may list the peer only in the IPv6 block. */
static int announce(const char *base, const uint8_t hash[20], const uint8_t pid[20],
                    uint16_t port, uint64_t uploaded, uint64_t left, int event,
                    peer_list *pl, char *err, size_t errcap) {
    static uint8_t body[8192];
    uint8_t trk_id[8];
    char url[2048];
    size_t bn = 0;
    int32_t tid;
    uint32_t iv, s, l;
    int np;

    memset(pl, 0, sizeof *pl);
    memset(trk_id, 0, sizeof trk_id);
    if (!ntx_tracker_http_url_build(url, sizeof url, base, hash, pid, port, uploaded, 0,
                                    left, event, trk_id, 0)) {
        snprintf(err, errcap, "url build fail");
        return -1;
    }
    if (ntx_http_get(url, body, sizeof body, &bn) != 0) {
        snprintf(err, errcap, "http/tls failure");
        return -1;
    }
    np = ntx_tracker_http_parse_ex(body, bn, &tid, &iv, &s, &l,
                                   pl->ips4, pl->ports4, 64,
                                   pl->ips6, pl->ports6, 64, err, errcap);
    if (np < 0) {
        if (err[0] == '\0')
            snprintf(err, errcap, "bad response");
        return -1;
    }
    return np;
}

/* Survey mode (§6.3 pkt 1+3): two announces on one freshly random hash.
 * P1 registers as a seeder on port 40001; OK when the response to P2 (port 40002)
 * lists P1's port 40001, i.e. the tracker remembered it for that hash. */
static int probe_url(const char *base) {
    uint8_t hash[20], p1[20], p2[20];
    peer_list pl;
    char err[128];
    int np;

    ntx_rand_bytes(hash, 20);
    mk_peer_id(p1, '1');
    mk_peer_id(p2, '2');
    err[0] = '\0';
    if (announce(base, hash, p1, 40001, 1u << 20, 0, NTX_TRACKER_EVENT_STARTED,
                 &pl, err, sizeof err) < 0) {
        printf("FAIL %s announce1: %s\n", base, err[0] ? err : "error");
        return 1;
    }
    err[0] = '\0';
    sleep(1); /* let the tracker commit the registration before asking for it back */
    np = announce(base, hash, p2, 40002, 0, 1u << 20, NTX_TRACKER_EVENT_STARTED,
                  &pl, err, sizeof err);
    if (np < 0) {
        printf("FAIL %s announce2: %s\n", base, err[0] ? err : "error");
        return 1;
    }
    for (int i = 0; i < 64; i++)
        if (pl.ports4[i] == 40001 || pl.ports6[i] == 40001) {
            printf("OK %s peers_for_hash=%d\n", base, np);
            return 0;
        }
    printf("FAIL %s peer port 40001 not listed (np=%d)\n", base, np);
    return 1;
}

int main(int argc, char **argv) {
    if (argc > 1) {
        int fail = 0;
        for (int i = 1; i < argc; i++)
            if (probe_url(argv[i]) != 0) fail = 1;
        return fail;
    }

    uint8_t peer_id[20];
    uint8_t trk_id[8];
    memset(peer_id, 'N', 20);
    peer_id[0] = '-';
    peer_id[1] = 'N';
    peer_id[2] = 'T';
    peer_id[3] = '0';

    static const char *bases[] = {
        "http://tracker.renfei.net:8080/announce",
        "http://tracker.dler.org:6969/announce",
        "http://tracker.bittor.pw:1337/announce",
    };
    int ok = 0;
    for (size_t i = 0; i < sizeof bases / sizeof bases[0]; i++) {
        char url[2048];
        if (!ntx_tracker_http_url_build(url, sizeof url, bases[i], ih, peer_id, 6881, 0, 0,
                                        UINT64_MAX, 0, trk_id, 0)) {
            printf("%s rc=-2 np=0 (url build fail)\n", bases[i]);
            continue;
        }
        uint8_t body[8192];
        size_t bn = 0;
        int rc = ntx_http_get(url, body, sizeof body, &bn);
        int32_t tid;
        uint32_t iv, s, l;
        uint8_t ips[256];
        uint16_t ports[64];
        char err[128];
        int np = -1;
        if (rc == 0)
            np = ntx_tracker_http_parse(body, bn, &tid, &iv, &s, &l, ips, ports, 64, err, sizeof err);
        printf("%s rc=%d np=%d\n", bases[i], rc, np);
        if (rc == 0 && np > 0) ok = 1;
    }
    return ok ? 0 : 1;
}
