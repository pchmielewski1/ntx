#define _GNU_SOURCE
#include "../src/proto/ntx_http.h"
#include "../src/proto/ntx_tracker.h"

#include <stdio.h>
#include <string.h>
#include <stdint.h>

static const uint8_t ih[20] = {
    0x94, 0xe4, 0x1e, 0xa2, 0x41, 0xf8, 0x11, 0x52, 0x98, 0x24,
    0x22, 0xb2, 0x4e, 0x5c, 0x25, 0xa0, 0x97, 0x42, 0x43, 0x31
};

int main(void) {
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
