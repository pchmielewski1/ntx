#include "ntx_tracker.h"
#include "ntx_bencode.h"
#include "ntx_wire.h"
#include "ntx_http.h"
#include <stdio.h>
#include <string.h>

/* BEP15 protocol_id = 0x41727101980 as uint64 BE → 00 00 04 17 27 10 19 80 */
static const uint8_t NTX_TRACKER_PROTO_ID[8] = {
    0x00, 0x00, 0x04, 0x17, 0x27, 0x10, 0x19, 0x80
};

static uint64_t rd64(const uint8_t *p) {
    return ((uint64_t)ntx_wire_rd32(p) << 32) | (uint64_t)ntx_wire_rd32(p + 4);
}

static void wr64(uint8_t *p, uint64_t v) {
    ntx_wire_wr32(p, (uint32_t)(v >> 32));
    ntx_wire_wr32(p + 4, (uint32_t)v);
}

void ntx_tracker_udp_connect_build(uint8_t out[16], int32_t trans_id) {
    memcpy(out, NTX_TRACKER_PROTO_ID, 8);
    ntx_wire_wr32(out + 8, (uint32_t)NTX_TRACKER_ACTION_CONNECT);
    ntx_wire_wr32(out + 12, (uint32_t)trans_id);
}

int ntx_tracker_udp_connect_parse(const uint8_t *buf, size_t n, int32_t *trans_id, uint64_t *conn_id) {
    if (n < 16) return -1;
    if (ntx_wire_rd32(buf) != (uint32_t)NTX_TRACKER_ACTION_CONNECT) return -1;
    *trans_id = (int32_t)ntx_wire_rd32(buf + 4);
    *conn_id = rd64(buf + 8);
    return 0;
}

void ntx_tracker_udp_announce_build(uint8_t out[98], uint64_t conn_id, int32_t trans_id,
                                    const uint8_t info_hash[20], const uint8_t peer_id[20],
                                    uint64_t downloaded, uint64_t left, uint64_t uploaded,
                                    int event, uint32_t key, uint16_t port) {
    wr64(out + 0, conn_id);
    ntx_wire_wr32(out + 8, (uint32_t)NTX_TRACKER_ACTION_ANNOUNCE);
    ntx_wire_wr32(out + 12, (uint32_t)trans_id);
    memcpy(out + 16, info_hash, 20);
    memcpy(out + 36, peer_id, 20);
    wr64(out + 56, downloaded);
    wr64(out + 64, left);
    wr64(out + 72, uploaded);
    ntx_wire_wr32(out + 80, (uint32_t)event);
    ntx_wire_wr32(out + 84, 0);
    ntx_wire_wr32(out + 88, key);
    ntx_wire_wr32(out + 92, NTX_TRACKER_NUMWANT);
    ntx_wire_wr16(out + 96, port);
}

int ntx_tracker_udp_announce_parse_ex(const uint8_t *buf, size_t n, int32_t *trans_id,
                                      uint32_t *interval, uint32_t *leechers, uint32_t *seeders,
                                      uint8_t *ips4, uint16_t *ports4, int max4, int *n4,
                                      uint8_t ips6[][16], uint16_t *ports6, int max6, int *n6) {
    if (n < 20) return -1;
    if (ntx_wire_rd32(buf) != (uint32_t)NTX_TRACKER_ACTION_ANNOUNCE) return -1;
    *trans_id = (int32_t)ntx_wire_rd32(buf + 4);
    *interval = ntx_wire_rd32(buf + 8);
    *leechers = ntx_wire_rd32(buf + 12);
    *seeders = ntx_wire_rd32(buf + 16);
    size_t avail = (n - 20) / 6;
    int count = (int)avail < max4 ? (int)avail : max4;
    if (count < 0) count = 0;
    for (int i = 0; i < count; i++) {
        const uint8_t *p = buf + 20 + (size_t)i * 6;
        memcpy(ips4 + (size_t)i * 4, p, 4);
        ports4[i] = ntx_wire_rd16(p + 4);
    }
    if (n4) *n4 = count;
    int c6 = 0;
    if (ips6 && ports6 && max6 > 0) {
        size_t rem = n - 20 - (size_t)count * 6;
        if (rem > 0 && rem % 18 == 0) {
            c6 = ntx_tracker_peer_parse_compact6(buf + 20 + (size_t)count * 6, rem, ips6, ports6, max6);
            if (c6 < 0) c6 = 0;
        }
    }
    if (n6) *n6 = c6;
    return count;
}

int ntx_tracker_udp_announce_parse(const uint8_t *buf, size_t n, int32_t *trans_id,
                                   uint32_t *interval, uint32_t *leechers, uint32_t *seeders,
                                   uint8_t *ips, uint16_t *ports, int max_peers) {
    return ntx_tracker_udp_announce_parse_ex(buf, n, trans_id, interval, leechers, seeders,
                                             ips, ports, max_peers, NULL,
                                             NULL, NULL, 0, NULL);
}

int ntx_tracker_peer_parse_compact(const uint8_t *buf, size_t n, uint8_t *ips, uint16_t *ports, int max_peers) {
    if (n % 6 != 0) return -1;
    size_t avail = n / 6;
    int count = (int)avail < max_peers ? (int)avail : max_peers;
    if (count < 0) count = 0;
    for (int i = 0; i < count; i++) {
        const uint8_t *p = buf + (size_t)i * 6;
        memcpy(ips + (size_t)i * 4, p, 4);
        ports[i] = ntx_wire_rd16(p + 4);
    }
    return count;
}

int ntx_tracker_peer_parse_compact6(const uint8_t *buf, size_t n, uint8_t ips[][16], uint16_t *ports, int max_peers) {
    size_t avail = n / 18;
    int count = (int)avail < max_peers ? (int)avail : max_peers;
    if (count < 0) count = 0;
    for (int i = 0; i < count; i++) {
        const uint8_t *p = buf + (size_t)i * 18;
        memcpy(ips[i], p, 16);
        ports[i] = ntx_wire_rd16(p + 16);
    }
    return count;
}

size_t ntx_tracker_http_url_build(char *out, size_t cap, const char *base_url,
                                  const uint8_t info_hash[20], const uint8_t peer_id[20],
                                  uint16_t port, uint64_t uploaded, uint64_t downloaded,
                                  uint64_t left, int event, const uint8_t tracker_id[8],
                                  uint32_t key) {
    if (!out || cap == 0) return 0;
    size_t pos = 0;
    int ov = 0;
    char num[40];

    http_put(out, cap, &pos, &ov, base_url);
    http_put(out, cap, &pos, &ov, "?info_hash=");
    for (int i = 0; i < 20; i++) {
        snprintf(num, sizeof num, "%%%02X", (int)info_hash[i]);
        http_put(out, cap, &pos, &ov, num);
    }
    http_put(out, cap, &pos, &ov, "&peer_id=");
    http_put_enc(out, cap, &pos, &ov, peer_id, 20);
    snprintf(num, sizeof num, "&port=%u", (unsigned)port);
    http_put(out, cap, &pos, &ov, num);
    snprintf(num, sizeof num, "&uploaded=%llu", (unsigned long long)uploaded);
    http_put(out, cap, &pos, &ov, num);
    snprintf(num, sizeof num, "&downloaded=%llu", (unsigned long long)downloaded);
    http_put(out, cap, &pos, &ov, num);
    snprintf(num, sizeof num, "&left=%llu", (unsigned long long)left);
    http_put(out, cap, &pos, &ov, num);
    snprintf(num, sizeof num, "&numwant=%d", NTX_TRACKER_NUMWANT);
    http_put(out, cap, &pos, &ov, num);
    http_put(out, cap, &pos, &ov, "&compact=1");
    if (event != 0) {
        const char *ev = NULL;
        switch (event) {
            case NTX_TRACKER_EVENT_COMPLETED: ev = "completed"; break;
            case NTX_TRACKER_EVENT_STARTED: ev = "started"; break;
            case NTX_TRACKER_EVENT_STOPPED: ev = "stopped"; break;
            default: break;
        }
        if (ev) {
            snprintf(num, sizeof num, "&event=%s", ev);
            http_put(out, cap, &pos, &ov, num);
        }
    }
    http_put(out, cap, &pos, &ov, "&trackerid=");
    http_put_enc(out, cap, &pos, &ov, tracker_id, 8);
    snprintf(num, sizeof num, "&key=%u", (unsigned)key);
    http_put(out, cap, &pos, &ov, num);
    http_put(out, cap, &pos, &ov, "&user_agent=ntx/1.0");

    if (ov) return 0;
    out[pos] = '\0';
    return pos;
}

int ntx_tracker_http_parse_ex(const uint8_t *buf, size_t n, int32_t *trans_id_unused,
                              uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                              uint8_t *ips4, uint16_t *ports4, int max4,
                              uint8_t ips6[][16], uint16_t *ports6, int max6,
                              char *error, size_t err_cap) {
    (void)trans_id_unused;
    if (interval) *interval = 0;
    if (seeders) *seeders = 0;
    if (leechers) *leechers = 0;

    ntx_be be;
    size_t consumed = 0;
    int rc = ntx_be_parse(buf, n, &be, &consumed, 16, n);
    if (rc == 0 && be.t == NTX_BE_DICT) {
        int count = http_parse_dict_ex(&be, interval, seeders, leechers, ips4, ports4, max4,
                                       ips6, ports6, max6, error, err_cap);
        ntx_be_free(&be);
        return count;
    }
    ntx_be_free(&be);

    if (n % 6 == 0) {
        size_t avail = n / 6;
        int count = (int)avail < max4 ? (int)avail : max4;
        if (count < 0) count = 0;
        for (int i = 0; i < count; i++) {
            const uint8_t *p = buf + (size_t)i * 6;
            memcpy(ips4 + (size_t)i * 4, p, 4);
            ports4[i] = ntx_wire_rd16(p + 4);
        }
        int c6 = 0;
        if (ips6 && ports6 && max6 > 0) {
            size_t rem = n - (size_t)count * 6;
            if (rem > 0 && rem % 18 == 0) {
                c6 = ntx_tracker_peer_parse_compact6(buf + (size_t)count * 6, rem, ips6, ports6, max6);
                if (c6 < 0) c6 = 0;
            }
        }
        return count + c6;
    }
    if (error && err_cap > 0) snprintf(error, err_cap, "unrecognized response");
    return -1;
}

int ntx_tracker_http_parse(const uint8_t *buf, size_t n, int32_t *trans_id_unused,
                           uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                           uint8_t *ips, uint16_t *ports, int max_peers, char *error, size_t err_cap) {
    return ntx_tracker_http_parse_ex(buf, n, trans_id_unused, interval, seeders, leechers,
                                     ips, ports, max_peers, NULL, NULL, 0, error, err_cap);
}
