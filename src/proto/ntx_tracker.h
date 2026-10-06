#ifndef NTX_TRACKER_H
#define NTX_TRACKER_H

/* Peers requested per announce (HTTP numwant / UDP num_want); the session parses up to this many. */
#define NTX_TRACKER_NUMWANT 200

#include <stddef.h>
#include <stdint.h>

enum {
    NTX_TRACKER_ACTION_CONNECT = 0,
    NTX_TRACKER_ACTION_ANNOUNCE = 1,
    NTX_TRACKER_ACTION_ERROR = 3
};

enum {
    NTX_TRACKER_EVENT_NONE = 0,
    NTX_TRACKER_EVENT_COMPLETED = 1,
    NTX_TRACKER_EVENT_STARTED = 2,
    NTX_TRACKER_EVENT_STOPPED = 3
};

enum {
    NTX_TRACKER_CONNECT_REQ_LEN = 16,
    NTX_TRACKER_ANNOUNCE_REQ_LEN = 98
};

void ntx_tracker_udp_connect_build(uint8_t out[16], int32_t trans_id);
int ntx_tracker_udp_connect_parse(const uint8_t *buf, size_t n, int32_t *trans_id, uint64_t *conn_id);
void ntx_tracker_udp_announce_build(uint8_t out[98], uint64_t conn_id, int32_t trans_id,
                                    const uint8_t info_hash[20], const uint8_t peer_id[20],
                                    uint64_t downloaded, uint64_t left, uint64_t uploaded,
                                    int event, uint32_t key, uint16_t port);
int ntx_tracker_udp_announce_parse(const uint8_t *buf, size_t n, int32_t *trans_id,
                                   uint32_t *interval, uint32_t *leechers, uint32_t *seeders,
                                   uint8_t *ips, uint16_t *ports, int max_peers);
/* IPv6: after the v4 block, if rem = n - 20 - count*6 satisfies rem>0 and rem%18==0,
 * the tail is parsed as peers6 (compact6, stride 18). v6 outputs = NULL → ignored (compat).
 * Returns the v4 peer count (like the old version); the n4/n6 pointers are optional. */
int ntx_tracker_udp_announce_parse_ex(const uint8_t *buf, size_t n, int32_t *trans_id,
                                      uint32_t *interval, uint32_t *leechers, uint32_t *seeders,
                                      uint8_t *ips4, uint16_t *ports4, int max4, int *n4,
                                      uint8_t ips6[][16], uint16_t *ports6, int max6, int *n6);
int ntx_tracker_peer_parse_compact(const uint8_t *buf, size_t n, uint8_t *ips, uint16_t *ports, int max_peers);
int ntx_tracker_peer_parse_compact6(const uint8_t *buf, size_t n, uint8_t ips[][16], uint16_t *ports, int max_peers);

size_t ntx_tracker_http_url_build(char *out, size_t cap, const char *base_url,
                                  const uint8_t info_hash[20], const uint8_t peer_id[20],
                                  uint16_t port, uint64_t uploaded, uint64_t downloaded,
                                  uint64_t left, int event, const uint8_t tracker_id[8],
                                  uint32_t key);
int ntx_tracker_http_parse(const uint8_t *buf, size_t n, int32_t *trans_id_unused,
                           uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                           uint8_t *ips, uint16_t *ports, int max_peers, char *error, size_t err_cap);
/* IPv6: v6 outputs (ips6/ports6/max6) — NULL/0 = ignore peers6.
 * Returns the total peer count (v4 + v6); -1 = error (error filled in). */
int ntx_tracker_http_parse_ex(const uint8_t *buf, size_t n, int32_t *trans_id_unused,
                              uint32_t *interval, uint32_t *seeders, uint32_t *leechers,
                              uint8_t *ips4, uint16_t *ports4, int max4,
                              uint8_t ips6[][16], uint16_t *ports6, int max6,
                              char *error, size_t err_cap);

#endif
