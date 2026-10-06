#ifndef NTX_PEER_H
#define NTX_PEER_H

#include <stdint.h>
#include "../net/ntx_addr.h"

enum {
    NTX_PEER_ST_HS = 0,
    NTX_PEER_ST_OK = 1,
    NTX_PEER_MAX_REQ = 128,
    NTX_PEER_REQ_LEN = 16384,
    NTX_PEER_REQ_TIMEOUT_S = 30,
    NTX_PEER_REQ_TIMEOUT_FAST_S = 12,
    NTX_PEER_REQ_STALE_MS = 8000,
    NTX_PEER_PIPE_MIN = 32 /* requests kept in flight to a new or slow peer */
};

typedef struct ntx_peer {
    int fd;
    ntx_addr addr;
    uint16_t port;
    int st;
    /* BEP55: the remote's 20-byte BT peer_id captured at
     * promote-time, used by the ut_holepunch race tie-break to pick the single
     * surviving connection when both sides dial at once. id_set gates use. */
    uint8_t id[20];
    uint8_t id_set;
    uint64_t conn_t0;
    uint64_t hs_t0;
    uint64_t rx_t0; /* last time bytes arrived from this peer (idle detection) */
    int choke_us;
    int we_choke;
    int int_us;
    int we_int;
    uint8_t *phave;
    int phave_n;
    int phave_none;
    uint32_t *req_idx;
    uint32_t *req_off;
    uint32_t *req_len;
    uint64_t *req_t0;
    int n_req;
    double spd_d;
    uint64_t down_B, up_B;
} ntx_peer;

void ntx_peer_init(ntx_peer *p, int fd, const ntx_addr *addr, uint16_t port, int np);
void ntx_peer_free(ntx_peer *p);
void ntx_peer_set_phave(ntx_peer *p, uint32_t i, int have);
int ntx_peer_has(const ntx_peer *p, uint32_t i);
int ntx_peer_can_download(const ntx_peer *p);
int ntx_peer_can_send(const ntx_peer *p);
void ntx_peer_set_choke_us(ntx_peer *p, int v);
void ntx_peer_set_we_choke(ntx_peer *p, int v);
void ntx_peer_set_int_us(ntx_peer *p, int v);
void ntx_peer_set_we_int(ntx_peer *p, int v);
int ntx_peer_request(ntx_peer *p, uint32_t idx, uint32_t off, uint32_t len, uint64_t now);
void ntx_peer_request_done(ntx_peer *p, uint32_t idx, uint32_t off);
/* 1 if (idx, off, len) is exactly a block we asked this peer for and have not received yet. */
int ntx_peer_request_match(const ntx_peer *p, uint32_t idx, uint32_t off, uint32_t len);
void ntx_peer_clear_requests(ntx_peer *p);
int ntx_peer_timeout(ntx_peer *p, uint64_t now);
int ntx_peer_timeout_lim(ntx_peer *p, uint64_t now, uint64_t lim_ms);
int ntx_peer_req_count(const ntx_peer *p);

/* How many block requests to keep in flight to this peer: enough for ~2 s of its measured throughput
 * (lifetime average since it became OK) plus slack, between NTX_PEER_PIPE_MIN and NTX_PEER_MAX_REQ.
 * A fast peer on a long path needs far more than 32 x 16 KiB to fill the pipe; a slow one must not be
 * handed megabytes of requests it cannot answer before the request timeout. hs_t0 is the OK-since time. */
static inline int ntx_peer_pipe_depth(const ntx_peer *p, uint64_t now) {
    if (!p->hs_t0 || now <= p->hs_t0 + 1000) return NTX_PEER_PIPE_MIN;
    uint64_t rate = p->down_B * 1000u / (now - p->hs_t0); /* B/s */
    uint64_t d = rate * 2u / NTX_PEER_REQ_LEN + 16u;
    if (d < NTX_PEER_PIPE_MIN) d = NTX_PEER_PIPE_MIN;
    if (d > NTX_PEER_MAX_REQ) d = NTX_PEER_MAX_REQ;
    return (int)d;
}

#endif
