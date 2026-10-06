#include "ntx_peer.h"

#include <stdlib.h>
#include <string.h>

void ntx_peer_init(ntx_peer *p, int fd, const ntx_addr *addr, uint16_t port, int np) {
    memset(p, 0, sizeof(*p));
    p->fd = fd;
    p->addr = *addr;
    p->port = port;
    p->st = NTX_PEER_ST_HS;
    p->choke_us = 1; /* BEP3 default: choked until unchoke */
    p->we_choke = 1;
    p->phave = calloc(np, 1);
    p->phave_n = np;
    p->phave_none = 1;
    p->req_idx = calloc(NTX_PEER_MAX_REQ, sizeof(uint32_t));
    p->req_off = calloc(NTX_PEER_MAX_REQ, sizeof(uint32_t));
    p->req_len = calloc(NTX_PEER_MAX_REQ, sizeof(uint32_t));
    p->req_t0 = calloc(NTX_PEER_MAX_REQ, sizeof(uint64_t));
    p->n_req = 0;
}

void ntx_peer_free(ntx_peer *p) {
    free(p->phave);
    free(p->req_idx);
    free(p->req_off);
    free(p->req_len);
    free(p->req_t0);
    memset(p, 0, sizeof(*p));
}

void ntx_peer_set_phave(ntx_peer *p, uint32_t i, int have) {
    if (i >= (uint32_t)p->phave_n) return;
    if (p->phave[i] == (uint8_t)have) return;
    p->phave[i] = (uint8_t)have;
    if (have) {
        p->phave_none = 0;
    } else {
        p->phave_none = 1;
        for (uint32_t k = 0; k < (uint32_t)p->phave_n; k++)
            if (p->phave[k]) { p->phave_none = 0; break; }
    }
}

int ntx_peer_has(const ntx_peer *p, uint32_t i) {
    if (i >= (uint32_t)p->phave_n) return 0;
    return p->phave[i];
}

int ntx_peer_can_download(const ntx_peer *p) {
    return !p->choke_us && p->we_int;
}

int ntx_peer_can_send(const ntx_peer *p) {
    return !p->we_choke && p->int_us;
}

void ntx_peer_set_choke_us(ntx_peer *p, int v) { p->choke_us = v ? 1 : 0; }
void ntx_peer_set_we_choke(ntx_peer *p, int v) { p->we_choke = v ? 1 : 0; }
void ntx_peer_set_int_us(ntx_peer *p, int v) { p->int_us = v ? 1 : 0; }
void ntx_peer_set_we_int(ntx_peer *p, int v) { p->we_int = v ? 1 : 0; }

int ntx_peer_request(ntx_peer *p, uint32_t idx, uint32_t off, uint32_t len, uint64_t now) {
    if (p->n_req >= NTX_PEER_MAX_REQ) return -1;
    int i = p->n_req;
    p->req_idx[i] = idx;
    p->req_off[i] = off;
    p->req_len[i] = len;
    p->req_t0[i] = now;
    p->n_req++;
    return 0;
}

void ntx_peer_request_done(ntx_peer *p, uint32_t idx, uint32_t off) {
    for (int i = 0; i < p->n_req; i++) {
        if (p->req_idx[i] == idx && p->req_off[i] == off) {
            int j = p->n_req - 1;
            if (i != j) {
                p->req_idx[i] = p->req_idx[j];
                p->req_off[i] = p->req_off[j];
                p->req_len[i] = p->req_len[j];
                p->req_t0[i] = p->req_t0[j];
            }
            p->n_req--;
            return;
        }
    }
}

int ntx_peer_request_match(const ntx_peer *p, uint32_t idx, uint32_t off, uint32_t len) {
    for (int i = 0; i < p->n_req; i++)
        if (p->req_idx[i] == idx && p->req_off[i] == off && p->req_len[i] == len) return 1;
    return 0;
}

void ntx_peer_clear_requests(ntx_peer *p) {
    p->n_req = 0;
}

int ntx_peer_timeout_lim(ntx_peer *p, uint64_t now, uint64_t lim_ms) {
    int removed = 0;
    for (int i = 0; i < p->n_req; i++) {
        if (now > p->req_t0[i] && now - p->req_t0[i] > lim_ms) {
            int j = p->n_req - 1;
            p->req_idx[i] = p->req_idx[j];
            p->req_off[i] = p->req_off[j];
            p->req_len[i] = p->req_len[j];
            p->req_t0[i] = p->req_t0[j];
            p->n_req--;
            removed++;
            i--;
        }
    }
    return removed;
}

int ntx_peer_timeout(ntx_peer *p, uint64_t now) {
    return ntx_peer_timeout_lim(p, now, (uint64_t)NTX_PEER_REQ_TIMEOUT_S * 1000);
}

int ntx_peer_req_count(const ntx_peer *p) {
    return p->n_req;
}
