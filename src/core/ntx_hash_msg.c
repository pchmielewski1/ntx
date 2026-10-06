#include "ntx_hash_msg.h"

#include <string.h>

static uint32_t hm_rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void hm_wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static void hm_rd_hdr(const uint8_t *p, ntx_hash_req *o) {
    memcpy(o->pieces_root, p, 32);
    o->base_layer = hm_rd32(p + 32);
    o->index = hm_rd32(p + 36);
    o->length = hm_rd32(p + 40);
    o->proof_layers = hm_rd32(p + 44);
}

static void hm_wr_hdr(uint8_t *p, const ntx_hash_req *r) {
    memcpy(p, r->pieces_root, 32);
    hm_wr32(p + 32, r->base_layer);
    hm_wr32(p + 36, r->index);
    hm_wr32(p + 40, r->length);
    hm_wr32(p + 44, r->proof_layers);
}

int ntx_hash_req_parse(const uint8_t *p, size_t n, ntx_hash_req *o) {
    if (!p || !o || n != NTX_HASH_REQ_PAYLOAD) return -1;
    hm_rd_hdr(p, o);
    return 0;
}

size_t ntx_hash_req_write(uint8_t *out, size_t cap, const ntx_hash_req *r) {
    if (!out || !r || cap < NTX_HASH_REQ_PAYLOAD) return 0;
    hm_wr_hdr(out, r);
    return NTX_HASH_REQ_PAYLOAD;
}

int ntx_hash_hashes_parse(const uint8_t *p, size_t n, ntx_hash_req *hdr,
                          const uint8_t **hashes, size_t *hashes_nbytes) {
    if (!p || !hdr || n < NTX_HASH_REQ_PAYLOAD) return -1;
    if ((n - NTX_HASH_REQ_PAYLOAD) % 32) return -1;
    hm_rd_hdr(p, hdr);
    size_t hn = n - NTX_HASH_REQ_PAYLOAD;
    if (hashes) *hashes = hn ? p + NTX_HASH_REQ_PAYLOAD : NULL;
    if (hashes_nbytes) *hashes_nbytes = hn;
    return 0;
}

size_t ntx_hash_hashes_write(uint8_t *out, size_t cap, const ntx_hash_req *hdr,
                             const uint8_t *hashes, size_t hashes_nbytes) {
    if (!out || !hdr) return 0;
    if (hashes_nbytes % 32) return 0;
    if (!hashes && hashes_nbytes) return 0;
    size_t total = NTX_HASH_REQ_PAYLOAD + hashes_nbytes;
    if (cap < total) return 0;
    hm_wr_hdr(out, hdr);
    if (hashes_nbytes) memcpy(out + NTX_HASH_REQ_PAYLOAD, hashes, hashes_nbytes);
    return total;
}

int ntx_hash_req_constraints_ok(const ntx_hash_req *r) {
    if (!r) return 0;
    uint32_t l = r->length;
    if (l < 2u || (l & (l - 1u)) != 0u) return 0; /* length >= 2, power of two */
    if ((r->index % l) != 0u) return 0;           /* index % length == 0 */
    return 1;
}

/* Full frame: len(BE32) + id + payload, buffer sized exactly to one frame. */
static int hm_frame(const uint8_t *p, size_t n, uint8_t id,
                    const uint8_t **pl, size_t *pln) {
    if (!p || n < 5) return -1;
    uint32_t len = hm_rd32(p);
    if (len < 2 || (size_t)len != n - 4) return -1; /* >= id + 1 payload B */
    if (p[4] != id) return -1;
    *pl = p + 5;
    *pln = (size_t)len - 1;
    return 0;
}

static int hm_parse_framed(const uint8_t *p, size_t n, uint8_t id, ntx_hash_req *o) {
    const uint8_t *pl;
    size_t pln;
    if (hm_frame(p, n, id, &pl, &pln) != 0) return -1;
    return ntx_hash_req_parse(pl, pln, o);
}

int ntx_hash_msg_parse_request(const uint8_t *p, size_t n, ntx_hash_req *o) {
    return hm_parse_framed(p, n, NTX_MSG_HASH_REQUEST, o);
}

int ntx_hash_msg_parse_reject(const uint8_t *p, size_t n, ntx_hash_req *o) {
    return hm_parse_framed(p, n, NTX_MSG_HASH_REJECT, o);
}

int ntx_hash_msg_parse_hashes(const uint8_t *p, size_t n, ntx_hash_req *hdr,
                              const uint8_t **hashes, size_t *hashes_nbytes) {
    const uint8_t *pl;
    size_t pln;
    if (hm_frame(p, n, NTX_MSG_HASHES, &pl, &pln) != 0) return -1;
    return ntx_hash_hashes_parse(pl, pln, hdr, hashes, hashes_nbytes);
}

static size_t hm_build(uint8_t *out, size_t cap, uint8_t id,
                       const uint8_t *pl, size_t pln) {
    if (!out || !pl) return 0;
    if (pln > (size_t)UINT32_MAX - 1) return 0;
    size_t total = 5 + pln;
    if (cap < total) return 0;
    hm_wr32(out, (uint32_t)(1 + pln));
    out[4] = id;
    memcpy(out + 5, pl, pln);
    return total;
}

static size_t hm_build_hdr(uint8_t *out, size_t cap, uint8_t id, const ntx_hash_req *r) {
    if (!r) return 0;
    uint8_t pl[NTX_HASH_REQ_PAYLOAD];
    if (!ntx_hash_req_write(pl, sizeof pl, r)) return 0;
    return hm_build(out, cap, id, pl, NTX_HASH_REQ_PAYLOAD);
}

size_t ntx_hash_msg_build_request(uint8_t *out, size_t cap, const ntx_hash_req *r) {
    return hm_build_hdr(out, cap, NTX_MSG_HASH_REQUEST, r);
}

size_t ntx_hash_msg_build_reject(uint8_t *out, size_t cap, const ntx_hash_req *r) {
    return hm_build_hdr(out, cap, NTX_MSG_HASH_REJECT, r);
}

size_t ntx_hash_msg_hashes_payload_len(const ntx_hash_req *hdr, size_t hashes_nbytes) {
    if (!hdr || hashes_nbytes % 32) return 0;
    if (hashes_nbytes / 32 < (size_t)hdr->length) return 0;
    return NTX_HASH_REQ_PAYLOAD + hashes_nbytes;
}

size_t ntx_hash_msg_build_hashes(uint8_t *out, size_t cap, const ntx_hash_req *hdr,
                                 const uint8_t *hashes, size_t hashes_nbytes) {
    if (!out || !hdr) return 0;
    if (ntx_hash_msg_hashes_payload_len(hdr, hashes_nbytes) == 0) return 0;
    if (!hashes) return 0;
    size_t pln = NTX_HASH_REQ_PAYLOAD + hashes_nbytes;
    if (pln > (size_t)UINT32_MAX - 1) return 0;
    size_t total = 5 + pln;
    if (cap < total) return 0;
    hm_wr32(out, (uint32_t)(1 + pln));
    out[4] = NTX_MSG_HASHES;
    if (!ntx_hash_req_write(out + 5, cap - 5, hdr)) return 0;
    memcpy(out + 5 + NTX_HASH_REQ_PAYLOAD, hashes, hashes_nbytes);
    return total;
}
