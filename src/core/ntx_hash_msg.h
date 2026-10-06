#ifndef NTX_HASH_MSG_H
#define NTX_HASH_MSG_H

#include <stddef.h>
#include <stdint.h>

/* BEP52 hash exchange wire codec.

   Message ids after the standard BT length+id framing:
     21 hash request | 22 hashes (answer to 21) | 23 hash reject (refusal)

   Request/reject payload layout (48 B), uint32 big-endian:
     pieces_root(32 B) | base_layer | index | length | proof_layers
   hashes payload = same header + trailing hashes blob (concat 32 B
   SHA2-256 hashes). reject layout is identical to the request it refuses.

   Two API levels:
     - payload level (ntx_hash_req_ and ntx_hash_hashes_ prefixes): buffer
       is the message payload only (after length+id);
     - framed level (ntx_hash_msg_ prefix): buffer is the full BT frame
       len(BE uint32) + id + payload; parse validates the length prefix
       and the message id.
   Parsers are framing-legal only: semantic BEP52 constraints live in
   ntx_hash_req_constraints_ok(). All return 0 ok / -1 bad (parsers),
   byte count or 0 (builders). */

enum { NTX_MSG_HASH_REQUEST = 21, NTX_MSG_HASHES = 22, NTX_MSG_HASH_REJECT = 23 };

#define NTX_HASH_REQ_PAYLOAD 48u /* 32 + 4 * 4 */

typedef struct {
    uint8_t pieces_root[32];
    uint32_t base_layer, index, length, proof_layers;
} ntx_hash_req;

/* ---- payload level ---- */

int ntx_hash_req_parse(const uint8_t *p, size_t n, ntx_hash_req *o);
size_t ntx_hash_req_write(uint8_t *out, size_t cap, const ntx_hash_req *r);
/* hashes: req header fields + trailing hash bytes */
int ntx_hash_hashes_parse(const uint8_t *p, size_t n, ntx_hash_req *hdr,
                          const uint8_t **hashes, size_t *hashes_nbytes);
size_t ntx_hash_hashes_write(uint8_t *out, size_t cap, const ntx_hash_req *hdr,
                             const uint8_t *hashes, size_t hashes_nbytes);

/* BEP52 MUST rules for a hash request: length >= 2 and power of two,
 * index % length == 0 (index == 0 included). The SHOULD length <= 512 is
 * deliberately NOT enforced (receiver tolerance; peers may send more).
 * Returns 1 ok, 0 violation (also for NULL). */
int ntx_hash_req_constraints_ok(const ntx_hash_req *r);

/* ---- framed level (full BT frame) ---- */

int ntx_hash_msg_parse_request(const uint8_t *p, size_t n, ntx_hash_req *o);
int ntx_hash_msg_parse_reject(const uint8_t *p, size_t n, ntx_hash_req *o);
int ntx_hash_msg_parse_hashes(const uint8_t *p, size_t n, ntx_hash_req *hdr,
                              const uint8_t **hashes, size_t *hashes_nbytes);

/* Builders emit the full frame; return total bytes, 0 when cap is too
 * small or the arguments are invalid. */
size_t ntx_hash_msg_build_request(uint8_t *out, size_t cap, const ntx_hash_req *r);
size_t ntx_hash_msg_build_reject(uint8_t *out, size_t cap, const ntx_hash_req *r);
size_t ntx_hash_msg_build_hashes(uint8_t *out, size_t cap, const ntx_hash_req *hdr,
                                 const uint8_t *hashes, size_t hashes_nbytes);

/* Payload byte count (excludes the length prefix and the id byte) of a
 * hashes message carrying hashes_nbytes hash bytes, i.e. 48 + hashes_nbytes.
 * 0 when the blob is not wire-legal: hashes_nbytes must be a multiple of 32
 * and hold at least hdr->length base-layer hashes (BEP52: the response
 * carries the requested base-layer span plus proof uncles). */
size_t ntx_hash_msg_hashes_payload_len(const ntx_hash_req *hdr, size_t hashes_nbytes);

#endif
