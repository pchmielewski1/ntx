#ifndef NTX_BTMSG_H
#define NTX_BTMSG_H

#include <stdint.h>
#include <stddef.h>

/* BEP3 message builders — split out of the ntx_session_peer.c send_* wrappers.
   Each returns the number of bytes written to `out` (0 if `cap` is too small).
   Implementations also need ntx_session_internal.h (MSG_* enum, NTX_PEER_REQ_LEN). */

size_t ntx_btmsg_build_choke(uint8_t *out, size_t cap, int choked);
size_t ntx_btmsg_build_interest(uint8_t *out, size_t cap, int interested);
size_t ntx_btmsg_build_have(uint8_t *out, size_t cap, uint32_t idx);
size_t ntx_btmsg_build_have_all(uint8_t *out, size_t cap);
size_t ntx_btmsg_build_have_none(uint8_t *out, size_t cap);
size_t ntx_btmsg_build_bitfield(uint8_t *out, size_t cap, const uint8_t *bits, size_t nbytes);
size_t ntx_btmsg_build_request(uint8_t *out, size_t cap, uint32_t idx, uint32_t off, uint32_t len);
size_t ntx_btmsg_build_cancel(uint8_t *out, size_t cap, uint32_t idx, uint32_t off, uint32_t len);
size_t ntx_btmsg_build_piece(uint8_t *out, size_t cap, uint32_t idx, uint32_t off, const uint8_t *data,
                             uint32_t len);
size_t ntx_btmsg_build_keepalive(uint8_t *out, size_t cap);

#endif
