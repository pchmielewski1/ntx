#include "ntx_btmsg.h"
#include "../core/ntx_session_internal.h"
#include "ntx_wire.h"

#include <string.h>

/* BEP3 message builders (ntx_btmsg_build_*) — split out of ntx_session_peer.c. */

size_t ntx_btmsg_build_choke(uint8_t *out, size_t cap, int choked) {
    if (cap < 5) return 0;
    ntx_wire_wr32(out, 1);
    out[4] = (uint8_t)(choked ? MSG_CHOKE : MSG_UNCHOKE);
    return 5;
}

size_t ntx_btmsg_build_interest(uint8_t *out, size_t cap, int interested) {
    if (cap < 5) return 0;
    ntx_wire_wr32(out, 1);
    out[4] = (uint8_t)(interested ? MSG_INTERESTED : MSG_NOT_INTERESTED);
    return 5;
}

size_t ntx_btmsg_build_have(uint8_t *out, size_t cap, uint32_t idx) {
    if (cap < 9) return 0;
    ntx_wire_wr32(out, 5);
    out[4] = (uint8_t)MSG_HAVE;
    ntx_wire_wr32(out + 5, idx);
    return 9;
}

size_t ntx_btmsg_build_have_all(uint8_t *out, size_t cap) {
    if (cap < 5) return 0;
    ntx_wire_wr32(out, 1);
    out[4] = (uint8_t)MSG_HAVE_ALL;
    return 5;
}

size_t ntx_btmsg_build_have_none(uint8_t *out, size_t cap) {
    if (cap < 5) return 0;
    ntx_wire_wr32(out, 1);
    out[4] = (uint8_t)MSG_HAVE_NONE;
    return 5;
}

size_t ntx_btmsg_build_bitfield(uint8_t *out, size_t cap, const uint8_t *bits, size_t nbytes) {
    if (cap < 5 + nbytes) return 0;
    ntx_wire_wr32(out, 1 + nbytes);
    out[4] = (uint8_t)MSG_BITFIELD;
    memcpy(out + 5, bits, nbytes);
    return 5 + nbytes;
}

size_t ntx_btmsg_build_request(uint8_t *out, size_t cap, uint32_t idx, uint32_t off, uint32_t len) {
    if (cap < 17) return 0;
    ntx_wire_wr32(out, 13);
    out[4] = (uint8_t)MSG_REQUEST;
    ntx_wire_wr32(out + 5, idx);
    ntx_wire_wr32(out + 9, off);
    ntx_wire_wr32(out + 13, len);
    return 17;
}

size_t ntx_btmsg_build_cancel(uint8_t *out, size_t cap, uint32_t idx, uint32_t off, uint32_t len) {
    if (cap < 17) return 0;
    ntx_wire_wr32(out, 13);
    out[4] = (uint8_t)MSG_CANCEL;
    ntx_wire_wr32(out + 5, idx);
    ntx_wire_wr32(out + 9, off);
    ntx_wire_wr32(out + 13, len);
    return 17;
}

size_t ntx_btmsg_build_piece(uint8_t *out, size_t cap, uint32_t idx, uint32_t off, const uint8_t *data,
                             uint32_t len) {
    if (cap < 13 + len) return 0;
    ntx_wire_wr32(out, 9 + len);
    out[4] = (uint8_t)MSG_PIECE;
    ntx_wire_wr32(out + 5, idx);
    ntx_wire_wr32(out + 9, off);
    memcpy(out + 13, data, len);
    return 13 + len;
}

size_t ntx_btmsg_build_keepalive(uint8_t *out, size_t cap) {
    if (cap < 4) return 0;
    memset(out, 0, 4);
    return 4;
}
