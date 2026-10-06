#include "ntx_holepunch.h"
#include "ntx_wire.h"

#include <string.h>

/* Byte offsets inside the payload (after the BT extended header). */
#define HP_O_MSG 0u
#define HP_O_TYPE 1u
#define HP_O_ADDR 2u

static int hp_addr_len(uint8_t addr_type) {
    switch (addr_type) {
        case NTX_HP_AF_V4: return 4;
        case NTX_HP_AF_V6: return 16;
        default: return -1;
    }
}

static int hp_err_valid(uint32_t e) {
    return e >= NTX_HP_ERR_NO_SUCH_PEER && e <= NTX_HP_ERR_NO_SELF;
}

size_t ntx_holepunch_build(uint8_t *out, size_t cap, const ntx_holepunch_msg *m) {
    if (!out || !m) return 0;
    if (m->msg_type != NTX_HP_MSG_RENDEZVOUS && m->msg_type != NTX_HP_MSG_CONNECT &&
        m->msg_type != NTX_HP_MSG_ERROR)
        return 0;
    int alen = hp_addr_len(m->addr_type);
    if (alen < 0) return 0;
    /* err_code is 0 in non-error messages and a known code in an error. */
    if (m->msg_type == NTX_HP_MSG_ERROR) {
        if (!hp_err_valid(m->err_code)) return 0;
    } else if (m->err_code != NTX_HP_ERR_NONE) {
        return 0;
    }
    size_t need = (size_t)(2 + alen + 2 + 4);
    if (cap < need) return 0;

    out[HP_O_MSG] = m->msg_type;
    out[HP_O_TYPE] = m->addr_type;
    /* addr is stored in network byte order inside ntx_addr; copy verbatim. */
    const uint8_t *src = (m->addr_type == NTX_HP_AF_V4) ? (const uint8_t *)&m->addr.u.v4 : m->addr.u.v6;
    memcpy(out + HP_O_ADDR, src, (size_t)alen);
    ntx_wire_wr16(out + HP_O_ADDR + alen, m->port);
    ntx_wire_wr32(out + HP_O_ADDR + alen + 2, m->err_code);
    return need;
}

int ntx_holepunch_parse(const uint8_t *p, size_t n, ntx_holepunch_msg *m) {
    if (!p || !m) return -1;
    /* msg_type + addr_type + at least a v4 addr + port + err_code == 12, but
     * we accept the shorter header probe first and derive the exact length
     * from addr_type so a truncated/short buffer is rejected precisely. */
    if (n < 2) return -1;
    uint8_t msg_type = p[HP_O_MSG];
    uint8_t addr_type = p[HP_O_TYPE];
    if (msg_type != NTX_HP_MSG_RENDEZVOUS && msg_type != NTX_HP_MSG_CONNECT && msg_type != NTX_HP_MSG_ERROR)
        return -1;
    int alen = hp_addr_len(addr_type);
    if (alen < 0) return -1;
    size_t need = (size_t)(2 + alen + 2 + 4);
    if (n < need) return -1; /* truncation / short-len reject */

    ntx_holepunch_msg t;
    memset(&t, 0, sizeof t);
    t.msg_type = msg_type;
    t.addr_type = addr_type;
    if (addr_type == NTX_HP_AF_V4) {
        uint32_t v4;
        memcpy(&v4, p + HP_O_ADDR, 4);
        ntx_addr_set_v4(&t.addr, v4);
    } else {
        ntx_addr_set_v6(&t.addr, p + HP_O_ADDR);
    }
    t.port = ntx_wire_rd16(p + HP_O_ADDR + alen);
    t.err_code = ntx_wire_rd32(p + HP_O_ADDR + alen + 2);

    if (msg_type == NTX_HP_MSG_ERROR) {
        if (!hp_err_valid(t.err_code)) return -1;
    } else if (t.err_code != NTX_HP_ERR_NONE) {
        return -1;
    }
    *m = t;
    return 0;
}

size_t ntx_holepunch_build_error(uint8_t *out, size_t cap, const ntx_holepunch_msg *rq, uint32_t err_code) {
    if (!rq) return 0;
    ntx_holepunch_msg e;
    memset(&e, 0, sizeof e);
    e.msg_type = NTX_HP_MSG_ERROR;
    /* MUST: error echoes the rendezvous addr_type/addr/port exactly. */
    e.addr_type = rq->addr_type;
    e.addr = rq->addr;
    e.port = rq->port;
    e.err_code = err_code;
    return ntx_holepunch_build(out, cap, &e);
}

ntx_hp_relay_action ntx_holepunch_relay_policy(int initiator_declared, int target_declared,
                                                int connected_to_target, int already_connected,
                                                int target_is_self, uint32_t *err_out) {
    if (err_out) *err_out = NTX_HP_ERR_NONE;
    /* no ut_holepunch declaration in the initiator's HS => relay ignores
     * the inbound holepunch entirely. */
    if (!initiator_declared) return NTX_HP_RELAY_IGNORE;
    /* already connected => both sides ignore the connect. */
    if (already_connected) return NTX_HP_RELAY_IGNORE;
    /* Punching yourself is meaningless (and is the NoSelf error case). */
    if (target_is_self) {
        if (err_out) *err_out = NTX_HP_ERR_NO_SELF;
        return NTX_HP_RELAY_ERROR;
    }
    /* Relay is not connected to the target: NoSuchPeer (MAY be NotConnected;
     * we emit the more specific NoSuchPeer here and treat them as equivalent
     * on the receiving side). */
    if (!connected_to_target) {
        if (err_out) *err_out = NTX_HP_ERR_NO_SUCH_PEER;
        return NTX_HP_RELAY_ERROR;
    }
    /* Connected but the target never advertised ut_holepunch: NoSupport. */
    if (!target_declared) {
        if (err_out) *err_out = NTX_HP_ERR_NO_SUPPORT;
        return NTX_HP_RELAY_ERROR;
    }
    /* MUST: relay is connected to the target and the target declares
     * ut_holepunch => send connect to BOTH sides. */
    return NTX_HP_RELAY_CONNECT_BOTH;
}

ntx_hp_target_action ntx_holepunch_target_policy(int self_declared, int already_connected) {
    /* an unwanted target ignores the connect and MUST NOT error the relay;
     * an undeclared peer or one already connected likewise ignores it. */
    if (!self_declared) return NTX_HP_TARGET_IGNORE;
    if (already_connected) return NTX_HP_TARGET_IGNORE;
    return NTX_HP_TARGET_DIAL;
}

int ntx_holepunch_race_winner(const uint8_t our_id[20], const uint8_t their_id[20]) {
    if (!our_id || !their_id) return 0;
    /* Lower peer_id keeps the connection it dialled (the outbound dial wins).
     * Symmetric: the higher id therefore keeps the one it accepted, and the
     * two views describe the same single socket, so exactly one conn survives. */
    return memcmp(our_id, their_id, 20) < 0 ? 1 : 0;
}
