#ifndef NTX_HOLEPUNCH_H
#define NTX_HOLEPUNCH_H

#include <stddef.h>
#include <stdint.h>

#include "../net/ntx_addr.h"

/* BEP55 ut_holepunch — pure payload codec + relay/target/race policy.
 * See BEP 55.
 * No I/O, no session, no netx: everything here is a deterministic function of
 * its inputs, so the relay policy matrix, the race tie-break and the wire
 * vectors are all unit-testable without a socket. */

enum {
    NTX_HP_MSG_RENDEZVOUS = 0x00, /* to relay: connect me to the target endpoint */
    NTX_HP_MSG_CONNECT    = 0x01, /* from relay: dial uTP to the given endpoint */
    NTX_HP_MSG_ERROR      = 0x02  /* rendezvous impossible */
};

enum {
    NTX_HP_AF_V4 = 0x00,
    NTX_HP_AF_V6 = 0x01
};

enum {
    NTX_HP_ERR_NONE          = 0x00000000u, /* 0 in non-error messages */
    NTX_HP_ERR_NO_SUCH_PEER  = 0x00000001u,
    NTX_HP_ERR_NOT_CONNECTED = 0x00000002u,
    NTX_HP_ERR_NO_SUPPORT    = 0x00000003u,
    NTX_HP_ERR_NO_SELF       = 0x00000004u
};

/* Payload size after the BT extended header: msg_type(1) addr_type(1)
 * addr(4|16) port(2) err_code(4). */
#define NTX_HP_WIRE_V4 12u
#define NTX_HP_WIRE_V6 24u
#define NTX_HP_WIRE_MAX 24u

typedef struct {
    uint8_t msg_type;  /* NTX_HP_MSG_* */
    uint8_t addr_type; /* NTX_HP_AF_* */
    ntx_addr addr;    /* decoded endpoint (network byte order inside) */
    uint16_t port;    /* host byte order */
    uint32_t err_code; /* NTX_HP_ERR_*; 0 for rendezvous/connect */
} ntx_holepunch_msg;

/* Build one payload into out[0..cap). Returns the bytes written (12 for v4,
 * 24 for v6) or 0 on invalid msg_type/addr_type/err_code or cap too small.
 * Non-error messages MUST carry err_code == 0; error messages MUST carry a
 * known (1..4) err_code — a zero/unknown code on an error is rejected. */
size_t ntx_holepunch_build(uint8_t *out, size_t cap, const ntx_holepunch_msg *m);

/* Parse one payload. Returns 0 on success, -1 on malformed input: too short
 * for the header, an unknown msg_type/addr_type, an addr length that does not
 * match the declared addr_type, a non-error message carrying a nonzero
 * err_code, or an error message carrying a zero/unknown err_code. */
int ntx_holepunch_parse(const uint8_t *p, size_t n, ntx_holepunch_msg *m);

/* Build an error that echoes the rendezvous addr_type/addr/port EXACTLY (BEP 55
 * MUST) with the supplied err_code. Returns bytes written or 0 on error. */
size_t ntx_holepunch_build_error(uint8_t *out, size_t cap, const ntx_holepunch_msg *rq, uint32_t err_code);

/* ---- relay policy (pure; the BEP 55 MUST matrix) ---- */
typedef enum {
    NTX_HP_RELAY_IGNORE = 0,     /* drop, send nothing back */
    NTX_HP_RELAY_CONNECT_BOTH = 1, /* relay is ready to punch: emit connect to both sides */
    NTX_HP_RELAY_ERROR = 2       /* send an error echoing the rendezvous addr */
} ntx_hp_relay_action;

/* initiator_declared: the initiator's ext HS advertised ut_holepunch.
 * target_declared:    the target's ext HS advertised ut_holepunch.
 * connected_to_target:relay currently holds a live connection to the target.
 * already_connected:  the two peers are already connected to each other.
 * target_is_self:     the relay IS the target (a self-punch request).
 * err_out:            when RELAY_ERROR, the err_code the relay must send.
 * Returns the relay action for an inbound rendezvous. */
ntx_hp_relay_action ntx_holepunch_relay_policy(int initiator_declared, int target_declared,
                                                int connected_to_target, int already_connected,
                                                int target_is_self, uint32_t *err_out);

/* ---- target policy (pure): a peer that just RECEIVED a connect. ---- */
typedef enum {
    NTX_HP_TARGET_IGNORE = 0, /* not declared / already connected => ignore, MUST NOT error the relay */
    NTX_HP_TARGET_DIAL = 1    /* dial uTP to the supplied endpoint */
} ntx_hp_target_action;

/* self_declared: this peer's ext HS advertised ut_holepunch.
 * already_connected: this peer already has a live conn to that endpoint.
 * An unwanted target simply ignores the connect and MUST NOT error the relay. */
ntx_hp_target_action ntx_holepunch_target_policy(int self_declared, int already_connected);

/* ---- race tie-break (pure; BOTH uTP dials may succeed). ---- */
/* 1 => the OUTBOUND dial is the survivor (drop the inbound accept).
 * 0 => the INBOUND accept is the survivor (drop the outbound dial).
 * Deterministic and symmetric: both peers, seeing the same peer_id pair,
 * agree on which single physical connection survives — the peer with the
 * lexicographically lower id keeps the connection it dialled, the other keeps
 * the one it accepted (which is the same socket). */
int ntx_holepunch_race_winner(const uint8_t our_id[20], const uint8_t their_id[20]);

#endif
