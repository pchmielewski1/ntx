#ifndef NTX_PCP_H
#define NTX_PCP_H

#include <stddef.h>
#include <stdint.h>

/* PCP (RFC 6887) and NAT-PMP (RFC 6886) codecs for the port mapper (design §8).
 * Pure byte transformers: no sockets, no state, no allocation. The session
 * driver (src/core/ntx_session_portmap.c) owns the socket, the nonce, the
 * retransmission clock and the source-address check (§8: only datagrams from
 * gateway:5351 are fed to the parsers). */

#define NTX_PCP_PORT 5351

enum { NTX_PCP_PROTO_TCP = 6, NTX_PCP_PROTO_UDP = 17 };

/* RFC 6887 MAP request (60 B): client ip as v4-mapped v6, nonce 12 B, proto,
 * internal/suggested port. Writes exactly 60 B and returns 60. The suggested
 * external IP is always the all-zeros "no preference" address (RFC 6887 §11.1). */
size_t pcp_build_map(uint8_t out[60], const uint8_t client_ip16[16], const uint8_t nonce[12],
                     uint8_t proto, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime);

typedef struct { uint8_t result; uint32_t lifetime, epoch; uint16_t ext_port; uint8_t ext_ip16[16]; } ntx_pcp_map_resp;

/* 0 ok; -1 short/garbage; -2 nonce/proto/port mismatch; 1 = version mismatch (NAT-PMP fallback).
 * Strict per §8: the length ceiling and multiple, the R bit, the opcode, the nonce,
 * the protocol and the internal port must all match the request, and no byte past
 * n is read. Result codes other than 0 (success) and 1 are -1 — a mapping is only
 * what SUCCESS grants. On -1/-2 the contents of *r are unspecified.
 * r->lifetime is the server's value VERBATIM, unclamped — RFC 6887 §8.3 wants
 * the client to cap an absurd one, and that cap (with the renewal clock) is
 * the session driver's job, so ntx_session_portmap.c must bound it before use. */
int pcp_parse_map(const uint8_t *b, size_t n, const uint8_t nonce[12], uint8_t proto, uint16_t int_port,
                  ntx_pcp_map_resp *r);

/* RFC 6886: external address request (2 B) and mapping request (12 B) */
size_t natpmp_build_addr(uint8_t out[2]);
size_t natpmp_build_map(uint8_t out[12], uint8_t op /*1 udp, 2 tcp*/, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime);

/* Both return 0 on a well-formed matching response and -1 on anything else
 * (length, version, opcode, result code or internal-port mismatch);
 * natpmp_parse_map also needs op to be 1 or 2.
 * Lifetime is the server's value VERBATIM, unclamped — RFC 6887 §8.3 wants the
 * client to cap an absurd one, and that cap (with the renewal clock) is the
 * session driver's job, so ntx_session_portmap.c must bound it before use. */
int natpmp_parse_addr(const uint8_t *b, size_t n, uint8_t ext_ip[4]);
int natpmp_parse_map(const uint8_t *b, size_t n, uint8_t op, uint16_t int_port, uint16_t *ext_port, uint32_t *lifetime);

/* 1 when the address is in 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT) or
 * fc00::/7, else 0. Input is always the 16-byte form that goes on the wire: an
 * IPv4 address must already be IPv4-mapped (::ffff:a.b.c.d — the first ten
 * octets zero, octets 10-11 0xff), exactly as RFC 6887 encodes IPv4 in PCP
 * fields. Callers holding a native 4-byte IPv4 must widen it first; a raw
 * a.b.c.d placed in the first four octets is read as a native IPv6 address and
 * will not match the v4 ranges. */
int pcp_ip_is_cgnat_or_private(const uint8_t ip16[16]);

#endif
