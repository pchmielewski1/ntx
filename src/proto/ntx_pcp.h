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

/* The result codes the driver has to tell apart: the pair each protocol reserves for
 * "not now, ask again later" (RFC 6887 §7.4 NO_RESOURCES / NETWORK_FAILURE, RFC 6886
 * §3.5 out-of-resources / network-failure) and the version code that means "speak the
 * other protocol". Every other verdict the gateway states is final for this sequence. */
enum { NTX_PCP_RES_NETWORK_FAILURE = 7, NTX_PCP_RES_NO_RESOURCES = 8 };
enum { NTX_NATPMP_RES_UNSUPP_VERSION = 1, NTX_NATPMP_RES_NETWORK_FAILURE = 3,
       NTX_NATPMP_RES_OUT_OF_RESOURCES = 4 };

/* RFC 6887 MAP request (60 B): client ip as v4-mapped v6, nonce 12 B, proto,
 * internal/suggested port. Writes exactly 60 B and returns 60. sugg_ip16 is the
 * suggested external address: NULL writes the all-zeros "no preference" of §11.1
 * (what a first acquisition sends); a renewal of a mapping we hold passes the address
 * the gateway assigned with the grant, which §11.2 wants back so the request still
 * identifies that mapping rather than asking for a new one. */
size_t pcp_build_map(uint8_t out[60], const uint8_t client_ip16[16], const uint8_t nonce[12],
                     uint8_t proto, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime,
                     const uint8_t sugg_ip16[16]);

typedef struct { uint8_t result; uint32_t lifetime, epoch; uint16_t ext_port; uint8_t ext_ip16[16]; } ntx_pcp_map_resp;

/* 0 ok; -1 short/garbage; -2 nonce/proto/port mismatch; 1 = version mismatch (NAT-PMP
 * fallback); any other positive value is the gateway's own Result Code (RFC 6887 §7.4),
 * which the driver has to tell apart from silence (R14). Strict per §8: the length
 * ceiling and multiple, the R bit and the opcode must all match the request, and no
 * byte past n is read — a verdict needs only the 24 B common header (§7.2), so a
 * result-only error reply of 24 B is a verdict, while SUCCESS without the 36 B of MAP
 * data grants nothing usable and is -1. On an error return r->result and r->lifetime
 * (the retry-after the reply carries, §7.4) are set; on -1/-2 *r is unspecified.
 * r->lifetime is the server's value VERBATIM, unclamped — RFC 6887 §8.3 wants
 * the client to cap an absurd one, and that cap (with the renewal clock) is
 * the session driver's job, so ntx_session_portmap.c must bound it before use. */
int pcp_parse_map(const uint8_t *b, size_t n, const uint8_t nonce[12], uint8_t proto, uint16_t int_port,
                  ntx_pcp_map_resp *r);

/* RFC 6886: external address request (2 B) and mapping request (12 B) */
size_t natpmp_build_addr(uint8_t out[2]);
size_t natpmp_build_map(uint8_t out[12], uint8_t op /*1 udp, 2 tcp*/, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime);

/* Both return 0 on a well-formed matching response and -1 on anything else
 * (length, version, opcode or internal-port mismatch); natpmp_parse_map also needs
 * op to be 1 or 2. natpmp_parse_map additionally returns the gateway's own result
 * code (RFC 6886 §3.5) as a positive value for a mapping response that refuses: the
 * driver must see a stated refusal as a refusal, not as silence (R14), and
 * *lifetime then carries the retry-after the reply names.
 * Lifetime is the server's value VERBATIM, unclamped — RFC 6887 §8.3 wants the
 * client to cap an absurd one, and that cap (with the renewal clock) is the
 * session driver's job, so ntx_session_portmap.c must bound it before use.
 *
 * Both also read octets 4..7 — the gateway's Seconds Since Start of Epoch (RFC 6886
 * §3.6, carried by every packet it sends, refusals included per §3.5). `sssoe` is an
 * optional read-out (NULL = not interested), written once the packet's shape —
 * version, opcode, length — has been accepted; on a -1 its value is unspecified. The
 * client compares it (RFC 6886 §3.7) and the comparison is the driver's job, exactly
 * like the lifetime cap above. */
int natpmp_parse_addr(const uint8_t *b, size_t n, uint8_t ext_ip[4], uint32_t *sssoe);
int natpmp_parse_map(const uint8_t *b, size_t n, uint8_t op, uint16_t int_port, uint16_t *ext_port,
                     uint32_t *lifetime, uint32_t *sssoe);

/* 1 when the address is in 10/8, 172.16/12, 192.168/16, 100.64/10 (CGNAT) or
 * fc00::/7, else 0. Input is always the 16-byte form that goes on the wire: an
 * IPv4 address must already be IPv4-mapped (::ffff:a.b.c.d — the first ten
 * octets zero, octets 10-11 0xff), exactly as RFC 6887 encodes IPv4 in PCP
 * fields. Callers holding a native 4-byte IPv4 must widen it first; a raw
 * a.b.c.d placed in the first four octets is read as a native IPv6 address and
 * will not match the v4 ranges. */
int pcp_ip_is_cgnat_or_private(const uint8_t ip16[16]);

#endif
