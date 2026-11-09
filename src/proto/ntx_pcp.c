#include <string.h>

#include "ntx_pcp.h"

/* PCP (RFC 6887) and NAT-PMP (RFC 6886) codecs (design §8).
 * Pure parsing/building: no sockets, no state, no allocation, no reads past n.
 * Everything static here is pcp_-prefixed for the unity build. */

#define PCP_VERSION 2
#define PCP_OPCODE_MAP 1
#define PCP_RESULT_SUCCESS 0
#define PCP_RESULT_UNSUPP_VERSION 1
#define PCP_HDR_LEN 24            /* §7.1 request / §7.2 response header */
#define PCP_MAP_DATA_LEN 36       /* §11.1 fig. 9 / fig. 10 */
#define PCP_MAP_LEN (PCP_HDR_LEN + PCP_MAP_DATA_LEN)
#define PCP_MAX_LEN 1100          /* §7: maximum UDP payload of a PCP message */

/* MAP opcode data offsets inside the 36 B following the common header:
 * nonce 12 | proto 1 + reserved 3 | internal port | assigned/suggested
 * external port | external IP 16 (RFC 6887 §11.1 fig. 9 and fig. 10). */
#define PCP_MAP_NONCE PCP_HDR_LEN
#define PCP_MAP_PROTO (PCP_HDR_LEN + 12)
#define PCP_MAP_INT_PORT (PCP_HDR_LEN + 16)
#define PCP_MAP_EXT_PORT (PCP_HDR_LEN + 18)
#define PCP_MAP_EXT_IP (PCP_HDR_LEN + 20)

static void pcp_put16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}

static void pcp_put32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static uint16_t pcp_get16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | p[1]);
}

static uint32_t pcp_get32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

size_t pcp_build_map(uint8_t out[60], const uint8_t client_ip16[16], const uint8_t nonce[12],
                     uint8_t proto, uint16_t int_port, uint16_t sugg_port, uint32_t lifetime)
{
    out[0] = PCP_VERSION;
    out[1] = PCP_OPCODE_MAP;      /* R clear = request */
    out[2] = 0;
    out[3] = 0;                    /* 16 reserved bits */
    pcp_put32(out + 4, lifetime);
    memcpy(out + 8, client_ip16, 16);
    memcpy(out + PCP_MAP_NONCE, nonce, 12);
    out[PCP_MAP_PROTO] = proto;
    out[PCP_MAP_PROTO + 1] = 0;
    out[PCP_MAP_PROTO + 2] = 0;
    out[PCP_MAP_PROTO + 3] = 0;    /* 24 reserved bits */
    pcp_put16(out + PCP_MAP_INT_PORT, int_port);
    pcp_put16(out + PCP_MAP_EXT_PORT, sugg_port);
    memset(out + PCP_MAP_EXT_IP, 0, 16); /* suggested external IP: no preference */
    return PCP_MAP_LEN;
}

int pcp_parse_map(const uint8_t *b, size_t n, const uint8_t nonce[12], uint8_t proto,
                  uint16_t int_port, ntx_pcp_map_resp *r)
{
    if (!b || !r || n < 1) return -1;

    /* A NAT-PMP server answers a PCP request with version 0 and the 16-bit
     * result code 1 (RFC 6886 §3.5, RFC 6887 App. A: first octet 0 is NAT-PMP).
     * That is the fallback signal and it is legal at 12 B, so test it before
     * the PCP length rules — otherwise it would just look like garbage. The
     * NAT-PMP UNSUPP_VERSION figure carries OP 0, so the response top bit is
     * deliberately not required here. */
    if (b[0] == 0)
        return (n >= 4 && pcp_get16(b + 2) == PCP_RESULT_UNSUPP_VERSION) ? 1 : -1;

    if (b[0] != PCP_VERSION) return -1;
    if (n < PCP_MAP_LEN || n > PCP_MAX_LEN || (n & 3) != 0) return -1;
    if (b[1] != (0x80 | PCP_OPCODE_MAP)) return -1;  /* R set, opcode MAP */

    uint8_t result = b[3];
    if (result == PCP_RESULT_UNSUPP_VERSION) return 1;
    if (result != PCP_RESULT_SUCCESS) return -1;     /* only SUCCESS grants a mapping */

    if (memcmp(b + PCP_MAP_NONCE, nonce, 12) != 0) return -2;
    if (b[PCP_MAP_PROTO] != proto) return -2;
    if (pcp_get16(b + PCP_MAP_INT_PORT) != int_port) return -2;

    r->result = result;
    r->lifetime = pcp_get32(b + 4);
    r->epoch = pcp_get32(b + 8);
    r->ext_port = pcp_get16(b + PCP_MAP_EXT_PORT);
    memcpy(r->ext_ip16, b + PCP_MAP_EXT_IP, 16);
    return 0;
}

size_t natpmp_build_addr(uint8_t out[2]) {
    out[0] = 0; /* version 0 */
    out[1] = 0; /* OP 0: Determine the External Address */
    return 2;
}

size_t natpmp_build_map(uint8_t out[12], uint8_t op, uint16_t int_port,
                        uint16_t sugg_port, uint32_t lifetime)
{
    out[0] = 0; /* version 0 */
    out[1] = op;
    out[2] = 0;
    out[3] = 0; /* reserved */
    pcp_put16(out + 4, int_port);
    pcp_put16(out + 6, sugg_port);
    pcp_put32(out + 8, lifetime);
    return 12;
}

int natpmp_parse_addr(const uint8_t *b, size_t n, uint8_t ext_ip[4]) {
    /* §3.2: Vers|OP|Result(16)|SSSE(32)|External IPv4(32) = 12 B. */
    if (!b || !ext_ip || n != 12 || b[0] != 0 || b[1] != 128) return -1;
    if (pcp_get16(b + 2) != PCP_RESULT_SUCCESS) return -1;
    memcpy(ext_ip, b + 8, 4);
    return 0;
}

int natpmp_parse_map(const uint8_t *b, size_t n, uint8_t op, uint16_t int_port,
                     uint16_t *ext_port, uint32_t *lifetime)
{
    /* §3.3: Vers|OP|Result(16)|SSSE(32)|InternalPort|MappedPort|Lifetime(32) = 16 B. */
    if (!b || !ext_port || !lifetime || n != 16 || b[0] != 0 || b[1] != 128 + op)
        return -1;
    if (pcp_get16(b + 2) != PCP_RESULT_SUCCESS) return -1;
    if (pcp_get16(b + 8) != int_port) return -1;
    *ext_port = pcp_get16(b + 10);
    *lifetime = pcp_get32(b + 12);
    return 0;
}

int pcp_ip_is_cgnat_or_private(const uint8_t ip16[16]) {
    /* Documented form is the on-wire one: IPv4 arrives IPv4-mapped. */
    if (ip16[10] == 0xff && ip16[11] == 0xff) {
        const uint8_t a = ip16[12], b = ip16[13];
        if (a == 10) return 1;                                   /* 10/8 */
        if (a == 172 && (b & 0xf0) == 16) return 1;              /* 172.16/12 */
        if (a == 192 && b == 168) return 1;                      /* 192.168/16 */
        if (a == 100 && (b & 0xc0) == 64) return 1;              /* 100.64/10 CGNAT */
        return 0;
    }
    return (ip16[0] & 0xfe) == 0xfc;                             /* fc00::/7 ULA */
}
