#include "ntx_utp.h"

#include <stddef.h>
#include <stdint.h>

/* uTP v1 (BEP29) 20-byte header pack/unpack, SACK bitmask parse, and
 * extension-chain skip. See BEP 29.
 *
 * Wire layout (network byte order), 20 bytes:
 *   byte 0      : type (high nibble) | ver (low nibble)
 *   byte 1      : extension (0 = none, else first extension type)
 *   bytes 2-3   : connection_id (u16 BE)
 *   bytes 4-7   : timestamp_microseconds (u32 BE)
 *   bytes 8-11  : timestamp_difference_microseconds (u32 BE)
 *   bytes 12-15 : wnd_size (u32 BE)
 *   bytes 16-17 : seq_nr (u16 BE)
 *   bytes 18-19 : ack_nr (u16 BE)
 */

static uint16_t be16(const uint8_t *p) {
    return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t be32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void put_be16(uint8_t *p, uint16_t v) {
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)(v & 0xFFu);
}

static void put_be32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v & 0xFFu);
}

int ntx_utp_hdr_parse(const uint8_t *p, size_t n, ntx_utp_hdr *o) {
    if (n < NTX_UTP_HDR_LEN) return -1;
    uint8_t b0 = p[0];
    uint8_t type = (uint8_t)(b0 >> 4);
    uint8_t ver = (uint8_t)(b0 & 0x0Fu);
    if (ver != NTX_UTP_VER) return -1;
    if (type > NTX_UTP_ST_SYN) return -1;
    o->type = type;
    o->ver = ver;
    o->extension = p[1];
    o->conn_id = be16(p + 2);
    o->ts_us = be32(p + 4);
    o->ts_diff_us = be32(p + 8);
    o->wnd_size = be32(p + 12);
    o->seq_nr = be16(p + 16);
    o->ack_nr = be16(p + 18);
    return 0;
}

int ntx_utp_hdr_write(uint8_t *p, size_t cap, const ntx_utp_hdr *h) {
    if (cap < NTX_UTP_HDR_LEN) return -1;
    if (h->type > NTX_UTP_ST_SYN) return -1;
    if (h->ver != NTX_UTP_VER) return -1;
    p[0] = (uint8_t)(((uint8_t)(h->type & 0x0Fu) << 4) | (uint8_t)(h->ver & 0x0Fu));
    p[1] = h->extension;
    put_be16(p + 2, h->conn_id);
    put_be32(p + 4, h->ts_us);
    put_be32(p + 8, h->ts_diff_us);
    put_be32(p + 12, h->wnd_size);
    put_be16(p + 16, h->seq_nr);
    put_be16(p + 18, h->ack_nr);
    return 0;
}

int ntx_utp_parse_sack(const uint8_t *mask, size_t n, uint16_t ack_nr,
                       uint16_t *out_seqs, int *n_acked, int cap) {
    if (n == 0) return -1;
    if (n % 4 != 0) return -1;
    if (n > NTX_UTP_SACK_MAX) return -1;
    /* Count set bits first so an over-cap mask fails without partial writes.
     * Within each byte the LSB is the lower sequence number (BEP29
     * reversed byte order); the first bit overall is ack_nr + 2. */
    int count = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = mask[i];
        while (b) {
            count++;
            b = (uint8_t)(b & (uint8_t)(b - 1u));
        }
    }
    if (count > cap) return -1;
    int k = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t b = mask[i];
        for (int bit = 0; bit < 8; bit++) {
            if (b & (uint8_t)(1u << bit)) {
                uint32_t seq = (uint32_t)ack_nr + 2u + (uint32_t)(i * 8u + (uint32_t)bit);
                out_seqs[k++] = (uint16_t)(seq & 0xFFFFu);
            }
        }
    }
    *n_acked = k;
    return 0;
}

int ntx_utp_ext_skip(const uint8_t *p, size_t n, int *out_first,
                     const uint8_t **out_payload) {
    if (n == 0) {
        *out_first = 0;
        *out_payload = p;
        return 0;
    }
    *out_first = (int)p[0];
    size_t off = 0;
    while (off < n) {
        if (off + 2 > n) return -1; /* truncated: cannot read type+len */
        uint8_t t = p[off];
        uint8_t len = p[off + 1];
        if (off + 2u + (size_t)len > n) return -1; /* truncated: data past end */
        if (t == 0) {
            if (len != 0) return -1; /* terminator must carry len == 0 */
            *out_payload = p + off + 2; /* just past the (0,0) terminator */
            return 0;
        }
        off += 2u + (size_t)len; /* unknown/known block: skip its data */
    }
    return -1; /* ran past the end without a (0,0) terminator */
}
