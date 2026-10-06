#include "ntx_pex.h"
#include "ntx_bencode.h"

#include <string.h>

static int pex_compact_peers(const ntx_be *nodes, uint32_t *ips, uint16_t *ports, int cap, int *n_out) {
    if (!nodes || nodes->t != NTX_BE_STR || !nodes->sp) return 0;
    int n = 0;
    size_t rem = nodes->sn;
    const uint8_t *p = nodes->sp;
    while (rem >= 6 && n < cap) {
        memcpy(&ips[n], p, 4);
        ports[n] = (uint16_t)(((uint16_t)p[4] << 8) | p[5]);
        n++;
        p += 6;
        rem -= 6;
    }
    *n_out = n;
    return n;
}

static int pex_compact_peers6(const ntx_be *nodes, uint8_t (*ips)[16], uint16_t *ports, int cap, int *n_out) {
    if (n_out) *n_out = 0;
    if (!ips || !ports || !nodes || nodes->t != NTX_BE_STR || !nodes->sp) return 0;
    int n = 0;
    size_t rem = nodes->sn;
    const uint8_t *p = nodes->sp;
    while (rem >= 18 && n < cap) {
        memcpy(ips[n], p, 16);
        ports[n] = (uint16_t)(((uint16_t)p[16] << 8) | p[17]);
        n++;
        p += 18;
        rem -= 18;
    }
    if (n_out) *n_out = n;
    return n;
}

int ntx_pex_parse_ex(const uint8_t *payload, size_t plen, uint32_t *added_ip, uint16_t *added_port,
                     int *n_added, uint32_t *dropped_ip, uint16_t *dropped_port, int *n_dropped, int cap,
                     uint8_t (*added6_ip)[16], uint16_t *added6_port, int *n_added6,
                     uint8_t (*dropped6_ip)[16], uint16_t *dropped6_port, int *n_dropped6, int cap6) {
    ntx_be be;
    size_t consumed = 0;
    *n_added = 0;
    *n_dropped = 0;
    if (n_added6) *n_added6 = 0;
    if (n_dropped6) *n_dropped6 = 0;
    if (ntx_be_parse(payload, plen, &be, &consumed, 8, 65536) != 0 || be.t != NTX_BE_DICT) return -1;
    const ntx_be *added = ntx_be_dict_get(&be, "added");
    const ntx_be *dropped = ntx_be_dict_get(&be, "dropped");
    if (added) pex_compact_peers(added, added_ip, added_port, cap, n_added);
    if (dropped) pex_compact_peers(dropped, dropped_ip, dropped_port, cap, n_dropped);
    const ntx_be *added6 = ntx_be_dict_get(&be, "added6");
    const ntx_be *dropped6 = ntx_be_dict_get(&be, "dropped6");
    if (added6) pex_compact_peers6(added6, added6_ip, added6_port, cap6, n_added6);
    if (dropped6) pex_compact_peers6(dropped6, dropped6_ip, dropped6_port, cap6, n_dropped6);
    ntx_be_free(&be);
    return 0;
}

int ntx_pex_parse(const uint8_t *payload, size_t plen, uint32_t *added_ip, uint16_t *added_port,
                  int *n_added, uint32_t *dropped_ip, uint16_t *dropped_port, int *n_dropped, int cap) {
    return ntx_pex_parse_ex(payload, plen, added_ip, added_port, n_added,
                            dropped_ip, dropped_port, n_dropped, cap,
                            0, 0, 0, 0, 0, 0, 0);
}

int ntx_pex_build_added(uint8_t *out, size_t cap, size_t *outn, uint32_t ip_net, uint16_t port) {
    if (!out || !outn || cap < 17) return -1;
    uint8_t peer6[6];
    memcpy(peer6, &ip_net, 4);
    peer6[4] = (uint8_t)(port >> 8);
    peer6[5] = (uint8_t)port;
    out[0] = 'd';
    memcpy(out + 1, "5:added6:", 9);
    memcpy(out + 10, peer6, 6);
    out[16] = 'e';
    *outn = 17;
    return 0;
}

int ntx_pex_build_added6(uint8_t *out, size_t cap, size_t *outn, const uint8_t ip6[16], uint16_t port) {
    if (!out || !outn || !ip6 || cap < 31) return -1;
    out[0] = 'd';
    memcpy(out + 1, "6:added6", 8);
    memcpy(out + 9, "18:", 3);
    memcpy(out + 12, ip6, 16);
    out[28] = (uint8_t)(port >> 8);
    out[29] = (uint8_t)port;
    out[30] = 'e';
    *outn = 31;
    return 0;
}

int ntx_pex_build_dropped(uint8_t *out, size_t cap, size_t *outn, uint32_t ip_net, uint16_t port) {
    if (!out || !outn || cap < 19) return -1;
    uint8_t peer6[6];
    memcpy(peer6, &ip_net, 4);
    peer6[4] = (uint8_t)(port >> 8);
    peer6[5] = (uint8_t)port;
    out[0] = 'd';
    memcpy(out + 1, "7:dropped", 9);
    memcpy(out + 10, "6:", 2);
    memcpy(out + 12, peer6, 6);
    out[18] = 'e';
    *outn = 19;
    return 0;
}

int ntx_pex_build_dropped6(uint8_t *out, size_t cap, size_t *outn, const uint8_t ip6[16], uint16_t port) {
    if (!out || !outn || !ip6 || cap < 33) return -1;
    out[0] = 'd';
    memcpy(out + 1, "8:dropped6", 10);
    memcpy(out + 11, "18:", 3);
    memcpy(out + 14, ip6, 16);
    out[30] = (uint8_t)(port >> 8);
    out[31] = (uint8_t)port;
    out[32] = 'e';
    *outn = 33;
    return 0;
}

/* number of decimal digits of n (n==0 -> 1) */
static size_t pex_dec_digits(size_t n) {
    size_t d = 0;
    do { d++; n /= 10; } while (n);
    return d;
}

/* write decimal n followed by ':' at p; returns bytes written */
static size_t pex_write_len(uint8_t *p, size_t n) {
    char tmp[16];
    size_t i = 0;
    if (n == 0) {
        p[0] = '0';
        p[1] = ':';
        return 2;
    }
    while (n > 0) {
        tmp[i++] = (char)('0' + (int)(n % 10));
        n /= 10;
    }
    for (size_t k = 0; k < i; k++)
        p[k] = (uint8_t)tmp[i - 1 - k];
    p[i] = ':';
    return i + 1;
}

int ntx_pex_build_msg(uint8_t *out, size_t cap, size_t *outn,
                      const uint32_t *a4, const uint16_t *ap4, int na4,
                      const uint8_t (*a6)[16], const uint16_t *ap6, int na6,
                      const uint32_t *d4, const uint16_t *dp4, int nd4,
                      const uint8_t (*d6)[16], const uint16_t *dp6, int nd6) {
    if (!out || !outn) return -1;
    if (na4 < 0 || na6 < 0 || nd4 < 0 || nd6 < 0) return -1;
    if (na4 + na6 + nd4 + nd6 == 0) return -1;
    if (na4 > 0 && (!a4 || !ap4)) return -1;
    if (na6 > 0 && (!a6 || !ap6)) return -1;
    if (nd4 > 0 && (!d4 || !dp4)) return -1;
    if (nd6 > 0 && (!d6 || !dp6)) return -1;

    size_t need = 2; /* 'd' + 'e' */
    if (na4 > 0) need += 7 + pex_dec_digits((size_t)6 * (size_t)na4) + 1 + (size_t)6 * (size_t)na4;
    if (na6 > 0) need += 8 + pex_dec_digits((size_t)18 * (size_t)na6) + 1 + (size_t)18 * (size_t)na6;
    if (nd4 > 0) need += 9 + pex_dec_digits((size_t)6 * (size_t)nd4) + 1 + (size_t)6 * (size_t)nd4;
    if (nd6 > 0) need += 10 + pex_dec_digits((size_t)18 * (size_t)nd6) + 1 + (size_t)18 * (size_t)nd6;
    if (cap < need) return -1;

    uint8_t *p = out;
    *p++ = 'd';
    if (na4 > 0) {
        memcpy(p, "5:added", 7); p += 7;
        p += pex_write_len(p, (size_t)6 * (size_t)na4);
        for (int i = 0; i < na4; i++) {
            memcpy(p, &a4[i], 4); p += 4;
            p[0] = (uint8_t)(ap4[i] >> 8);
            p[1] = (uint8_t)ap4[i];
            p += 2;
        }
    }
    if (na6 > 0) {
        memcpy(p, "6:added6", 8); p += 8;
        p += pex_write_len(p, (size_t)18 * (size_t)na6);
        for (int i = 0; i < na6; i++) {
            memcpy(p, a6[i], 16); p += 16;
            p[0] = (uint8_t)(ap6[i] >> 8);
            p[1] = (uint8_t)ap6[i];
            p += 2;
        }
    }
    if (nd4 > 0) {
        memcpy(p, "7:dropped", 9); p += 9;
        p += pex_write_len(p, (size_t)6 * (size_t)nd4);
        for (int i = 0; i < nd4; i++) {
            memcpy(p, &d4[i], 4); p += 4;
            p[0] = (uint8_t)(dp4[i] >> 8);
            p[1] = (uint8_t)dp4[i];
            p += 2;
        }
    }
    if (nd6 > 0) {
        memcpy(p, "8:dropped6", 10); p += 10;
        p += pex_write_len(p, (size_t)18 * (size_t)nd6);
        for (int i = 0; i < nd6; i++) {
            memcpy(p, d6[i], 16); p += 16;
            p[0] = (uint8_t)(dp6[i] >> 8);
            p[1] = (uint8_t)dp6[i];
            p += 2;
        }
    }
    *p++ = 'e';
    *outn = (size_t)(p - out);
    return 0;
}
