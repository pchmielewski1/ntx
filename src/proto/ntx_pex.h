#ifndef NTX_PEX_H
#define NTX_PEX_H

#include <stddef.h>
#include <stdint.h>

#define NTX_EXT_NAME_UT_PEX "ut_pex"
#define NTX_EXT_LOCAL_PEX 2

/* BEP11 ut_pex payload parse — extracts compact peers from added/dropped keys. */
int ntx_pex_parse(const uint8_t *payload, size_t plen, uint32_t *added_ip, uint16_t *added_port,
                  int *n_added, uint32_t *dropped_ip, uint16_t *dropped_port, int *n_dropped, int cap);

/* BEP11 ut_pex payload parse — v4 (added/dropped, 6 B) plus optional v6
 * (added6/dropped6, 18 B = 16 B IP + 2 B port BE).
 * v4 arguments follow ntx_pex_parse (counters must be non-NULL).
 * Pass NULL for a v6 array (and its counter) to ignore that key. */
int ntx_pex_parse_ex(const uint8_t *payload, size_t plen, uint32_t *added_ip, uint16_t *added_port,
                     int *n_added, uint32_t *dropped_ip, uint16_t *dropped_port, int *n_dropped, int cap,
                     uint8_t (*added6_ip)[16], uint16_t *added6_port, int *n_added6,
                     uint8_t (*dropped6_ip)[16], uint16_t *dropped6_port, int *n_dropped6, int cap6);

/* Build ut_pex ext payload with one added peer (6 B compact). */
int ntx_pex_build_added(uint8_t *out, size_t cap, size_t *outn, uint32_t ip_net, uint16_t port);

/* Build ut_pex ext payload with one added IPv6 peer (18 B compact: 16 B IP + port BE). */
int ntx_pex_build_added6(uint8_t *out, size_t cap, size_t *outn, const uint8_t ip6[16], uint16_t port);

/* Build ut_pex ext payload with one dropped peer (6 B compact, key "7:dropped"). */
int ntx_pex_build_dropped(uint8_t *out, size_t cap, size_t *outn, uint32_t ip_net, uint16_t port);

/* Build ut_pex ext payload with one dropped IPv6 peer (18 B compact, key "8:dropped6"). */
int ntx_pex_build_dropped6(uint8_t *out, size_t cap, size_t *outn, const uint8_t ip6[16], uint16_t port);

/* Build a full ut_pex ext payload dict from up to four compact lists.
 * Key order: added (v4), added6 (v6), dropped (v4), dropped6 (v6).
 * Only lists with count > 0 are emitted; all-zero counts -> -1.
 * Compact records: v4 = 6 B (4 B IP net order + 2 B port BE), v6 = 18 B. */
int ntx_pex_build_msg(uint8_t *out, size_t cap, size_t *outn,
                      const uint32_t *a4, const uint16_t *ap4, int na4,
                      const uint8_t (*a6)[16], const uint16_t *ap6, int na6,
                      const uint32_t *d4, const uint16_t *dp4, int nd4,
                      const uint8_t (*d6)[16], const uint16_t *dp6, int nd6);

#endif
