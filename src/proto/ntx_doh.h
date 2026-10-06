#ifndef NTX_DOH_H
#define NTX_DOH_H

#include <stddef.h>
#include <stdint.h>

/* DoH A lookup via pinned TLS pool. 0=ok, -1=fail (no system DNS). */
int ntx_doh_lookup_a(const char *host, uint32_t *ip_out);

/* DoH AAAA lookup via the same pinned TLS pool. 0=ok, -1=fail (no system DNS). */
int ntx_doh_lookup_aaaa(const char *host, uint8_t out[16]);

/* Counters (verbose fail message / stats / CLI). */
extern unsigned ntx_doh_ok;
extern unsigned ntx_doh_fail;
extern unsigned ntx_doh_mitm_fail;

/* When non-zero, print per-host DoH resolve failures to stderr. Default 0. */
extern int ntx_doh_verbose;

/* Compact CLI status: tag "Q9"/"OD"/"CD"/"!" ; busy=1 while TLS/DoH in flight. */
void ntx_doh_status(char *tag_out, size_t tag_cap, int *busy_out);

/* Optional: refresh one-line UI before each blocking pool attempt (set from main). */
void ntx_doh_set_ui_kick(void (*fn)(void));

/* DNS wire helpers (usable by tests and lookup): */
size_t ntx_doh_build_query_a(uint8_t *out, size_t cap, const char *host, uint16_t id);
/* Parse response; returns number of A records written (0..max), or -1 on error.
 * ips[] are network-order IPv4. Prefer first A; also return TTL of first via *ttl_out (optional, may be NULL). */
int ntx_doh_parse_response_a(const uint8_t *msg, size_t n,
                             uint32_t *ips, int max,
                             uint32_t *ttl_out);
/* DoH AAAA wire helpers (QTYPE 28, RDATA 16 B). Same contract as the A pair. */
size_t ntx_doh_build_query_aaaa(uint8_t *out, size_t cap, const char *host, uint16_t id);
int ntx_doh_parse_response_aaaa(const uint8_t *msg, size_t n,
                                uint8_t ips[][16], int max,
                                uint32_t *ttl_out);

/* Implemented in ntx_doh.c: doh_ui_kick */
#endif
