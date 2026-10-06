#ifndef NTX_UTMETA_H
#define NTX_UTMETA_H

#include <stdint.h>
#include <stddef.h>

#include "ntx_bencode.h"

uint32_t ntx_ut_metadata_npieces(uint32_t total_size);
int ntx_ut_metadata_piece_write(uint8_t *buf, uint32_t total_size, uint32_t piece, const uint8_t *data, size_t dlen);
int ntx_ut_metadata_request_build(uint8_t *out, size_t *outn, uint32_t piece);
int ntx_ut_metadata_data_build(uint8_t *out, size_t *outn, uint32_t piece, uint32_t total_size, const uint8_t *data,
                               size_t dlen);
int ntx_ut_metadata_reject_build(uint8_t *out, size_t *outn, uint32_t piece);
int ntx_ut_metadata_parse(const uint8_t *payload, size_t plen, int *msg_type, uint32_t *piece, uint32_t *total_size,
                          const uint8_t **data, size_t *dlen);
int utmeta_dict_build(uint8_t *out, size_t *outn, const ntx_be *dict, size_t cap, const uint8_t *data, size_t dlen);

/* BEP9 (ut_metadata) — declarations split out of ntx_ext.h. */
#endif
