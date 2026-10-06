#ifndef NTX_EXT_H
#define NTX_EXT_H

#include <stddef.h>
#include <stdint.h>

enum { NTX_EXT_MSG_TYPE = 0x14 };

enum {
    NTX_UT_METADATA_REQUEST = 0,
    NTX_UT_METADATA_DATA = 1,
    NTX_UT_METADATA_REJECT = 2
};

#define NTX_EXT_NAME_UT_METADATA "ut_metadata"
#define NTX_EXT_NAME_UT_PEX "ut_pex"
#define NTX_EXT_NAME_UT_HOLEPUNCH "ut_holepunch"
#define NTX_EXT_LOCAL_METADATA 1
#define NTX_EXT_LOCAL_PEX 2
#define NTX_EXT_LOCAL_HOLEPUNCH 3
#define NTX_UT_META_PIECE 16384u
/* Largest info dict we accept (the same cap ntx_be_parse gets for it). total_size / metadata_size come
 * from the peer and size an allocation, so they are validated against this first. */
#define NTX_UT_METADATA_MAX (16u * 1024u * 1024u)
#define NTX_META_INFLIGHT 16u

size_t ntx_ext_msg_build(uint8_t *out, size_t cap, uint8_t ext_id, const uint8_t *payload, size_t plen);
int ntx_ext_msg_parse(const uint8_t *buf, size_t n, uint8_t *ext_id, const uint8_t **payload, size_t *plen);
void ntx_ext_handshake_build(uint8_t *out, size_t *outn, const char *const *names, const uint8_t *ids, int n_ext,
                             int metadata_size, uint16_t port, const char *version);
int ntx_ext_handshake_parse(const uint8_t *payload, size_t plen, uint8_t *ids, int max_ext, const char **names_out,
                             int *n_ext, int *metadata_size);

/* ntx_ut_metadata_* + utmeta_dict_build live in ntx_utmeta.h/ntx_utmeta.c; be_dict_* + be_val_end live in ntx_bencode.h/ntx_bencode.c. */
#endif
