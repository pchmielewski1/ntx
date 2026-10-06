#include "ntx_utmeta.h"
#include "ntx_ext.h"
#include "ntx_bencode.h"

#include <string.h>

/* BEP9 (ut_metadata) — split out of ntx_ext.c. */

int utmeta_dict_build(uint8_t *out, size_t *outn, const ntx_be *dict, size_t cap, const uint8_t *data,
                      size_t dlen) {
    size_t written = 0;
    int rc = ntx_be_encode(dict, out, cap, &written);
    if (rc != 0) return -1;
    if (out && dlen && data) memcpy(out + written, data, dlen);
    if (outn) *outn = written + dlen;
    return 0;
}

int ntx_ut_metadata_request_build(uint8_t *out, size_t *outn, uint32_t piece) {
    be_dict d;
    if (be_dict_init(&d, 2) != 0) return -1;
    ntx_be k1 = {0};
    k1.t = NTX_BE_STR;
    k1.sp = (uint8_t *)"msg_type";
    k1.sn = 8;
    ntx_be v1 = {0};
    v1.t = NTX_BE_INT;
    v1.i = NTX_UT_METADATA_REQUEST;
    ntx_be k2 = {0};
    k2.t = NTX_BE_STR;
    k2.sp = (uint8_t *)"piece";
    k2.sn = 5;
    ntx_be v2 = {0};
    v2.t = NTX_BE_INT;
    v2.i = (int64_t)piece;
    if (be_dict_add(&d, k1, v1) != 0 || be_dict_add(&d, k2, v2) != 0) {
        be_dict_free(&d);
        return -1;
    }
    ntx_be dict = {0};
    dict.t = NTX_BE_DICT;
    dict.nd = d.n;
    dict.k = d.kp;
    dict.v = d.vp;
    int rc = utmeta_dict_build(out, outn, &dict, 64, 0, 0);
    be_dict_free(&d);
    return rc;
}

int ntx_ut_metadata_data_build(uint8_t *out, size_t *outn, uint32_t piece, uint32_t total_size, const uint8_t *data,
                               size_t dlen) {
    be_dict d;
    if (be_dict_init(&d, 3) != 0) return -1;
    ntx_be k1 = {0};
    k1.t = NTX_BE_STR;
    k1.sp = (uint8_t *)"msg_type";
    k1.sn = 8;
    ntx_be v1 = {0};
    v1.t = NTX_BE_INT;
    v1.i = NTX_UT_METADATA_DATA;
    ntx_be k2 = {0};
    k2.t = NTX_BE_STR;
    k2.sp = (uint8_t *)"piece";
    k2.sn = 5;
    ntx_be v2 = {0};
    v2.t = NTX_BE_INT;
    v2.i = (int64_t)piece;
    ntx_be k3 = {0};
    k3.t = NTX_BE_STR;
    k3.sp = (uint8_t *)"total_size";
    k3.sn = 10;
    ntx_be v3 = {0};
    v3.t = NTX_BE_INT;
    v3.i = (int64_t)total_size;
    if (be_dict_add(&d, k1, v1) != 0 || be_dict_add(&d, k2, v2) != 0 || be_dict_add(&d, k3, v3) != 0) {
        be_dict_free(&d);
        return -1;
    }
    ntx_be dict = {0};
    dict.t = NTX_BE_DICT;
    dict.nd = d.n;
    dict.k = d.kp;
    dict.v = d.vp;
    int rc = utmeta_dict_build(out, outn, &dict, 256, data, dlen);
    be_dict_free(&d);
    return rc;
}

int ntx_ut_metadata_reject_build(uint8_t *out, size_t *outn, uint32_t piece) {
    be_dict d;
    if (be_dict_init(&d, 2) != 0) return -1;
    ntx_be k1 = {0};
    k1.t = NTX_BE_STR;
    k1.sp = (uint8_t *)"msg_type";
    k1.sn = 8;
    ntx_be v1 = {0};
    v1.t = NTX_BE_INT;
    v1.i = NTX_UT_METADATA_REJECT;
    ntx_be k2 = {0};
    k2.t = NTX_BE_STR;
    k2.sp = (uint8_t *)"piece";
    k2.sn = 5;
    ntx_be v2 = {0};
    v2.t = NTX_BE_INT;
    v2.i = (int64_t)piece;
    if (be_dict_add(&d, k1, v1) != 0 || be_dict_add(&d, k2, v2) != 0) {
        be_dict_free(&d);
        return -1;
    }
    ntx_be dict = {0};
    dict.t = NTX_BE_DICT;
    dict.nd = d.n;
    dict.k = d.kp;
    dict.v = d.vp;
    int rc = utmeta_dict_build(out, outn, &dict, 64, 0, 0);
    be_dict_free(&d);
    return rc;
}

uint32_t ntx_ut_metadata_npieces(uint32_t total_size) {
    if (total_size == 0) return 0;
    return (total_size + NTX_UT_META_PIECE - 1u) / NTX_UT_META_PIECE;
}

int ntx_ut_metadata_piece_write(uint8_t *buf, uint32_t total_size, uint32_t piece, const uint8_t *data, size_t dlen) {
    if (!buf || !data || total_size == 0) return -1;
    uint32_t np = ntx_ut_metadata_npieces(total_size);
    if (piece >= np) return -1;
    uint32_t off = piece * NTX_UT_META_PIECE;
    if ((uint64_t)off + dlen > total_size) dlen = total_size - off;
    if (dlen) memcpy(buf + off, data, dlen);
    return 0;
}

int ntx_ut_metadata_parse(const uint8_t *payload, size_t plen, int *msg_type, uint32_t *piece, uint32_t *total_size,
                          const uint8_t **data, size_t *dlen) {
    if (msg_type) *msg_type = 0;
    if (piece) *piece = 0;
    if (total_size) *total_size = 0;
    if (data) *data = 0;
    if (dlen) *dlen = 0;
    if (!payload || plen < 2) return -1;

    size_t dict_end = 0;
    if (be_val_end(payload, plen, &dict_end) != 0) return -1;

    ntx_be be;
    size_t consumed = 0;
    int rc = ntx_be_parse(payload, dict_end, &be, &consumed, 16, dict_end);
    if (rc != 0 || be.t != NTX_BE_DICT) {
        ntx_be_free(&be);
        return -1;
    }
    const ntx_be *mt = ntx_be_dict_get(&be, "msg_type");
    const ntx_be *pc = ntx_be_dict_get(&be, "piece");
    if (!mt || mt->t != NTX_BE_INT || !pc || pc->t != NTX_BE_INT) {
        ntx_be_free(&be);
        return -1;
    }
    if (mt->i < 0 || mt->i > 255 || pc->i < 0 || pc->i > (int64_t)UINT32_MAX) {
        ntx_be_free(&be);
        return -1;
    }
    *msg_type = (int)mt->i;
    *piece = (uint32_t)pc->i;
    if (*msg_type == NTX_UT_METADATA_DATA) {
        const ntx_be *ts = ntx_be_dict_get(&be, "total_size");
        if (!ts || ts->t != NTX_BE_INT || ts->i < 1 || ts->i > (int64_t)NTX_UT_METADATA_MAX) {
            ntx_be_free(&be);
            return -1;
        }
        uint32_t total = (uint32_t)ts->i;
        /* BEP9: every DATA block is 16 KiB except the last, which is the remainder. */
        if (*piece >= ntx_ut_metadata_npieces(total)) {
            ntx_be_free(&be);
            return -1;
        }
        uint64_t off = (uint64_t)*piece * NTX_UT_META_PIECE;
        uint64_t want = total - off < NTX_UT_META_PIECE ? total - off : NTX_UT_META_PIECE;
        if (plen - dict_end != want) {
            ntx_be_free(&be);
            return -1;
        }
        *total_size = total;
        *data = payload + dict_end;
        *dlen = plen - dict_end;
    }
    ntx_be_free(&be);
    return 0;
}
