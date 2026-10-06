#include "ntx_torrent.h"
#include "../proto/ntx_bencode.h"
#include "../crypto/ntx_sha1.h"
#include "../crypto/ntx_sha256.h"

#include <string.h>

/* BEP52: metainfo version + infohash dispatch helpers.
 * The info dict is hashed as the bencoded substring found in the metainfo
 * (never a decode->encode roundtrip; the parser validates key order and
 * leading zeros, so the substring is canonical). */

int ntx_torrent_metainfo_version(const uint8_t *info, size_t n) {
    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(info, n, &be, &consumed, 32, (size_t)(1u << 24)) != 0) return -1;
    if (be.t != NTX_BE_DICT) {
        ntx_be_free(&be);
        return -1;
    }
    int mv = 0;
    const ntx_be *mvbe = ntx_be_dict_get(&be, "meta version");
    if (mvbe) {
        if (mvbe->t != NTX_BE_INT) {
            ntx_be_free(&be);
            return -1;
        }
        if (mvbe->i > 2) {
            ntx_be_free(&be);
            return -1; /* unsupported meta version */
        }
        if (mvbe->i == 2) mv = 2;
    }
    ntx_be_free(&be);
    return mv;
}

int ntx_torrent_metainfo_hash(const uint8_t *info, size_t n, uint8_t out20[20],
                              uint8_t out32[32]) {
    int mv = ntx_torrent_metainfo_version(info, n);
    if (mv < 0) return -1;
    if (mv == 2) {
        uint8_t h32[32];
        ntx_sha256(info, n, h32);
        memcpy(out20, h32, 20);
        memcpy(out32, h32, 32);
    } else {
        ntx_sha1(info, n, out20);
        memset(out32, 0, 32);
    }
    return mv;
}
