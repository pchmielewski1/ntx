#ifndef NTX_SHARE_OUT_H
#define NTX_SHARE_OUT_H

#include <stddef.h>
#include <stdint.h>

#include "ntx_share.h"

/* Magnet builder, atomic .torrent writer and the share name checks
 * (design §5.4). Bodies: ntx_share_out.c. */

/* magnet:?xt=urn:btih=<40 hex>&xt=urn:btmh:1220<64 hex>&dn=<pct>&tr=<pct>…
 * RFC 3986 unreserved (A-Za-z0-9-._~) stay raw, every other byte is %XX with
 * uppercase hex. Empty name omits dn. 0 on success, -1 on bad args or when the
 * result does not fit in out (out is then an empty string). */
int ntx_share_magnet(char *out, size_t cap, const uint8_t ih[20], const uint8_t ih2[32],
                     const char *name, const char *const *trackers, int ntrk);

/* <dir>/<stem>-<first 8 hex of ih>.torrent. The stem is the name cut on a
 * UTF-8 character boundary so the basename fits NAME_MAX; the name inside the
 * torrent is never cut. 0 on success, -1 on bad args or when out is too small. */
int ntx_share_torrent_path(char *out, size_t cap, const char *dir, const char *name, const uint8_t ih[20]);

/* tmp in the same dir + fsync + rename, mode 0600 (the file is the access key).
 * buf must be a bencoded torrent whose raw info subtree hashes to ih — i.e.
 * SHA-1 of the buffer ntx_share_build_info produced, not a hash straight from
 * the hasher — otherwise NTX_SHARE_E_BAD_ARG and nothing is written. An existing
 * file whose raw info subtree hashes to ih is overwritten (that is how
 * --share-from keeps its link); anything else gives NTX_SHARE_E_EXISTS and
 * leaves the file untouched. */
ntx_share_err ntx_share_write_torrent(const char *path, const uint8_t *buf, size_t n, const uint8_t ih[20]);

/* valid UTF-8, no byte < 0x20, no 0x7f, no '/', non-empty. */
int ntx_share_name_ok(const char *name);

#endif
