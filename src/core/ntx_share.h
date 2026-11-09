#ifndef NTX_SHARE_H
#define NTX_SHARE_H

#include <stdint.h>

#include "ntx_session.h"

/* Public contract for `ntx --share` (design §5). Bodies: ntx_share.c. */

#define NTX_SHARE_MAGNET_MAX 4096
#define NTX_SHARE_PATH_MAX 1024

typedef enum {
    NTX_SHARE_NONE = 0,
    NTX_SHARE_HASHING,
    NTX_SHARE_ANNOUNCING,
    NTX_SHARE_READY,
    NTX_SHARE_FAILED
} ntx_share_state;

typedef enum {
    NTX_SHARE_OK = 0,
    NTX_SHARE_E_BAD_ARG,
    NTX_SHARE_E_IO,
    NTX_SHARE_E_FULL,
    NTX_SHARE_E_NO_TRACKERS,
    NTX_SHARE_E_TOO_BIG,
    NTX_SHARE_E_EXISTS,
    NTX_SHARE_E_CHANGED,
    NTX_SHARE_E_BAD_NAME
} ntx_share_err;

typedef struct {
    int i, ok; /* slot; 1 = ready, 0 = failed */
    ntx_share_err err;
    uint8_t ih[20], ih2[32];
    char name[512];
    char magnet[NTX_SHARE_MAGNET_MAX];
    char torrent_path[NTX_SHARE_PATH_MAX];
} ntx_share_event;

/* JSON "code" for the share event/ack (design §11); BAD_NAME maps to "bad_arg". */
const char *ntx_share_err_code(ntx_share_err e);
const char *ntx_share_err_msg(ntx_share_err e); /* one-line English text for stderr */

/* Synchronous checks (open, S_ISREG, size, name, trackers, free slot). Returns slot or -1 + *err. */
int ntx_session_share_add(ntx_session *s, const char *path, const char *from_torrent, ntx_share_err *err);
int ntx_session_share_poll_event(ntx_session *s, ntx_share_event *ev); /* 1 = one event dequeued */
ntx_share_state ntx_session_share_state(const ntx_session *s, int ti);
uint32_t ntx_session_share_pct(const ntx_session *s, int ti); /* 0..100 while HASHING */
int ntx_session_share_serving(const ntx_session *s, int ti);  /* 0 = refuse block requests */
void ntx_session_share_tick(struct ntx_session *s);           /* every session tick */
void ntx_session_share_on_remove(struct ntx_session *s, int ti);
void ntx_session_share_free(struct ntx_session *s);

#endif
