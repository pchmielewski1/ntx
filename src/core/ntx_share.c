#include "ntx_share.h"
#include "../proto/ntx_share_trackers.h"

/* --share lifecycle (design §5). Task A5 fills this file; the stubs below keep
 * the contract linkable and reproduce today's behaviour (no share slots). */

static const char *const share_codes[] = {"ok", "bad_arg", "io",     "full",       "no_trackers",
                                          "too_big", "exists", "changed", "bad_arg"};
static const char *const share_msgs[] = {
    "ok",
    "invalid share argument",
    "cannot read the file",
    "too many shared files",
    "no HTTPS share trackers are pinned in this build",
    "file too large to share",
    "this file is already shared",
    "the file changed while sharing",
    "invalid file name"};

const char *ntx_share_err_code(ntx_share_err e) {
    if ((unsigned)e >= sizeof share_codes / sizeof share_codes[0]) return "bad_arg";
    return share_codes[e];
}

const char *ntx_share_err_msg(ntx_share_err e) {
    if ((unsigned)e >= sizeof share_msgs / sizeof share_msgs[0]) return share_msgs[NTX_SHARE_E_BAD_ARG];
    return share_msgs[e];
}

int ntx_session_share_add(ntx_session *s, const char *path, const char *from_torrent, ntx_share_err *err) {
    (void)s; (void)path; (void)from_torrent;
    if (err) *err = ntx_share_available() ? NTX_SHARE_E_BAD_ARG : NTX_SHARE_E_NO_TRACKERS;
    return -1;
}

int ntx_session_share_poll_event(ntx_session *s, ntx_share_event *ev) {
    (void)s; (void)ev;
    return 0;
}

ntx_share_state ntx_session_share_state(const ntx_session *s, int ti) {
    (void)s; (void)ti;
    return NTX_SHARE_NONE;
}

uint32_t ntx_session_share_pct(const ntx_session *s, int ti) {
    (void)s; (void)ti;
    return 0;
}

int ntx_session_share_serving(const ntx_session *s, int ti) {
    (void)s; (void)ti;
    return 1;
}

void ntx_session_share_tick(struct ntx_session *s) { (void)s; }

void ntx_session_share_on_remove(struct ntx_session *s, int ti) { (void)s; (void)ti; }

void ntx_session_share_free(struct ntx_session *s) { (void)s; }
