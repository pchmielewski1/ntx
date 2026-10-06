#ifndef NTX_SESSION_H
#define NTX_SESSION_H

#include <stdint.h>
#include <stddef.h>
#include "../net/ntx_netx.h"
#include "../core/ntx_config.h"
#include "../core/ntx_torrent.h"
#include "../core/ntx_peer.h"
#include "../core/ntx_store.h"
#include "../ui/ntx_stats.h"

#define NTX_SESSION_MAX_TTS 16
#define NTX_SESSION_MAX_PEERS 128
#define NTX_SESSION_MAX_TRK 32

typedef struct ntx_session ntx_session;

ntx_session *ntx_session_init(ntx_netx *netx, const ntx_config *cfg);
void ntx_session_free(ntx_session *s);
int ntx_session_add_magnet(ntx_session *s, const char *url);
int ntx_session_add_torrent_file(ntx_session *s, const char *path);
void ntx_session_remove(ntx_session *s, int i);
void ntx_session_pause(ntx_session *s, int i);
/* JSON-API v1 §6.3: state-setting pause (not a toggle). Idempotent both ways. */
#define NTX_PAUSE_OK 0
#define NTX_PAUSE_E_RANGE (-1) /* i outside 0..MAX_TTS-1 */
#define NTX_PAUSE_E_DEAD (-2)  /* slot free → err/no_slot */
#define NTX_PAUSE_E_STATE (-3) /* source state not allowed → err/not_ready */
int ntx_session_set_paused(ntx_session *s, int i, int on);
/* First reusable tts slot (k >= n_tts || DEAD), or -1 when all 16 are live. */
int ntx_session_free_slot(const ntx_session *s);
void ntx_session_snapshot(const ntx_session *s, ntx_stats *dst);
void ntx_session_stats_refresh(struct ntx_session *s, int rotate_ring);
void ntx_session_trk_pump_http(ntx_session *s, int max);
void ntx_session_trk_pump_udp(ntx_session *s);
/* Tell the trackers we are leaving (event=stopped), synchronously and best effort; bounded to a few
 * seconds in total. Call before removing a torrent / freeing the session. */
void ntx_session_trk_stop(ntx_session *s, int tts_idx);
void ntx_session_trk_stop_all(ntx_session *s);
void ntx_session_quit(ntx_session *s);

#endif
