#ifndef NTX_SESSION_PORTMAP_H
#define NTX_SESSION_PORTMAP_H

#include <stdint.h>

/* NAT-PMP/PCP port mapping for shares (design §8). Enum values are the JSON
 * "port_map" field verbatim (design §11). Bodies: ntx_session_portmap.c. */

typedef enum {
    NTX_PM_OFF = 0,
    NTX_PM_PENDING = 1,
    NTX_PM_ACTIVE = 2,
    NTX_PM_NONE = 3,
    NTX_PM_CGNAT = 4
} ntx_pm_state;

/* How long a share waits in PENDING before it announces on the listen port
 * (R11, design §5.5/§8). The retransmission schedule of a gateway that never
 * answers runs to ~64 s (NAT-PMP, RFC 6886 §3.1) or ~128 s (PCP, RFC 6887 §8.1.1)
 * before the driver gives up, and the magnet is worthless for all of it. The
 * mapping keeps running in the background: a late grant re-announces with the
 * external port. */
#define NTX_PM_SHARE_SETTLE_MS 4000u

void ntx_session_portmap_want(struct ntx_session *s, int on); /* share add/remove; honours cfg->port_map */
void ntx_session_portmap_tick(struct ntx_session *s);
void ntx_session_portmap_stop(struct ntx_session *s); /* lifetime 0, bounded, at exit */
ntx_pm_state ntx_session_portmap_state(const struct ntx_session *s);
uint16_t ntx_session_adv_port(const struct ntx_session *s); /* ext port when ACTIVE, else listen port */

#endif
