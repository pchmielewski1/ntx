#include "../net/ntx_netx.h"
#include "ntx_session_internal.h"
#include "ntx_session_portmap.h"

/* PCP/NAT-PMP mapping driver for shares (design §8).
 * Task B5 replaces these bodies; they must reproduce today's behaviour. */

void ntx_session_portmap_want(struct ntx_session *s, int on) { (void)s; (void)on; }

void ntx_session_portmap_tick(struct ntx_session *s) { (void)s; }

void ntx_session_portmap_stop(struct ntx_session *s) { (void)s; }

ntx_pm_state ntx_session_portmap_state(const struct ntx_session *s) {
    (void)s;
    return NTX_PM_OFF;
}

uint16_t ntx_session_adv_port(const struct ntx_session *s) { return ntx_netx_port(s->netx); }
