#include <stdint.h>

#include "ntx_session_internal.h"

/* BEP 27 / strict-encryption / dial policy hooks (design §4, §7).
 * Task B1 replaces these bodies; they must reproduce today's behaviour. */

int sp_dht_allowed(const struct ntx_session *s, int ti) {
    (void)ti;
    return (s->cfg && s->cfg->dht) ? 1 : 0;
}

int sp_ext_allowed(const struct ntx_session *s, int ti, int ext_local_id) {
    (void)s; (void)ti; (void)ext_local_id;
    return 1;
}

int sp_dial_allowed(const struct ntx_session *s, int ti, uint8_t src) {
    (void)s; (void)ti; (void)src;
    return 1;
}
