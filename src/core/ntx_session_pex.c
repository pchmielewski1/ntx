#include "ntx_session_internal.h"
#include "../proto/ntx_pex.h"
#include "ntx_time.h"

#include <string.h>

/* BEP3 PEX — ntx_session_data_pex_tick/on_pex + ext_is_pex split out of ntx_session_data.c. */

#define NTX_PEX_INTERVAL_MS 60000ull

void ntx_session_data_on_pex(struct ntx_session *s, int pi, const uint8_t *payload, size_t plen) {
    if (pi < 0 || pi >= NTX_SESSION_MAX_PEERS) return;
    int i = s->peer_tts[pi];
    if (i < 0 || i >= s->n_tts) return;
    uint32_t aip[32], dip[32];
    uint16_t aport[32], dport[32];
    int na = 0, nd = 0;
    uint8_t a6ip[32][16], d6ip[32][16];
    uint16_t a6port[32], d6port[32];
    int na6 = 0, nd6 = 0;
    if (ntx_pex_parse_ex(payload, plen, aip, aport, &na, dip, dport, &nd, 32,
                         a6ip, a6port, &na6, d6ip, d6port, &nd6, 32) != 0) return;
    for (int k = 0; k < na; k++) {
        if (!aip[k] || !aport[k]) continue;
        ntx_addr a;
        ntx_addr_set_v4(&a, aip[k]);
        ntx_session_add_peer_from_tracker(s, i, &a, aport[k]);
    }
    for (int k = 0; k < na6; k++) {
        ntx_addr a;
        ntx_addr_set_v6(&a, a6ip[k]);
        if (ntx_addr_is_zero(&a) || !a6port[k]) continue;
        ntx_session_add_peer_from_tracker(s, i, &a, a6port[k]);
    }
}

void ntx_session_data_pex_tick(struct ntx_session *s) {
    if ((s->tick_n % 600) != 0) return; /* ~60 s */
    uint64_t now = ntx_mono_ms();
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++) {
        if (s->peer_phase[pi] != PH_OK || !s->peer_pex_id[pi]) continue;
        int ti = s->peer_tts[pi];
        if (ti < 0 || ti >= s->n_tts) continue;
        if (s->peer_pex_last_ms[pi] && now - s->peer_pex_last_ms[pi] < NTX_PEX_INTERVAL_MS)
            continue;

        uint32_t a4[NTX_PEX_TX_MSG_MAX], d4[NTX_PEX_TX_MSG_MAX];
        uint16_t ap4[NTX_PEX_TX_MSG_MAX], dp4[NTX_PEX_TX_MSG_MAX];
        uint8_t a6[NTX_PEX_TX_MSG_MAX][16], d6[NTX_PEX_TX_MSG_MAX][16];
        uint16_t ap6[NTX_PEX_TX_MSG_MAX], dp6[NTX_PEX_TX_MSG_MAX];
        int na4 = 0, na6 = 0, nd4 = 0, nd6 = 0;
        if (ntx_pex_tx_peek(&s->pex_tx[ti], a4, ap4, &na4, a6, ap6, &na6,
                            d4, dp4, &nd4, d6, dp6, &nd6,
                            NTX_PEX_TX_MSG_MAX, NTX_PEX_TX_MSG_MAX) != 0)
            continue;

        const ntx_addr *ra = &s->peers[pi].addr;
        if (ntx_addr_is_v6(ra)) {
            for (int k = 0; k < na6; k++) {
                if (ap6[k] == s->peers[pi].port && memcmp(a6[k], ra->u.v6, 16) == 0) {
                    memmove(&a6[k], &a6[k + 1], (size_t)(na6 - 1 - k) * 16);
                    memmove(&ap6[k], &ap6[k + 1], (size_t)(na6 - 1 - k) * sizeof ap6[0]);
                    na6--;
                    k--;
                }
            }
        } else {
            for (int k = 0; k < na4; k++) {
                if (a4[k] == ra->u.v4 && ap4[k] == s->peers[pi].port) {
                    memmove(&a4[k], &a4[k + 1], (size_t)(na4 - 1 - k) * sizeof a4[0]);
                    memmove(&ap4[k], &ap4[k + 1], (size_t)(na4 - 1 - k) * sizeof ap4[0]);
                    na4--;
                    k--;
                }
            }
        }
        if (na4 == 0 && na6 == 0 && nd4 == 0 && nd6 == 0) continue;

        uint8_t pex[2048];
        size_t pn = 0;
        if (ntx_pex_build_msg(pex, sizeof pex, &pn, a4, ap4, na4, a6, ap6, na6,
                              d4, dp4, nd4, d6, dp6, nd6) != 0)
            continue;
        uint8_t wire[2200];
        size_t wn = ntx_ext_msg_build(wire, sizeof wire, s->peer_pex_id[pi], pex, pn);
        if (!wn) continue;
        if (ntx_session_peer_send_raw(s, pi, wire, wn) == 0) {
            ntx_pex_tx_commit(&s->pex_tx[ti], na4, na6, nd4, nd6);
            s->peer_pex_last_ms[pi] = now;
        }
    }
}

int ext_is_pex(struct ntx_session *s, int pi, int ext_id) {
    (void)s;
    (void)pi;
    return ext_id == (int)NTX_EXT_LOCAL_PEX;
}
