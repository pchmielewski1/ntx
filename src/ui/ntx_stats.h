#ifndef NTX_STATS_H
#define NTX_STATS_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    char name[48];
    uint8_t h[20];
    uint32_t pct, spd_d, spd_u, eta_s;
    uint32_t done, total, partial, peers;
    uint64_t size, down, up;
    /* CLI / diagnostics (see docs/cli.md) */
    uint8_t state; /* ntx_tts_state */
    uint8_t slot;  /* JSON-API v1 §5.2: session slot 0..15 (dense array ≠ slot) */
    char phase[12];
    uint16_t trk_total, trk_pend, trk_udp_ok, trk_dead;
    uint16_t peers_all, peers_hs, peers_ok, peers_unchoked, peers_interested;
    uint16_t meta_got, meta_need;
    uint16_t verify_q;
    /* BEP52 v2 / hash-exchange */
    uint8_t meta_version;   /* 0 = v1, 2 = v2/hybrid metainfo */
    uint8_t hybrid;         /* 1 = metainfo carries v1 + v2 */
    uint8_t layers_pending; /* 1 = pure-v2 awaiting piece layers (22) */
} ntx_tts_stat;

typedef struct {
    uint32_t down_Bps, up_Bps, total_peers, conn_peers;
    int n;
    ntx_tts_stat t[16];
    uint64_t down_total, up_total, rx, tx, uptime_s;
    uint16_t port;
    int dht, n_trk, enc;
    uint16_t dht_nodes4, dht_nodes6; /* DHT RT sizes */
    uint16_t p_by_trk[16];
    /* DoH compact status for one-line CLI (dnsQ9 / dns..Q9 / dns!UC) */
    char doh[8];
    uint8_t doh_busy;
    uint16_t doh_ok, doh_fail, doh_mitm;
    /* BEP52 session hash-exchange counters (ntx_session_peer.c) */
    uint32_t hash_req_tx, hash_req_rx_ok, hash_rej;
    /* BEP29/BEP55 uTP + shared-sock demux + holepunch */
    uint8_t utp;        /* cfg: uTP transport enabled (0/1) */
    uint8_t utp_v6;     /* 1 = v6 listen bound or a v6 uTP conn exists */
    uint16_t utp_conns; /* active uTP connections */
    uint64_t demux_dht, demux_utp, demux_drop; /* shared-sock classifier (ntx_netx) */
    uint32_t punch_ok, punch_fail;             /* BEP55 dial initiated / dial refused */
} ntx_stats;

/* Implemented in ui/ntx_stats.c: ntx_stats_to_json */
int ntx_stats_to_json(const ntx_stats *st, char *out, size_t cap);
#endif
