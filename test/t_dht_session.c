#define _GNU_SOURCE
#include "../src/core/ntx_session.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_peer.c"
#include "../src/core/ntx_store.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rc4.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/crypto/ntx_dh.c"
#include "../src/proto/ntx_pe.c"
#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_holepunch.c"
#include "../src/proto/ntx_pex.c"
#include "../src/proto/ntx_http.c"
#include "../src/proto/ntx_http_url.c"
#include "../src/proto/ntx_https.c"
#include "../src/proto/ntx_https_pin.c"
#include "../src/net/ntx_tls.c"
#include "../src/net/ntx_tls_rec.c"
#include "../src/net/ntx_tls13.c"
#include "../src/crypto/ntx_hkdf.c"
#include "../src/crypto/ntx_x25519_fe.c"
#include "../src/crypto/ntx_x25519.c"
#include "../src/crypto/ntx_bignum.c"
#include "../src/crypto/ntx_p256.c"
#include "../src/crypto/ntx_rsa_pkcs1.c"
#include "../src/proto/ntx_tracker.c"
#include "../src/proto/ntx_magnet.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/core/ntx_session_stats.c"
#include "../src/core/ntx_pieceblk.c"
#include "../src/core/ntx_session_webseed.c"
#include "../src/core/ntx_session_pex.c"
#include "../src/core/ntx_session_meta.c"
#include "../src/core/ntx_session_vlog.c"
#include "../src/core/ntx_session_pe.c"
#include "../src/core/ntx_session_bt_hs.c"
#include "../src/proto/ntx_btmsg.c"
#include "../src/proto/ntx_utmeta.c"
#include "../src/proto/ntx_pe_vc.c"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static const char *MAGNET = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Test&tr=udp://tracker.example.com:6969";

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

static void cfg_base(ntx_config *cfg, const char *dir) {
    memset(cfg, 0, sizeof *cfg);
    cfg->store_dir = dir;
    cfg->port_lo = 6881;
    cfg->port_hi = 6891;
    cfg->max_peers = 50;
    cfg->dht = 1;
    cfg->allow_local_peers = 1; /* peers in these tests are loopback */
}

static void clean_dir(const char *dir) {
    char path[256];
    snprintf(path, sizeof path, "%s/ntx_dht_state", dir);
    unlink(path);
    rmdir(dir);
}

static int count_tts(const ntx_session *s, int ti) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_tts[pi] == ti) c++;
    return c;
}

static int count_peers_tts(const ntx_session *s, int ti, const ntx_addr *a) {
    int c = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peer_tts[pi] == ti && ntx_addr_eq(&s->peers[pi].addr, a)) c++;
    return c;
}

/* A: session with dht=1 — DHT starts, RT is empty, stats mirror the RT counters. */
static void test_smoke(void) {
    ntx_config cfg;
    cfg_base(&cfg, "test/.dht_sess_T27");
    if (mkdir("test/.dht_sess_T27", 0700) != 0 && errno != EEXIST)
        fail("smoke_mkdir");

    ntx_netx *n = ntx_netx_init(&cfg);
    if (!n) fail("smoke_netx");
    ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) fail("smoke_init");

    if (ntx_dht_port4() == 0) fail("smoke_port4");
    if (ntx_dht_node_count(0) != 0) fail("smoke_rt4_empty");
    if (ntx_dht_node_count(1) != 0) fail("smoke_rt6_empty");

    ntx_session_stats_refresh(s, 0);
    ntx_stats st;
    ntx_session_snapshot(s, &st);
    if (st.dht != 1) fail("smoke_st_dht");
    if (st.dht_nodes4 != 0 || st.dht_nodes6 != 0) fail("smoke_st_nodes0");

    uint8_t idA[20], idB[20];
    memset(idA, 1, sizeof idA);
    memset(idB, 2, sizeof idB);
    ntx_addr a4;
    ntx_addr_set_v4(&a4, htonl(0x7f000001));
    ntx_addr a6;
    static const uint8_t v6b[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ntx_addr_set_v6(&a6, v6b);
    if (ntx_dht_test_inject_node(idA, &a4, 7777) != 1) fail("smoke_inj4");
    if (ntx_dht_test_inject_node(idB, &a6, 7778) != 1) fail("smoke_inj6");

    ntx_session_stats_refresh(s, 0);
    ntx_session_snapshot(s, &st);
    if (st.dht_nodes4 != 1) fail("smoke_st_nodes4");
    if (st.dht_nodes6 != 1) fail("smoke_st_nodes6");

    ntx_session_free(s);
    ntx_netx_free(n);
    clean_dir("test/.dht_sess_T27");
    printf("PASS dht_session_smoke\n");
}

/* B: dht_peers_cb (static w ntx_session.c) — v4+v6 peers reach the session by hash. */
static void test_cb(void) {
    ntx_config cfg;
    cfg_base(&cfg, "test/.dht_sess_T27b");
    if (mkdir("test/.dht_sess_T27b", 0700) != 0 && errno != EEXIST)
        fail("cb_mkdir");

    ntx_netx *n = ntx_netx_init(&cfg);
    if (!n) fail("cb_netx");
    ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) fail("cb_init");

    if (ntx_session_add_magnet(s, MAGNET) != 0) fail("cb_magnet");
    if (s->n_tts != 1) fail("cb_n");

    uint8_t hash[20];
    memcpy(hash, s->tts[0].info_hash, 20);

    ntx_dht_peer peers[2];
    ntx_addr a4;
    ntx_addr_set_v4(&a4, htonl(0x7f000001));
    peers[0].addr = a4;
    peers[0].port = 5001;
    ntx_addr a6;
    static const uint8_t v6b[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    ntx_addr_set_v6(&a6, v6b);
    peers[1].addr = a6;
    peers[1].port = 5002;

    dht_peers_cb(hash, peers, 2, s);

    if (count_tts(s, 0) != 2) fail("cb_count");
    if (count_peers_tts(s, 0, &a4) != 1) fail("cb_v4");
    if (count_peers_tts(s, 0, &a6) != 1) fail("cb_v6");

    ntx_session_free(s);
    ntx_netx_free(n);
    clean_dir("test/.dht_sess_T27b");
    printf("PASS dht_session_cb_v6\n");
}

int main(void) {
    test_smoke();
    test_cb();
    return 0;
}
