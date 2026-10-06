#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <arpa/inet.h>
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

/* Security audit: peer addresses learned from trackers / PEX / DHT / holepunch are attacker-steerable.
 * The session must not dial loopback, link-local (cloud metadata), multicast or unspecified
 * addresses unless --allow-local-peers is set. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int live_peers(const ntx_session *s) {
    int n = 0;
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (s->peers[pi].fd != -1) n++;
    return n;
}

static ntx_session *mk(ntx_netx **nout, int allow) {
    static ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.allow_local_peers = allow;
    cfg.max_peers = 50;
    ntx_netx *n = ntx_netx_init(&cfg);
    ntx_session *s = ntx_session_init(n, &cfg);
    uint8_t ih[20] = {1};
    s->n_tts = 1;
    ntx_torrent_init_meta(&s->tts[0], ih);
    *nout = n;
    return s;
}

int main(void) {
    ntx_rng_init();
    ntx_netx *n;
    ntx_session *s = mk(&n, 0);

    const char *bad4[] = {"127.0.0.1", "127.9.9.9", "169.254.169.254", "169.254.1.1", "224.0.0.251",
                          "255.255.255.255", "0.1.2.3", "240.0.0.1"};
    for (size_t i = 0; i < sizeof bad4 / sizeof bad4[0]; i++) {
        ntx_addr a;
        struct in_addr ia;
        inet_pton(AF_INET, bad4[i], &ia);
        ntx_addr_set_v4(&a, ia.s_addr);
        if (ntx_session_add_peer_dial(s, 0, &a, 6881) != 0) return fail(bad4[i]);
    }
    const char *bad6[] = {"::1", "fe80::1", "ff02::1", "::ffff:127.0.0.1", "::ffff:169.254.169.254"};
    for (size_t i = 0; i < sizeof bad6 / sizeof bad6[0]; i++) {
        ntx_addr a;
        uint8_t raw[16];
        inet_pton(AF_INET6, bad6[i], raw);
        ntx_addr_set_v6(&a, raw);
        if (ntx_session_add_peer_dial(s, 0, &a, 6881) != 0) return fail(bad6[i]);
    }
    {
        ntx_addr a;
        ntx_addr_set_v4(&a, htonl(0x7f000001));
        ntx_session_holepunch_dial(s, 0, &a, 6881);
        if (s->hp_dial_ok != 0) return fail("holepunch_to_loopback");
    }
    if (live_peers(s) != 0) return fail("slot_allocated");
    ntx_session_free(s);
    ntx_netx_free(n);

    /* the escape hatch really dials (LAN / loopback test swarms) */
    s = mk(&n, 1);
    {
        ntx_addr a;
        ntx_addr_set_v4(&a, htonl(0x7f000001));
        if (ntx_session_add_peer_dial(s, 0, &a, 6881) != 1) return fail("allow_local_peers_dial");
    }
    ntx_session_free(s);
    ntx_netx_free(n);
    printf("PASS session_peer_filter\n");
    return 0;
}
