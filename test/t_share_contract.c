/* Task 1 contract: the share/portmap/policy surface must exist and the stubs
 * must reproduce today's behaviour exactly (design §13, plan Task 1 Step 1).
 * Same .c set as test/t_session.c plus the seven new share sources. */
#define _GNU_SOURCE
#include "../src/core/ntx_session.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
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

/* share contract sources (Task 1 stubs) */
#include "../src/core/ntx_share.c"
#include "../src/core/ntx_share_meta.c"
#include "../src/core/ntx_share_out.c"
#include "../src/core/ntx_session_priv.c"
#include "../src/core/ntx_session_portmap.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/proto/ntx_pcp.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

int main(void) {
    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.store_dir = "downloads";
    cfg.port_lo = 6881;
    cfg.port_hi = 6891;
    cfg.max_peers = 50;
    cfg.allow_local_peers = 1;
    cfg.dht = 1;

    ntx_netx *n = ntx_netx_init(&cfg);
    if (!n) fail("netx_init");
    ntx_session *s = ntx_session_init(n, &cfg);
    if (!s) fail("session_init");

    /* Stubs keep today's behaviour: advertise the listen port, no mapping. */
    if (ntx_session_adv_port(s) != ntx_netx_port(s->netx)) fail("adv_port");
    if (ntx_session_portmap_state(s) != NTX_PM_OFF) fail("pm_state");

    /* Policy hooks are permissive while stream B has no bodies. */
    if (sp_dht_allowed(s, 0) != (cfg.dht != 0)) fail("sp_dht");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_PEX) != 1) fail("sp_ext_pex");
    if (sp_ext_allowed(s, 0, NTX_EXT_LOCAL_HOLEPUNCH) != 1) fail("sp_ext_hp");
    if (sp_dial_allowed(s, 0, NTX_PSRC_PEX) != 1) fail("sp_dial_pex");
    if (sp_dial_allowed(s, 0, NTX_PSRC_INBOUND) != 1) fail("sp_dial_in");
    if (ntx_session_share_state(s, 0) != NTX_SHARE_NONE) fail("share_none");
    if (ntx_session_share_serving(s, 0) != 1) fail("serving_none");
    if (ntx_session_share_pct(s, 0) != 0) fail("pct_none");
    {
        ntx_share_event ev;
        if (ntx_session_share_poll_event(s, &ev) != 0) fail("poll_none");
    }

    /* No trackers compiled in on a gate-less build → synchronous no_trackers. */
    ntx_share_trackers_test_set(NULL, 0);
    if (ntx_share_tracker_count() != 0) fail("trk_count");
    if (ntx_share_available() != 0) fail("available");
    ntx_share_err e = NTX_SHARE_OK;
    if (ntx_session_share_add(s, "test/t_share_contract.c", NULL, &e) != -1 ||
        e != NTX_SHARE_E_NO_TRACKERS)
        fail("add_no_trackers");

    if (strcmp(ntx_share_err_code(NTX_SHARE_E_BAD_NAME), "bad_arg") != 0) fail("code_bad_name");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_NO_TRACKERS), "no_trackers") != 0) fail("code_no_trk");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_BAD_ARG), "bad_arg") != 0) fail("code_bad_arg");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_IO), "io") != 0) fail("code_io");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_FULL), "full") != 0) fail("code_full");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_TOO_BIG), "too_big") != 0) fail("code_too_big");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_EXISTS), "exists") != 0) fail("code_exists");
    if (strcmp(ntx_share_err_code(NTX_SHARE_E_CHANGED), "changed") != 0) fail("code_changed");
    if (strcmp(ntx_share_err_code(NTX_SHARE_OK), "ok") != 0) fail("code_ok");
    if (!ntx_share_err_msg(NTX_SHARE_E_NO_TRACKERS)[0]) fail("msg");

    /* Two test trackers make the list available again; the stub still refuses. */
    ntx_share_tracker tv[2];
    memset(tv, 0, sizeof tv);
    tv[0].url = "https://trk-a.example/announce";
    tv[0].host = "trk-a.example";
    tv[0].npins = 1;
    tv[1].url = "https://trk-b.example/announce";
    tv[1].host = "trk-b.example";
    tv[1].npins = 1;
    ntx_share_trackers_test_set(tv, 2);
    if (ntx_share_tracker_count() != 2) fail("trk_count2");
    if (!ntx_share_available()) fail("available2");
    if (strcmp(ntx_share_tracker_get(1)->host, "trk-b.example") != 0) fail("trk_get");
    if (ntx_share_tracker_get(2) != NULL) fail("trk_get_oob");
    e = NTX_SHARE_OK;
    if (ntx_session_share_add(s, "test/t_share_contract.c", NULL, &e) != -1 ||
        e != NTX_SHARE_E_BAD_ARG)
        fail("add_bad_arg");
    ntx_share_trackers_test_set(NULL, -1); /* built-in list restored */

    /* stats_refresh must publish the stub values (ntx_pm_state / no ext port). */
    ntx_session_add_magnet(s, "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=T");
    ntx_session_stats_refresh(s, 0);
    ntx_stats st;
    ntx_session_snapshot(s, &st);
    if (st.port_map != 0 || st.ext_port != 0) fail("stats_pm");
    if (st.n != 1) fail("stats_n");
    if (st.t[0].share != 0 || st.t[0].priv != 0 || st.t[0].enc_strict != 0 ||
        st.t[0].trk_pin_fail != 0 || st.t[0].in_ok != 0)
        fail("stats_tts_fields");
    if (strcmp(st.t[0].phase, "hash") == 0) fail("phase_not_hash_without_share");

    ntx_session_share_tick(s);
    ntx_session_portmap_tick(s);
    ntx_session_portmap_want(s, 1);
    if (ntx_session_portmap_state(s) != NTX_PM_OFF) fail("pm_want_off");
    ntx_session_portmap_stop(s);
    ntx_session_share_free(s);

    ntx_session_free(s);
    ntx_netx_free(n);

    /* Static contract: the fields every stream reads must exist with these types. */
    {
        ntx_torrent t;
        memset(&t, 0, sizeof t);
        t.priv = 1;
        if (t.priv != 1) fail("t_priv");
        ntx_config c;
        memset(&c, 0, sizeof c);
        c.port_map = -1;
        if (c.port_map != -1) fail("c_port_map");
        ntx_tts_stat ts;
        memset(&ts, 0, sizeof ts);
        ts.priv = 1; ts.share = 2; ts.enc_strict = 1; ts.trk_pin_fail = 3; ts.in_ok = 4;
        if (ts.share != 2 || ts.in_ok != 4) fail("tts_stat");
    }
    if (NTX_SHARE_MIN_TRACKERS != 2) fail("min_trackers");
    if (NTX_HTTP_E_PIN != -2) fail("e_pin");
    if (NTX_PM_PENDING != 1 || NTX_PM_ACTIVE != 2 || NTX_PM_NONE != 3 || NTX_PM_CGNAT != 4)
        fail("pm_values");

    printf("PASS share_contract\n");
    return 0;
}
