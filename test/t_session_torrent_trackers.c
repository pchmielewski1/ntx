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

#include <netinet/in.h>

/* A .torrent file lists its trackers in "announce" / "announce-list".  They used to be ignored
 * (only magnet tr= parameters were loaded), so a plain `ntx file.torrent` announced nowhere. */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int has_tracker(const ntx_session *s, int ti, const char *url) {
    for (int j = 0; j < s->trk_n[ti]; j++)
        if (strcmp(s->trk_urls[ti][j], url) == 0) return 1;
    return 0;
}

static size_t put_str(char *o, const char *v) {
    return (size_t)sprintf(o, "%zu:%s", strlen(v), v);
}

/* top: pre-built bencoded key/value pairs (may be ""), then a one-piece info dict */
static int write_torrent(const char *path, const char *top) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    fprintf(f, "d%s4:infod6:lengthi16384e4:name1:a12:piece lengthi16384e6:pieces20:", top);
    for (int i = 0; i < 20; i++) fputc('x', f);
    fputs("ee", f);
    fclose(f);
    return 0;
}

static ntx_session *fresh(ntx_netx **n, ntx_config *cfg) {
    *n = ntx_netx_init(cfg);
    return ntx_session_init(*n, cfg);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    mkdir("test/t_tt_store", 0700);
    ntx_config cfg = {0};
    cfg.store_dir = "test/t_tt_store";
    ntx_netx *n;
    ntx_session *s = fresh(&n, &cfg);

    /* announce + announce-list (two tiers): every distinct supported URL once */
    {
        char top[1024];
        size_t o = 0;
        o += (size_t)sprintf(top + o, "8:announce");
        o += put_str(top + o, "udp://127.0.0.1:9/ann");
        o += (size_t)sprintf(top + o, "13:announce-listl");
        o += (size_t)sprintf(top + o, "l");
        o += put_str(top + o, "udp://127.0.0.1:9/ann"); /* duplicate of announce */
        o += put_str(top + o, "http://127.0.0.1:1/a");
        o += (size_t)sprintf(top + o, "e");
        o += (size_t)sprintf(top + o, "l");
        o += put_str(top + o, "udp://127.0.0.1:7/ann");
        o += put_str(top + o, "ftp://example.org/x");  /* unsupported scheme: ignored */
        o += put_str(top + o, "javascript:alert(1)");  /* garbage: ignored */
        o += (size_t)sprintf(top + o, "e");
        o += (size_t)sprintf(top + o, "e");
        top[o] = 0;
        if (write_torrent("test/t_tt_store/a.torrent", top) != 0) return fail("write_a");
        if (ntx_session_add_torrent_file(s, "test/t_tt_store/a.torrent") != 0) return fail("add_a");
        if (s->trk_n[0] != 3) {
            printf("trk_n=%d\n", s->trk_n[0]);
            return fail("torrent_trackers_count");
        }
        if (!has_tracker(s, 0, "udp://127.0.0.1:9/ann")) return fail("has_announce");
        if (!has_tracker(s, 0, "http://127.0.0.1:1/a")) return fail("has_list_http");
        if (!has_tracker(s, 0, "udp://127.0.0.1:7/ann")) return fail("has_list_tier2");
        if (has_tracker(s, 0, "ftp://example.org/x")) return fail("ftp_rejected");
        printf("PASS torrent_trackers\n");
    }
    ntx_session_free(s);
    ntx_netx_free(n);

    /* announce only */
    s = fresh(&n, &cfg);
    {
        char top[256];
        size_t o = (size_t)sprintf(top, "8:announce");
        o += put_str(top + o, "http://127.0.0.1:1/only");
        top[o] = 0;
        if (write_torrent("test/t_tt_store/b.torrent", top) != 0) return fail("write_b");
        if (ntx_session_add_torrent_file(s, "test/t_tt_store/b.torrent") != 0) return fail("add_b");
        if (s->trk_n[0] != 1 || !has_tracker(s, 0, "http://127.0.0.1:1/only")) return fail("announce_only");
        printf("PASS torrent_announce_only\n");
    }
    ntx_session_free(s);
    ntx_netx_free(n);

    /* no trackers in the file: pre-existing entries are kept, nothing is invented */
    s = fresh(&n, &cfg);
    {
        if (write_torrent("test/t_tt_store/c.torrent", "") != 0) return fail("write_c");
        if (ntx_session_add_torrent_file(s, "test/t_tt_store/c.torrent") != 0) return fail("add_c");
        if (s->trk_n[0] != 0) return fail("no_trackers");
        printf("PASS torrent_no_trackers\n");
    }
    ntx_session_free(s);
    ntx_netx_free(n);

    /* more tracker URLs than slots, one overlong URL: capped, no overflow */
    s = fresh(&n, &cfg);
    {
        static char top[NTX_SESSION_MAX_TRK * 64 + 4096];
        size_t o = (size_t)sprintf(top, "13:announce-listl");
        char u[600];
        for (int i = 0; i < NTX_SESSION_MAX_TRK + 8; i++) {
            snprintf(u, sizeof u, "udp://127.0.0.1:%d/ann", 1000 + i);
            o += (size_t)sprintf(top + o, "l");
            o += put_str(top + o, u);
            o += (size_t)sprintf(top + o, "e");
        }
        memset(u, 'a', sizeof u - 1);
        memcpy(u, "http://", 7);
        u[sizeof u - 1] = 0;
        o += (size_t)sprintf(top + o, "l");
        o += put_str(top + o, u);
        o += (size_t)sprintf(top + o, "e");
        o += (size_t)sprintf(top + o, "e");
        top[o] = 0;
        if (write_torrent("test/t_tt_store/d.torrent", top) != 0) return fail("write_d");
        if (ntx_session_add_torrent_file(s, "test/t_tt_store/d.torrent") != 0) return fail("add_d");
        if (s->trk_n[0] != NTX_SESSION_MAX_TRK) return fail("cap");
        for (int j = 0; j < s->trk_n[0]; j++)
            if (strlen(s->trk_urls[0][j]) >= 512) return fail("overlong_kept");
        printf("PASS torrent_trackers_cap\n");
    }
    ntx_session_free(s);
    ntx_netx_free(n);

    unlink("test/t_tt_store/a.torrent");
    unlink("test/t_tt_store/b.torrent");
    unlink("test/t_tt_store/c.torrent");
    unlink("test/t_tt_store/d.torrent");
    unlink("test/t_tt_store/a");
    rmdir("test/t_tt_store");
    printf("ALL PASS\n");
    return 0;
}
