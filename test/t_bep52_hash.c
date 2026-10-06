/* BEP52: session-layer infohash selection for announce/handshake
 * and the incoming-metainfo gate (v1: sha1; v2: sha256 vs info_hash_v2).
 *
 * Self-contained TU: #includes the .c files it needs (mirrors test/t_session.c
 * fake-session harness). All expected bytes/hashes come from the fixture
 * manifests under test/vectors/bep52/ (read at runtime, never hardcoded).
 */
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

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int fails = 0;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails++; }
}

static void hard_fail(const char *name) {
    fprintf(stderr, "ERROR %s\n", name);
    exit(1);
}

/* ---- fixture helpers (read at runtime; no hardcoded hashes) ---- */

static int read_file(const char *path, uint8_t **out, size_t *outn) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *b = malloc((size_t)sz);
    if (!b) { fclose(f); return -1; }
    size_t rd = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(b); return -1; }
    *out = b;
    *outn = rd;
    return 0;
}

static int tb_hexval(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t cap) {
    size_t nhex = strlen(hex);
    if (nhex % 2) return -1;
    size_t nb = nhex / 2;
    if (nb > cap) return -1;
    for (size_t i = 0; i < nb; i++) {
        int hi = tb_hexval(hex[2 * i]);
        int lo = tb_hexval(hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

/* value on a line that starts with "key:" (trimmed of leading whitespace) */
static const char *manifest_val(const char *buf, size_t n, const char *key) {
    size_t klen = strlen(key);
    for (size_t i = 0; i + klen <= n; i++) {
        if (i > 0 && buf[i - 1] != '\n') continue;
        if (memcmp(buf + i, key, klen) != 0) continue;
        if (buf[i + klen] != ':') continue;
        const char *v = (const char *)(buf + i + klen + 1);
        while ((size_t)(v - buf) < n && (*v == ' ' || *v == '\t')) v++;
        return v;
    }
    return NULL;
}

/* magnet URL on the line following the "magnet: <fixture> <kind>" marker */
static const char *manifest_magnet_url(const char *buf, size_t n, const char *fixture,
                                       const char *kind) {
    char pat[128];
    snprintf(pat, sizeof pat, "magnet: %s %s", fixture, kind);
    size_t plen = strlen(pat);
    for (size_t i = 0; i + plen <= n; i++) {
        if (i > 0 && buf[i - 1] != '\n') continue;
        if (memcmp(buf + i, pat, plen) != 0) continue;
        size_t j = i + plen;
        while (j < n && buf[j] != '\n') j++;
        j++;
        const char *v = (const char *)(buf + j);
        while ((size_t)(v - buf) < n && (*v == ' ' || *v == '\t')) v++;
        return v;
    }
    return NULL;
}

static void copy_line(const char *s, char *dst, size_t cap) {
    size_t i = 0;
    while (s[i] && s[i] != '\n' && i + 1 < cap) {
        dst[i] = s[i];
        i++;
    }
    dst[i] = 0;
}

/* ---- fake-session harness (mirrors t_session.c) ---- */

static ntx_session *mk(ntx_netx **n, const ntx_config *cfg) {
    *n = ntx_netx_init(cfg);
    if (!*n) hard_fail("netx_init");
    ntx_session *s = ntx_session_init(*n, cfg);
    if (!s) hard_fail("session_init");
    return s;
}

static void drop(ntx_session *s, ntx_netx *n) {
    ntx_session_free(s);
    ntx_netx_free(n);
}

int main(void) {
    /* load fixtures */
    uint8_t *m1 = 0, *m2 = 0;
    size_t n1 = 0, n2 = 0;
    if (read_file("test/vectors/bep52/single_16k/manifest.txt", &m1, &n1) != 0)
        hard_fail("read single_16k manifest");
    if (read_file("test/vectors/bep52/hybrid_ok/manifest.txt", &m2, &n2) != 0)
        hard_fail("read hybrid_ok manifest");

    char ih_full_hex[80], ih_trunc_hex[48], ih_sha1_hex[48];
    const char *v;
    v = manifest_val((const char *)m1, n1, "ih_full");
    if (!v) hard_fail("single ih_full");
    copy_line(v, ih_full_hex, sizeof ih_full_hex);
    v = manifest_val((const char *)m1, n1, "ih_trunc");
    if (!v) hard_fail("single ih_trunc");
    copy_line(v, ih_trunc_hex, sizeof ih_trunc_hex);
    v = manifest_val((const char *)m2, n2, "ih_sha1");
    if (!v) hard_fail("hybrid ih_sha1");
    copy_line(v, ih_sha1_hex, sizeof ih_sha1_hex);
    v = manifest_val((const char *)m2, n2, "ih_trunc");
    if (!v) hard_fail("hybrid ih_trunc");
    char hybrid_trunc_hex[48];
    copy_line(v, hybrid_trunc_hex, sizeof hybrid_trunc_hex);
    v = manifest_val((const char *)m2, n2, "ih_full");
    if (!v) hard_fail("hybrid ih_full");
    char hybrid_full_hex[128];
    copy_line(v, hybrid_full_hex, sizeof hybrid_full_hex);

    uint8_t ih_full[32], ih_trunc[20], ih_sha1[20], hybrid_full[32], hybrid_trunc[20];
    if (hex_to_bytes(ih_full_hex, ih_full, 32) != 0) hard_fail("decode ih_full");
    if (hex_to_bytes(ih_trunc_hex, ih_trunc, 20) != 0) hard_fail("decode ih_trunc");
    if (hex_to_bytes(ih_sha1_hex, ih_sha1, 20) != 0) hard_fail("decode ih_sha1");
    if (hex_to_bytes(hybrid_full_hex, hybrid_full, 32) != 0) hard_fail("decode hybrid ih_full");
    if (hex_to_bytes(hybrid_trunc_hex, hybrid_trunc, 20) != 0) hard_fail("decode hybrid ih_trunc");

    char magnet_btmh[512], magnet_dual[512];
    v = manifest_magnet_url((const char *)m1, n1, "single_16k", "btmh_only");
    if (!v) hard_fail("single btmh magnet");
    copy_line(v, magnet_btmh, sizeof magnet_btmh);
    v = manifest_magnet_url((const char *)m2, n2, "hybrid_ok", "dual");
    if (!v) hard_fail("hybrid dual magnet");
    copy_line(v, magnet_dual, sizeof magnet_dual);

    ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.store_dir = "downloads";
    cfg.port_lo = 6881;
    cfg.port_hi = 6891;
    cfg.max_peers = 50;

    /* T1: add_magnet btmh_only (single_16k) -> info_hash=trunc20, v2=full, mv=2 */
    {
        ntx_netx *n;
        ntx_session *s = mk(&n, &cfg);
        if (ntx_session_add_magnet(s, magnet_btmh) != 0) hard_fail("add_magnet btmh_only");
        ntx_torrent *t = &s->tts[0];
        check(memcmp(t->info_hash, ih_trunc, 20) == 0, "magnet_btmh_info_hash_trunc");
        check(memcmp(t->info_hash_v2, ih_full, 32) == 0, "magnet_btmh_info_hash_v2_full");
        check(t->meta_version == 2, "magnet_btmh_meta_version_2");
        drop(s, n);
    }

    /* T2: add_magnet dual (hybrid_ok) -> info_hash=sha1, v2=full, mv=2 */
    {
        ntx_netx *n;
        ntx_session *s = mk(&n, &cfg);
        if (ntx_session_add_magnet(s, magnet_dual) != 0) hard_fail("add_magnet dual");
        ntx_torrent *t = &s->tts[0];
        check(memcmp(t->info_hash, ih_sha1, 20) == 0, "magnet_dual_info_hash_sha1");
        check(memcmp(t->info_hash_v2, hybrid_full, 32) == 0, "magnet_dual_info_hash_v2_full");
        check(t->meta_version == 2, "magnet_dual_meta_version_2");
        drop(s, n);
    }

    /* T3: add_magnet btih-only -> info_hash=those 20 bytes, mv=0, v2 all zero */
    {
        char btih_url[128];
        snprintf(btih_url, sizeof btih_url, "magnet:?xt=urn:btih:%s", ih_trunc_hex);
        ntx_netx *n;
        ntx_session *s = mk(&n, &cfg);
        if (ntx_session_add_magnet(s, btih_url) != 0) hard_fail("add_magnet btih_only");
        ntx_torrent *t = &s->tts[0];
        check(memcmp(t->info_hash, ih_trunc, 20) == 0, "magnet_btih_info_hash");
        check(t->meta_version == 0, "magnet_btih_meta_version_0");
        int v2zero = 1;
        for (int b = 0; b < 32; b++) if (t->info_hash_v2[b]) { v2zero = 0; break; }
        check(v2zero, "magnet_btih_info_hash_v2_zero");
        drop(s, n);
    }

    /* T4: add_torrent_file (single_16k/meta.torrent) -> info_hash=trunc20, v2=full, mv=2.
     * Hash selection happens at init_meta (before the set_metainfo dispatch gate), so
     * read slot 0 directly. Do NOT assert np/state: the v2 metainfo dispatch may
     * still reject, leaving n_tts unincremented. */
    {
        ntx_netx *n;
        ntx_session *s = mk(&n, &cfg);
        (void)ntx_session_add_torrent_file(s, "test/vectors/bep52/single_16k/meta.torrent");
        ntx_torrent *t = &s->tts[0];
        check(memcmp(t->info_hash, ih_trunc, 20) == 0, "file_info_hash_trunc");
        check(memcmp(t->info_hash_v2, ih_full, 32) == 0, "file_info_hash_v2_full");
        check(t->meta_version == 2, "file_meta_version_2");
        drop(s, n);
    }

    /* T4b: add_torrent_file (hybrid_ok/meta.torrent) -> HYBRID: info_hash = v1 SHA-1
     * (join the v1 swarm), info_hash_v2 = SHA-256(info), meta_version = 2.
     * BEP52: a hybrid torrent MUST announce/handshake with the v1 SHA-1 infohash,
     * NOT trunc20(SHA-256). Read slot 0 directly (hash selection at init_meta, before
     * the set_metainfo dispatch gate); do not assert np/state. */
    {
        ntx_netx *n;
        ntx_session *s = mk(&n, &cfg);
        (void)ntx_session_add_torrent_file(s, "test/vectors/bep52/hybrid_ok/meta.torrent");
        ntx_torrent *t = &s->tts[0];
        check(memcmp(t->info_hash, ih_sha1, 20) == 0, "file_hybrid_info_hash_sha1");
        check(memcmp(t->info_hash, hybrid_trunc, 20) != 0, "file_hybrid_info_hash_not_trunc");
        check(memcmp(t->info_hash_v2, hybrid_full, 32) == 0, "file_hybrid_info_hash_v2_full");
        check(t->meta_version == 2, "file_hybrid_meta_version_2");
        drop(s, n);
    }

    /* T5: meta_hash_gate unit tests (static in ntx_session_meta.c) */
    {
        uint8_t buf[64];
        for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(i * 7);
        uint8_t h32[32];
        ntx_sha256(buf, sizeof buf, h32);
        ntx_torrent t;
        memset(&t, 0, sizeof t);
        t.meta_version = 2;
        memcpy(t.info_hash_v2, h32, 32);
        check(meta_hash_gate(&t, buf, sizeof buf) == 0, "gate_v2_ok");
        uint8_t bad[64];
        memcpy(bad, buf, sizeof buf);
        bad[10] ^= 0x01;
        check(meta_hash_gate(&t, bad, sizeof bad) == -1, "gate_v2_flip");
    }
    {
        uint8_t buf[64];
        for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(i ^ 0x5a);
        uint8_t h20[20];
        ntx_sha1(buf, sizeof buf, h20);
        ntx_torrent t;
        memset(&t, 0, sizeof t);
        t.meta_version = 0;
        memcpy(t.info_hash, h20, 20);
        check(meta_hash_gate(&t, buf, sizeof buf) == 0, "gate_v1_ok");
        uint8_t bad[64];
        memcpy(bad, buf, sizeof bad);
        bad[3] ^= 0xff;
        check(meta_hash_gate(&t, bad, sizeof bad) == -1, "gate_v1_wrong");
    }
    /* v2 flag but zeroed info_hash_v2 -> falls back to the sha1 path */
    {
        uint8_t buf[64];
        for (int i = 0; i < 64; i++) buf[i] = (uint8_t)(i + 1);
        uint8_t h20[20];
        ntx_sha1(buf, sizeof buf, h20);
        ntx_torrent t;
        memset(&t, 0, sizeof t);
        t.meta_version = 2; /* v2 flag set */
        /* info_hash_v2 stays all zero -> gate must use the sha1 path */
        memcpy(t.info_hash, h20, 20);
        check(meta_hash_gate(&t, buf, sizeof buf) == 0, "gate_v2_zeroed_fallback_sha1");
        uint8_t bad[64];
        memcpy(bad, buf, sizeof bad);
        bad[0] ^= 0x01;
        check(meta_hash_gate(&t, bad, sizeof bad) == -1, "gate_v2_zeroed_fallback_sha1_wrong");
    }

    free(m1);
    free(m2);
    return fails;
}
