/* ── session TU block, verbatim copy of the test/t_session.c header block ── */
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

#include "../src/ui/ntx_ipc.c"
#include "../src/ui/ntx_ipc_dispatch.c"
#include "../src/ui/ntx_stats.c"

/* §3.8: the pump tick under test is the shipped one from
   ntx_main.c; NTX_NO_MAIN guards out the CLI main() so this TU keeps its
   own entry point. Production builds compile ntx_main.c without this macro. */
#define NTX_NO_MAIN
#include "../src/ntx_main.c"

#include "../src/core/ntx_share.c"
#include "../src/core/ntx_share_meta.c"
#include "../src/core/ntx_share_out.c"
#include "../src/core/ntx_session_priv.c"
#include "../src/core/ntx_session_portmap.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/proto/ntx_pcp.c"
#undef NTX_NO_MAIN

#include "util.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

static int fail(const char *m) { fprintf(stderr, "FAIL %s\n", m); return 1; }
static int ok(const char *m) { printf("PASS %s\n", m); return 0; }

/* Replace fd 0 with an anonymous file holding exactly buf[0..n) followed by EOF.
   A pipe would also work, but a pipe holds only F_GETPIPE_SZ bytes (4–8 KiB when
   the user's pipe-user-pages quota is exhausted, e.g. in containers or on busy CI
   hosts) and write() would block forever with no reader. A regular file has no
   such limit; the pump only needs poll(0)/read() semantics and EOF. */
static int feed_stdin(const void *buf, size_t n) {
    FILE *tf = tmpfile();
    if (!tf) return -1;
    if (fwrite(buf, 1, n, tf) != n || fflush(tf) != 0 || fseek(tf, 0, SEEK_SET) != 0) {
        fclose(tf);
        return -1;
    }
    int rc = dup2(fileno(tf), 0) < 0 ? -1 : 0;
    fclose(tf);
    return rc;
}

/* structural validator — same measure as ipc_json_ok in t_cli.c (independent TUs) */
static int ipc_ok_local(const char *s) {
    int depth = 0, in_str = 0, esc = 0;
    for (; *s; s++) {
        char c = *s;
        if (in_str) {
            if (esc) esc = 0;
            else if (c == '\\') esc = 1;
            else if (c == '"') in_str = 0;
            continue;
        }
        if (c == '"') in_str = 1;
        else if (c == '{' || c == '[') depth++;
        else if (c == '}' || c == ']') if (--depth < 0) return 0;
    }
    return depth == 0 && !in_str && !esc;
}

static const char *code_name(ntx_ipc_code c) { /* same strings as §8.1 */
    switch (c) {
    case NTX_IPC_OK: return "ok";
    case NTX_IPC_E_BAD_JSON: return "bad_json";
    case NTX_IPC_E_UNKNOWN_CMD: return "unknown_cmd";
    case NTX_IPC_E_BAD_I: return "bad_i";
    case NTX_IPC_E_NO_SLOT: return "no_slot";
    case NTX_IPC_E_NOT_READY: return "not_ready";
    case NTX_IPC_E_BAD_ARG: return "bad_arg";
    case NTX_IPC_E_FULL: return "full";
    case NTX_IPC_E_IO: return "io";
    default: return "internal";
    }
}

/* R8: strict UTF-8 witness for the NDJSON lines the share path emits, over the
   whole string. test_utf8_strict (test/util.h) is the independent decoder — the
   shipped one is static-inline in ntx_utf8.h, so reusing it would test it
   against itself (same reason test_utf8_ok exists in t_share_out.c). */
static int utf8_strict(const char *s, size_t *bad) {
    return test_utf8_strict(s, strlen(s), bad);
}

/* one emitted line: structurally sound JSON and strictly decodable UTF-8 */
static int r8_line(const char *tag, const char *line) {
    size_t bad = 0;
    if (!ipc_ok_local(line)) {
        printf("R8 %s: torn JSON line: %s\n", tag, line);
        return 1;
    }
    if (!utf8_strict(line, &bad)) {
        printf("R8 %s: line byte %zu (0x%02x) is not valid UTF-8: %s\n", tag, bad,
               (unsigned)(unsigned char)line[bad], line);
        return 1;
    }
    return 0;
}

/* Byte-exact stand-in for snprintf "%s" truncation (the production cuts), without
   the -Wformat-truncation complaint about the deliberately short destination. */
static void r8_cut(char *dst, size_t capsz, const char *src) {
    size_t n = strlen(src);
    if (n > capsz - 1) n = capsz - 1;
    memcpy(dst, src, n);
    dst[n] = 0;
}

static int hexb(const char *hx, unsigned char *dst, size_t cap) {
    size_t n = 0;
    for (const char *q = hx; q[0] && q[1] && n + 1 < cap; q += 2) {
        char b[3] = { q[0], q[1], 0 };
        dst[n++] = (unsigned char)strtoul(b, 0, 16);
    }
    dst[n] = 0;
    return (int)n;
}

/* mk/drop — verbatim copy of the mk/drop helpers in test/t_session.c */
static ntx_session *mk(ntx_netx **n, const ntx_config *cfg) {
    *n = ntx_netx_init(cfg);
    if (!*n) fail("netx_init");
    ntx_session *s = ntx_session_init(*n, cfg);
    if (!s) fail("session_init");
    return s;
}

static void drop(ntx_session *s, ntx_netx *n) {
    ntx_session_free(s);
    ntx_netx_free(n);
}

/* ── framer test helpers: the nested-function block hoisted to
   file scope per the controller ruling — bodies verbatim, assertions
   byte-identical; only the enclosing block references these names now. ── */
static ntx_ipc_reader ipc_t_rd;
static char ipc_t_got[8][4200];
static int ipc_t_ngot, ipc_t_nbad, ipc_t_stop_seen;
static int ipc_t_rec(void *ud, const char *line) { (void)ud; snprintf(ipc_t_got[ipc_t_ngot++ % 8], 4200, "%s", line); return 0; }
static void ipc_t_bad(void *ud) { (void)ud; ipc_t_nbad++; }
static int ipc_t_recstop(void *ud, const char *line) { (void)ud; (void)line; ipc_t_stop_seen++; return 1; }

/* R30: byte-transparent capture sink. A raw NUL inside the frame survives the
   framer (it copies every byte of the read), so the parser is the place that
   must reject it; strlen of the captured line proves the truncation. */
static size_t r30_cap_slen;
static const char *r30_cap_raw; /* into the reader's own line buffer (stable until the next feed) */
static int r30_cap_n;
static int r30_cap_cb(void *ud, const char *line) {
    (void)ud;
    const char *z = memchr(line, 0, NTX_IPC_LINE_MAX);
    r30_cap_slen = (size_t)(z - line);
    r30_cap_raw = line;
    r30_cap_n++;
    return 0;
}

/* R31: framer capture for the magnet round trip — the generated line goes through
   the SHIPPED framer, so an over-long frame surfaces as on_bad (the pre-fix
   symptom) instead of being quietly shortened by the test. */
static char r31_line[4608];
static int r31_nline, r31_nbad;
static int r31_cap_cb(void *ud, const char *line) {
    (void)ud;
    snprintf(r31_line, sizeof r31_line, "%s", line);
    r31_nline++;
    return 0;
}
static void r31_bad_cb(void *ud) { (void)ud; r31_nbad++; }

/* ── V04 (§6, open part) helpers: the announce seam, the test tracker table,
   the stdout capture and the line scanner the ordering assertions run on.
   The seam is the shipped one (src/core/ntx_session_trk.c:289 — "tests swap
   this to inject … without a TLS server"), the same hook t_share_session.c
   arms for NTX_HTTP_E_PIN; everything above it (hasher, .torrent write,
   share_tick's started/READY machine, the event queue, the emitter) is the
   production code path. ── */
static int v04_n_announce;
static int v04_http_get(const char *url, uint8_t *out, size_t cap, size_t *out_n) {
    (void)url;
    static const char body[] = "d8:intervali60ee"; /* what the forked tracker of
                                                      test/t_share_session.c answers */
    size_t n = sizeof body - 1;
    if (cap < n) return -1;
    memcpy(out, body, n);
    *out_n = n;
    v04_n_announce++;
    return 0;
}

static ntx_share_tracker v04_trk[2];
static const char *const v04_trk_url[2] = { "http://127.0.0.1:65001/announce",
                                            "http://127.0.0.1:65002/announce" };
static void v04_use_test_trackers(void) {
    for (int k = 0; k < 2; k++) {
        v04_trk[k].url = v04_trk_url[k];
        v04_trk[k].host = "127.0.0.1";
        v04_trk[k].npins = 1;
        memset(v04_trk[k].pins[0], k + 1, 32);
    }
    ntx_share_trackers_test_set(v04_trk, 2);
}

/* The B5 port-map park of t_share_session.c: §5.5 holds `started` back while
   the mapping is PENDING, so pin the ENUM to OFF and the announce goes out on
   the listen port at once. Parked AFTER share_add — that call is what asks for
   a mapping (src/core/ntx_share.c:941). */
static void v04_pm_park(ntx_session *s) {
    if (!s->pm) ntx_session_portmap_want(s, 1);
    if (!s->pm) return;
    s->pm->want = 0;
    s->pm->st = NTX_PM_OFF;
}

/* The cadence snapshot of main()'s loop body (src/ntx_main.c:573-581), the same
   three shipped calls into the shipped g_js. The status-triggered snapshot does
   NOT need this helper: ipc_on_line emits it itself (NTX_IPC_F_EMIT_STATUS),
   which is why the ack-before-stats leg below is production code, not test code. */
static void v04_emit_stats(ntx_session *s) {
    ntx_session_stats_refresh(s, 0);
    ntx_stats st;
    ntx_session_snapshot(s, &st);
    if (ntx_stats_to_json(&st, g_js, sizeof g_js) > 0) {
        puts(g_js);
        fflush(stdout);
    }
}

static int v04_cap_open(const char *path, int *save) {
    fflush(stdout);
    int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
    if (fd < 0) return -1;
    *save = dup(1);
    dup2(fd, 1);
    close(fd);
    return 0;
}
static void v04_cap_close(int save) {
    fflush(stdout);
    dup2(save, 1);
    close(save);
}

/* Drives a slot out of HASHING and on to READY exactly the way the process does:
   the shipped session tick (hasher, share_finish_from, the §5.5 announce arm) and
   the shipped HTTP pump with its jitter cleared, the same two lines
   pump_to_ready() in test/t_share_session.c runs. Nothing here pushes a state
   field — READY is reached only through a `started` the seam answered. */
static int v04_pump_ready(ntx_session *s, int ti) {
    for (int k = 0; k < 200 && ntx_session_share_state(s, ti) != NTX_SHARE_READY; k++) {
        ntx_session_tick(s);
        for (int q = 0; q < NTX_SESSION_MAX_TRK; q++) s->trk_http_due[ti][q] = 0;
        ntx_session_trk_pump_http(s, NTX_SESSION_MAX_TRK);
    }
    return ntx_session_share_state(s, ti) == NTX_SHARE_READY ? 0 : -1;
}

/* one "k:v" scalar out of test/vectors/share/<fixture>/manifest.txt — the hashes
   the ordering assertions compare against come from the fixture's own witness
   file, never from a copy typed into this test. */
static int v04_manifest_hex(const char *dir, const char *key, char *out, size_t cap) {
    char path[512], line[256];
    if ((size_t)snprintf(path, sizeof path, "%s/manifest.txt", dir) >= sizeof path) return -1;
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t kl = strlen(key);
    int found = 0;
    while (fgets(line, sizeof line, f)) {
        if (strncmp(line, key, kl) != 0) continue;
        const char *v = line + kl;
        while (*v == ' ' || *v == '\t') v++;
        size_t n = 0;
        while (n + 1 < cap && v[n] && v[n] != ' ' && v[n] != '\n' && v[n] != '\r') { out[n] = v[n]; n++; }
        out[n] = 0;
        found = n > 0;
        break;
    }
    fclose(f);
    return found ? 0 : -1;
}

/* the captured stream, split into lines for the ordering assertions */
static char v04_buf[200000];
static char *v04_ln[512];
static int v04_nln;
static int v04_load(const char *path) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    size_t n = fread(v04_buf, 1, sizeof v04_buf - 1, f);
    fclose(f);
    v04_buf[n] = 0;
    v04_nln = 0;
    for (char *p = v04_buf; *p && v04_nln < 512; ) {
        v04_ln[v04_nln++] = p;
        char *nl = strchr(p, '\n');
        if (!nl) break;
        *nl = 0;
        p = nl + 1;
    }
    return 0;
}
static int v04_first(const char *needle) {
    for (int k = 0; k < v04_nln; k++) if (strstr(v04_ln[k], needle)) return k;
    return -1;
}
static int v04_count(const char *needle) {
    int c = 0;
    for (int k = 0; k < v04_nln; k++) if (strstr(v04_ln[k], needle)) c++;
    return c;
}
/* every captured line: structurally sound JSON and strictly decodable UTF-8 */
static int v04_all_lines_ok(const char *tag) {
    for (int k = 0; k < v04_nln; k++) {
        if (!ipc_ok_local(v04_ln[k]) || !utf8_strict(v04_ln[k], NULL)) {
            printf("V04 %s: line %d torn: %s\n", tag, k, v04_ln[k]);
            return 1;
        }
    }
    return 0;
}

/* one "key":"value" pull out of a captured line — the ordering assertions read
   the event's own ih back out of it instead of trusting a hand-typed copy */
static int v04_field(const char *line, const char *key, char *out, size_t cap) {
    char pat[34];
    /* the key is matched with BOTH quotes and the colon: a bare `torrent"` would
       also hit the tail of a value that ends in ".torrent" */
    if (snprintf(pat, sizeof pat, "\"%s\":", key) >= (int)sizeof pat) return 0;
    const char *p = strstr(line, pat);
    if (!p) return 0;
    p += strlen(pat);
    if (*p != '"') return 0;
    p++;
    const char *e = strchr(p, '"');
    if (!e) return 0;
    size_t n = (size_t)(e - p);
    if (n >= cap) n = cap - 1;
    memcpy(out, p, n);
    out[n] = 0;
    return 1;
}

/* bytes of a repo file into the scratch tree, so the fixture paths stay short;
   -1 when the fixture is not next to this test (the riscv scratch root case,
   same SKIP discipline as r33's missing /dev/full) */
/* byte-identity of two files (the "the .torrent is never rewritten" leg) */
static int v04_same_bytes(const char *a, const char *b) {
    FILE *fa = fopen(a, "rb"), *fb = fopen(b, "rb");
    int same = fa && fb;
    if (same) {
        for (;;) {
            int ca = fgetc(fa), cb = fgetc(fb);
            if (ca == EOF || cb == EOF) { if (ca != cb) same = 0; break; }
            if (ca != cb) { same = 0; break; }
        }
    }
    if (fa) fclose(fa);
    if (fb) fclose(fb);
    return same;
}

static int v04_copy_file(const char *src, const char *dst) {
    FILE *in = fopen(src, "rb"), *out = fopen(dst, "wb");
    if (!in || !out) {
        if (in) fclose(in);
        if (out) fclose(out);
        return -1;
    }
    char tmp[8192];
    size_t r;
    while ((r = fread(tmp, 1, sizeof tmp, in)) > 0)
        if (fwrite(tmp, 1, r, out) != r) { fclose(in); fclose(out); return -1; }
    fclose(in);
    fclose(out);
    return 0;
}

/* R31 oracle: the RFC 3986 length a magnet field has after the generator's
   percent-encoding (unreserved raw, everything else %XX). Deliberately a second,
   independent implementation — the same role utf8_strict plays for R8 — so the
   worst-case length is CHECKED, not read back off the code under test. */
static size_t r31_pct_len(const char *s) {
    static const char UN[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
                             "0123456789-._~";
    size_t n = 0;
    for (const unsigned char *p = (const unsigned char *)s; *p; p++)
        n += memchr(UN, *p, sizeof UN - 1) ? 1 : 3;
    return n;
}

int main(void) {
    char out[512];

    /* §11.1: the documented witness vector a"b\c<TAB><LF>e
       (9 input bytes → 13 output: a \" b \\ c \t d \n e) */
    if (ntx_json_escape(out, sizeof out, "a\"b\\c\td\ne") != 13)
        return fail("esc_len");
    if (strcmp(out, "a\\\"b\\\\c\\td\\ne") != 0)
        return fail("esc_body");

    /* control byte -> \u00xx (exactly 6 chars) */
    char bell[2] = { 0x07, 0 };
    if (ntx_json_escape(out, sizeof out, bell) != 6)
        return fail("esc_ctl_len");
    if (strcmp(out, "\\u0007") != 0)
        return fail("esc_ctl_body");

    /* high bytes pass raw (§3.4: encoding is bytes) */
    char hib[3] = { (char)0xC3, (char)0xB3, 0 }; /* UTF-8 'ó' */
    if (ntx_json_escape(out, sizeof out, hib) != 2 || memcmp(out, hib, 2) != 0)
        return fail("esc_raw_high");

    /* empty string -> empty, not failure */
    if (ntx_json_escape(out, sizeof out, "") != 0 || out[0] != 0)
        return fail("esc_empty");

    /* exact fit: two control bytes needing 6 each = 12; cap 13 ok, cap 12 -> -1 */
    char two[3] = { 0x1F, 0x1F, 0 };
    if (ntx_json_escape(out, 13, two) != 12) return fail("esc_fit_exact");
    if (ntx_json_escape(out, 12, two) != -1) return fail("esc_fit_off_by_one");
    if (out[0] != 0) return fail("esc_no_torn"); /* caller sees a clean refusal */

    /* §5.2: hex40 lowercase, leading zeros kept */
    uint8_t h[20];
    memset(h, 0, sizeof h);
    h[0] = 0x01; h[19] = 0xab;
    char ih[41];
    if (ntx_hex40(ih, h) != 40) return fail("hex40_len");
    if (strcmp(ih, "01000000000000000000000000000000000000ab") != 0)
        return fail("hex40_body");

    if (ok("ipc_helpers_v1")) return 1;

    /* §7 hello — verbatim contract keys, caps catalog in fixed order.
       C3/§11: this TU links ntx_share_trackers.c, so the built-in list is usable
       and "share" is appended (the gated-off spelling is pinned in c3_caps_share). */
    char hl[512];
    int hn = ntx_ipc_hello_json(hl, sizeof hl, "seed-ratio-v1");
    if (hn <= 0) return fail("hello_len");
    if (strcmp(hl, "{\"type\":\"hello\",\"v\":1,\"protocol\":\"ntx-json\","
                   "\"max_tts\":16,\"max_peers\":128,\"build\":\"seed-ratio-v1\","
                   "\"caps\":[\"ping\",\"status\",\"hello\",\"add\",\"pause\","
                   "\"resume\",\"remove\",\"quit\",\"share\"]}") != 0)
        return fail("hello_body");
    if (ntx_ipc_hello_json(hl, 64, "x") != -1) return fail("hello_tiny_cap");
    /* hostile build id must not break the line (§11.1 escape discipline) */
    if (ntx_ipc_hello_json(hl, sizeof hl, "b\"\\u") <= 0 || !ipc_ok_local(hl))
        return fail("hello_escape");

    /* table-driven gates over the vector files (§6.4, §12) */
    {
        static const char *const FILES[] = {
            "test/vectors/ipc/cmds_ok.jsonl", "test/vectors/ipc/cmds_err.jsonl"
        };
        for (int f_i = 0; f_i < 2; f_i++) {
            FILE *f = fopen(FILES[f_i], "rb");
            if (!f) return fail("cmd_vec_open");
            char ln[8192];
            while (fgets(ln, sizeof ln, f)) {
                ln[strcspn(ln, "\r\n")] = 0;
                if (!ln[0]) continue;
                char *li = strstr(ln, "line="), *wa = strstr(ln, " want=");
                if (!li || !wa) { fclose(f); return fail("cmd_vec_fmt"); }
                wa[0] = 0;
                unsigned char raw[8192];
                hexb(li + 5, raw, sizeof raw);
                char wantv[32];
                size_t wl = strcspn(wa + 6, " "); /* want token ends at the first space */
                if (wl > 31) wl = 31;
                memcpy(wantv, wa + 6, wl);
                wantv[wl] = 0;
                ntx_ipc_req r;
                ntx_ipc_parse((const char *)raw, &r);
                if (strcmp(code_name(r.pre), wantv) != 0) {
                    fprintf(stderr, "vec=%s want=%s got=%s\n", (const char *)raw, wantv, code_name(r.pre));
                    fclose(f); return fail("cmd_vec_verdict");
                }
                /* field expectations (cmd=/i=/seq=) are asserted by hand in (c):
                   the vector file carries verdicts; the C asserts carry the tree. */
            }
            fclose(f);
        }
    }
    if (ok("ipc_vectors_cmds")) return 1;

    { /* §6.1 witness line: the documented example parses to pause/i/0/seq/7 */
        ntx_ipc_req r;
        ntx_ipc_parse("{\"cmd\":\"pause\",\"i\":0,\"seq\":7}", &r);
        if (r.pre != NTX_IPC_OK || r.cmd != NTX_CMD_PAUSE || r.i != 0 ||
            !r.has_i || r.seq != 7 || !r.has_seq) return fail("parse_witness");
        ntx_ipc_parse("{\"cmd\":\"add\",\"path\":\"a.torrent\"}", &r);
        if (r.pre != NTX_IPC_OK || r.cmd != NTX_CMD_ADD || !r.has_path ||
            strcmp(r.path, "a.torrent") != 0) return fail("parse_add_path");
        ntx_ipc_parse("{\"cmd\":\"add\",\"magnet\":\"m\"}", &r);
        if (r.pre != NTX_IPC_OK || !r.has_magnet || strcmp(r.magnet, "m") != 0)
            return fail("parse_add_magnet");
        ntx_ipc_parse("{\"cmd\":\"ping\",\"a\":[1]}", &r);   /* arrays rejected */
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("parse_array_reject");
        ntx_ipc_parse("{\"cmd\":\"ping\",\"a\":{\"b\":1}}", &r); /* objects too */
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("parse_obj_reject");
        ntx_ipc_parse("{\"cmd\":\"ping\" \"ok\":1}", &r);        /* missing comma */
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("parse_comma");
        ntx_ipc_parse("  {\"cmd\":\"ping\"}  ", &r);              /* outer ws tolerated */
        if (r.pre != NTX_IPC_OK) return fail("parse_outer_ws");
        ntx_ipc_parse("{\"cmd\":\"ping\",\"seq\":99999999999999999999}", &r);
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("parse_seq_overflow_reject");
        ntx_ipc_parse("{\"cmd\":\"pause\",\"i\":1e1}", &r);      /* exponent != number */
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("parse_num_junk");
    }
    if (ok("ipc_parse_cases")) return 1;

    { /* ── dispatcher on a live session ── */
        ntx_config cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.store_dir = "/tmp/ntx-ipc-t6";
        ntx_netx *nx;
        ntx_session *s = mk(&nx, &cfg);
        char out[2048];
        int fl;

        /* ping from §6.1: full copy of the reply */
        fl = ntx_ipc_dispatch(s, "{\"cmd\":\"ping\",\"seq\":7}", out, sizeof out);
        if (fl != 0 || strcmp(out, "{\"type\":\"ack\",\"seq\":7,\"cmd\":\"ping\",\"ok\":1}") != 0)
            return fail("d_ping_seq");
        /* ping without seq: the seq field is absent (not "seq":0!) */
        ntx_ipc_dispatch(s, "{\"cmd\":\"ping\"}", out, sizeof out);
        if (strcmp(out, "{\"type\":\"ack\",\"cmd\":\"ping\",\"ok\":1}") != 0)
            return fail("d_ping_no_seq");
        if (strstr(out, "\"seq\"")) return fail("d_seq_absent");

        /* unknown_cmd: echo token + code §8.1 */
        ntx_ipc_dispatch(s, "{\"cmd\":\"nope\",\"seq\":-3}", out, sizeof out);
        if (strcmp(out, "{\"type\":\"err\",\"seq\":-3,\"cmd\":\"nope\",\"ok\":0,\"code\":\"unknown_cmd\"}") != 0)
            return fail("d_unknown");

        /* add magnet → ack with the new i, ih, state (META=0) */
        fl = ntx_ipc_dispatch(s,
            "{\"cmd\":\"add\",\"seq\":1,\"magnet\":\"magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=Test\"}",
            out, sizeof out);
        if (fl != 0) return fail("d_add_flags");
        if (!strstr(out, "\"cmd\":\"add\"") || !strstr(out, "\"i\":0") ||
            !strstr(out, "\"state\":0") || !strstr(out, "\"ih\":\"0123456789abcdef0123456789abcdef01234567\"") ||
            !strstr(out, "\"ok\":1"))
            return fail("d_add_ack");

        /* pause per §6.1 → §8 sample: state 3 */
        ntx_ipc_dispatch(s, "{\"cmd\":\"pause\",\"i\":0,\"seq\":7}", out, sizeof out);
        if (strcmp(out, "{\"type\":\"ack\",\"seq\":7,\"cmd\":\"pause\",\"i\":0,\"ok\":1,\"state\":3}") != 0)
            return fail("d_pause_sample");
        /* idempotent repeat = OK (§6.2) */
        ntx_ipc_dispatch(s, "{\"cmd\":\"pause\",\"i\":0}", out, sizeof out);
        if (!strstr(out, "\"ok\":1")) return fail("d_pause_idem");
        /* resume → back to META (paused_from), not blindly to DL */
        ntx_ipc_dispatch(s, "{\"cmd\":\"resume\",\"i\":0}", out, sizeof out);
        if (!strstr(out, "\"ok\":1") || !strstr(out, "\"state\":0")) return fail("d_resume_meta");

        /* no_slot: free slot 5 (§8 sample with i:9 → code no_slot) */
        ntx_ipc_dispatch(s, "{\"cmd\":\"pause\",\"i\":9,\"seq\":8}", out, sizeof out);
        if (strcmp(out, "{\"type\":\"err\",\"seq\":8,\"cmd\":\"pause\",\"i\":9,\"ok\":0,\"code\":\"no_slot\"}") != 0)
            return fail("d_no_slot");

        /* bad_i: 16 is out of range — no i echo in the error (only a sensible one) */
        ntx_ipc_dispatch(s, "{\"cmd\":\"pause\",\"i\":16}", out, sizeof out);
        if (!strstr(out, "\"code\":\"bad_i\"") || strstr(out, "\"i\":16")) return fail("d_bad_i");

        /* add: both arguments → bad_arg; none → bad_arg; bad magnet → bad_arg */
        ntx_ipc_dispatch(s, "{\"cmd\":\"add\",\"magnet\":\"m\",\"path\":\"a\"}", out, sizeof out);
        if (!strstr(out, "\"code\":\"bad_arg\"")) return fail("d_add_both");
        ntx_ipc_dispatch(s, "{\"cmd\":\"add\"}", out, sizeof out);
        if (!strstr(out, "\"code\":\"bad_arg\"")) return fail("d_add_none");
        ntx_ipc_dispatch(s, "{\"cmd\":\"add\",\"magnet\":\"not-a-magnet\"}", out, sizeof out);
        if (!strstr(out, "\"code\":\"bad_arg\"")) return fail("d_add_junk");

        /* add path: an existing fixture (repo vectors) → ok */
        fl = ntx_ipc_dispatch(s,
            "{\"cmd\":\"add\",\"path\":\"test/vectors/bep52/single_16k/meta.torrent\"}",
            out, sizeof out);
        if (!strstr(out, "\"ok\":1") || !strstr(out, "\"i\":1")) return fail("d_add_path");

        /* add path: non-existent → io */
        ntx_ipc_dispatch(s, "{\"cmd\":\"add\",\"path\":\"/nonexistent/ntx-nope.torrent\"}", out, sizeof out);
        if (!strstr(out, "\"code\":\"io\"")) return fail("d_add_io");

        /* remove → ack state 5; a repeated remove → no_slot (§6.2 + §5.5) */
        ntx_ipc_dispatch(s, "{\"cmd\":\"remove\",\"i\":0}", out, sizeof out);
        if (!strstr(out, "\"ok\":1") || !strstr(out, "\"state\":5")) return fail("d_remove");
        ntx_ipc_dispatch(s, "{\"cmd\":\"remove\",\"i\":0}", out, sizeof out);
        if (!strstr(out, "\"code\":\"no_slot\"")) return fail("d_remove_again");

        /* full: 16 occupied slots → err/full (§6.4). Slot 1 is already occupied
           by the .torrent fixture, so 15 magnets fill up to 16 and the sixteenth
           add (ffff) gets full. (k<16 would be one too many with
           slot 1 already occupied; a minimal gate correction, documented here). */
        for (int k = 0; k < 15; k++) {
            char line[512];
            snprintf(line, sizeof line,
                     "{\"cmd\":\"add\",\"magnet\":\"magnet:?xt=urn:btih:%02d23456789abcdef0123456789abcdef01234567\"}",
                     k);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (!strstr(out, "\"ok\":1")) return fail("d_fill");
        }
        ntx_ipc_dispatch(s, "{\"cmd\":\"add\",\"magnet\":\"magnet:?xt=urn:btih:ffffffffffffffffffffffffffffffffffffffff\"}",
                         out, sizeof out);
        if (!strstr(out, "\"code\":\"full\"")) return fail("d_full");

        /* hardening: a huge literal i wraps past the parser guard
           (int) to an in-range value. The dispatcher must give bad_i and not
           drive slot 0. The assertion is on the real bytes of the verdict. */
        ntx_ipc_dispatch(s, "{\"cmd\":\"pause\",\"i\":4294967296,\"seq\":11}", out, sizeof out);
        if (!strstr(out, "\"code\":\"bad_i\"") || strstr(out, "\"i\":4294967296") ||
            strstr(out, "\"i\":0") || !strstr(out, "\"seq\":11"))
            return fail("d_bad_i_huge");
        ntx_ipc_dispatch(s, "{\"cmd\":\"remove\",\"i\":-1}", out, sizeof out);
        if (!strstr(out, "\"code\":\"bad_i\"")) return fail("d_bad_i_neg");

        /* status: no line of its own, EMIT_STATUS flag (§6.2) */
        fl = ntx_ipc_dispatch(s, "{\"cmd\":\"status\"}", out, sizeof out);
        if (out[0] || !(fl & NTX_IPC_F_EMIT_STATUS)) return fail("d_status_flag");

        /* hello cmd: the reply is a hello line (§6.2 — a repeat of the contract) */
        fl = ntx_ipc_dispatch(s, "{\"cmd\":\"hello\"}", out, sizeof out);
        if (strncmp(out, "{\"type\":\"hello\"", 14) != 0 || fl != 0) return fail("d_hello_cmd");

        /* quit: ack as the last line + QUIT flag; the session receives quit */
        fl = ntx_ipc_dispatch(s, "{\"cmd\":\"quit\",\"seq\":2}", out, sizeof out);
        if (strcmp(out, "{\"type\":\"ack\",\"seq\":2,\"cmd\":\"quit\",\"ok\":1}") != 0 ||
            !(fl & NTX_IPC_F_QUIT)) return fail("d_quit");

        /* formal error before mutation: bad JSON does not touch the session (§6.4 gate) */
        fl = ntx_ipc_dispatch(s, "junk", out, sizeof out);
        if (strcmp(out, "{\"type\":\"err\",\"cmd\":\"\",\"ok\":0,\"code\":\"bad_json\"}") != 0 || fl != 0)
            return fail("d_junk_gate");

        /* §6.1/§6.4: a 100-char cmd → unknown_cmd with an empty echo,
           never bad_json; the seq echo is unchanged; the echo must not cut the cmd. */
        {
            char z[101], bigc[600];
            memset(z, 'z', 100); z[100] = 0;
            snprintf(bigc, sizeof bigc, "{\"cmd\":\"%s\",\"seq\":-2}", z);
            ntx_ipc_dispatch(s, bigc, out, sizeof out);
            if (!strstr(out, "\"code\":\"unknown_cmd\"") || strstr(out, "zzzz") ||
                !strstr(out, "\"seq\":-2")) return fail("d_long_cmd");
        }

        /* §6.1: a short unknown key (fits in key[16]) with a
           string value ≥ 512 B must be SKIPPED (measured by ipc_json_str_len),
           not bad_json via -2 on sink[NTX_IPC_ARGS_MAX]. A document with a following
           recognised field after the skip must reach the ack. */
        {
            char huge[700], line[900];
            memset(huge, 'v', 600); huge[600] = 0;
            snprintf(line, sizeof line, "{\"cmd\":\"ping\",\"k\":\"%s\",\"seq\":4242}", huge);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (!strstr(out, "\"ok\":1") || !strstr(out, "\"seq\":4242"))
                return fail("d_huge_unknown_value");
            snprintf(line, sizeof line, "{\"cmd\":\"ping\",\"k\":\"%s\"}", huge);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (!strstr(out, "\"ok\":1") || !strstr(out, "\"cmd\":\"ping\""))
                return fail("d_huge_unknown_value_no_seq");
            /* the skip grammar still enforces: \q is not a valid escape */
            snprintf(line, sizeof line, "{\"cmd\":\"ping\",\"k\":\"aa\\qb\"}");
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (!strstr(out, "\"code\":\"bad_json\"")) return fail("d_bad_escape_value");
            /* long unknown key + huge value: the long-key path (≥16 B) must
               measure as well, not chop into the sink — combined robustness §6.1 */
            snprintf(line, sizeof line, "{\"cmd\":\"ping\",\"k1234567890abcdef%04d\":\"%s\"}", 7, huge);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (!strstr(out, "\"ok\":1")) return fail("d_huge_unknown_longkey_value");
        }

        drop(s, nx);
        if (ok("ipc_dispatch")) return 1;
    }

    /* ── line framer §3.3/§3.7/§3.9 ── */
    {
        ntx_ipc_sink snk = { 0, ipc_t_rec, ipc_t_bad };
        ntx_ipc_reader_init(&ipc_t_rd);
        ntx_ipc_feed(&ipc_t_rd, "{\"cmd\":\"ping\"}\r\n", 16, &snk);   /* CRLF-strip */
        if (ipc_t_ngot != 1 || strcmp(ipc_t_got[0], "{\"cmd\":\"ping\"}") != 0) return fail("fr_crlf");
        ntx_ipc_feed(&ipc_t_rd, "{\"c", 3, &snk);                       /* split across feeds */
        ntx_ipc_feed(&ipc_t_rd, "md\":\"ping\"}\n", 12, &snk);
        if (ipc_t_ngot != 2 || strcmp(ipc_t_got[1], "{\"cmd\":\"ping\"}") != 0) return fail("fr_split");
        ntx_ipc_feed(&ipc_t_rd, "\n", 1, &snk);                        /* blank line: silence */
        if (ipc_t_ngot != 2 || ipc_t_nbad != 0) return fail("fr_blank_silent");
        /* overflow: 4097 B without \n → drop up to \n, one on_bad, one err line */
        char big[4200];
        memset(big, 'x', sizeof big);
        big[4097] = '\n';
        ntx_ipc_feed(&ipc_t_rd, big, 4098, &snk);
        if (ipc_t_ngot != 2 || ipc_t_nbad != 1) return fail("fr_overflow");
        /* exactly 4096 B fits (§3.7: line ≤ 4096) */
        memset(big, 'y', sizeof big);
        big[4096] = '\n';
        ntx_ipc_feed(&ipc_t_rd, big, 4097, &snk);
        if (ipc_t_ngot != 3 || ipc_t_nbad != 1) return fail("fr_edge_4096");
        /* stop: on_line != 0 halts reading of the rest of the chunk */
        ipc_t_stop_seen = 0;
        ntx_ipc_sink snk2 = { 0, ipc_t_recstop, ipc_t_bad };
        ntx_ipc_reader_init(&ipc_t_rd);
        ntx_ipc_feed(&ipc_t_rd, "{\"cmd\":\"quit\"}\n{\"cmd\":\"ping\"}\n", 30, &snk2);
        if (ipc_t_stop_seen != 1) return fail("fr_stop");
    }
    if (ok("ipc_framer")) return 1;

    { /* §6.1: overlay robustness — a long unknown key (≥16 B,
         beyond key[16]) must be SKIPPED together with its value and not return
         bad_json; recognised keys in the same document must remain
         byte-identical (the longest recognised one is "magnet" — 6 B). */
        ntx_ipc_req r;
        ntx_ipc_parse("{\"cmd\":\"ping\",\"longunknownkey123456\":42,\"seq\":7}", &r);
        if (r.pre != NTX_IPC_OK || r.seq != 7 || !r.has_seq) return fail("parse_long_key_num");
        ntx_ipc_parse("{\"cmd\":\"ping\",\"longunknownkey123456\":\"aaaaaaaaaaaaaaaaaaaaaaaa\",\"seq\":9}", &r);
        if (r.pre != NTX_IPC_OK || r.seq != 9 || !r.has_seq) return fail("parse_long_key_str");
        ntx_ipc_parse("{\"junkkeywaytoolong1234\":1,\"cmd\":\"pause\",\"i\":3}", &r);
        if (r.pre != NTX_IPC_OK || r.cmd != NTX_CMD_PAUSE || r.i != 3 || !r.has_i)
            return fail("parse_long_key_order");
        ntx_ipc_parse("{\"cmd\":\"add\",\"junkkeywaytoolong1234\":\"x\",\"magnet\":\"m\"}", &r);
        if (r.pre != NTX_IPC_OK || !r.has_magnet || strcmp(r.magnet, "m") != 0)
            return fail("parse_long_key_magnet");
        /* long key + long numeric value at once: the pair is skipped, the document is OK */
        ntx_ipc_parse("{\"cmd\":\"hello\",\"averyveryverylongunknownkey99\":-1234567890123}", &r);
        if (r.pre != NTX_IPC_OK || r.cmd != NTX_CMD_HELLO) return fail("parse_long_key_big");
        /* the separator must work after the pair — the object closes after the skip */
        ntx_ipc_parse("{\"longunknownkey123456\":[],\"cmd\":\"ping\"}", &r);
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("parse_long_key_array_reject");
    }
    if (ok("ipc_overlay_resilience")) return 1;

    { /* §3.8: the pump caps DISPATCHED lines per tick at 64 and
         carries the surplus to the next tick — nothing dropped, order kept.
         Drives the shipped ipc_pump_tick (ntx_main.c via NTX_NO_MAIN) over a
         command stream fed on fd 0 (see feed_stdin); the reply stream is
         captured from fd 1. */
        ntx_config cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.store_dir = "/tmp/ntx-ipc-t9";
        ntx_netx *nx;
        ntx_session *s3 = mk(&nx, &cfg);
        char burst[9000];
        size_t bn = 0;
        for (int k = 0; k < 300; k++)
            bn += (size_t)snprintf(burst + bn, sizeof burst - bn, "{\"cmd\":\"ping\",\"seq\":%d}\n", k);
        if (feed_stdin(burst, bn) != 0) { drop(s3, nx); return fail("bud_stdin"); }
        int save_out = dup(1);
        fflush(stdout);
        unlink("/tmp/ntx-ipc-budget.ndjson");
        int capfd = open("/tmp/ntx-ipc-budget.ndjson", O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (capfd < 0) { dup2(save_out, 1); close(save_out); drop(s3, nx); return fail("bud_file"); }
        dup2(capfd, 1);
        close(capfd);
        ntx_ipc_reader_init(&g_rd);
        g_ipc_open = 1; g_ipc_quit = 0; g_ipc_stash_len = 0;
        int tick = 0;
        while ((g_ipc_open || g_ipc_stash_len) && tick < 40) {
            ipc_pump_tick(s3);
            if (g_ipc_tick_lines > 64) {
                fflush(stdout); dup2(save_out, 1); close(save_out);
                drop(s3, nx); return fail("bud_cap");
            }
            tick++;
        }
        fflush(stdout);
        dup2(save_out, 1);
        close(save_out);
        FILE *rf = fopen("/tmp/ntx-ipc-budget.ndjson", "rb");
        if (!rf) { drop(s3, nx); return fail("bud_read"); }
        char bl[256];
        int seen = 0;
        while (fgets(bl, sizeof bl, rf)) {
            if (!strstr(bl, "\"type\":\"ack\"")) continue;
            char *q = strstr(bl, "\"seq\":");
            if (!q) { fclose(rf); drop(s3, nx); return fail("bud_seq"); }
            if (atoi(q + 6) != seen) { fclose(rf); drop(s3, nx); return fail("bud_order"); }
            seen++;
        }
        fclose(rf);
        if (seen != 300) { drop(s3, nx); return fail("bud_total"); }
        if (tick < 5) { drop(s3, nx); return fail("bud_ticks"); } /* ceil(300/64) */
        drop(s3, nx);
        if (ok("ipc_pump_budget")) return 1;
    }

    { /* §8 + §3.8: quit dispatched from the STASH DRAIN must stop
         the pump — commands left in the pipe may not run after the quit ack.
         70 fixed-width lines of exactly 200 B: 1..64 ping, 65 quit, 66 ping,
         67 ping, 68..69 add, 70 ping. The 64th line ends at byte 64*200=12800,
         inside read chunk 12 = [12288,13312): lines 65,66 complete that chunk →
         STASHED; 67 straddles the edge (partial lives in g_rd); 68..70 remain in
         the pipe when the drain meets the quit. Pre-fix the read loop (no
         g_ipc_quit/g_ipc_open gate) fed the pipe after the drain-quit: the adds
         ran and the last line was not the quit ack. */
        ntx_config cfg;
        memset(&cfg, 0, sizeof cfg);
        cfg.store_dir = "test/.scratch/ntx-ipc-r2-store";
        ntx_netx *nx;
        ntx_session *s4 = mk(&nx, &cfg);
        char wire[70 * 200];
        size_t bn = 0;
        for (int k = 0; k < 70; k++) {
            int seq = k + 1, n;
            if (seq == 68 || seq == 69)
                n = snprintf(wire + bn, 200,
                             "{\"cmd\":\"add\",\"seq\":%04d,\"magnet\":\"magnet:?xt=urn:btih:"
                             "0123456789abcdef0123456789abcdef01234567\",\"pad\":\"", seq);
            else
                n = snprintf(wire + bn, 200, "{\"cmd\":\"%s\",\"seq\":%04d,\"pad\":\"",
                             seq == 65 ? "quit" : "ping", seq);
            while (n < 197) wire[bn + n++] = 'a';
            wire[bn + n++] = '"';
            wire[bn + n++] = '}';
            if (bn + (size_t)n != (size_t)(k + 1) * 200 - 1) { drop(s4, nx); return fail("bud2_len"); }
            wire[bn + n++] = '\n';
            bn += (size_t)n;
        }
        if (feed_stdin(wire, bn) != 0) { drop(s4, nx); return fail("bud2_stdin"); }
        int save_out = dup(1);
        fflush(stdout);
        unlink("test/.scratch/ntx-ipc-r2-postquit.ndjson");
        int capfd = open("test/.scratch/ntx-ipc-r2-postquit.ndjson", O_CREAT | O_TRUNC | O_WRONLY, 0644);
        if (capfd < 0) { dup2(save_out, 1); close(save_out); drop(s4, nx); return fail("bud2_file"); }
        dup2(capfd, 1);
        close(capfd);
        ntx_ipc_reader_init(&g_rd);
        g_ipc_open = 1; g_ipc_quit = 0; g_ipc_stash_len = 0;
        int tick = 0;
        while ((g_ipc_open || g_ipc_stash_len) && tick < 40) { ipc_pump_tick(s4); tick++; }
        fflush(stdout);
        dup2(save_out, 1);
        close(save_out);
        FILE *rf = fopen("test/.scratch/ntx-ipc-r2-postquit.ndjson", "rb");
        if (!rf) { drop(s4, nx); return fail("bud2_read"); }
        char bl[256];
        int seen = 0;
        while (fgets(bl, sizeof bl, rf)) {
            if (!strstr(bl, "\"type\":\"ack\"") && !strstr(bl, "\"type\":\"err\"")) continue;
            if (strstr(bl, "\"cmd\":\"add\"")) { fclose(rf); drop(s4, nx); return fail("bud2_add_ran"); }
            char *q = strstr(bl, "\"seq\":");
            if (!q) { fclose(rf); drop(s4, nx); return fail("bud2_seq"); }
            if (atoi(q + 6) != seen + 1) { fclose(rf); drop(s4, nx); return fail("bud2_order"); }
            seen++;
            if (seen == 65 && !strstr(bl, "\"cmd\":\"quit\"")) { fclose(rf); drop(s4, nx); return fail("bud2_last"); }
        }
        fclose(rf);
        if (seen != 65) { drop(s4, nx); return fail("bud2_count"); }
        drop(s4, nx);
        if (ok("ipc_post_quit_stop")) return 1;
    }

    { /* ── §11 Task C3: share cmd parse, magnet limit, caps, stats fields, event ── */
        ntx_ipc_req r;
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"/x\",\"torrent\":\"/y.torrent\",\"seq\":3}", &r);
        if (r.pre != NTX_IPC_OK || r.cmd != NTX_CMD_SHARE || !r.has_torrent ||
            strcmp(r.torrent, "/y.torrent") != 0 || r.seq != 3 || !r.has_seq)
            return fail("c3_parse_share");
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"\"}", &r);
        if (r.pre != NTX_IPC_E_BAD_ARG) return fail("c3_share_empty_path");
        ntx_ipc_parse("{\"cmd\":\"share\"}", &r);
        if (r.pre != NTX_IPC_E_BAD_ARG) return fail("c3_share_no_path");
        {
            char line[1200], big[513];
            memset(big, 'a', 512); big[512] = 0;
            snprintf(line, sizeof line, "{\"cmd\":\"share\",\"path\":\"%s\"}", big);
            ntx_ipc_parse(line, &r);
            if (r.pre != NTX_IPC_E_IO) return fail("c3_share_path_512");
            big[511] = 0; /* 511 B is the contract limit */
            snprintf(line, sizeof line, "{\"cmd\":\"share\",\"path\":\"%s\"}", big);
            ntx_ipc_parse(line, &r);
            if (r.pre != NTX_IPC_OK || strlen(r.path) != 511) return fail("c3_share_path_511");
            big[511] = 'a'; big[512] = 0; /* back to 512 B for the torrent limit */
            snprintf(line, sizeof line, "{\"cmd\":\"share\",\"path\":\"/x\",\"torrent\":\"%s\"}", big);
            ntx_ipc_parse(line, &r);
            if (r.pre != NTX_IPC_E_IO) return fail("c3_share_torrent_512");
        }
        /* magnet in add: 2048 B is accepted, 2049 B is io (frame limit 4096 kept) */
        {
            char line[2200], mag[2050];
            for (int probe = 0; probe < 3; probe++) {
                static const size_t len[] = { 2000, 2048, 2049 };
                memset(mag, 'a', len[probe]);
                mag[len[probe]] = 0;
                snprintf(line, sizeof line, "{\"cmd\":\"add\",\"magnet\":\"%s\"}", mag);
                ntx_ipc_parse(line, &r);
                if (len[probe] <= 2048) {
                    if (r.pre != NTX_IPC_OK || strlen(r.magnet) != len[probe])
                        return fail("c3_magnet_under_ok");
                } else if (r.pre != NTX_IPC_E_IO) {
                    return fail("c3_magnet_2049_io");
                }
            }
        }
        if (ok("c3_parse_share")) return 1;

        /* caps carries "share" exactly while ntx_share_available() (§6.4/§11) */
        {
            char hl[512];
            static ntx_share_tracker one[2];
            for (int k = 0; k < 2; k++) {
                one[k].url = "https://x.invalid/announce";
                one[k].host = "x.invalid";
                one[k].npins = 1;
                memset(one[k].pins[0], k + 1, 32);
            }
            ntx_share_trackers_test_set(one, 2);
            if (!ntx_share_available()) { ntx_share_trackers_test_set(0, -1); return fail("c3_caps_setup"); }
            if (ntx_ipc_hello_json(hl, sizeof hl, "b") <= 0 || !strstr(hl, "\"quit\",\"share\"]"))
                { ntx_share_trackers_test_set(0, -1); return fail("c3_caps_on"); }
            ntx_share_trackers_test_set(one, 1); /* below NTX_SHARE_MIN_TRACKERS */
            if (ntx_share_available()) { ntx_share_trackers_test_set(0, -1); return fail("c3_gate_off"); }
            if (ntx_ipc_hello_json(hl, sizeof hl, "b") <= 0 || strstr(hl, "share"))
                { ntx_share_trackers_test_set(0, -1); return fail("c3_caps_off"); }
            if (strcmp(hl, "{\"type\":\"hello\",\"v\":1,\"protocol\":\"ntx-json\","
                           "\"max_tts\":16,\"max_peers\":128,\"build\":\"b\","
                           "\"caps\":[\"ping\",\"status\",\"hello\",\"add\",\"pause\","
                           "\"resume\",\"remove\",\"quit\"]}") != 0)
                { ntx_share_trackers_test_set(0, -1); return fail("c3_caps_off_exact"); }
            ntx_share_trackers_test_set(0, -1);
            if (ntx_ipc_hello_json(hl, sizeof hl, "b") <= 0 || !strstr(hl, "\"share\""))
                return fail("c3_caps_restored");
        }
        if (ok("c3_caps_share")) return 1;

        /* §11 stats fields, additive at the end of each scope */
        {
            ntx_stats st;
            char js[4096];
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.port_map = 2;
            st.ext_port = 40123;
            st.t[0].slot = 0;
            st.t[0].priv = 1; st.t[0].share = 1; st.t[0].enc_strict = 1;
            st.t[0].trk_pin_fail = 0; st.t[0].in_ok = 0;
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("c3_stats_fit");
            if (!strstr(js, "\"priv\":1,\"share\":1,\"enc_strict\":1,\"trk_pin_fail\":0,\"in_ok\":0"))
                return fail("c3_stats_torrent_fields");
            if (!strstr(js, "\"port_map\":2,\"ext_port\":40123")) return fail("c3_stats_session_fields");
            if (!ipc_ok_local(js)) return fail("c3_stats_parseable");
        }
        if (ok("c3_stats_fields")) return 1;

        /* S17d / R15: the IPv6 mapping keys. The aggregate and the two per-family
           fields must come out exactly as the session published them — the JSON is the
           operator's only view of WHICH family is mapped once the aggregate says only
           "reachable" — and every line stays strictly parseable (§10 no-space rule
           included, which ipc_ok_local plus the substring pins). */
        {
            ntx_stats st;
            char js[4096];

            /* both families ACTIVE, each with its own port */
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.port_map = NTX_PM_ACTIVE; st.ext_port = 40123;
            st.port_map6 = NTX_PM_ACTIVE; st.ext_port6 = 6881;
            st.t[0].slot = 0;
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("s17d_stats_fit");
            if (!strstr(js, "\"port_map\":2,\"ext_port\":40123,\"port_map6\":2,\"ext_port6\":6881"))
                return fail("s17d_stats_both");
            if (!ipc_ok_local(js)) return fail("s17d_stats_both_parseable");

            /* ACTIVE from v6 alone: the aggregate is 2 while the v4-only field is 0 —
             * the pair is what keeps the line honest about which family granted. */
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.port_map = NTX_PM_ACTIVE; st.ext_port = 0;
            st.port_map6 = NTX_PM_ACTIVE; st.ext_port6 = 6881;
            st.t[0].slot = 0;
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("s17d_stats_fit2");
            if (!strstr(js, "\"port_map\":2,\"ext_port\":0,\"port_map6\":2,\"ext_port6\":6881"))
                return fail("s17d_stats_v6_only");
            if (!ipc_ok_local(js)) return fail("s17d_stats_v6_only_parseable");

            /* v4 ACTIVE, v6 settled at none, and nothing brought up at all: the two
             * new keys are present in every state (never omitted), 0 when unused. */
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.port_map = NTX_PM_ACTIVE; st.ext_port = 40123;
            st.port_map6 = NTX_PM_NONE; st.ext_port6 = 0;
            st.t[0].slot = 0;
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("s17d_stats_fit3");
            if (!strstr(js, "\"port_map\":2,\"ext_port\":40123,\"port_map6\":3,\"ext_port6\":0"))
                return fail("s17d_stats_v4_only");
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.t[0].slot = 0;
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("s17d_stats_fit4");
            if (!strstr(js, "\"port_map\":0,\"ext_port\":0,\"port_map6\":0,\"ext_port6\":0"))
                return fail("s17d_stats_off");
            if (!ipc_ok_local(js)) return fail("s17d_stats_off_parseable");

            /* the worst-case header still fits the reserve with the two extra keys:
             * every field at its widest, no truncation and honest n. The v6 `4` here is a
             * width probe only — ntx_session_stats_refresh can never publish it (NAT-PMP
             * has no IPv6, so no CGNAT verdict exists for that family). */
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.port_map = NTX_PM_CGNAT; st.ext_port = 65535;
            st.port_map6 = NTX_PM_CGNAT; st.ext_port6 = 65535;
            st.t[0].slot = 0;
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("s17d_stats_fit5");
            if (!strstr(js, "\"port_map\":4,\"ext_port\":65535,\"port_map6\":4,\"ext_port6\":65535"))
                return fail("s17d_stats_widest");
            if (strstr(js, "\"truncated\":1")) return fail("s17d_stats_header_reserve");
            if (!ipc_ok_local(js)) return fail("s17d_stats_widest_parseable");
        }
        if (ok("s17d_stats_v6_fields")) return 1;

        /* §11 share event lines: the ready shape with the §11.1 escaping, and the
           failure shape whose code comes from ntx_share_err_code */
        {
            ntx_share_event ev;
            char line[40960];
            memset(&ev, 0, sizeof ev);
            ev.i = 3; ev.ok = 1;
            for (int k = 0; k < 20; k++) ev.ih[k] = (uint8_t)k;
            for (int k = 0; k < 32; k++) ev.ih2[k] = (uint8_t)(0xa0 + k);
            snprintf(ev.name, sizeof ev.name, "a\"b\\c\nd");
            snprintf(ev.magnet, sizeof ev.magnet, "magnet:?xt=urn:btih:%040x", 1);
            snprintf(ev.torrent_path, sizeof ev.torrent_path, "/tmp/x.bin");
            if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("c3_evt_len");
            if (!ipc_ok_local(line)) return fail("c3_evt_parseable");
            if (strncmp(line, "{\"type\":\"share\",\"i\":3,\"ok\":1,", 25) != 0)
                return fail("c3_evt_head");
            if (!strstr(line, "\"ih\":\"000102030405060708090a0b0c0d0e0f10111213\""))
                return fail("c3_evt_ih");
            if (!strstr(line, "\"ih2\":\"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf\""))
                return fail("c3_evt_ih2");
            if (!strstr(line, "\"name\":\"a\\\"b\\\\c\\nd\"")) return fail("c3_evt_escape");
            if (!strstr(line, "\"magnet\":\"magnet:")) return fail("c3_evt_magnet");
            if (!strstr(line, "\"torrent\":\"/tmp/x.bin\"}")) return fail("c3_evt_torrent");
            ev.ok = 0; ev.err = NTX_SHARE_E_NO_TRACKERS;
            if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0 ||
                strcmp(line, "{\"type\":\"share\",\"i\":3,\"ok\":0,\"code\":\"no_trackers\"}") != 0)
                return fail("c3_evt_fail");
            if (ntx_ipc_share_event_json(line, 32, &ev) != -1) return fail("c3_evt_tiny_cap");
        }
        if (ok("c3_share_event_json")) return 1;

        /* dispatcher over a live session: §11 ack (i/ok/state 4 = VERIFY, no ih)
           and the synchronous err codes io / bad_arg / no_trackers */
        {
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-t6";
            ntx_session *s = mk(&nx, &cfg);
            char out[2048];
            FILE *wf = fopen("/tmp/ntx-ipc-t6/c3-share.bin", "wb");
            if (!wf) { drop(s, nx); return fail("c3_file"); }
            fputs("0123456789", wf);
            fclose(wf);

            ntx_ipc_dispatch(s, "{\"cmd\":\"share\",\"seq\":31}", out, sizeof out);
            if (!strstr(out, "\"cmd\":\"share\"") || !strstr(out, "\"code\":\"bad_arg\"") ||
                !strstr(out, "\"seq\":31") || strstr(out, "\"i\":"))
                return fail("c3_d_bad_arg");
            ntx_ipc_dispatch(s, "{\"cmd\":\"share\",\"path\":\"\",\"seq\":32}", out, sizeof out);
            if (!strstr(out, "\"code\":\"bad_arg\"")) return fail("c3_d_bad_arg_empty");
            ntx_ipc_dispatch(s, "{\"cmd\":\"share\",\"path\":\"/tmp/ntx-ipc-t6/nope.bin\",\"seq\":33}",
                             out, sizeof out);
            if (!strstr(out, "\"cmd\":\"share\"") || !strstr(out, "\"code\":\"io\"") ||
                !strstr(out, "\"seq\":33"))
                return fail("c3_d_io");

            static ntx_share_tracker one[2];
            for (int k = 0; k < 2; k++) {
                one[k].url = "https://x.invalid/announce";
                one[k].host = "x.invalid";
                one[k].npins = 1;
                memset(one[k].pins[0], k + 1, 32);
            }
            ntx_share_trackers_test_set(one, 1); /* gate closed -> no_trackers */
            ntx_ipc_dispatch(s, "{\"cmd\":\"share\",\"path\":\"/tmp/ntx-ipc-t6/c3-share.bin\",\"seq\":34}",
                             out, sizeof out);
            ntx_share_trackers_test_set(0, -1);
            if (!strstr(out, "\"code\":\"no_trackers\"") || !strstr(out, "\"seq\":34"))
                return fail("c3_d_no_trackers");

            ntx_ipc_dispatch(s, "{\"cmd\":\"share\",\"path\":\"/tmp/ntx-ipc-t6/c3-share.bin\",\"seq\":35}",
                             out, sizeof out);
            if (strcmp(out, "{\"type\":\"ack\",\"seq\":35,\"cmd\":\"share\",\"i\":0,\"ok\":1,\"state\":4}") != 0)
                return fail("c3_d_ack"); /* §11: no ih — the hash is not known yet */

            /* The queue still holds nothing: share_add leaves the slot HASHING and
               ntx_session_share_poll_event reports only HASHING-exited slots, so the
               ready line is covered synthetically in c3_share_event_json above. */
            if (ntx_session_share_state(s, 0) != NTX_SHARE_HASHING) { drop(s, nx); return fail("c3_d_state"); }
            drop(s, nx);
        }
        if (ok("c3_dispatch_share")) return 1;
    }

    { /* ── R8: a name cut by BYTE count must not split a UTF-8 character, and the
         emitter must not leak invalid sequences into the NDJSON stream.
         Every line here goes through the strict validator above — the same verdict
         a strict NDJSON parser (Python/Go/Node) makes on the IPC channel. ── */
        ntx_stats st;
        char js[40960];
        char big[704];

        /* (a) THE REAL CUT: a live session slot whose torrent name is 60 ×
           U+00E9 (120 B) is cut into char name[48] by
           ntx_session_stats_refresh — the old snprintf left "\xc3" as byte 47
           and every stats line for the whole share was undecodable. */
        {
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-t6";
            ntx_session *s = mk(&nx, &cfg);
            char line[256];
            snprintf(line, sizeof line,
                     "{\"cmd\":\"add\",\"magnet\":\"magnet:?xt=urn:btih:%s\"}",
                     "0123456789abcdef0123456789abcdef01234567");
            ntx_ipc_req r;
            ntx_ipc_parse(line, &r);
            if (ntx_session_add_magnet(s, r.magnet) != 0) { drop(s, nx); return fail("r8_sess_add"); }
            for (int k = 0; k < 60; k++) memcpy(big + (size_t)k * 2, "\xc3\xa9", 2);
            big[120] = 0;
            memcpy(s->tts[0].name, big, 121); /* what a 120-B torrent name looks like */
            ntx_session_stats_refresh(s, 0);
            ntx_session_snapshot(s, &st);
            drop(s, nx);
            if (st.n != 1) return fail("r8_sess_n");
            if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("r8_stats_len_session");
            if (r8_line("stats session 60x e-acute", js)) return fail("r8_stats_session_name");
            if (strstr(js, "\xef\xbf\xbd")) return fail("r8_stats_session_fffd"); /* no cut to repair */
            {
                char want[64], fld[128];
                for (int k = 0; k < 23; k++) memcpy(want + (size_t)k * 2, "\xc3\xa9", 2);
                want[46] = 0; /* 23 × é fits in 47 B, the 24th would not */
                snprintf(fld, sizeof fld, "\"name\":\"%s\"", want);
                if (!strstr(js, fld)) { printf("R8 session 23x prefix missing: %s\n", js); return fail("r8_stats_session_cut"); }
            }
        }

        /* (b) emitter path: a name already cut mid-character (a share name read
           off disk, or any other byte-cut producer) must still yield a line a
           strict parser accepts. */
        memset(&st, 0, sizeof st);
        st.n = 1;
        for (int k = 0; k < 60; k++) memcpy(big + (size_t)k * 2, "\xc3\xa9", 2);
        big[120] = 0;
        r8_cut(st.t[0].name, sizeof st.t[0].name, big);
        if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("r8_stats_len_2byte");
        if (r8_line("stats 60x e-acute", js)) return fail("r8_stats_2byte_name");
        /* the escaper replaced exactly the torn tail with one U+FFFD and kept
           the 23 whole characters that fit in the field */
        {
            char want[80];
            want[0] = 0;
            for (int k = 0; k < 23; k++) memcpy(want + (size_t)k * 2, "\xc3\xa9", 2);
            memcpy(want + 46, "\xef\xbf\xbd\"", 4);
            want[50] = 0;
            char fld[128];
            snprintf(fld, sizeof fld, "\"name\":\"%s", want);
            if (!strstr(js, fld)) { printf("R8 stats 23x prefix missing: %s\n", js); return fail("r8_stats_2byte_cut"); }
        }

        /* (c) stats name with a 4-byte character straddling the 47/48 B boundary
           (45 ASCII, then the emoji occupies bytes 45..48 of the 47-byte field). */
        memset(&st, 0, sizeof st);
        st.n = 1;
        memset(big, 'a', 45); big[45] = 0;
        snprintf(big + 45, sizeof big - 45, "\xf0\x9f\x98\x80tail");
        r8_cut(st.t[0].name, sizeof st.t[0].name, big);
        if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("r8_stats_len_4byte");
        if (r8_line("stats 4-byte at 47/48", js)) return fail("r8_stats_4byte_boundary");
        {
            char want[80];
            memset(want, 'a', 45);
            memcpy(want + 45, "\xef\xbf\xbd\"", 4); /* one run, one U+FFFD */
            want[49] = 0;
            char fld[128];
            snprintf(fld, sizeof fld, "\"name\":\"%s", want);
            if (!strstr(js, fld)) { printf("R8 stats 45x a prefix missing: %s\n", js); return fail("r8_stats_4byte_cut"); }
        }

        /* (d) share event name: 300 × é is 600 B, so the copy into char name[512]
           is itself cut mid-character; the line must still decode. */
        {
            ntx_share_event ev;
            char line[40960];
            memset(&ev, 0, sizeof ev);
            ev.i = 5; ev.ok = 1;
            for (int k = 0; k < 20; k++) ev.ih[k] = (uint8_t)(0x10 + k);
            for (int k = 0; k < 32; k++) ev.ih2[k] = (uint8_t)(0x20 + k);
            for (int k = 0; k < 300; k++) memcpy(big + (size_t)k * 2, "\xc3\xa9", 2);
            big[600] = 0;
            r8_cut(ev.name, sizeof ev.name, big);
            snprintf(ev.magnet, sizeof ev.magnet, "magnet:?xt=urn:btih:%040x", 7);
            snprintf(ev.torrent_path, sizeof ev.torrent_path, "/tmp/r8.torrent");
            /* the input really is a torn 511-byte cut — without this the emitter
               case below would pass trivially */
            if (utf8_strict(ev.name, NULL)) return fail("r8_event_input_whole");
            if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("r8_event_len");
            if (r8_line("share event 300x e-acute", line)) return fail("r8_event_long_name");

            /* the REAL producer: share_evq_push (static, this TU includes
               ntx_share.c) copies sl->name into ev->name. A 600-B name on a
               FAILED slot must reach the queue cut on a boundary, so the
               emitted line needs no repair at all (no U+FFFD). */
            {
                ntx_config cfg;
                ntx_netx *nx;
                memset(&cfg, 0, sizeof cfg);
                cfg.store_dir = "/tmp/ntx-ipc-t6";
                ntx_session *s = mk(&nx, &cfg);
                FILE *wf = fopen("/tmp/ntx-ipc-t6/r8-share.bin", "wb");
                if (!wf) { drop(s, nx); return fail("r8_prod_file"); }
                fputs("0123456789", wf);
                fclose(wf);
                ntx_ipc_req r;
                ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"/tmp/ntx-ipc-t6/r8-share.bin\"}", &r);
                ntx_share_err se = NTX_SHARE_OK;
                int ti = ntx_session_share_add(s, r.path, NULL, &se);
                if (ti < 0) { drop(s, nx); printf("R8 share_add err=%d\n", (int)se); return fail("r8_prod_add"); }
                struct ntx_share_slot *sl = s->share[ti];
                /* the pre-fix producer did exactly this: snprintf "%s" into
                   char name[512] cut the 600-B name in mid-character */
                r8_cut(sl->name, sizeof sl->name, big);
                if (utf8_strict(sl->name, NULL)) return fail("r8_prod_setup");
                sl->st = NTX_SHARE_FAILED;
                sl->err = NTX_SHARE_E_CHANGED;
                share_evq_push(sl);
                ntx_share_event pev;
                if (ntx_session_share_poll_event(s, &pev) != 1) { drop(s, nx); return fail("r8_prod_event"); }
                drop(s, nx);
                size_t pl = strlen(pev.name);
                if (pl != 510 || !utf8_strict(pev.name, NULL)) {
                    printf("R8 producer cut: len=%zu valid=%d tail=%02x %02x\n", pl,
                           utf8_strict(pev.name, NULL), (unsigned)(unsigned char)pev.name[509],
                           (unsigned)(unsigned char)pev.name[510]);
                    return fail("r8_event_producer_cut");
                }
                snprintf(pev.magnet, sizeof pev.magnet, "magnet:?xt=urn:btih:%040x", 8);
                snprintf(pev.torrent_path, sizeof pev.torrent_path, "/tmp/r8-prod.torrent");
                pev.ok = 1;
                if (ntx_ipc_share_event_json(line, sizeof line, &pev) <= 0) return fail("r8_prod_evt_len");
                if (r8_line("share event producer 300x e-acute", line)) return fail("r8_prod_event_line");
                if (strstr(line, "\xef\xbf\xbd")) return fail("r8_prod_event_fffd");
            }

            /* (e) invalid bytes in name / magnet / torrent become U+FFFD, never a
               rejected line (§11.1 keeps the escaping discipline). */
            memset(&ev, 0, sizeof ev);
            ev.i = 6; ev.ok = 1;
            snprintf(ev.name, sizeof ev.name, "ok\xc3\x28tail");        /* C3 + '(' = invalid */
            snprintf(ev.magnet, sizeof ev.magnet, "m?\xfe\xff");          /* impossible lead bytes */
            snprintf(ev.torrent_path, sizeof ev.torrent_path, "/p/\xe2\x82"); /* truncated 3-byte */
            if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("r8_event_bad_len");
            if (r8_line("share event invalid bytes", line)) return fail("r8_event_sanitize");
            if (!strstr(line, "\"name\":\"ok\xef\xbf\xbd(") && !strstr(line, "\"name\":\"ok\xef\xbf\xbd\xef\xbf\xbd(")) {
                printf("R8 no U+FFFD in name: %s\n", line);
                return fail("r8_event_sanitize_name");
            }
            if (!strstr(line, "\xef\xbf\xbd") ) return fail("r8_event_sanitize_missing");

            /* (f) guard: an ASCII name and a short, already-valid UTF-8 name come
               out byte-for-byte unchanged. */
            memset(&ev, 0, sizeof ev);
            ev.i = 7; ev.ok = 1;
            snprintf(ev.name, sizeof ev.name, "Plain.Name-01.txt");
            snprintf(ev.magnet, sizeof ev.magnet, "magnet:?xt=urn:btih:%040x", 9);
            snprintf(ev.torrent_path, sizeof ev.torrent_path, "/tmp/plain.torrent");
            if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("r8_evt_ascii_len");
            if (!strstr(line, "\"name\":\"Plain.Name-01.txt\"")) return fail("r8_event_ascii_guard");
            if (strstr(line, "\xef\xbf\xbd")) return fail("r8_event_ascii_fffd");
            snprintf(ev.name, sizeof ev.name, "za\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87.txt");
            if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("r8_evt_utf8_len");
            if (!strstr(line, "\"name\":\"za\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87.txt\""))
                return fail("r8_event_utf8_guard");
            if (strstr(line, "\xef\xbf\xbd")) return fail("r8_event_utf8_fffd");
            if (r8_line("share event ascii", line)) return fail("r8_event_ascii_line");
        }

        /* (g) guard: a short, already-valid stats name is byte-for-byte unchanged. */
        memset(&st, 0, sizeof st);
        st.n = 1;
        snprintf(st.t[0].name, sizeof st.t[0].name, "za\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87.txt");
        if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("r8_stats_short_len");
        if (!strstr(js, "\"name\":\"za\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87.txt\"")) return fail("r8_stats_short_guard");
        if (strstr(js, "\xef\xbf\xbd")) return fail("r8_stats_short_fffd");
        memset(&st, 0, sizeof st);
        st.n = 1;
        memset(big, 'x', 47); big[47] = 0; /* the t_cli_tags.c 47-char name */
        r8_cut(st.t[0].name, sizeof st.t[0].name, big);
        if (ntx_stats_to_json(&st, js, sizeof js) <= 0) return fail("r8_stats_ascii47_len");
        if (!strstr(js, "\"name\":\"xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\""))
            return fail("r8_stats_ascii47_guard");
        if (ok("r8_utf8_stats_event")) return 1;
    }

    { /* ── R30 · S18: a decoded \u0000 must not silently cut path/torrent ──
         The bug: "a\u0000b" decoded to the bytes a 00 b, so every strlen-based
         consumer downstream (ntx_session_share_add opens r->path / r->torrent)
         saw "a" — the wrong file got seeded and the reply said ok. A NUL cannot
         name a POSIX path, so the decoder rejects the code point as bad_json,
         exactly like the other malformed-JSON cases (same seq/cmd/ok/code shape). */
        ntx_ipc_req r;
        static const char *NUL_LINES[] = {
            "{\"cmd\":\"share\",\"path\":\"a\\u0000b\"}",
            "{\"cmd\":\"share\",\"path\":\"/x\",\"torrent\":\"x\\u0000y.torrent\"}",
            "{\"cmd\":\"add\",\"path\":\"a\\u0000b.torrent\"}",
            "{\"cmd\":\"add\",\"magnet\":\"magnet:?xt=urn:btih:0123456789abcdef0123456789ab"
            "cdef01234567\\u0000&dn=x\"}",
            "{\"cmd\":\"share\",\"\\u0000key\":1}",                 /* key position */
            "{\"cmd\":\"ping\",\"k\":\"a\\u0000b\"}"                /* unknown-key value */
        };
        for (size_t k = 0; k < sizeof NUL_LINES / sizeof NUL_LINES[0]; k++) {
            ntx_ipc_parse(NUL_LINES[k], &r);
            if (r.pre != NTX_IPC_E_BAD_JSON) {
                printf("R30 line %zu: want=bad_json got=%s line=%s\n", k,
                       code_name(r.pre), NUL_LINES[k]);
                return fail("r30_nul_bad_json");
            }
        }
        /* the measure-only mirror (ipc_json_str_len, §6.1 skip paths) must reach
           the same verdict: the same grammar, so no pair can be skipped past a NUL */
        ntx_ipc_parse("{\"cmd\":\"ping\",\"kkkkkkkkkkkkkkkkkk\":\"a\\u0000b\",\"seq\":3}", &r);
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("r30_nul_longkey_value");

        /* guards: only U+0000 is newly refused. The escapes that worked before
           still decode byte-for-byte, and >U+007F is still refused (§3.4). */
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"a\\u005cb\"}", &r);
        if (r.pre != NTX_IPC_OK || strcmp(r.path, "a\\b") != 0) return fail("r30_esc_backslash");
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"a\\u0041\\u007fb\"}", &r);
        if (r.pre != NTX_IPC_OK || strcmp(r.path, "aA\x7f" "b") != 0) return fail("r30_esc_ascii_kept");
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"a\\u0001\\u001fb\"}", &r);
        if (r.pre != NTX_IPC_OK || strcmp(r.path, "a\x01\x1f" "b") != 0) return fail("r30_esc_ctl_kept");
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"a\\u00e9b\"}", &r);
        if (r.pre != NTX_IPC_E_BAD_JSON) return fail("r30_esc_above_7f_still_rejected");
        /* a raw é travels raw (§3.4) and must stay accepted */
        ntx_ipc_parse("{\"cmd\":\"share\",\"path\":\"a\xc3\xa9" "b\"}", &r);
        if (r.pre != NTX_IPC_OK || strcmp(r.path, "a\xc3\xa9" "b") != 0) return fail("r30_raw_utf8_kept");
        if (ok("r30_nul_parse")) return 1;

        /* dispatcher over a live session: the truncation target really exists, so
           pre-fix this shared the file "a" (ack ok:1, slot HASHING) instead of
           answering bad_json. Post-fix: no slot, no .torrent, no share event. */
        {
            ntx_config cfg;
            ntx_netx *nx;
            char dir[96], real[192], line[768], out[2048];
            struct stat sb;

            memset(&cfg, 0, sizeof cfg);
            snprintf(dir, sizeof dir, "test/.scratch/ntx-ipc-r30");
            cfg.store_dir = dir;
            if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return fail("r30_scratch");
            if (mkdir(dir, 0755) != 0 && errno != EEXIST) return fail("r30_dir");
            snprintf(real, sizeof real, "%s/a", dir);       /* what pre-fix would seed */
            FILE *wf = fopen(real, "wb");
            if (!wf) return fail("r30_file");
            fputs("0123456789", wf);
            fclose(wf);

            ntx_session *s = mk(&nx, &cfg);
            snprintf(line, sizeof line,
                     "{\"cmd\":\"share\",\"seq\":41,\"path\":\"%s/a\\u0000b\"}", dir);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (strcmp(out, "{\"type\":\"err\",\"seq\":41,\"cmd\":\"share\","
                            "\"ok\":0,\"code\":\"bad_json\"}") != 0) {
                printf("R30 share reply: %s\n", out);
                drop(s, nx); return fail("r30_d_share_reply");
            }
            snprintf(line, sizeof line,
                     "{\"cmd\":\"share\",\"seq\":42,\"path\":\"%s/a\",\"torrent\":"
                     "\"%s/x\\u0000y.torrent\"}", dir, dir);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (strcmp(out, "{\"type\":\"err\",\"seq\":42,\"cmd\":\"share\","
                            "\"ok\":0,\"code\":\"bad_json\"}") != 0) {
                printf("R30 torrent reply: %s\n", out);
                drop(s, nx); return fail("r30_d_torrent_reply");
            }
            /* nothing was created for the truncated name: no share slot anywhere,
               no event queued, and no `.torrent` written for the seed of "a"
               (share_add names the output <store-dir>/<basename>.torrent). */
            for (int ti = 0; ti < NTX_SESSION_MAX_TTS; ti++)
                if (ntx_session_share_state(s, ti) != NTX_SHARE_NONE) {
                    printf("R30 slot %d state=%d\n", ti, (int)ntx_session_share_state(s, ti));
                    drop(s, nx); return fail("r30_no_slot");
                }
            {
                ntx_share_event ev;
                if (ntx_session_share_poll_event(s, &ev) != 0) { drop(s, nx); return fail("r30_no_event"); }
            }
            snprintf(real, sizeof real, "%s/a.torrent", dir);
            if (stat(real, &sb) == 0) { printf("R30 wrote %s\n", real); drop(s, nx); return fail("r30_no_write"); }
            drop(s, nx);
            if (ok("r30_nul_dispatch")) return 1;
        }

        /* a RAW NUL byte in the frame is already refused, and this pins WHO
           refuses it: the framer is \n-delimited and stores the NUL verbatim
           (the bytes past it are still in the line buffer), so the parser's
           `c == 0` guard in ipc_json_str is what rejects the document. No
           second guard is needed downstream — no dead code. */
        {
            static const char frame[] = { '{', '"', 'c', 'm', 'd', '"', ':', '"', 's',
                                          'h', 'a', 'r', 'e', '"', ',', '"', 'p', 'a',
                                          't', 'h', '"', ':', '"', 'a', '\0', 'b', '"',
                                          '}', '\n' };
            ntx_ipc_reader rd;
            ntx_ipc_sink snk = { 0, r30_cap_cb, 0 };
            char out[2048];
            ntx_config cfg;
            ntx_netx *nx;
            r30_cap_n = 0; r30_cap_slen = 0; r30_cap_raw = 0;
            ntx_ipc_reader_init(&rd);
            ntx_ipc_feed(&rd, frame, sizeof frame, &snk);
            if (r30_cap_n != 1) return fail("r30_raw_framed");
            /* the framer kept the byte after the NUL (10 bytes of the frame past it) */
            if (r30_cap_slen != 24 || r30_cap_raw[24] != 0 ||
                memcmp(r30_cap_raw + 25, "b\"}", 3) != 0) {
                printf("R30 framer: slen=%zu b24=%02x b25=%02x\n", r30_cap_slen,
                       (unsigned)(unsigned char)r30_cap_raw[24],
                       (unsigned)(unsigned char)r30_cap_raw[25]);
                return fail("r30_raw_framer_keeps_nul");
            }
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "test/.scratch/ntx-ipc-r30";
            ntx_session *s = mk(&nx, &cfg);
            ntx_ipc_dispatch(s, r30_cap_raw, out, sizeof out);
            drop(s, nx);
            /* the cmd was read before the NUL, so it is echoed — the same shape
               the existing malformed cases take (§ json-api: seq/cmd echoed when
               they were read before the error) */
            if (strcmp(out, "{\"type\":\"err\",\"cmd\":\"share\",\"ok\":0,\"code\":\"bad_json\"}") != 0) {
                printf("R30 raw NUL reply: %s\n", out);
                return fail("r30_raw_nul_reply");
            }
            if (ok("r30_raw_nul_framer")) return 1;
        }
    }

    { /* ── R29 · S25: a share event the emitter cannot build must still reach the
         client as {"ok":0,"code":"io"} ─────────────────────────────────────────
         The bug: ntx_ipc_share_event_json returned -1 when the ready line would
         not fit the caller's buffer, and its caller (ipc_share_events in
         ntx_main.c) emitted nothing — but ntx_session_share_poll_event had
         ALREADY dequeued the event and share_evq_push had ALREADY spent the
         slot's ev_ready flag, so nothing was requeued either. The client saw no
         verdict for that `i`, ever, and waited forever (§11: every queued event
         owes the client exactly one line). The floor is now the §11 failure
         line, which is small, fixed-shape and always pairable by `i`. ── */
        ntx_share_event ev;
        char line[70000];
        char want[64], want4[64];
        static const char IO_FMT[] = "{\"type\":\"share\",\"i\":%d,\"ok\":0,\"code\":\"io\"}";

        /* the worst case the §11.1 escape can produce: every field at its maximum
           length and every byte a control byte (6 output bytes per input byte).
           The consumer's buffer (g_share_evt in ntx_main.c) is sized for exactly
           this, so today the emitter never fails in production — the pin below
           says so, and the cases below say what happens if it ever does. */
        memset(&ev, 0, sizeof ev);
        ev.i = 11; ev.ok = 1;
        for (int k = 0; k < 20; k++) ev.ih[k] = (uint8_t)0xff;
        for (int k = 0; k < 32; k++) ev.ih2[k] = (uint8_t)0xff;
        memset(ev.name, (char)0x1f, sizeof ev.name - 1);
        memset(ev.magnet, (char)0x1f, sizeof ev.magnet - 1);
        memset(ev.torrent_path, (char)0x1f, sizeof ev.torrent_path - 1);
        if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("r29_worst_len");
        if (!ipc_ok_local(line)) return fail("r29_worst_shape");
        if ((int)strlen(line) >= (int)sizeof g_share_evt) {
            printf("R29 worst-case line %zu B vs g_share_evt %zu B\n", strlen(line),
                   sizeof g_share_evt);
            return fail("r29_consumer_buffer_too_small");
        }

        /* THE RED CASE: the line does not fit the cap → the client still gets the
           verdict, the §11 failure shape for that same `i`, and nothing else.
           Pre-fix this call returned -1 and ipc_share_events stayed silent. */
        snprintf(want, sizeof want, IO_FMT, 11);
        line[0] = 'Z'; line[1] = 0;
        if (ntx_ipc_share_event_json(line, 64, &ev) <= 0) return fail("r29_ready_fallback_len");
        if (strcmp(line, want) != 0) { printf("R29 fallback: %s\n", line); return fail("r29_ready_fallback_body"); }
        if (r8_line("share fallback", line)) return fail("r29_ready_fallback_valid");

        /* the same verdict when the overflow is the magnet alone, and when it is
           the name alone (each field on its own can push the line past a small cap) */
        memset(&ev, 0, sizeof ev);
        ev.i = 0; ev.ok = 1;
        snprintf(ev.name, sizeof ev.name, "photo.jpg");
        snprintf(ev.magnet, sizeof ev.magnet, "magnet:?xt=urn:btih:%040x", 3);
        snprintf(ev.torrent_path, sizeof ev.torrent_path, "/tmp/r29.torrent");
        snprintf(want, sizeof want, IO_FMT, 0);
        if (ntx_ipc_share_event_json(line, 48, &ev) <= 0 || strcmp(line, want) != 0) {
            printf("R29 small-cap magnet: %s\n", line);
            return fail("r29_magnet_overflow");
        }
        memset(ev.name, (char)0x01, sizeof ev.name - 1); /* 511 control bytes: the escaping blow-up */
        if (ntx_ipc_share_event_json(line, 512, &ev) <= 0 || strcmp(line, want) != 0) {
            printf("R29 name-overflow fallback: %s\n", line);
            return fail("r29_name_overflow");
        }

        /* floor of the floor: even the fallback has to fit. Below that the honest
           answer is still a clean refusal — out[0] == 0, never a torn line. */
        line[0] = 'Z'; line[1] = 0;
        if (ntx_ipc_share_event_json(line, 32, &ev) != -1) return fail("r29_fallback_tiny_cap");
        if (line[0] != 0) return fail("r29_fallback_torn");

        /* guards: the normal paths are untouched by the fallback. */
        if (ntx_ipc_share_event_json(line, 64, NULL) != -1) return fail("r29_null_ev");
        snprintf(want4, sizeof want4, IO_FMT, 4);
        memset(&ev, 0, sizeof ev);
        ev.i = 4; ev.ok = 1;
        snprintf(ev.name, sizeof ev.name, "photo.jpg");
        snprintf(ev.magnet, sizeof ev.magnet, "magnet:?xt=urn:btih:%040x", 4);
        snprintf(ev.torrent_path, sizeof ev.torrent_path, "/tmp/r29.torrent");
        if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0) return fail("r29_ok_len");
        if (!ipc_ok_local(line)) return fail("r29_ok_shape");
        if (!strstr(line, "\"ok\":1") || strstr(line, "\"code\"")) return fail("r29_ok_got_fallback");
        ev.ok = 0; ev.err = NTX_SHARE_E_CHANGED; /* its own code wins, never "io" */
        if (ntx_ipc_share_event_json(line, sizeof line, &ev) <= 0 ||
            strcmp(line, "{\"type\":\"share\",\"i\":4,\"ok\":0,\"code\":\"changed\"}") != 0)
            return fail("r29_err_code_kept");
        /* the error path is never silent either: below the width of its own code
           the verdict degrades to the "io" line (ok:0 stays true — the client is
           told the share is dead, only the reason is lost), and below the width
           of THAT line the answer is a clean refusal, out[0] == 0. */
        if (ntx_ipc_share_event_json(line, 44, &ev) <= 0 || strcmp(line, want4) != 0) {
            printf("R29 err-cap 44: %s\n", line);
            return fail("r29_err_fallback");
        }
        line[0] = 'Z'; line[1] = 0;
        if (ntx_ipc_share_event_json(line, 32, &ev) != -1) return fail("r29_err_tiny_cap");
        if (line[0] != 0) return fail("r29_err_torn");
        if (ok("r29_share_event_fallback")) return 1;

        /* The shipped consumer (ipc_share_events in ntx_main.c) over a real queue:
           one ready event → exactly one ok:1 line, the event retired ONCE, and a
           later push attempt must not resurrect it (S07's retry machinery may
           delay an event, never spin on one). */
        {
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-r29";
            if (mkdir("/tmp/ntx-ipc-r29", 0755) != 0 && errno != EEXIST) return fail("r29_dir");
            ntx_session *s = mk(&nx, &cfg);
            FILE *wf = fopen("/tmp/ntx-ipc-r29/r29.bin", "wb");
            if (!wf) { drop(s, nx); return fail("r29_file"); }
            fputs("0123456789", wf);
            fclose(wf);
            ntx_share_err se = NTX_SHARE_OK;
            int ti = ntx_session_share_add(s, "/tmp/ntx-ipc-r29/r29.bin", NULL, &se);
            if (ti < 0) { drop(s, nx); printf("R29 share_add err=%d\n", (int)se); return fail("r29_add"); }
            struct ntx_share_slot *sl = s->share[ti];
            sl->st = NTX_SHARE_READY;
            snprintf(sl->name, sizeof sl->name, "r29.bin");
            snprintf(sl->magnet, sizeof sl->magnet, "magnet:?xt=urn:btih:%040x", 5);
            snprintf(sl->torrent_path, sizeof sl->torrent_path, "/tmp/ntx-ipc-r29/r29.bin.torrent");
            share_evq_push(sl);

            int save_out = dup(1);
            fflush(stdout);
            unlink("/tmp/ntx-ipc-r29.ndjson");
            int capfd = open("/tmp/ntx-ipc-r29.ndjson", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (capfd < 0) { dup2(save_out, 1); close(save_out); drop(s, nx); return fail("r29_cap_file"); }
            dup2(capfd, 1);
            close(capfd);
            ipc_share_events(s);  /* the consumer, as main() calls it per tick */
            ipc_share_events(s);  /* the queue is empty now — must print nothing */
            share_evq_push(sl);   /* R4: ev_ready is spent — a re-push is a no-op */
            ipc_share_events(s);
            fflush(stdout);
            dup2(save_out, 1);
            close(save_out);
            ntx_share_event pev;
            int polled = ntx_session_share_poll_event(s, &pev);
            drop(s, nx);
            if (polled != 0) return fail("r29_event_republished");
            FILE *rf = fopen("/tmp/ntx-ipc-r29.ndjson", "rb");
            if (!rf) return fail("r29_cap_read");
            char bl[40960];
            int nshare = 0;
            while (fgets(bl, sizeof bl, rf)) {
                if (!strstr(bl, "\"type\":\"share\"")) continue;
                nshare++;
                if (!strstr(bl, "\"ok\":1") || strstr(bl, "\"code\":\"io\"")) {
                    fclose(rf); printf("R29 pump line: %s\n", bl);
                    return fail("r29_pump_normal_line");
                }
            }
            fclose(rf);
            if (nshare != 1) { printf("R29 share lines: %d\n", nshare); return fail("r29_pump_line_count"); }
            if (ok("r29_consumer_single_event")) return 1;
        }

        /* The CLI --share consumer (share_drain_events) reads the event struct, not
           the JSON line, so an emitter failure cannot silence it. Pinned here: a
           ready event delivers the magnet and keeps the run alive; a failure event
           returns fatal, which is what makes main() leave the loop with exit 1
           (the alternative is waiting for a share that will never be ready). */
        {
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-r29";
            ntx_session *s = mk(&nx, &cfg);
            ntx_share_err se = NTX_SHARE_OK;
            int ti = ntx_session_share_add(s, "/tmp/ntx-ipc-r29/r29.bin", NULL, &se);
            if (ti < 0) { drop(s, nx); return fail("r29_cli_add"); }
            struct ntx_share_slot *sl = s->share[ti];
            sl->st = NTX_SHARE_FAILED;
            sl->err = NTX_SHARE_E_CHANGED;
            share_evq_push(sl);
            int save_out = dup(1), save_err = dup(2);
            fflush(stdout);
            fflush(stderr);
            unlink("/tmp/ntx-ipc-r29-cli.out");
            int capfd = open("/tmp/ntx-ipc-r29-cli.out", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (capfd < 0) { dup2(save_out, 1); close(save_out); dup2(save_err, 2); close(save_err);
                             drop(s, nx); return fail("r29_cli_file"); }
            dup2(capfd, 1);
            dup2(capfd, 2);
            close(capfd);
            int fatal = 0;
            int drained = share_drain_events(s, &fatal);
            fflush(stdout);
            fflush(stderr);
            dup2(save_out, 1);
            dup2(save_err, 2);
            close(save_out);
            close(save_err);
            drop(s, nx);
            if (!drained || !fatal) return fail("r29_cli_fatal_exit");
            FILE *rf = fopen("/tmp/ntx-ipc-r29-cli.out", "rb");
            if (!rf) return fail("r29_cli_read");
            char bl[512];
            int saw_fail_msg = 0;
            while (fgets(bl, sizeof bl, rf)) if (strstr(bl, "ntx: share failed:")) saw_fail_msg = 1;
            fclose(rf);
            if (!saw_fail_msg) return fail("r29_cli_msg");
            if (ok("r29_cli_share_failure_exits")) return 1;
        }

        /* The consumer over an EMITTER FAILURE: the shipped ipc_share_events must
           print the fallback for the event it could not build, print it exactly
           ONCE (the event leaves the queue either way — S07's retry covers the
           UNPLACED case, never this one), and leave the queue usable: the same
           slot's later error event and another slot's ready line still come out.
           The hook stands in for the one path that reaches the fallback (a ready
           line that will not fit the escape buffer), which the 40 KiB consumer
           buffer above pins as unreachable in production. */
        {
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-r29";
            ntx_session *s = mk(&nx, &cfg);
            FILE *fa = fopen("/tmp/ntx-ipc-r29/qa.bin", "wb");
            FILE *fb = fopen("/tmp/ntx-ipc-r29/qb.bin", "wb");
            if (!fa || !fb) { if (fa) fclose(fa); if (fb) fclose(fb); drop(s, nx); return fail("r29_q_file_setup"); }
            fputs("0123456789", fa); fclose(fa);
            fputs("9876543210", fb); fclose(fb);
            ntx_share_err se = NTX_SHARE_OK;
            int ta = ntx_session_share_add(s, "/tmp/ntx-ipc-r29/qa.bin", NULL, &se);
            int tb = ntx_session_share_add(s, "/tmp/ntx-ipc-r29/qb.bin", NULL, &se);
            if (ta < 0 || tb < 0 || ta == tb) { drop(s, nx); return fail("r29_q_add"); }
            struct ntx_share_slot *sla = s->share[ta], *slb = s->share[tb];
            sla->st = NTX_SHARE_READY;
            snprintf(sla->name, sizeof sla->name, "a.bin");
            snprintf(sla->magnet, sizeof sla->magnet, "magnet:?xt=urn:btih:%040x", 21);
            snprintf(sla->torrent_path, sizeof sla->torrent_path, "/tmp/a.torrent");
            slb->st = NTX_SHARE_READY;
            snprintf(slb->name, sizeof slb->name, "b.bin");
            snprintf(slb->magnet, sizeof slb->magnet, "magnet:?xt=urn:btih:%040x", 22);
            snprintf(slb->torrent_path, sizeof slb->torrent_path, "/tmp/b.torrent");
            share_evq_push(sla); /* only A is queued while the emitter is armed */
            ntx_ipc_test_set_share_emit_fail(1);
            int save_out = dup(1);
            fflush(stdout);
            unlink("/tmp/ntx-ipc-r29-q.ndjson");
            int capfd = open("/tmp/ntx-ipc-r29-q.ndjson", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (capfd < 0) { dup2(save_out, 1); close(save_out); ntx_ipc_test_set_share_emit_fail(0);
                             drop(s, nx); return fail("r29_q_file"); }
            dup2(capfd, 1);
            close(capfd);
            ipc_share_events(s);       /* A's ready event: one io fallback ... */
            ipc_share_events(s);       /* ... and nothing more — the event left the queue */
            ntx_ipc_test_set_share_emit_fail(0);
            share_evq_push(slb);       /* B's ready line: the queue still works */
            sla->st = NTX_SHARE_FAILED; /* A's own error event: real code wins */
            sla->err = NTX_SHARE_E_CHANGED;
            share_evq_push(sla);
            ipc_share_events(s);       /* ok:1 for B, ok:0/changed for A */
            ipc_share_events(s);
            fflush(stdout);
            dup2(save_out, 1);
            close(save_out);
            ntx_share_event pev;
            int polled = ntx_session_share_poll_event(s, &pev);
            drop(s, nx);
            if (polled != 0) return fail("r29_q_event_left");
            FILE *rf = fopen("/tmp/ntx-ipc-r29-q.ndjson", "rb");
            if (!rf) return fail("r29_q_read");
            char bl[40960];
            char want_a[64], want_b[64];
            snprintf(want_a, sizeof want_a, "{\"type\":\"share\",\"i\":%d,\"ok\":0,\"code\":\"io\"}", ta);
            snprintf(want_b, sizeof want_b, "{\"type\":\"share\",\"i\":%d,\"ok\":0,\"code\":\"changed\"}", ta);
            int n_io_a = 0, n_io_b = 0, n_chg = 0, n_other = 0;
            while (fgets(bl, sizeof bl, rf)) {
                size_t len = strlen(bl);
                while (len && (bl[len - 1] == '\n' || bl[len - 1] == '\r')) bl[--len] = 0;
                if (!strstr(bl, "\"type\":\"share\"")) continue;
                if (!ipc_ok_local(bl) || !utf8_strict(bl, NULL)) {
                    fclose(rf); printf("R29 queue line malformed: %s\n", bl);
                    return fail("r29_q_line_valid");
                }
                if (!strcmp(bl, want_a)) n_io_a++;
                else if (!strcmp(bl, want_b)) n_chg++;
                else if (strstr(bl, "\"ok\":1")) n_io_b++; /* B's ready line, still flowing */
                else n_other++;
            }
            fclose(rf);
            if (n_io_a != 1) { printf("R29 io fallbacks for i=%d: %d\n", ta, n_io_a); return fail("r29_q_fallback_count"); }
            if (n_io_b != 1) { printf("R29 ok:1 lines: %d\n", n_io_b); return fail("r29_q_next_event"); }
            if (n_chg != 1) { printf("R29 changed lines: %d\n", n_chg); return fail("r29_q_after_fallback"); }
            if (n_other) return fail("r29_q_extra_line");
            if (ok("r29_consumer_fallback_once")) return 1;
        }
    }

    { /* ── S26 · R36: every accept path shares ONE name gate ──────────────────
         The JSON `share` command takes the basename of `path` as the torrent
         name, so it is gated by ntx_share_name_ok — the same function the CLI
         and the --share-from metainfo name go through. Pre-fix the JSON path was
         already gated, but ntx_share_build_info carried a SECOND rule that knew
         the control characters and nothing about UTF-8, so the two could disagree
         (pinned for the builder in t_share_meta.c). What the §11.1 escaping could
         smuggle in is exactly what the gate must refuse: an escaped control byte
         decodes into the name, and a name is one field of the status line and one
         magnet dn=. The verdict is the pinned "bad_arg" of a rejected name. ── */
        ntx_config cfg;
        ntx_netx *nx;
        char dir[96], line[512], out[2048];

        memset(&cfg, 0, sizeof cfg);
        snprintf(dir, sizeof dir, "test/.scratch/ntx-ipc-r36");
        cfg.store_dir = dir;
        if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return fail("r36_scratch");
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) return fail("r36_dir");
        {
            char real[192];
            snprintf(real, sizeof real, "%s/good.bin", dir);
            FILE *wf = fopen(real, "wb");
            if (!wf) return fail("r36_file");
            fputs("0123456789", wf);
            fclose(wf);
        }
        ntx_session *s = mk(&nx, &cfg);

        /* The name gate runs AFTER the open (docs/json-api.md: open, S_ISREG,
           size, name), so every hostile name must really exist on disk —
           otherwise the verdict would be "io" from ENOENT and the case would
           prove nothing about the name. */
        static const struct { const char *tag, *name, *disk; } bad[] = {
            { "ctl", "\\u0001bad", "\x01" "bad" },     { "tab", "a\\tb", "a\tb" },
            { "del", "a\\u007fb", "a\x7f" "b" },       { "newline", "a\\nb", "a\nb" },
            { "cr", "a\\rb", "a\rb" },                 { "bad_utf8", "\xc3\x28", "\xc3\x28" },
            { "lone_cont", "\x80", "\x80" },
        };
        for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
            char real[192];
            snprintf(real, sizeof real, "%s/%s", dir, bad[k].disk);
            FILE *wf = fopen(real, "wb");
            if (!wf) {
                printf("R36 %s: cannot create the fixture\n", bad[k].tag);
                drop(s, nx);
                return fail("r36_fixture");
            }
            fputs("0123456789", wf);
            fclose(wf);
            snprintf(line, sizeof line, "{\"cmd\":\"share\",\"seq\":6%zu,\"path\":\"%s/%s\"}", k, dir,
                     bad[k].name);
            ntx_ipc_dispatch(s, line, out, sizeof out);
            if (!strstr(out, "\"code\":\"bad_arg\"") || !strstr(out, "\"cmd\":\"share\"")) {
                printf("R36 %s reply: %s\n", bad[k].tag, out);
                drop(s, nx);
                return fail("r36_name_rejected");
            }
        }
        /* a legal multi-byte name is accepted, not refused (S15: an over-long name
           is CUT on a character boundary, never rejected) */
        snprintf(line, sizeof line, "{\"cmd\":\"share\",\"seq\":70,\"path\":\"%s/\xc5\xbc\xc3\xb3.bin\"}", dir);
        {
            char real[192];
            snprintf(real, sizeof real, "%s/\xc5\xbc\xc3\xb3.bin", dir);
            FILE *wf = fopen(real, "wb");
            if (!wf) { drop(s, nx); return fail("r36_u8_file"); }
            fputs("0123456789", wf);
            fclose(wf);
        }
        ntx_ipc_dispatch(s, line, out, sizeof out);
        if (!strstr(out, "\"ok\":1")) {
            printf("R36 utf8 name reply: %s\n", out);
            drop(s, nx);
            return fail("r36_utf8_accepted");
        }
        for (int ti = 0; ti < NTX_SESSION_MAX_TTS; ti++)
            if (ti != 0 && ntx_session_share_state(s, ti) != NTX_SHARE_NONE) {
                drop(s, nx);
                return fail("r36_only_good_slot");
            }
        drop(s, nx);
        if (ok("r36_ipc_one_name_gate")) return 1;
    }

    { /* ── R31: every magnet ntx emits must fit what `add` accepts (spec §11) ──
         The generator capped a magnet at NTX_SHARE_MAGNET_MAX (4095 usable B) while
         the add path capped it at NTX_IPC_MAGNET_MAX (2048 B). Two limits, so they
         could drift — and one share produced a link ntx itself refused to re-add.
         They are ONE constant now; this block is the invariant. The parity itself is
         a _Static_assert in ntx_ipc.h, next to the two macros it constrains. */

        /* Widest magnet the gates can actually produce. The name field is char[512]
           in the slot and in the event, so the generator sees at most 511 B, and the
           S26 gate (valid UTF-8, no control bytes, no '/') plus S15 (cut on a
           character boundary) leave 255 × U+0142 + one '!' as the worst encodable
           name: 2 input bytes → 6 output bytes each. Trackers: the built-in pinned
           list is the only list a share ever gets (share_trk_list), so its encoded
           total is the real tracker term. */
        char nm[512];
        for (int k = 0; k < 255; k++) { nm[2 * k] = (char)0xC5; nm[2 * k + 1] = (char)0x82; }
        nm[510] = '!';
        nm[511] = 0; /* 511 B = the full field: 255 × U+0142 + one unreserved byte */
        int nb2 = ntx_share_tracker_count();
        const char *tl[NTX_SESSION_MAX_TRK];
        if (nb2 < 2 || nb2 > NTX_SESSION_MAX_TRK) return fail("r31_trk_setup");
        for (int k = 0; k < nb2; k++) tl[k] = ntx_share_tracker_get(k)->url;
        uint8_t mih[20], mih2[32];
        for (int k = 0; k < 20; k++) mih[k] = (uint8_t)(0x10 + k);
        for (int k = 0; k < 32; k++) mih2[k] = (uint8_t)(0x40 + k);

        char mag[NTX_SHARE_MAGNET_MAX];
        if (ntx_share_magnet(mag, sizeof mag, mih, mih2, nm, tl, nb2) != 0)
            return fail("r31_gen_worst_case");
        {
            size_t want = (sizeof("magnet:?xt=urn:btih:") - 1) + 40 +
                          (sizeof("&xt=urn:btmh:1220") - 1) + 64 +
                          (sizeof("&dn=") - 1) + r31_pct_len(nm);
            for (int k = 0; k < nb2; k++) want += (sizeof("&tr=") - 1) + r31_pct_len(tl[k]);
            if (strlen(mag) != want) {
                printf("R31 worst-case magnet %zu B, oracle says %zu B\n", strlen(mag), want);
                return fail("r31_len_oracle");
            }
            printf("R31 worst-case share magnet = %zu B (magnet cap %d, frame %d, %d trackers)\n",
                   strlen(mag), NTX_IPC_MAGNET_MAX, NTX_IPC_LINE_MAX, nb2);
            if ((size_t)sizeof mag - 1 < (size_t)NTX_IPC_MAGNET_MAX)
                return fail("r31_gen_cap_below_add_cap");
            if (want > (size_t)NTX_IPC_MAGNET_MAX) {
                printf("R31 note: the gates now allow a %zu B magnet — %d B past the add cap\n",
                       want, (int)(want - (size_t)NTX_IPC_MAGNET_MAX));
                return fail("r31_gates_exceed_add_cap");
            }
            /* one length, measured on the buffers, not only on the macros */
            if (sizeof(((ntx_ipc_req *)0)->magnet) != sizeof(((ntx_share_event *)0)->magnet))
                return fail("r31_buffers_drifted");
            if (strlen(mag) + (sizeof("{\"cmd\":\"add\",\"magnet\":\"") - 1) +
                    (sizeof("\"}") - 1) >= (size_t)NTX_IPC_LINE_MAX)
                return fail("r31_frame_headroom");
        }

        /* The round trip over the SHIPPED framer: feed the JSON line, require the
           framer to accept the frame (§3.7), then require add to take it whole. */
        {
            char line[4608];
            snprintf(line, sizeof line, "{\"cmd\":\"add\",\"magnet\":\"%s\"}", mag);
            ntx_ipc_sink snk = { 0, r31_cap_cb, r31_bad_cb };
            r31_nline = r31_nbad = 0;
            ntx_ipc_reader_init(&ipc_t_rd);
            ntx_ipc_feed(&ipc_t_rd, line, strlen(line), &snk);
            if (r31_nline || r31_nbad) return fail("r31_frame_partial"); /* no \n yet */
            ntx_ipc_feed(&ipc_t_rd, "\n", 1, &snk);
            if (r31_nbad || r31_nline != 1) {
                printf("R31 frame: %zu B line → %d lines, %d bad (§3.7 dropped it)\n",
                       strlen(line), r31_nline, r31_nbad);
                return fail("r31_frame_dropped");
            }
            ntx_ipc_req r;
            ntx_ipc_parse(r31_line, &r);
            if (r.pre != NTX_IPC_OK || !r.has_magnet || strcmp(r.magnet, mag) != 0) {
                printf("R31 add verdict %d on a %zu B generated magnet (cap %d)\n",
                       (int)r.pre, strlen(mag), NTX_IPC_MAGNET_MAX);
                return fail("r31_gen_within_add_cap");
            }
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-r31";
            ntx_session *s = mk(&nx, &cfg);
            char out2[1024];
            if (ntx_ipc_dispatch(s, r31_line, out2, sizeof out2) != 0 || !strstr(out2, "\"ok\":1")) {
                printf("R31 add reply: %s\n", out2);
                drop(s, nx);
                return fail("r31_add_rejects_own_magnet");
            }
            int ntrk = s->trk_n[0], nurl = 0;
            for (int k = 0; k < nb2; k++)
                if (s->trk_urls[0][k][0]) nurl++;
            int name_ok = strcmp(s->tts[0].name, nm) == 0;
            drop(s, nx);
            if (ntrk != nb2 || nurl != nb2) {
                printf("R31 add kept %d urls for trk_n=%d, expected %d\n", nurl, ntrk, nb2);
                return fail("r31_add_trackers");
            }
            if (!name_ok) return fail("r31_add_name"); /* the dn= reached the slot */
        }
        /* the magnet the generator produced is still a magnet, by the parser's eye */
        {
            ntx_magnet mg;
            if (ntx_magnet_parse(mag, &mg) != 0) return fail("r31_parse_back");
            if (mg.n_trackers != nb2) return fail("r31_parse_back_trackers");
            if (!mg.has_name || strlen(mg.name) != 511 || memcmp(mg.name, nm, 511) != 0)
                return fail("r31_parse_back_name");
            if (memcmp(mg.info_hash, mih, 20) != 0 || !mg.has_v2 ||
                memcmp(mg.ih_v2, mih2, 32) != 0)
                return fail("r31_parse_back_hashes");
        }

        /* Guards: an ordinary share magnet is untouched by the shared cap, and the
           store file's stem is a NAME_MAX basename, not a magnet field (its cut
           rules live in t_share_out.c's path cases). */
        {
            int nb2 = ntx_share_tracker_count();
            const char *list[32];
            for (int k = 0; k < nb2; k++) list[k] = ntx_share_tracker_get(k)->url;
            char m2[NTX_SHARE_MAGNET_MAX];
            if (ntx_share_magnet(m2, sizeof m2, mih, mih2, "photo.jpg", list, nb2) != 0)
                return fail("r31_guard_ordinary_build");
            if (strstr(m2, "dn=photo.jpg") == NULL || strlen(m2) > 1024) {
                printf("R31 ordinary magnet: %zu B: %s\n", strlen(m2), m2);
                return fail("r31_guard_ordinary_shape");
            }
            char nm2[256], p2[NTX_SHARE_PATH_MAX];
            memset(nm2, 'a', 250);
            nm2[250] = 0;
            if (ntx_share_torrent_path(p2, sizeof p2, "test/.scratch", nm2, mih) != 0)
                return fail("r31_guard_stem_build");
            const char *bn = strrchr(p2, '/');
            if (!bn || strlen(bn + 1) != 255 || strstr(bn, ".torrent") == NULL) {
                printf("R31 stem basename: %s\n", bn ? bn : "(none)");
                return fail("r31_guard_stem_shape");
            }
        }

        /* NON-VACUITY PROBE. The gates above already bound a real share magnet at
           1946 B, INSIDE the 2048 B add cap — so the round trip alone would still
           pass if the two limits drifted apart again. Two probes say otherwise.
           (a) the add bound is real and reachable: a 2049 B magnet is `io` (the exact
               pre-fix refusal a generated over-long link got), while one byte less is
               accepted — so the case below is not vacuous;
           (b) drive the generator one name byte past that same boundary — what any
               future gate relaxation is — and require an honest refusal. Pre-fix the
               generator happily emitted those 2049 B (its own cap was 4095) and add
               answered `io`: the self-incompatibility of R31. */
        {
            static char pn[1024], p0[704], p1[704];
            const char *pl[2] = { p0, p1 };
            memset(p0, 'z', 700); p0[700] = 0; /* unreserved: 1 output byte each */
            memset(p1, 'z', 700); p1[700] = 0;
            size_t head = (sizeof("magnet:?xt=urn:btih:") - 1) + 40 +
                          (sizeof("&xt=urn:btmh:1220") - 1) + 64 + (sizeof("&dn=") - 1) +
                          2 * ((sizeof("&tr=") - 1) + 700);
            size_t fit = (size_t)NTX_IPC_MAGNET_MAX - head; /* name bytes landing ON the cap */
            if (fit == 0 || fit >= sizeof pn) return fail("r31_probe_setup");
            char big[NTX_SHARE_MAGNET_MAX];
            memset(pn, 'a', fit + 2);
            pn[fit] = 0; /* → exactly the cap: built, and add takes it */
            if (ntx_share_magnet(big, sizeof big, mih, mih2, pn, pl, 2) != 0)
                return fail("r31_probe_boundary_ok");
            if (strlen(big) != (size_t)NTX_IPC_MAGNET_MAX) {
                printf("R31 probe: name %zu B → %zu B, cap %d\n", fit, strlen(big),
                       NTX_IPC_MAGNET_MAX);
                return fail("r31_probe_boundary_len");
            }
            { /* (a) the add bound is real and reachable: hand the reader the same
                   magnet with one byte appended (a magnet the generator is now
                   refusing to build) and the verdict must be `io` — the exact
                   pre-fix refusal — while one byte less is accepted whole. */
                char line[4608], over[NTX_SHARE_MAGNET_MAX + 2];
                ntx_ipc_req rr;
                memcpy(over, big, strlen(big));
                over[strlen(big)] = 'a';
                over[strlen(big) + 1] = 0;
                snprintf(line, sizeof line, "{\"cmd\":\"add\",\"magnet\":\"%s\"}", over);
                ntx_ipc_parse(line, &rr);
                if (rr.pre != NTX_IPC_E_IO) {
                    printf("R31 probe: a %zu B magnet got verdict %d, expected io(%d)\n",
                           strlen(over), (int)rr.pre, (int)NTX_IPC_E_IO);
                    return fail("r31_probe_add_bound_real");
                }
                snprintf(line, sizeof line, "{\"cmd\":\"add\",\"magnet\":\"%s\"}", big);
                ntx_ipc_parse(line, &rr);
                if (rr.pre != NTX_IPC_OK || strlen(rr.magnet) != (size_t)NTX_IPC_MAGNET_MAX)
                    return fail("r31_probe_add_bound_off_by_one");
            }
            /* (b) the generator must refuse the one-byte overspill, not emit it */
            pn[fit] = 'a';
            pn[fit + 1] = 0; /* strlen = fit + 1 → the magnet would be 2049 B */
            big[0] = 'Z';
            if (ntx_share_magnet(big, sizeof big, mih, mih2, pn, pl, 2) == 0) {
                printf("R31 probe: emitted a %zu B magnet, %d B past the add cap — the "
                       "pre-fix behaviour (add answers io for it)\n",
                       strlen(big), (int)(strlen(big) - (size_t)NTX_IPC_MAGNET_MAX));
                return fail("r31_probe_refuses_overspill");
            }
            if (big[0]) return fail("r31_probe_no_torn_magnet");
        }
        if (ok("r31_one_magnet_limit")) return 1;
    }

    { /* ── R33 · S29: a magnet that cannot be written to stdout must be an
         honest failure, never a silent success ────────────────────────────────
         The bug: share_drain_events printed the magnet with puts() + fflush() and
         checked nothing, so on ENOSPC (stdout = /dev/full) or EPIPE (stdout is a
         pipe whose reader died) the operator saw `ntx: shared — …` on stderr and
         exit 0 while the link — the ONE thing `ntx --share=f > link.txt` is for —
         never arrived. The shipped consumer is driven here over two real, broken
         fds: /dev/full (ENOSPC at the flush) and a pipe with no reader (EPIPE at
         the write). SIGPIPE is ignored for the block, exactly as main() does at
         ntx_main.c:500, so EPIPE is an errno and not a death. Pre-fix: drained 0,
         fatal 0, no message — the run kept serving and exited 0. */
        int efull = open("/dev/full", O_WRONLY);
        if (efull < 0) { /* the node is not there: nothing to assert, say so loudly */
            printf("SKIP r33 (no /dev/full on this host)\n");
        } else {
            signal(SIGPIPE, SIG_IGN); /* the shipped binary does the same before the loop */
            ntx_config cfg;
            ntx_netx *nx;
            memset(&cfg, 0, sizeof cfg);
            cfg.store_dir = "/tmp/ntx-ipc-r33";
            if (mkdir("/tmp/ntx-ipc-r33", 0755) != 0 && errno != EEXIST) return fail("r33_dir");
            FILE *wf = fopen("/tmp/ntx-ipc-r33/r33.bin", "wb");
            if (!wf) return fail("r33_file");
            fputs("0123456789", wf);
            fclose(wf);

            /* one READY event, re-armed per case (each case spends it) */
            ntx_session *s = mk(&nx, &cfg);
            ntx_share_err se = NTX_SHARE_OK;
            int ti = ntx_session_share_add(s, "/tmp/ntx-ipc-r33/r33.bin", NULL, &se);
            if (ti < 0) { drop(s, nx); return fail("r33_add"); }
            struct ntx_share_slot *sl = s->share[ti];
            sl->st = NTX_SHARE_READY;
            snprintf(sl->name, sizeof sl->name, "r33.bin");
            snprintf(sl->magnet, sizeof sl->magnet, "magnet:?xt=urn:btih:%040x", 33);
            snprintf(sl->torrent_path, sizeof sl->torrent_path, "/tmp/ntx-ipc-r33/r33.torrent");

            /* (0) positive control, taken while the stream is still pristine: a
               healthy stdout gets the whole magnet AND the `shared —` note, and
               the run stays alive. The two cases below must not change this. */
            share_evq_push(sl);
            int save_out = dup(1), save_err = dup(2);
            fflush(stdout); fflush(stderr);
            unlink("/tmp/ntx-ipc-r33-ok.txt");
            unlink("/tmp/ntx-ipc-r33-ok.err");
            int okfd = open("/tmp/ntx-ipc-r33-ok.txt", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            int okefd = open("/tmp/ntx-ipc-r33-ok.err", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (okfd < 0 || okefd < 0) { dup2(save_out, 1); close(save_out); dup2(save_err, 2);
                                         close(save_err); drop(s, nx); return fail("r33_ok_file"); }
            dup2(okfd, 1); dup2(okefd, 2); close(okfd); close(okefd);
            int fatal = 0;
            int drained = share_drain_events(s, &fatal);
            fflush(stdout); fflush(stderr);
            dup2(save_out, 1); dup2(save_err, 2);
            close(save_out); close(save_err);
            if (drained || fatal) { printf("R33 healthy stdout: drained=%d fatal=%d, want 0/0\n",
                                           drained, fatal); drop(s, nx); return fail("r33_ok_fatal"); }
            { FILE *rf = fopen("/tmp/ntx-ipc-r33-ok.txt", "rb"); char bl[256]; int mag = 0;
              if (!rf) { drop(s, nx); return fail("r33_ok_read"); }
              while (fgets(bl, sizeof bl, rf)) if (strncmp(bl, "magnet:?xt=urn:btih:", 20) == 0) mag = 1;
              fclose(rf);
              if (!mag) { printf("R33 healthy stdout: no magnet on stdout\n");
                          drop(s, nx); return fail("r33_ok_magnet"); } }
            { FILE *rf = fopen("/tmp/ntx-ipc-r33-ok.err", "rb"); char bl[256]; int note = 0;
              if (!rf) { drop(s, nx); return fail("r33_ok_err_read"); }
              while (fgets(bl, sizeof bl, rf)) if (strstr(bl, "ntx: shared \xe2\x80\x94")) note = 1;
              fclose(rf);
              if (!note) { printf("R33 healthy stdout: no 'shared —' note on stderr\n");
                           drop(s, nx); return fail("r33_ok_note"); } }
            if (ok("r33_healthy_stdout_unchanged")) return 1;

            /* (a) ENOSPC: stdout is /dev/full. */
            sl->ev_ready = 0; /* (0) spent the slot's one-shot flag — re-arm it */
            share_evq_push(sl);
            /* A failed flush leaves the stream's error indicator set for good
               (glibc), so each case starts from a clean stream. In production the
               process leaves the loop right after the failure and never writes
               stdout again, so the stale flag is never observed. */
            clearerr(stdout);
            save_out = dup(1); save_err = dup(2);
            fflush(stdout); fflush(stderr);
            unlink("/tmp/ntx-ipc-r33-cli.err");
            int errfd = open("/tmp/ntx-ipc-r33-cli.err", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (errfd < 0) { dup2(save_out, 1); close(save_out); dup2(save_err, 2); close(save_err);
                             drop(s, nx); return fail("r33_errfile"); }
            dup2(errfd, 2); close(errfd);
            dup2(efull, 1);
            fatal = 0; drained = 0;
            drained = share_drain_events(s, &fatal);
            fflush(stdout); fflush(stderr);
            dup2(save_out, 1); dup2(save_err, 2);
            close(save_out); close(save_err);
            if (!drained || !fatal) {
                printf("R33 /dev/full: drained=%d fatal=%d — the magnet was dropped "
                       "silently and the run would have exited 0\n", drained, fatal);
                drop(s, nx); return fail("r33_enospc_fatal");
            }
            { FILE *rf = fopen("/tmp/ntx-ipc-r33-cli.err", "rb"); char bl[512]; int saw = 0, note = 0;
              if (!rf) { drop(s, nx); return fail("r33_enospc_read"); }
              while (fgets(bl, sizeof bl, rf)) {
                  if (strstr(bl, "ntx: cannot write the magnet")) saw = 1;
                  if (strstr(bl, "ntx: shared \xe2\x80\x94")) note = 1;
              }
              fclose(rf);
              if (!saw) { printf("R33 /dev/full: no 'cannot write the magnet' on stderr\n");
                          drop(s, nx); return fail("r33_enospc_msg"); }
              /* the success note belongs to a link the operator never got */
              if (note) { printf("R33 /dev/full: 'shared —' note printed next to the failure\n");
                          drop(s, nx); return fail("r33_enospc_no_note"); } }
            if (ok("r33_enospc_reports_failure")) return 1;

            /* (b) EPIPE: stdout is a pipe whose read end is already closed. */
            int pfds[2];
            if (pipe(pfds) != 0) { drop(s, nx); return fail("r33_pipe"); }
            close(pfds[0]);
            sl->ev_ready = 0; /* (a) spent the slot's one-shot flag — re-arm it */
            share_evq_push(sl);
            clearerr(stdout); /* (a) left the indicator set; same reasoning as above */
            save_out = dup(1); save_err = dup(2);
            fflush(stdout); fflush(stderr);
            unlink("/tmp/ntx-ipc-r33-pipe.err");
            errfd = open("/tmp/ntx-ipc-r33-pipe.err", O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (errfd < 0) { dup2(save_out, 1); close(save_out); dup2(save_err, 2); close(save_err);
                             close(pfds[1]); drop(s, nx); return fail("r33_pipe_errfile"); }
            dup2(errfd, 2); close(errfd);
            dup2(pfds[1], 1);
            fatal = 0; drained = 0;
            drained = share_drain_events(s, &fatal);
            fflush(stdout); fflush(stderr);
            dup2(save_out, 1); dup2(save_err, 2);
            close(save_out); close(save_err); close(pfds[1]);
            if (!drained || !fatal) {
                printf("R33 closed pipe: drained=%d fatal=%d — EPIPE on the link went "
                       "unnoticed\n", drained, fatal);
                drop(s, nx); return fail("r33_epipe_fatal");
            }
            { FILE *rf = fopen("/tmp/ntx-ipc-r33-pipe.err", "rb"); char bl[512]; int saw = 0;
              if (!rf) { drop(s, nx); return fail("r33_epipe_read"); }
              while (fgets(bl, sizeof bl, rf)) if (strstr(bl, "ntx: cannot write the magnet")) saw = 1;
              fclose(rf);
              if (!saw) { printf("R33 closed pipe: no 'cannot write the magnet' on stderr\n");
                          drop(s, nx); return fail("r33_epipe_msg"); } }
            /* EPIPE is reported through errno, not through a signal death: the
               block ran to this line instead of being killed by SIGPIPE. */
            drop(s, nx);
            if (ok("r33_epipe_reports_failure")) return 1;
        }
    }

    { /* ── V04 (a)+(b) · §6: the REAL command path, ack → share → stats ───────
         docs/json-api.md §"Event ordering": "Per event-loop tick the order is
         always `ack` first, then `share`, then the `stats` snapshot." Today
         nothing on the command path pins that. `bud_order`/`bud2_order` pin the
         64-lines-per-tick budget and the post-quit stop over ping/add lines only —
         neither has a share, neither sees a "share" event, and `c3_dispatch_share`
         stops at the synchronous ack (its own comment says the ready line is
         "covered synthetically in c3_share_event_json"). This block drives the
         shipped ipc_pump_tick + ipc_share_events + the main() cadence snapshot in
         main()'s own order (src/ntx_main.c:561/570/573-581) over a real command
         stream on fd 0, with a real share reaching READY through the real hasher,
         the real share_finish_from and a real `started` answered by the shipped
         announce seam. ── */
        ntx_config cfg;
        ntx_netx *nx;
        char dir[96], wire[4096];
        const char *VEC = "test/vectors/share/one_piece_16k";
        if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return fail("v04_scratch");
        snprintf(dir, sizeof dir, "test/.scratch/ntx-ipc-v04");
        if (mkdir(dir, 0755) != 0 && errno != EEXIST) return fail("v04_dir");
        /* same SKIP discipline as r33's missing /dev/full and r36's missing dir */
        if (access("test/vectors/share/one_piece_16k/meta.torrent", R_OK) != 0) {
            printf("SKIP v04 (the share fixtures are not next to this test — riscv scratch root)\n");
            goto v04_done;
        }
        memset(&cfg, 0, sizeof cfg);
        cfg.store_dir = dir;

        /* The three legs of the ordering contract, in ONE stream:
           seq 1 share        → ack(1)
           seq 2 status       → stats (ipc_on_line's own NTX_IPC_F_EMIT_STATUS
                                 snapshot — production code, not the cadence one)
           the ready event    → share line (ipc_share_events)
           then the cadence   → stats line (main()'s 100 ms snapshot)
           A reordering in main() — snapshot before the drain, or the drain before
           the dispatch — is exactly what the index assertions below catch. */
        {
            int save_out = 0;
            if (v04_cap_open("test/.scratch/ntx-ipc-v04-order.ndjson", &save_out) != 0)
                return fail("v04_cap_file");
            /* the table must be the test one BEFORE the dispatch: share_add copies
               the tracker urls into the slot at add time (src/core/ntx_share.c:936) */
            v04_use_test_trackers();
            ntx_ipc_reader_init(&g_rd);
            g_ipc_open = 1; g_ipc_quit = 0; g_ipc_stash_len = 0;
            ntx_session *s = mk(&nx, &cfg);
            char p[256];
            snprintf(p, sizeof p, "%s/v04-plain.bin", dir);
            FILE *wf = fopen(p, "wb");
            if (!wf) { v04_cap_close(save_out); drop(s, nx); return fail("v04_plain_file"); }
            for (int k = 0; k < 4096; k++) fputc(k & 0xff, wf);
            fclose(wf);
            snprintf(wire, sizeof wire,
                     "{\"cmd\":\"share\",\"seq\":1,\"path\":\"%s\"}\n"
                     "{\"cmd\":\"status\",\"seq\":2}\n", p);
            if (feed_stdin(wire, strlen(wire)) != 0) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_stdin");
            }
            ipc_pump_tick(s); /* ack(1) + the status snapshot, in dispatch order */
            if (ntx_session_share_state(s, 0) != NTX_SHARE_HASHING) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_plain_hashing");
            }
            /* The async leg: hasher → share_finish → ANNOUNCING → `started` → READY,
               all through ntx_session_tick and the HTTP pump, nothing forced. The
               mapping is parked exactly like t_share_session.c's pm_park (a PENDING
               mapping holds `started` back, §5.5), the tracker table is the test one
               and the announce goes out through the shipped seam. */
            v04_use_test_trackers();
            v04_pm_park(s);
            int (*saved_get)(const char *, uint8_t *, size_t, size_t *) = strk_http_get;
            v04_n_announce = 0;
            strk_http_get = v04_http_get;
            int pr = v04_pump_ready(s, 0);
            strk_http_get = saved_get;
            if (pr != 0 || v04_n_announce < 1) {
                v04_cap_close(save_out); drop(s, nx);
                printf("V04 plain share: ready=%d announces=%d\n", pr, v04_n_announce);
                return fail("v04_plain_not_ready");
            }
            ipc_share_events(s); /* the share line — after the ack, by contract */
            ipc_share_events(s); /* the queue is drained: must add nothing */
            v04_emit_stats(s);   /* the cadence snapshot of the same tick */
            fflush(stdout);
            v04_cap_close(save_out);
            g_ipc_open = 0;
            if (v04_load("test/.scratch/ntx-ipc-v04-order.ndjson") != 0) {
                drop(s, nx); return fail("v04_order_read");
            }
            /* status has NO ack (§6.2): its only footprint is the extra stats
               line, emitted by ipc_on_line itself. So the stream is exactly
               ack, stats(status), share, stats(cadence) and the two stats lines
               are identified by position, first and last. */
            int a_ack = v04_first("\"seq\":1,\"cmd\":\"share\"");
            int a_sta = v04_first("\"type\":\"stats\"");
            int s_evt = v04_first("\"type\":\"share\"");
            int s_sta = -1;
            for (int k = v04_nln - 1; k > s_evt; k--)
                if (strstr(v04_ln[k], "\"type\":\"stats\"")) { s_sta = k; break; }
            if (a_ack < 0 || s_evt < 0 || s_sta < 0 || v04_count("\"type\":\"stats\"") != 2) {
                printf("V04 order: ack=%d status=%d share=%d stats=%d lines=%d\n",
                       a_ack, a_sta, s_evt, v04_count("\"type\":\"stats\""), v04_nln);
                for (int k = 0; k < v04_nln && k < 8; k++)
                    printf("V04  line %d: %.120s\n", k, v04_ln[k]);
                drop(s, nx); return fail("v04_order_shape");
            }
            if (!(a_ack < a_sta && a_sta < s_evt && s_evt < s_sta)) {
                printf("V04 order broken: ack=%d status-stats=%d share=%d cadence-stats=%d\n",
                       a_ack, a_sta, s_evt, s_sta);
                drop(s, nx); return fail("v04_order_sequence");
            }
            /* no line lost, none doubled: exactly one ack, two stats, one share */
            if (v04_count("\"type\":\"ack\"") != 1 || v04_count("\"type\":\"share\"") != 1 ||
                v04_count("\"type\":\"stats\"") != 2) {
                printf("V04 counts: ack=%d share=%d stats=%d\n", v04_count("\"type\":\"ack\""),
                       v04_count("\"type\":\"share\""), v04_count("\"type\":\"stats\""));
                drop(s, nx); return fail("v04_order_no_loss_no_dup");
            }
            if (v04_all_lines_ok("order")) { drop(s, nx); return fail("v04_order_lines"); }
            drop(s, nx);
            if (ok("v04_ack_share_stats_order")) return 1;
        }

        { /* (b) THE SAME STREAM FOR A `share` THAT CARRIES THE `torrent` KEY.
             docs/json-api.md §share: "`torrent`: re-share under an existing
             .torrent (the --share-from equivalent) — the name, piece length and
             both hash lists come from that file and the bytes are compared
             against them, so the link does not change; the .torrent itself is
             never rewritten." Pinned here end to end over the command path: the
             ack, then the ready event whose ih/ih2/name are the fixture's OWN
             witness hashes and whose `torrent` is the path we handed in, while
             the .torrent on disk keeps its bytes (§5.6 "never rewritten"). */
            int save_out = 0;
            if (v04_cap_open("test/.scratch/ntx-ipc-v04-from.ndjson", &save_out) != 0)
                return fail("v04_from_cap");
            v04_use_test_trackers(); /* before the dispatch: share_add copies the urls */
            ntx_ipc_reader_init(&g_rd);
            g_ipc_open = 1; g_ipc_quit = 0; g_ipc_stash_len = 0;
            ntx_session *s = mk(&nx, &cfg);
            char data[256], meta[256];
            snprintf(data, sizeof data, "%s/v04-data.bin", dir);
            snprintf(meta, sizeof meta, "%s/v04-meta.torrent", dir);
            if (v04_copy_file("test/vectors/share/one_piece_16k/data.bin", data) != 0 ||
                v04_copy_file("test/vectors/share/one_piece_16k/meta.torrent", meta) != 0) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_from_fixture");
            }
            /* Snapshot the .torrent BEFORE the share runs: with a `torrent` the
               slot's torrent_path IS this file (src/core/ntx_share.c:912), so a
               "never rewritten" check taken after the fact compares the file with
               itself and can never notice a write. */
            if (v04_copy_file(meta, "test/.scratch/ntx-ipc-v04-before.torrent") != 0) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_from_before_copy");
            }
            char ih_exp[80], ih2_exp[80];
            if (v04_manifest_hex(VEC, "ih_sha1:", ih_exp, sizeof ih_exp) != 0 ||
                v04_manifest_hex(VEC, "ih_sha256:", ih2_exp, sizeof ih2_exp) != 0) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_from_manifest");
            }
            snprintf(wire, sizeof wire,
                     "{\"cmd\":\"share\",\"seq\":3,\"path\":\"%s\",\"torrent\":\"%s\"}\n"
                     "{\"cmd\":\"status\",\"seq\":4}\n", data, meta);
            if (feed_stdin(wire, strlen(wire)) != 0) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_from_stdin");
            }
            ipc_pump_tick(s);
            /* §11: the ack of a share carries i + state and NO ih — state 4 is
               VERIFY, i.e. hashing, which is exactly the synchronous verdict of a
               --share-from add. (The reply itself is asserted from the stream
               below, once it is loaded.) */
            if (ntx_session_share_state(s, 0) != NTX_SHARE_HASHING) {
                v04_cap_close(save_out); drop(s, nx); return fail("v04_from_hashing");
            }
            v04_use_test_trackers();
            v04_pm_park(s);
            int (*saved2)(const char *, uint8_t *, size_t, size_t *) = strk_http_get;
            v04_n_announce = 0;
            strk_http_get = v04_http_get;
            int pr2 = v04_pump_ready(s, 0);
            strk_http_get = saved2;
            if (pr2 != 0 || v04_n_announce < 1) {
                v04_cap_close(save_out); drop(s, nx);
                printf("V04 share-from: ready=%d announces=%d\n", pr2, v04_n_announce);
                return fail("v04_from_not_ready");
            }
            ipc_share_events(s);
            v04_emit_stats(s);
            fflush(stdout);
            v04_cap_close(save_out);
            g_ipc_open = 0;
            if (v04_load("test/.scratch/ntx-ipc-v04-from.ndjson") != 0) {
                drop(s, nx); return fail("v04_from_read");
            }
            int f_ack = v04_first("\"seq\":3,\"cmd\":\"share\"");
            int f_sta = v04_first("\"type\":\"stats\""); /* status: a line, not an ack */
            int f_evt = v04_first("\"type\":\"share\"");
            int f_cad = -1;
            for (int k = v04_nln - 1; k > f_evt; k--)
                if (strstr(v04_ln[k], "\"type\":\"stats\"")) { f_cad = k; break; }
            if (f_ack < 0 || f_sta < 0 || f_evt < 0 || f_cad < 0 ||
                !(f_ack < f_sta && f_sta < f_evt && f_evt < f_cad)) {
                printf("V04 from order: ack=%d status=%d share=%d cadence=%d lines=%d\n",
                       f_ack, f_sta, f_evt, f_cad, v04_nln);
                for (int k = 0; k < v04_nln && k < 8; k++)
                    printf("V04 from line %d: %.120s\n", k, v04_ln[k]);
                drop(s, nx); return fail("v04_from_order");
            }
            if (v04_count("\"type\":\"ack\"") != 1 || v04_count("\"type\":\"share\"") != 1 ||
                v04_count("\"type\":\"stats\"") != 2) {
                printf("V04 from counts: ack=%d share=%d stats=%d\n",
                       v04_count("\"type\":\"ack\""), v04_count("\"type\":\"share\""),
                       v04_count("\"type\":\"stats\""));
                drop(s, nx); return fail("v04_from_counts");
            }
            if (v04_all_lines_ok("from")) { drop(s, nx); return fail("v04_from_lines"); }
            const char *evl = v04_ln[f_evt];
            char got[128];
            /* the hash the link is built on IS the .torrent's, not a fresh salt */
            if (!v04_field(evl, "ih", got, sizeof got) || strcmp(got, ih_exp) != 0) {
                printf("V04 from event ih: got=%s want=%s\n%s\n", got, ih_exp, evl);
                drop(s, nx); return fail("v04_from_ih");
            }
            if (!v04_field(evl, "ih2", got, sizeof got) || strcmp(got, ih2_exp) != 0) {
                printf("V04 from event ih2: got=%s want=%s\n", got, ih2_exp);
                drop(s, nx); return fail("v04_from_ih2");
            }
            if (!v04_field(evl, "name", got, sizeof got) || strcmp(got, "one_piece_16k.bin") != 0) {
                printf("V04 from event name: got=%s\n", got);
                drop(s, nx); return fail("v04_from_name");
            }
            if (!v04_field(evl, "torrent", got, sizeof got) || strcmp(got, meta) != 0) {
                printf("V04 from event torrent: got=%s want=%s\n", got, meta);
                drop(s, nx); return fail("v04_from_torrent_field");
            }
            if (!strstr(evl, "\"ok\":1") || !strstr(evl, "\"magnet\":\"magnet:")) {
                printf("V04 from event: %s\n", evl);
                drop(s, nx); return fail("v04_from_ok_magnet");
            }
            /* the ack says VERIFY and carries no ih (§11), and the stats line of
               that same tick reports share:1 — the ordering claim is only worth
               something if the row it brackets is the share's own. */
            if (!strstr(v04_ln[f_ack], "\"i\":0,\"ok\":1,\"state\":4") ||
                strstr(v04_ln[f_ack], "\"ih\"")) {
                printf("V04 from ack: %s\n", v04_ln[f_ack]);
                drop(s, nx); return fail("v04_from_ack_shape");
            }
            if (!strstr(v04_ln[f_evt], "\"i\":0")) { drop(s, nx); return fail("v04_from_evt_i"); }
            if (!strstr(v04_ln[f_cad], "\"share\":1")) {
                printf("V04 from cadence stats: %.200s\n", v04_ln[f_cad]);
                drop(s, nx); return fail("v04_from_stats_share");
            }
            /* §5.6: with a `torrent` the metainfo is never rewritten — the file the
               share read must still match the snapshot taken before it ran. */
            if (v04_copy_file(meta, "test/.scratch/ntx-ipc-v04-after.torrent") != 0) {
                drop(s, nx); return fail("v04_from_after_copy");
            }
            if (!v04_same_bytes("test/.scratch/ntx-ipc-v04-before.torrent",
                                "test/.scratch/ntx-ipc-v04-after.torrent")) {
                printf("V04 the share rewrote %s\n", meta);
                drop(s, nx); return fail("v04_from_torrent_rewritten");
            }
            if (!v04_same_bytes("test/vectors/share/one_piece_16k/meta.torrent",
                                "test/.scratch/ntx-ipc-v04-after.torrent")) {
                printf("V04 the shared .torrent drifted from the fixture\n");
                drop(s, nx); return fail("v04_from_torrent_drift");
            }
            { /* §5.6: a --share-from share writes no metainfo. The path it WOULD
                 have used is asked of the shipped builder itself, so the name
                 cannot drift from what share_finish would have written. */
                char tp[NTX_SHARE_PATH_MAX];
                uint8_t wih[21];
                if (hexb(ih_exp, wih, sizeof wih) != 20) { drop(s, nx); return fail("v04_from_wih"); }
                if (ntx_share_torrent_path(tp, sizeof tp, dir, "one_piece_16k.bin", wih) != 0) {
                    printf("V04 the plain-path builder refused the fixture name\n");
                    drop(s, nx); return fail("v04_from_builder");
                }
                if (access(tp, F_OK) == 0) {
                    printf("V04 wrote a .torrent for a --share-from share: %s\n", tp);
                    drop(s, nx); return fail("v04_from_wrote_torrent");
                }
            }
            /* the event's ih is also what the slot now announces with — proof the
               `started` that made it READY was for the .torrent's hash */
            {
                char ih[41];
                ntx_hex40(ih, s->tts[0].info_hash);
                if (strcmp(ih, ih_exp) != 0) {
                    printf("V04 slot ih=%s want=%s\n", ih, ih_exp);
                    drop(s, nx); return fail("v04_from_slot_ih");
                }
            }
            drop(s, nx);
            if (ok("v04_share_torrent_success_path")) return 1;
        }
    }
v04_done:;

    { /* ── V04 (c) · a share event at MAXIMUM size through the emitter ────────
         r29 pins the OVERFLOW fallback (every field at 0x1f, the escape blow-up
         that no longer fits) and r31 pins the one 2048/4096 magnet length; r8 (d)
         cuts a 600-B name in half. None of them sends the longest LEGAL event
         through ntx_ipc_share_event_json and asks whether the line comes out
         complete and decodable. A line cut by a buffer off-by-one would still be
         "not the fallback", so this is the missing boundary: 511 B of legal name,
         a 2048 B legal magnet, a maximum-length torrent path, asserted byte-exact
         — not torn, not repaired (no U+FFFD anywhere), and inside the consumer
         buffer g_share_evt. ── */
        ntx_share_event ev;
        static char line[40960 + 16];
        memset(&ev, 0, sizeof ev);
        ev.i = 15; ev.ok = 1;
        for (int k = 0; k < 20; k++) ev.ih[k] = (uint8_t)(0xa0 + k);
        for (int k = 0; k < 32; k++) ev.ih2[k] = (uint8_t)(0x10 + k);

        /* longest legal name: 511 B, no control byte, no '/', valid UTF-8
           (ntx_share_name_ok's own rules) — 255 × U+0142 + one ASCII byte */
        for (int k = 0; k < 255; k++) { ev.name[2 * k] = (char)0xC5; ev.name[2 * k + 1] = (char)0x82; }
        ev.name[510] = '~';
        ev.name[511] = 0;
        if (strlen(ev.name) != 511 || !ntx_share_name_ok(ev.name) || !utf8_strict(ev.name, NULL))
            return fail("v04_max_name_setup");

        /* longest legal magnet: exactly NTX_IPC_MAGNET_MAX bytes, and NOT the
           unreserved-only 1946 B of r31 — this one carries the percent-escapes a
           real dn=/tr= produces, so the emitter's escape path is exercised at the
           same boundary. */
        {
            char nm2[512], tl1[128];
            for (int k = 0; k < 255; k++) { nm2[2 * k] = (char)0xC5; nm2[2 * k + 1] = (char)0x82; }
            nm2[510] = '~'; nm2[511] = 0;
            snprintf(tl1, sizeof tl1, "https://127.0.0.3:8080/announce");
            uint8_t mih[20], mih2[32];
            for (int k = 0; k < 20; k++) mih[k] = (uint8_t)(0xa0 + k);
            for (int k = 0; k < 32; k++) mih2[k] = (uint8_t)(0x10 + k);
            /* Grow the query of the first tracker with unreserved bytes until the
               magnet lands on the cap exactly — the length is a property of the
               generator, not something this test gets to choose. */
            int built = -1;
            for (int extra = 0; extra <= 600; extra++) {
                char q[768];
                if ((size_t)snprintf(q, sizeof q, "https://127.0.0.2:8080/announce?") >= sizeof q)
                    return fail("v04_max_q_setup");
                size_t ql = strlen(q);
                if (ql + (size_t)extra + 1 >= sizeof q) break;
                memset(q + ql, 'a', (size_t)extra);
                q[ql + (size_t)extra] = 0;
                const char *pair[2] = { q, tl1 };
                ev.magnet[0] = 0;
                if (ntx_share_magnet(ev.magnet, sizeof ev.magnet, mih, mih2, nm2, pair, 2) == 0 &&
                    strlen(ev.magnet) == (size_t)NTX_IPC_MAGNET_MAX) { built = extra; break; }
            }
            if (built < 0) {
                printf("V04 could not build a %d B magnet\n", NTX_IPC_MAGNET_MAX);
                return fail("v04_max_magnet_setup");
            }
        }
        if (strlen(ev.magnet) != (size_t)NTX_IPC_MAGNET_MAX) return fail("v04_max_magnet_len");
        /* maximum legal torrent path (ntx_share.c copies it from the request, which
           caps at NTX_IPC_ARGS_MAX-1, but the event field is NTX_SHARE_PATH_MAX) */
        memset(ev.torrent_path, '/', sizeof ev.torrent_path - 1);
        {
            size_t n = 0;
            for (size_t k = 0; k < sizeof ev.torrent_path - 5; k++) ev.torrent_path[k] = (k % 7) ? 'w' : '.';
            while (ev.torrent_path[n]) n++;
            memcpy(ev.torrent_path + n - 8, ".torrent", 9);
        }
        if (strlen(ev.torrent_path) != NTX_SHARE_PATH_MAX - 1) return fail("v04_max_path_setup");

        int w = ntx_ipc_share_event_json(line, sizeof g_share_evt, &ev);
        if (w <= 0) { printf("V04 max-size emitter refused the line (fallback?)\n"); return fail("v04_max_len"); }
        if ((size_t)w >= sizeof g_share_evt) return fail("v04_max_exceeds_consumer_buf");
        if ((size_t)w != strlen(line)) return fail("v04_max_torn_return");
        if (r8_line("max-size share event", line)) return fail("v04_max_line_invalid");
        if (strstr(line, "\xef\xbf\xbd")) {
            printf("V04 max line needed a repair: %s\n", line);
            return fail("v04_max_repaired"); /* legal input must arrive whole */
        }
        if (strncmp(line, "{\"type\":\"share\",\"i\":15,\"ok\":1,", 27) != 0) {
            printf("V04 max head: %.40s\n", line);
            return fail("v04_max_head");
        }
        { /* the three long fields come back byte-for-byte, so a cut anywhere inside
             one of them cannot hide behind "it is still valid UTF-8" */
            char got[2200];
            if (!v04_field(line, "name", got, sizeof got)) return fail("v04_max_name_field");
            size_t el = strlen(got);
            char *cut = strstr(line, "\"name\":\"");
            if (!cut) return fail("v04_max_name_pos");
            /* name: 511 legal bytes -> escaped to 1022 */
            if (el != 511 || memcmp(got, ev.name, 511) != 0) {
                printf("V04 max name round trip: %zu B\n", el);
                return fail("v04_max_name_lost");
            }
            if (!v04_field(line, "magnet", got, sizeof got) || strcmp(got, ev.magnet) != 0) {
                printf("V04 max magnet round trip: %zu B want %zu\n", strlen(got), strlen(ev.magnet));
                return fail("v04_max_magnet_lost");
            }
            if (!v04_field(line, "torrent", got, sizeof got) || strcmp(got, ev.torrent_path) != 0) {
                printf("V04 max path round trip: %zu B\n", strlen(got));
                return fail("v04_max_path_lost");
            }
            /* the escape really expanded the name (otherwise the case would be the
               ASCII one r29 already covers): 255 two-byte characters stay raw */
            if (strstr(cut, "\xc5\x82") == NULL) return fail("v04_max_no_multibyte");
        }
        /* non-vacuity, in-test: one byte less of cap than the line needs is the
           r29 fallback, and the line's real width is what makes that so. */
        {
            static char tight[40960 + 16];
            memcpy(tight, line, 8);
            if (ntx_ipc_share_event_json(tight, (size_t)w, &ev) <= 0 ||
                strcmp(tight, "{\"type\":\"share\",\"i\":15,\"ok\":0,\"code\":\"io\"}") != 0) {
                printf("V04 tight cap %d did not reach the fallback: %.60s\n", w, tight);
                return fail("v04_max_bound_real");
            }
        }
        printf("V04 max-size share event = %d B (name 511 B, magnet %d B, path %d B, buf %zu B)\n",
               w, NTX_IPC_MAGNET_MAX, NTX_SHARE_PATH_MAX - 1, sizeof g_share_evt);
        if (ok("v04_share_event_max_size")) return 1;
    }

    { /* ── V04 (d) · `add` with a REAL magnet longer than 511 B ───────────────
         docs/json-api.md §Limits: "`magnet` at most **2048** bytes after unescaping
         (longer: `io`) — the old 511-byte cap was relaxed for `add`, so a magnet
         with many `tr=` parameters fits". So the 512 B framer line buffer makes
         this a SUCCESS test, not a rejection test — and r31 only ever drives
         generated magnets (1946 B, unreserved-only). This one is a real magnet
         with many percent-encoded tr= parameters, >511 B: it must survive the
         framer, the parser and the dispatcher, and its trackers must reach the
         session. The >2048 B verdict stays pinned by r31's probe; the 512 B itself
         is pinned here as the width r31's 1946 B magnet already cleared, so the
         relaxation is measured, not assumed. ── */
        ntx_config cfg;
        ntx_netx *nx;
        memset(&cfg, 0, sizeof cfg);
        cfg.store_dir = "test/.scratch/ntx-ipc-v04";
        uint8_t mih[20], mih2[32];
        for (int k = 0; k < 20; k++) mih[k] = (uint8_t)(0x30 + k);
        for (int k = 0; k < 32; k++) mih2[k] = (uint8_t)(0x70 + k);
        const char *tl[6];
        char urls[6][128];
        for (int k = 0; k < 6; k++)
            snprintf(urls[k], sizeof urls[k],
                     "https://tracker%d.example.org:443/%02d/announce?q=%%C5%%82%%C5%%82", k, k);
        for (int k = 0; k < 6; k++) tl[k] = urls[k];
        char mag[NTX_SHARE_MAGNET_MAX];
        if (ntx_share_magnet(mag, sizeof mag, mih, mih2, "V04 Long Name 01.bin", tl, 6) != 0)
            return fail("v04_real_magnet_build");
        size_t mlen = strlen(mag);
        if (mlen <= 511) { printf("V04 real magnet is only %zu B\n", mlen); return fail("v04_real_magnet_short"); }
        if (mlen > (size_t)NTX_IPC_MAGNET_MAX) {
            printf("V04 real magnet %zu B past the add cap\n", mlen);
            return fail("v04_real_magnet_long");
        }
        char line[4608];
        snprintf(line, sizeof line, "{\"cmd\":\"add\",\"seq\":5,\"magnet\":\"%s\"}\n", mag);
        if (strlen(line) >= (size_t)NTX_IPC_LINE_MAX) return fail("v04_real_frame_fit");

        /* over the SHIPPED framer + pump, on a real fd 0, so the 512 B question is
           answered by the product and not by a hand-fed parser */
        ntx_session *s = mk(&nx, &cfg);
        if (feed_stdin(line, strlen(line)) != 0) { drop(s, nx); return fail("v04_real_stdin"); }
        int save_out = 0;
        if (v04_cap_open("test/.scratch/ntx-ipc-v04-add.ndjson", &save_out) != 0) {
            drop(s, nx); return fail("v04_real_cap");
        }
        ntx_ipc_reader_init(&g_rd);
        g_ipc_open = 1; g_ipc_quit = 0; g_ipc_stash_len = 0;
        ipc_pump_tick(s);
        fflush(stdout);
        v04_cap_close(save_out);
        g_ipc_open = 0;
        if (v04_load("test/.scratch/ntx-ipc-v04-add.ndjson") != 0) { drop(s, nx); return fail("v04_real_read"); }
        int ia = v04_first("\"seq\":5,\"cmd\":\"add\"");
        if (ia < 0 || !strstr(v04_ln[ia], "\"ok\":1") || strstr(v04_ln[ia], "\"code\"")) {
            printf("V04 add of a %zu B magnet: %s\n", mlen, ia < 0 ? "(no reply)" : v04_ln[ia]);
            drop(s, nx); return fail("v04_real_add_refused");
        }
        if (v04_count("\"code\":\"bad_json\"") != 0) {
            printf("V04 the framer dropped the %zu B line (§3.7)\n", strlen(line));
            drop(s, nx); return fail("v04_real_frame_dropped");
        }
        char ih[41];
        ntx_hex40(ih, mih);
        if (!strstr(v04_ln[ia], ih) || !strstr(v04_ln[ia], "\"state\":0")) {
            printf("V04 add ack: %s\n", v04_ln[ia]);
            drop(s, nx); return fail("v04_real_add_ih");
        }
        /* the many tr= the docs promise really arrived */
        int nurl = 0;
        for (int k = 0; k < 6; k++) if (s->trk_urls[0][k][0]) nurl++;
        if (s->trk_n[0] != 6 || nurl != 6) {
            printf("V04 long magnet kept trk_n=%d urls=%d, want 6/6\n", s->trk_n[0], nurl);
            drop(s, nx); return fail("v04_real_trackers");
        }
        if (strcmp(s->tts[0].name, "V04 Long Name 01.bin") != 0) {
            printf("V04 long magnet dn=%s\n", s->tts[0].name);
            drop(s, nx); return fail("v04_real_dn");
        }
        /* the relaxation is measured, not assumed: the same line one byte past
           511 is still accepted, and the 512 B boundary itself is only meaningful
           because a magnet this long is what the docs promise to fit — one byte
           past the 2048 cap stays `io` (r31's probe pins that width exactly). */
        if (mlen < 512) {
            printf("V04 magnet %zu B never crossed the old 511 B cap\n", mlen);
            drop(s, nx); return fail("v04_real_below_old_cap");
        }
        drop(s, nx);
        printf("V04 real add: %zu B magnet (past the old 511 B cap), %zu B line, 6 trackers\n",
               mlen, strlen(line));
        if (ok("v04_add_long_magnet_success")) return 1;
    }

    return 0; /* tasks append here; keep the final line intact */
}
