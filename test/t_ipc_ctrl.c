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

    return 0; /* tasks append here; keep the final line intact */
}
