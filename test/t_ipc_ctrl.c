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

    return 0; /* tasks append here; keep the final line intact */
}
