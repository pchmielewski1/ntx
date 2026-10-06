#include "../src/ui/ntx_cli.c"
#include "../src/ui/ntx_diag.c"
#include "../src/ui/ntx_stats.c"
#include "../src/ui/ntx_ipc.c"

#include <stdio.h>
#include <string.h>

static int fail(const char *msg) {
    fprintf(stderr, "FAIL %s\n", msg);
    return 1;
}

static int ok(const char *msg) {
    printf("PASS %s\n", msg);
    return 0;
}

/* structural validator: balanced {}[] outside strings, escapes honoured. */
static int ipc_json_ok(const char *s) {
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
/* counts "ih":" occurrences == emitted objects (every object carries ih (§5.2)) */
static int ipc_obj_count(const char *s) {
    int n = 0;
    for (const char *p = strstr(s, "\"ih\":\""); p; p = strstr(p + 1, "\"ih\":\"")) n++;
    return n;
}
/* reads the single "n": header value (§11.2 honesty gate) */
static long ipc_n_value(const char *s) {
    const char *p = strstr(s, "\"n\":");
    return p ? strtol(p + 4, 0, 10) : -1;
}
/* reads "truncated":1 presence (key absent when 0 — §5.1) */
static int ipc_has_truncated(const char *s) { return strstr(s, "\"truncated\":1") != 0; }

int main(void) {
    char line[256];
    ntx_stats st;
    memset(&st, 0, sizeof st);
    st.port = 6881;
    st.uptime_s = 12;

    if (ntx_cli_status_format(&st, line, sizeof line) == 0) return fail("idle_len");
    if (!strstr(line, "idle")) return fail("idle_text");
    if (strlen(line) > 120) return fail("idle_long");
    if (ok("idle")) return 1;

    memset(&st, 0, sizeof st);
    st.uptime_s = 8;
    st.n = 1;
    ntx_tts_stat *t = &st.t[0];
    snprintf(t->name, sizeof t->name, "Test.Torrent");
    t->state = NTX_TTS_META;
    snprintf(t->phase, sizeof t->phase, "trk-wait");
    t->trk_total = 18;
    t->trk_udp_ok = 2;
    t->trk_pend = 1;

    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "META:trk-wait")) return fail("meta_phase");
    if (!strstr(line, "trk02/18p01")) return fail("meta_trk");
    if (strlen(line) > 120) return fail("meta_long");
    if (ok("meta_trk")) return 1;

    t->trk_dead = 7;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "trk02/18p01d07")) return fail("meta_trk_dead");
    t->trk_dead = 0;
    if (ok("meta_trk_dead")) return 1;

    st.doh[0] = 'Q';
    st.doh[1] = '9';
    st.doh[2] = 0;
    st.doh_busy = 1;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "dns..Q9")) return fail("meta_dns_busy");
    st.doh_busy = 0;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "dnsQ9")) return fail("meta_dns_ok");
    if (strstr(line, "dns..Q9")) return fail("meta_dns_idle_no_dots");
    snprintf(st.doh, sizeof st.doh, "!UC");
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "dns!UC")) return fail("meta_dns_mitm");
    st.doh[0] = 0;
    if (ok("meta_dns")) return 1;

    snprintf(t->phase, sizeof t->phase, "meta");
    t->meta_got = 4;
    t->meta_need = 15;
    t->peers_all = 43;
    t->peers_ok = 8;
    t->peers_unchoked = 2;
    t->peers_interested = 3;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "m04/15")) return fail("meta_pieces");
    if (!strstr(line, "i03")) return fail("meta_interested");
    if (ok("meta_pieces")) return 1;

    t->state = NTX_TTS_DL;
    snprintf(t->phase, sizeof t->phase, "dl");
    t->size = 1024ULL * 1024 * 1024;
    t->down = 100ULL * 1024 * 1024;
    t->up = 10ULL * 1024 * 1024;
    t->total = 934;
    t->done = 12;
    t->partial = 3;
    t->verify_q = 2;
    t->pct = 9;
    t->spd_d = 8 * 1024 * 1024;
    t->spd_u = 128 * 1024;
    t->peers_interested = 0;
    ntx_cli_status_format(&st, line, sizeof line);
    if (strchr(line, '|')) return fail("dl_no_pipes");
    if (!strstr(line, "12/934")) return fail("dl_pieces");
    if (!strstr(line, "@dl")) return fail("dl_phase_tag");
    if (!strstr(line, "v") || !strstr(line, "^")) return fail("dl_speeds");
    if (!strstr(line, "trk")) return fail("dl_flags");
    if (!strstr(line, "i00")) return fail("dl_interested");
    if (strlen(line) > 160) return fail("dl_long");
    if (ok("dl_line")) return 1;

    t->state = NTX_TTS_DONE;
    t->done = 934;
    t->pct = 100;
    t->spd_d = 0;
    t->spd_u = 256 * 1024;
    t->up = (uint64_t)(0.5 * (double)t->size);
    snprintf(t->phase, sizeof t->phase, "seed");
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "@seed") && !strstr(line, "seed")) return fail("seed_phase");
    if (!strstr(line, "r0.5") && !strstr(line, "r0,5")) return fail("seed_ratio");
    if (!strstr(line, "^")) return fail("seed_up");
    if (!strstr(line, "up")) return fail("seed_up_total");
    if (ok("seed_line")) return 1;

    t->up = 3ULL * t->size;
    snprintf(t->phase, sizeof t->phase, "ratio-done");
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "ratio-done")) return fail("ratio_phase");
    if (ok("ratio_done_line")) return 1;

    /* BEP52: v2/hybrid/layers_pending status tags + hash-exchange JSON
     * keys. */
    memset(&st, 0, sizeof st);
    st.uptime_s = 9;
    st.n = 1;
    t = &st.t[0];
    snprintf(t->name, sizeof t->name, "V2.Torrent");
    t->state = NTX_TTS_DL;
    snprintf(t->phase, sizeof t->phase, "dl");
    t->size = 1024ULL * 1024 * 1024;
    t->down = 100ULL * 1024 * 1024;
    t->up = 10ULL * 1024 * 1024;
    t->total = 934;
    t->done = 12;
    t->pct = 9;
    t->spd_d = 8 * 1024 * 1024;
    t->spd_u = 128 * 1024;
    t->meta_version = 2;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "v2")) return fail("v2_tag");
    if (strstr(line, "hl")) return fail("v2_not_hybrid");
    if (strstr(line, "Lpend")) return fail("v2_layers_ok");
    t->hybrid = 1;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "hl")) return fail("hl_tag");
    if (strstr(line, "v2")) return fail("hl_not_pure_v2");
    t->hybrid = 0;
    t->layers_pending = 1;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "v2") || !strstr(line, "Lpend")) return fail("v2_lpend");
    /* Worst case: every tag + dns + dead + meta segment — pinned to the
     * original 160-char budget (CLI_MAX_LINE was raised to 176 only for the
     * utp/punch tags, gated separately in p6b_tags below). */
    snprintf(st.doh, sizeof st.doh, "!UC");
    t->trk_total = 99;
    t->trk_udp_ok = 99;
    t->trk_pend = 99;
    t->trk_dead = 99;
    t->peers_all = 99;
    t->peers_hs = 99;
    t->peers_ok = 99;
    t->peers_unchoked = 99;
    t->peers_interested = 99;
    t->meta_got = 99;
    t->meta_need = 99;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "v2 Lpend")) return fail("v2_lpend_all");
    if (strlen(line) > 160) return fail("v2_line_len");
    if (ok("v2_tags")) return 1;

    st.hash_req_tx = 7;
    st.hash_req_rx_ok = 5;
    st.hash_rej = 2;
    char js[2048];
    int jn = ntx_stats_to_json(&st, js, sizeof js);
    if (jn <= 0 || (size_t)jn >= sizeof js) return fail("json_fit");
    if (!strstr(js, "\"hash_req_tx\":7")) return fail("json_hash_tx");
    if (!strstr(js, "\"hash_req_rx_ok\":5")) return fail("json_hash_rx");
    if (!strstr(js, "\"hash_rej\":2")) return fail("json_hash_rej");
    if (!strstr(js, "\"meta_version\":2")) return fail("json_meta_version");
    if (!strstr(js, "\"hybrid\":0")) return fail("json_hybrid");
    if (!strstr(js, "\"layers_pending\":1")) return fail("json_layers_pending");
    if (ok("json_v2_fields")) return 1;

    /* BEP29/BEP55: uTP/demux/holepunch status tags + NDJSON keys.
     * Counter deltas themselves are driven
     * non-vacuously in t_holepunch (punch) and t_netx_shared (demux). */
    memset(&st, 0, sizeof st);
    st.uptime_s = 11;
    st.n = 1;
    t = &st.t[0];
    snprintf(t->name, sizeof t->name, "Utp.Torrent"); /* capital U: no "utp" substring */
    t->state = NTX_TTS_DL;
    snprintf(t->phase, sizeof t->phase, "dl");
    t->size = 1024ULL * 1024 * 1024;
    t->down = 100ULL * 1024 * 1024;
    t->up = 10ULL * 1024 * 1024;
    t->total = 934;
    t->done = 12;
    t->pct = 9;
    t->spd_d = 8 * 1024 * 1024;
    t->spd_u = 128 * 1024;
    st.utp = 1;
    st.utp_conns = 7;
    st.utp_v6 = 1;
    st.demux_dht = 111;
    st.demux_utp = 42;
    st.demux_drop = 3;
    st.punch_ok = 5;
    st.punch_fail = 2;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, " utp7")) return fail("utp_tag");
    if (strstr(line, " utp0")) return fail("utp_not_capped_value");
    if (!strstr(line, " punch5/2")) return fail("punch_tag");
    /* Negative: transport off => no utp tag anywhere; no activity => no punch tag. */
    st.utp = 0;
    st.utp_conns = 0;
    st.punch_ok = 0;
    st.punch_fail = 0;
    ntx_cli_status_format(&st, line, sizeof line);
    if (strstr(line, "utp")) return fail("utp_off_absent");
    if (strstr(line, "punch")) return fail("punch_idle_absent");
    /* Enabled but idle: utp0 rides the cfg flag with zero conns. */
    st.utp = 1;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, " utp0")) return fail("utp_idle_zero");
    if (strstr(line, "punch")) return fail("punch_still_idle");
    /* Worst case: every tag at the 99 cap + dns + dead + meta + v2/Lpend +
     * utp99 + punch99/99 — must stay in the 160-char CLI_MAX_LINE budget. */
    snprintf(st.doh, sizeof st.doh, "!UC");
    st.doh_busy = 0;
    st.utp_conns = 999;
    st.punch_ok = 999;
    st.punch_fail = 999;
    t->trk_total = 99;
    t->trk_udp_ok = 99;
    t->trk_pend = 99;
    t->trk_dead = 99;
    t->peers_all = 99;
    t->peers_hs = 99;
    t->peers_ok = 99;
    t->peers_unchoked = 99;
    t->peers_interested = 99;
    t->meta_got = 99;
    t->meta_need = 99;
    t->meta_version = 2;
    t->hybrid = 0;
    t->layers_pending = 1;
    ntx_cli_status_format(&st, line, sizeof line);
    printf("  worst-case status line: %zu chars (budget 176)\n", strlen(line));
    if (!strstr(line, " utp99")) return fail("utp_capped");
    if (!strstr(line, " punch99/99")) return fail("punch_capped");
    if (strlen(line) > 176) return fail("p6b_line_len");
    if (ok("p6b_tags")) return 1;

    st.utp = 1;
    st.utp_conns = 7;
    st.utp_v6 = 1;
    st.demux_dht = 111;
    st.demux_utp = 42;
    st.demux_drop = 3;
    st.punch_ok = 5;
    st.punch_fail = 2;
    char js2[2048];
    int jn2 = ntx_stats_to_json(&st, js2, sizeof js2);
    if (jn2 <= 0 || (size_t)jn2 >= sizeof js2) return fail("p6b_json_fit");
    if (!strstr(js2, "\"utp\":1")) return fail("json_utp");
    if (!strstr(js2, "\"utp_conns\":7")) return fail("json_utp_conns");
    if (!strstr(js2, "\"utp_v6\":1")) return fail("json_utp_v6");
    if (!strstr(js2, "\"demux_dht\":111")) return fail("json_demux_dht");
    if (!strstr(js2, "\"demux_utp\":42")) return fail("json_demux_utp");
    if (!strstr(js2, "\"demux_drop\":3")) return fail("json_demux_drop");
    if (!strstr(js2, "\"punch_ok\":5")) return fail("json_punch_ok");
    if (!strstr(js2, "\"punch_fail\":2")) return fail("json_punch_fail");
    /* Negative: zeroed flags emit 0, never the set values. */
    st.utp = 0;
    st.utp_conns = 0;
    st.utp_v6 = 0;
    st.punch_ok = 0;
    st.punch_fail = 0;
    int jn3 = ntx_stats_to_json(&st, js2, sizeof js2);
    if (jn3 <= 0 || (size_t)jn3 >= sizeof js2) return fail("p6b_json_fit2");
    if (!strstr(js2, "\"utp\":0")) return fail("json_utp_off");
    if (strstr(js2, "\"utp\":1")) return fail("json_utp_stale_on");
    if (!strstr(js2, "\"utp_conns\":0")) return fail("json_utp_conns_zero");
    if (!strstr(js2, "\"utp_v6\":0")) return fail("json_utp_v6_zero");
    if (!strstr(js2, "\"punch_ok\":0")) return fail("json_punch_ok_zero");
    if (!strstr(js2, "\"punch_fail\":0")) return fail("json_punch_fail_zero");
    /* Structural parseability (json.loads equivalent, C-side): balanced
     * braces/brackets outside strings, even quote count. */
    {
        int braces = 0, brackets = 0, quotes = 0;
        for (char *p = js2; *p; p++) {
            if (*p == '"') quotes++;
            else if (quotes % 2 == 0) {
                if (*p == '{') braces++;
                else if (*p == '}') braces--;
                else if (*p == '[') brackets++;
                else if (*p == ']') brackets--;
            }
            if (braces < 0 || brackets < 0) return fail("json_p6b_unbalanced");
        }
        if (braces != 0 || brackets != 0 || quotes % 2 != 0) return fail("json_p6b_unbalanced");
    }
    if (ok("json_p6b_fields")) return 1;

    /* ── JSON Control API v1 (§4, §5.1-§5.4, §10, §11) ── */
    memset(&st, 0, sizeof st);
    st.uptime_s = 3;
    st.n = 2;
    st.port = 6881;
    t = &st.t[0];
    t->slot = 0;
    t->h[0] = 0x01; t->h[19] = 0xab;
    snprintf(t->name, sizeof t->name, "a\"b\\c\td\ne"); /* §11.1 witness */
    snprintf(t->phase, sizeof t->phase, "dl");
    t->state = 1; t->pct = 100; t->total = 1; t->done = 1; t->size = 1;
    t = &st.t[1];
    t->slot = 9;                       /* dense array ≠ slot (§11.3) */
    t->h[0] = 0x0f; t->h[19] = 0xf0;
    snprintf(t->name, sizeof t->name, "ok");
    snprintf(t->phase, sizeof t->phase, "seed");
    t->state = 2; t->pct = 100; t->total = 4; t->done = 4;
    char js3[24576];
    int j3 = ntx_stats_to_json(&st, js3, sizeof js3);
    if (j3 <= 0 || (size_t)j3 >= sizeof js3) return fail("ipc_fit");
    if (strncmp(js3, "{\"type\":\"stats\",\"v\":1,\"down_Bps\":", 28) != 0)
        return fail("ipc_envelope");
    if (!strstr(js3, "\"i\":9")) return fail("ipc_slot_key");
    if (!strstr(js3, "\"ih\":\"01000000000000000000000000000000000000ab\""))
        return fail("ipc_ih0");
    if (!strstr(js3, "\"ih\":\"0f000000000000000000000000000000000000f0\""))
        return fail("ipc_ih1");
    if (!strstr(js3, "\"name\":\"a\\\"b\\\\c\\td\\ne\"")) return fail("ipc_escape"); /* §11.1 */
    if (!strstr(js3, "\"pct\":100")) return fail("ipc_pct100_regression"); /* §10 */
    if (strstr(js3, ", ") || strstr(js3, ": ")) return fail("ipc_no_spaces"); /* §10 */
    if (ipc_has_truncated(js3)) return fail("ipc_trunc_absent_when_full");
    if (!ipc_json_ok(js3)) return fail("ipc_parseable");
    if (ipc_obj_count(js3) != 2 || ipc_n_value(js3) != 2) return fail("ipc_n_honest"); /* §11.2 */
    if (ok("ipc_v1_envelope")) return 1;

    /* 16 torrents, worst-case values, 47-quote names (escape blow-up 6x):
       everything must fit the 24 KiB budget with honest n, no truncation. */
    memset(&st, 0, sizeof st);
    st.n = 16;
    snprintf(st.doh, sizeof st.doh, "!UC");
    st.doh_mitm = 65535; st.utp = 1; st.utp_conns = 65535; st.utp_v6 = 1;
    st.demux_dht = st.demux_utp = st.demux_drop = 1000000000ULL;
    st.punch_ok = st.punch_fail = 4294967295u;
    st.down_total = st.up_total = st.uptime_s = 100000000000ULL;
    for (int i = 0; i < 16; i++) {
        t = &st.t[i];
        t->slot = (uint8_t)(i * 3 > 15 ? 15 : i);
        memset(t->h, 0xa5 + i, 20);
        memset(t->name, '"', 47);                    /* 47 × 6 = 282 B escape */
        snprintf(t->phase, sizeof t->phase, "ratio-done");
        t->state = 4; t->pct = 100;
        t->spd_d = t->spd_u = t->eta_s = t->done = t->total = t->partial = t->peers = 4294967295u;
        t->trk_total = t->trk_pend = t->trk_udp_ok = t->trk_dead = 65535;
        t->peers_all = t->peers_hs = t->peers_ok = t->peers_unchoked = t->peers_interested = 65535;
        t->meta_got = t->meta_need = t->verify_q = 65535;
        t->meta_version = 2; t->hybrid = 1; t->layers_pending = 1;
        t->size = t->down = t->up = 18446744073709551615ULL; /* 20 digits */
    }
    char js4[24576];
    int j4 = ntx_stats_to_json(&st, js4, sizeof js4);
    if (j4 <= 0 || (size_t)j4 >= sizeof js4) return fail("ipc_worst_fit");
    if (!ipc_json_ok(js4)) return fail("ipc_worst_parseable");
    if (ipc_obj_count(js4) != 16 || ipc_n_value(js4) != 16) return fail("ipc_worst_n");
    if (ipc_has_truncated(js4)) return fail("ipc_worst_no_trunc");
    if (ok("ipc_v1_worst_case")) return 1;

    /* Tight cap → stop before a torn object, honest n, truncated:1 (§5.4, §11.2). */
    char js5[768 + 3u * 1024];
    int j5 = ntx_stats_to_json(&st, js5, sizeof js5);
    if (j5 <= 0) return fail("ipc_trunc_fit");
    if (!ipc_json_ok(js5)) return fail("ipc_trunc_parseable");
    if (ipc_obj_count(js5) < 1 || ipc_n_value(js5) != (long)ipc_obj_count(js5))
        return fail("ipc_trunc_honest_n");
    if (!ipc_has_truncated(js5) || ipc_obj_count(js5) == 16)
        return fail("ipc_trunc_flag");
    if (ok("ipc_v1_truncated")) return 1;

    /* Vectors: the repo's golden rule — the witness file drives the escape
       gate, too (§11.1: escape_bad_name.jsonl is run by t_cli). */
    {
        FILE *f = fopen("test/vectors/ipc/escape_bad_name.jsonl", "rb");
        if (!f) return fail("ipc_vec_open");
        char ln[4096];
        while (fgets(ln, sizeof ln, f)) {
            ln[strcspn(ln, "\r\n")] = 0;
            if (!ln[0]) continue;
            char *ini = strstr(ln, "in="), *oto = strstr(ln, " out=");
            if (!ini || !oto) { fclose(f); return fail("ipc_vec_fmt"); }
            oto[0] = 0; /* terminate the in= hex at the ' out=' delimiter */
            unsigned char inb[1024], want[6144];
            size_t ni = 0, nw = 0;
            for (char *q = ini + 3; q[0] && q[1]; q += 2) {
                char b[3] = { q[0], q[1], 0 };
                inb[ni++] = (unsigned char)strtoul(b, 0, 16);
            }
            inb[ni] = 0;
            char *wp = oto + 5;
            for (char *q = wp; q[0] && q[1]; q += 2) {
                char b[3] = { q[0], q[1], 0 };
                want[nw++] = (unsigned char)strtoul(b, 0, 16);
            }
            char res[6144];
            int r = ntx_json_escape(res, sizeof res, (const char *)inb);
            if (r != (int)nw || memcmp(res, want, nw) != 0) { fclose(f); return fail("ipc_vec_esc"); }
        }
        fclose(f);
    }
    if (ok("ipc_vectors_escape")) return 1;

    return 0;
}
