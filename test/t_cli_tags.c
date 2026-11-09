/* Task C2 — status-line tags for private/share/strict/pins/port-map (design §10).
 * Includes the CLI TU directly; output captured via fmemopen (§10 line budget). */
#include "../src/ui/ntx_cli.c"
#include "../src/ui/ntx_diag.c"

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

/* tags must appear in this relative order (§10) */
static int ordered(const char *line, const char *const *tags, int n) {
    const char *p = line;
    for (int i = 0; i < n; i++) {
        p = strstr(p, tags[i]);
        if (!p) return 0;
        p++;
    }
    return 1;
}

static void seed(ntx_stats *st, const char *name) {
    memset(st, 0, sizeof *st);
    st->uptime_s = 7;
    st->n = 1;
    ntx_tts_stat *t = &st->t[0];
    snprintf(t->name, sizeof t->name, "%s", name);
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
}

int main(void) {
    char line[512];
    ntx_stats st;
    ntx_tts_stat *t;

    /* ── full tag set, §10 order ── */
    seed(&st, "Priv.Share");
    t = &st.t[0];
    t->priv = 1;
    t->share = 1;
    t->enc_strict = 1;
    t->trk_pin_fail = 2;
    st.port_map = 2; /* NTX_PM_ACTIVE */
    st.ext_port = 40123;
    t->in_ok = 3;
    ntx_cli_status_format(&st, line, sizeof line);
    {
        static const char *const want[] = {"prv", "shr", "enc!", "pin!2", "map:40123", "in3"};
        if (!ordered(line, want, 6)) {
            fprintf(stderr, "line: %s\n", line);
            return fail("tag_order");
        }
    }
    if (ok("tag_order")) return 1;

    /* ── share failed → shr! ── */
    t->share = 2;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "shr!")) return fail("share_failed_tag");
    if (strstr(line, "shr ") || strstr(line, "shr\n")) return fail("shr_plain_on_fail");
    if (ok("share_failed_tag")) return 1;

    /* ── port-map states ── */
    t->share = 1;
    st.port_map = 4; /* NTX_PM_CGNAT */
    st.ext_port = 0;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "map!cg")) return fail("map_cgnat");
    if (strstr(line, "map:")) return fail("map_cgnat_no_port");
    st.port_map = 3; /* NTX_PM_NONE */
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "map-")) return fail("map_none");
    st.port_map = 1; /* NTX_PM_PENDING — gateway has not answered yet, same as "no answer" */
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "map-")) return fail("map_pending");
    st.port_map = 0; /* NTX_PM_OFF */
    ntx_cli_status_format(&st, line, sizeof line);
    if (strstr(line, "map")) return fail("map_off_absent");
    st.port_map = 2;
    st.ext_port = 40123;
    if (ok("map_states")) return 1;

    /* ── negatives: no flags set ⇒ no tags, and no stray substrings ── */
    /* Name deliberately spells out tag-ish words ("Pin"/"Ingress"): a tag
     * emitted unconditionally must not hide behind the truncated name. */
    seed(&st, "Pingpong.Ingress");
    ntx_cli_status_format(&st, line, sizeof line);
    if (strstr(line, "prv") || strstr(line, "shr") || strstr(line, "enc!"))
        return fail("plain_no_tags");
    if (strstr(line, "pin!") || strstr(line, "map") || strstr(line, " in"))
        return fail("plain_no_pin_map_in");
    if (ok("plain_no_tags")) return 1;

    /* share active with zero inbound ⇒ in0 (the tag rides the share, §10) */
    seed(&st, "Idle.Share");
    t = &st.t[0];
    t->share = 1;
    t->in_ok = 0;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "shr")) return fail("share_tag_present");
    if (!strstr(line, " in0")) return fail("in_zero_shown");
    if (ok("in_zero_shown")) return 1;

    /* ── pin!N absent at 0, inN absent when not sharing ── */
    seed(&st, "Pin.Zero");
    t = &st.t[0];
    t->trk_pin_fail = 0;
    t->in_ok = 5; /* inbound only counts for a share (§10) */
    ntx_cli_status_format(&st, line, sizeof line);
    if (strstr(line, "pin!")) return fail("pin_zero_absent");
    if (strstr(line, "in5")) return fail("in_ok_without_share");
    t->share = 1;
    t->trk_pin_fail = 99;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "pin!99")) return fail("pin_capped");
    if (!strstr(line, "in5")) return fail("in_ok_tag");
    if (ok("pin_and_in_gating")) return 1;

    /* ── phase "hash" renders as @hash (§10) ── */
    seed(&st, "Hashing.Share");
    t = &st.t[0];
    t->share = 1;
    t->state = NTX_TTS_META;
    t->size = 0;
    t->total = 0;
    t->pct = 42;
    snprintf(t->phase, sizeof t->phase, "hash");
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "@hash")) return fail("hash_phase_at");
    if (strstr(line, "META:hash")) return fail("hash_phase_meta");
    if (!strstr(line, "42%")) return fail("hash_phase_pct");
    if (ok("hash_phase")) return 1;

    /* ── every counter at cap (pattern from ntx_cli.c:14) ⇒ ≤ CLI_MAX_LINE ── */
    memset(&st, 0, sizeof st);
    st.uptime_s = 11;
    st.n = 1;
    st.port_map = 2;
    st.ext_port = 65535;
    snprintf(st.doh, sizeof st.doh, "!UC");
    st.utp = 1;
    st.utp_conns = 999;
    st.punch_ok = 999;
    st.punch_fail = 999;
    t = &st.t[0];
    memset(t->name, 'x', 47);
    t->name[47] = 0;
    t->state = NTX_TTS_DL;
    snprintf(t->phase, sizeof t->phase, "ratio-done");
    t->trk_total = t->trk_pend = t->trk_udp_ok = t->trk_dead = 65535;
    t->peers_all = t->peers_hs = t->peers_ok = t->peers_unchoked = t->peers_interested = 65535;
    t->meta_got = t->meta_need = 65535;
    t->meta_version = 2;
    t->hybrid = 0;
    t->layers_pending = 1;
    t->priv = 1;
    t->share = 1;
    t->enc_strict = 1;
    t->trk_pin_fail = 65535;
    t->in_ok = 65535;
    t->size = t->down = t->up = 18446744073709551615ULL;
    t->total = t->done = 4294967295u;
    t->pct = 100;
    t->spd_d = t->spd_u = t->eta_s = 4294967295u;
    ntx_cli_status_format(&st, line, sizeof line);
    printf("  worst-case tagged line: %zu chars (budget %d)\n", strlen(line), CLI_MAX_LINE);
    if (strlen(line) > CLI_MAX_LINE) return fail("worst_case_len");
    if (ok("worst_case_len")) return 1;

    /* ── no room ⇒ tags are dropped from the END of the list (§10) ── */
    seed(&st, "Tight.Line");
    t = &st.t[0];
    t->priv = 1;
    t->share = 1;
    t->enc_strict = 1;
    t->trk_pin_fail = 2;
    st.port_map = 2;
    st.ext_port = 40123;
    t->in_ok = 3;
    {
        /* Base line is 119 chars; " prv" ends at 123, " shr" at 127. A 125-byte
         * cap lands inside " shr", so the tail must be cut back to the last
         * complete tag, never torn mid-tag. */
        char tight[125];
        ntx_cli_status_format(&st, tight, sizeof tight);
        printf("  tight[125] = %zu chars [%s]\n", strlen(tight), tight);
        if (strlen(tight) >= sizeof tight) return fail("tight_torn");
        if (!strstr(tight, "prv")) return fail("tight_keeps_head");
        if (strstr(tight, "shr") || strstr(tight, "enc!") || strstr(tight, "pin!") ||
            strstr(tight, "map:") || strstr(tight, "in3"))
            return fail("tight_truncates_tail");
        if (ok("tight_truncates_tail")) return 1;
    }

    /* ── the whole line is capped at CLI_MAX_LINE by the writer too ── */
    {
        char buf[CLI_MAX_LINE + 8];
        FILE *fp = fmemopen(buf, sizeof buf, "w");
        if (!fp) return fail("fmemopen");
        ntx_cli_status_update(&st, fp, NULL);
        fflush(fp);
        fclose(fp);
        buf[sizeof buf - 1] = 0;
        {
            size_t n = strcspn(buf, "\n");
            if (n > (size_t)CLI_MAX_LINE) return fail("writer_len");
        }
        if (ok("writer_len")) return 1;
    }

    return 0;
}
