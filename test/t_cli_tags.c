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

/* Which legacy tags ride along in front of the §10 tail, i.e. how far the line
 * overshoots the 176-char budget. Measured would-be lengths are in the table below. */
typedef struct { int dns, utp, punch, dead, lpend; } maxload;

/* Every field at its widest rendering (pattern from ntx_cli.c:14): 20-char name,
 * 99-capped counters, "1.00G" / "1024K" / "1024K/s" / "59:59". tags = 0 gives the
 * pre-§10 line, tags = 1 adds all six §10 tags at their caps. The widths are
 * pinned instead of left at ULLONG_MAX because the widest size/speed forms leave no
 * room for any tag at all — the budget would then be exercised by the sizes, not
 * by the tag list, which is what §10 truncation is about. */
static void maxseed(ntx_stats *st, int tags, const maxload *l) {
    memset(st, 0, sizeof *st);
    st->uptime_s = 11;
    st->n = 1;
    st->utp = l->utp;
    st->utp_conns = 999;
    st->punch_ok = l->punch ? 999 : 0;
    st->punch_fail = l->punch ? 999 : 0;
    if (l->dns) snprintf(st->doh, sizeof st->doh, "!UC");
    ntx_tts_stat *t = &st->t[0];
    memset(t->name, 'x', 47);
    t->name[47] = 0;
    t->state = NTX_TTS_DL;
    snprintf(t->phase, sizeof t->phase, "dl");
    t->trk_total = t->trk_pend = t->trk_udp_ok = 65535;
    t->trk_dead = l->dead ? 65535 : 0;
    t->peers_all = t->peers_hs = t->peers_ok = t->peers_unchoked = t->peers_interested = 65535;
    t->meta_got = t->meta_need = 65535;
    t->meta_version = 2;
    t->hybrid = 0;
    t->layers_pending = l->lpend;
    t->priv = t->share = t->enc_strict = tags;
    t->trk_pin_fail = t->in_ok = tags ? 65535 : 0;
    st->port_map = tags ? 2 : 0; /* NTX_PM_ACTIVE */
    st->ext_port = tags ? 65535 : 0;
    t->size = 1024ULL * 1024 * 1024;       /* 1.00G */
    t->down = 1024ULL * 1024 - 1;          /* 1024K */
    t->total = 934;
    t->done = 12;
    t->pct = 9;
    t->spd_d = t->spd_u = 1024 * 1024 - 1; /* 1024K/s */
    t->eta_s = 59 * 60 + 59;               /* 59:59 */
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

    /* ── private only: share 0 ⇒ prv alone, no shr / in ── */
    seed(&st, "Private.Only");
    t = &st.t[0];
    t->priv = 1;
    t->share = 0;
    t->in_ok = 4; /* inbound must not leak a tag without a share */
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "prv")) return fail("priv_only_prv");
    if (strstr(line, "shr") || strstr(line, "in4") || strstr(line, " in"))
        return fail("priv_only_no_share_tags");
    if (ok("priv_only")) return 1;

    /* ── share failed → shr! ── */
    seed(&st, "Priv.Share");
    t = &st.t[0];
    t->priv = 1;
    t->share = 2;
    t->enc_strict = 1;
    t->trk_pin_fail = 2;
    st.port_map = 2;
    st.ext_port = 40123;
    t->in_ok = 3;
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
    /* ACTIVE but ext_port == 0 ⇒ nothing to show, so no "map:0" (pinned) */
    st.port_map = 2;
    st.ext_port = 0;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, "map-")) return fail("map_active_no_port");
    if (strstr(line, "map:0")) return fail("map_zero_port");
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

    /* ── (a) worst case that still FITS: all six §10 tags at their caps ──
     * Widest load that keeps them all — measured 176 chars, the budget exactly. */
    {
        const maxload fits = {1, 0, 0, 1, 0};
        maxseed(&st, 1, &fits);
    }
    ntx_cli_status_format(&st, line, sizeof line);
    printf("  worst-case tagged line (fits): %zu chars (budget %d)\n", strlen(line), CLI_MAX_LINE);
    if (strlen(line) > (size_t)CLI_MAX_LINE) return fail("worst_case_fits_all_tags_len");
    /* must sit on the budget, otherwise the case is not exercising it */
    if (strlen(line) != (size_t)CLI_MAX_LINE) return fail("worst_case_fits_all_tags_not_worst");
    {
        static const char *const want[] = {"prv", "shr", "enc!", "pin!99", "map:65535", "in99"};
        for (int i = 0; i < 6; i++)
            if (!strstr(line, want[i])) {
                fprintf(stderr, "line: %s\n", line);
                return fail("worst_case_fits_all_tags_missing");
            }
        if (!ordered(line, want, 6)) {
            fprintf(stderr, "line: %s\n", line);
            return fail("worst_case_fits_all_tags_order");
        }
    }
    if (ok("worst_case_fits_all_tags")) return 1;

    /* ── (b) no room ⇒ tags cut from the END of the list only, the pre-§10
     *     layout byte-identical, never a half-written tag (§10) ── */
    {
        char base[512], cut[512], sweep[512];
        /* Cumulative tails: every legal truncation is one of these, so a cut
         * that stops inside a tag ("… pin!9") matches none of them. */
        static const char *const keep[] = {"", " prv", " prv shr", " prv shr enc!",
                                           " prv shr enc! pin!99",
                                           " prv shr enc! pin!99 map:65535",
                                           " prv shr enc! pin!99 map:65535 in99"};
        /* The loads below would be 177, 178, 179, 183 and 199 chars long without
         * the cap (measured): the 177 one overshoots by a single char, so even a
         * cap that is one byte too generous is caught. */
        static const maxload load[] = {{0, 0, 1, 0, 0}, {0, 1, 0, 0, 1},
                                       {1, 0, 0, 0, 1}, {0, 0, 1, 0, 1},
                                       {1, 1, 1, 1, 1}};
        for (unsigned c = 0; c < sizeof load / sizeof load[0]; c++) {
            maxseed(&st, 0, &load[c]);
            ntx_cli_status_format(&st, base, sizeof base);
            maxseed(&st, 1, &load[c]);
            ntx_cli_status_format(&st, cut, sizeof cut);
            printf("  cut dns%d utp%d punch%d dead%d lp%d: %zu chars (budget %d) suffix [%s]\n",
                   load[c].dns, load[c].utp, load[c].punch, load[c].dead, load[c].lpend,
                   strlen(cut), CLI_MAX_LINE, cut + strlen(base));
            if (strlen(cut) > (size_t)CLI_MAX_LINE) return fail("worst_case_truncation_len");
            /* truncation must actually have happened on every load */
            if (strstr(cut, "in99")) return fail("worst_case_truncation_noop");
            /* the pre-§10 line must survive untouched as a prefix, so only the
             * §10 tail can be cut — the earlier layout cannot shift or shrink */
            if (strncmp(cut, base, strlen(base)) != 0) return fail("worst_case_truncation_layout");
            /* what is left of the tag list is a whole number of leading tags */
            int legal = 0;
            for (unsigned i = 0; i < sizeof keep / sizeof keep[0]; i++)
                if (strcmp(cut + strlen(base), keep[i]) == 0) legal = (int)i + 1;
            if (!legal) {
                fprintf(stderr, "cut: %s\n", cut);
                return fail("worst_case_truncation_half_tag");
            }
            /* only the END of the list is gone: kept tags are the first ones */
            static const char *const tail[] = {"prv", "shr", "enc!", "pin!99", "map:65535", "in99"};
            for (int i = 0; i < 6; i++) {
                int has = strstr(cut, tail[i]) != NULL;
                if (has != (i < legal - 1)) {
                    fprintf(stderr, "cut: %s\n", cut);
                    return fail("worst_case_truncation_not_from_end");
                }
            }
            /* Every cap from "just past the base" up must land on a tag boundary
             * too — one fixed cut would pass by luck. Sweeping pins the rule. */
            for (int cap = (int)strlen(base) + 1; cap <= (int)sizeof sweep - 1; cap++) {
                maxseed(&st, 1, &load[c]);
                ntx_cli_status_format(&st, sweep, (size_t)cap);
                size_t got = strlen(sweep);
                size_t lim = (size_t)(cap - 1) < (size_t)CLI_MAX_LINE ? (size_t)cap - 1
                                                                      : (size_t)CLI_MAX_LINE;
                if (got > lim) return fail("worst_case_sweep_len");
                if (got && sweep[got - 1] == ' ') return fail("worst_case_sweep_trailing_space");
                if (strncmp(sweep, base, got < strlen(base) ? got : strlen(base)) != 0)
                    return fail("worst_case_sweep_layout");
                if (got < strlen(base)) continue; /* cut inside legacy flags: pre-§10 rule */
                int k = 0;
                for (unsigned i = 0; i < sizeof keep / sizeof keep[0]; i++)
                    if (strcmp(sweep + strlen(base), keep[i]) == 0) k = (int)i + 1;
                if (!k) {
                    fprintf(stderr, "load %u cap %d: [%s]\n", c, cap, sweep);
                    return fail("worst_case_sweep_half_tag");
                }
            }
        }
        if (ok("worst_case_truncation")) return 1;
    }

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
