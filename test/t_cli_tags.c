/* Task C2 — status-line tags for private/share/strict/pins/port-map (design §10).
 * Includes the CLI TU directly; output captured via fmemopen (§10 line budget).
 *
 * R26 also needs the TTY branch of ntx_cli_status_update() (the live, in-place
 * line) and the ioctl-driven width cannot be set from a test, so isatty is
 * overridden the way test/t_rng.c overrides read(): declared first, then
 * macro'd, so the <unistd.h> ntx_cli.c pulls in is the already-processed one. */
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int g_test_isatty;
static int test_isatty(int fd) {
    (void)fd;
    return g_test_isatty;
}
#define isatty test_isatty
#include "../src/ui/ntx_cli.c"
#undef isatty
#include "../src/ui/ntx_diag.c"

#include "util.h"

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
typedef struct { int dns, utp, punch, dead, lpend, v6; } maxload;

/* R17: the tty path of ntx_cli_status_update() is cli_status_tty() — budget cap
 * plus the cut to the terminal width. The width itself comes from
 * ioctl(stderr), which a test cannot set, so the renderer is driven directly. */
static size_t render_at(ntx_stats *st, char *out, size_t cap, int cols) {
    return cli_status_tty(st, out, cap, cols);
}

/* No tag torn in half: every occurrence that starts a token must end on a space
 * or at the end of the line, so a cut can only drop tags whole. `tag` is the
 * COMPLETE spelling of one tag ("map!cg", not "map"). */
static int tag_whole(const char *line, const char *tag) {
    size_t n = strlen(tag);
    for (const char *p = strstr(line, tag); p; p = strstr(p + 1, tag)) {
        if (p != line && p[-1] != ' ') continue; /* inside another token */
        if (p[n] != 0 && p[n] != ' ') return 0;  /* token continues: torn tag */
    }
    return 1;
}

/* Every tag spelling the renderer can emit — the alphabet for the torn-tag
 * checks below. A suffix that is a PROPER prefix of any of these means the cut
 * stopped inside a tag. */
static const char *const r17_tags[] = {"prv", "shr", "shr!", "enc!", "pin!", "map:", "map!",
                                       "map-", "map6:", "in", "trk", "pe", "m", "dns", "dns..",
                                       "utp", "punch", "Lpend", "v2", "hl"};
#define R17_NTAGS ((int)(sizeof r17_tags / sizeof r17_tags[0]))

/* The last token of a trimmed line must not be a PROPER prefix of one of the
 * tags: "… pin!3" is a cut, "… pin!." (the trim's dots over a torn tag) is not a
 * word of the line. The dots are stripped before the compare, so a cut inside a
 * tag is caught even though cli_trim_to_width() overwrites its last bytes. */
static int no_torn_tag(const char *line, const char *const *tags, int n) {
    size_t len = strlen(line), s = len, tl;
    char tok[32];
    while (s > 0 && line[s - 1] != ' ') s--;
    tl = len - s;
    if (tl >= sizeof tok) tl = sizeof tok - 1;
    memcpy(tok, line + s, tl);
    tok[tl] = 0;
    while (tl > 0 && tok[tl - 1] == '.') tok[--tl] = 0; /* the trim's ellipsis */
    if (tl == 0) return 1;
    for (int i = 0; i < n; i++)
        if (tl < strlen(tags[i]) && strncmp(tok, tags[i], tl) == 0) return 0;
    return 1;
}

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
    /* S17d: map6:<port> at its own widest form, riding the same `tags` switch so the
     * pre-S17d loads (v6 = 0) render byte-for-byte what they rendered before. */
    st->port_map6 = (tags && l->v6) ? NTX_PM_ACTIVE : 0;
    st->ext_port6 = (tags && l->v6) ? 65535 : 0;
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

/* A seeding share with the alarm tags on — R17's case. 20-char name, every
 * informational tag active (trk/pe/dns/utp/punch), safety block in its alarm
 * form. Measured full length 164 columns, so 80/100/120 all have to cut.
 * cgnat = 1 swaps map:<port> for map!cg. v6 = 1 adds the IPv6 mapping, which rides
 * its own map6:<port> tag (S17d) right behind the aggregate one. */
static void seedshare(ntx_stats *st, int cgnat, int v6) {
    seed(st, "Q4.Report.2026.pdf");
    ntx_tts_stat *t = &st->t[0];
    t->state = NTX_TTS_DONE;
    snprintf(t->phase, sizeof t->phase, "seed");
    t->done = t->total = 934;
    t->down = t->up = t->size = 1024ULL * 1024 * 1024;
    t->pct = 100;
    t->priv = 1;
    t->share = 2; /* the shared file changed — shr! */
    t->enc_strict = 1;
    t->trk_pin_fail = 3;
    t->in_ok = 2;
    t->trk_udp_ok = 2;
    t->trk_total = 5;
    t->trk_pend = 1;
    t->trk_dead = 2;
    t->peers_all = t->peers_hs = t->peers_ok = t->peers_unchoked = t->peers_interested = 4;
    st->utp = 1;
    st->utp_conns = 7;
    st->punch_ok = 3;
    st->punch_fail = 1;
    snprintf(st->doh, sizeof st->doh, "!UC");
    st->port_map = cgnat ? NTX_PM_CGNAT : NTX_PM_ACTIVE;
    st->ext_port = cgnat ? 0 : 40123;
    /* S17d. With v6 the family is ACTIVE on the listen port; without it the family was
     * never brought up (OFF), which is the identity of the aggregate. */
    st->port_map6 = v6 ? NTX_PM_ACTIVE : NTX_PM_OFF;
    st->ext_port6 = v6 ? 6881 : 0;
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

    /* ── S17d: map6:<port> rides the IPv6 family ALONE ──
     * The aggregate tag above answers "is inbound reachable at all"; this one names the
     * v6 grant, which the aggregate cannot express (a v6-only host is ACTIVE with no v4
     * ext port, so `map:` has nothing to show). It is emitted only for an ACTIVE v6
     * family that has a port, exactly the rule map:<port> obeys. */
    st.port_map = 0;
    st.ext_port = 0;
    st.port_map6 = NTX_PM_ACTIVE;
    st.ext_port6 = 6881;
    ntx_cli_status_format(&st, line, sizeof line);
    if (!strstr(line, " map6:6881")) return fail("map6_active_rendered");
    if (strstr(line, " map:") || strstr(line, "map!cg") || strstr(line, " map-"))
        return fail("map6_active_no_aggregate_tag"); /* v6 alone must not fake a v4 tag */
    {
        const char *want6[] = {"prv", "shr", "enc!", "pin!2", "map6:6881", "in3"};
        if (!ordered(line, want6, 6)) {
            fprintf(stderr, "line: %s\n", line);
            return fail("map6_order_without_map");
        }
    }
    /* The documented position: behind the aggregate tag, ahead of inN. */
    st.port_map = NTX_PM_ACTIVE;
    st.ext_port = 40123;
    ntx_cli_status_format(&st, line, sizeof line);
    {
        const char *want6[] = {"prv", "shr", "enc!", "pin!2", "map:40123", "map6:6881", "in3"};
        if (!ordered(line, want6, 7)) {
            fprintf(stderr, "line: %s\n", line);
            return fail("map6_order_after_map");
        }
    }
    if (ok("map6_order")) return 1;

    /* Every other v6 state, and ACTIVE without a port, render nothing. */
    {
        static const int off_states[] = {NTX_PM_OFF, NTX_PM_PENDING, NTX_PM_NONE, NTX_PM_CGNAT};
        for (unsigned i = 0; i < sizeof off_states / sizeof off_states[0]; i++) {
            st.port_map = NTX_PM_ACTIVE; /* the aggregate is not what gates this tag */
            st.ext_port = 40123;
            st.port_map6 = (uint8_t)off_states[i];
            st.ext_port6 = 6881;
            ntx_cli_status_format(&st, line, sizeof line);
            if (strstr(line, "map6")) {
                fprintf(stderr, "state %d: [%s]\n", off_states[i], line);
                return fail("map6_present_on_inactive_family");
            }
        }
        /* ACTIVE but no port yet ⇒ nothing to show, and never "map6:0" — the same rule
         * the map: tag pins above. */
        st.port_map6 = NTX_PM_ACTIVE;
        st.ext_port6 = 0;
        ntx_cli_status_format(&st, line, sizeof line);
        if (strstr(line, "map6")) return fail("map6_active_no_port");
        if (strstr(line, "map6:0")) return fail("map6_zero_port");
        st.port_map = 0;
        st.ext_port = 0;
        ntx_cli_status_format(&st, line, sizeof line);
        if (strstr(line, "map")) return fail("map6_both_off_absent");
        if (ok("map6_states")) return 1;
    }

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
        const maxload fits = {1, 0, 0, 1, 0, 0};
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
        static const maxload load[] = {{0, 0, 1, 0, 0, 0}, {0, 1, 0, 0, 1, 0},
                                       {1, 0, 0, 0, 1, 0}, {0, 0, 1, 0, 1, 0},
                                       {1, 1, 1, 1, 1, 0}};
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

    /* ── R17: the safety tags of a share survive a cut to a terminal width ──
     * A seeding share with every informational tag on is 164 columns wide, so
     * 80/100/120 all have to cut. shr!/pin!N/enc!/map! are the tags that must
     * still be readable after the cut — before R17 they were the tail of the
     * list and were exactly what fell off, leaving a healthy-looking line. */
    {
        static const char *const safe_port[] = {"prv", "shr!", "enc!", "pin!3", "map:40123", "in2"};
        static const char *const safe_cgnat[] = {"prv", "shr!", "enc!", "pin!3", "map!cg", "in2"};
        static const char *const safe_port6[] = {"prv", "shr!", "enc!", "pin!3", "map:40123",
                                                 "map6:6881", "in2"};
        static const char *const safe_cgnat6[] = {"prv", "shr!", "enc!", "pin!3", "map!cg",
                                                  "map6:6881", "in2"};
        static const int widths[] = {80, 100, 120};
        /* S17d: the v6 half of the sweep — map6:<port> belongs to the hoisted block, so
         * it is a safety tag too and must survive the same cut, in the documented
         * position (after the aggregate map tag, before inN). */
        for (int v = 0; v < 4; v++) {
            int cgnat = v & 1, v6 = v >> 1;
            for (int w = 0; w < 3; w++) {
                int cols = widths[w];
                const char *const *safe = v6 ? (cgnat ? safe_cgnat6 : safe_port6)
                                             : (cgnat ? safe_cgnat : safe_port);
                int nsafe = v6 ? 7 : 6;
                seedshare(&st, cgnat, v6);
                size_t n = render_at(&st, line, sizeof line, cols);
                printf("  R17 %s%s @%-3d cols -> %2zu: [%s]\n", cgnat ? "cgnat" : "port",
                       v6 ? "+v6" : "", cols, n, line);
                if ((int)n > cols) {
                    fprintf(stderr, "line: %s\n", line);
                    return fail("r17_within_width");
                }
                /* The cut is marked: docs/cli.md promises the removed part is
                 * shown as " ..", so a line that was actually cut ends in dots. */
                if (n < 2 || line[n - 1] != '.' || line[n - 2] != '.') {
                    fprintf(stderr, "%s @%d cols: cut without ellipsis [%s]\n",
                            cgnat ? "cgnat" : "port", cols, line);
                    return fail("r17_ellipsis");
                }
                for (int i = 0; i < nsafe; i++) {
                    if (!strstr(line, safe[i])) {
                        fprintf(stderr, "%s%s @%d cols: no \"%s\" in [%s]\n", cgnat ? "cgnat" : "port",
                                v6 ? "+v6" : "", cols, safe[i], line);
                        return fail("r17_safety_tag_cut");
                    }
                    if (!tag_whole(line, safe[i])) {
                        fprintf(stderr, "%s @%d cols: torn \"%s\" in [%s]\n", cgnat ? "cgnat" : "port",
                                cols, safe[i], line);
                        return fail("r17_safety_tag_torn");
                    }
                }
                /* the safety block must still be in the documented order, and it
                 * must sit ahead of the informational tags it used to trail */
                if (!ordered(line, safe, nsafe)) {
                    fprintf(stderr, "line: %s\n", line);
                    return fail("r17_safety_order");
                }
                const char *inf = strstr(line, "trk");
                if (inf && strstr(line, "shr!") > inf) {
                    fprintf(stderr, "line: %s\n", line);
                    return fail("r17_safety_after_info");
                }
                if (!no_torn_tag(line, safe, nsafe)) {
                    fprintf(stderr, "%s @%d cols: torn suffix [%s]\n", cgnat ? "cgnat" : "port", cols,
                            line);
                    return fail("r17_torn_suffix");
                }
            }
        }
        if (ok("r17_safety_visible")) return 1;
    }

    /* ── R17: the §10 block at its documented widest form still fits behind the
     * name column at 80 columns — 20 (name) + 36 (the block) = 56. With the v6 tag
     * (S17d) the block grows by " map6:65535" — 11 more, 67 columns, still inside
     * every width the CLI is used at, which is what the second half pins. ── */
    {
        static const char *const caps[] = {"prv", "shr!", "enc!", "pin!99", "map:65535", "in99"};
        static const char *const caps6[] = {"prv", "shr!", "enc!", "pin!99", "map:65535",
                                            "map6:65535", "in99"};
        for (int v6 = 0; v6 < 2; v6++) {
            const maxload wide = {1, 1, 1, 1, 1, v6};
            maxseed(&st, 1, &wide);
            st.t[0].share = 2; /* the alarm form: shr! */
            size_t n = render_at(&st, line, sizeof line, 80);
            printf("  R17 widest block%s @80 -> %zu: [%s]\n", v6 ? "+v6" : "", n, line);
            if ((int)n > 80) return fail("r17_widest_width");
            const char *const *caps_want = v6 ? caps6 : caps;
            int ncaps = v6 ? 7 : 6;
            for (int i = 0; i < ncaps; i++)
                if (!strstr(line, caps_want[i])) {
                    fprintf(stderr, "no \"%s\" in [%s]\n", caps_want[i], line);
                    return fail("r17_widest_tag_cut");
                }
            if (!ordered(line, caps_want, ncaps)) return fail("r17_widest_order");
            const char *inf = strstr(line, "trk");
            if (inf && strstr(line, "shr!") > inf) return fail("r17_widest_after_info");
            if (!no_torn_tag(line, r17_tags, R17_NTAGS)) return fail("r17_widest_torn");
        }
        if (ok("r17_widest_block")) return 1;
    }

    /* ── R17 guard: every terminal width keeps the line inside the width and
     * off a tag boundary — swept, not sampled. ── */
    {
        for (int cols = 24; cols <= CLI_MAX_LINE + 30; cols++) {
            for (int v = 0; v < 4; v++) {
                seedshare(&st, v & 1, v >> 1);
                size_t n = render_at(&st, line, sizeof line, cols);
                if ((int)n > cols) {
                    fprintf(stderr, "cols %d %s: %zu [%s]\n", cols, (v & 1) ? "cgnat" : "port", n,
                            line);
                    return fail("r17_sweep_width");
                }
                if (n && line[n - 1] == ' ') return fail("r17_sweep_trailing_space");
                if (!no_torn_tag(line, r17_tags, R17_NTAGS)) {
                    fprintf(stderr, "cols %d v%d: torn suffix [%s]\n", cols, v, line);
                    return fail("r17_sweep_torn");
                }
                /* shr! is never half-present ("shr" without the '!') */
                if (strstr(line, "shr ") || strstr(line, "shr.") || strstr(line, "shr\n"))
                    return fail("r17_shr_plain");
            }
        }
        if (ok("r17_width_sweep")) return 1;
    }

    /* ── R17 guard: a plain torrent (no share) is unaffected by the reorder ──
     * The measured 119-char line fits 120 columns, so it must come out
     * byte-identical to the pre-R17 layout and carry no tag of its own. */
    {
        static const char *const plain_line_119 =
            "Plain.Torrent          9% [>         ]  100.0M/1.00G  v8.0M/s^128K/s --:--"
            "   12/934  @dl   trk00/00p00 pe00/00/00u00i00";
        seed(&st, "Plain.Torrent");
        size_t n = render_at(&st, line, sizeof line, 120);
        printf("  R17 plain @120 -> %zu: [%s]\n", n, line);
        if (strcmp(line, plain_line_119) != 0) {
            fprintf(stderr, "got : [%s]\nwant: [%s]\n", line, plain_line_119);
            return fail("r17_plain_layout");
        }
        if (strstr(line, "prv") || strstr(line, "shr") || strstr(line, "enc!") ||
            strstr(line, "pin!") || strstr(line, "map") || strstr(line, " in"))
            return fail("r17_plain_tags");
        for (int cols = 30; cols <= 120; cols += 7) {
            seed(&st, "Plain.Torrent");
            size_t m = render_at(&st, line, sizeof line, cols);
            if ((int)m > cols) return fail("r17_plain_width");
            if (!no_torn_tag(line, r17_tags, R17_NTAGS)) {
                fprintf(stderr, "cols %d: torn suffix [%s]\n", cols, line);
                return fail("r17_plain_torn");
            }
        }
        if (ok("r17_plain_unaffected")) return 1;
    }

    /* ── R8: the 20-byte name column must never be cut inside a UTF-8 character,
     * so the status line stays decodable (§10 layout, docs/cli.md "first 20
     * bytes"). A strict decoder is the witness. ── */
    {
        char utf[128], pad[96];

        /* odd offset: "a" + 30 × é (61 B) → the 20-byte budget must stop at 19
         * bytes ("a" + 9 × é), not tear the 10th. */
        utf[0] = 'a';
        for (int k = 0; k < 30; k++) memcpy(utf + 1 + (size_t)k * 2, "\xc3\xa9", 2);
        utf[61] = 0;
        seed(&st, utf);
        ntx_cli_status_format(&st, line, sizeof line);
        {
            size_t bad = 0;
            if (!test_utf8_strict(line, strcspn(line, "\n"), &bad)) {
                fprintf(stderr, "line: %s\nbyte %zu: %02x\n", line, bad,
                        (unsigned)(unsigned char)line[bad]);
                return fail("r8_cli_name_2byte");
            }
        }
        {
            char want[32], col[64];
            want[0] = 'a';
            for (int k = 0; k < 9; k++) memcpy(want + 1 + (size_t)k * 2, "\xc3\xa9", 2);
            want[19] = 0;
            snprintf(col, sizeof col, "%s ", want); /* %-*s pads to 20 with one space */
            if (strncmp(line, col, strlen(col)) != 0) {
                fprintf(stderr, "line: %s\nwant: [%s]\n", line, col);
                return fail("r8_cli_name_2byte_cut");
            }
        }

        /* 4-byte character straddling the 20th byte: 17 ASCII + U+1F600 (4 B). */
        memset(utf, 'b', 17); utf[17] = 0;
        memcpy(utf + 17, "\xf0\x9f\x98\x80", 4);
        seed(&st, utf);
        ntx_cli_status_format(&st, line, sizeof line);
        {
            size_t bad = 0;
            if (!test_utf8_strict(line, strcspn(line, "\n"), &bad)) {
                fprintf(stderr, "line: %s\nbyte %zu: %02x\n", line, bad,
                        (unsigned)(unsigned char)line[bad]);
                return fail("r8_cli_name_4byte");
            }
        }
        memset(pad, 'b', 17); pad[17] = 0;
        {
            char col[64];
            snprintf(col, sizeof col, "%s   ", pad); /* 17 kept + 3 pad to 20 */
            if (strncmp(line, col, strlen(col)) != 0) {
                fprintf(stderr, "line: %s\nwant: [%s]\n", line, col);
                return fail("r8_cli_name_4byte_cut");
            }
        }

        /* guard: an ASCII name and a short valid UTF-8 name are unchanged. */
        {
            static const char *const plain[] = { "Plain.Name-01.txt",
                                                 "za\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87.txt" };
            for (int k = 0; k < 2; k++) {
                char col[64];
                size_t pl = strlen(plain[k]);
                if (pl > (size_t)CLI_NAME_W) return fail("r8_cli_guard_setup");
                memcpy(col, plain[k], pl);
                memset(col + pl, ' ', (size_t)CLI_NAME_W - pl);
                col[CLI_NAME_W] = 0;
                seed(&st, plain[k]);
                ntx_cli_status_format(&st, line, sizeof line);
                if (memcmp(line, col, (size_t)CLI_NAME_W) != 0) {
                    fprintf(stderr, "line: %s\nwant: [%s]\n", line, col);
                    return fail(k ? "r8_cli_utf8_guard" : "r8_cli_ascii_guard");
                }
                if (strstr(line, "\xef\xbf\xbd")) return fail("r8_cli_guard_fffd");
            }
        }
        if (ok("r8_cli_name_boundary")) return 1;
    }

    /* ── R26: one "close the status line" hook for ntx_diag ─────────────────
     * The tty line is rewritten in place (`\r` + clear line), so a diagnostic
     * printed while it is open lands ON it: the two texts run together and the
     * next redraw erases the message. Only the magnet path used to close the
     * line (the hand-rolled g_cli_needs_nl block in ntx_main.c), which is also
     * why a failure left an extra blank line behind: the flag stayed set and
     * ntx_cli_status_finish() still paid it out.
     * Both the status line and ntx_diag write to stderr, so the case redirects
     * fd 2 into a scratch file the way test/t_ipc_ctrl.c redirects stdout. */
    {
        static const char *const R26_MSG = "ntx: share big.bin changed on disk, stopping\n";
        char cap_path[128];
        snprintf(cap_path, sizeof cap_path, "%s", "test/.scratch/r26_cli_tags.err");
        if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return fail("r26_scratch");
        ntx_diag_set_close_hook(ntx_cli_close_status_line); /* what ntx_main does at startup */
        int save_out = dup(2);
        if (save_out < 0) return fail("r26_dup");
        char got[4096];
        ssize_t gn;

        /* (a) a diagnostic while the live line is open starts on its OWN line,
         *     leaves no blank line behind, and spends the pending newline. */
        seed(&st, "R26.Share.bin");
        g_test_isatty = 1;
        int needs_nl = 0;
        unlink(cap_path);
        {
            int fd = open(cap_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd < 0) { dup2(save_out, 2); close(save_out); return fail("r26_open"); }
            dup2(fd, 2);
            close(fd);
            ntx_cli_status_update(&st, stderr, &needs_nl);
            if (!needs_nl) { /* the driver itself: a live line must be open */
                fflush(stderr);
                dup2(save_out, 2); close(save_out);
                return fail("r26_update_no_flag");
            }
            ntx_diag("%s", R26_MSG);
            fflush(stderr);
            dup2(save_out, 2);
        }
        {
            FILE *rf = fopen(cap_path, "rb");
            if (!rf) { close(save_out); return fail("r26_read"); }
            gn = fread(got, 1, sizeof got - 1, rf);
            fclose(rf);
            close(save_out);
        }
        if (gn < 0) return fail("r26_read2");
        got[gn] = 0;
        if (!strstr(got, "\r\033[2K")) { fprintf(stderr, "got: [%s]\n", got); return fail("r26_no_live_line"); }
        if (!strstr(got, "\nntx: share big.bin changed on disk, stopping\n")) {
            fprintf(stderr, "glued: [%s]\n", got);
            return fail("r26_diag_own_line");
        }
        if (strstr(got, "\n\n")) { fprintf(stderr, "got: [%s]\n", got); return fail("r26_blank_line"); }
        if (needs_nl != 0) { printf("needs_nl=%d\n", needs_nl); return fail("r26_flag_cleared"); }

        /* (b) the hook is a no-op with no live line: two further diagnostics
         *     write their own bytes and nothing else. */
        save_out = dup(2);
        if (save_out < 0) return fail("r26_dup2");
        unlink(cap_path);
        {
            int fd = open(cap_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd < 0) { dup2(save_out, 2); close(save_out); return fail("r26_open2"); }
            dup2(fd, 2);
            close(fd);
            ntx_diag("%s", R26_MSG);
            ntx_diag("%s", R26_MSG);
            fflush(stderr);
            dup2(save_out, 2);
        }
        {
            FILE *rf = fopen(cap_path, "rb");
            if (!rf) { close(save_out); return fail("r26_read3"); }
            gn = fread(got, 1, sizeof got - 1, rf);
            fclose(rf);
            close(save_out);
        }
        if (gn < 0) return fail("r26_read4");
        got[gn] = 0;
        {
            size_t ml = strlen(R26_MSG);
            if ((size_t)gn != 2 * ml || memcmp(got, R26_MSG, ml) != 0 ||
                memcmp(got + ml, R26_MSG, ml) != 0) {
                fprintf(stderr, "got: [%s]\n", got);
                return fail("r26_noop_when_closed");
            }
        }

        /* (c) the closer itself: one newline for an open line, nothing once
         *     closed — the primitive the magnet path now goes through too. */
        g_test_isatty = 1;
        needs_nl = 0;
        save_out = dup(2);
        if (save_out < 0) return fail("r26_dup3");
        unlink(cap_path);
        {
            int fd = open(cap_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd < 0) { dup2(save_out, 2); close(save_out); return fail("r26_open3"); }
            dup2(fd, 2);
            close(fd);
            ntx_cli_status_update(&st, stderr, &needs_nl);
            ntx_cli_close_status_line();
            ntx_cli_close_status_line();
            fflush(stderr);
            dup2(save_out, 2);
        }
        {
            FILE *rf = fopen(cap_path, "rb");
            if (!rf) { close(save_out); return fail("r26_read5"); }
            gn = fread(got, 1, sizeof got - 1, rf);
            fclose(rf);
            close(save_out);
        }
        if (gn < 0) return fail("r26_read6");
        got[gn] = 0;
        {
            const char *nl = strrchr(got, '\n');
            if (!nl || nl[1] != 0) { fprintf(stderr, "got: [%s]\n", got); return fail("r26_close_once_nl"); }
            if (needs_nl != 0) return fail("r26_close_clears_flag");
        }

        /* (d) a pipe (isatty false) keeps its bytes EXACTLY: line, newline, the
         *     diagnostic, the summary — no hook byte anywhere in the stream. */
        g_test_isatty = 0;
        needs_nl = 0;
        seed(&st, "R26.Pipe.bin");
        char want[4096];
        char plain[CLI_MAX_LINE + 8];
        ntx_cli_status_format(&st, plain, sizeof plain);
        save_out = dup(2);
        if (save_out < 0) return fail("r26_dup4");
        unlink(cap_path);
        {
            int fd = open(cap_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd < 0) { dup2(save_out, 2); close(save_out); return fail("r26_open4"); }
            dup2(fd, 2);
            close(fd);
            ntx_cli_status_update(&st, stderr, &needs_nl);
            ntx_diag("%s", R26_MSG);
            ntx_cli_status_finish(&st, stderr, needs_nl);
            fflush(stderr);
            dup2(save_out, 2);
        }
        {
            FILE *rf = fopen(cap_path, "rb");
            if (!rf) { close(save_out); return fail("r26_read7"); }
            gn = fread(got, 1, sizeof got - 1, rf);
            fclose(rf);
            close(save_out);
        }
        if (gn < 0) return fail("r26_read8");
        got[gn] = 0;
        snprintf(want, sizeof want, "%s\n%s", plain, R26_MSG);
        if (strncmp(got, want, strlen(want)) != 0) {
            fprintf(stderr, "got : [%s]\nwant: [%s]\n", got, want);
            return fail("r26_plain_bytes");
        }
        if (needs_nl != 0) return fail("r26_plain_flag");
        if (strchr(got, '\r')) return fail("r26_plain_no_cr");

        /* (e) the summary CLOSES the line it was written over: the tracker
         *     goodbyes the caller runs after it are diagnostics, and a line
         *     still registered at that point would pay out a stray newline. */
        g_test_isatty = 1;
        needs_nl = 0;
        seed(&st, "R26.Exit.bin");
        save_out = dup(2);
        if (save_out < 0) return fail("r26_dup5");
        unlink(cap_path);
        {
            int fd = open(cap_path, O_CREAT | O_TRUNC | O_WRONLY, 0644);
            if (fd < 0) { dup2(save_out, 2); close(save_out); return fail("r26_open5"); }
            dup2(fd, 2);
            close(fd);
            ntx_cli_status_update(&st, stderr, &needs_nl);
            ntx_cli_status_finish(&st, stderr, needs_nl);
            needs_nl = 0; /* as the caller does after the summary */
            ntx_diag("%s", R26_MSG); /* a goodbye printed after the summary */
            fflush(stderr);
            dup2(save_out, 2);
        }
        {
            FILE *rf = fopen(cap_path, "rb");
            if (!rf) { close(save_out); return fail("r26_read9"); }
            gn = fread(got, 1, sizeof got - 1, rf);
            fclose(rf);
            close(save_out);
        }
        if (gn < 0) return fail("r26_read10");
        got[gn] = 0;
        if (strstr(got, "\n\n")) { fprintf(stderr, "got: [%s]\n", got); return fail("r26_no_blank_after_finish"); }
        if (!strstr(got, "phase dl)\nntx: share big.bin changed on disk, stopping\n")) {
            fprintf(stderr, "got: [%s]\n", got);
            return fail("r26_finish_closes_line");
        }

        /* (f) a row that is not a share and has no name keeps the placeholder:
         *     the R28 fallback must not reach past the metainfo it never got. */
        {
            memset(&st, 0, sizeof st);
            st.n = 1;
            st.t[0].state = NTX_TTS_META;
            snprintf(st.t[0].phase, sizeof st.t[0].phase, "meta");
            char fin[CLI_MAX_LINE + 64];
            FILE *fp = fmemopen(fin, sizeof fin, "w");
            if (!fp) return fail("r26_fmemopen");
            ntx_cli_status_finish(&st, fp, 0);
            fclose(fp);
            if (!strstr(fin, "stopped — (torrent) (metadata not fetched, phase meta)")) {
                fprintf(stderr, "fin: [%s]\n", fin);
                return fail("r28_noshare_placeholder_kept");
            }
            if (ok("r26_status_line_hook")) return 1;
        }
    }

    return 0;
}
