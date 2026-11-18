#include "ntx_cli.h"
#include "ntx_diag.h"

#include "../core/ntx_torrent.h"
#include "../core/ntx_utf8.h"

/* Only the NTX_PM_* enum is needed here; ntx_session_portmap.h declares the
 * ntx_session_portmap_* fns taking `struct ntx_session *` but does not
 * forward-declare the struct itself (opaque to the CLI). */
struct ntx_session;
#include "../core/ntx_session_portmap.h" /* NTX_PM_* == ntx_stats.port_map (design §8, §11) */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>

#define CLI_NAME_W 20
#define CLI_BAR_W  10
/* Status-line budget. Raised 160 -> 176 for the utpN/punch tags
 * (measured worst case with every tag at the 99 cap incl. dns/utp/punch:
 * 162 chars, t_cli p6b_tags gate). Documented in docs/cli.md. */
#define CLI_MAX_LINE 176

static int cli_term_cols(void) {
    struct winsize ws;
    if (ioctl(STDERR_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0)
        return (int)ws.ws_col;
    return 100;
}

static void cli_size_short(uint64_t bytes, char *out, size_t cap) {
    if (cap == 0) return;
    if (bytes < 1024ULL)
        snprintf(out, cap, "%llub", (unsigned long long)bytes);
    else if (bytes < 1024ULL * 1024ULL)
        snprintf(out, cap, "%.0fK", (double)bytes / 1024.0);
    else if (bytes < 1024ULL * 1024ULL * 1024ULL)
        snprintf(out, cap, "%.1fM", (double)bytes / (1024.0 * 1024.0));
    else
        snprintf(out, cap, "%.2fG", (double)bytes / (1024.0 * 1024.0 * 1024.0));
}

static void cli_speed_short(uint32_t bps, char *out, size_t cap) {
    if (cap == 0) return;
    if (bps < 1024)
        snprintf(out, cap, "%uB/s", (unsigned)bps);
    else if (bps < 1024U * 1024U)
        snprintf(out, cap, "%.0fK/s", (double)bps / 1024.0);
    else
        snprintf(out, cap, "%.1fM/s", (double)bps / (1024.0 * 1024.0));
}

static void cli_eta_short(uint32_t secs, char *out, size_t cap) {
    if (cap == 0) return;
    if (secs == 0) {
        snprintf(out, cap, "--:--");
        return;
    }
    if (secs >= 3600)
        snprintf(out, cap, "%uh%02um", (unsigned)(secs / 3600), (unsigned)((secs % 3600) / 60));
    else
        snprintf(out, cap, "%u:%02u", (unsigned)(secs / 60), (unsigned)(secs % 60));
}

static void cli_bar_short(uint32_t pct, char *out, size_t cap) {
    if (cap < CLI_BAR_W + 3) {
        if (cap) out[0] = 0;
        return;
    }
    if (pct > 100) pct = 100;
    int fill = (int)(pct * CLI_BAR_W / 100);
    if (fill > CLI_BAR_W) fill = CLI_BAR_W;
    out[0] = '[';
    int i;
    for (i = 0; i < CLI_BAR_W; i++)
        out[1 + i] = (i < fill) ? '=' : (i == fill && fill < CLI_BAR_W) ? '>' : ' ';
    out[1 + CLI_BAR_W] = ']';
    out[2 + CLI_BAR_W] = 0;
}

static void cli_name_short(const char *src, char *out, size_t cap) {
    if (cap == 0) return;
    if (!src || !src[0]) {
        snprintf(out, cap, "(torrent)");
        return;
    }
    /* R8: the column budget stays CLI_NAME_W BYTES (docs/cli.md pins the layout
     * on it), but the cut lands on a UTF-8 character boundary — the status line
     * is a terminal stream and a torn character renders as garbage. A name that
     * is already valid ASCII/UTF-8 and short comes out byte-for-byte unchanged. */
    size_t fit = cap - 1 < (size_t)CLI_NAME_W ? cap - 1 : (size_t)CLI_NAME_W;
    ntx_utf8_copy(out, fit + 1, src);
}

/* Builds the tag list. `out` gets the tags the line ends with. When `hoist` is
 * set and the slot is a share, the design §10 block (prv/shr/enc!/pin!/map/
 * inN) is built into `sec` instead of onto the tail, so the caller can print it
 * directly behind the fixed 20-column name: those four tags are what tells the
 * operator the share is NOT healthy ("shr!" = stopped serving, "pin!N" = pin
 * check failed, "enc!" = strict encryption, "map!cg" = inbound will not work),
 * and on a terminal the line is cut to the column count — the counters
 * (trk/pe/m/dns/utp/punch) are what a narrow terminal gives up first, never a
 * warning (R17). `sec` stays empty for a slot that is not a share and for
 * hoist = 0, which is the layout docs/cli.md documents. Either way the relative
 * order of the six §10 tags is the same; their widest form is
 * " prv shr! enc! pin!99 map:65535 in99" (36 chars, pin!/in capped at 99 like
 * the peer counters), so name column + block is 56 columns — inside every width
 * the CLI is used at. */
static void cli_flags_compact(const ntx_stats *st, const ntx_tts_stat *t, char *out, size_t cap,
                              int hoist, char *sec, size_t seccap) {
    if (seccap) sec[0] = 0;
    if (cap == 0) return;
    unsigned a = t->peers_all > 99 ? 99 : t->peers_all;
    unsigned h = t->peers_hs > 99 ? 99 : t->peers_hs;
    unsigned o = t->peers_ok > 99 ? 99 : t->peers_ok;
    unsigned u = t->peers_unchoked > 99 ? 99 : t->peers_unchoked;
    unsigned ii = t->peers_interested > 99 ? 99 : t->peers_interested;
    unsigned tu = t->trk_udp_ok > 99 ? 99 : t->trk_udp_ok;
    unsigned tt = t->trk_total > 99 ? 99 : t->trk_total;
    unsigned tp = t->trk_pend > 99 ? 99 : t->trk_pend;
    unsigned td = t->trk_dead > 99 ? 99 : t->trk_dead;
    char dead[8] = "";
    if (td > 0) snprintf(dead, sizeof dead, "d%02u", td);
    char dns[16] = "";
    if (st && st->doh[0]) {
        if (st->doh[0] == '!')
            snprintf(dns, sizeof dns, " dns%s", st->doh); /* dns!UC */
        else if (st->doh_busy)
            snprintf(dns, sizeof dns, " dns..%s", st->doh);
        else
            snprintf(dns, sizeof dns, " dns%s", st->doh);
    }
    /* BEP52 v2 tags: 'v2' pure-v2, 'hl' hybrid,
     * 'Lpend' pure-v2 still waiting for piece layers via hash exchange (22). */
    char v2[16] = "";
    if (t->meta_version == 2)
        snprintf(v2, sizeof v2, "%s%s", t->hybrid ? " hl" : " v2",
                 t->layers_pending ? " Lpend" : "");
    /* BEP29/BEP55 compact tags: 'utpN' rides
     * the cfg flag (N = active uTP conns, capped 99; absent = transport off),
     * 'punchO/F' = BEP55 dials initiated / refused (capped 99; absent = no
     * punch activity yet). Session-level, like the dns tag. */
    char utp[16] = "";
    if (st && st->utp) snprintf(utp, sizeof utp, " utp%u", st->utp_conns > 99 ? 99u : (unsigned)st->utp_conns);
    char punch[16] = "";
    if (st && (st->punch_ok || st->punch_fail))
        snprintf(punch, sizeof punch, " punch%u/%u", st->punch_ok > 99 ? 99u : (unsigned)st->punch_ok,
                 st->punch_fail > 99 ? 99u : (unsigned)st->punch_fail);
    /* Design §10 tags — the safety block, see the note on hoist above. pin!/in
     * cap at 99 like the peer counters. */
    char prv[8] = "", shr[8] = "", enc[8] = "", pin[16] = "", map[16] = "", map6[16] = "", inn[8] = "";
    if (t->priv) snprintf(prv, sizeof prv, " prv");
    if (t->share) snprintf(shr, sizeof shr, " shr%s", t->share == 2 ? "!" : "");
    if (t->enc_strict) snprintf(enc, sizeof enc, " enc!");
    if (t->trk_pin_fail)
        snprintf(pin, sizeof pin, " pin!%u", t->trk_pin_fail > 99 ? 99u : (unsigned)t->trk_pin_fail);
    /* map:<port> needs a port worth showing: ACTIVE with ext_port == 0 has no
     * usable mapping yet (stats zero ext_port unless the state is ACTIVE, and
     * adv_port is 0 before the socket is bound), so it reads as "no mapping". */
    if (st && st->port_map == NTX_PM_ACTIVE && st->ext_port)
        snprintf(map, sizeof map, " map:%u", st->ext_port);
    else if (st && st->port_map == NTX_PM_CGNAT)
        snprintf(map, sizeof map, " map!cg");
    else if (st && st->port_map != NTX_PM_OFF)
        snprintf(map, sizeof map, " map-"); /* PENDING, NONE, or ACTIVE w/o ext port */
    /* map6:<port> rides the IPv6 family ALONE and only while it is ACTIVE with a port
     * (the same "no map:0" rule as above). The aggregate tag above is about reachability
     * from either family, so this one is what names the v6 grant the operator cannot
     * read out of `map:` — a v6-only host shows `map- map6:6881`, a dual host shows
     * both. Nothing is printed for a family that was never brought up. */
    if (st && st->port_map6 == NTX_PM_ACTIVE && st->ext_port6)
        snprintf(map6, sizeof map6, " map6:%u", st->ext_port6);
    if (t->share)
        snprintf(inn, sizeof inn, " in%u", t->in_ok > 99 ? 99u : (unsigned)t->in_ok);
    char info[128];
    if (t->meta_need > 0) {
        unsigned mg = t->meta_got > 99 ? 99 : t->meta_got;
        unsigned mn = t->meta_need > 99 ? 99 : t->meta_need;
        snprintf(info, sizeof info,
                 " trk%02u/%02up%02u%s pe%02u/%02u/%02uu%02ui%02u m%02u/%02u%s%s%s%s", tu, tt, tp,
                 dead, a, h, o, u, ii, mg, mn, v2, dns, utp, punch);
    } else {
        snprintf(info, sizeof info,
                 " trk%02u/%02up%02u%s pe%02u/%02u/%02uu%02ui%02u%s%s%s%s", tu, tt, tp, dead, a, h,
                 o, u, ii, v2, dns, utp, punch);
    }
    if (hoist && t->share && seccap) {
        snprintf(sec, seccap, "%s%s%s%s%s%s%s", prv, shr, enc, pin, map, map6, inn);
        snprintf(out, cap, "%s", info);
    } else {
        snprintf(out, cap, "%s%s%s%s%s%s%s%s", info, prv, shr, enc, pin, map, map6, inn);
    }
}

/* Design §10: the whole line stays inside CLI_MAX_LINE. Tags are the tail of
 * the flags list, so over-long lines lose them from the end — cut on a tag
 * boundary, never torn mid-tag. */
static void cli_cap_line(char *line, size_t want, size_t cap) {
    size_t lim = cap - 1 < CLI_MAX_LINE ? cap - 1 : CLI_MAX_LINE;
    if (want <= lim) return;
    line[lim] = 0;
    while (lim > 0 && line[lim - 1] != ' ') lim--;
    if (lim) line[--lim] = 0;
    while (lim > 0 && line[lim - 1] == ' ') line[--lim] = 0;
}

/* Cut the line to the terminal width. R17: the " .." ellipsis must not land
 * inside a tag, so the cut backs off to the last token boundary that still
 * leaves room for the dots — the same rule cli_cap_line applies to the
 * CLI_MAX_LINE budget. A width so narrow that no boundary is left keeps the old
 * hard cut; no tag could be saved at that width anyway. */
static void cli_trim_to_width(char *line, int cols) {
    if (cols <= 0) cols = CLI_MAX_LINE;
    if (cols > CLI_MAX_LINE) cols = CLI_MAX_LINE;
    size_t n = strlen(line);
    if ((int)n < cols) return;
    if (cols <= 4) { /* nothing is left to save — the old hard cut */
        line[(size_t)cols - 1] = 0;
        if (cols > 2) line[(size_t)cols - 2] = '.';
        if (cols > 3) line[(size_t)cols - 3] = '.';
        return;
    }
    /* " .." rides on after the cut, so the last token has to end by cols-5 to
     * keep the whole line at cols-1 chars, the length the hard cut produced. */
    size_t lim = (size_t)cols - 5;
    while (lim > 0 && line[lim] != ' ') lim--;
    if (lim == 0) { /* no token boundary to land on: the old hard cut */
        line[(size_t)cols - 1] = 0;
        line[(size_t)cols - 2] = '.';
        line[(size_t)cols - 3] = '.';
        return;
    }
    while (lim > 1 && line[lim - 1] == ' ') lim--; /* no run of spaces before .. */
    /* line[lim] is the first space of the run that ends the last token: it stays
     * as the single separator and the two dots ride on behind it. Writing a NUL
     * at lim here would terminate the line and put the dots past the terminator,
     * i.e. invisible. */
    line[lim] = ' ';
    line[lim + 1] = '.';
    line[lim + 2] = '.';
    line[lim + 3] = 0;
}

/* `hoist` moves the §10 safety block of a share slot behind the name column
 * (R17); see cli_flags_compact(). */
static size_t cli_status_raw(const ntx_stats *st, char *out, size_t cap, int hoist) {
    if (!st || !out || cap == 0) return 0;

    if (st->n <= 0) {
        return (size_t)snprintf(out, cap, "ntx idle  :%u  %llus", (unsigned)st->port,
                                (unsigned long long)st->uptime_s);
    }

    const ntx_tts_stat *t = &st->t[0];
    char name[CLI_NAME_W + 4], sec[64] = "";
    /* Staging room for trk/pe/m/v2/dns/utp/punch + the §10 tags (worst case
     * measured 110 B); the line is capped to CLI_MAX_LINE by cli_cap_line. */
    char flags[128];
    cli_name_short(t->name, name, sizeof name);
    cli_flags_compact(st, t, flags, sizeof flags, hoist, sec, sizeof sec);
    const char *phase = t->phase[0] ? t->phase : "?";

    /* --share hashing rides the normal line so bar/pct show progress (§10);
     * everything else without metadata keeps the META: rendering. */
    if (strcmp(phase, "hash") != 0 &&
        (t->state == NTX_TTS_META || (t->size == 0 && t->total == 0))) {
        return (size_t)snprintf(out, cap, "%-*s%s META:%-9s%s %3llus", CLI_NAME_W, name, sec, phase,
                                flags, (unsigned long long)st->uptime_s);
    }

    if (t->state == NTX_TTS_PAUSED) {
        char dn[16], tot[16];
        cli_size_short(t->down, dn, sizeof dn);
        cli_size_short(t->size ? t->size : t->down, tot, sizeof tot);
        return (size_t)snprintf(out, cap, "%-*s%s PAUSED  %6s/%-5s  %4u/%-4u%s", CLI_NAME_W, name,
                                sec, dn, tot, (unsigned)t->done, (unsigned)t->total, flags);
    }

    char bar[CLI_BAR_W + 4], dn[16], tot[16], spd_d[16], spd_u[16], eta[16];
    cli_bar_short(t->pct, bar, sizeof bar);
    cli_size_short(t->down, dn, sizeof dn);
    cli_size_short(t->size ? t->size : t->down, tot, sizeof tot);
    cli_speed_short(t->spd_d, spd_d, sizeof spd_d);
    cli_speed_short(t->spd_u, spd_u, sizeof spd_u);
    cli_eta_short(t->eta_s, eta, sizeof eta);

    double ratio = (t->size > 0) ? ((double)t->up / (double)t->size) : 0.0;

    if (t->state == NTX_TTS_DONE || (t->total > 0 && t->done >= t->total)) {
        const char *tag = phase;
        char up[16];
        cli_size_short(t->up, up, sizeof up);
        if (strcmp(phase, "ratio-done") == 0 || ratio >= 3.0 - 1e-9)
            tag = "ratio-done";
        else if (strcmp(phase, "seed") != 0 && strcmp(phase, "ratio-done") != 0)
            tag = "seed";
        /* Live line must show uploaded total (not only rate) — finish line alone was too late. */
        return (size_t)snprintf(out, cap, "%-*s%s 100%% %s  %6s/%-5s  up%-5s ^%-5s r%.1f @%-4s%s",
                                CLI_NAME_W, name, sec, bar, dn, tot, up, spd_u, ratio, tag, flags);
    }

    return (size_t)snprintf(out, cap,
                            "%-*s%s %3u%% %s  %6s/%-5s  v%-5s^%-5s %5s %4u/%-4u @%-4s%s",
                            CLI_NAME_W, name, sec, (unsigned)t->pct, bar, dn, tot, spd_d, spd_u, eta,
                            (unsigned)t->done, (unsigned)t->total, phase, flags);
}

size_t ntx_cli_status_format(const ntx_stats *st, char *out, size_t cap) {
    if (!st || !out || cap == 0) return 0;
    /* raw returns the *would-be* length; the cap needs it, not the truncated
     * strlen, to know how many tags did not fit. */
    size_t want = cli_status_raw(st, out, cap, 0);
    if (cap > 1) cli_cap_line(out, want, cap);
    return strlen(out);
}

/* The tty line (R17). Same budget rules as ntx_cli_status_format(), plus two
 * things the plain formatter must not do because its output is pinned by the
 * docs and the tests: the safety block of a share slot rides behind the name so
 * it sits ahead of the cut, and the final cut is to the terminal width instead
 * of to CLI_MAX_LINE. */
static size_t cli_status_tty(const ntx_stats *st, char *out, size_t cap, int cols) {
    if (!st || !out || cap == 0) return 0;
    size_t want = cli_status_raw(st, out, cap, 1);
    if (cap > 1) cli_cap_line(out, want, cap);
    cli_trim_to_width(out, cols);
    return strlen(out);
}

/* R26: the live line the tty path below drew in place, and the caller's
 * pending-newline flag that belongs to it. The closer needs both, so the CLI —
 * not the caller — owns the state of "a line is open": ntx_diag reaches it
 * through ntx_diag_set_close_hook() and the magnet print reaches the very same
 * function directly. One state, one closer, no caller-side spelling of it. */
static FILE *g_line_fp;
static int *g_line_needs_nl;

void ntx_cli_close_status_line(void) {
    if (!g_line_fp) return; /* nothing open: a no-op, prints nothing */
    fputc('\n', g_line_fp);
    fflush(g_line_fp);
    g_line_fp = NULL;
    if (g_line_needs_nl) *g_line_needs_nl = 0; /* spent: no blank line later */
}

void ntx_cli_status_update(const ntx_stats *st, FILE *fp, int *needs_nl) {
    if (!st || !fp) return;
    char line[CLI_MAX_LINE + 1];

    if (isatty(fileno(fp))) {
        static size_t prev_len = 0;
        cli_status_tty(st, line, sizeof line, cli_term_cols());
        size_t len = strlen(line);
        fputs("\r\033[2K", fp);
        fputs(line, fp);
        for (size_t i = len; i < prev_len; i++)
            fputc(' ', fp);
        prev_len = len;
        fflush(fp);
        if (needs_nl) *needs_nl = 1;
        g_line_fp = fp;
        g_line_needs_nl = needs_nl;
    } else {
        g_line_fp = NULL; /* a pipe line is already terminated: nothing to close */
        ntx_cli_status_format(st, line, sizeof line);
        fputs(line, fp);
        fputc('\n', fp);
        fflush(fp);
    }
    /* Mirror status as newline records into --verbose/--log file (no \r spam). */
    {
        FILE *diag = ntx_diag_fp();
        if (diag && diag != fp) {
            fputs(line, diag);
            fputc('\n', diag);
        }
    }
}

void ntx_cli_status_finish(const ntx_stats *st, FILE *fp, int needs_nl) {
    if (!st || !fp) return;
    /* R26: the summary is written where the live line stopped, so it goes
     * through the one closer — which also FORGETS the line. Left registered, a
     * later diagnostic (the tracker goodbyes below the caller's summary) would
     * pay out a newline of its own on a line that is long over. A caller whose
     * fp is not the line's fp keeps the plain flag spelling. */
    if (fp == g_line_fp) ntx_cli_close_status_line();
    else if (needs_nl) fputc('\n', fp);
    if (st->n <= 0) {
        fputs("ntx: stopped.\n", fp);
        fflush(fp);
        if (ntx_diag_fp() && ntx_diag_fp() != fp) fputs("ntx: stopped.\n", ntx_diag_fp());
        return;
    }
    const ntx_tts_stat *t = &st->t[0];
    char name[CLI_NAME_W + 4], down_sz[16], total_sz[16], up_sz[16];
    char fin[CLI_MAX_LINE + 64];
    cli_name_short(t->name, name, sizeof name);
    cli_size_short(t->down, down_sz, sizeof down_sz);
    cli_size_short(t->size ? t->size : t->down, total_sz, sizeof total_sz);
    cli_size_short(t->up, up_sz, sizeof up_sz);
    double ratio = (t->size > 0) ? ((double)t->up / (double)t->size) : 0.0;
    if (t->total > 0 && t->done >= t->total)
        snprintf(fin, sizeof fin,
                 "ntx: complete — %s (verified %u/%u, %s, uploaded %s r%.1f, phase %s)\n", name,
                 t->done, t->total, total_sz, up_sz, ratio, t->phase[0] ? t->phase : "?");
    else if (t->state == NTX_TTS_META || (t->size == 0 && t->total == 0))
        snprintf(fin, sizeof fin, "ntx: stopped — %s (metadata not fetched, phase %s)\n", name,
                 t->phase[0] ? t->phase : "?");
    else
        snprintf(fin, sizeof fin, "ntx: stopped — %s (verified %u/%u, %s of %s, phase %s)\n",
                 name, t->done, t->total, down_sz, total_sz, t->phase[0] ? t->phase : "?");
    fputs(fin, fp);
    fflush(fp);
    if (ntx_diag_fp() && ntx_diag_fp() != fp) fputs(fin, ntx_diag_fp());
}
