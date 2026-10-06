#include "ntx_cli.h"
#include "ntx_diag.h"

#include "../core/ntx_torrent.h"

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
    snprintf(out, cap, "%.*s", CLI_NAME_W, src);
}

static void cli_flags_compact(const ntx_stats *st, const ntx_tts_stat *t, char *out, size_t cap) {
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
    if (t->meta_need > 0) {
        unsigned mg = t->meta_got > 99 ? 99 : t->meta_got;
        unsigned mn = t->meta_need > 99 ? 99 : t->meta_need;
        snprintf(out, cap, " trk%02u/%02up%02u%s pe%02u/%02u/%02uu%02ui%02u m%02u/%02u%s%s%s%s", tu, tt, tp,
                 dead, a, h, o, u, ii, mg, mn, v2, dns, utp, punch);
    } else {
        snprintf(out, cap, " trk%02u/%02up%02u%s pe%02u/%02u/%02uu%02ui%02u%s%s%s%s", tu, tt, tp, dead, a, h, o,
                 u, ii, v2, dns, utp, punch);
    }
}

static void cli_trim_to_width(char *line, int cols) {
    if (cols <= 0) cols = CLI_MAX_LINE;
    if (cols > CLI_MAX_LINE) cols = CLI_MAX_LINE;
    size_t n = strlen(line);
    if ((int)n >= cols) {
        line[(size_t)cols - 1] = 0;
        if (cols > 2) line[(size_t)cols - 2] = '.';
        if (cols > 3) line[(size_t)cols - 3] = '.';
    }
}

size_t ntx_cli_status_format(const ntx_stats *st, char *out, size_t cap) {
    if (!st || !out || cap == 0) return 0;

    if (st->n <= 0) {
        return (size_t)snprintf(out, cap, "ntx idle  :%u  %llus", (unsigned)st->port,
                                (unsigned long long)st->uptime_s);
    }

    const ntx_tts_stat *t = &st->t[0];
    char name[CLI_NAME_W + 4];
    char flags[96]; /* staging room for trk/pe/m/v2/dns/utp/punch (line trimmed to CLI_MAX_LINE) */
    cli_name_short(t->name, name, sizeof name);
    cli_flags_compact(st, t, flags, sizeof flags);
    const char *phase = t->phase[0] ? t->phase : "?";

    if (t->state == NTX_TTS_META || (t->size == 0 && t->total == 0)) {
        return (size_t)snprintf(out, cap, "%-*s META:%-9s%s %3llus", CLI_NAME_W, name, phase, flags,
                                (unsigned long long)st->uptime_s);
    }

    if (t->state == NTX_TTS_PAUSED) {
        char dn[16], tot[16];
        cli_size_short(t->down, dn, sizeof dn);
        cli_size_short(t->size ? t->size : t->down, tot, sizeof tot);
        return (size_t)snprintf(out, cap, "%-*s PAUSED  %6s/%-5s  %4u/%-4u%s", CLI_NAME_W, name, dn, tot,
                                (unsigned)t->done, (unsigned)t->total, flags);
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
        return (size_t)snprintf(out, cap, "%-*s 100%% %s  %6s/%-5s  up%-5s ^%-5s r%.1f @%-4s%s",
                                CLI_NAME_W, name, bar, dn, tot, up, spd_u, ratio, tag, flags);
    }

    return (size_t)snprintf(out, cap,
                            "%-*s %3u%% %s  %6s/%-5s  v%-5s^%-5s %5s %4u/%-4u @%-4s%s", CLI_NAME_W,
                            name, (unsigned)t->pct, bar, dn, tot, spd_d, spd_u, eta,
                            (unsigned)t->done, (unsigned)t->total, phase, flags);
}

void ntx_cli_status_update(const ntx_stats *st, FILE *fp, int *needs_nl) {
    if (!st || !fp) return;
    char line[CLI_MAX_LINE + 1];
    ntx_cli_status_format(st, line, sizeof line);

    if (isatty(fileno(fp))) {
        static size_t prev_len = 0;
        int cols = cli_term_cols();
        cli_trim_to_width(line, cols);
        size_t len = strlen(line);
        fputs("\r\033[2K", fp);
        fputs(line, fp);
        for (size_t i = len; i < prev_len; i++)
            fputc(' ', fp);
        prev_len = len;
        fflush(fp);
        if (needs_nl) *needs_nl = 1;
    } else {
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
    if (needs_nl) fputc('\n', fp);
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
