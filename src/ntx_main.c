#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <time.h>
#include <errno.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include "ui/ntx_ipc.h"
#include "core/ntx_session.h"
#include "net/ntx_netx.h"
#include "net/ntx_proxy.h"
#include "net/ntx_sock.h"
#include "core/ntx_config.h"
#include "crypto/ntx_rng.h"
#include "core/ntx_time.h"
#include "ui/ntx_stats.h"
#include "ui/ntx_cli.h"
#include "ui/ntx_diag.h"
#include "proto/ntx_http.h"
#include "proto/ntx_share_trackers.h"
#include "core/ntx_share.h"
#include "proto/ntx_doh.h"

#include "proto/ntx_https_pin.h"
#include "net/ntx_tls.h"

static ntx_ipc_reader g_rd;
static int g_ipc_open;   /* command channel: pipe stdin, not a TTY (§3.2) */
static int g_ipc_quit;   /* quit command answered — exit 0 after the ack */
static char g_js[24576]; /* §5.4: static emitter buffer (.bss), zero malloc */
static char g_ack[2048];
static int g_ipc_tick_lines;   /* §3.8: lines dispatched in the current tick */
static char g_ipc_stash[1280]; /* §3.8: one 1024 B chunk, re-framed with \n */
static int g_ipc_stash_len;
#define NTX_IPC_TICK_LINES 64  /* §3.8: at most 64 lines per tick */

#ifndef NTX_NO_MAIN
/* ntx_share_available/ntx_share_err_msg live in ntx_share_trackers.c / ntx_share.c
   and every shipped binary links them. test/t_cli_https.c includes this file
   standalone with its own stub list, where a strong reference would be an
   undefined symbol; weak references keep that TU linking and both wrappers
   below fail closed (options hidden, --share refused) without them.
   ponytail: ceiling = a build that lost the share objects behaves as the §6.4
   gate. Upgrade path: drop the attributes once t_cli_https.c stubs these two
   the way it stubs the session externs. */
__attribute__((weak)) int ntx_share_available(void);
__attribute__((weak)) const char *ntx_share_err_msg(ntx_share_err e);
static int main_share_available(void) { return ntx_share_available ? ntx_share_available() : 0; }
static const char *main_share_err_msg(ntx_share_err e) {
    return ntx_share_err_msg ? ntx_share_err_msg(e) : "sharing is not available in this build";
}
static int g_stats_json;
static volatile sig_atomic_t g_quit;
static char g_magnet_buf[4096];
static ntx_session *g_sess;
static int g_cli_needs_nl;
/* §9: --share/--share-from are main()'s business (ntx_config carries only
   port_map); file scope so parse_args keeps the arity t_cli_https.c calls it with. */
static const char *g_share_path, *g_share_from;
static void on_sig(int sig) { (void)sig; g_quit = 1; }
#endif

static void ipc_emit(const char *line) {
    if (line && line[0]) {
        puts(line);
        fflush(stdout);
    }
}
static int ipc_on_line(void *ud, const char *line) {
    ntx_session *s = (ntx_session *)ud;
    if (g_ipc_tick_lines >= NTX_IPC_TICK_LINES) { /* §3.8: surplus carried over to the next tick */
        int l = (int)strlen(line);
        if (g_ipc_stash_len + l + 1 < (int)sizeof g_ipc_stash) {
            memcpy(g_ipc_stash + g_ipc_stash_len, line, (size_t)l);
            g_ipc_stash_len += l;
            g_ipc_stash[g_ipc_stash_len++] = '\n';
        } /* else: unreachable — the stash is sized for one full 1024 B chunk */
        return 0; /* keep framing the rest of the chunk: the pipe must not lose a line */
    }
    g_ipc_tick_lines++;
    int fl = ntx_ipc_dispatch(s, line, g_ack, sizeof g_ack);
    ipc_emit(g_ack);                    /* ack/err/hello: the reply line (§4) */
    if (fl & NTX_IPC_F_EMIT_STATUS) {   /* §6.2: snapshot outside the tick cadence */
        ntx_session_stats_refresh(s, 0);
        ntx_stats st;
        ntx_session_snapshot(s, &st);
        if (ntx_stats_to_json(&st, g_js, sizeof g_js) > 0) ipc_emit(g_js);
    }
    if (fl & NTX_IPC_F_QUIT) { g_ipc_quit = 1; return 1; } /* last line was the quit */
    return 0;
}
static void ipc_on_bad(void *ud) {
    (void)ud; /* §3.7: overflow → one bad_json, no cmd echo (§8: no meaningful cmd) */
    ipc_emit("{\"type\":\"err\",\"cmd\":\"\",\"ok\":0,\"code\":\"bad_json\"}");
}

/* §3.6/§3.8: one pump tick — commands first, the caller's snapshot after.
   A function (not inlined into main) so test/t_ipc_ctrl.c can drive it over
   a real pipe via the NTX_NO_MAIN include seam. */
static void ipc_pump_tick(ntx_session *s) {
    g_ipc_tick_lines = 0;
    if (g_ipc_stash_len) { /* §3.8: the stashed surplus goes first — already framed,
                             so it must NOT re-enter the framer (g_rd holds the
                             partial line that follows it in stream order). */
        char tmp[1280];
        int m = g_ipc_stash_len;
        memcpy(tmp, g_ipc_stash, (size_t)m);
        g_ipc_stash_len = 0;
        int pos = 0;
        while (pos < m) {
            int e = pos;
            while (e < m && tmp[e] != '\n') e++;
            tmp[e] = 0;
            int stop = ipc_on_line(s, tmp + pos) != 0; /* budget-exceeded → re-stashed inside */
            pos = e + 1;
            if (stop) { g_ipc_open = 0; break; } /* §6.2: quit — the rest dies with the channel */
        }
    }
    int chunks = 0;
    /* §8 + §3.8: a quit (or channel close) seen by the drain must
       stop the pump — re-feeding the pipe after the quit ack would break ack-last
       and run post-quit mutations. Both flags are true on the normal path, so
       the cadence stays bit-identical when no quit/stash is pending. The
       early quit check in main() remains a second safeguard. */
    while (g_ipc_open && !g_ipc_quit && chunks < 64 && g_ipc_tick_lines < NTX_IPC_TICK_LINES) { /* §3.8: 64 lines per tick, the rest stays in the pipe */
        struct pollfd pf = { .fd = 0, .events = POLLIN };
        int pr = poll(&pf, 1, 0); /* §3.5: never waits for a command */
        if (pr < 0 && errno == EINTR) { chunks++; continue; } /* a signal is work: it spends the budget */
        if (pr <= 0 || !(pf.revents & POLLIN)) break;
        char rb[1024];
        ssize_t k = read(0, rb, sizeof rb);
        if (k < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) break;
            g_ipc_open = 0; /* hostile pipe: close the channel, keep serving */
            break;
        }
        if (k == 0) { g_ipc_open = 0; break; } /* §3.9: EOF ≠ kill */
        ntx_ipc_sink snk = { s, ipc_on_line, ipc_on_bad };
        ntx_ipc_feed(&g_rd, rb, (size_t)k, &snk);
        chunks++;
        if (g_ipc_quit) { g_ipc_open = 0; break; }
    }
}

#ifndef NTX_NO_MAIN
static void doh_ui_kick(void) {
    if (!g_sess || g_stats_json) return;
    ntx_session_stats_refresh(g_sess, 0);
    ntx_stats st;
    ntx_session_snapshot(g_sess, &st);
    ntx_cli_status_update(&st, stderr, &g_cli_needs_nl);
}

/* §5.4/§9: share results in the CLI loop. The magnet is the deliverable — one
   line on stdout, so `ntx --share=f > link.txt` is a file ntx accepts as input —
   with the human note on stderr after the status line is closed. 1 = the share
   failed and the caller must leave the loop with exit 1. */
static int share_drain_events(ntx_session *s, int *fatal) {
    ntx_share_event ev;
    while (ntx_session_share_poll_event(s, &ev)) {
        /* Called in CLI mode only: under --stats-json nothing raw may touch stdout
           or stderr, so the queue is left to the `share` event of Task C3
           (ntx_ipc_dispatch.c / ntx_stats.c) — polling it here would steal it. */
        if (!ev.ok) {
            fprintf(stderr, "ntx: share failed: %s\n", main_share_err_msg(ev.err));
            fflush(stderr);
            *fatal = 1;
            return 1;
        }
        if (g_cli_needs_nl) {
            fputc('\n', stderr);
            fflush(stderr);
            g_cli_needs_nl = 0;
        }
        puts(ev.magnet);
        fflush(stdout);
        fprintf(stderr, "ntx: shared — %s (torrent %s)\n", ev.name, ev.torrent_path);
        fflush(stderr);
    }
    return 0;
}

static const char *load_magnet_file(const char *path) {
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    if (!fgets(g_magnet_buf, sizeof g_magnet_buf, f)) {
        fclose(f);
        return 0;
    }
    fclose(f);
    size_t n = strlen(g_magnet_buf);
    while (n && (g_magnet_buf[n - 1] == '\n' || g_magnet_buf[n - 1] == '\r'))
        g_magnet_buf[--n] = 0;
    return strncmp(g_magnet_buf, "magnet:", 7) == 0 ? g_magnet_buf : 0;
}

static void print_usage(FILE *fp, const char *argv0) {
    fprintf(fp,
            "usage: %s [opts] <magnet|link.txt|.torrent>\n"
            "  --store-dir=DIR  --port-lo=N  --port-hi=N  --max-peers=N\n"
            "  --proxy=socks5:HOST:PORT  --tunnel=HOST:PORT\n"
            "  --dht  --compat-peers  --allow-local-peers  --utp  --smooth  --down-limit=B/s  --up-limit=B/s\n"
            "  --no-https-tofu  --https-pin-file=PATH\n"
            "  --stats-json  --verbose  --log=FILE\n",
            argv0);
    /* §6.4: below NTX_SHARE_MIN_TRACKERS usable hosts the feature is not in the
       release, so the options must not be advertised either. */
    if (main_share_available())
        fprintf(fp, "  --share=PATH  --share-from=FILE.torrent  --port-map  --no-port-map\n");
    fprintf(fp, "  -h, --help  -V, --version\n");
}

/* Strict unsigned decimal for numeric options: digits only (no sign, blanks, hex
   or suffix), no overflow, <= max. The former strtol() calls turned "abc" into 0,
   "-1" into a huge limit and a port of 99999 into a silently wrapped uint16_t. */
static int parse_uint_opt(const char *opt, const char *s, uint64_t max, uint64_t *out) {
    char *end = 0;
    errno = 0;
    unsigned long long v = (*s >= '0' && *s <= '9') ? strtoull(s, &end, 10) : 0;
    if (!end || *end || errno == ERANGE || v > max) {
        fprintf(stderr, "ntx: invalid value for %s: '%s' (expected an integer 0..%llu)\n", opt, s,
                (unsigned long long)max);
        return -1;
    }
    *out = v;
    return 0;
}

/* 0 = ok, 1 = --help requested, -1 = invalid command line (message already on stderr).
   A malformed --proxy/--tunnel MUST be fatal: ignoring it would silently send peer and
   tracker traffic out directly, bypassing the proxy the user asked for. */
static int parse_args(int argc, char **argv, ntx_config *cfg, char *proxy_buf, char *tunnel_buf,
                      const char **magnet_out, const char **torrent_out, const char **log_out) {
    uint64_t n;
    int pm_on = 0, pm_off = 0;
    cfg->https_tofu = 1;
    g_share_path = 0;
    g_share_from = 0;
    for (int i = 1; i < argc; i++) {
        const char *a = argv[i];
        if (strcmp(a, "--help") == 0 || strcmp(a, "-h") == 0) return 1;
        if (strncmp(a, "--store-dir=", 12) == 0) cfg->store_dir = a + 12;
        else if (strncmp(a, "--port-lo=", 10) == 0) {
            if (parse_uint_opt("--port-lo", a + 10, 65535, &n)) return -1;
            cfg->port_lo = (uint16_t)n;
        } else if (strncmp(a, "--port-hi=", 10) == 0) {
            if (parse_uint_opt("--port-hi", a + 10, 65535, &n)) return -1;
            cfg->port_hi = (uint16_t)n;
        } else if (strncmp(a, "--max-peers=", 12) == 0) {
            if (parse_uint_opt("--max-peers", a + 12, 0x7fffffff, &n)) return -1;
            cfg->max_peers = (int)n;
        } else if (strncmp(a, "--proxy=", 8) == 0) {
            if (ntx_proxy_parse_spec(a + 8, cfg, proxy_buf, 256) != 0) {
                fprintf(stderr, "ntx: invalid --proxy value '%s' (expected socks5:HOST:PORT)\n", a + 8);
                return -1;
            }
        } else if (strncmp(a, "--tunnel=", 9) == 0) {
            if (ntx_sock_parse_host_port(a + 9, tunnel_buf, 256, &cfg->tunnel_host, &cfg->tunnel_port) != 0) {
                fprintf(stderr, "ntx: invalid --tunnel value '%s' (expected HOST:PORT)\n", a + 9);
                return -1;
            }
            cfg->tunnel = 1;
        } else if (strncmp(a, "--down-limit=", 13) == 0) {
            if (parse_uint_opt("--down-limit", a + 13, UINT64_MAX, &n)) return -1;
            cfg->down_limit = n;
        } else if (strncmp(a, "--up-limit=", 11) == 0) {
            if (parse_uint_opt("--up-limit", a + 11, UINT64_MAX, &n)) return -1;
            cfg->up_limit = n;
        } else if (strcmp(a, "--no-https-tofu") == 0) cfg->https_tofu = 0;
        else if (strncmp(a, "--https-pin-file=", 17) == 0) cfg->https_pin_file = a + 17;
        else if (strncmp(a, "--log=", 6) == 0) *log_out = a + 6;
        else if (strcmp(a, "--dht") == 0) cfg->dht = 1;
        else if (strcmp(a, "--compat-peers") == 0) cfg->compat_peers = 1;
        else if (strcmp(a, "--allow-local-peers") == 0) cfg->allow_local_peers = 1;
        else if (strcmp(a, "--utp") == 0) cfg->utp = 1;
        else if (strcmp(a, "--smooth") == 0) cfg->smooth = 1;
        else if (strncmp(a, "--share-from=", 13) == 0) g_share_from = a + 13;
        else if (strncmp(a, "--share=", 8) == 0) {
            /* §9: --share is a torrent source, so it cannot ride a magnet or a
               .torrent argument, and it cannot be given twice. */
            if (g_share_path) {
                fprintf(stderr, "ntx: --share given twice\n");
                return -1;
            }
            g_share_path = a + 8;
        } else if (strcmp(a, "--port-map") == 0) pm_on = 1;
        else if (strcmp(a, "--no-port-map") == 0) pm_off = 1;
        else if (strcmp(a, "--stats-json") == 0) g_stats_json = 1;
        else if (strcmp(a, "--verbose") == 0 || strcmp(a, "-v") == 0) cfg->verbose = 1;
        else if (strncmp(a, "magnet:", 7) == 0) *magnet_out = a;
        else if (strlen(a) >= 8 && strcmp(a + strlen(a) - 8, ".torrent") == 0) *torrent_out = a;
        else if (a[0] == '-' && a[1]) {
            fprintf(stderr, "ntx: unknown option '%s'\n", a);
            return -1;
        } else if (!*magnet_out) {
            const char *m = load_magnet_file(a);
            if (!m) {
                fprintf(stderr,
                        "ntx: '%s' is not a magnet link, a .torrent file, or a readable file "
                        "whose first line is a magnet link\n",
                        a);
                return -1;
            }
            *magnet_out = m;
        } else {
            fprintf(stderr, "ntx: unexpected argument '%s'\n", a);
            return -1;
        }
    }
    /* The DHT is plain UDP from our own socket: with a proxy/tunnel it would reveal the address the user
     * asked to hide.  Refuse the combination instead of leaking silently. */
    if (cfg->dht && (cfg->proxy || cfg->tunnel)) {
        fprintf(stderr, "ntx: --dht cannot be combined with --proxy/--tunnel (DHT traffic is UDP and would bypass them)\n");
        return -1;
    }
    /* §9: the share flag combinations. Wording is a contract (test/cli_errors.sh
       compares these lines exactly), so it is not free text. */
    if (g_share_path && (*magnet_out || *torrent_out)) {
        fprintf(stderr, "ntx: --share cannot be combined with a magnet or .torrent argument\n");
        return -1;
    }
    if (g_share_from && !g_share_path) {
        fprintf(stderr, "ntx: --share-from requires --share\n");
        return -1;
    }
    if (pm_on && pm_off) {
        fprintf(stderr, "ntx: --port-map and --no-port-map are mutually exclusive\n");
        return -1;
    }
    /* Inbound peers would arrive through the proxy path the mapping is meant to
       avoid, and the mapping itself announces our real address. */
    if (pm_on && (cfg->proxy || cfg->tunnel)) {
        fprintf(stderr, "ntx: --port-map cannot be used with --proxy or --tunnel (inbound traffic would bypass it and the mapping would reveal your address)\n");
        return -1;
    }
    cfg->port_map = pm_on ? 1 : (pm_off ? -1 : 0);
    return 0;
}

#ifndef NTX_IPC_BUILD_ID
#define NTX_IPC_BUILD_ID "seed-ratio-v1"
#endif
#define NTX_BUILD_ID NTX_IPC_BUILD_ID

int main(int argc, char **argv) {
    for (int i = 1; i < argc; i++)
        if (strcmp(argv[i], "--version") == 0 || strcmp(argv[i], "-V") == 0) {
            printf("ntx %s\n", NTX_VERSION);
            return 0;
        }
    fprintf(stderr, "ntx: build %s compiled %s %s\n", NTX_BUILD_ID, __DATE__, __TIME__);
    ntx_config cfg = {0};
    char proxy_buf[256], tunnel_buf[256];
    const char *magnet = 0, *torrent = 0, *log_path = 0;
    cfg.store_dir = "downloads";
    cfg.compat_peers = 1;
    cfg.port_lo = 6881;
    cfg.port_hi = 6891;
    cfg.max_peers = 128;
    int pa = parse_args(argc, argv, &cfg, proxy_buf, tunnel_buf, &magnet, &torrent, &log_path);
    if (pa > 0) {
        print_usage(stdout, argv[0]);
        return 0;
    }
    if (pa < 0) {
        fprintf(stderr, "ntx: try '%s --help'\n", argv[0]);
        return 2;
    }
    ntx_doh_verbose = cfg.verbose;
    ntx_tls_pin_stderr = cfg.verbose;
    if (!magnet && !torrent && !g_share_path && !g_stats_json) {
        print_usage(stderr, argv[0]);
        return 2;
    }
    /* §6.4: with too few pinned share trackers the feature is not in the release —
       the same no_trackers error as the JSON command, and the reason is the
       share module's text, not ours. */
    if (g_share_path && !main_share_available()) {
        fprintf(stderr, "ntx: cannot share: %s\n", main_share_err_msg(NTX_SHARE_E_NO_TRACKERS));
        return 1;
    }
    if (cfg.verbose || log_path) {
        if (!log_path) log_path = "ntx-verbose.log";
        if (ntx_diag_open(log_path) != 0)
            fprintf(stderr, "ntx: cannot open log %s errno=%d\n", log_path, errno);
        else
            ntx_diag("ntx: verbose log %s\n", log_path);
    }
    if (cfg.smooth && !cfg.down_limit) cfg.down_limit = 128 * 1024;
    if (cfg.smooth && !cfg.up_limit) cfg.up_limit = 32 * 1024;
    if (cfg.proxy && cfg.proxy_host) ntx_http_set_proxy(cfg.proxy_host, cfg.proxy_port);
    if (cfg.https_tofu) {
        char tofu_path[256];
        snprintf(tofu_path, sizeof tofu_path, "%s/https_tofu.bin", cfg.store_dir);
        ntx_https_tofu_set_enabled(1);
        ntx_https_set_tofu_path(tofu_path);
    } else {
        ntx_https_tofu_set_enabled(0);
    }
    if (cfg.https_pin_file) ntx_https_pin_set_file(cfg.https_pin_file);
    if (ntx_rng_init() != 0) {
        ntx_diag_close();
        return 1;
    }
    ntx_netx *netx = ntx_netx_init(&cfg);
    if (!netx) {
        fprintf(stderr, "ntx: cannot initialise networking (out of memory or no sockets available)\n");
        ntx_http_clear_proxy();
        ntx_diag_close();
        return 1;
    }
    ntx_session *s = ntx_session_init(netx, &cfg);
    if (!s) {
        fprintf(stderr, "ntx: cannot allocate session (out of memory)\n");
        ntx_http_clear_proxy();
        ntx_netx_free(netx);
        ntx_diag_close();
        return 1;
    }
    g_sess = s;
    g_cli_needs_nl = 0;
    ntx_doh_set_ui_kick(doh_ui_kick);
    /* A torrent that cannot be added is a hard error: otherwise the client would sit
       "idle" forever on a typo'd path or a malformed magnet link. */
    int add_failed = 0;
    if (magnet && ntx_session_add_magnet(s, magnet) != 0) {
        fprintf(stderr, "ntx: invalid magnet link (needs xt=urn:btih:... or urn:btmh:...): %s\n", magnet);
        add_failed = 1;
    } else if (torrent && ntx_session_add_torrent_file(s, torrent) != 0) {
        fprintf(stderr, "ntx: cannot load .torrent file (missing, empty or not valid metainfo): %s\n",
                torrent);
        add_failed = 1;
    } else if (g_share_path) {
        /* Synchronous gate only (open, S_ISREG, size, name, slot): hashing and the
           trackers run in the session tick, so no share here has reached the network. */
        ntx_share_err serr = NTX_SHARE_OK;
        if (ntx_session_share_add(s, g_share_path, g_share_from, &serr) < 0) {
            fprintf(stderr, "ntx: cannot share %s: %s\n", g_share_path, main_share_err_msg(serr));
            add_failed = 1;
        }
    }
    if (add_failed) {
        ntx_http_clear_proxy();
        ntx_session_free(s);
        ntx_netx_free(netx);
        ntx_diag_close();
        return 1;
    }
    signal(SIGINT, on_sig);
    signal(SIGTERM, on_sig);
    signal(SIGPIPE, SIG_IGN);
    if (g_stats_json) {
        char hl[512];
        if (ntx_ipc_hello_json(hl, sizeof hl, NTX_BUILD_ID) > 0) ipc_emit(hl); /* §7: once, before the first stats */
        if (!isatty(fileno(stdin))) { /* §3.2: TTY never becomes the protocol */
            int fl = fcntl(0, F_GETFL);
            if (fl >= 0) fcntl(0, F_SETFL, fl | O_NONBLOCK);
            ntx_ipc_reader_init(&g_rd);
            g_ipc_open = 1;
        }
    }

    uint64_t last_ui = 0;
    int ui_tick = 0, share_failed = 0;
    for (;;) {
        ntx_session_trk_pump_udp(s);
        ntx_session_trk_pump_http(s, 1);
        ntx_netx_run_once(netx, 50);
        /* CLI mode only: under --stats-json the share event is JSON's (§9/C3). */
        if (g_share_path && !g_stats_json && share_drain_events(s, &share_failed)) break;
        if (g_ipc_open) ipc_pump_tick(s); /* §3.6: commands first, then the snapshot */
        if (g_ipc_quit) break; /* ack already on stdout; exit code 0 (§6.2) */
        uint64_t now = ntx_mono_ms();
        if (now - last_ui >= 100) {
            ntx_session_stats_refresh(s, (++ui_tick % 10) == 0);
            ntx_stats st;
            ntx_session_snapshot(s, &st);
            if (g_stats_json) {
                if (ntx_stats_to_json(&st, g_js, sizeof g_js) > 0) {
                    puts(g_js);
                    fflush(stdout);
                }
            } else {
                ntx_cli_status_update(&st, stderr, &g_cli_needs_nl);
            }
            last_ui = now;
        }
        if (g_quit) {
            ntx_session_quit(s);
            break;
        }
    }
    if (!g_stats_json) {
        ntx_stats st;
        ntx_session_snapshot(s, &st);
        ntx_cli_status_finish(&st, stderr, g_cli_needs_nl);
    }
    ntx_session_trk_stop_all(s); /* event=stopped, best effort, bounded */
    ntx_http_clear_proxy();
    ntx_session_free(s);
    ntx_netx_free(netx);
    ntx_diag_close();
    /* §9: a share that failed while it was the only torrent is a startup-class
       failure — the message is already on stderr, the exit code says 1. */
    return share_failed ? 1 : 0;
}
#endif /* NTX_NO_MAIN */
