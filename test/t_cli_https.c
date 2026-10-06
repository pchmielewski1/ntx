/* CLI --no-https-tofu + --https-pin-file (parse_args in ntx_main.c).
   Standalone: include ntx_main.c (main renamed) + stub its externs. */
#include "../src/core/ntx_config.h"

#define main ntx_main_entry
#include "../src/ntx_main.c"
#undef main

/* ---- stubs: externs referenced by ntx_main.c (link standalone) ---- */
ntx_session *ntx_session_init(ntx_netx *netx, const ntx_config *cfg) { (void)netx; (void)cfg; return 0; }
void ntx_session_free(ntx_session *s) { (void)s; }
int ntx_session_add_magnet(ntx_session *s, const char *url) { (void)s; (void)url; return 0; }
int ntx_session_add_torrent_file(ntx_session *s, const char *path) { (void)s; (void)path; return 0; }
void ntx_session_snapshot(const ntx_session *s, ntx_stats *dst) { (void)s; (void)dst; }
void ntx_session_stats_refresh(struct ntx_session *s, int rotate_ring) { (void)s; (void)rotate_ring; }
void ntx_session_trk_pump_http(ntx_session *s, int max) { (void)s; (void)max; }
void ntx_session_quit(ntx_session *s) { (void)s; }
ntx_netx *ntx_netx_init(const ntx_config *cfg) { (void)cfg; return 0; }
void ntx_netx_run_once(ntx_netx *n, int timeout_ms) { (void)n; (void)timeout_ms; }
void ntx_netx_free(ntx_netx *n) { (void)n; }
int ntx_rng_init(void) { return 0; }
void ntx_http_set_proxy(const char *host, uint16_t port) { (void)host; (void)port; }
void ntx_http_clear_proxy(void) {}
void ntx_doh_set_ui_kick(void (*fn)(void)) { (void)fn; }
int ntx_stats_to_json(const ntx_stats *st, char *out, size_t cap) { (void)st; (void)out; (void)cap; return 0; }
void ntx_cli_status_update(const ntx_stats *st, FILE *fp, int *needs_nl) { (void)st; (void)fp; (void)needs_nl; }
void ntx_cli_status_finish(const ntx_stats *st, FILE *fp, int needs_nl) { (void)st; (void)fp; (void)needs_nl; }
int ntx_diag_open(const char *path) { (void)path; return 0; }
void ntx_diag_close(void) {}
void ntx_diag(const char *fmt, ...) { (void)fmt; }
int ntx_proxy_parse_spec(const char *spec, ntx_config *cfg, char *hostbuf, size_t hcap) {
    (void)spec; (void)cfg; (void)hostbuf; (void)hcap; return 0;
}
int ntx_sock_parse_host_port(const char *spec, char *hostbuf, size_t hcap,
                             const char **host_out, uint16_t *port_out) {
    (void)spec; (void)hostbuf; (void)hcap; (void)host_out; (void)port_out; return -1;
}
void ntx_https_tofu_set_enabled(int on) { (void)on; }
void ntx_https_set_tofu_path(const char *path) { (void)path; }
void ntx_https_pin_set_file(const char *path) { (void)path; }
/* ipc externs referenced by the T7 glue in ntx_main.c (ntx_main_entry is a
   global root so --gc-sections keeps its call graph; this TU never runs it). */
int ntx_ipc_dispatch(struct ntx_session *s, const char *line, char *out, size_t cap) {
    (void)s; (void)line; (void)out; (void)cap; return 0;
}
int ntx_ipc_hello_json(char *out, size_t cap, const char *build_id) {
    (void)out; (void)cap; (void)build_id; return 0;
}
void ntx_ipc_reader_init(ntx_ipc_reader *r) { (void)r; }
void ntx_ipc_feed(ntx_ipc_reader *r, const char *buf, size_t n, const ntx_ipc_sink *sink) {
    (void)r; (void)buf; (void)n; (void)sink;
}
int ntx_doh_verbose;
int ntx_tls_pin_stderr;

static int fail(const char *msg) {
    fprintf(stderr, "FAIL %s\n", msg);
    return 1;
}

static int ok(const char *msg) {
    printf("PASS %s\n", msg);
    return 0;
}

static void run(int argc, char **argv, ntx_config *cfg,
                const char **magnet, const char **torrent, const char **log_out) {
    char proxy_buf[256], tunnel_buf[256];
    parse_args(argc, argv, cfg, proxy_buf, tunnel_buf, magnet, torrent, log_out);
}

int main(void) {
    ntx_config cfg;
    const char *magnet = 0, *torrent = 0, *log_out = 0;

    /* default: https_tofu on, no pin file */
    memset(&cfg, 0, sizeof cfg);
    {
        char *argv[] = { "ntx" };
        run(1, argv, &cfg, &magnet, &torrent, &log_out);
    }
    if (cfg.https_tofu != 1) return fail("default_tofu_on");
    if (cfg.https_pin_file != 0) return fail("default_pin_null");
    if (cfg.utp != 0) return fail("default_utp_off");
    if (ok("default")) return 1;

    /* --no-https-tofu */
    memset(&cfg, 0, sizeof cfg);
    {
        char *argv[] = { "ntx", "--no-https-tofu" };
        run(2, argv, &cfg, &magnet, &torrent, &log_out);
    }
    if (cfg.https_tofu != 0) return fail("no_tofu");
    if (ok("no_tofu")) return 1;

    /* --https-pin-file=x */
    memset(&cfg, 0, sizeof cfg);
    {
        char *argv[] = { "ntx", "--https-pin-file=x" };
        run(2, argv, &cfg, &magnet, &torrent, &log_out);
    }
    if (cfg.https_pin_file == 0 || strcmp(cfg.https_pin_file, "x") != 0) return fail("pin_file");
    if (ok("pin_file")) return 1;

    /* --utp */
    memset(&cfg, 0, sizeof cfg);
    {
        char *argv[] = { "ntx", "--utp" };
        run(2, argv, &cfg, &magnet, &torrent, &log_out);
    }
    if (cfg.utp != 1) return fail("utp_on");
    if (ok("utp_on")) return 1;

    /* --utp combined with --port-lo */
    memset(&cfg, 0, sizeof cfg);
    {
        char *argv[] = { "ntx", "--utp", "--port-lo=6999" };
        run(3, argv, &cfg, &magnet, &torrent, &log_out);
    }
    if (cfg.utp != 1) return fail("utp_combo_utp");
    if (cfg.port_lo != 6999) return fail("utp_combo_port");
    if (ok("utp_combo")) return 1;

    return 0;
}
