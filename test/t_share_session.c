/* Task A5: share lifecycle in the session (design §5.1..§5.5).
 * Same .c set as test/t_session_trk_stop.c (which already pulls in the share
 * sources), a loopback ntx_netx like test/t_session_trk_http_peers.c and a
 * forked local TCP tracker like test/t_session_trk_stop.c. HTTPS is enforced by
 * the built-in list and pins.py (C4), not by this module, so the test trackers
 * are plain http:// on loopback. */
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

#include "../src/core/ntx_share.c"
#include "../src/core/ntx_share_meta.c"
#include "../src/core/ntx_share_out.c"
#include "../src/core/ntx_session_priv.c"
#include "../src/core/ntx_session_portmap.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/proto/ntx_pcp.c"

#include <arpa/inet.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define SCRATCH "test/.scratch/a5"
#define BIG_MIB 64

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    fflush(stdout);
    exit(1);
}
static void ok(const char *m) { printf("PASS %s\n", m); }

static uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ull + (uint64_t)ts.tv_nsec;
}

static void scratch(void) {
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) fail("scratch_root");
    if (mkdir(SCRATCH, 0755) != 0 && errno != EEXIST) fail("scratch");
    static const char *const tags[] = {"gates","hash","started","rmhash","pin","revive","ratio","a4","ceil","fdheld"};
    for (size_t k = 0; k < sizeof tags / sizeof tags[0]; k++) {
        char d[640];
        snprintf(d, sizeof d, SCRATCH "/%s", tags[k]);
        if (mkdir(d, 0755) != 0 && errno != EEXIST) fail("scratch_tag");
        if (mkdir(d, 0755) != 0 && errno != EEXIST) fail("scratch_st");
        /* the store dirs must start empty: a leftover .torrent (the salt makes
         * every run's hash new) would turn the A4 write into E_EXISTS */
        DIR *sd = opendir(d);
        if (sd) {
            struct dirent *de;
            while ((de = readdir(sd)))
                if (de->d_name[0] != '.') {
                    snprintf(d, sizeof d, SCRATCH "/st_%s/%s", tags[k], de->d_name);
                    unlink(d);
                }
            closedir(sd);
        }
    }
}

/* Deterministic file content, written in 1 MiB chunks from one fd. */
static void mk_file(const char *path, uint64_t size, uint8_t seed) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) fail("mk_open");
    static uint8_t buf[1 << 20];
    uint32_t x = 0x12345678u ^ seed;
    uint64_t done = 0;
    while (done < size) {
        size_t want = size - done < sizeof buf ? (size_t)(size - done) : sizeof buf;
        for (size_t i = 0; i < want; i++) {
            x = x * 1103515245u + 12345u;
            buf[i] = (uint8_t)(x >> 16);
        }
        if (write(fd, buf, want) != (ssize_t)want) fail("mk_write");
        done += want;
    }
    if (fsync(fd) != 0) fail("mk_fsync");
    close(fd);
}

static int file_exists(const char *p) {
    struct stat sb;
    return stat(p, &sb) == 0;
}

/* --- forked local HTTP tracker: answers every announce with a valid empty
 * dictionary and appends each request line (one per line) to a pipe. --- */
typedef struct {
    pid_t pid;
    int rfd;
    uint16_t port;
    char lines[16384];
    size_t n_lines;
} tracker;

static void tracker_start(tracker *t) {
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    int on = 1;
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof on);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&a, sizeof a) != 0 || listen(lfd, 16) != 0) fail("trk_bind");
    socklen_t al = sizeof a;
    getsockname(lfd, (struct sockaddr *)&a, &al);
    t->port = ntohs(a.sin_port);
    int p[2];
    if (pipe(p) != 0) fail("trk_pipe");
    pid_t pid = fork();
    if (pid == 0) {
        close(p[0]);
        alarm(60);
        for (;;) {
            int c = accept(lfd, NULL, NULL);
            if (c < 0) _exit(0);
            char req[4096];
            ssize_t n = read(c, req, sizeof req - 1);
            if (n > 0) {
                req[n] = 0;
                char *eol = strstr(req, "\r\n");
                if (eol) *eol = 0;
                char *sp = strchr(req, ' '), *ur = sp ? strchr(sp + 1, ' ') : NULL;
                if (ur) *ur = 0;
                char out[4200];
                int ol = snprintf(out, sizeof out, "%s\n", req);
                if (ol > 0 && write(p[1], out, (size_t)ol) < 0) _exit(2);
            }
            const char *resp = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nConnection: close\r\n\r\nd8:intervali60ee";
            if (write(c, resp, strlen(resp)) < 0) _exit(2);
            close(c);
        }
    }
    t->pid = pid;
    close(lfd);
    close(p[1]);
    t->rfd = p[0];
    t->n_lines = 0;
    t->lines[0] = 0;
}

static void tracker_drain(tracker *t) {
    for (;;) {
        struct pollfd pf = {t->rfd, POLLIN, 0};
        if (poll(&pf, 1, 25) <= 0) return;
        char tmp[4200];
        ssize_t n = read(t->rfd, tmp, sizeof tmp);
        if (n <= 0) return;
        if (t->n_lines + (size_t)n + 1 < sizeof t->lines) {
            memcpy(t->lines + t->n_lines, tmp, (size_t)n);
            t->n_lines += (size_t)n;
            t->lines[t->n_lines] = 0;
        }
    }
}

static int tracker_count(tracker *t) {
    tracker_drain(t);
    int c = 0;
    for (size_t i = 0; i < t->n_lines; i++)
        if (t->lines[i] == '\n') c++;
    return c;
}

static void tracker_stop(tracker *t) {
    kill(t->pid, SIGKILL);
    waitpid(t->pid, NULL, 0);
    close(t->rfd);
    t->rfd = -1;
}

static void set_test_trackers(tracker *t, int n) {
    static ntx_share_tracker tv[2];
    static char urls[2][64];
    for (int i = 0; i < n; i++) {
        snprintf(urls[i], sizeof urls[i], "http://127.0.0.1:%u/announce%s", (unsigned)t->port, i ? "2" : "");
        tv[i].url = urls[i];
        tv[i].host = "127.0.0.1";
        tv[i].npins = 1;
        memset(tv[i].pins, 0, sizeof tv[i].pins);
    }
    ntx_share_trackers_test_set(tv, n);
}

typedef struct {
    ntx_config cfg;
    ntx_netx *n;
    ntx_session *s;
} sess;

static void sess_open(sess *x, const char *tag) {
    char dir[640];
    snprintf(dir, sizeof dir, SCRATCH "/st_%s", tag);
    if (mkdir(dir, 0755) != 0 && errno != EEXIST) fail("sess_dir");
    memset(&x->cfg, 0, sizeof x->cfg);
    x->cfg.store_dir = strdup(dir);
    x->cfg.port_lo = 6975;
    x->cfg.port_hi = 6995;
    x->cfg.max_peers = 8;
    x->cfg.dht = 0;
    x->n = ntx_netx_init(&x->cfg);
    if (!x->n) fail("netx_init");
    x->s = ntx_session_init(x->n, &x->cfg);
    if (!x->s) fail("sess_init");
}

static void sess_close(sess *x) {
    ntx_session_free(x->s);
    ntx_netx_free(x->n);
}

/* Pins the driver without letting it talk to a gateway: the B5 hook pattern —
 * the state field is forced, so behaviour 5 is pinned by the ENUM, not by a
 * natural NTX_PM_PENDING transition (the stub never reaches PENDING). */
static void pm_park(sess *x, ntx_pm_state st) {
    if (!x->s->pm) ntx_session_portmap_want(x->s, 1);
    if (!x->s->pm) fail("pm_park_alloc");
    x->s->pm->want = 0;
    x->s->pm->st = st;
}

/* Ticks until the share leaves HASHING. Returns the longest single
 * ntx_session_tick observed, in milliseconds. */
static uint64_t pump_until_hashed(sess *x, int ti, int max_ticks, int *out_ticks) {
    uint64_t max_ms = 0;
    int i = 0;
    for (; i < max_ticks; i++) {
        uint64_t t0 = now_ns();
        ntx_session_tick(x->s);
        uint64_t dt = (now_ns() - t0) / 1000000ull;
        if (dt > max_ms) max_ms = dt;
        if (ntx_session_share_state(x->s, ti) != NTX_SHARE_HASHING) break;
    }
    if (out_ticks) *out_ticks = i + 1;
    return max_ms;
}

/* Drives the queued HTTP announce to the local tracker: clears the announce
 * jitter and pumps, which runs the blocking loopback GET synchronously. */
static void pump_announces(sess *x, int ti) {
    for (int k = 0; k < NTX_SESSION_MAX_TRK; k++) x->s->trk_http_due[ti][k] = 0;
    ntx_session_trk_pump_http(x->s, NTX_SESSION_MAX_TRK);
}

/* ---------------- case 1: §5.1 input gates ---------------- */
static void test_add_gates(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);

    sess x;
    sess_open(&x, "gates");
    ntx_share_err e = NTX_SHARE_OK;
    if (ntx_session_share_add(x.s, SCRATCH, NULL, &e) != -1 || e != NTX_SHARE_E_IO) fail("add_dir_io");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/gates/empty");
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("empty_open");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_IO) fail("add_empty_io");
    snprintf(p, sizeof p, SCRATCH "/gates/\001bad");
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("ctl_open");
        if (write(fd, "x", 1) != 1) fail("ctl_write");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_BAD_NAME) fail("add_ctl_bad_name");
    snprintf(p, sizeof p, SCRATCH "/gates/small.bin");
    mk_file(p, 200000, 1);
    if (ntx_session_share_add(x.s, p, NULL, &e) < 0 || e != NTX_SHARE_OK) fail("add_two_trackers");

    ntx_share_trackers_test_set(NULL, 0);
    snprintf(p, sizeof p, SCRATCH "/gates/small2.bin");
    mk_file(p, 4000, 2);
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_NO_TRACKERS) fail("add_no_trackers");
    ntx_session_share_free(x.s);
    sess_close(&x);
    tracker_stop(&tr);
    ok("add_gates");
}

/* ------ cases 2+3+4: VERIFY/hash phase, tick budget, on-disk results ------ */
static void test_hash_and_results(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);

    sess x;
    sess_open(&x, "hash");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/hash/big.bin");
    mk_file(p, (uint64_t)BIG_MIB << 20, 7);
    struct stat before;
    if (stat(p, &before) != 0) fail("big_stat");

    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_big");
    if (x.s->tts[ti].state != NTX_TTS_VERIFY) fail("state_not_verify");
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("share_not_hashing");
    static const uint8_t zeros[20];
    if (memcmp(x.s->tts[ti].info_hash, zeros, 20) != 0) fail("ih_not_zeros");
    if (x.s->tts[ti].priv != 1 || x.s->tts_enc_strict[ti] != 1) fail("priv_or_strict");
    if (x.s->trk_n[ti] != 2) fail("trk_urls_from_list");
    if (x.s->trk_urls[ti][0][0] == 0) fail("trk_url_empty");
    if (!x.s->pm || !x.s->pm->want) fail("portmap_not_requested"); /* behaviour 2 */
    pm_park(&x, NTX_PM_OFF);

    ntx_session_stats_refresh(x.s, 0);
    ntx_stats st;
    ntx_session_snapshot(x.s, &st);
    if (strcmp(st.t[ti].phase, "hash") != 0) fail("phase_not_hash");
    if (st.t[ti].share != 1) fail("stats_share_flag");
    if (ntx_session_share_pct(x.s, ti) > 100) fail("pct_range");
    if (ntx_session_share_serving(x.s, ti) != 0) fail("serving_during_hash");

    int ticks = 0;
    uint64_t max_ms = pump_until_hashed(&x, ti, 6000, &ticks);
    printf("MEASURE 64MiB ticks=%d max_tick_ms=%llu (budget %d ms, gate 50 ms)\n", ticks,
           (unsigned long long)max_ms, NTX_SHARE_HASH_BUDGET_MS);
    if (max_ms > 50) fail("tick_over_50ms");
    ntx_share_state sh = ntx_session_share_state(x.s, ti);
    if (sh != NTX_SHARE_ANNOUNCING && sh != NTX_SHARE_READY) fail("hash_did_not_finish");
    if (x.s->tts[ti].state != NTX_TTS_DONE) fail("tts_not_done");
    if (x.s->tts[ti].pre_complete != 1) fail("pre_complete");
    if (x.s->tts[ti].np == 0 || x.s->tts[ti].have_n != x.s->tts[ti].np) fail("have_all");
    if (x.s->tts[ti].store.ro != 1) fail("store_ro");
    if (x.s->tts[ti].verified_B != x.s->tts[ti].size) fail("verified_B");

    char plain[256], tp[NTX_SHARE_PATH_MAX];
    snprintf(plain, sizeof plain, "%s/%s", x.cfg.store_dir, "big.bin");
    if (file_exists(plain)) fail("source_name_in_store");
    if (ntx_share_torrent_path(tp, sizeof tp, x.cfg.store_dir, "big.bin", x.s->tts[ti].info_hash) != 0)
        fail("torrent_path_build");
    if (!file_exists(tp)) fail("torrent_missing");

    struct stat after;
    if (stat(p, &after) != 0) fail("big_stat_after");
    if (after.st_size != before.st_size || after.st_ino != before.st_ino ||
        after.st_mtime != before.st_mtime || after.st_mtim.tv_nsec != before.st_mtim.tv_nsec)
        fail("source_mtime_changed");

    /* A4 write gate: the real bytes with a wrong info-hash → E_BAD_ARG and no file */
    static uint8_t tb[1 << 22];
    size_t tn = 0;
    {
        int fd = open(tp, O_RDONLY);
        if (fd < 0) fail("torrent_read");
        ssize_t r = read(fd, tb, sizeof tb);
        close(fd);
        if (r <= 0) fail("torrent_read2");
        tn = (size_t)r;
    }
    uint8_t bad[20];
    memcpy(bad, x.s->tts[ti].info_hash, 20);
    bad[0] ^= 0xFF;
    char other[NTX_SHARE_PATH_MAX];
    snprintf(other, sizeof other, "%s/gate_probe.torrent", x.cfg.store_dir);
    if (ntx_share_write_torrent(other, tb, tn, bad) != NTX_SHARE_E_BAD_ARG) fail("gate_bad_arg");
    if (file_exists(other)) fail("gate_wrote_anyway");
    { /* a foreign file at that path stays the E_EXISTS contract (no over-cap special case) */
        int fd = open(other, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) fail("foreign_open");
        if (write(fd, "d6:lengthi1e", 12) != 12) fail("foreign_write");
        close(fd);
    }
    if (ntx_share_write_torrent(other, tb, tn, x.s->tts[ti].info_hash) != NTX_SHARE_E_EXISTS) fail("gate_exists");
    unlink(other);

    if (ntx_session_share_serving(x.s, ti) != 1) fail("serving_after_hash");
    ntx_session_remove(x.s, ti);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_NONE) fail("remove_clears_share");
    if (x.s->pm && x.s->pm->want) fail("pm_not_released"); /* last share → want(s,0) */
    sess_close(&x);
    tracker_stop(&tr);
    ok("hash_and_results");
}

/* ---- case 5: started announce (left=0), one ok event, magnet round-trip ---- */
static void test_started_and_magnet(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "started");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/started/f.bin");
    mk_file(p, 300000, 11);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_started");
    pm_park(&x, NTX_PM_PENDING); /* gate pinned on the enum, not a real transition */
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("not_announcing");

    for (int i = 0; i < 5; i++) ntx_session_tick(x.s);
    pump_announces(&x, ti);
    if (tracker_count(&tr) != 0) fail("announce_while_pm_pending");

    x.s->pm->st = NTX_PM_OFF; /* §8: success, failure or skipped — never wait forever */
    for (int i = 0; i < 8 && tracker_count(&tr) < 1; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    int reqs = tracker_count(&tr);
    if (reqs < 1) fail("no_started_request");
    if (!strstr(tr.lines, "event=started")) fail("started_event_missing");
    if (!strstr(tr.lines, "left=0")) { printf("REQ[%s]\n", tr.lines); printf("VB=%llu SIZE=%llu HM=%d NP=%u\n", (unsigned long long)x.s->tts[ti].verified_B, (unsigned long long)x.s->tts[ti].size, (int)x.s->tts[ti].have_meta, x.s->tts[ti].np); fail("left_zero_missing"); }
    printf("PASS started_request reqs=%d (left=0, event=seen)\n", reqs);

    if (x.s->trk_started_ok[ti] != 1) fail("started_ok_flag");
    for (int i = 0; i < 4 && ntx_session_share_state(x.s, ti) != NTX_SHARE_READY; i++)
        ntx_session_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_READY) fail("not_ready");

    ntx_share_event ev;
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("no_ok_event");
    if (!ev.ok || ev.i != ti || ev.err != NTX_SHARE_OK) fail("event_fields");
    if (!ev.magnet[0] || !ev.torrent_path[0] || !ev.name[0]) fail("event_empty_strings");
    if (strcmp(ev.torrent_path, "") == 0) fail("event_path");
    ntx_magnet mg;
    if (ntx_magnet_parse(ev.magnet, &mg) != 0) fail("magnet_parse");
    if (memcmp(mg.info_hash, x.s->tts[ti].info_hash, 20) != 0) fail("magnet_btih");
    if (!mg.has_v2 || memcmp(mg.ih_v2, x.s->tts[ti].info_hash_v2, 32) != 0) fail("magnet_btmh");
    if (mg.n_trackers != 2) fail("magnet_trackers");
    if (!strstr(mg.name, "f.bin")) fail("magnet_name");

    ntx_session_stats_refresh(x.s, 0);
    ntx_stats st2;
    ntx_session_snapshot(x.s, &st2);
    if (st2.t[ti].share != 1 || st2.t[ti].priv != 1 || st2.t[ti].enc_strict != 1) fail("stats_after_ready");
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("second_event_leaked"); /* exactly one */
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("started_magnet_one_event");
}

/* ----------- case 6: remove during hashing (review focus 2) ----------- */
static void test_remove_during_hash(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "rmhash");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/rmhash/g.bin");
    mk_file(p, (uint64_t)32 << 20, 13);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_rmhash");
    pm_park(&x, NTX_PM_OFF);
    for (int i = 0; i < 3; i++) ntx_session_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("hashed_too_fast");
    ntx_session_remove(x.s, ti);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_NONE) fail("rm_state");
    if (x.s->share[ti] != NULL) fail("rm_slot");

    DIR *d = opendir(x.cfg.store_dir);
    if (!d) fail("opendir_store");
    struct dirent *de;
    while ((de = readdir(d)))
        if (strncmp(de->d_name, "g.bin", 5) == 0) fail("tmp_or_torrent_left");
    closedir(d);

    ntx_share_event ev;
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("event_after_remove");
    for (int i = 0; i < 3; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (tracker_count(&tr) != 0) fail("tracker_saw_stopped_or_started");
    sess_close(&x);
    tracker_stop(&tr);
    ok("remove_during_hash");
}

/* -------- case 7: pin fail (E_PIN seam) — never revived this session -------- */
static int pin_get(const char *url, uint8_t *out, size_t cap, size_t *out_n) {
    (void)url; (void)out; (void)cap; (void)out_n;
    return NTX_HTTP_E_PIN; /* E_PIN return site lands with Task B3; seam pinned here */
}

static void test_pin_fail(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "pin");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/pin/h.bin");
    mk_file(p, 60000, 17);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_pin");
    pm_park(&x, NTX_PM_OFF);
    (void)pump_until_hashed(&x, ti, 2000, NULL);

    int (*saved)(const char *, uint8_t *, size_t, size_t *) = strk_http_get;
    strk_http_get = pin_get;
    trk_http_announce(x.s, ti, 0, x.s->trk_urls[ti][0], NTX_TRACKER_EVENT_STARTED);
    if (x.s->trk_pin_fail[ti][0] != 1) fail("pin_flag");
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL) fail("pin_max_fail");
    if (x.s->trk_started_ok[ti] != 0) fail("pin_set_started_ok");
    ntx_session_share_tick(x.s); /* arms the revival clock … */
    ntx_share_test_advance_ms(3600000);
    ntx_session_share_tick(x.s); /* … which must not fire for a pinned key */
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL) fail("pin_revived");
    if (x.s->trk_pin_fail[ti][0] != 1) fail("pin_flag_cleared");

    trk_http_announce(x.s, ti, 1, x.s->trk_urls[ti][1], NTX_TRACKER_EVENT_STARTED);
    if (x.s->trk_pin_fail[ti][1] != 1) fail("pin_second");
    strk_http_get = saved;
    ntx_session_share_tick(x.s); /* §5.5 all-pinned wording goes to stderr here */
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("pin_changed_state");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("pin_fail_no_revival");
}

/* ------ case 8: ordinary tracker death → revival after 300 s, then 600 s ------ */
static void test_revival(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "revive");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/revive/i.bin");
    mk_file(p, 60000, 19);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_revive");
    pm_park(&x, NTX_PM_OFF);
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("revive_not_announcing");

    x.s->trk_fail[ti][0] = NTX_TRK_MAX_FAIL;
    x.s->trk_next[ti] = 12345; /* the revival must clear this */
    ntx_session_share_tick(x.s); /* observes the death, arms 300 s */
    ntx_share_test_advance_ms(299000);
    ntx_session_share_tick(x.s);
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL) fail("revived_too_early");
    ntx_share_test_advance_ms(2000);
    ntx_session_share_tick(x.s);
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL - 1) fail("not_revived_after_300s");
    if (x.s->trk_next[ti] != 0) fail("trk_next_not_cleared");

    x.s->trk_fail[ti][0] = NTX_TRK_MAX_FAIL; /* dies again → the backoff doubles */
    ntx_session_share_tick(x.s);
    ntx_share_test_advance_ms(599000);
    ntx_session_share_tick(x.s);
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL) fail("revived_before_600s");
    ntx_share_test_advance_ms(2000);
    ntx_session_share_tick(x.s);
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL - 1) fail("not_revived_after_600s");

    x.s->trk_fail[ti][0] = NTX_TRK_MAX_FAIL; /* and keeps doubling, capped at 3600 s */
    ntx_session_share_tick(x.s);
    ntx_share_test_advance_ms(1199000);
    ntx_session_share_tick(x.s);
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL) fail("revived_before_1200s");
    ntx_share_test_advance_ms(2000);
    ntx_session_share_tick(x.s);
    if (x.s->trk_fail[ti][0] != NTX_TRK_MAX_FAIL - 1) fail("not_revived_after_1200s");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("tracker_revival_300_600");
}

/* ------------- case 9: no ratio cap for a share (§5.5) ------------- */
static void test_ratio_exempt(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "ratio");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/ratio/j.bin");
    mk_file(p, 40000, 23);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_ratio");
    pm_park(&x, NTX_PM_OFF);
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (x.s->tts[ti].state != NTX_TTS_DONE) fail("ratio_not_done");
    x.s->tts_up[ti] = x.s->tts[ti].size * 10;
    for (int i = 0; i < 3; i++) ntx_session_data_tick(x.s);
    if (x.s->tts_ratio_done[ti] != 0) fail("ratio_done_on_share");
    if (x.s->tts[ti].state != NTX_TTS_DONE) fail("ratio_state_changed");
    if (data_ratio_threshold_hit(x.s, ti) != 0) fail("ratio_hit_not_zero");

    /* the same numbers on a plain slot must trip: the exemption is the only cause */
    int oi = -1;
    for (int k = 0; k < NTX_SESSION_MAX_TTS; k++)
        if (k != ti && !x.s->share[k]) { oi = k; break; }
    if (oi < 0) fail("no_free_slot");
    uint8_t ih[20];
    memset(ih, 3, sizeof ih);
    ntx_torrent_init_meta(&x.s->tts[oi], ih);
    x.s->tts[oi].state = NTX_TTS_DONE;
    x.s->tts[oi].size = 40000;
    if (oi >= x.s->n_tts) x.s->n_tts = oi + 1;
    x.s->tts_up[oi] = 400000;
    if (data_ratio_threshold_hit(x.s, oi) != 1) fail("ratio_not_hit_on_plain");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("ratio_exempt");
}

/* ---------- case 10: A3→A4 hand-off through the real write gate ---------- */
static void test_a3_to_a4_round_trip(void) {
    scratch();
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/a4/k.bin");
    mk_file(p, 500000, 29);
    struct stat sb;
    if (stat(p, &sb) != 0 || sb.st_size <= 0) fail("a4_stat");
    uint32_t ps = 0;
    if (smeta_piece_len((uint64_t)sb.st_size, &ps) != 0) fail("a4_piece_len");
    ntx_share_hasher *h = ntx_share_hasher_new((uint64_t)sb.st_size, ps);
    if (!h) fail("a4_hasher");
    int fd = open(p, O_RDONLY);
    if (fd < 0) fail("a4_open");
    static uint8_t buf[1 << 16];
    uint64_t off = 0;
    for (;;) {
        ssize_t r = pread(fd, buf, sizeof buf, (off_t)off);
        if (r < 0) fail("a4_pread");
        if (r == 0) break;
        if (ntx_share_hasher_feed(h, buf, (size_t)r) != 0) fail("a4_feed");
        off += (uint64_t)r;
    }
    close(fd);
    if (!ntx_share_hasher_done(h)) fail("a4_done");

    const char *trks[2] = {"https://trk-a.example/announce", "https://trk-b.example/announce"};
    const char salt[] = "000102030405060708090a0b0c0d0e0f";
    uint8_t *ib = NULL, *torrent = NULL;
    size_t ibn = 0, tn = 0;
    if (ntx_share_build_info(h, "k.bin", salt, &ib, &ibn) != 0) fail("a4_build_info");
    if (ntx_share_build_torrent(ib, ibn, h, trks, 2, 1700000000, &torrent, &tn) != 0) fail("a4_build_torrent");
    /* The write gate hashes the info subtree with SHA-1, so that is the key the
     * writer must be handed (not trunc20(sha256) from ntx_torrent_metainfo_hash). */
    uint8_t ih[20], ih2[32];
    ntx_sha1(ib, ibn, ih);
    ntx_sha256(ib, ibn, ih2);

    char tp[NTX_SHARE_PATH_MAX];
    snprintf(tp, sizeof tp, SCRATCH "/a4/out.torrent");
    unlink(tp);
    if (ntx_share_write_torrent(tp, torrent, tn, ih) != NTX_SHARE_OK) fail("a4_write_ok");
    static uint8_t back[1 << 22];
    size_t bn = 0;
    {
        int f2 = open(tp, O_RDONLY);
        if (f2 < 0) fail("a4_reread_open");
        ssize_t r = read(f2, back, sizeof back);
        close(f2);
        if (r < 0) fail("a4_reread");
        bn = (size_t)r;
    }
    if (bn != tn || memcmp(back, torrent, tn) != 0) fail("a4_bytes_not_equal");
    struct stat tsb;
    if (stat(tp, &tsb) != 0 || (tsb.st_mode & 0777) != 0600) fail("a4_mode");

    /* the gate really is the gate: flip one byte INSIDE the embedded info
     * subtree, so the raw subtree no longer hashes to ih. */
    static uint8_t tampered[1 << 22];
    memcpy(tampered, torrent, tn);
    size_t isz = 0;
    for (size_t i = 0; i + ibn <= tn; i++) {
        if (!memcmp(tampered + i, ib, ibn)) { isz = i; break; }
    }
    if (!isz) fail("a4_info_substring_not_found");
    tampered[isz + 1] ^= 0x01;
    char tp2[NTX_SHARE_PATH_MAX];
    snprintf(tp2, sizeof tp2, SCRATCH "/a4/probe.torrent");
    unlink(tp2);
    if (ntx_share_write_torrent(tp2, tampered, tn, ih) != NTX_SHARE_E_BAD_ARG) fail("a4_gate_not_enforced");
    if (file_exists(tp2)) fail("a4_gate_wrote");

    char mag[NTX_SHARE_MAGNET_MAX];
    if (ntx_share_magnet(mag, sizeof mag, ih, ih2, "k.bin", trks, 2) != 0) fail("a4_magnet_build");
    ntx_magnet mg;
    if (ntx_magnet_parse(mag, &mg) != 0) fail("a4_magnet_parse");
    if (memcmp(mg.info_hash, ih, 20) != 0) fail("a4_magnet_btih");
    if (!mg.has_v2 || memcmp(mg.ih_v2, ih2, 32) != 0) fail("a4_magnet_btmh");
    if (mg.n_trackers != 2 || strcmp(mg.trackers[0], trks[0]) != 0) fail("a4_magnet_trk");
    if (strcmp(mg.name, "k.bin") != 0) fail("a4_magnet_dn");

    free(ib);
    free(torrent);
    unlink(tp);
    ntx_share_hasher_free(h);
    ok("a3_to_a4_round_trip");
}

/* ---- case 11: pre-hash piece ceiling, §5.5 change detection, 60 s warning ---- */
static void test_ceiling_and_changed(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "ceil");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/ceil/huge.bin");
    unlink(p);
    int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) fail("huge_open");
    /* > NTX_SHARE_MAX_PIECES pieces at the 64 MiB ceiling — sparse, so the A3
     * writer cap (E_EXISTS) is never reached and never special-cased. */
    if (ftruncate(fd, (off_t)((uint64_t)32769 * NTX_SHARE_PIECE_MAX)) != 0) {
        printf("SKIP ceiling: ftruncate EFBIG (%s)\n", strerror(errno));
    } else {
        close(fd);
        ntx_share_err e = NTX_SHARE_OK;
        if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_TOO_BIG) fail("ceiling_too_big");
        if (!file_exists(p)) fail("ceiling_consumed_the_file");
    }
    if (fd >= 0) close(fd);
    unlink(p);

    snprintf(p, sizeof p, SCRATCH "/ceil/m.bin");
    mk_file(p, 60000, 31);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_changed");
    pm_park(&x, NTX_PM_OFF);
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("changed_not_announcing");
    {
        int f2 = open(p, O_WRONLY | O_APPEND);
        if (f2 < 0) fail("touch_open");
        if (write(f2, "x", 1) != 1) fail("touch_write");
        close(f2);
    }
    ntx_share_test_advance_ms(1500); /* past the 1 s fstat interval */
    ntx_session_share_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("change_not_detected");
    if (ntx_session_share_serving(x.s, ti) != 0) fail("changed_still_serving");
    ntx_share_event ev;
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("changed_no_event");
    if (ev.ok || ev.err != NTX_SHARE_E_CHANGED) fail("changed_event_fields");
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("changed_two_events");

    /* §5.5: 60 s without READY warns once and never ends the share */
    snprintf(p, sizeof p, SCRATCH "/ceil/n.bin");
    mk_file(p, 40000, 37);
    int tj = ntx_session_share_add(x.s, p, NULL, &e);
    if (tj < 0) fail("add_slow");
    (void)pump_until_hashed(&x, tj, 2000, NULL);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_ANNOUNCING) fail("slow_not_announcing");
    ntx_share_test_advance_ms(61000);
    ntx_session_share_tick(x.s);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_ANNOUNCING) fail("slow_promoted");
    ntx_session_remove(x.s, tj);
    sess_close(&x);
    tracker_stop(&tr);
    ok("ceiling_changed_warn");
}

/* ------ behaviour 1/2 detail: fd kept, RO store, replacement (§5.1) ------ */
static void test_fd_held_and_ro(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fdheld");
    char p[256], tmp[256];
    snprintf(p, sizeof p, SCRATCH "/fdheld/o.bin");
    mk_file(p, 40000, 41);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("add_fdheld");
    int held = x.s->share[ti]->fd;
    if (held < 0 || fcntl(held, F_GETFD) == -1) fail("fd_not_held");
    pm_park(&x, NTX_PM_OFF);
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("fdheld_not_announcing");
    if (fcntl(held, F_GETFD) == -1) fail("fd_closed_after_hash");
    ntx_torrent *t = &x.s->tts[ti];
    if (t->store.ro != 1) fail("ro_flag");
    static uint8_t junk[16];
    if (ntx_store_write(&t->store, 0, 0, junk, sizeof junk) != -1) fail("ro_write_allowed");
    if (ntx_store_verified_bytes(&t->store) != t->size) fail("ro_verified_bytes");
    if (ntx_store_pmap(&t->store, 0) != 2) fail("ro_pmap_marked");

    /* §5.1 + §5.5: replacing the file under the same name is detected through
     * st_ctim (the old inode's link count drops) AND cannot change the bytes we
     * serve, because the fd taken at share_add is the only handle we ever use. */
    static uint8_t a[16];
    if (ntx_store_read(&t->store, 0, 0, a, 16) != 16) fail("ro_read");
    snprintf(tmp, sizeof tmp, SCRATCH "/fdheld/o.new");
    mk_file(tmp, 40000, 42);
    if (rename(tmp, p) != 0) fail("rename");
    ntx_share_test_advance_ms(1500);
    ntx_session_share_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("replacement_not_detected");
    static uint8_t b[16];
    if (ntx_store_read(&t->store, 0, 0, b, 16) != 16) fail("ro_read_after_change");
    if (memcmp(a, b, 16) != 0) fail("served_bytes_changed_after_replacement");
    int f2 = open(p, O_RDONLY);
    if (f2 < 0 || read(f2, b, 16) != 16) fail("disk_read");
    close(f2);
    if (memcmp(a, b, 16) == 0) fail("the replacement was never really written");
    ntx_session_remove(x.s, ti);
    if (fcntl(held, F_GETFD) != -1) fail("fd_not_closed_on_remove");
    sess_close(&x);
    tracker_stop(&tr);
    ok("fd_held_store_ro");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    ntx_rng_init();
    scratch();
    test_add_gates();
    test_hash_and_results();
    test_started_and_magnet();
    test_remove_during_hash();
    test_pin_fail();
    test_revival();
    test_ratio_exempt();
    test_a3_to_a4_round_trip();
    test_ceiling_and_changed();
    test_fd_held_and_ro();
    ntx_share_trackers_test_set(NULL, -1);
    printf("ALL PASS\n");
    return 0;
}
