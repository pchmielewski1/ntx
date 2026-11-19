#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <arpa/inet.h>
#include "../src/core/ntx_session.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_hash_msg.c"
#include "../src/core/ntx_session_trk.c"
#include "../src/core/ntx_session_peer.c"
#include "../src/core/ntx_pex_tx.c"
#include "../src/core/ntx_session_data.c"
#include "../src/core/ntx_torrent.c"
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

#include <netinet/in.h>

#include "tscale.h" /* the harness only runs natively; see main() */

/* V01 (docs/superpowers review §9.2): NTX_TRK_HTTP_BUDGET_MS was validated only against
 * a DEAD loopback listener (t_session_trk_http_stall.c — 30.7 s to 964 ms). Nobody ever
 * measured a HEALTHY announce. Measured with the shipped HTTPS stack against the pinned
 * share pool, one whole successful announce (DoH + connect + TLS 1.3 + request + reply)
 * costs up to 1303 ms, and 981 ms of that is the wait for the reply AFTER the request is
 * already on the wire (docs/network.md). At the 900 ms the budget had, that announce — a
 * SUCCESSFUL one — was killed, struck, and after NTX_TRK_MAX_FAIL the tracker was
 * dropped, so `--share` could never reach READY.
 *
 * This is the missing half of the gate: a pinned loopback HTTPS tracker that does the
 * TLS handshake, answers the announce, and sleeps in each phase
 * (test/interop/share/tracker_https_slow.py). Three cases:
 *
 *   A  a fixed 1500 ms announce — the measured healthy worst case — must SUCCEED.
 *      RED against the old 900 ms budget, GREEN now.
 *   B  65 % of the budget must SUCCEED: the bound may not sit under its own budget.
 *   C  the budget plus 800 ms must FAIL, and stop AT the bound rather than at the
 *      tracker's own reply: the bound is real, not deleted.
 *
 * Where the sleeps go matters. The tight leg (NTX_TRK_HTTP_PRE_REPLY_MS) is armed only
 * until the request is written, so the accept/handshake sleeps ride it and stay small;
 * the request/response sleeps ride the whole NTX_TRK_HTTP_BUDGET_MS. The dead-host trap
 * of t_session_trk_http_stall.c never gets past the pre-reply leg, so it keeps its
 * 900 ms bound: a live tracker gets the whole budget, a silent one still costs the
 * tight leg.
 *
 * Non-vacuity: A and B assert the compact peer from the reply really reached the session
 * and that the wall time really is the sleep time; C asserts both the failure and that
 * the fetch stopped inside budget + slack. A tracker that stopped being slow trips the
 * floor in A.
 */

#define TRK_PY "test/interop/share/tracker_https_slow.py"
#define TRK_IP "127.0.0.2"   /* not 127.0.0.1: the built-in dev pin owns that host */
#define HEALTHY_MS 1500      /* case A: the measured worst successful announce */
#define BUDGET_FRACTION 65   /* case B: percent of NTX_TRK_HTTP_BUDGET_MS */
#define OVER_MS 800          /* case C: how far past the bound to sleep */
#define PRE_SLEEP 100        /* accept + handshake sleeps; both ride the tight leg */

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static void on_alarm(int sig) {
    (void)sig;
    printf("FAIL slow_announce_timeout\n");
    _exit(1);
}

static uint64_t now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

/* ---- the forked slow tracker ---------------------------------------------------- */

typedef struct {
    pid_t pid;
    uint16_t port;      /* the tracker's HTTPS port      */
    uint16_t peer_port; /* the port its peer list advertises */
    int listener;       /* keeps that peer connectable so the dialled slot survives */
    char log[256];
} slow_trk;

static int read_line_timeout(int fd, char *line, size_t cap, int timeout_ms) {
    size_t n = 0;
    uint64_t t0 = now_ms();
    while (now_ms() - t0 < (uint64_t)timeout_ms) {
        char c;
        ssize_t r = read(fd, &c, 1);
        if (r == 1) {
            if (c == '\n') {
                line[n] = '\0';
                return (int)n;
            }
            if (n + 1 < cap) line[n++] = c;
            continue;
        }
        if (r == 0) break;
        if (errno != EINTR && errno != EAGAIN) break;
        usleep(2000);
    }
    line[n] = '\0';
    return -1;
}

static void trk_kill(slow_trk *t) {
    if (t->listener >= 0) { close(t->listener); t->listener = -1; }
    if (t->pid > 0) {
        int st;
        kill(t->pid, SIGKILL);
        waitpid(t->pid, &st, 0);
        t->pid = -1;
    }
}

/* Binds the peer sink first (the tracker has to advertise its port), then spawns the
 * tracker and installs its SPKI in the test pin pool.
 * 0=ok, -1=harness unavailable (SKIP), -2=spawned but unusable (FAIL). */
static int trk_start(slow_trk *t, int accept_ms, int handshake_ms, int request_ms,
                     int response_ms) {
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof sa);
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(0x7f000001);
    int lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0 || bind(lfd, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(lfd, 8) != 0) {
        if (lfd >= 0) close(lfd);
        return -2;
    }
    socklen_t sl = sizeof sa;
    getsockname(lfd, (struct sockaddr *)&sa, &sl);
    t->listener = lfd;
    t->peer_port = ntohs(sa.sin_port);

    char args[7][400];
    snprintf(args[0], sizeof args[0], "--accept-ms=%d", accept_ms);
    snprintf(args[1], sizeof args[1], "--handshake-ms=%d", handshake_ms);
    snprintf(args[2], sizeof args[2], "--request-ms=%d", request_ms);
    snprintf(args[3], sizeof args[3], "--response-ms=%d", response_ms);
    snprintf(args[4], sizeof args[4], "--peer-port=%u", (unsigned)t->peer_port);
    snprintf(args[5], sizeof args[5], "--ip=%s", TRK_IP);
    snprintf(args[6], sizeof args[6], "--log=%s", t->log);
    int p[2];
    if (pipe(p) != 0) { trk_kill(t); return -2; }
    fflush(stdout);
    fflush(stderr);
    pid_t pid = fork();
    if (pid < 0) { close(p[0]); close(p[1]); trk_kill(t); return -2; }
    if (pid == 0) {
        int fd = open("/dev/null", O_WRONLY);
        dup2(p[1], STDOUT_FILENO);
        if (fd >= 0) dup2(fd, STDERR_FILENO);
        close(p[0]); close(p[1]);
        execlp("python3", "python3", TRK_PY, args[0], args[1], args[2], args[3], args[4],
               args[5], args[6], (char *)NULL);
        _exit(127);
    }
    close(p[1]);
    t->pid = pid;
    fcntl(p[0], F_SETFL, fcntl(p[0], F_GETFL) | O_NONBLOCK);
    char line[256];
    uint16_t port = 0;
    uint8_t pin[32];
    int have_pin = 0;
    for (int i = 0; i < 8; i++) {
        if (read_line_timeout(p[0], line, sizeof line, 20000) < 0) break;
        if (!strncmp(line, "PORT=ERR", 8)) { printf("tracker: %s\n", line); break; }
        if (!strncmp(line, "PORT=", 5)) port = (uint16_t)atoi(line + 5);
        if (!strncmp(line, "SPKI=", 5) && strlen(line) == 69) {
            have_pin = 1;
            for (int k = 0; k < 32; k++) {
                unsigned v;
                if (sscanf(line + 5 + 2 * k, "%2x", &v) != 1) { have_pin = 0; break; }
                pin[k] = (uint8_t)v;
            }
        }
        if (port && have_pin) break;
    }
    close(p[0]);
    if (!port || !have_pin) {
        int st;
        pid_t r = waitpid(pid, &st, WNOHANG); /* already gone → no python3 → SKIP */
        if (r == pid && WIFEXITED(st) && (WEXITSTATUS(st) == 127 || WEXITSTATUS(st) == 3)) {
            close(t->listener);
            t->listener = -1;
            t->pid = -1;
            return -1;
        }
        trk_kill(t);
        return -2;
    }
    t->port = port;
    ntx_https_pin_test_pool_clear();
    ntx_https_pin_set_file(NULL);
    ntx_https_tofu_set_enabled(0);
    if (ntx_https_pin_test_pool_add(TRK_IP, pin) != 1) {
        trk_kill(t);
        return -2;
    }
    return 0;
}

/* ---- the session --------------------------------------------------------------- */

static ntx_netx *g_n;
static ntx_session *g_s;

static void session_new(void) {
    static ntx_config cfg;
    memset(&cfg, 0, sizeof cfg);
    cfg.max_peers = 8;
    cfg.allow_local_peers = 1; /* the reply's peer is 127.0.0.1: the dial must not be refused */
    g_n = ntx_netx_init(&cfg);
    g_s = ntx_session_init(g_n, &cfg);
    uint8_t ih[20] = {7};
    g_s->n_tts = 1;
    ntx_torrent_init_meta(&g_s->tts[0], ih);
    g_s->tts[0].state = NTX_TTS_META;
    g_s->trk_fd = ntx_sock_udp4();
    ntx_sock_bind0(g_s->trk_fd);
}

static void session_free(void) {
    ntx_session_free(g_s);
    ntx_netx_free(g_n);
    g_s = NULL;
    g_n = NULL;
}

/* The compact peer the tracker hands back: proof that the reply was fetched AND parsed. */
static int peer_seen(const slow_trk *t) {
    ntx_addr want;
    ntx_addr_set_v4(&want, htonl(0x7f000001u)); /* the tracker answers with 127.0.0.1, network order */
    for (int pi = 0; pi < NTX_SESSION_MAX_PEERS; pi++)
        if (g_s->peers[pi].fd != -1 && g_s->peers[pi].port == t->peer_port &&
            ntx_addr_eq(&g_s->peers[pi].addr, &want))
            return 1;
    return 0;
}

/* One production loop iteration's worth of HTTPS announces, timed. */
static uint64_t pump_one(slow_trk *t) {
    snprintf(g_s->trk_urls[0][0], sizeof g_s->trk_urls[0][0], "https://%s:%u/announce", TRK_IP,
             (unsigned)t->port);
    g_s->trk_n[0] = 1;
    g_s->trk_fail[0][0] = 0;
    g_s->trk_started_ok[0] = 0;
    g_s->trk_http_pending[0][0] = 1;
    g_s->trk_http_due[0][0] = 0;
    g_s->trk_http_event[0] = NTX_TRACKER_EVENT_STARTED;
    uint64_t t0 = now_ms();
    ntx_session_trk_pump_http(g_s, 1);
    return now_ms() - t0;
}

static int case_healthy(int total, int fraction, const char *tag) {
    slow_trk t;
    memset(&t, 0, sizeof t);
    t.listener = -1;
    snprintf(t.log, sizeof t.log, "test/.scratch/trk_slow_%s.log", tag);
    unlink(t.log);
    int half = total / 2;
    int rc = trk_start(&t, PRE_SLEEP, PRE_SLEEP, half, total - half - PRE_SLEEP);
    if (rc != 0) { trk_kill(&t); return rc; }
    session_new();
    uint64_t ms = pump_one(&t);
    int ok = g_s->trk_fail[0][0] == 0 && g_s->trk_started_ok[0] == 1 && peer_seen(&t);
    printf("%s: %d ms of sleeps (%d%% of the %u ms budget) -> %llu ms, fail=%u started_ok=%u "
           "peer=%d -> %s\n",
           tag, total, fraction, (unsigned)NTX_TRK_HTTP_BUDGET_MS, (unsigned long long)ms,
           (unsigned)g_s->trk_fail[0][0], (unsigned)g_s->trk_started_ok[0], peer_seen(&t),
           ok ? "accepted" : "KILLED");
    session_free();
    trk_kill(&t);
    if (!ok) return fail("slow_healthy_announce_killed");
    if (ms < (uint64_t)total / 2) { /* the sleeps must really have happened */
        printf("%s: returned after %llu ms — the tracker never delayed us\n", tag,
               (unsigned long long)ms);
        return fail("slow_healthy_not_really_slow");
    }
    printf("PASS %s\n", tag);
    return 0;
}

static int case_healthy_fixed(void) { return case_healthy(HEALTHY_MS, 100, "A"); }

static int case_healthy_fraction(void) {
    return case_healthy((int)(NTX_TRK_HTTP_BUDGET_MS * BUDGET_FRACTION / 100u), BUDGET_FRACTION,
                        "B");
}

/* C: past the budget it must still fail, and stop AT the bound. */
static int case_over_budget(void) {
    slow_trk t;
    memset(&t, 0, sizeof t);
    t.listener = -1;
    int total = (int)NTX_TRK_HTTP_BUDGET_MS + OVER_MS;
    snprintf(t.log, sizeof t.log, "test/.scratch/trk_slow_C.log");
    unlink(t.log);
    int half = total / 2;
    int rc = trk_start(&t, PRE_SLEEP, PRE_SLEEP, half, total - half - PRE_SLEEP);
    if (rc != 0) { trk_kill(&t); return rc; }
    session_new();
    uint64_t ms = pump_one(&t);
    int failed = g_s->trk_fail[0][0] == 1 && g_s->trk_started_ok[0] == 0 && !peer_seen(&t);
    printf("C: %d ms of sleeps (budget %u + %d) -> %llu ms, fail=%u started_ok=%u peer=%d -> %s\n",
           total, (unsigned)NTX_TRK_HTTP_BUDGET_MS, OVER_MS, (unsigned long long)ms,
           (unsigned)g_s->trk_fail[0][0], (unsigned)g_s->trk_started_ok[0], peer_seen(&t),
           failed ? "failed as expected" : "NOT BOUNDED");
    session_free();
    trk_kill(&t);
    if (!failed) return fail("over_budget_announce_not_failed");
    if (ms < (uint64_t)NTX_TRK_HTTP_BUDGET_MS * 8 / 10) {
        printf("C gave up after %llu ms, before its %u ms budget\n",
               (unsigned long long)ms, (unsigned)NTX_TRK_HTTP_BUDGET_MS);
        return fail("budget_expired_early");
    }
    if (ms > (uint64_t)NTX_TRK_HTTP_BUDGET_MS + OVER_MS + 1500) {
        printf("C ran %llu ms — the bound never expired the fetch\n",
               (unsigned long long)ms);
        return fail("budget_not_enforced");
    }
    printf("PASS over_budget_fails\n");
    return 0;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    signal(SIGALRM, on_alarm);
    alarm(240);
    ntx_rng_init();
    mkdir("test/.scratch", 0755);

    if (access(TRK_PY, R_OK) != 0) {
        printf("FAIL missing %s\n", TRK_PY);
        return 1;
    }
    /* The harness forks python3, so it belongs to the native suite. Under qemu-user
     * (mipsel, riscv64 — both export NTX_TEST_TIMEOUT_SCALE=4) the child is the guest
     * binary and the wall-clock sleeps are TCG-slowed; print SKIP the way the IPv6 cases
     * do rather than assert on an emulated stopwatch. */
    if (ntx_test_timeout_scale() != 1) {
        printf("SKIP trk_http_slow (TCG run: the python3 tracker harness is native-only)\n");
        return 0;
    }

    struct { int (*fn)(void); const char *name; } cases[] = {
        { case_healthy_fixed, "A_healthy_measured" },
        { case_healthy_fraction, "B_healthy_65pct" },
        { case_over_budget, "C_over_budget" },
    };
    int rc = 0, skipped = 0;
    for (size_t i = 0; i < sizeof cases / sizeof cases[0]; i++) {
        int r = cases[i].fn();
        if (r == -1) {
            printf("SKIP %s (python3 or the tracker harness unavailable)\n", cases[i].name);
            skipped++;
        } else if (r == -2) {
            printf("FAIL %s_harness_came_up\n", cases[i].name);
            rc = 1;
        } else if (r != 0) {
            rc = 1;
        }
    }
    /* An environment without python3/openssl cannot run the harness. That is a printed
     * SKIP, the same honest absence the IPv6 cases use, not a fake pass — and not a
     * failure either: the dead-host half of the bound is gated unconditionally by
     * t_session_trk_http_stall.c. A harness that is present but will not come up is a
     * FAIL (r == -2 above). */
    if (skipped == (int)(sizeof cases / sizeof cases[0]))
        printf("SKIP trk_http_slow — nothing was asserted (no python3/openssl?)\n");
    if (rc == 0)
        printf("PASS trk_http_slow (budget %u ms, pre-reply leg %u ms)\n",
               (unsigned)NTX_TRK_HTTP_BUDGET_MS, (unsigned)NTX_TRK_HTTP_PRE_REPLY_MS);
    return rc;
}
