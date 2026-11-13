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

#include "tscale.h" /* the tick gate below is widened by NTX_TEST_TIMEOUT_SCALE */

#define SCRATCH "test/.scratch/a5"
#define BIG_MIB 64

/* Sanitizer detection: GCC defines __SANITIZE_ADDRESS__ for -fsanitize=address,
 * clang needs __has_feature (nested #if: GCC's #if expands an undefined
 * function-like macro instead of short-circuiting it). Only the tick-budget
 * gate below cares. */
#if defined(__SANITIZE_ADDRESS__)
#define NTX_TEST_SANITIZED 1
#elif defined(__has_feature)
#if __has_feature(address_sanitizer)
#define NTX_TEST_SANITIZED 1
#else
#define NTX_TEST_SANITIZED 0
#endif
#else
#define NTX_TEST_SANITIZED 0
#endif

/* Absolute per-tick ceiling for the 64 MiB hash (§5.3 budget check). The
 * production budget is NTX_SHARE_HASH_BUDGET_MS and ntx_session_share_add /
 * share_hash_tick re-checks that deadline inside the tick, so this gate is a
 * "the budget is actually being honoured" tripwire, never a throughput
 * assertion: what it has to catch is an unbounded tick (seconds for 64 MiB),
 * not a slow host. Worst tick observed — native aarch64 34..45 ms, under
 * qemu-riscv64 TCG 66..68 ms, under ASAN on this aarch64 box 256..272 ms
 * (x86_64 CI with the same sanitizer flags still fits under 50, which is why
 * CI with detect_leaks=0 never flagged it), all against the 20 ms budget —
 * which is only sampled at tick granularity, so an emulator that overshoots
 * gets more, shorter ticks (32 native vs 64 under TCG). 100 ms is 2x the worst
 * native tick, so the native path gets a real margin instead of the 50 ms coin
 * flip that only x86_64 CI survived by being faster, and it still dwarfs an
 * unbounded tick. The ASAN branch pins 800 unscaled (~3x its worst figure, its
 * 16x headroom built in); the plain gate is ts_ms(100), so
 * scripts/{riscv,mips}/run-suite.sh buy the emulator headroom via
 * NTX_TEST_TIMEOUT_SCALE (4 -> 400 ms, ~6x the TCG figure). */
#if NTX_TEST_SANITIZED
#define NTX_TEST_TICK_GATE_MS 800
#else
#define NTX_TEST_TICK_GATE_MS 100
#endif

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
    static const char *const tags[] = {"gates","hash","started","rmhash","pin","revive","ratio","a4","ceil","fdheld",
                                       "from","fromchg","fromerr","fromdup","fromio","fromserve",
                                       "frompread"};
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

static int copy_file(const char *src, const char *dst) {
    int ifd = open(src, O_RDONLY), ofd = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (ifd < 0 || ofd < 0) {
        if (ifd >= 0) close(ifd);
        if (ofd >= 0) close(ofd);
        return -1;
    }
    static uint8_t cb[1 << 16];
    for (;;) {
        ssize_t r = read(ifd, cb, sizeof cb);
        if (r < 0) { close(ifd); close(ofd); return -1; }
        if (r == 0) break;
        if (write(ofd, cb, (size_t)r) != r) { close(ifd); close(ofd); return -1; }
    }
    if (fsync(ofd) != 0) { close(ifd); close(ofd); return -1; }
    close(ifd);
    close(ofd);
    return 0;
}

static uint8_t *slurp(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz <= 0) { fclose(f); return NULL; }
    rewind(f);
    uint8_t *b = malloc((size_t)sz);
    if (!b) { fclose(f); return NULL; }
    size_t rd = fread(b, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(b); return NULL; }
    *n = (size_t)sz;
    return b;
}

static int write_all(const char *path, const uint8_t *b, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0) return -1;
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, b + off, n - off);
        if (w <= 0) { close(fd); return -1; }
        off += (size_t)w;
    }
    if (fsync(fd) != 0) { close(fd); return -1; }
    close(fd);
    return 0;
}

/* §5.6/review focus 4: the source is truncated from OUTSIDE, the way a user
 * would do it — the share's own fd is O_RDONLY, so ftruncate through it would
 * only ever be EBADF. */
static int trunc_to(const char *path, off_t len) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    int rc = ftruncate(fd, len);
    close(fd);
    return rc;
}

/* --- minimal bencode writer for the forged .torrents of §5.6 (keys sorted by
 * the encoder itself, so the insertion order here is irrelevant) --- */
typedef struct {
    uint8_t *b;
    size_t n, cap;
} bstr;

static void bput(bstr *w, const void *p, size_t n) {
    if (w->n + n > w->cap) {
        size_t nc = w->cap ? w->cap * 2 : 512;
        while (nc < w->n + n) nc *= 2;
        uint8_t *nb = realloc(w->b, nc);
        if (!nb) return;
        w->b = nb;
        w->cap = nc;
    }
    memcpy(w->b + w->n, p, n);
    w->n += n;
}
static void bputs(bstr *w, const char *s) { bput(w, s, strlen(s)); }
static void bkey(bstr *w, const char *k) {
    char t[24];
    snprintf(t, sizeof t, "%zu:", strlen(k));
    bputs(w, t);
    bputs(w, k);
}
static void bstrn(bstr *w, const void *p, size_t n) {
    char t[24];
    snprintf(t, sizeof t, "%zu:", n);
    bputs(w, t);
    bput(w, p, n);
}
static void bint(bstr *w, long long v) {
    char t[32];
    snprintf(t, sizeof t, "i%llde", v);
    bputs(w, t);
}

/* One hybrid (v1 SHA-1 + BEP 52) single-file .torrent, byte-for-byte the shape
 * ntx_share_build_torrent produces, so the slot it feeds goes through the very
 * same validator as a real ntx share. When `pub` is non-zero info carries no
 * "private" key. `size` is what the metainfo DECLARES and what `data` holds, so
 * a length mismatch is produced by handing in a buffer one byte longer than the
 * file on disk (the metainfo stays internally valid: only §5.6.1 can reject it). */
static uint8_t *mk_torrent(const uint8_t *data, size_t size, uint32_t ps, int pub, size_t *out_n) {
    uint32_t np = (uint32_t)((size + ps - 1) / ps);
    uint8_t *pieces = malloc((size_t)np * 20);
    uint8_t *layer = np > 1 ? malloc((size_t)np * 32) : NULL;
    if (!pieces || (np > 1 && !layer)) {
        free(pieces);
        free(layer);
        return NULL;
    }
    for (uint32_t i = 0; i < np; i++) {
        uint32_t off = i * ps;
        uint32_t len = (uint32_t)(size - off < ps ? size - off : ps);
        ntx_sha1(data + off, len, pieces + (size_t)i * 20);
    }
    /* BEP 52: 16 KiB leaves, zero-filled to a power of two, folded (the same
     * fold ntx_share_meta.c and ntx_merkle.c use). */
    const uint32_t leaf = NTX_MERKLE_LEAF;
    uint32_t T = ps / leaf;
    uint8_t *lev = malloc((size_t)T * 32);
    if (!lev) { free(pieces); free(layer); return NULL; }
    for (uint32_t i = 0; i < np; i++) {
        uint32_t off = i * ps;
        /* capped at the piece length: lev holds T = ps/leaf leaves, not the
         * whole tail of the file */
        uint32_t left = (uint32_t)(size - off < ps ? size - off : ps);
        uint32_t done = 0, li = 0;
        while (left) {
            uint32_t k = left < leaf ? left : leaf;
            ntx_sha256(data + off + done, k, lev + (size_t)li * 32);
            done += k;
            left -= k;
            li++;
        }
        for (uint32_t j = li; j < T; j++) memset(lev + (size_t)j * 32, 0, 32);
        for (uint32_t p = T; p > 1; p >>= 1)
            for (uint32_t j = 0; j < p / 2; j++) {
                uint8_t cat[64];
                memcpy(cat, lev + (size_t)j * 2 * 32, 32);
                memcpy(cat + 32, lev + (size_t)(j * 2 + 1) * 32, 32);
                ntx_sha256(cat, 64, lev + (size_t)j * 32);
            }
        if (np > 1) memcpy(layer + (size_t)i * 32, lev, 32);
    }
    uint8_t root[32];
    if (np == 1) memcpy(root, lev, 32);
    else { /* fold the piece layer up to the pieces root (BEP 52, zero-filled) */
        uint32_t p = 1;
        while (p < np) p <<= 1;
        uint8_t *up = calloc(p, 32);
        if (!up) { free(lev); free(pieces); free(layer); return NULL; }
        memcpy(up, layer, (size_t)np * 32);
        for (uint32_t q = p; q > 1; q >>= 1)
            for (uint32_t j = 0; j < q / 2; j++) {
                uint8_t cat[64];
                memcpy(cat, up + (size_t)j * 2 * 32, 32);
                memcpy(cat + 32, up + (size_t)(j * 2 + 1) * 32, 32);
                ntx_sha256(cat, 64, up + (size_t)j * 32);
            }
        memcpy(root, up, 32);
        free(up);
    }
    free(lev);

    bstr info = {0, 0, 0}, top = {0, 0, 0};
    bputs(&info, "d");
    bkey(&info, "file tree");
    bputs(&info, "d"); /* name key ("" = single file) -> {"" : props} */
    bstrn(&info, "f.bin", 5);
    bputs(&info, "d");
    bstrn(&info, "", 0);
    bputs(&info, "d");
    bkey(&info, "length");
    bint(&info, (long long)size);
    bkey(&info, "pieces root");
    bstrn(&info, root, 32);
    bputs(&info, "ee");
    bputs(&info, "e");
    bkey(&info, "length");
    bint(&info, (long long)size);
    bkey(&info, "meta version");
    bint(&info, 2);
    bkey(&info, "name");
    bstrn(&info, "f.bin", 5);
    bkey(&info, "ntx salt");
    bstrn(&info, "000102030405060708090a0b0c0d0e0f", 32);
    bkey(&info, "piece length");
    bint(&info, ps);
    bkey(&info, "pieces");
    bstrn(&info, pieces, (size_t)np * 20);
    if (!pub) {
        bkey(&info, "private");
        bint(&info, 1);
    }
    bputs(&info, "e");

    bputs(&top, "d");
    bkey(&top, "announce");
    bstrn(&top, "https://forge.invalid/announce", 27);
    bkey(&top, "announce-list");
    bputs(&top, "ll");
    bstrn(&top, "https://forge.invalid/announce", 27);
    bputs(&top, "ee");
    bkey(&top, "created by");
    bstrn(&top, "ntx-test", 8);
    bkey(&top, "creation date");
    bint(&top, 1700000000LL);
    bkey(&top, "info");
    bput(&top, info.b, info.n);
    if (np > 1) {
        bkey(&top, "piece layers");
        bputs(&top, "d");
        bstrn(&top, root, 32);
        bstrn(&top, layer, (size_t)np * 32);
        bputs(&top, "e");
    }
    bputs(&top, "e");
    free(info.b);
    free(pieces);
    free(layer);
    if (!top.b) return NULL;
    *out_n = top.n;
    return top.b;
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
    /* sess_open strdups store_dir. Nothing keeps the pointer past teardown:
     * ntx_session_init/ntx_netx_init only store the address of the caller's
     * ntx_config and read store_dir during their own lifetime (dht state path,
     * ntx_torrent_set_metainfo, ntx_share_torrent_path), each snprintf-ing it
     * into a fixed buffer; ntx_store holds fds/pmap only and ntx_torrent /
     * ntx_share_slot hold char[] copies. Free it after both frees, which is
     * also why the test's own x.cfg.store_dir reads must stay before this. */
    free((void *)x->cfg.store_dir);
    x->cfg.store_dir = NULL;
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
    /* ts_ms() is a runtime value, so the gate that is actually compared has to
     * be computed here; the ASAN branch keeps its own built-in 16x headroom. */
    long gate_ms = NTX_TEST_SANITIZED ? (long)NTX_TEST_TICK_GATE_MS
                                      : ts_ms(NTX_TEST_TICK_GATE_MS);
    printf("MEASURE 64MiB ticks=%d max_tick_ms=%llu (budget %d ms, gate %ld ms)\n", ticks,
           (unsigned long long)max_ms, NTX_SHARE_HASH_BUDGET_MS, gate_ms);
    if (max_ms > (uint64_t)gate_ms) fail("tick_over_budget_gate");
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

/* =================== Task A6: --share-from (§5.6) ========================= */

/* Drives a slot that has left HASHING to READY through the local tracker. */
static int pump_to_ready(sess *x, int ti) {
    for (int i = 0; i < 40 && ntx_session_share_state(x->s, ti) != NTX_SHARE_READY; i++) {
        ntx_session_tick(x->s);
        pump_announces(x, ti);
    }
    return ntx_session_share_state(x->s, ti) == NTX_SHARE_READY;
}

/* share_add + the B5 port-map park. Parking AFTER the add matters: share_add
 * itself calls portmap_want(1), which restarts the (want==0) sequence and the
 * port-map tick would then drive it to PENDING, where §5.5 never announces. */
static int share_add_parked(sess *x, const char *path, const char *from, ntx_share_err *e) {
    int ti = ntx_session_share_add(x->s, path, from, e);
    if (ti >= 0) pm_park(x, NTX_PM_OFF);
    return ti;
}

/* ---- A6 case a: the same link — same ih, .torrent untouched (§5.6) ------- */
static void test_from_same_link(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "from");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/from/s.bin");
    mk_file(p, 300000, 51);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e); /* the A5 share */
    if (ti < 0) fail("from_add_plain");
    if (!x.s->pm || !x.s->pm->want) fail("from_portmap_not_requested"); /* §8 */
    pm_park(&x, NTX_PM_OFF);
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (!pump_to_ready(&x, ti)) fail("from_plain_not_ready");
    uint8_t ih1[20], ih2a[32];
    memcpy(ih1, x.s->tts[ti].info_hash, 20);
    memcpy(ih2a, x.s->tts[ti].info_hash_v2, 32);
    char tp[NTX_SHARE_PATH_MAX];
    if (ntx_share_torrent_path(tp, sizeof tp, x.cfg.store_dir, "s.bin", ih1) != 0) fail("from_torrent_path");
    size_t tn = 0;
    uint8_t *tb = slurp(tp, &tn);
    if (!tb) fail("from_torrent_slurp");
    struct stat tstat, fstat0;
    if (stat(tp, &tstat) != 0 || stat(p, &fstat0) != 0) fail("from_stat_before");

    ntx_session_remove(x.s, ti); /* same session, slot free: the link must survive */
    int tj = ntx_session_share_add(x.s, p, tp, &e);
    if (tj < 0 || e != NTX_SHARE_OK) {
        printf("ADD_FROM rc=%d err=%d\n", tj, (int)e);
        fail("from_add_failed");
    }
    if (!x.s->pm || !x.s->pm->want) fail("from_portmap_not_requested"); /* §8: from-path wants it too */
    pm_park(&x, NTX_PM_OFF);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_HASHING) fail("from_not_hashing");
    if (x.s->tts[tj].state != NTX_TTS_VERIFY) fail("from_state_not_verify");
    { /* §5.3: no hash and no bytes before the verification finished */
        ntx_session_stats_refresh(x.s, 0);
        ntx_stats st;
        ntx_session_snapshot(x.s, &st);
        if (strcmp(st.t[tj].phase, "hash") != 0) fail("from_phase_not_hash");
        if (st.t[tj].share != 1) fail("from_stats_share_flag");
    }
    (void)pump_until_hashed(&x, tj, 2000, NULL);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_ANNOUNCING &&
        ntx_session_share_state(x.s, tj) != NTX_SHARE_READY)
        fail("from_hash_did_not_finish");
    if (memcmp(x.s->tts[tj].info_hash, ih1, 20) != 0) fail("from_ih_differs");
    if (memcmp(x.s->tts[tj].info_hash_v2, ih2a, 32) != 0) fail("from_ih2_differs");
    if (x.s->tts[tj].np == 0 || x.s->tts[tj].have_n != x.s->tts[tj].np) fail("from_have_all");
    if (x.s->tts[tj].store.ro != 1 || x.s->tts[tj].priv != 1) fail("from_ro_or_priv");
    if (x.s->tts[tj].state != NTX_TTS_DONE) fail("from_tts_not_done");
    if (ntx_session_share_serving(x.s, tj) != 1) fail("from_not_serving");
    if (!pump_to_ready(&x, tj)) fail("from_not_ready");

    ntx_share_event ev;
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("from_no_ok_event");
    if (!ev.ok || ev.err != NTX_SHARE_OK || ev.i != tj) fail("from_event_fields");
    if (memcmp(ev.ih, ih1, 20) != 0) fail("from_event_ih");
    ntx_magnet mg;
    if (ntx_magnet_parse(ev.magnet, &mg) != 0) fail("from_magnet_parse");
    if (memcmp(mg.info_hash, ih1, 20) != 0) fail("from_magnet_btih");
    if (mg.n_trackers != 2) fail("from_magnet_trackers"); /* §5.6.4: the CURRENT list */

    /* §5.6.5: the .torrent is never rewritten — same bytes, same mtime — and
     * no second file appeared in the store. */
    struct stat tstat2, fstat1;
    if (stat(tp, &tstat2) != 0 || stat(p, &fstat1) != 0) fail("from_stat_after");
    if (tstat2.st_size != tstat.st_size || tstat2.st_mtim.tv_sec != tstat.st_mtim.tv_sec ||
        tstat2.st_mtim.tv_nsec != tstat.st_mtim.tv_nsec)
        fail("from_torrent_mtime_changed");
    if (fstat1.st_size != fstat0.st_size) fail("from_source_changed");
    size_t tn2 = 0;
    uint8_t *tb2 = slurp(tp, &tn2);
    if (!tb2 || tn2 != tn || memcmp(tb, tb2, tn) != 0) fail("from_torrent_bytes_changed");
    free(tb);
    free(tb2);
    ntx_session_remove(x.s, tj);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_same_link");
}

/* ---- A6 case b: one byte changed in the copy → CHANGED event (§5.6.3) ---- */
static void test_from_changed(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fromchg");
    char p[256], cp[256];
    snprintf(p, sizeof p, SCRATCH "/fromchg/s.bin");
    snprintf(cp, sizeof cp, SCRATCH "/fromchg/c.bin");
    mk_file(p, 300000, 53);
    if (copy_file(p, cp) != 0) fail("fromchg_copy");
    /* The .torrent is the ORIGINAL bytes; the copy we share carries one byte
     * changed inside the SECOND piece, so both the v1 SHA-1 and the BEP 52 layer
     * of that piece disagree with what the .torrent claims. */
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data) fail("fromchg_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, 16384, 0, &tn);
    free(data);
    {
        int fd = open(cp, O_WRONLY);
        if (fd < 0) fail("fromchg_open");
        uint8_t one = 0xA5;
        if (pwrite(fd, &one, 1, 20000) != 1) fail("fromchg_pwrite");
        close(fd);
    }
    if (!tb) fail("fromchg_mktorrent");
    char tp[NTX_SHARE_PATH_MAX];
    snprintf(tp, sizeof tp, SCRATCH "/fromchg/known.torrent");
    if (write_all(tp, tb, tn) != 0) fail("fromchg_write");
    free(tb);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, cp, tp, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("fromchg_add");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("fromchg_not_failed");
    if (ntx_session_share_serving(x.s, ti) != 0) fail("fromchg_serving_after_fail");
    ntx_share_event ev;
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("fromchg_no_event");
    if (ev.ok || ev.err != NTX_SHARE_E_CHANGED) {
        printf("EV ok=%d err=%d\n", ev.ok, (int)ev.err);
        fail("fromchg_event_fields");
    }
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("fromchg_two_events");
    /* the .torrent of a failed verification is still untouched, and no new
     * file was written for it */
    char other[NTX_SHARE_PATH_MAX];
    snprintf(other, sizeof other, SCRATCH "/st_fromchg/known-00000000.torrent");
    if (file_exists(other)) fail("fromchg_wrote_a_torrent");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_changed_gives_changed_event");
}

/* ---- A6 case c: public / wrong length / junk → -1 + BAD_ARG (§5.6.1) ----- */
static void test_from_bad_arg(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fromerr");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/fromerr/s.bin");
    mk_file(p, 300000, 57);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data) fail("fromerr_slurp");
    size_t tn = 0;
    uint8_t *pub = mk_torrent(data, dn, 16384, 1, &tn); /* private flag missing */
    /* a metainfo that declares one byte MORE than the file on disk: internally
     * valid bencode, valid hashes, valid hybrid layout — only §5.6.1 can reject it */
    uint8_t *longer = malloc(dn + 1);
    if (!longer) fail("fromerr_alloc");
    memcpy(longer, data, dn);
    longer[dn] = data[0];
    uint8_t *bad = mk_torrent(longer, dn + 1, 16384, 0, &tn);
    free(longer);
    free(data);
    if (!pub || !bad) fail("fromerr_mktorrent");
    char tp[NTX_SHARE_PATH_MAX];
    ntx_share_err e = NTX_SHARE_OK;
    pm_park(&x, NTX_PM_OFF);

    snprintf(tp, sizeof tp, SCRATCH "/fromerr/public.torrent");
    if (write_all(tp, pub, tn) != 0) fail("fromerr_write_pub");
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG) fail("fromerr_public");
    if (ntx_session_share_state(x.s, 0) != NTX_SHARE_NONE) fail("fromerr_public_slot");

    snprintf(tp, sizeof tp, SCRATCH "/fromerr/badlen.torrent");
    if (write_all(tp, bad, tn) != 0) fail("fromerr_write_bad");
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG) fail("fromerr_bad_len");

    snprintf(tp, sizeof tp, SCRATCH "/fromerr/junk.torrent");
    if (write_all(tp, (const uint8_t *)"d6:lengthi1e", 12) != 0) fail("fromerr_write_junk");
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG) fail("fromerr_junk");

    if (ntx_session_share_add(x.s, p, SCRATCH "/fromerr", &e) != -1 || e != NTX_SHARE_E_BAD_ARG)
        fail("fromerr_dir");
    if (ntx_session_share_add(x.s, p, SCRATCH "/fromerr/missing.torrent", &e) != -1 ||
        e != NTX_SHARE_E_BAD_ARG)
        fail("fromerr_missing");
    if (!file_exists(p)) fail("fromerr_consumed_the_file");
    if (ntx_session_share_state(x.s, 0) != NTX_SHARE_NONE) fail("fromerr_slot_used");
    free(pub);
    free(bad);
    ntx_session_share_free(x.s);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_bad_arg");
}

/* ---- A6 case d (review focus 5): same .torrent twice → EXISTS, first ok --- */
static void test_from_duplicate(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fromdup");
    char p[256];
    snprintf(p, sizeof p, SCRATCH "/fromdup/s.bin");
    mk_file(p, 300000, 59);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data) fail("fromdup_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, 16384, 0, &tn);
    free(data);
    if (!tb) fail("fromdup_mktorrent");
    char tp[NTX_SHARE_PATH_MAX];
    snprintf(tp, sizeof tp, SCRATCH "/fromdup/dup.torrent");
    if (write_all(tp, tb, tn) != 0) fail("fromdup_write");
    free(tb);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, tp, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("fromdup_add_first");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (!pump_to_ready(&x, ti)) fail("fromdup_first_not_ready");
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_READY) fail("fromdup_first_state");

    int tj = share_add_parked(&x, p, tp, &e); /* the same link, twice */
    if (tj < 0 || e != NTX_SHARE_OK) fail("fromdup_add_second");
    if (tj == ti) fail("fromdup_same_slot");
    (void)pump_until_hashed(&x, tj, 2000, NULL);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_FAILED) fail("fromdup_second_not_failed");

    ntx_share_event ev;
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("fromdup_no_first_event");
    if (!ev.ok || ev.i != ti) fail("fromdup_first_event"); /* the READY one */
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("fromdup_no_second_event");
    if (ev.ok || ev.err != NTX_SHARE_E_EXISTS) {
        printf("EV2 ok=%d err=%d code=%s\n", ev.ok, (int)ev.err, ntx_share_err_code(ev.err));
        fail("fromdup_second_event");
    }
    if (ev.i != tj) fail("fromdup_second_event_slot");
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_READY) fail("fromdup_first_broken");
    if (ntx_session_share_serving(x.s, ti) != 1) fail("fromdup_first_not_serving");
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("fromdup_third_event");
    ntx_session_remove(x.s, ti);
    ntx_session_remove(x.s, tj);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_duplicate_gives_exists");
}

/* --------- A6 case e (review focus 4): truncation during hash/serve -------- */
static void test_from_truncated(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fromio");
    char p[256], tp[NTX_SHARE_PATH_MAX];
    const uint64_t big = (uint64_t)32 << 20;
    const uint32_t ps = 16384;

    /* --- part 1: ftruncate to half MID-HASH → CHANGED or IO, session lives --- */
    snprintf(p, sizeof p, SCRATCH "/fromio/big.bin");
    mk_file(p, big, 61);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data || dn != big) fail("fromio_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, ps, 0, &tn);
    free(data);
    if (!tb) fail("fromio_mktorrent");
    snprintf(tp, sizeof tp, SCRATCH "/fromio/big.torrent");
    if (write_all(tp, tb, tn) != 0) fail("fromio_write");
    free(tb);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, tp, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("fromio_add");
    for (int i = 0; i < 3; i++) ntx_session_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("fromio_hashed_too_fast");
    if (trunc_to(p, (off_t)(big / 2)) != 0) fail("fromio_ftruncate");
    (void)pump_until_hashed(&x, ti, 4000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("fromio_not_failed");
    ntx_share_event ev;
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("fromio_no_event");
    if (ev.ok || (ev.err != NTX_SHARE_E_CHANGED && ev.err != NTX_SHARE_E_IO)) {
        printf("EVio ok=%d err=%d code=%s\n", ev.ok, (int)ev.err, ntx_share_err_code(ev.err));
        fail("fromio_event_fields");
    }
    /* the session survives: another share still works, ticks stay clean */
    char q[256];
    snprintf(q, sizeof q, SCRATCH "/fromio/small.bin");
    mk_file(q, 40000, 62);
    int tj = ntx_session_share_add(x.s, q, NULL, &e);
    if (tj < 0 || e != NTX_SHARE_OK) fail("fromio_session_dead");
    (void)pump_until_hashed(&x, tj, 2000, NULL);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_ANNOUNCING &&
        ntx_session_share_state(x.s, tj) != NTX_SHARE_READY)
        fail("fromio_second_share_failed");
    for (int i = 0; i < 5; i++) ntx_session_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("fromio_failed_revived");
    ntx_session_remove(x.s, ti);
    ntx_session_remove(x.s, tj);

    /* --- part 2: after READY a ftruncate gives CHANGED in <= 2 s and the
     *            block request is refused (§5.5, review focus 4) --- */
    sess y;
    sess_open(&y, "fromserve");
    snprintf(p, sizeof p, SCRATCH "/fromserve/s.bin");
    mk_file(p, 300000, 63);
    dn = 0;
    data = slurp(p, &dn);
    if (!data) fail("fromserve_slurp");
    tn = 0;
    tb = mk_torrent(data, dn, 16384, 0, &tn);
    free(data);
    if (!tb) fail("fromserve_mktorrent");
    snprintf(tp, sizeof tp, SCRATCH "/fromserve/s.torrent");
    if (write_all(tp, tb, tn) != 0) fail("fromserve_write");
    free(tb);

    e = NTX_SHARE_OK;
    int si = share_add_parked(&y, p, tp, &e);
    if (si < 0 || e != NTX_SHARE_OK) fail("fromserve_add");
    (void)pump_until_hashed(&y, si, 2000, NULL);
    if (!pump_to_ready(&y, si)) fail("fromserve_not_ready");
    ntx_share_event ev2;
    (void)ntx_session_share_poll_event(y.s, &ev2);

    /* a real peer slot on a socketpair, so data_serve() is the production path */
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) fail("fromserve_socketpair");
    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(y.s, sv[0], &pa, 6881, si);
    if (pi < 0) fail("fromserve_peer_alloc");
    y.s->peer_phase[pi] = PH_OK;
    y.s->peer_plain[pi] = 1;
    y.s->peer_hello_sent[pi] = 1;
    y.s->peer_fast[pi] = 1;
    ntx_peer_set_we_choke(&y.s->peers[pi], 0);
    ntx_peer_set_int_us(&y.s->peers[pi], 1);

    static uint8_t rx[4096];
    ntx_session_data_on_request(y.s, pi, 0, 0, 1024);
    ntx_session_peer_out_flush(y.s, pi);
    ssize_t rn = recv(sv[1], rx, sizeof rx, MSG_DONTWAIT);
    if (rn < 13 || rx[4] != MSG_PIECE) {
        printf("PRE rn=%zd id=%d\n", rn, rn > 4 ? rx[4] : -1);
        fail("fromserve_serve_before_change");
    }
    printf("PASS fromserve_serves_before_change (piece %zd B)\n", rn);

    if (trunc_to(p, (off_t)(dn / 2)) != 0) fail("fromserve_ftruncate");
    ntx_share_test_advance_ms(1500); /* past the 1 s fstat interval, <= 2 s gate */
    ntx_session_share_tick(y.s);
    if (ntx_session_share_state(y.s, si) != NTX_SHARE_FAILED) fail("fromserve_not_changed");
    if (ntx_session_share_serving(y.s, si) != 0) fail("fromserve_still_serving");
    /* One event per share (§5.5, A5): the READY one was already reported, so the
     * failure reaches the UI through share=2 / code in the stats, not a second
     * event. Asserting that here keeps the rule visible. */
    ntx_share_event ev3;
    if (ntx_session_share_poll_event(y.s, &ev3) != 0) fail("fromserve_second_event");
    if (y.s->share[si]->err != NTX_SHARE_E_CHANGED) fail("fromserve_err_not_changed");
    uint64_t up_before = y.s->tts_up[si];
    ntx_session_data_on_request(y.s, pi, 0, 0, 1024);
    ntx_session_peer_out_flush(y.s, pi);
    rn = recv(sv[1], rx, sizeof rx, MSG_DONTWAIT);
    { /* §5.5: the change path choked the peer first, then data_serve refused with
       * BEP6 reject_request (16) — the bytes must be choke(5) + reject(17). */
        size_t o = 0;
        if (rn >= 5 && rx[4] == MSG_CHOKE) o = 5;
        if (rn != (ssize_t)(o + 17) || rx[o + 4] != 16 || o + 17 != 22) { /* 16 = BEP6 reject */
            printf("POST rn=%zd id=%d up=%llu\n", rn, rn > 4 ? rx[4] : -1,
                   (unsigned long long)y.s->tts_up[si]);
            fail("fromserve_served_after_change");
        }
        if (ntx_wire_rd32(rx + o + 5) != 0 || ntx_wire_rd32(rx + o + 9) != 0 ||
            ntx_wire_rd32(rx + o + 13) != 1024)
            fail("fromserve_reject_fields");
    }
    if (y.s->tts_up[si] != up_before) fail("fromserve_up_counted");
    close(sv[0]);
    close(sv[1]);
    y.s->peers[pi].fd = -1;
    y.s->peer_tts[pi] = -1;
    ntx_session_remove(y.s, si);
    sess_close(&y);
    ntx_session_remove(x.s, 0);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_truncated_io_and_changed");
}

/* §5.6, second half of review focus 4: a short pread *while serving* (not a stat
 * change) must refuse the request AND park the share in FAILED/IO. The 1 s fstat
 * is disarmed for the duration so the read error is the only thing that can fail
 * the share — otherwise the truncation below would be caught as CHANGED first and
 * the IO branch would never be exercised. */
static void test_from_serve_io(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess z;
    sess_open(&z, "frompread");
    char p[256], tp[NTX_SHARE_PATH_MAX];
    const uint32_t ps = 16384;

    snprintf(p, sizeof p, SCRATCH "/frompread/g.bin");
    mk_file(p, 40000, 64); /* 3 pieces: 16384 + 16384 + 7232 */
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data || dn != 40000) fail("frompread_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, ps, 0, &tn);
    free(data);
    if (!tb) fail("frompread_mktorrent");
    snprintf(tp, sizeof tp, SCRATCH "/frompread/g.torrent");
    if (write_all(tp, tb, tn) != 0) fail("frompread_write");
    free(tb);

    ntx_share_err e = NTX_SHARE_OK;
    int si = share_add_parked(&z, p, tp, &e);
    if (si < 0 || e != NTX_SHARE_OK) fail("frompread_add");
    (void)pump_until_hashed(&z, si, 2000, NULL);
    if (!pump_to_ready(&z, si)) fail("frompread_not_ready");
    ntx_share_event ev0;
    if (ntx_session_share_poll_event(z.s, &ev0) != 1 || !ev0.ok) fail("frompread_ready_event");
    if (ntx_session_share_serving(z.s, si) != 1) fail("frompread_not_serving");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) fail("frompread_socketpair");
    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(z.s, sv[0], &pa, 6881, si);
    if (pi < 0) fail("frompread_peer_alloc");
    z.s->peer_phase[pi] = PH_OK;
    z.s->peer_plain[pi] = 1;
    z.s->peer_hello_sent[pi] = 1;
    z.s->peer_fast[pi] = 1;
    ntx_peer_set_we_choke(&z.s->peers[pi], 0);
    ntx_peer_set_int_us(&z.s->peers[pi], 1);

    /* the last piece is the one that disappears: abs = 2 * 16384 > 20000 */
    z.s->share[si]->fstat_at = UINT64_MAX; /* only the read may fail the share */
    if (trunc_to(p, 20000) != 0) fail("frompread_ftruncate");

    uint64_t up_before = z.s->tts_up[si];
    ntx_session_data_on_request(z.s, pi, 2, 0, 1024);
    ntx_session_peer_out_flush(z.s, pi);
    static uint8_t rx[4096];
    ssize_t rn = recv(sv[1], rx, sizeof rx, MSG_DONTWAIT);
    if (rn != 17 || rx[4] != 16 /* BEP6 reject */) {
        printf("IO rn=%zd id=%d\n", rn, rn > 4 ? rx[4] : -1);
        fail("frompread_not_rejected");
    }
    if (ntx_wire_rd32(rx + 5) != 2 || ntx_wire_rd32(rx + 9) != 0 || ntx_wire_rd32(rx + 13) != 1024)
        fail("frompread_reject_fields");
    if (z.s->tts_up[si] != up_before) fail("frompread_up_counted");
    if (ntx_session_share_state(z.s, si) != NTX_SHARE_FAILED) fail("frompread_not_failed");
    if (z.s->share[si]->err != NTX_SHARE_E_IO)
        fail("frompread_err_not_io");
    if (ntx_session_share_serving(z.s, si) != 0) fail("frompread_still_serving");
    /* one event per share (§5.5): the failure is in the stats, not a second line */
    ntx_share_event ev1;
    if (ntx_session_share_poll_event(z.s, &ev1) != 0) fail("frompread_second_event");

    close(sv[0]);
    close(sv[1]);
    z.s->peers[pi].fd = -1;
    z.s->peer_tts[pi] = -1;
    ntx_session_remove(z.s, si);
    sess_close(&z);
    tracker_stop(&tr);
    ok("from_serve_read_io");
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
    test_from_same_link();
    test_from_changed();
    test_from_bad_arg();
    test_from_duplicate();
    test_from_truncated();
    test_from_serve_io();
    ntx_share_trackers_test_set(NULL, -1);
    printf("ALL PASS\n");
    return 0;
}
