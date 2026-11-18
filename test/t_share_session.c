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

/* R27: the .torrent destination is named after a 16-byte salt that lives INSIDE
 * `info`, so the info hash — and with it the file name — is unpredictable, and a
 * foreign file cannot be planted at the destination to force the disk collision.
 * The one ntx_rand_bytes call ntx_share.c makes is therefore overridden the way
 * test/t_rng.c overrides read(): off by default (every existing case keeps real
 * randomness, which is what keeps two shares of one file two different hashes),
 * switched on only by the case that needs the name to be computable. */
static void (*g_real_rand_bytes)(void *, size_t) = ntx_rand_bytes;
static int g_fixed_salt;
static void test_rand_bytes(void *buf, size_t n) {
    if (!g_fixed_salt) { g_real_rand_bytes(buf, n); return; }
    uint8_t *s = buf;
    for (size_t i = 0; i < n; i++) s[i] = 0x2a;
}
#define ntx_rand_bytes test_rand_bytes
#include "../src/core/ntx_share.c"
#undef ntx_rand_bytes
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

/* Pid-scoped scratch root. Two concurrent instances of this binary under one
 * root destroyed each other's payloads and store entries — scratch() unlinks
 * every non-dot entry in the st_<tag> store dirs and the cases write their
 * payload files under the same tree — which showed up as FAIL
 * hash_did_not_finish and FAIL tmp_or_torrent_left only when the two runs
 * overlapped. CI runs one sequential suite per checkout, so this is local and
 * parallel-agent hygiene; no product code is involved. Pid-suffixed dirs
 * persist as garbage in a gitignored tree; clean up with
 * `rm -rf test/.scratch/a5-*` (no stale-dir reaper here on purpose). */
static char scratch_root[64];

static void scratch_root_init(void) {
    snprintf(scratch_root, sizeof scratch_root, "test/.scratch/a5-%d", (int)getpid());
}

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
    if (mkdir(scratch_root, 0755) != 0 && errno != EEXIST) fail("scratch");
    static const char *const tags[] = {"gates","hash","started","rmhash","pin","revive","ratio","a4","ceil","fdheld",
                                       "from","fromchg","fromerr","fromdup","fromio","fromserve",
                                       "frompread","fromexact","fromname","store","during","durtrunc",
                                       "r7dead","r7hash","r7pend",
                                       "r5chg","r5io","r4evt","r4qa","r11","r11b","r12",
                                       "exdisk","exslot","r28name"};
    for (size_t k = 0; k < sizeof tags / sizeof tags[0]; k++) {
        char d[640];
        snprintf(d, sizeof d, "%s/%s", scratch_root, tags[k]);
        if (mkdir(d, 0755) != 0 && errno != EEXIST) fail("scratch_tag");
        if (mkdir(d, 0755) != 0 && errno != EEXIST) fail("scratch_st");
        /* the store dirs must start empty: a leftover .torrent (the salt makes
         * every run's hash new) would turn the A4 write into E_EXISTS */
        DIR *sd = opendir(d);
        if (sd) {
            struct dirent *de;
            while ((de = readdir(sd)))
                if (de->d_name[0] != '.') {
                    snprintf(d, sizeof d, "%s/st_%s/%s", scratch_root, tags[k], de->d_name);
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
/* `name` is BOTH the v1 "name" and the single BEP 52 file-tree key, exactly as
 * ntx_share_build_info writes them (one string, two places), so a forged
 * metainfo with a hostile name is the same shape a real share would produce. */
static uint8_t *mk_torrent_named(const uint8_t *data, size_t size, uint32_t ps, int pub, const char *name,
                                 size_t *out_n) {
    size_t name_n = strlen(name);
    if (name_n == 0 || name_n > 200) return NULL;
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
    bstrn(&info, name, name_n);
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
    bstrn(&info, name, name_n);
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

/* The fixed name is the CLI/JSON basename in every other case, so the plain
 * builder is the named builder with its own default. */
static uint8_t *mk_torrent(const uint8_t *data, size_t size, uint32_t ps, int pub, size_t *out_n) {
    return mk_torrent_named(data, size, ps, pub, "f.bin", out_n);
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
    snprintf(dir, sizeof dir, "%s/st_%s", scratch_root, tag);
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

static int tr_count(tracker *t, const char *needle); /* below, with the R5 helpers */

/* --- R11 helpers: a real driver against a gateway that never answers ---------
 * pm_park pins the ENUM; this case needs the real state machine, so the driver is
 * pointed at a fake UDP socket that only receives (the silent gateway of R11) and
 * at a route fixture under the scratch tree. Same fixture shape t_portmap.c uses:
 * /proc/net/route prints the gateway as a host-byte-order hex u32. */
static char r11_v4[256], r11_v6[256];

/* The driver's cap and the port its grant will carry, spelled out here instead of
 * read from the driver: the case must fail on the BEHAVIOUR it is about (R11), not
 * on a missing macro. */
#define R11_SETTLE_MS 4000u
#define R11_EXT 40123u

static void r11_routes(uint16_t port) {
    snprintf(r11_v4, sizeof r11_v4, "%s/r11_route4", scratch_root);
    snprintf(r11_v6, sizeof r11_v6, "%s/r11_route6", scratch_root);
    char line[512];
    snprintf(line, sizeof line,
             "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n"
             "lo\t00000000\t0100007F\t0003\t0\t0\t100\t00000000\t0\t0\t0\n"
             "lo\t0100007F\t00000000\t0001\t0\t0\t100\t000000FF\t0\t0\t0\n");
    FILE *f = fopen(r11_v4, "w");
    if (!f) fail("r11_route4_open");
    fputs(line, f);
    fclose(f);
    snprintf(line, sizeof line,
             "00000000000000000000000000000000 00 00000000000000000000FFFF7F000001 40 "
             "00000000000000000000000000000000 00000100 00000001 00000000 00000001 lo\n");
    f = fopen(r11_v6, "w");
    if (!f) fail("r11_route6_open");
    fputs(line, f);
    fclose(f);
    ntx_portmap_test_set_route_files(r11_v4, r11_v6);
    ntx_portmap_test_set_gateway_port(port);
}

/* A UDP socket bound and never read: the driver's datagrams go there, nothing
 * ever answers, and no ICMP comes back (it is alive), so this is the SILENT
 * gateway of R11 — neither PCP nor NAT-PMP replies. */
static int r11_gw_start(uint16_t *port) {
    int fd = socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    struct sockaddr_in a;
    memset(&a, 0, sizeof a);
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = htonl(0x7f000001);
    if (fd < 0 || bind(fd, (struct sockaddr *)&a, sizeof a) != 0) fail("r11_gw_bind");
    socklen_t al = sizeof a;
    getsockname(fd, (struct sockaddr *)&a, &al);
    *port = ntohs(a.sin_port);
    return fd;
}

/* ---- R11: a share must not wait on a silent gateway -------------------------
 * The gate of §5.5 held `started` back until the port map LEFT PENDING. Against a
 * gateway that answers nothing that is the whole retransmission schedule — nine
 * sends, doubled, ~64 s over NAT-PMP (the driver's first family is PCP, so ~128 s
 * of RFC 6887 pacing plus the NAT-PMP fallback). The magnet, which §5.5 promises
 * as soon as one tracker answers `started`, therefore arrived two minutes late.
 * Now: after NTX_PM_SHARE_SETTLE_MS the announce goes out on the listen port, and
 * a grant that arrives later re-announces with the external port. */
static void test_silent_gateway_settles(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    uint16_t gport = 0;
    int gwd = r11_gw_start(&gport);
    r11_routes(gport);

    sess x;
    sess_open(&x, "r11");
    x.cfg.port_map = 1;
    char p[256];
    snprintf(p, sizeof p, "%s/r11/s.bin", scratch_root);
    mk_file(p, 300000, 141);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e); /* §8: the share wants the map */
    if (ti < 0) {
        printf("R11ADD e=%d %s\n", (int)e, ntx_share_err_msg(e));
        fail("r11_add");
    }
    if (!x.s->pm || !x.s->pm->want) fail("r11_portmap_not_requested");

    /* The driver reaches PENDING for real (route read, socket opened), and the
     * share leaves HASHING, so the §5.5 gate is the only thing left holding. */
    for (int i = 0; i < 20; i++) ntx_session_tick(x.s);
    if (ntx_session_portmap_state(x.s) != NTX_PM_PENDING) fail("r11_not_pending");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("r11_not_announcing");

    /* Nothing announced while the mapping is pending and the settle window is
     * still open (the §5.5 behaviour, and the pre-fix state forever). */
    for (int i = 0; i < 3; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (tracker_count(&tr) != 0) {
        printf("EARLY[%s]\n", tr.lines);
        fail("r11_announced_before_settle");
    }

    /* The clock to just under the cap: still nothing. Just past it: `started` on
     * the LISTEN port, with the mapping still PENDING. */
    ntx_share_test_advance_ms(R11_SETTLE_MS - 500);
    for (int i = 0; i < 3; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (tr_count(&tr, "event=started") != 0) fail("r11_started_before_cap");
    ntx_share_test_advance_ms(1000);
    for (int i = 0; i < 8 && tr_count(&tr, "event=started") < 1; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (ntx_session_portmap_state(x.s) != NTX_PM_PENDING) fail("r11_map_still_pending");
    if (tr_count(&tr, "event=started") < 1) {
        printf("TRK[%s]\n", tr.lines);
        fail("r11_no_started_after_settle");
    }
    char want[64];
    snprintf(want, sizeof want, "port=%u&", (unsigned)ntx_netx_port(x.n));
    if (!strstr(tr.lines, want)) {
        printf("TRK[%s]\n", tr.lines);
        printf("WANT[%s]\n", want);
        fail("r11_started_not_on_listen_port");
    }
    if (!x.s->trk_started_ok[ti]) fail("r11_started_ok");

    /* The late grant: the canned PCP SUCCESS for the request the driver has
     * outstanding. The port it carries must reach a LATER announce. */
    struct sockaddr_in from;
    socklen_t fl = sizeof from;
    uint8_t req[2048], rsp[60];
    ssize_t rn = -1;
    for (int i = 0; i < 40 && rn < 0; i++) {
        ntx_portmap_test_advance_ms(1000); /* walk the retransmission schedule */
        ntx_session_portmap_tick(x.s);
        rn = recvfrom(gwd, req, sizeof req, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
    }
    if (rn != 60 || req[1] != 1 || req[36] != 6) {
        printf("REQ n=%zd\n", rn);
        fail("r11_no_pcp_request_outstanding");
    }
    memset(rsp, 0, sizeof rsp);
    rsp[0] = 2;
    rsp[1] = 0x81;
    rsp[4] = 0; rsp[5] = 0x1c; rsp[6] = 0x20; rsp[7] = 0; /* lifetime 7200 */
    rsp[8] = 0; rsp[9] = 0; rsp[10] = 0; rsp[11] = 7;    /* epoch */
    memcpy(rsp + 24, req + 24, 12);                      /* its nonce */
    rsp[36] = req[36];
    rsp[40] = req[40];
    rsp[41] = req[41];
    rsp[42] = (uint8_t)(R11_EXT >> 8);
    rsp[43] = (uint8_t)R11_EXT;
    /* The Assigned External IP Address of §11.1 is octets 44..59, and the IPv4-mapped
     * prefix lives in octets 10..11 of THAT field — 54/55 of the message, not 44/45.
     * The fixture used to write them at 44/45, i.e. `ffff::c700:7109`, which is no one's
     * address; the driver accepted it only because it judged no shape at all (R22). */
    rsp[54] = 0xff; rsp[55] = 0xff;                       /* IPv4-mapped … */
    rsp[56] = 203; rsp[57] = 0; rsp[58] = 113; rsp[59] = 9;
    if (sendto(gwd, rsp, sizeof rsp, 0, (struct sockaddr *)&from, fl) < 0) fail("r11_gw_send");
    for (int i = 0; i < 40; i++) ntx_netx_run_once(x.n, 2);
    if (ntx_session_portmap_state(x.s) != NTX_PM_ACTIVE) fail("r11_not_active_after_grant");
    if (ntx_session_adv_port(x.s) != (uint16_t)R11_EXT) fail("r11_adv_port");

    snprintf(want, sizeof want, "port=%u&", (unsigned)R11_EXT);
    int got_ext = 0;
    for (int i = 0; i < 8 && !got_ext; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
        tracker_drain(&tr);
        got_ext = strstr(tr.lines, want) != NULL;
    }
    if (!got_ext) {
        printf("TRK2[%s]\n", tr.lines);
        printf("WANT[%s]\n", want);
        fail("r11_no_reannounce_with_ext_port");
    }

    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    close(gwd);
    ntx_portmap_test_set_route_files(NULL, NULL);
    ntx_portmap_test_set_gateway_port(0);
    ok("silent_gateway_settles");
}

/* ---- R11 b: the mapping gives up AFTER the share already announced ----------
 * The interaction with R9's error paths: the settle cap fired, `started` went out
 * on the listen port, and the sequence then runs its budget out. The share must
 * stay up on the listen port, announce no second `started`, and the driver must
 * still reach `none` exactly as it did before the cap existed. */
static void test_silent_gateway_gives_up(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    uint16_t gport = 0;
    int gwd = r11_gw_start(&gport);
    r11_routes(gport);

    sess x;
    sess_open(&x, "r11b");
    x.cfg.port_map = 1;
    char p[256];
    snprintf(p, sizeof p, "%s/r11/t.bin", scratch_root);
    mk_file(p, 100000, 142);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("r11b_add");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING) fail("r11b_not_announcing");

    /* §5.5 held it back while the mapping was pending and the window was open, then
     * the cap let it go — both on the share's own clock, so neither is a race. */
    for (int i = 0; i < 3; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (tr_count(&tr, "event=started") != 0) fail("r11b_started_before_cap");
    ntx_share_test_advance_ms(R11_SETTLE_MS + 1000);
    for (int i = 0; i < 400 && tr_count(&tr, "event=started") < 1; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (tr_count(&tr, "event=started") < 1) fail("r11b_no_started_after_settle");
    if (ntx_session_portmap_state(x.s) != NTX_PM_PENDING) fail("r11b_still_pending");
    x.s->share[ti]->fstat_at = UINT64_MAX; /* the fstat is not what this case tests */

    /* Walk the whole retransmission schedule of the silent gateway: step the
     * virtual clock to each scheduled instant and let one tick do the one send it
     * is allowed to do, exactly as t_portmap's case D drives it. */
    int steps = 0;
    while (ntx_session_portmap_state(x.s) == NTX_PM_PENDING && steps++ < 60) {
        long w = (long)(x.s->pm->next_try - pm_now());
        ntx_portmap_test_advance_ms((uint64_t)(w > 0 ? w + 5 : 5));
        ntx_session_portmap_tick(x.s);
    }
    for (int i = 0; i < 10; i++) ntx_session_tick(x.s);
    if (ntx_session_portmap_state(x.s) != NTX_PM_NONE) {
        printf("PMSTATE=%d PH=%d TRIES=%d FAM=%d GAP=%u WAIT=%lld STEPS=%d\n", (int)ntx_session_portmap_state(x.s),
               x.s->pm->phase, x.s->pm->tries, x.s->pm->fam, x.s->pm->gap,
               (long long)(x.s->pm->next_try - pm_now()), steps);
        fail("r11b_none_after_budget");
    }
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_READY &&
        ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING)
        fail("r11b_share_died_with_the_mapping");
    if (ntx_session_adv_port(x.s) != (uint16_t)ntx_netx_port(x.n)) fail("r11b_adv_port");

    int started = tr_count(&tr, "event=started");
    for (int i = 0; i < 4; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
    }
    if (tr_count(&tr, "event=started") != started) fail("r11b_second_started_announce");
    char want[64];
    snprintf(want, sizeof want, "port=%u&", (unsigned)ntx_netx_port(x.n));
    if (!strstr(tr.lines, want)) fail("r11b_not_on_listen_port");

    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    close(gwd);
    ntx_portmap_test_set_route_files(NULL, NULL);
    ntx_portmap_test_set_gateway_port(0);
    ok("silent_gateway_gives_up");
}

/* ---- R12: a renewal that dies takes the advertised port with it, and a re-grant
 * brings the external port back -------------------------------------------------
 * The share announced on the external port; the gateway then stops answering the
 * renewal, spends the driver's budget and lets the mapping expire. Pre-fix the driver
 * kept the grant: the state stayed ACTIVE, `ntx_session_adv_port` went on returning
 * the port nobody forwards any more, every announce and ext-handshake told the swarm
 * to dial it, and the renewal loop — which only walks `active && !failed` — never
 * asked for a mapping again. Pre-fix failures: r12_adv_port_back_to_listen
 * got=40123 want=<listen>, r12_no_announce_on_listen (no such line in the tracker),
 * r12_reacquired / r12_adv_port_new_ext / r12_no_reannounce_with_new_ext (nothing was
 * ever re-asked, so the second half never happened at all). */
#define R12_EXT 40123u
#define R12_EXT2 40155u
#define R12_REACQ_MS 300000u

/* One PCP answer with `ext`, for the MAP request the driver has outstanding. The
 * Epoch advances with the client's clock, so a healthy gateway is never mistaken for a
 * §8.5 restart. `skip_nonce`, when non-NULL, marks the DEAD grant's nonce: the last
 * retransmissions of a renewal that is already lost carry it, and answering them would
 * pass the case on a datagram nobody is waiting for. */
static uint64_t r12_epoch_at;
static uint32_t r12_epoch;

static int r12_answer_map(int gwd, sess *x, uint16_t ext, const uint8_t skip_nonce[12]) {
    ntx_session *s = x->s;
    uint8_t req[2048], rsp[60];
    for (int spins = 0; spins < 900; spins++) {
        struct sockaddr_in from;
        socklen_t fl = sizeof from;
        ssize_t n = recvfrom(gwd, req, sizeof req, MSG_DONTWAIT, (struct sockaddr *)&from, &fl);
        if (n == 60 && req[1] == 1 && req[36] == 6 && req[0] == 2 &&
            !(skip_nonce && memcmp(req + 24, skip_nonce, 12) == 0)) {
            memset(rsp, 0, sizeof rsp);
            rsp[0] = 2;
            rsp[1] = 0x81;
            rsp[4] = 0; rsp[5] = 0x1c; rsp[6] = 0x20; rsp[7] = 0; /* lifetime 7200 */
            uint32_t ep = r12_epoch + (uint32_t)((pm_now() - r12_epoch_at) / 1000u);
            rsp[8] = (uint8_t)(ep >> 24);
            rsp[9] = (uint8_t)(ep >> 16);
            rsp[10] = (uint8_t)(ep >> 8);
            rsp[11] = (uint8_t)ep;
            memcpy(rsp + 24, req + 24, 12);
            rsp[36] = req[36];
            rsp[40] = req[40];
            rsp[41] = req[41];
            rsp[42] = (uint8_t)(ext >> 8);
            rsp[43] = (uint8_t)ext;
            /* The 16 B Assigned External IP Address starts at octet 44, so its
             * IPv4-mapped prefix is octets 54/55 (see r11_gw_send for R22's rule). */
            rsp[54] = 0xff; rsp[55] = 0xff;
            rsp[56] = 203; rsp[57] = 0; rsp[58] = 113; rsp[59] = 9;
            r12_epoch = ep;
            r12_epoch_at = pm_now();
            if (sendto(gwd, rsp, sizeof rsp, 0, (struct sockaddr *)&from, fl) < 0) return -1;
            for (int i = 0; i < 20; i++) ntx_netx_run_once(x->n, 2);
            return 1;
        }
        ntx_portmap_test_advance_ms(1000);
        ntx_session_portmap_tick(s);
        ntx_netx_run_once(x->n, 2);
    }
    return 0;
}

static void test_lost_renewal_reannounces(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    uint16_t gport = 0;
    int gwd = r11_gw_start(&gport);
    r11_routes(gport);

    sess x;
    sess_open(&x, "r12");
    x.cfg.port_map = 1;
    char p[256];
    snprintf(p, sizeof p, "%s/r12/t.bin", scratch_root);
    mk_file(p, 120000, 151);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0) fail("r12_add");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    x.s->share[ti]->fstat_at = UINT64_MAX; /* the fstat is not what this case tests */

    /* The first grant, and `started` with the external port on the wire. */
    r12_epoch = 7;
    r12_epoch_at = pm_now();
    if (r12_answer_map(gwd, &x, R12_EXT, NULL) != 1) fail("r12_no_first_grant");
    if (ntx_session_portmap_state(x.s) != NTX_PM_ACTIVE) fail("r12_active");
    if (ntx_session_adv_port(x.s) != (uint16_t)R12_EXT) fail("r12_adv_port_ext");
    char want[64];
    snprintf(want, sizeof want, "port=%u&", (unsigned)R12_EXT);
    int got = 0;
    for (int i = 0; i < 12 && !got; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
        tracker_drain(&tr);
        got = strstr(tr.lines, want) != NULL;
    }
    if (!got) {
        printf("TRK1[%s]\n", tr.lines);
        fail("r12_no_announce_with_ext_port");
    }
    /* The nonce of this grant is the one the renewal reuses (R13), so it is also the
     * nonce of the retransmissions that go out while the renewal dies. */
    uint8_t dead_nonce[12];
    memcpy(dead_nonce, x.s->pm->grant_nonce[PM_PH_TCP], 12);

    /* The gateway goes quiet for the renewal: the renew window, then the budget. The
     * tick below is what puts the renewal on the wire. */
    ntx_portmap_test_advance_ms(3601000);
    ntx_session_portmap_tick(x.s);
    if (x.s->pm->phase != PM_PH_TCP) fail("r12_renewal_not_sent");
    int steps = 0;
    while (x.s->pm->phase >= 0 && steps++ < 40) {
        long w = (long)(x.s->pm->next_try - pm_now());
        ntx_portmap_test_advance_ms((uint64_t)(w > 0 ? w + 5 : 5));
        ntx_session_portmap_tick(x.s);
    }
    if (x.s->pm->phase != -1) fail("r12_renewal_still_outstanding");
    if (x.s->pm->active[PM_PH_TCP] != 0) fail("r12_grant_kept_after_failed_renewal");
    if (ntx_session_portmap_state(x.s) != NTX_PM_PENDING) fail("r12_pending_after_renewal_failed");
    if (ntx_session_adv_port(x.s) != (uint16_t)ntx_netx_port(x.n)) fail("r12_adv_port_back_to_listen");

    /* The swarm is told: a LATER announce carries the listen port again, and the share
     * stays up (it has been reachable on the listen port since the settle cap). */
    snprintf(want, sizeof want, "port=%u&", (unsigned)ntx_netx_port(x.n));
    got = 0;
    for (int i = 0; i < 12 && !got; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
        tracker_drain(&tr);
        got = strstr(tr.lines, want) != NULL;
    }
    if (!got) {
        printf("TRK2[%s]\n", tr.lines);
        fail("r12_no_announce_on_listen");
    }
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_READY &&
        ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING)
        fail("r12_share_died_with_the_grant");

    /* The gateway is back, with a DIFFERENT external port. The re-acquisition is owed
     * but paced (PM_REACQ_MS), so the clock walks in bounded steps. */
    if (r12_answer_map(gwd, &x, R12_EXT2, dead_nonce) != 1) fail("r12_no_reacquisition_query");
    if (ntx_session_portmap_state(x.s) != NTX_PM_ACTIVE) fail("r12_reacquired");
    if (ntx_session_adv_port(x.s) != (uint16_t)R12_EXT2) fail("r12_adv_port_new_ext");
    snprintf(want, sizeof want, "port=%u&", (unsigned)R12_EXT2);
    got = 0;
    for (int i = 0; i < 12 && !got; i++) {
        ntx_session_tick(x.s);
        pump_announces(&x, ti);
        tracker_drain(&tr);
        got = strstr(tr.lines, want) != NULL;
    }
    if (!got) {
        printf("TRK3[%s]\n", tr.lines);
        fail("r12_no_reannounce_with_new_ext");
    }

    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    close(gwd);
    ntx_portmap_test_set_route_files(NULL, NULL);
    ntx_portmap_test_set_gateway_port(0);
    ok("lost_renewal_reannounces");
}

/* --- R5 helpers -------------------------------------------------------------
 * How many of the requests the fake tracker saw carry `needle` (an announce
 * carries its event in the query string, so "event=stopped" counts goodbyes). */
static int tr_count(tracker *t, const char *needle) {
    tracker_drain(t);
    int c = 0;
    size_t nl = strlen(needle);
    for (size_t i = 0; i + nl <= t->n_lines; i++)
        if (memcmp(t->lines + i, needle, nl) == 0) c++;
    return c;
}

static void r5_nb(int fd) {
    int fl = fcntl(fd, F_GETFL, 0);
    if (fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0) fail("r5_nonblock");
}

/* A promoted peer of slot ti on a socketpair; *cli is the end the test owns.
 * The same shaping the from_serve cases use, so data_serve() is the real path. */
static int r5_attach_peer(sess *x, int ti, int *cli) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) fail("r5_socketpair");
    /* both ends nonblocking: the halt assertions drive ntx_session_tick, whose OK
     * peer poll reads this fd, and a blocking socketpair would stall the loop */
    r5_nb(sv[0]);
    r5_nb(sv[1]);
    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(x->s, sv[0], &pa, 6881, ti);
    if (pi < 0) fail("r5_peer_alloc");
    x->s->peer_phase[pi] = PH_OK;
    x->s->peer_plain[pi] = 1;
    x->s->peer_hello_sent[pi] = 1;
    x->s->peer_fast[pi] = 1;
    ntx_peer_set_we_choke(&x->s->peers[pi], 0);
    ntx_peer_set_int_us(&x->s->peers[pi], 1);
    *cli = sv[1];
    return pi;
}

/* Everything the peer end received, with a short timeout so "nothing was sent"
 * is an assertion and not a blocked read. */
static size_t r5_recv_all(int fd, uint8_t *buf, size_t cap) {
    size_t got = 0;
    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = POLLIN};
        if (poll(&pfd, 1, 60) <= 0) break;
        ssize_t r = read(fd, buf + got, cap - got);
        if (r <= 0) break;
        got += (size_t)r;
        if (got == cap) break;
    }
    return got;
}

static int r5_send_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) continue;
        return -1;
    }
    return 0;
}

/* The peer end of an inbound probe: alloc + the production on_accept, so the
 * responder path (sp_pe_set_infohash, sp_pe_step, sp_bths_try) is what answers. */
static int r5_accept_probe(sess *x, int *cli) {
    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) fail("r5_hs_socketpair");
    r5_nb(sv[0]);
    r5_nb(sv[1]);
    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0x7f000002));
    int pi = ntx_session_peer_alloc(x->s, sv[0], &pa, 6882, -1);
    if (pi < 0) fail("r5_hs_peer_alloc");
    ntx_session_peer_on_accept(x->s, x->s->netx, sv[0], NULL);
    *cli = sv[1];
    return pi;
}

static void r5_mk_hs(uint8_t m[68], const uint8_t ih[20]) {
    memset(m, 0, 68);
    m[0] = 19;
    memcpy(m + 1, "BitTorrent protocol", 19);
    m[25] = 0x10;
    m[27] = 0x04;
    memcpy(m + 28, ih, 20);
    memcpy(m + 48, "-peer0000000000000000", 20);
}

/* R5, last half of the halt: a new inbound connection that names the share with
 * its REAL hash must be refused. Both wire forms are asked: plaintext (the
 * reply would be the first byte we send, so nothing may go at all) and MSE (the
 * responder has to send its DH key before the decision, so what must not happen
 * is a reply handshake naming the dead slot). sp_slot_matchable is the gate. */
static void assert_new_handshake_refused(sess *x, int ti) {
    int cli = -1;
    int pi = r5_accept_probe(x, &cli);
    uint8_t hs[68];
    r5_mk_hs(hs, x->s->tts[ti].info_hash);
    if (r5_send_all(cli, hs, sizeof hs) != 0) fail("r5_hs_write");
    for (int k = 0; k < 3; k++) ntx_session_peer_hs_tick(x->s);
    static uint8_t got[2048];
    size_t gn = r5_recv_all(cli, got, sizeof got);
    if (x->s->peers[pi].fd != -1) {
        printf("R5HS_PL fd=%d bl=%zu\n", x->s->peers[pi].fd, x->s->peer_buflen[pi]);
        fail("r5_new_handshake_kept");
    }
    if (gn != 0) {
        printf("R5HS_PL bytes=%zu\n", gn);
        fail("r5_new_handshake_answered");
    }
    close(cli);

    cli = -1;
    pi = r5_accept_probe(x, &cli);
    ntx_pe cand;
    if (pi >= 0 && x->s->peer_phase[pi] == PH_PE) cand = x->s->pe[pi];
    else memset(&cand, 0, sizeof cand);
    ntx_pe cli_pe;
    ntx_pe_init(&cli_pe, NTX_PE_INITIATOR, cli);
    ntx_pe_set_infohash(&cli_pe, x->s->tts[ti].info_hash);
    r5_mk_hs(hs, x->s->tts[ti].info_hash);
    ntx_pe_set_bt_handshake(&cli_pe, hs);
    int idle = 0;
    for (int k = 0; k < 20000 && !cli_pe.done && !cli_pe.failed; k++) {
        int r = ntx_pe_step(&cli_pe);
        if (r < 0) break;
        ntx_session_peer_hs_tick(x->s);
        if (r == 0) {
            if (++idle > 2000) break;
        } else idle = 0;
    }
    if (cli_pe.bt_hs_got) fail("r5_mse_handshake_answered");
    if (x->s->peers[pi].fd != -1) fail("r5_mse_handshake_kept");
    if (x->s->pe[pi].bt_hs_sent) fail("r5_mse_reply_hs_sent");
    if (x->s->peer_phase[pi] == PH_OK) fail("r5_mse_handshake_promoted");
    /* the dead slot must not even be offered as an SKEY candidate */
    for (int k = 0; k < cand.infohash_cand_n; k++)
        if (memcmp(cand.infohash_cand[k], x->s->tts[ti].info_hash, 20) == 0)
            fail("r5_dead_slot_is_skey_candidate");
    close(cli);
}

/* The whole R5 contract, asserted on a share that was READY and is now gone:
 * ONE `stopped` per tracker (a `started` did go out), the announce schedule
 * gone, no announce at all for 2 x the tracker interval, the slot's peers
 * dropped, new handshakes refused, and no second goodbye when the slot is
 * finally removed. `pre` is the request count taken before the failed share. */
static void assert_halted(sess *x, int ti, tracker *tr, int pre, int pi, const char *tag) {
    char m[96];
    if (ntx_session_share_state(x->s, ti) != NTX_SHARE_FAILED) fail("halt_not_failed");
    if (ntx_session_share_serving(x->s, ti) != 0) fail("halt_still_serving");

    snprintf(m, sizeof m, "%s_peer_alive", tag);
    if (pi >= 0 && x->s->peers[pi].fd != -1) {
        printf("TAG=%s PI=%d FD=%d\n", tag, pi, x->s->peers[pi].fd);
        fail(m);
    }

    /* One goodbye per tracker that ever answered this slot — trk_stop_one is the
     * only sender and it skips the ones that never answered. */
    int live = 0;
    for (int k = 0; k < x->s->trk_n[ti]; k++)
        if (!x->s->trk_fail[ti][k]) live++;
    snprintf(m, sizeof m, "%s_exactly_one_stopped", tag);
    int stopped = tr_count(tr, "event=stopped");
    if (stopped != live || tracker_count(tr) != pre + live) {
        printf("TAG=%s STOPPED=%d want=%d REQS=%d TRK[%s]\n", tag, stopped, live,
               tracker_count(tr) - pre, tr->lines);
        fail(m);
    }
    snprintf(m, sizeof m, "%s_announce_scheduled", tag);
    if (x->s->trk_next[ti] != 0) {
        printf("TAG=%s NEXT=%llu\n", tag, (unsigned long long)x->s->trk_next[ti]);
        fail(m);
    }

    /* Nothing may go out for 2 x the interval the tracker granted (60 s in the
     * fake answer), from the periodic tick or from the peer boost — even with an
     * announce left scheduled, which is exactly the pre-fix state. */
    int base = tracker_count(tr);
    for (int r = 0; r < 2; r++) {
        x->s->trk_next[ti] = 1; /* as if one were still scheduled */
        ntx_share_test_advance_ms(61000);
        for (int i = 0; i < 3; i++) ntx_session_tick(x->s);
        ntx_session_trk_tick(x->s);
        ntx_session_trk_boost_peers(x->s);
        pump_announces(x, ti);
    }
    snprintf(m, sizeof m, "%s_announced_after_halt", tag);
    if (tracker_count(tr) != base) {
        printf("TAG=%s MORE=%d TRK[%s]\n", tag, tracker_count(tr) - base, tr->lines);
        fail(m);
    }

    assert_new_handshake_refused(x, ti);

    /* Removal must not add a goodbye: the one `stopped` above was the share's
     * only one (share_halt clears trk_started_ok, the fact trk_stop_one gates on). */
    base = tracker_count(tr);
    ntx_session_trk_stop_all(x->s);
    ntx_session_remove(x->s, ti);
    snprintf(m, sizeof m, "%s_second_stopped", tag);
    if (tracker_count(tr) != base) {
        printf("TAG=%s STOP2=%d TRK[%s]\n", tag, tracker_count(tr) - base, tr->lines);
        fail(m);
    }
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
    if (ntx_session_share_add(x.s, scratch_root, NULL, &e) != -1 || e != NTX_SHARE_E_IO)
        fail("add_dir_io");
    char p[256];
    snprintf(p, sizeof p, "%s/gates/empty", scratch_root);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("empty_open");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_IO) fail("add_empty_io");
    snprintf(p, sizeof p, "%s/gates/\001bad", scratch_root);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("ctl_open");
        if (write(fd, "x", 1) != 1) fail("ctl_write");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_BAD_NAME) fail("add_ctl_bad_name");
    /* R36: the basename is the name of a share, so the ONE gate
     * (ntx_share_name_ok: no byte 0x01-0x1f, no 0x7f, no '/', valid UTF-8) is
     * what decides it here — a tab and a DEL are as unusable as a \x01, and a
     * name that is not UTF-8 is unusable even though every byte of it is
     * printable. A multi-byte name is a legal name, not a rejection. */
    snprintf(p, sizeof p, "%s/gates/tab\there", scratch_root);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("tab_open");
        if (write(fd, "x", 1) != 1) fail("tab_write");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_BAD_NAME) fail("add_tab_bad_name");
    snprintf(p, sizeof p, "%s/gates/del\177file", scratch_root);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("del_open");
        if (write(fd, "x", 1) != 1) fail("del_write");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_BAD_NAME) fail("add_del_bad_name");
    snprintf(p, sizeof p, "%s/gates/bad%scoding", scratch_root, "\xc3\x28");
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("butf8_open");
        if (write(fd, "x", 1) != 1) fail("butf8_write");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) != -1 || e != NTX_SHARE_E_BAD_NAME) fail("add_badutf8_bad_name");
    snprintf(p, sizeof p, "%s/gates/\xc5\xbc\xc3\xb3\xc5\x82\xe2\x82\xac.txt", scratch_root);
    {
        int fd = open(p, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) fail("u8_open");
        if (write(fd, "x", 1) != 1) fail("u8_write");
        close(fd);
    }
    if (ntx_session_share_add(x.s, p, NULL, &e) < 0 || e != NTX_SHARE_OK) fail("add_utf8_name_ok");
    snprintf(p, sizeof p, "%s/gates/small.bin", scratch_root);
    mk_file(p, 200000, 1);
    if (ntx_session_share_add(x.s, p, NULL, &e) < 0 || e != NTX_SHARE_OK) fail("add_two_trackers");

    ntx_share_trackers_test_set(NULL, 0);
    snprintf(p, sizeof p, "%s/gates/small2.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/hash/big.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/started/f.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/rmhash/g.bin", scratch_root);
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

/* ---- case 6b (R2): the .torrent destination is prepared before hashing ----
 * docs/cli.md promises the store dir is "Created on demand" and §5.4 writes the
 * .torrent into it, so ntx_session_share_add must create it and prove it writable
 * synchronously: a destination that can never hold the file is an `io` verdict
 * before the first byte is hashed, and its text names the write, not a read. */
static void test_store_dir_on_demand(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "store");

    char p[256];
    snprintf(p, sizeof p, "%s/store/h.bin", scratch_root);
    mk_file(p, 4000, 71);

    /* (a) three levels that do not exist are created by the add itself, the last
     * one 0700 (it will hold .torrent files, which are access keys — §5.4). */
    char sd[640];
    snprintf(sd, sizeof sd, "%s/store/new/er/deep", scratch_root);
    free((void *)x.cfg.store_dir);
    x.cfg.store_dir = strdup(sd);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) {
        printf("ADD e=%s\n", ntx_share_err_code(e));
        fail("store_missing_add");
    }
    struct stat st;
    if (stat(sd, &st) != 0 || !S_ISDIR(st.st_mode)) fail("store_dir_not_created");
    if ((st.st_mode & 0777) != 0700) {
        printf("MODE=%o\n", (unsigned)(st.st_mode & 0777));
        fail("store_dir_mode");
    }
    char par[640];
    snprintf(par, sizeof par, "%s/store/new", scratch_root);
    if (stat(par, &st) != 0 || !S_ISDIR(st.st_mode)) fail("store_parent_not_created");
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("store_missing_not_hashing");
    ntx_session_remove(x.s, ti);

    /* (b) an existing store dir with no write permission is io, synchronously:
     * no slot was taken, so nothing could have started hashing. */
    char ro[640];
    snprintf(ro, sizeof ro, "%s/store/ro", scratch_root);
    if (mkdir(ro, 0500) != 0 && errno != EEXIST) fail("ro_mkdir");
    free((void *)x.cfg.store_dir);
    x.cfg.store_dir = strdup(ro);
    e = NTX_SHARE_OK;
    int rj = ntx_session_share_add(x.s, p, NULL, &e);
    if (geteuid() != 0) { /* root ignores the mode, so the gate cannot be forced there */
        if (rj != -1 || e != NTX_SHARE_E_IO) {
            printf("RJ=%d e=%s\n", rj, ntx_share_err_code(e));
            fail("store_ro_not_early_io");
        }
        const char *m = ntx_share_err_msg(NTX_SHARE_E_IO);
        if (!strstr(m, "cannot write the .torrent into") || !strstr(m, ro)) {
            printf("MSG=%s\n", m);
            fail("store_ro_msg_wording");
        }
        if (strstr(m, "cannot read the file")) fail("store_ro_blames_read");
        if (ntx_session_share_state(x.s, rj) != NTX_SHARE_NONE) fail("store_ro_took_a_slot");
    } else if (rj >= 0) {
        ntx_session_remove(x.s, rj);
    }
    if (chmod(ro, 0755) != 0) fail("ro_chmod_back");

    /* (c) the same dir made unwritable AFTER the gate: the .torrent write is what
     * fails, and its message still reads like a write into <dir>. */
    free((void *)x.cfg.store_dir);
    x.cfg.store_dir = strdup(ro);
    e = NTX_SHARE_OK;
    ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("store_writefail_add");
    if (geteuid() != 0) {
        if (chmod(ro, 0500) != 0) fail("ro_chmod_off");
        (void)pump_until_hashed(&x, ti, 2000, NULL);
        if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("store_writefail_not_failed");
        if (x.s->share[ti]->err != NTX_SHARE_E_IO) fail("store_writefail_not_io");
        const char *m = ntx_share_err_msg(NTX_SHARE_E_IO);
        if (!strstr(m, "cannot write the .torrent into") || !strstr(m, ro)) {
            printf("MSG=%s\n", m);
            fail("store_writefail_msg_wording");
        }
        if (chmod(ro, 0755) != 0) fail("ro_chmod_back2");
    }
    ntx_session_remove(x.s, ti);

    /* (d) an unrelated io failure is back to the generic reason: the destination
     * sentence never outlives the add that set it. */
    free((void *)x.cfg.store_dir);
    x.cfg.store_dir = strdup(sd);
    e = NTX_SHARE_OK;
    if (ntx_session_share_add(x.s, "test/.scratch/no-such-share-target.bin", NULL, &e) != -1 ||
        e != NTX_SHARE_E_IO || strcmp(ntx_share_err_msg(NTX_SHARE_E_IO), "cannot read the file") != 0) {
        printf("GENERIC e=%s msg=%s\n", ntx_share_err_code(e), ntx_share_err_msg(NTX_SHARE_E_IO));
        fail("stale_io_message");
    }

    sess_close(&x);
    tracker_stop(&tr);
    ok("store_dir_on_demand");
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
    snprintf(p, sizeof p, "%s/pin/h.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/revive/i.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/ratio/j.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/a4/k.bin", scratch_root);
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
    snprintf(tp, sizeof tp, "%s/a4/out.torrent", scratch_root);
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
    snprintf(tp2, sizeof tp2, "%s/a4/probe.torrent", scratch_root);
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
    snprintf(p, sizeof p, "%s/ceil/huge.bin", scratch_root);
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

    snprintf(p, sizeof p, "%s/ceil/m.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/ceil/n.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/fdheld/o.bin", scratch_root);
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
    snprintf(tmp, sizeof tmp, "%s/fdheld/o.new", scratch_root);
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
    snprintf(p, sizeof p, "%s/from/s.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/fromchg/s.bin", scratch_root);
    snprintf(cp, sizeof cp, "%s/fromchg/c.bin", scratch_root);
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
    snprintf(tp, sizeof tp, "%s/fromchg/known.torrent", scratch_root);
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
    snprintf(other, sizeof other, "%s/st_fromchg/known-00000000.torrent", scratch_root);
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
    snprintf(p, sizeof p, "%s/fromerr/s.bin", scratch_root);
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

    snprintf(tp, sizeof tp, "%s/fromerr/public.torrent", scratch_root);
    if (write_all(tp, pub, tn) != 0) fail("fromerr_write_pub");
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG) fail("fromerr_public");
    if (ntx_session_share_state(x.s, 0) != NTX_SHARE_NONE) fail("fromerr_public_slot");

    snprintf(tp, sizeof tp, "%s/fromerr/badlen.torrent", scratch_root);
    if (write_all(tp, bad, tn) != 0) fail("fromerr_write_bad");
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG) fail("fromerr_bad_len");

    snprintf(tp, sizeof tp, "%s/fromerr/junk.torrent", scratch_root);
    if (write_all(tp, (const uint8_t *)"d6:lengthi1e", 12) != 0) fail("fromerr_write_junk");
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG) fail("fromerr_junk");

    char dp[640];
    snprintf(dp, sizeof dp, "%s/fromerr", scratch_root);
    if (ntx_session_share_add(x.s, p, dp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG)
        fail("fromerr_dir");
    snprintf(tp, sizeof tp, "%s/fromerr/missing.torrent", scratch_root);
    if (ntx_session_share_add(x.s, p, tp, &e) != -1 || e != NTX_SHARE_E_BAD_ARG)
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

/* ---- S26/R35: the .torrent must be ONE exact document, no bytes after it ---
 * share_from_read hands the whole file to ntx_be_parse. A prefix parser would
 * accept `<valid document><anything>` and the share would then be published
 * under the link of the prefix while the operator believes the file is that
 * .torrent — so the reader requires that the parser consumed EVERY byte it
 * read.
 *
 * What counts as trailing garbage here is every byte ntx_be_parse does not take
 * as part of the document: bencode has no insignificant whitespace, so a
 * closing brace, a second document, a NUL, a newline, a space and a CRLF are all
 * garbage. That is stricter than the announce-response parser (which S31/R41
 * taught to skip a trailing CRLF) and the difference is deliberate: the strict
 * end-of-input of ntx_be_parse is what makes the raw info subtree that gets
 * hashed unambiguous, so a .torrent file — the thing whose hash IS the link —
 * must be byte-exact. */
static void test_from_exact_document(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fromexact");
    char p[256];
    snprintf(p, sizeof p, "%s/fromexact/s.bin", scratch_root);
    mk_file(p, 300000, 61);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data) fail("fromexact_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, 16384, 0, &tn);
    free(data);
    if (!tb) fail("fromexact_mktorrent");
    ntx_share_err e = NTX_SHARE_OK;
    pm_park(&x, NTX_PM_OFF);

    static const struct { const char *tag; const char *tail; size_t n; } tails[] = {
        { "brace", "}", 1 },            { "second", "e", 1 },
        { "nul", "\x00", 1 },           { "ctrl", "\x00\x01junk", 6 },
        { "space", " ", 1 },            { "newline", "\n", 1 },
        { "crlf", "\r\n", 2 },          { "tab", "\t", 1 },
    };
    for (size_t k = 0; k < sizeof tails / sizeof tails[0]; k++) {
        size_t tln = tn + tails[k].n;
        uint8_t *garbage = malloc(tln);
        if (!garbage) fail("fromexact_alloc");
        memcpy(garbage, tb, tn);
        memcpy(garbage + tn, tails[k].tail, tails[k].n);
        char tp[NTX_SHARE_PATH_MAX];
        snprintf(tp, sizeof tp, "%s/fromexact/%s.torrent", scratch_root, tails[k].tag);
        if (write_all(tp, garbage, tln) != 0) fail("fromexact_write");
        free(garbage);
        int ti = ntx_session_share_add(x.s, p, tp, &e);
        if (ti != -1 || e != NTX_SHARE_E_BAD_ARG) {
            printf("TAIL %s -> rc=%d err=%d\n", tails[k].tag, ti, (int)e);
            fail("fromexact_trailing_garbage");
        }
        if (ntx_session_share_state(x.s, 0) != NTX_SHARE_NONE) fail("fromexact_slot_used");
    }

    /* The same bytes without a tail are accepted — the gate above must not turn
     * a good document into a rejection. */
    char tp[NTX_SHARE_PATH_MAX];
    snprintf(tp, sizeof tp, "%s/fromexact/exact.torrent", scratch_root);
    if (write_all(tp, tb, tn) != 0) fail("fromexact_write_good");
    int ti = share_add_parked(&x, p, tp, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("fromexact_good_rejected");
    ntx_session_remove(x.s, ti);
    free(tb);
    ntx_session_share_free(x.s);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_exact_document");
}

/* ---- S26/R36: the name INSIDE a --share-from .torrent uses the same gate ---
 * The name of a from-share is the metainfo's name, and it is the string that
 * goes into the magnet's dn=, the store file's stem and the status line, so it
 * must pass the one gate the basename passes: no control character (0x01-0x1f,
 * 0x7f), no '/', valid UTF-8. A multi-byte name is legal.
 *
 * The code is the one docs/json-api.md pins for a `torrent` that does not pass
 * the re-share gate — `bad_arg` (the basename gate's NTX_SHARE_E_BAD_NAME is the
 * `path` path, and both spell "bad_arg" on the wire). */
static void test_from_name_gate(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "fromname");
    char p[256];
    snprintf(p, sizeof p, "%s/fromname/s.bin", scratch_root);
    mk_file(p, 100000, 63);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data) fail("fromname_slurp");
    ntx_share_err e = NTX_SHARE_OK;
    pm_park(&x, NTX_PM_OFF);

    static const struct { const char *tag; const char *name; } bad[] = {
        { "tab", "a\tb.bin" },        { "del", "a\x7f" "b.bin" },     { "nul_lead", "\x01" "b.bin" },
        { "bad_utf8", "\xc3\x28.bin" }, { "overlong", "\xc0\x80.bin" }, { "slash", "a/b.bin" },
        { "lone_cont", "\x80.bin" },
    };
    for (size_t k = 0; k < sizeof bad / sizeof bad[0]; k++) {
        size_t tn = 0;
        uint8_t *tb = mk_torrent_named(data, dn, 16384, 0, bad[k].name, &tn);
        if (!tb) fail("fromname_mktorrent");
        char tp[NTX_SHARE_PATH_MAX];
        snprintf(tp, sizeof tp, "%s/fromname/%s.torrent", scratch_root, bad[k].tag);
        if (write_all(tp, tb, tn) != 0) fail("fromname_write");
        free(tb);
        int ti = ntx_session_share_add(x.s, p, tp, &e);
        if (ti != -1 || e != NTX_SHARE_E_BAD_ARG) {
            printf("NAME %s -> rc=%d err=%d\n", bad[k].tag, ti, (int)e);
            fail("fromname_rejected");
        }
        if (ntx_session_share_state(x.s, 0) != NTX_SHARE_NONE) fail("fromname_slot_used");
    }
    /* the legal multi-byte name still gets through (S15: over-long is CUT, never
     * rejected, so a long-but-valid UTF-8 name must be accepted too) */
    {
        char longname[201];
        for (int i = 0; i < 200; i++) longname[i] = (i % 3 == 2) ? 'k' : 'a';
        longname[200] = 0;
        size_t tn = 0;
        uint8_t *tb = mk_torrent_named(data, dn, 16384, 0, longname, &tn);
        if (!tb) fail("fromname_mktorrent_long");
        char tp[NTX_SHARE_PATH_MAX];
        snprintf(tp, sizeof tp, "%s/fromname/long.bin", scratch_root);
        if (write_all(tp, tb, tn) != 0) fail("fromname_write_long");
        free(tb);
        int ti = share_add_parked(&x, p, tp, &e);
        if (ti < 0 || e != NTX_SHARE_OK) fail("fromname_long_rejected");
        ntx_session_remove(x.s, ti);
    }
    {
        const char *u8 = "\xc5\xbc\xc3\xb3\xc5\x82\xe2\x82\xac.bin";
        size_t tn = 0;
        uint8_t *tb = mk_torrent_named(data, dn, 16384, 0, u8, &tn);
        if (!tb) fail("fromname_mktorrent_u8");
        char tp[NTX_SHARE_PATH_MAX];
        snprintf(tp, sizeof tp, "%s/fromname/u8.bin", scratch_root);
        if (write_all(tp, tb, tn) != 0) fail("fromname_write_u8");
        free(tb);
        int ti = share_add_parked(&x, p, tp, &e);
        if (ti < 0 || e != NTX_SHARE_OK) fail("fromname_utf8_rejected");
        ntx_session_remove(x.s, ti);
    }
    free(data);
    ntx_session_share_free(x.s);
    sess_close(&x);
    tracker_stop(&tr);
    ok("from_name_gate");
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
    snprintf(p, sizeof p, "%s/fromdup/s.bin", scratch_root);
    mk_file(p, 300000, 59);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data) fail("fromdup_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, 16384, 0, &tn);
    free(data);
    if (!tb) fail("fromdup_mktorrent");
    char tp[NTX_SHARE_PATH_MAX];
    snprintf(tp, sizeof tp, "%s/fromdup/dup.torrent", scratch_root);
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
    snprintf(p, sizeof p, "%s/fromio/big.bin", scratch_root);
    mk_file(p, big, 61);
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data || dn != big) fail("fromio_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, ps, 0, &tn);
    free(data);
    if (!tb) fail("fromio_mktorrent");
    snprintf(tp, sizeof tp, "%s/fromio/big.torrent", scratch_root);
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
    snprintf(q, sizeof q, "%s/fromio/small.bin", scratch_root);
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
    snprintf(p, sizeof p, "%s/fromserve/s.bin", scratch_root);
    mk_file(p, 300000, 63);
    dn = 0;
    data = slurp(p, &dn);
    if (!data) fail("fromserve_slurp");
    tn = 0;
    tb = mk_torrent(data, dn, 16384, 0, &tn);
    free(data);
    if (!tb) fail("fromserve_mktorrent");
    snprintf(tp, sizeof tp, "%s/fromserve/s.torrent", scratch_root);
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
    /* R4: the READY event was already reported, so the failure must arrive as
     * the slot's one error event — not as silence behind `share: 2` in the stats.
     * Exactly one, carrying `changed`. */
    ntx_share_event ev3;
    memset(&ev3, 0, sizeof ev3);
    if (ntx_session_share_poll_event(y.s, &ev3) != 1) fail("fromserve_second_event");
    if (ev3.ok || ev3.err != NTX_SHARE_E_CHANGED || ev3.i != si) {
        printf("EV3 ok=%d err=%d i=%d\n", ev3.ok, (int)ev3.err, ev3.i);
        fail("fromserve_second_event_fields");
    }
    if (ntx_session_share_poll_event(y.s, &ev3) != 0) fail("fromserve_third_event");
    if (y.s->share[si]->err != NTX_SHARE_E_CHANGED) fail("fromserve_err_not_changed");
    uint64_t up_before = y.s->tts_up[si];
    /* R5 replaced the old choke-and-keep here: share_halt drops the peer instead
     * of choking it, so the connection is gone and a further request reaches a
     * dead slot — no byte may leave, and nothing may be counted as uploaded. */
    if (y.s->peers[pi].fd != -1) fail("fromserve_peer_kept_after_change");
    ntx_session_data_on_request(y.s, pi, 0, 0, 1024);
    ntx_session_peer_out_flush(y.s, pi);
    rn = recv(sv[1], rx, sizeof rx, MSG_DONTWAIT);
    {
        if (rn > 0) { /* the peer end was closed by the halt: EOF, never a message */
            printf("POST rn=%zd id=%d up=%llu\n", rn, rn > 4 ? rx[4] : -1,
                   (unsigned long long)y.s->tts_up[si]);
            fail("fromserve_served_after_change");
        }
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

    snprintf(p, sizeof p, "%s/frompread/g.bin", scratch_root);
    mk_file(p, 40000, 64); /* 3 pieces: 16384 + 16384 + 7232 */
    size_t dn = 0;
    uint8_t *data = slurp(p, &dn);
    if (!data || dn != 40000) fail("frompread_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent(data, dn, ps, 0, &tn);
    free(data);
    if (!tb) fail("frompread_mktorrent");
    snprintf(tp, sizeof tp, "%s/frompread/g.torrent", scratch_root);
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
    { /* R5 replaced the old refuse-only answer here: data_serve hooks
       * ntx_session_share_io_failed BEFORE the refuse, so share_halt has already
       * dropped this peer and neither a piece nor a reject can reach the wire. */
        if (rn > 0) {
            printf("IO rn=%zd id=%d\n", rn, rn > 4 ? rx[4] : -1);
            fail("frompread_answered_after_halt");
        }
    }
    if (z.s->tts_up[si] != up_before) fail("frompread_up_counted");
    if (ntx_session_share_state(z.s, si) != NTX_SHARE_FAILED) fail("frompread_not_failed");
    if (z.s->share[si]->err != NTX_SHARE_E_IO)
        fail("frompread_err_not_io");
    if (ntx_session_share_serving(z.s, si) != 0) fail("frompread_still_serving");
    if (z.s->peers[pi].fd != -1) fail("frompread_peer_kept_after_io");
    /* R4: one READY event, then exactly one error event with `code io` — the
     * queue is not full here, so nothing may delay it. */
    ntx_share_event ev1;
    memset(&ev1, 0, sizeof ev1);
    if (ntx_session_share_poll_event(z.s, &ev1) != 1) fail("frompread_second_event");
    if (ev1.ok || ev1.err != NTX_SHARE_E_IO || ev1.i != si) {
        printf("EV1 ok=%d err=%d i=%d\n", ev1.ok, (int)ev1.err, ev1.i);
        fail("frompread_second_event_fields");
    }
    if (ntx_session_share_poll_event(z.s, &ev1) != 0) fail("frompread_third_event");

    close(sv[0]);
    close(sv[1]);
    z.s->peers[pi].fd = -1;
    z.s->peer_tts[pi] = -1;
    ntx_session_remove(z.s, si);
    sess_close(&z);
    tracker_stop(&tr);
    ok("from_serve_read_io");
}

/* R3: nothing may be published for a file that was edited while it was being
 * hashed. The store dir of the session must stay empty and the one event the
 * share gets must carry no magnet. `stem` is the .torrent's expected prefix. */
static void assert_nothing_published(sess *x, int ti, const char *stem, const char *tag) {
    char m[64];
    snprintf(m, sizeof m, "%s_serving_after_fail", tag);
    if (ntx_session_share_serving(x->s, ti) != 0) fail(m);
    snprintf(m, sizeof m, "%s_magnet_produced", tag);
    if (x->s->share[ti]->magnet[0]) fail(m);
    snprintf(m, sizeof m, "%s_torrent_left", tag);
    DIR *d = opendir(x->cfg.store_dir);
    if (!d) fail("opendir_store");
    struct dirent *de;
    while ((de = readdir(d)))
        if (strncmp(de->d_name, stem, strlen(stem)) == 0) {
            closedir(d);
            printf("LEFT[%s]\n", de->d_name);
            fail(m);
        }
    closedir(d);
    ntx_share_event ev;
    memset(&ev, 0, sizeof ev);
    snprintf(m, sizeof m, "%s_no_event", tag);
    if (ntx_session_share_poll_event(x->s, &ev) != 1) fail(m);
    snprintf(m, sizeof m, "%s_event_fields", tag);
    if (ev.ok || ev.err != NTX_SHARE_E_CHANGED || ev.magnet[0] || ev.torrent_path[0]) {
        printf("EV ok=%d code=%s magnet=%d path=%d\n", ev.ok, ntx_share_err_code(ev.err),
               (int)!!ev.magnet[0], (int)!!ev.torrent_path[0]);
        fail(m);
    }
    snprintf(m, sizeof m, "%s_two_events", tag);
    if (ntx_session_share_poll_event(x->s, &ev) != 0) fail(m);
}

/* ---- R3 case a: one byte rewritten MID-HASH (same size) → CHANGED ----
 * §5.3/§5.5: the snapshot the change check compares against has to be the one
 * taken when the descriptor was opened. Taken after the hash — as it was — every
 * edit made DURING hashing is invisible, and the .torrent plus the magnet then
 * describe bytes that no longer exist on disk. The byte lands far behind the
 * pump, so the hash the share publishes is the one from before the edit. */
static void test_edit_during_hash(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "during");
    char p[256];
    snprintf(p, sizeof p, "%s/during/e.bin", scratch_root);
    mk_file(p, (uint64_t)32 << 20, 73);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("during_add");
    for (int i = 0; i < 3; i++) ntx_session_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("during_hashed_too_fast");
    {
        int fd = open(p, O_WRONLY); /* the share's own fd is O_RDONLY */
        if (fd < 0) fail("during_edit_open");
        uint8_t one = 0x5A;
        if (pwrite(fd, &one, 1, ((uint64_t)16 << 20) + 7) != 1) fail("during_edit_pwrite");
        close(fd);
    }
    (void)pump_until_hashed(&x, ti, 6000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) {
        printf("ST=%d (want FAILED)\n", (int)ntx_session_share_state(x.s, ti));
        fail("during_edit_not_failed");
    }
    if (x.s->share[ti]->err != NTX_SHARE_E_CHANGED) {
        printf("CODE=%s (want changed)\n", ntx_share_err_code(x.s->share[ti]->err));
        fail("during_edit_not_changed");
    }
    assert_nothing_published(&x, ti, "e.bin", "during_edit");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("edit_during_hash_is_changed");
}

/* ---- R3 case b: the file is SHORTENED mid-hash → CHANGED, never IO ----
 * A pread that comes back 0 while hashing means the file lost bytes underneath
 * us: that is the same `changed` verdict as an in-place edit, not an I/O error. */
static void test_trunc_during_hash(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "durtrunc");
    char p[256];
    snprintf(p, sizeof p, "%s/durtrunc/t.bin", scratch_root);
    mk_file(p, (uint64_t)32 << 20, 74);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("durtrunc_add");
    for (int i = 0; i < 3; i++) ntx_session_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("durtrunc_hashed_too_fast");
    if (trunc_to(p, (off_t)(9 << 20)) != 0) fail("durtrunc_ftruncate");
    (void)pump_until_hashed(&x, ti, 6000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) {
        printf("ST=%d (want FAILED)\n", (int)ntx_session_share_state(x.s, ti));
        fail("durtrunc_not_failed");
    }
    if (x.s->share[ti]->err != NTX_SHARE_E_CHANGED) {
        printf("CODE=%s (want changed, not io)\n", ntx_share_err_code(x.s->share[ti]->err));
        fail("durtrunc_not_changed");
    }
    assert_nothing_published(&x, ti, "t.bin", "durtrunc");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("truncate_during_hash_is_changed");
}

/* ---- R7: a share that failed AFTER its metainfo was published ----
 * share_finish fills the slot through ntx_torrent_init_meta (state META, real
 * info-hash, np/have set) and only then discovers that the .torrent cannot be
 * written. share_fail parked the share in FAILED, but left the torrent slot
 * looking like a live seed: stats said phase "trk-wait" with the real `ih`,
 * ntx_session_trk_tick would announce it as soon as an announce was scheduled,
 * and ntx_session_trk_stop_all sent `stopped` with the real hash for a share
 * that had never sent `started`. The .torrent write is forced to fail by moving
 * the store dir away after the synchronous gate proved it writable (works for
 * root too, unlike the 0500 trick of case 6b). */
static void test_failed_share_is_dead(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "r7dead");
    char p[256];
    snprintf(p, sizeof p, "%s/r7dead/f.bin", scratch_root);
    mk_file(p, 4000, 91);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = ntx_session_share_add(x.s, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("r7dead_add");
    pm_park(&x, NTX_PM_OFF);
    /* sess_close frees cfg.store_dir, so the path is kept here for the rename back. */
    char sd[640], gone[768];
    snprintf(sd, sizeof sd, "%s", x.cfg.store_dir);
    snprintf(gone, sizeof gone, "%.600s.gone", sd);
    (void)rmdir(gone); /* a leftover from a killed run is not a verdict */
    if (rename(sd, gone) != 0) fail("r7dead_store_rename");
    (void)pump_until_hashed(&x, ti, 2000, NULL);

    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) {
        printf("ST=%d (want FAILED)\n", (int)ntx_session_share_state(x.s, ti));
        fail("r7dead_not_failed");
    }
    if (x.s->share[ti]->err != NTX_SHARE_E_IO) {
        printf("CODE=%s (want io)\n", ntx_share_err_code(x.s->share[ti]->err));
        fail("r7dead_not_io");
    }
    if (ntx_session_share_serving(x.s, ti) != 0) fail("r7dead_still_serving");

    /* (1) the UI must not see a live torrent: share 2, phase fail, zeroed ih. */
    ntx_session_stats_refresh(x.s, 0);
    ntx_stats st;
    ntx_session_snapshot(x.s, &st);
    if (st.n != 1) fail("r7dead_stats_n");
    if (st.t[ti].share != 2) fail("r7dead_stats_share");
    if (strcmp(st.t[ti].phase, "fail") != 0) {
        printf("PHASE=%s (want fail)\n", st.t[ti].phase);
        fail("r7dead_phase_not_fail");
    }
    static const uint8_t zeros[20];
    if (memcmp(st.t[ti].h, zeros, 20) != 0) {
        printf("IH=%02x%02x%02x%02x... (want 40 zeros)\n", st.t[ti].h[0], st.t[ti].h[1],
               st.t[ti].h[2], st.t[ti].h[3]);
        fail("r7dead_ih_not_zero");
    }
    /* the slot itself keeps the real hash: the gate is in the stats output, not
     * in the data the rest of the session reads. */
    if (memcmp(x.s->tts[ti].info_hash, zeros, 20) == 0) fail("r7dead_slot_hash_zeroed");
    /* S04's predicate still refuses to resolve the dead slot by its real hash. */
    if (sp_match_tts(x.s, x.s->tts[ti].info_hash) >= 0) fail("r7dead_still_matchable");

    /* (2) a scheduled announce must not go out, neither from the periodic tick
     * nor from the peer-boost path. The three sub-sessions share this tracker, so
     * every check compares against the count the tracker already holds. */
    int base = tracker_count(&tr);
    x.s->trk_next[ti] = 1; /* as if one had been scheduled before the failure */
    for (int i = 0; i < 60; i++) ntx_session_tick(x.s);
    ntx_session_trk_tick(x.s);
    ntx_session_trk_boost_peers(x.s);
    pump_announces(&x, ti);
    if (tracker_count(&tr) != base) {
        printf("REQS=%d PHASE=%s\n", tracker_count(&tr) - base, st.t[ti].phase);
        printf("TRK[%s]\n", tr.lines);
        fail("r7dead_announced_after_fail");
    }

    /* (3) teardown sends no goodbye for a share that never sent `started`. */
    base = tracker_count(&tr);
    ntx_session_trk_stop_all(x.s);
    if (tracker_count(&tr) != base) {
        printf("STOPREQS=%d TRK[%s]\n", tracker_count(&tr) - base, tr.lines);
        fail("r7dead_stopped_without_started");
    }
    printf("PASS r7dead_failed_share_quiet (phase=%s)\n", st.t[ti].phase);

    /* (4) regression guard: while a share merely HASHES, nothing is announced
     * either (the happy path of cases 2..5 stays untouched). */
    sess y;
    sess_open(&y, "r7hash");
    snprintf(p, sizeof p, "%s/r7hash/g.bin", scratch_root);
    mk_file(p, (uint64_t)32 << 20, 92);
    e = NTX_SHARE_OK;
    int hi = ntx_session_share_add(y.s, p, NULL, &e);
    if (hi < 0) fail("r7hash_add");
    pm_park(&y, NTX_PM_OFF);
    for (int i = 0; i < 3; i++) ntx_session_tick(y.s);
    if (ntx_session_share_state(y.s, hi) != NTX_SHARE_HASHING) fail("r7hash_not_hashing");
    ntx_session_stats_refresh(y.s, 0);
    ntx_session_snapshot(y.s, &st);
    if (st.t[hi].share != 1 || strcmp(st.t[hi].phase, "hash") != 0) {
        printf("HASH share=%u phase=%s\n", (unsigned)st.t[hi].share, st.t[hi].phase);
        fail("r7hash_phase");
    }
    base = tracker_count(&tr);
    y.s->trk_next[hi] = 1;
    for (int i = 0; i < 3; i++) ntx_session_tick(y.s);
    ntx_session_trk_tick(y.s);
    ntx_session_trk_boost_peers(y.s);
    pump_announces(&y, hi);
    if (tracker_count(&tr) != base) {
        printf("HASHREQS=%d TRK[%s]\n", tracker_count(&tr) - base, tr.lines);
        fail("r7hash_announced_while_hashing");
    }
    for (int k = 0; k < NTX_SESSION_MAX_TRK; k++)
        if (y.s->trk_http_pending[hi][k] || y.s->trk_udp_pending[hi][k])
            fail("r7hash_announce_queued_while_hashing");
    if (ntx_session_share_state(y.s, hi) != NTX_SHARE_HASHING) fail("r7hash_promoted_by_the_tick");
    ntx_session_remove(y.s, hi);
    sess_close(&y);

    /* (5) `started` held back for the port map (§5.5) and then a failure: the
     * goodbye of ntx_session_trk_stop must stay in too — nothing was announced. */
    sess z;
    sess_open(&z, "r7pend");
    snprintf(p, sizeof p, "%s/r7pend/h.bin", scratch_root);
    mk_file(p, 60000, 93);
    e = NTX_SHARE_OK;
    int pi = ntx_session_share_add(z.s, p, NULL, &e);
    if (pi < 0) fail("r7pend_add");
    pm_park(&z, NTX_PM_PENDING);
    (void)pump_until_hashed(&z, pi, 2000, NULL);
    if (ntx_session_share_state(z.s, pi) != NTX_SHARE_ANNOUNCING) fail("r7pend_not_announcing");
    if (!z.s->pm || ntx_session_portmap_state(z.s) != NTX_PM_PENDING) fail("r7pend_pm");
    for (int i = 0; i < 5; i++) {
        ntx_session_tick(z.s);
        pump_announces(&z, pi);
    }
    base = tracker_count(&tr);
    if (tracker_count(&tr) != base) fail("r7pend_announced_while_pending");
    {
        int fd = open(p, O_WRONLY);
        if (fd < 0) fail("r7pend_edit_open");
        uint8_t one = 0x77;
        if (pwrite(fd, &one, 1, 10) != 1) fail("r7pend_edit_pwrite");
        close(fd);
    }
    ntx_share_test_advance_ms(1500);
    ntx_session_share_tick(z.s);
    if (ntx_session_share_state(z.s, pi) != NTX_SHARE_FAILED) fail("r7pend_not_failed");
    if (tracker_count(&tr) != base) {
        printf("PENDREQS=%d TRK[%s]\n", tracker_count(&tr) - base, tr.lines);
        fail("r7pend_stopped_without_started");
    }
    ntx_session_trk_stop_all(z.s);
    if (tracker_count(&tr) != base) {
        printf("PENDSTOP=%d TRK[%s]\n", tracker_count(&tr) - base, tr.lines);
        fail("r7pend_stop_all_stopped_without_started");
    }
    ntx_session_remove(z.s, pi);
    sess_close(&z);

    sess_close(&x);
    if (rename(gone, sd) != 0) fail("r7dead_store_rename_back");
    tracker_stop(&tr);
    ok("failed_share_is_dead");
}

/* ---- R5 a: a READY share whose file CHANGES on disk ----
 * share_changed used to park the slot in FAILED and send a `stopped` while the
 * announce schedule stayed armed, its peers stayed promoted and a new handshake
 * naming the real hash was still answered. The halt must be one coherent act. */
static void test_halt_after_change(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "r5chg");
    char p[256];
    snprintf(p, sizeof p, "%s/r5chg/c.bin", scratch_root);
    mk_file(p, 300000, 95);

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("r5chg_add");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (!pump_to_ready(&x, ti)) fail("r5chg_not_ready");
    ntx_share_event ev;
    if (ntx_session_share_poll_event(x.s, &ev) != 1 || !ev.ok) fail("r5chg_ready_event");
    if (x.s->trk_started_ok[ti] != 1) fail("r5chg_no_started");
    if (ntx_session_share_serving(x.s, ti) != 1) fail("r5chg_not_serving");

    int cli = -1;
    int pi = r5_attach_peer(&x, ti, &cli);

    int pre = tracker_count(&tr);
    { /* the byte edit of the §5.5 gate: same size, different bytes */
        int fd = open(p, O_WRONLY);
        if (fd < 0) fail("r5chg_edit_open");
        uint8_t one = 0xA5;
        if (pwrite(fd, &one, 1, 7) != 1) fail("r5chg_edit_pwrite");
        close(fd);
    }
    ntx_share_test_advance_ms(1500); /* past the 1 s fstat interval */
    ntx_session_share_tick(x.s);
    assert_halted(&x, ti, &tr, pre, pi, "r5chg");
    close(cli);
    sess_close(&x);
    tracker_stop(&tr);
    ok("halt_after_change");
}

/* ---- R5 b: the same after a read that fails while serving ----
 * The short pread seam of the frompread case: the last piece disappears under a
 * serving share, data_serve refuses the block and calls
 * ntx_session_share_io_failed. Pre-fix that hook only parked the share in
 * FAILED/IO — no `stopped` at all, no peer drop, handshakes still answered. */
static void test_halt_after_io(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "r5io");
    char p[256];
    snprintf(p, sizeof p, "%s/r5io/d.bin", scratch_root);
    mk_file(p, 40000, 96); /* 3 pieces: 16384 + 16384 + 7232 */

    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("r5io_add");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (!pump_to_ready(&x, ti)) fail("r5io_not_ready");
    ntx_share_event ev;
    if (ntx_session_share_poll_event(x.s, &ev) != 1 || !ev.ok) fail("r5io_ready_event");
    if (x.s->trk_started_ok[ti] != 1) fail("r5io_no_started");

    int cli = -1;
    int pi = r5_attach_peer(&x, ti, &cli);
    x.s->share[ti]->fstat_at = UINT64_MAX; /* only the read may fail the share */

    int pre = tracker_count(&tr);
    if (trunc_to(p, 20000) != 0) fail("r5io_ftruncate"); /* abs of piece 2 is past EOF */
    ntx_session_data_on_request(x.s, pi, 2, 0, 1024);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("r5io_not_failed");
    if (x.s->share[ti]->err != NTX_SHARE_E_IO) fail("r5io_err_not_io");
    assert_halted(&x, ti, &tr, pre, pi, "r5io");
    close(cli);
    sess_close(&x);
    tracker_stop(&tr);
    ok("halt_after_io");
}

/* =================== R4: the error that FOLLOWS a ready event ==============
 * share_evq_push used to lock a slot after its FIRST event (sl->ev_full), so a
 * share that reached READY and later died of `changed` (§5.5) or of a failed
 * read while serving (§5.6.1) pushed an error event that was never queued: the
 * CLI kept running as if all was well (docs/cli.md promises `ntx: share failed:
 * <reason>` and exit 1) and the JSON consumer never saw {"ok":0}. */

/* ---- R4 a: READY -> changed, and READY -> io: exactly one error event ---- */
static void test_error_after_ready(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "r4evt");
    char p[256];
    ntx_share_err e = NTX_SHARE_OK;
    ntx_share_event ev;

    /* (1) READY, then a byte edited under the held fd: the one error event the
     * share gets must be the CHANGED one, drained after the READY event. */
    snprintf(p, sizeof p, "%s/r4evt/a.bin", scratch_root);
    mk_file(p, 60000, 121);
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) fail("r4evt_add");
    (void)pump_until_hashed(&x, ti, 2000, NULL);
    if (!pump_to_ready(&x, ti)) fail("r4evt_not_ready");
    if (ntx_session_share_poll_event(x.s, &ev) != 1 || !ev.ok || ev.i != ti) fail("r4evt_ready_event");

    {
        int fd = open(p, O_WRONLY);
        if (fd < 0) fail("r4evt_edit_open");
        uint8_t one = 0xA5;
        if (pwrite(fd, &one, 1, 7) != 1) fail("r4evt_edit_pwrite");
        close(fd);
    }
    ntx_share_test_advance_ms(1500); /* past the 1 s fstat interval (§5.5) */
    ntx_session_share_tick(x.s);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("r4evt_not_failed");
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("r4evt_changed_no_error_event");
    if (ev.ok || ev.err != NTX_SHARE_E_CHANGED || ev.i != ti) {
        printf("EV ok=%d err=%d i=%d\n", ev.ok, (int)ev.err, ev.i);
        fail("r4evt_error_fields");
    }
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("r4evt_third_event");
    ntx_session_remove(x.s, ti);

    /* (2) READY, then a pread that fails *while serving* (§5.6.1): the same
     * contract with the code `io`. The 1 s fstat is disarmed so the read is the
     * only thing that can fail the share. */
    snprintf(p, sizeof p, "%s/r4evt/b.bin", scratch_root);
    mk_file(p, 40000, 122); /* 3 pieces: 16384 + 16384 + 7232 */
    int tj = share_add_parked(&x, p, NULL, &e);
    if (tj < 0 || e != NTX_SHARE_OK) fail("r4evt_io_add");
    (void)pump_until_hashed(&x, tj, 2000, NULL);
    if (!pump_to_ready(&x, tj)) fail("r4evt_io_not_ready");
    if (ntx_session_share_poll_event(x.s, &ev) != 1 || !ev.ok || ev.i != tj) fail("r4evt_io_ready_event");

    int sv[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0) fail("r4evt_socketpair");
    ntx_addr pa;
    ntx_addr_set_v4(&pa, htonl(0x7f000001));
    int pi = ntx_session_peer_alloc(x.s, sv[0], &pa, 6881, tj);
    if (pi < 0) fail("r4evt_peer_alloc");
    x.s->peer_phase[pi] = PH_OK;
    x.s->peer_plain[pi] = 1;
    x.s->peer_hello_sent[pi] = 1;
    x.s->peer_fast[pi] = 1;
    ntx_peer_set_we_choke(&x.s->peers[pi], 0);
    ntx_peer_set_int_us(&x.s->peers[pi], 1);
    x.s->share[tj]->fstat_at = UINT64_MAX; /* only the read may fail the share */
    if (trunc_to(p, 20000) != 0) fail("r4evt_trunc"); /* abs of piece 2 is past EOF */
    ntx_session_data_on_request(x.s, pi, 2, 0, 1024);
    if (ntx_session_share_state(x.s, tj) != NTX_SHARE_FAILED) fail("r4evt_io_not_failed");
    if (x.s->share[tj]->err != NTX_SHARE_E_IO) fail("r4evt_io_err_not_io");
    memset(&ev, 0, sizeof ev);
    if (ntx_session_share_poll_event(x.s, &ev) != 1) fail("r4evt_io_no_error_event");
    if (ev.ok || ev.err != NTX_SHARE_E_IO || ev.i != tj) {
        printf("EVio ok=%d err=%d i=%d\n", ev.ok, (int)ev.err, ev.i);
        fail("r4evt_io_error_fields");
    }
    if (ntx_session_share_poll_event(x.s, &ev) != 0) fail("r4evt_io_third_event");

    close(sv[0]);
    close(sv[1]);
    x.s->peers[pi].fd = -1;
    x.s->peer_tts[pi] = -1;
    ntx_session_remove(x.s, tj);
    sess_close(&x);
    tracker_stop(&tr);
    ok("error_after_ready");
}

/* ---- R4 b: a full queue delays an event, it never drops one ----
 * share_evq is NTX_SESSION_MAX_TTS * 2 deep and the old push set ev_full even
 * when the loop found no room, so a discarded event was gone forever. Three
 * shares reach READY, the queue is then stuffed to its capacity with OTHER
 * shares' events, and only now is one of them failed: the error event cannot be
 * placed, and must still come out after the queue drains. */
static void test_evq_full_delays(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "r4qa");
    char p[256];
    int ti[3] = {-1, -1, -1};
    ntx_share_err e = NTX_SHARE_OK;

    for (int k = 0; k < 3; k++) {
        snprintf(p, sizeof p, "%s/r4qa/p%d.bin", scratch_root, k);
        mk_file(p, 40000, (uint8_t)(131 + k));
        ti[k] = share_add_parked(&x, p, NULL, &e);
        if (ti[k] < 0 || e != NTX_SHARE_OK) fail("r4q_add");
        (void)pump_until_hashed(&x, ti[k], 2000, NULL);
        if (!pump_to_ready(&x, ti[k])) fail("r4q_not_ready");
    }

    /* Keep the three real READY events, then take every remaining entry for the
     * backlog of another share: the array only holds (owner, event) pairs, so a
     * copy of a queued event is exactly what a full queue looks like to a push. */
    size_t cap = sizeof share_evq / sizeof share_evq[0];
    share_evt real[3];
    size_t n = 0;
    for (size_t i = 0; i < cap; i++)
        if (share_evq[i].owner && n < 3) real[n++] = share_evq[i];
    if (n != 3) fail("r4q_three_ready_events");
    for (size_t i = 0; i < cap; i++) share_evq[i].owner = NULL;
    for (size_t i = 0; i < 3; i++) share_evq[i] = real[i]; /* A, B, C first */
    for (size_t i = 3; i < cap; i++) {
        share_evq[i].owner = share_evq[1].owner;
        share_evq[i].ev = share_evq[1].ev;
    }

    /* A's file changes while the queue is full: the push must be refused and the
     * event kept pending, not spent. */
    snprintf(p, sizeof p, "%s/r4qa/p0.bin", scratch_root);
    {
        int fd = open(p, O_WRONLY);
        if (fd < 0) fail("r4q_edit_open");
        uint8_t one = 0x5A;
        if (pwrite(fd, &one, 1, 11) != 1) fail("r4q_edit_pwrite");
        close(fd);
    }
    ntx_share_test_advance_ms(1500);
    ntx_session_share_tick(x.s);
    if (ntx_session_share_state(x.s, ti[0]) != NTX_SHARE_FAILED) fail("r4q_not_failed");
    for (size_t i = 0; i < cap; i++)
        if (share_evq[i].owner == x.s->share[ti[0]] && !share_evq[i].ev.ok)
            fail("r4q_queued_while_full");

    /* Drain everything; the pending error has to survive to the next attempt. */
    int seen_ready = 0, got_err = 0, spins = 0;
    for (int i = 0; i < 400 && !got_err; i++) {
        ntx_share_event ev;
        if (ntx_session_share_poll_event(x.s, &ev)) {
            if (ev.i != ti[0]) continue; /* the other shares' backlog */
            if (ev.ok) seen_ready = 1;
            else if (ev.err == NTX_SHARE_E_CHANGED) got_err = 1;
            continue;
        }
        if (++spins > 60) break; /* no event and no progress: the queue is empty */
        ntx_session_share_tick(x.s);
    }
    if (!seen_ready) fail("r4q_ready_lost");
    if (!got_err) fail("r4q_error_event_lost");
    for (int k = 0; k < 3; k++) ntx_session_remove(x.s, ti[k]);
    sess_close(&x);
    tracker_stop(&tr);
    ok("evq_full_delays");
}

/* ---- R27 (§9): the two `exists` verdicts are two different facts ----------
 * ONE text covered both a .torrent that is already on disk under the destination
 * name and the same info hash already live in another slot. Spec §9 wants the
 * .torrent case to name the FILE and the slot case to name the SHARE that owns
 * it; the wire code stays `exists` for both (§11 pins it). The two cases are
 * driven apart here by what each one can see: (a) names the destination path and
 * nothing else, (b) names the other share. Pre-fix both answer the identical
 * string "this file is already shared", which is what the two *_still_generic
 * checks below catch. */
static void test_exists_two_messages(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);

    /* (a) the .torrent could not reach disk because something that is not this
     * hash sits at the destination. The destination is <store>/<name>-<8 hex of
     * ih>.torrent and ih covers the salt, so the salt is pinned (see the
     * test_rand_bytes override above) — that is what lets the file be planted
     * where the share is about to write it. */
    sess x;
    sess_open(&x, "exdisk");
    char p[256];
    snprintf(p, sizeof p, "%s/exdisk/h.bin", scratch_root);
    mk_file(p, 200000, 91);
    ntx_share_err e = NTX_SHARE_OK;
    g_fixed_salt = 1;
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) {
        printf("ADD e=%s\n", ntx_share_err_code(e));
        fail("exdisk_add");
    }
    (void)pump_until_hashed(&x, ti, 8000, NULL);
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_ANNOUNCING &&
        ntx_session_share_state(x.s, ti) != NTX_SHARE_READY)
        fail("exdisk_first_not_hashed");
    char tp[NTX_SHARE_PATH_MAX];
    if (ntx_share_torrent_path(tp, sizeof tp, x.cfg.store_dir, "h.bin",
                              x.s->tts[ti].info_hash) != 0)
        fail("exdisk_path_build");
    { /* the file really was written under exactly that name */
        struct stat st;
        if (stat(tp, &st) != 0) { printf("TP=%s\n", tp); fail("exdisk_first_write"); }
    }
    ntx_session_remove(x.s, ti);
    { /* a foreign file at the destination: not bencode, so never ours to replace */
        int fd = open(tp, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        if (fd < 0) fail("exdisk_plant_open");
        if (write(fd, "not bencode at all", 18) != 18) fail("exdisk_plant_write");
        close(fd);
    }
    e = NTX_SHARE_OK;
    ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) {
        printf("ADD2 e=%s\n", ntx_share_err_code(e));
        fail("exdisk_add_second");
    }
    (void)pump_until_hashed(&x, ti, 8000, NULL);
    g_fixed_salt = 0;
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_FAILED) fail("exdisk_not_failed");
    if (x.s->share[ti]->err != NTX_SHARE_E_EXISTS) {
        printf("ERR=%s\n", ntx_share_err_code(x.s->share[ti]->err));
        fail("exdisk_not_exists");
    }
    {
        const char *m = ntx_share_err_msg(NTX_SHARE_E_EXISTS);
        printf("EXDISK msg=[%s]\n", m);
        if (strcmp(ntx_share_err_code(NTX_SHARE_E_EXISTS), "exists") != 0) fail("exdisk_code");
        if (strcmp(m, "this file is already shared") == 0) fail("exdisk_still_generic");
        if (!strstr(m, tp)) fail("exdisk_names_the_file");
    }
    ntx_session_remove(x.s, ti);
    unlink(tp);
    sess_close(&x);

    /* (b) the same info hash is already shared from another slot: the text names
     * the OTHER share and never blames a file. Two --share-from attempts of one
     * .torrent is the only way to get two slots with one hash — a plain --share
     * salts its info, so its hash is never reproducible. */
    sess_open(&x, "exslot");
    char sp[256];
    snprintf(sp, sizeof sp, "%s/exslot/s.bin", scratch_root);
    mk_file(sp, 300000, 92);
    size_t dn = 0;
    uint8_t *data = slurp(sp, &dn);
    if (!data) fail("exslot_slurp");
    size_t tn = 0;
    uint8_t *tb = mk_torrent_named(data, dn, 16384, 0, "Uniq.Dup.Alpha.torrent", &tn);
    free(data);
    if (!tb) fail("exslot_mktorrent");
    char fjp[NTX_SHARE_PATH_MAX];
    snprintf(fjp, sizeof fjp, "%s/exslot/dup.torrent", scratch_root);
    if (write_all(fjp, tb, tn) != 0) fail("exslot_write");
    free(tb);

    e = NTX_SHARE_OK;
    int sai = share_add_parked(&x, sp, fjp, &e);
    if (sai < 0 || e != NTX_SHARE_OK) fail("exslot_add_first");
    (void)pump_until_hashed(&x, sai, 2000, NULL);
    if (!pump_to_ready(&x, sai)) fail("exslot_first_not_ready");

    int sbi = share_add_parked(&x, sp, fjp, &e);
    if (sbi < 0 || e != NTX_SHARE_OK) fail("exslot_add_second");
    (void)pump_until_hashed(&x, sbi, 2000, NULL);
    if (ntx_session_share_state(x.s, sbi) != NTX_SHARE_FAILED) fail("exslot_second_not_failed");
    if (x.s->share[sbi]->err != NTX_SHARE_E_EXISTS) fail("exslot_second_not_exists");
    {
        const char *m = ntx_share_err_msg(NTX_SHARE_E_EXISTS);
        printf("EXSLOT msg=[%s]\n", m);
        if (strcmp(ntx_share_err_code(NTX_SHARE_E_EXISTS), "exists") != 0) fail("exslot_code");
        if (strcmp(m, "this file is already shared") == 0) fail("exslot_still_generic");
        if (!strstr(m, "Uniq.Dup.Alpha.torrent")) fail("exslot_names_the_share");
        if (strstr(m, fjp)) fail("exslot_blames_a_file");
    }
    if (ntx_session_share_state(x.s, sai) != NTX_SHARE_READY) fail("exslot_first_broken");
    ntx_session_remove(x.s, sai);
    ntx_session_remove(x.s, sbi);
    sess_close(&x);
    tracker_stop(&tr);

    /* (c) neither sentence outlives the share that set it. */
    {
        const char *m = ntx_share_err_msg(NTX_SHARE_E_CHANGED);
        if (strcmp(m, "the file changed while sharing") != 0) {
            printf("GENERIC=[%s]\n", m);
            fail("exists_stale_sentence");
        }
    }
    ok("exists_two_messages");
}

/* ---- R28: the name of a share is known long before its hash is ------------
 * Ctrl-C during the hash phase built the summary row out of metainfo that never
 * arrived, so it read `stopped — (torrent) (metadata not fetched, phase hash)`.
 * The row is built from the stats name, so the stats row of a HASHING share has
 * to carry the share's own name — the basename, which ntx_session_share_add
 * knows the moment it opens the file (§5.3: only the HASH is unknown then). */
static void test_hash_row_carries_the_name(void) {
    scratch();
    tracker tr;
    memset(&tr, 0, sizeof tr);
    tracker_start(&tr);
    set_test_trackers(&tr, 2);
    sess x;
    sess_open(&x, "r28name");
    char p[256];
    snprintf(p, sizeof p, "%s/r28name/Stopping.Name.bin", scratch_root);
    mk_file(p, 8u * 1024u * 1024u, 93);
    ntx_share_err e = NTX_SHARE_OK;
    int ti = share_add_parked(&x, p, NULL, &e);
    if (ti < 0 || e != NTX_SHARE_OK) {
        printf("ADD e=%s\n", ntx_share_err_code(e));
        fail("r28_add");
    }
    if (ntx_session_share_state(x.s, ti) != NTX_SHARE_HASHING) fail("r28_not_hashing");
    ntx_session_stats_refresh(x.s, 0);
    ntx_stats st;
    ntx_session_snapshot(x.s, &st);
    printf("R28 n=%d phase=[%s] name=[%s]\n", st.n, st.t[0].phase, st.t[0].name);
    if (st.n != 1) fail("r28_stats_n");
    if (strcmp(st.t[0].phase, "hash") != 0) fail("r28_not_hash_phase");
    if (strcmp(st.t[0].name, "Stopping.Name.bin") != 0) fail("r28_hash_row_has_name");
    ntx_session_remove(x.s, ti);
    sess_close(&x);
    tracker_stop(&tr);
    ok("hash_row_carries_the_name");
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    scratch_root_init();
    ntx_rng_init();
    scratch();
    test_add_gates();
    test_hash_and_results();
    test_started_and_magnet();
    test_silent_gateway_settles();
    test_silent_gateway_gives_up();
    test_lost_renewal_reannounces();
    test_remove_during_hash();
    test_store_dir_on_demand();
    test_pin_fail();
    test_revival();
    test_ratio_exempt();
    test_a3_to_a4_round_trip();
    test_ceiling_and_changed();
    test_fd_held_and_ro();
    test_from_same_link();
    test_from_changed();
    test_from_bad_arg();
    test_from_exact_document();
    test_from_name_gate();
    test_from_duplicate();
    test_from_truncated();
    test_from_serve_io();
    test_edit_during_hash();
    test_trunc_during_hash();
    test_failed_share_is_dead();
    test_halt_after_change();
    test_halt_after_io();
    test_error_after_ready();
    test_evq_full_delays();
    test_exists_two_messages();
    test_hash_row_carries_the_name();
    ntx_share_trackers_test_set(NULL, -1);
    printf("ALL PASS\n");
    return 0;
}
