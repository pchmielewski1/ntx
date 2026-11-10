/* Task A4 (§5.4): magnet builder, atomic 0600 .torrent writer and the name
 * checks. This is Review Focus 1's test: a name with '&', '%', '#', '+', a
 * space and UTF-8 must survive a magnet round trip through ntx_magnet_parse,
 * and the .torrent basename must stay within NAME_MAX with the stem cut on a
 * UTF-8 boundary while the name inside the torrent stays full. The "same hash"
 * rule is checked against a real parse of the existing file (ntx_be_parse +
 * SHA-1 of the raw info subtree), so the fixtures here are hand-built bencode. */
#include "../src/core/ntx_share_out.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/proto/ntx_magnet.c"
#include "../src/proto/ntx_share_trackers.c"
#include "../src/crypto/ntx_sha1.c"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define OUTDIR "test/.scratch/share_out"
#define PREFIX "so_"
#define SFX_LEN 17 /* "-<8 hex>.torrent" */
#define STEM_MAX (255 - SFX_LEN)

static int fails;

static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) fails = 1;
}

static int mkdir_scratch(void) {
    if (mkdir("test/.scratch", 0755) != 0 && errno != EEXIST) return -1;
    if (mkdir(OUTDIR, 0755) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int read_all(const char *path, uint8_t **out, size_t *out_n) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) { close(fd); return -1; }
    size_t n = (size_t)st.st_size;
    uint8_t *buf = malloc(n);
    if (!buf) { close(fd); return -1; }
    size_t o = 0;
    while (o < n) {
        ssize_t r = read(fd, buf + o, n - o);
        if (r < 0) { if (errno == EINTR) continue; free(buf); close(fd); return -1; }
        if (r == 0) break;
        o += (size_t)r;
    }
    close(fd);
    if (o != n) { free(buf); return -1; }
    *out = buf;
    *out_n = n;
    return 0;
}

static int write_raw(const char *path, const uint8_t *buf, size_t n) {
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return -1;
    size_t o = 0;
    while (o < n) {
        ssize_t w = write(fd, buf + o, n - o);
        if (w < 0) { if (errno == EINTR) continue; close(fd); return -1; }
        o += (size_t)w;
    }
    close(fd);
    return 0;
}

/* Entries of OUTDIR whose name starts with PREFIX (streams share test/, so only
 * our own prefix is authoritative). */
static int list_ours(char names[][256], size_t cap) {
    DIR *d = opendir(OUTDIR);
    if (!d) return -1;
    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strncmp(de->d_name, PREFIX, sizeof PREFIX - 1) != 0) continue;
        if (n >= cap) { closedir(d); return -1; }
        snprintf(names[n++], 256, "%s", de->d_name);
    }
    closedir(d);
    return (int)n;
}

/* Independent UTF-8 check for the basename assertion (the writer's own helper
 * is static, so reusing it would test it against itself). */
static int test_utf8_ok(const uint8_t *s, size_t n) {
    size_t i = 0;
    while (i < n) {
        uint8_t c = s[i];
        int need;
        uint32_t cp;
        if (c < 0x80) { i++; continue; }
        if (c >= 0xC2 && c <= 0xDF) { need = 1; cp = c & 0x1Fu; }
        else if (c >= 0xE0 && c <= 0xEF) { need = 2; cp = c & 0x0Fu; }
        else if (c >= 0xF0 && c <= 0xF4) { need = 3; cp = c & 0x07u; }
        else return 0;
        if (i + (size_t)need >= n) return 0;
        for (int k = 1; k <= need; k++) {
            if (s[i + k] < 0x80 || s[i + k] > 0xBF) return 0;
            cp = (cp << 6) | (uint32_t)(s[i + k] & 0x3Fu);
        }
        if (need == 2 && cp < 0x800) return 0;
        if (need == 3 && cp < 0x10000) return 0;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        i += (size_t)need + 1;
    }
    return 1;
}

/* Hand-built bencode `d4:info<info>e` with an optional trailing comment, so two
 * files can share one info subtree (one hash) but differ in bytes. The SHA-1 of
 * the raw info subtree is reported as the hash the writer must recognise. */
static int mk_torrent(const char *tag, const char *comment, uint8_t **out, size_t *out_n, uint8_t ih[20]) {
    uint8_t pieces[20];
    for (int i = 0; i < 20; i++) pieces[i] = (uint8_t)(0x30 + i + (unsigned)tag[0]);
    size_t tn = strlen(tag);
    size_t cn = comment ? strlen(comment) : 0;
    /* room for the prefixes, two decimal lengths and the payload */
    size_t cap = 64 + tn + cn + 20 + 32;
    uint8_t *info = malloc(cap);
    uint8_t *top = malloc(cap * 2);
    if (!info || !top) { free(info); free(top); return -1; }

    int w = snprintf((char *)info, cap, "d4:name%zu:%s12:piece lengthi16384e7:pieces20:", tn, tag);
    if (w < 0 || (size_t)w + 21 > cap) { free(info); free(top); return -1; }
    memcpy(info + w, pieces, 20);
    size_t info_n = (size_t)w + 20;
    info[info_n++] = 'e';

    w = snprintf((char *)top, cap * 2, "d4:info%zu:", info_n);
    if (w < 0 || (size_t)w + info_n + cn + 16 > cap * 2) { free(info); free(top); return -1; }
    memcpy(top + w, info, info_n);
    w += (int)info_n;
    if (cn) {
        int k = snprintf((char *)top + w, cap * 2 - (size_t)w, "7:comment%zu:%s", cn, comment);
        if (k < 0 || (size_t)w + (size_t)k + 2 > cap * 2) { free(info); free(top); return -1; }
        w += k;
    }
    top[w++] = 'e';

    ntx_sha1(info, info_n, ih);
    free(info);
    *out = top;
    *out_n = (size_t)w;
    return 0;
}

int main(void) {
    static const uint8_t ih[20] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc,
        0xba, 0x98, 0x76, 0x54, 0x32, 0x10, 0x11, 0x22, 0x33, 0x44
    };
    static const uint8_t ih2[32] = {
        0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x0f, 0xed,
        0xcb, 0xa9, 0x87, 0x65, 0x43, 0x21, 0x11, 0x22, 0x33, 0x44,
        0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee,
        0xff, 0x00
    };
    static const char *trk[2] = {
        "https://alpha.example/announce",
        "https://beta.example/announce?key=abc&x=1#frag"
    };

    if (mkdir_scratch() != 0) { printf("FAIL scratch\n"); return 1; }

    /* ---- magnet: the Review Focus 1 round trip ---- */
    {
        const char *name = "a b&c%d#e+\xC5\x82.bin";
        char mag[NTX_SHARE_MAGNET_MAX];
        check(ntx_share_magnet(mag, sizeof mag, ih, ih2, name, trk, 2) == 0, "magnet_built");
        /* RFC 3986 unreserved raw, everything else %XX uppercase: space, & % # +
         * and both bytes of 'ł' must come out percent-encoded. */
        check(strstr(mag, "dn=a%20b%26c%25d%23e%2B%C5%82.bin") != NULL, "magnet_dn_encoded");
        check(strncmp(mag, "magnet:?xt=urn:btih:", sizeof("magnet:?xt=urn:btih:") - 1) == 0, "magnet_prefix");
        check(strstr(mag, "xt=urn:btih:0123456789abcdeffedcba987654321011223344") != NULL, "magnet_btih_hex");
        check(strstr(mag, "xt=urn:btmh:1220123456789abcdef00fedcba987654321112233445566778899aabbccddeeff00") != NULL,
              "magnet_btmh_hex");
        int ntr = 0;
        for (const char *p = mag; (p = strstr(p, "&tr=")) != NULL; p += 4) ntr++;
        check(ntr == 2, "magnet_two_tr");
        check(strchr(mag, ' ') == NULL, "magnet_no_raw_space");

        ntx_magnet m;
        check(ntx_magnet_parse(mag, &m) == 0, "magnet_parsed");
        check(memcmp(m.info_hash, ih, 20) == 0, "magnet_ih");
        check(m.has_v2 == 1, "magnet_has_v2");
        check(memcmp(m.ih_v2, ih2, 32) == 0, "magnet_ih2");
        check(m.has_name == 1 && strcmp(m.name, name) == 0, "magnet_name_roundtrip");
        check(m.n_trackers == 2, "magnet_n_trackers");
        check(strcmp(m.trackers[0], trk[0]) == 0, "magnet_trk0");
        check(strcmp(m.trackers[1], trk[1]) == 0, "magnet_trk1");
    }

    /* ---- magnet: edge cases ---- */
    {
        char mag[NTX_SHARE_MAGNET_MAX];
        check(ntx_share_magnet(mag, sizeof mag, ih, ih2, "", trk, 0) == 0, "magnet_no_name");
        check(strstr(mag, "dn=") == NULL, "magnet_no_dn_param");
        ntx_magnet m;
        check(ntx_magnet_parse(mag, &m) == 0 && m.has_name == 0 && m.n_trackers == 0, "magnet_no_name_parse");
        check(ntx_share_magnet(NULL, sizeof mag, ih, ih2, "x", trk, 0) != 0, "magnet_null_out");
        check(ntx_share_magnet(mag, 0, ih, ih2, "x", trk, 0) != 0, "magnet_zero_cap");
        check(ntx_share_magnet(mag, sizeof mag, NULL, ih2, "x", trk, 0) != 0, "magnet_null_ih");
        check(ntx_share_magnet(mag, sizeof mag, ih, NULL, "x", trk, 0) != 0, "magnet_null_ih2");
        check(ntx_share_magnet(mag, sizeof mag, ih, ih2, NULL, trk, 0) != 0, "magnet_null_name");
        check(ntx_share_magnet(mag, sizeof mag, ih, ih2, "x", NULL, 2) != 0, "magnet_null_trk");
        check(ntx_share_magnet(mag, sizeof mag, ih, ih2, "x", trk, -1) != 0, "magnet_neg_ntrk");
        {
            const char *bad[1] = { NULL };
            check(ntx_share_magnet(mag, sizeof mag, ih, ih2, "x", bad, 1) != 0, "magnet_null_trk_row");
            const char *empty[1] = { "" };
            check(ntx_share_magnet(mag, sizeof mag, ih, ih2, "x", empty, 1) != 0, "magnet_empty_trk");
        }
        check(ntx_share_magnet(mag, 64, ih, ih2, "x", trk, 2) != 0, "magnet_too_small");
        /* The real share list must fit the contract buffer NTX_SHARE_MAGNET_MAX
         * even in the worst case: every built-in tracker plus a 511 B name whose
         * bytes are all percent-encoded. (The JSON event caps a magnet lower —
         * 2048 B, plan C3 — which that task's own test pins.) */
        {
            int nb2 = ntx_share_tracker_count();
            const char *list[32];
            check(nb2 >= 2 && nb2 <= 32, "trk_builtin_count");
            for (int i = 0; i < nb2; i++) list[i] = ntx_share_tracker_get(i)->url;
            char nm[512];
            for (int i = 0; i < 255; i++) { nm[2 * i] = '\xC5'; nm[2 * i + 1] = '\x82'; }
            nm[510] = 'x';
            nm[511] = 0; /* 511 B, all 2-byte chars but one */
            char full[NTX_SHARE_MAGNET_MAX];
            check(ntx_share_magnet(full, sizeof full, ih, ih2, nm, list, nb2) == 0, "magnet_builtin_list");
            check(strlen(full) > 1000, "magnet_builtin_is_worst_case");
            ntx_magnet m;
            check(ntx_magnet_parse(full, &m) == 0 && m.n_trackers == nb2, "magnet_builtin_parse");
            check(strcmp(m.trackers[nb2 - 1], list[nb2 - 1]) == 0, "magnet_builtin_last_trk");
        }
        {
            char big[NTX_SHARE_MAGNET_MAX];
            char nm[512];
            memset(nm, 'a', sizeof nm - 1);
            nm[sizeof nm - 1] = 0;
            check(ntx_share_magnet(big, sizeof big, ih, ih2, nm, trk, 2) == 0, "magnet_511_name");
            ntx_magnet m;
            check(ntx_magnet_parse(big, &m) == 0 && strlen(m.name) == 511, "magnet_511_parse");
        }
    }

    /* ---- .torrent path: long UTF-8 names, stem cut on a character boundary ---- */
    {
        /* Case 1 — 236 ASCII + 7 two-byte chars = 250 B, last char 2-byte. The
         * byte cut at STEM_MAX (238) happens to be legal here, so the basename is
         * exactly 255 B: the widest legal name must not be chopped further. */
        static char n250[256];
        size_t i = 0;
        while (i < 236) n250[i++] = 'a';
        for (int k = 0; k < 7; k++) { n250[i++] = '\xC4'; n250[i++] = '\x87'; }
        n250[i] = 0;
        check(i == 250, "path_name_is_250");

        char path[NTX_SHARE_PATH_MAX];
        char orig[256];
        memcpy(orig, n250, sizeof n250);
        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, n250, ih) == 0, "path_250_built");
        check(memcmp(n250, orig, sizeof n250) == 0, "path_name_not_mutated"); /* torrent keeps it full */
        const char *bn = strrchr(path, '/');
        check(bn != NULL, "path_has_dir");
        if (bn) {
            bn++;
            check(strlen(bn) == 255, "path_250_basename_is_255");
            check(strlen(bn) <= 255, "path_basename_le_255");
            check(strcmp(bn + strlen(bn) - SFX_LEN, "-01234567.torrent") == 0, "path_suffix_8hex");
            check(bn[238] == '-', "path_250_cut_at_boundary");
            check(test_utf8_ok((const uint8_t *)bn, strlen(bn)) == 1, "path_250_basename_valid_utf8");
            check(strncmp(path, OUTDIR "/", strlen(OUTDIR) + 1) == 0, "path_uses_dir");
        }

        /* Case 2 — 237 ASCII + 6 two-byte chars = 249 B: byte STEM_MAX (238) falls
         * INSIDE the char at 237..238, so a naive byte cut leaves a lone lead byte
         * (invalid UTF-8). The correct stem is 237 B → basename 254 B. */
        static char n249[256];
        i = 0;
        while (i < 237) n249[i++] = 'a';
        for (int k = 0; k < 6; k++) { n249[i++] = '\xC4'; n249[i++] = '\x87'; }
        n249[i] = 0;
        check(i == 249, "path_name_is_249");
        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, n249, ih) == 0, "path_249_built");
        if ((bn = strrchr(path, '/')) != NULL) {
            bn++;
            check(strlen(bn) == 237 + SFX_LEN, "path_249_stem_cut_to_237");
            check(bn[237] == '-', "path_249_cut_at_boundary");
            check(test_utf8_ok((const uint8_t *)bn, strlen(bn)) == 1, "path_249_basename_valid_utf8");
            check(strncmp(bn, n249, 237) == 0, "path_249_stem_is_prefix");
        }

        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, "film.mkv", ih) == 0, "path_short_built");
        {
            char want[256];
            sprintf(want, "%s/film.mkv-01234567.torrent", OUTDIR);
            check(strcmp(path, want) == 0, "path_short_exact");
        }
        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, "\xE2\x82\xAC", ih) == 0, "path_short_utf8");
        {
            const char *b2 = strrchr(path, '/');
            check(b2 && strcmp(b2 + 1, "\xE2\x82\xAC-01234567.torrent") == 0, "path_short_utf8_exact");
        }
        check(ntx_share_torrent_path(NULL, sizeof path, OUTDIR, "x", ih) != 0, "path_null_out");
        check(ntx_share_torrent_path(path, 0, OUTDIR, "x", ih) != 0, "path_zero_cap");
        check(ntx_share_torrent_path(path, sizeof path, NULL, "x", ih) != 0, "path_null_dir");
        check(ntx_share_torrent_path(path, sizeof path, "", "x", ih) != 0, "path_empty_dir");
        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, "", ih) != 0, "path_empty_name");
        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, "a/b", ih) != 0, "path_slash_name");
        check(ntx_share_torrent_path(path, sizeof path, OUTDIR, "\xc3\x28", ih) != 0, "path_bad_utf8");
        check(ntx_share_torrent_path(path, 10, OUTDIR, "film.mkv", ih) != 0, "path_too_small");
        {
            char dir[NTX_SHARE_PATH_MAX];
            memset(dir, 'd', sizeof dir - 1);
            dir[sizeof dir - 1] = 0;
            check(ntx_share_torrent_path(path, sizeof path, dir, "film.mkv", ih) != 0, "path_dir_too_long");
        }
    }

    /* ---- name_ok ---- */
    {
        check(ntx_share_name_ok("a/b") == 0, "name_slash");
        check(ntx_share_name_ok("\x01" "x") == 0, "name_ctl");
        check(ntx_share_name_ok("\x7f") == 0, "name_del");
        check(ntx_share_name_ok("\xc3\x28") == 0, "name_bad_utf8");
        check(ntx_share_name_ok("") == 0, "name_empty");
        check(ntx_share_name_ok(NULL) == 0, "name_null");
        check(ntx_share_name_ok("za\xC5\xBC\xC3\xB3\xC5\x82\xC4\x87.txt") == 1, "name_utf8_ok");
        check(ntx_share_name_ok("a b&c%d#e+.bin") == 1, "name_punct_ok");
        check(ntx_share_name_ok("\xc2\xa2") == 1, "name_2byte_ok");
        check(ntx_share_name_ok("\xe2\x82\xac") == 1, "name_3byte_ok");
        check(ntx_share_name_ok("\xf0\x9f\x98\x80") == 1, "name_4byte_ok");
        check(ntx_share_name_ok("\xc0\x80") == 0, "name_overlong");
        check(ntx_share_name_ok("\xed\xa0\x80") == 0, "name_surrogate");
        check(ntx_share_name_ok("\xf4\x90\x80\x80") == 0, "name_above_max");
        check(ntx_share_name_ok("\xe2\x82") == 0, "name_truncated");
        check(ntx_share_name_ok("\x80") == 0, "name_stray_cont");
        check(ntx_share_name_ok("a\x00" "b") == 1, "name_stops_at_nul");
    }

    /* ---- atomic writer ---- */
    {
        uint8_t *buf = NULL, *rb = NULL;
        size_t n = 0, rn = 0;
        uint8_t wh[20];
        char path[NTX_SHARE_PATH_MAX];
        char names[64][256];
        int nb, na;

        if (mk_torrent("seed-A", NULL, &buf, &n, wh) != 0) { printf("FAIL fixture\n"); return 1; }
        sprintf(path, "%s/%s_a.torrent", OUTDIR, PREFIX);
        unlink(path);
        nb = list_ours(names, 64);
        check(nb >= 0, "dir_listable");

        check(ntx_share_write_torrent(path, buf, n, wh) == NTX_SHARE_OK, "write_first_ok");
        na = list_ours(names, 64);
        check(na == nb + 1, "write_no_stray_files");
        int found = 0, tmp = 0;
        for (int i = 0; i < na; i++) {
            if (strcmp(names[i], path + strlen(OUTDIR) + 1) == 0) found = 1;
            if (strstr(names[i], ".tmp")) tmp = 1;
        }
        check(found, "write_file_exists");
        check(!tmp, "write_no_tmp_left");
        check(read_all(path, &rb, &rn) == 0, "write_readback");
        check(rn == n && memcmp(rb, buf, n) == 0, "write_bytes_equal");
        free(rb);
        rb = NULL;
        {
            struct stat st;
            check(stat(path, &st) == 0, "write_stat");
            check((st.st_mode & 0777) == 0600, "write_mode_0600");
        }

        /* same bytes again: OK, no stray file, still 0600 */
        check(ntx_share_write_torrent(path, buf, n, wh) == NTX_SHARE_OK, "write_same_ok");
        na = list_ours(names, 64);
        check(na == nb + 1, "write_same_no_stray");
        {
            struct stat st;
            check(stat(path, &st) == 0 && (st.st_mode & 0777) == 0600, "write_same_mode");
        }

        /* different bytes, same info hash (extra top-level comment): the hash,
         * not the bytes, is the identity — §5.6 re-share must overwrite. */
        {
            uint8_t *b2 = NULL;
            size_t n2 = 0;
            uint8_t h2[20];
            if (mk_torrent("seed-A", "second run", &b2, &n2, h2) != 0) { printf("FAIL fixture2\n"); return 1; }
            check(memcmp(h2, wh, 20) == 0 && n2 != n, "write_same_hash_fixture");
            check(ntx_share_write_torrent(path, b2, n2, h2) == NTX_SHARE_OK, "write_same_hash_ok");
            check(read_all(path, &rb, &rn) == 0 && rn == n2 && memcmp(rb, b2, n2) == 0, "write_same_hash_bytes");
            free(rb);
            rb = NULL;
            na = list_ours(names, 64);
            check(na == nb + 1, "write_same_hash_no_stray");
            free(b2);
        }

        /* different hash on disk: E_EXISTS and the old file is untouched */
        {
            uint8_t *other = NULL;
            size_t on = 0;
            uint8_t oh[20];
            if (mk_torrent("seed-B", NULL, &other, &on, oh) != 0) { printf("FAIL fixture3\n"); return 1; }
            check(memcmp(oh, wh, 20) != 0, "fixtures_differ");
            /* re-establish the A file first (the case above left its own bytes) */
            check(ntx_share_write_torrent(path, buf, n, wh) == NTX_SHARE_OK, "write_other_reset");
            nb = list_ours(names, 64);
            check(ntx_share_write_torrent(path, other, on, oh) == NTX_SHARE_E_EXISTS, "write_other_ih_exists");
            na = list_ours(names, 64);
            check(na == nb, "write_other_no_stray");
            check(read_all(path, &rb, &rn) == 0 && rn == n && memcmp(rb, buf, n) == 0, "write_other_untouched");
            free(rb);
            rb = NULL;
            /* the reverse direction too: the file on disk decides, not the caller */
            sprintf(path, "%s/%s_foreign.torrent", OUTDIR, PREFIX);
            unlink(path);
            check(write_raw(path, other, on) == 0, "write_seed_foreign");
            check(ntx_share_write_torrent(path, buf, n, wh) == NTX_SHARE_E_EXISTS, "write_foreign_rejected");
            check(read_all(path, &rb, &rn) == 0 && rn == on && memcmp(rb, other, on) == 0, "write_foreign_untouched");
            free(rb);
            rb = NULL;
            check(ntx_share_write_torrent(path, other, on, oh) == NTX_SHARE_OK, "write_foreign_owner_ok");
            unlink(path);
            free(other);
        }

        /* unparseable file, or info whose hash differs: never clobber */
        {
            sprintf(path, "%s/%s_garbage.torrent", OUTDIR, PREFIX);
            unlink(path);
            check(write_raw(path, (const uint8_t *)"not bencode at all", 18) == 0, "write_seed_garbage");
            check(ntx_share_write_torrent(path, buf, n, wh) == NTX_SHARE_E_EXISTS, "write_garbage_exists");
            unlink(path);

        /* buf whose info does not hash to ih is a caller bug, never a write: the
         * filename carries the hash and is the access key. */
        {
            uint8_t bad[20];
            memcpy(bad, wh, 20);
            bad[19] ^= 0xff;
            sprintf(path, "%s/%s_hashmismatch.torrent", OUTDIR, PREFIX);
            unlink(path);
            check(ntx_share_write_torrent(path, buf, n, bad) == NTX_SHARE_E_BAD_ARG, "write_buf_hash_mismatch");
            struct stat st;
            check(stat(path, &st) != 0, "write_buf_hash_mismatch_no_file");

            /* not bencode at all in buf: also bad_arg */
            check(ntx_share_write_torrent(path, (const uint8_t *)"junk", 4, wh) == NTX_SHARE_E_BAD_ARG,
                  "write_buf_not_bencode");

            /* ih is SHA-1 of the raw info subtree of the buffer (that is what
             * ntx_share_build_info + ntx_share_build_torrent give A5), so any
             * other hash — e.g. of the whole file — is refused instead of
             * written under a filename that lies about its contents. */
            uint8_t info_sha1[20];
            ntx_be be;
            size_t cc = 0;
            if (ntx_be_parse(buf, n, &be, &cc, 32, 1 << 20) != 0) { printf("FAIL fixture_parse\n"); return 1; }
            const ntx_be *info = ntx_be_dict_get(&be, "info");
            if (!info) { printf("FAIL fixture_info\n"); return 1; }
            ntx_sha1(buf + info->start, info->end - info->start, info_sha1);
            ntx_be_free(&be);
            check(memcmp(info_sha1, wh, 20) == 0, "write_ih_is_info_sha1");
            uint8_t bare[20];
            ntx_sha1(buf, n, bare); /* the whole file, not the info dict */
            check(ntx_share_write_torrent(path, buf, n, bare) == NTX_SHARE_E_BAD_ARG, "write_whole_file_hash");
            unlink(path);
        }

            /* a directory at that path is an IO error, not a clobber */
            sprintf(path, "%s/%s_dir.torrent", OUTDIR, PREFIX);
            (void)mkdir(path, 0755);
            check(ntx_share_write_torrent(path, buf, n, wh) == NTX_SHARE_E_EXISTS, "write_dir_exists");
            rmdir(path);
        }

        /* bad args / IO */
        {
            check(ntx_share_write_torrent(NULL, buf, n, wh) == NTX_SHARE_E_BAD_ARG, "write_null_path");
            check(ntx_share_write_torrent(path, NULL, n, wh) == NTX_SHARE_E_BAD_ARG, "write_null_buf");
            check(ntx_share_write_torrent(path, buf, 0, wh) == NTX_SHARE_E_BAD_ARG, "write_zero_len");
            check(ntx_share_write_torrent(path, buf, n, NULL) == NTX_SHARE_E_BAD_ARG, "write_null_ih");
            check(ntx_share_write_torrent(OUTDIR "/no-such-dir/x.torrent", buf, n, wh) == NTX_SHARE_E_IO, "write_no_dir");
            check(strlen(OUTDIR "/no-such-dir/x.torrent") < NTX_SHARE_PATH_MAX, "write_long_path_sanity");
        }

        /* fresh path with an over-long name, end to end */
        {
            char longname[STEM_MAX + 64];
            memset(longname, 'z', sizeof longname - 1);
            longname[sizeof longname - 1] = 0;
            char p[NTX_SHARE_PATH_MAX];
            check(ntx_share_torrent_path(p, sizeof p, OUTDIR, longname, wh) == 0, "write_long_path_built");
            unlink(p);
            check(ntx_share_write_torrent(p, buf, n, wh) == NTX_SHARE_OK, "write_long_ok");
            struct stat st;
            check(stat(p, &st) == 0 && (st.st_mode & 0777) == 0600, "write_long_mode");
            check(strlen(strrchr(p, '/') + 1) <= 255, "write_long_basename_len");
            unlink(p);
        }

        unlink(path);
        free(buf);
    }

    printf("%s share_out (%d fail)\n", fails ? "FAIL" : "PASS", fails);
    return fails ? 1 : 0;
}
