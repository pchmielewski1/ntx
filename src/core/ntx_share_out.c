#include "ntx_share_out.h"
#include "../crypto/ntx_sha1.h"
#include "../proto/ntx_bencode.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Magnet builder and atomic .torrent writer for --share (design §5.4). */

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

/* "-<8 hex>.torrent" */
#define SOUT_SUFFIX_LEN 17

/* Largest existing .torrent whose hash we verify by reading it. ntx's own
 * builds stay far below this (pieces are 20 B/piece and piece layers 32 B/piece,
 * both capped by the parser's 1 MiB string limit), so anything larger is not one
 * of ours. */
#define SOUT_MAX_TORRENT (4u * 1024u * 1024u)

static int sout_char_len(unsigned char c) {
    if (c < 0x80) return 1;
    if (c >= 0xC2 && c <= 0xDF) return 2;
    if (c >= 0xE0 && c <= 0xEF) return 3;
    if (c >= 0xF0 && c <= 0xF4) return 4;
    return 0;
}

/* Strict UTF-8: no overlong forms, no surrogates, nothing above U+10FFFF. */
static int sout_utf8_ok(const char *s, size_t n) {
    const unsigned char *u = (const unsigned char *)s;
    size_t i = 0;
    while (i < n) {
        int need = sout_char_len(u[i]);
        if (need == 0 || i + (size_t)need > n) return 0;
        for (int k = 1; k < need; k++)
            if (u[i + k] < 0x80 || u[i + k] > 0xBF) return 0;
        unsigned cp;
        if (need == 2) cp = u[i] & 0x1Fu;
        else if (need == 3) cp = u[i] & 0x0Fu;
        else if (need == 4) cp = u[i] & 0x07u;
        else cp = 0;
        for (int k = 1; k < need; k++) cp = (cp << 6) | (unsigned)(u[i + k] & 0x3F);
        if (need == 3 && cp < 0x800) return 0;
        if (need == 4 && cp < 0x10000) return 0;
        if (cp > 0x10FFFF || (cp >= 0xD800 && cp <= 0xDFFF)) return 0;
        i += (size_t)need;
    }
    return 1;
}

int ntx_share_name_ok(const char *name) {
    if (!name) return 0;
    size_t n = strlen(name);
    if (n == 0) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned char c = (unsigned char)name[i];
        if (c < 0x20 || c == 0x7f || c == '/') return 0;
    }
    return sout_utf8_ok(name, n);
}

static int sout_append(char *out, size_t cap, size_t *o, const char *s, size_t n) {
    if (*o + n >= cap) return -1;
    memcpy(out + *o, s, n);
    *o += n;
    out[*o] = 0;
    return 0;
}

/* sizeof-based so a literal can never be counted by hand. */
#define SOUT_LIT(out, cap, o, lit) sout_append((out), (cap), (o), (lit), sizeof(lit) - 1)

/* Hash hex is lowercase, as everywhere else in ntx (ntx_hex40, to_hex); only the
 * percent-escapes are uppercase, because RFC 3986 §2.1 asks for that. */
static int sout_hex(char *out, size_t cap, size_t *o, const uint8_t *b, size_t n) {
    static const char H[] = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        char pair[2] = { H[b[i] >> 4], H[b[i] & 15] };
        if (sout_append(out, cap, o, pair, 2) != 0) return -1;
    }
    return 0;
}

/* RFC 3986: unreserved stays raw, every other byte becomes %XX with uppercase
 * hex. '+' must be escaped or ntx_magnet_parse would turn it into a space. */
static int sout_pct(char *out, size_t cap, size_t *o, const char *s) {
    static const char H[] = "0123456789ABCDEF";
    for (const unsigned char *p = (const unsigned char *)s; *p; p++) {
        unsigned char c = *p;
        int raw = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                  c == '-' || c == '.' || c == '_' || c == '~';
        if (raw) {
            if (sout_append(out, cap, o, (const char *)&c, 1) != 0) return -1;
        } else {
            char esc[3] = { '%', H[c >> 4], H[c & 15] };
            if (sout_append(out, cap, o, esc, 3) != 0) return -1;
        }
    }
    return 0;
}

int ntx_share_magnet(char *out, size_t cap, const uint8_t ih[20], const uint8_t ih2[32],
                     const char *name, const char *const *trackers, int ntrk) {
    if (!out || cap == 0 || !ih || !ih2 || !name || ntrk < 0 || (ntrk > 0 && !trackers)) {
        if (out && cap) out[0] = 0;
        return -1;
    }
    size_t o = 0;
    int rc = SOUT_LIT(out, cap, &o, "magnet:?xt=urn:btih:");
    if (rc == 0) rc = sout_hex(out, cap, &o, ih, 20);
    if (rc == 0) rc = SOUT_LIT(out, cap, &o, "&xt=urn:btmh:1220");
    if (rc == 0) rc = sout_hex(out, cap, &o, ih2, 32);
    if (rc == 0 && name[0]) {
        if (SOUT_LIT(out, cap, &o, "&dn=") != 0) rc = -1;
        else rc = sout_pct(out, cap, &o, name);
    }
    for (int i = 0; rc == 0 && i < ntrk; i++) {
        if (!trackers[i] || !trackers[i][0]) {
            rc = -1;
            break;
        }
        if (SOUT_LIT(out, cap, &o, "&tr=") != 0) rc = -1;
        else rc = sout_pct(out, cap, &o, trackers[i]);
    }
    if (rc != 0) out[0] = 0;
    return rc;
}

int ntx_share_torrent_path(char *out, size_t cap, const char *dir, const char *name, const uint8_t ih[20]) {
    if (out && cap) out[0] = 0;
    if (!out || cap == 0 || !dir || !dir[0] || !ih || !ntx_share_name_ok(name)) return -1;

    /* Longest whole-character prefix of name that still leaves room for the
     * suffix in a NAME_MAX basename. The name in the torrent is never cut. */
    size_t n = strlen(name);
    size_t stem = 0;
    while (stem < n) {
        size_t step = (size_t)sout_char_len((unsigned char)name[stem]);
        if (step == 0 || stem + step > n || stem + step > (size_t)NAME_MAX - SOUT_SUFFIX_LEN) break;
        stem += step;
    }

    char hex[8 + 1];
    size_t ho = 0;
    if (sout_hex(hex, sizeof hex, &ho, ih, 4) != 0) return -1;

    int w = snprintf(out, cap, "%s/%.*s-%s.torrent", dir, (int)stem, name, hex);
    if (w < 0 || (size_t)w >= cap) {
        out[0] = 0;
        return -1;
    }
    return 0;
}

/* SHA-1 of the raw info subtree of a bencoded torrent, or -1. */
static int sout_info_sha1(const uint8_t *buf, size_t n, uint8_t out[20]) {
    ntx_be be;
    size_t consumed = 0;
    if (ntx_be_parse(buf, n, &be, &consumed, 32, (size_t)1 << 20) != 0) return -1;
    int rc = -1;
    if (be.t == NTX_BE_DICT) {
        const ntx_be *info = ntx_be_dict_get(&be, "info");
        if (info && info->end > info->start) {
            ntx_sha1(buf + info->start, info->end - info->start, out);
            rc = 0;
        }
    }
    ntx_be_free(&be);
    return rc;
}

/* 1 = path exists and already holds exactly this info hash, 0 = nothing is
 * there, -1 = something that is not ours to replace. Anything unreadable or
 * unparseable is -1: fail closed rather than clobber a file we did not write. */
static int sout_same_hash(const char *path, const uint8_t ih[20]) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) return errno == ENOENT || errno == ENOTDIR ? 0 : -1;
    struct stat st;
    uint8_t *buf = NULL;
    int rc = -1;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0 ||
        (size_t)st.st_size > SOUT_MAX_TORRENT)
        goto done;
    size_t sz = (size_t)st.st_size;
    buf = malloc(sz);
    if (!buf) goto done;
    size_t off = 0;
    while (off < sz) {
        ssize_t r = read(fd, buf + off, sz - off);
        if (r < 0) { if (errno == EINTR) continue; goto done; }
        if (r == 0) break;
        off += (size_t)r;
    }
    if (off != sz) goto done;
    uint8_t got[20];
    if (sout_info_sha1(buf, sz, got) != 0) goto done; /* not bencode / no info: not ours */
    rc = memcmp(got, ih, 20) == 0 ? 1 : -1;
done:
    free(buf);
    close(fd);
    return rc;
}

static int sout_write_all(int fd, const uint8_t *buf, size_t n) {
    size_t off = 0;
    while (off < n) {
        ssize_t w = write(fd, buf + off, n - off);
        if (w < 0) { if (errno == EINTR) continue; return -1; }
        if (w == 0) return -1;
        off += (size_t)w;
    }
    return 0;
}

/* <path> with its last component removed; "." when path has no '/'. */
static int sout_dirname(char *dir, size_t cap, const char *path) {
    const char *slash = strrchr(path, '/');
    if (!slash) {
        if (cap < 2) return -1;
        dir[0] = '.';
        dir[1] = 0;
        return 0;
    }
    size_t dl = (size_t)(slash - path);
    if (dl == 0) dl = 1; /* "/" → "/" */
    if (dl >= cap) return -1;
    memcpy(dir, path, dl);
    dir[dl] = 0;
    return 0;
}

/* <path>.tmp<pid> in the same directory, with the basename shortened so the
 * tmp name itself stays inside NAME_MAX (the final name may already use all of it). */
static int sout_tmpname(char *tmp, size_t capsz, const char *path, int attempt) {
    const char *slash = strrchr(path, '/');
    size_t dlen = slash ? (size_t)(slash - path) + 1 : 0;
    char tail[16];
    int tl = snprintf(tail, sizeof tail, ".tmp%d", attempt);
    if (tl < 0 || (size_t)tl >= sizeof tail) return -1;
    size_t bl = strlen(path + dlen);
    if (bl + (size_t)tl > (size_t)NAME_MAX) bl = (size_t)NAME_MAX - (size_t)tl;
    int w = snprintf(tmp, capsz, "%.*s%.*s%s", (int)dlen, path, (int)bl, path + dlen, tail);
    return (w < 0 || (size_t)w >= capsz) ? -1 : 0;
}

ntx_share_err ntx_share_write_torrent(const char *path, const uint8_t *buf, size_t n, const uint8_t ih[20]) {
    if (!path || !path[0] || strlen(path) >= PATH_MAX || !buf || n == 0 || !ih) return NTX_SHARE_E_BAD_ARG;

    /* buf must really be the torrent ih names: the hash is in the filename and is
     * the access key of a private share, so a file whose bytes do not match its
     * name must never reach disk. Costs one parse + SHA-1, once per share. */
    uint8_t got[20];
    if (sout_info_sha1(buf, n, got) != 0 || memcmp(got, ih, 20) != 0) return NTX_SHARE_E_BAD_ARG;

    /* Absent and "already this hash" both fall through to the atomic replace
     * (§5.6 re-share keeps its link); anything else on disk is exists.
     * ponytail: the check is not atomic with the rename — a file created in the
     * window is overwritten. --share writes only into its own store dir; closing
     * it would need O_EXCL on the final name plus a re-read. */
    if (sout_same_hash(path, ih) < 0) return NTX_SHARE_E_EXISTS;

    char tmp[PATH_MAX];
    int fd = -1;
    for (int attempt = 0; attempt < 8; attempt++) {
        if (sout_tmpname(tmp, sizeof tmp, path, attempt) != 0) return NTX_SHARE_E_IO;
        /* O_EXCL so a planted symlink or a leftover from a killed run is never
         * followed or shared. */
        fd = open(tmp, O_WRONLY | O_CREAT | O_TRUNC | O_EXCL, 0600);
        if (fd >= 0) break;
        if (errno != EEXIST) return NTX_SHARE_E_IO;
    }
    if (fd < 0) return NTX_SHARE_E_IO;

    ntx_share_err err = NTX_SHARE_OK;
    /* fchmod regardless of how the fd came to be: the mode is a security
     * property here and must not depend on the caller's umask. */
    if (fchmod(fd, 0600) != 0 || sout_write_all(fd, buf, n) != 0 || fsync(fd) != 0) err = NTX_SHARE_E_IO;
    if (close(fd) != 0 && err == NTX_SHARE_OK) err = NTX_SHARE_E_IO;
    if (err == NTX_SHARE_OK && rename(tmp, path) != 0) err = NTX_SHARE_E_IO;
    if (err != NTX_SHARE_OK) unlink(tmp);

    if (err == NTX_SHARE_OK) {
        /* Best effort: the file is already durable and visible; failing to sync
         * the directory must not make the caller think the write failed. */
        char dir[PATH_MAX];
        if (sout_dirname(dir, sizeof dir, path) == 0) {
            int dfd = open(dir, O_RDONLY | O_DIRECTORY);
            if (dfd >= 0) {
                fsync(dfd);
                close(dfd);
            }
        }
    }
    return err;
}
