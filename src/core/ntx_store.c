#include "ntx_store.h"
#include "../proto/ntx_bencode.h"
#include "../crypto/ntx_sha1.h"
#include "../ui/ntx_diag.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int mkdir_p_parent(const char *path) {
    char tmp[768];
    size_t n = strlen(path);
    if (n >= sizeof tmp) return -1;
    memcpy(tmp, path, n + 1);
    for (char *p = tmp + 1; *p; p++) {
        if (*p != '/') continue;
        *p = 0;
        if (mkdir(tmp, 0755) < 0 && errno != EEXIST) return -1;
        *p = '/';
    }
    return 0;
}

/* Open or create one part; fresh files are truncated, existing ones are only
 * extended to len (never shrunk). Returns 1 when the part pre-existed (any
 * size — piece hashes protect correctness), 0 when created fresh. */
static int open_part(const char *path, uint64_t len, int *out_fd) {
    int fd = open(path, O_RDWR);
    if (fd >= 0) {
        struct stat st;
        if (fstat(fd, &st) < 0) {
            close(fd);
            return -1;
        }
        if ((uint64_t)st.st_size != len)
            ntx_diag("store: %s size %llu != expected %llu, kept as-is\n", path,
                     (unsigned long long)st.st_size, (unsigned long long)len);
        if ((uint64_t)st.st_size < len) {
            if (ftruncate(fd, (off_t)len) < 0) {
                close(fd);
                return -1;
            }
        }
        *out_fd = fd;
        return 1;
    }
    if (errno != ENOENT) return -1;
    fd = open(path, O_RDWR | O_CREAT, 0644);
    if (fd < 0) return -1;
    if (ftruncate(fd, (off_t)len) < 0) {
        close(fd);
        return -1;
    }
    *out_fd = fd;
    return 0;
}

int ntx_store_open(ntx_store *st, const char *path, uint64_t size, uint32_t ps) {
    memset(st, 0, sizeof *st);
    st->fd = -1;
    if (mkdir_p_parent(path) != 0) return -1;
    int existed = open_part(path, size, &st->fd);
    if (existed < 0) return -1;
    st->size = size;
    st->ps = ps;
    st->np = (uint32_t)((size + ps - 1) / ps);
    st->pmap = calloc(st->np, 1);
    if (!st->pmap) {
        close(st->fd);
        st->fd = -1;
        return -1;
    }
    /* Single contiguous file spanning the whole torrent. */
    st->parts = calloc(1, sizeof *st->parts);
    if (!st->parts) {
        free(st->pmap);
        close(st->fd);
        st->fd = -1;
        return -1;
    }
    st->nparts = 1;
    st->parts[0].fd = st->fd;
    st->parts[0].start = 0;
    st->parts[0].len = size;
    st->existed = existed;
    return 0;
}

int ntx_store_open_parts(ntx_store *st, const ntx_store_part_spec *specs, int nspecs, uint64_t size,
                         uint32_t ps) {
    memset(st, 0, sizeof *st);
    st->fd = -1;
    if (!specs || nspecs <= 0) return -1;
    st->parts = calloc((size_t)nspecs, sizeof *st->parts);
    if (!st->parts) return -1;
    st->nparts = nspecs;
    st->size = size;
    st->ps = ps;
    st->np = (uint32_t)((size + ps - 1) / ps);
    st->pmap = calloc(st->np, 1);
    if (!st->pmap) {
        free(st->parts);
        st->parts = NULL;
        return -1;
    }
    for (int i = 0; i < nspecs; i++) {
        if (mkdir_p_parent(specs[i].path) != 0) goto fail;
        int fd, ex;
        if ((ex = open_part(specs[i].path, specs[i].len, &fd)) < 0) goto fail;
        st->existed |= (uint8_t)ex;
        st->parts[i].fd = fd;
        st->parts[i].start = specs[i].start;
        st->parts[i].len = specs[i].len;
    }
    st->fd = st->parts[0].fd;
    return 0;
fail:
    ntx_store_close(st);
    return -1;
}

void ntx_store_close(ntx_store *st) {
    if (st->parts) {
        for (int i = 0; i < st->nparts; i++) {
            if (st->parts[i].fd >= 0) {
                /* Avoid double-close when fd aliases parts[0]. */
                int dup = 0;
                for (int j = 0; j < i; j++)
                    if (st->parts[j].fd == st->parts[i].fd) {
                        dup = 1;
                        break;
                    }
                if (!dup) close(st->parts[i].fd);
            }
            st->parts[i].fd = -1;
        }
        free(st->parts);
        st->parts = NULL;
        st->nparts = 0;
    } else if (st->fd >= 0) {
        close(st->fd);
    }
    st->fd = -1;
    free(st->pmap);
    st->pmap = NULL;
}

uint32_t ntx_store_pl(const ntx_store *st, uint32_t i) {
    uint64_t rem = st->size - (uint64_t)i * st->ps;
    return rem < st->ps ? (uint32_t)rem : st->ps;
}

static int store_io(const ntx_store *st, int do_write, uint64_t abs, const void *wbuf, void *rbuf, size_t len) {
    size_t done = 0;
    while (done < len) {
        uint64_t pos = abs + done;
        int part = -1;
        for (int i = 0; i < st->nparts; i++) {
            if (pos >= st->parts[i].start && pos < st->parts[i].start + st->parts[i].len) {
                part = i;
                break;
            }
        }
        if (part < 0) return -1;
        uint64_t local = pos - st->parts[part].start;
        size_t room = (size_t)(st->parts[part].len - local);
        size_t chunk = len - done;
        if (chunk > room) chunk = room;
        ssize_t r;
        if (do_write)
            r = pwrite(st->parts[part].fd, (const uint8_t *)wbuf + done, chunk, (off_t)local);
        else
            r = pread(st->parts[part].fd, (uint8_t *)rbuf + done, chunk, (off_t)local);
        if (r < 0) return -1;
        if ((size_t)r != chunk) return -1;
        done += chunk;
    }
    return 0;
}

int ntx_store_write(ntx_store *st, uint32_t i, uint32_t off, const void *buf, size_t len) {
    uint64_t abs = (uint64_t)i * st->ps + off;
    if (abs + len > st->size) return -1;
    if (store_io(st, 1, abs, buf, NULL, len) != 0) return -1;
    if (st->pmap[i] == 0) st->pmap[i] = 1;
    return 0;
}

int ntx_store_read(const ntx_store *st, uint32_t i, uint32_t off, void *buf, size_t len) {
    uint64_t abs = (uint64_t)i * st->ps + off;
    if (abs + len > st->size) return -1;
    if (store_io(st, 0, abs, NULL, buf, len) != 0) return -1;
    return (int)len;
}

int ntx_store_complete(ntx_store *st, uint32_t i, const uint8_t h20[20]) {
    uint32_t pl = ntx_store_pl(st, i);
    uint8_t *buf = malloc(pl);
    if (!buf) return 0;
    int ok = 0;
    if (ntx_store_read(st, i, 0, buf, pl) == (int)pl) {
        uint8_t h[20];
        ntx_sha1(buf, pl, h);
        ok = memcmp(h, h20, 20) == 0;
    }
    free(buf);
    st->pmap[i] = ok ? 2 : 0;
    return ok;
}

uint8_t ntx_store_pmap(const ntx_store *st, uint32_t i) {
    return st->pmap[i];
}

uint64_t ntx_store_verified_bytes(const ntx_store *st) {
    uint64_t total = 0;
    for (uint32_t i = 0; i < st->np; i++)
        if (st->pmap[i] == 2) total += ntx_store_pl(st, i);
    return total;
}

int ntx_store_size_of(const ntx_be *info, uint64_t *out) {
    const ntx_be *len = ntx_be_dict_get(info, "length");
    if (len && len->t == NTX_BE_INT && len->i > 0) {
        *out = (uint64_t)len->i;
        return 0;
    }
    const ntx_be *files = ntx_be_dict_get(info, "files");
    if (files && files->t == NTX_BE_LIST && files->ne > 0) {
        uint64_t total = 0;
        for (size_t i = 0; i < files->ne; i++) {
            const ntx_be *fe = files->el[i];
            const ntx_be *flen = fe && fe->t == NTX_BE_DICT ? ntx_be_dict_get(fe, "length") : NULL;
            if (!flen || flen->t != NTX_BE_INT || flen->i < 0) return -1;
            if ((uint64_t)flen->i > UINT64_MAX - total) return -1; /* sum wraps 2^64 */
            total += (uint64_t)flen->i;
        }
        if (total == 0) return -1;
        *out = total;
        return 0;
    }
    return -1;
}

/* Append UTF-8 path component; reject empty, '.', '..', and embedded '/'. */
int ntx_store_path_append(char *out, size_t cap, size_t *o, const uint8_t *sp, size_t sn) {
    if (!sp || sn == 0) return -1;
    if (sn == 1 && sp[0] == '.') return -1;
    if (sn == 2 && sp[0] == '.' && sp[1] == '.') return -1;
    for (size_t i = 0; i < sn; i++)
        if (sp[i] == '/' || sp[i] == 0) return -1;
    if (*o && *o + 1 < cap) out[(*o)++] = '/';
    if (*o + sn >= cap) return -1;
    memcpy(out + *o, sp, sn);
    *o += sn;
    out[*o] = 0;
    return 0;
}

int ntx_store_file_rel(char *out, size_t cap, const ntx_be *name, const ntx_be *path) {
    size_t o = 0;
    out[0] = 0;
    if (name && name->t == NTX_BE_STR && name->sn > 0) {
        if (ntx_store_path_append(out, cap, &o, name->sp, name->sn) != 0) return -1;
    }
    if (!path || path->t != NTX_BE_LIST || path->ne == 0) return out[0] ? 0 : -1;
    for (size_t i = 0; i < path->ne; i++) {
        const ntx_be *c = path->el[i];
        if (!c || c->t != NTX_BE_STR) return -1;
        if (ntx_store_path_append(out, cap, &o, c->sp, c->sn) != 0) return -1;
    }
    return out[0] ? 0 : -1;
}
