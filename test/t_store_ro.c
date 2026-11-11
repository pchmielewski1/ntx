#include "../src/core/ntx_store.c"
#include "../src/proto/ntx_bencode.c" /* (ntx_be_dict_get) */
#include "../src/crypto/ntx_sha1.c"
#include "../src/ui/ntx_diag.c"

#include <dirent.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SIZE 40000ULL
#define PS 16384U
#define PATH "test/store_ro_test.tmp"
#define PREFIX "store_ro"

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

static int cmp_str(const void *a, const void *b) {
    return strcmp((const char *)a, (const char *)b);
}

/* Sorted names in test/, excluding . and .. */
static int list_dir(char names[][256], size_t cap) {
    DIR *d = opendir("test");
    if (!d) return -1;
    size_t n = 0;
    struct dirent *de;
    while ((de = readdir(d))) {
        if (strcmp(de->d_name, ".") == 0 || strcmp(de->d_name, "..") == 0) continue;
        if (n >= cap) { closedir(d); return -1; }
        snprintf(names[n++], 256, "%s", de->d_name);
    }
    closedir(d);
    qsort(names, n, sizeof names[0], cmp_str);
    return (int)n;
}

/* Streams share test/, so only our own prefix is authoritative: nothing this
 * store variant creates or removes may carry it. */
static int ours(const char *name) { return strncmp(name, PREFIX, sizeof PREFIX - 1) == 0; }

static int file_sha1(const char *path, uint8_t out[20]) {
    static uint8_t buf[SIZE];
    int fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
    ssize_t r = read(fd, buf, sizeof buf);
    close(fd);
    if (r != (ssize_t)SIZE) return -1;
    ntx_sha1(buf, (size_t)r, out);
    return 0;
}

int main(void) {
    ntx_store st;
    static uint8_t pat[SIZE];
    static uint8_t rb[SIZE];
    static char before[512][256], after[512][256];
    int nb, na;

    for (uint64_t i = 0; i < SIZE; i++) pat[i] = (uint8_t)(i * 7 + 3);

    unlink(PATH);
    int fd = open(PATH, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0 || pwrite(fd, pat, SIZE, 0) != (ssize_t)SIZE) fail("setup_file");
    close(fd);

    nb = list_dir(before, 512);
    if (nb < 0) fail("list_before");

    uint8_t h_before[20];
    if (file_sha1(PATH, h_before) != 0) fail("sha1_before");

    fd = open(PATH, O_RDONLY);
    if (fd < 0) fail("open_rdonly");

    if (ntx_store_open_ro_fd(&st, fd, SIZE, PS) != 0) fail("open_ro");
    if (st.np != 3) fail("np");
    if (st.nparts != 1) fail("nparts");
    if (st.ro != 1) fail("ro_flag");
    if (st.size != SIZE || st.ps != PS) fail("size_ps");
    if (st.parts[0].fd != fd || st.parts[0].start != 0 || st.parts[0].len != SIZE) fail("part");
    for (uint32_t i = 0; i < st.np; i++)
        if (ntx_store_pmap(&st, i) != 0) fail("pmap_init");
    printf("PASS open_ro\n");

    if (ntx_store_pl(&st, 0) != PS || ntx_store_pl(&st, 1) != PS || ntx_store_pl(&st, 2) != 7232)
        fail("pl");
    size_t off = 0;
    for (uint32_t i = 0; i < st.np; i++) {
        uint32_t pl = ntx_store_pl(&st, i);
        if (ntx_store_read(&st, i, 0, rb + off, pl) != (int)pl) fail("read");
        if (memcmp(rb + off, pat + off, pl) != 0) fail("read_match");
        off += pl;
    }
    if (off != SIZE) fail("read_total");
    if (ntx_store_read(&st, 0, 1024, rb, 4096) != 4096 || memcmp(rb, pat + 1024, 4096) != 0)
        fail("read_offset");
    if (ntx_store_read(&st, 2, 0, rb, 7233) != -1) fail("read_overrun");
    printf("PASS read\n");

    static uint8_t junk[16];
    memset(junk, 0xAB, sizeof junk);
    if (ntx_store_write(&st, 0, 0, junk, sizeof junk) != -1) fail("write_rejected");
    if (ntx_store_write(&st, 2, 0, junk, sizeof junk) != -1) fail("write_rejected_last");
    for (uint32_t i = 0; i < st.np; i++)
        if (ntx_store_pmap(&st, i) != 0) fail("pmap_after_write");
    if (ntx_store_verified_bytes(&st) != 0) fail("verified_bytes");
    printf("PASS write_rejected\n");

    ntx_store_close(&st);
    if (fcntl(fd, F_GETFD) == -1) fail("fd_still_open");
    if (st.parts != NULL) fail("close_parts");

    uint8_t h_after[20];
    if (file_sha1(PATH, h_after) != 0) fail("sha1_after");
    if (memcmp(h_before, h_after, 20) != 0) fail("file_unchanged");

    if (fcntl(fd, F_GETFD) == -1) fail("fd_after_close");
    close(fd);
    printf("PASS fd_kept_file_intact\n");

    na = list_dir(after, 512);
    if (na < 0) fail("list_after");
    for (int i = 0, j = 0; i < nb || j < na;) {
        int cmp;
        if (j >= na || (i < nb && (cmp = strcmp(before[i], after[j])) < 0)) {
            if (ours(before[i])) fail("file_removed");
            i++;
        } else if (i >= nb || (cmp = strcmp(before[i], after[j])) > 0) {
            if (ours(after[j])) fail("new_file");
            j++;
        } else {
            i++;
            j++;
        }
    }
    printf("PASS no_new_file\n");

    unlink(PATH);

    /* bad arguments refused, caller's fd left alone */
    fd = open("/etc/hostname", O_RDONLY);
    if (fd < 0) fail("setup_probe");
    if (ntx_store_open_ro_fd(&st, -1, SIZE, PS) != -1) fail("bad_fd");
    if (ntx_store_open_ro_fd(&st, fd, 0, PS) != -1) fail("zero_size");
    if (ntx_store_open_ro_fd(&st, fd, SIZE, 0) != -1) fail("zero_ps");
    if (ntx_store_open_ro_fd(&st, fd, SIZE, PS) != 0) fail("probe_open");
    ntx_store_close(&st);
    if (fcntl(fd, F_GETFD) == -1) fail("probe_fd_kept");
    close(fd);
    printf("PASS bad_args\n");

    /* A5 extension: a decoy file that already exists must be provably untouched
     * by the read-only store — same mtime (both clocks) and same bytes — while
     * every write API on that store fails. No new file under test/ is created
     * for this: the decoy is a tracked source file of the suite. */
    {
        static const char *decoys[] = {"test/t_store_ro.c", "test/t_store_ro.c"};
        const char *dp = decoys[0];
        struct stat d0;
        if (stat(dp, &d0) != 0) fail("decoy_stat");
        int dfd = open(dp, O_RDONLY);
        if (dfd < 0) fail("decoy_open");
        off_t dlen = lseek(dfd, 0, SEEK_END);
        if (dlen <= 0) fail("decoy_len");
        static uint8_t dbuf[1 << 16];
        if (dlen > (off_t)sizeof dbuf) dlen = (off_t)sizeof dbuf;
        if (pread(dfd, dbuf, (size_t)dlen, 0) != dlen) fail("decoy_read");

        ntx_store dst;
        if (ntx_store_open_ro_fd(&dst, dfd, (uint64_t)dlen, PS) != 0) fail("decoy_ro_open");
        if (dst.ro != 1) fail("decoy_ro_flag");
        static uint8_t junk[4096];
        memset(junk, 0x5A, sizeof junk);
        for (uint32_t i = 0; i < dst.np; i++)
            if (ntx_store_write(&dst, i, 0, junk, sizeof junk) != -1) fail("decoy_write_allowed");
        if (ntx_store_complete(&dst, 0, junk) != 0) fail("decoy_complete_claimed");
        for (uint32_t i = 0; i < dst.np; i++)
            if (ntx_store_pmap(&dst, i) != 0) fail("decoy_pmap_touched");
        if (ntx_store_verified_bytes(&dst) != 0) fail("decoy_verified");
        ntx_store_close(&dst);
        if (fcntl(dfd, F_GETFD) == -1) fail("decoy_fd_closed");

        struct stat d1;
        if (stat(dp, &d1) != 0) fail("decoy_stat2");
        if (d1.st_size != d0.st_size || d1.st_mtime != d0.st_mtime ||
            d1.st_mtim.tv_nsec != d0.st_mtim.tv_nsec || d1.st_ctim.tv_nsec != d0.st_ctim.tv_nsec ||
            d1.st_ctim.tv_sec != d0.st_ctim.tv_sec || d1.st_ino != d0.st_ino)
            fail("decoy_mtime_changed");
        static uint8_t again[1 << 16];
        int d2 = open(dp, O_RDONLY);
        if (d2 < 0 || read(d2, again, (size_t)dlen) != dlen) fail("decoy_reread");
        close(d2);
        if (memcmp(again, dbuf, (size_t)dlen) != 0) fail("decoy_bytes_changed");
        close(dfd);
        printf("PASS decoy_untouched\n");
    }

    return 0;
}
