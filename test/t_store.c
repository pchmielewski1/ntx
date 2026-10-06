#include "../src/core/ntx_store.c"
#include "../src/proto/ntx_bencode.c" /* (ntx_be_dict_get) */
#include "../src/crypto/ntx_sha1.c"
#include "../src/ui/ntx_diag.c"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SIZE 100000ULL
#define PS 16384U
#define PATH "test/store_test.tmp"
#define T1 "test/t1_store.tmp"
#define T1P1 "test/t1p1.tmp"
#define T1P2 "test/t1p2.tmp"

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

int main(void) {
    ntx_store st;
    unlink(T1);
    unlink(T1P1);
    unlink(T1P2);
    if (ntx_store_open(&st, PATH, SIZE, PS) != 0) fail("open");
    if (st.np != 7) fail("np");
    printf("PASS open\n");

    for (uint32_t i = 0; i < 6; i++)
        if (ntx_store_pl(&st, i) != 16384) fail("pl");
    if (ntx_store_pl(&st, 6) != 1696) fail("pl_last");
    printf("PASS pl\n");

    static uint8_t pat[PS];
    for (uint32_t i = 0; i < PS; i++) pat[i] = (uint8_t)(i * 7 + 3);
    if (ntx_store_write(&st, 0, 0, pat, PS) != 0) fail("write");
    if (ntx_store_pmap(&st, 0) != 1) fail("pmap_partial");
    printf("PASS write_partial\n");

    uint8_t h[20];
    ntx_sha1(pat, PS, h);
    if (ntx_store_complete(&st, 0, h) != 1) fail("complete_ok");
    if (ntx_store_pmap(&st, 0) != 2) fail("pmap_verified");
    printf("PASS complete_ok\n");

    static uint8_t wrong[PS];
    for (uint32_t i = 0; i < PS; i++) wrong[i] = (uint8_t)(i + 1);
    if (ntx_store_write(&st, 1, 0, wrong, PS) != 0) fail("write_wrong");
    uint8_t wh[20];
    ntx_sha1(h, 20, wh);
    if (ntx_store_complete(&st, 1, wh) != 0) fail("complete_bad");
    if (ntx_store_pmap(&st, 1) != 0) fail("pmap_missing");
    printf("PASS complete_bad\n");

    static uint8_t rb[PS];
    if (ntx_store_read(&st, 0, 0, rb, PS) != (int)PS) fail("read");
    if (memcmp(rb, pat, PS) != 0) fail("read_match");
    printf("PASS read_back\n");

    if (ntx_store_verified_bytes(&st) != 16384) fail("verified_bytes");
    printf("PASS verified_bytes\n");

    ntx_store_close(&st);
    unlink(PATH);

    struct stat s;
    int fd;

    /* t1a: fresh open */
    if (ntx_store_open(&st, T1, SIZE, PS) != 0) fail("t1a_open");
    if (st.existed != 0) fail("t1a_existed");
    if (fstat(st.fd, &s) < 0 || (uint64_t)s.st_size != SIZE) fail("t1a_size");
    for (uint32_t i = 0; i < st.np; i++)
        if (ntx_store_pmap(&st, i) != 0) fail("t1a_pmap");
    if (ntx_store_write(&st, 0, 0, pat, PS) != 0) fail("t1a_write1");
    if (ntx_store_write(&st, 1, 0, wrong, PS) != 0) fail("t1a_write2");
    printf("PASS t1a_fresh\n");
    ntx_store_close(&st);

    /* t1b: reopen preserves data */
    if (ntx_store_open(&st, T1, SIZE, PS) != 0) fail("t1b_open");
    if (st.existed != 1) fail("t1b_existed");
    if (fstat(st.fd, &s) < 0 || (uint64_t)s.st_size != SIZE) fail("t1b_size");
    if (ntx_store_read(&st, 0, 0, rb, PS) != (int)PS || memcmp(rb, pat, PS) != 0)
        fail("t1b_pattern");
    if (ntx_store_read(&st, 1, 0, rb, PS) != (int)PS || memcmp(rb, wrong, PS) != 0)
        fail("t1b_pattern2");
    printf("PASS t1b_reopen\n");
    ntx_store_close(&st);

    /* t1c: larger file not truncated */
    fd = open(T1, O_RDWR);
    if (fd < 0 || ftruncate(fd, (off_t)(SIZE * 2)) < 0) fail("t1c_setup");
    close(fd);
    fd = open(T1, O_WRONLY);
    if (fd < 0) fail("t1c_write");
    if (pwrite(fd, &s, 1, (off_t)(SIZE / 2)) != 1) fail("t1c_write2");
    close(fd);
    if (ntx_store_open(&st, T1, SIZE, PS) != 0) fail("t1c_open");
    if (st.existed != 1) fail("t1c_existed");
    if (fstat(st.fd, &s) < 0 || (uint64_t)s.st_size != SIZE * 2) fail("t1c_kept");
    printf("PASS t1c_larger\n");
    ntx_store_close(&st);

    /* t1d: smaller file extended */
    fd = open(T1, O_RDWR);
    if (fd < 0 || ftruncate(fd, 1000) < 0) fail("t1d_setup");
    close(fd);
    if (ntx_store_open(&st, T1, SIZE, PS) != 0) fail("t1d_open");
    if (st.existed != 1) fail("t1d_existed");
    if (fstat(st.fd, &s) < 0 || (uint64_t)s.st_size != SIZE) fail("t1d_size");
    printf("PASS t1d_smaller\n");
    ntx_store_close(&st);

    /* t1e: multi-file, one exact + one too long -> existed==0, nothing cut */
    fd = open(T1P1, O_RDWR | O_CREAT, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)SIZE) < 0) fail("t1e_setup1");
    close(fd);
    fd = open(T1P2, O_RDWR | O_CREAT, 0644);
    if (fd < 0 || ftruncate(fd, (off_t)(SIZE * 2)) < 0) fail("t1e_setup2");
    close(fd);
    ntx_store_part_spec specs[2] = {{T1P1, 0, SIZE}, {T1P2, SIZE, SIZE}};
    if (ntx_store_open_parts(&st, specs, 2, SIZE * 2, PS) != 0) fail("t1e_open");
    if (st.existed != 1) fail("t1e_existed");
    if (fstat(st.parts[0].fd, &s) < 0 || (uint64_t)s.st_size != SIZE) fail("t1e_p1");
    if (fstat(st.parts[1].fd, &s) < 0 || (uint64_t)s.st_size != SIZE * 2) fail("t1e_p2");
    printf("PASS t1e_mixed\n");
    ntx_store_close(&st);
    unlink(T1);
    unlink(T1P1);
    unlink(T1P2);
    return 0;
}
