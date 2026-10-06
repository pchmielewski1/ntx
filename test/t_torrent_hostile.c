/* Security audit: metainfo comes from the network (magnet -> ut_metadata) or from a file of unknown
 * origin.  Inconsistent sizes must be rejected before they size allocations or index arrays: piece
 * count vs. total size, absurd piece lengths, 64-bit wrap in the multi-file length sum. */
#include "../src/core/ntx_torrent.c"
#include "../src/core/ntx_torrent_meta.c"
#include "../src/core/ntx_torrent_v2.c"
#include "../src/core/ntx_torrent_v2_layers.c"
#include "../src/core/ntx_merkle.c"
#include "../src/core/ntx_store.c"
#include "../src/core/ntx_peer.c"
#include "../src/net/ntx_addr.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/ui/ntx_diag.c"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define DIR "test/.scratch/torrent_hostile"

static int g_fail;

static void check(int cond, const char *name) {
    printf("%s %s\n", cond ? "PASS" : "FAIL", name);
    if (!cond) g_fail = 1;
}

/* info dict: "<mid>" is spliced between piece length and pieces; npieces random 20-byte hashes */
static size_t build(uint8_t *out, size_t cap, const char *head, int npieces, const char *tail) {
    size_t o = (size_t)snprintf((char *)out, cap, "d%s6:pieces%d:", head, npieces * 20);
    memset(out + o, 0x5a, (size_t)npieces * 20);
    o += (size_t)npieces * 20;
    o += (size_t)snprintf((char *)out + o, cap - o, "%se", tail);
    return o;
}

static int try_info(const uint8_t *info, size_t n) {
    ntx_torrent t;
    uint8_t ih[20];
    ntx_sha1(info, n, ih);
    ntx_torrent_init_meta(&t, ih);
    int rc = ntx_torrent_set_metainfo(&t, info, n, DIR, NULL);
    if (rc == 0) tt_free(&t);
    return rc;
}

int main(void) {
    mkdir("test/.scratch", 0755);
    mkdir(DIR, 0755);
    static uint8_t info[4096];
    size_t n;

    /* sane baseline: 100000 bytes / 16384 = 7 pieces */
    n = build(info, sizeof info, "6:lengthi100000e4:name4:good12:piece lengthi16384e", 7, "");
    check(try_info(info, n) == 0, "baseline-accepted");
    unlink(DIR "/good");

    /* fewer hashes than the size needs: later pieces would index past phash/have */
    n = build(info, sizeof info, "6:lengthi100000e4:name3:few12:piece lengthi16384e", 1, "");
    check(try_info(info, n) != 0, "too-few-piece-hashes-rejected");
    /* more hashes than the size needs */
    n = build(info, sizeof info, "6:lengthi100000e4:name4:many12:piece lengthi16384e", 20, "");
    check(try_info(info, n) != 0, "too-many-piece-hashes-rejected");
    /* piece length that truncates to a small uint32 */
    n = build(info, sizeof info, "6:lengthi100000e4:name5:trunc12:piece lengthi4294983680e", 7, "");
    check(try_info(info, n) != 0, "piece-length-truncating-rejected");
    /* huge piece length (a single piece would be a multi-GiB buffer) */
    n = build(info, sizeof info, "6:lengthi100000e4:name3:big12:piece lengthi2147483648e", 1, "");
    check(try_info(info, n) != 0, "piece-length-2GiB-rejected");
    /* total of the file lengths wraps 2^64 down to a tiny number */
    n = build(info, sizeof info,
              "5:filesld6:lengthi9223372036854775807e4:pathl1:aeed6:lengthi9223372036854775807e4:pathl1:beed6:"
              "lengthi4e4:pathl1:ceee4:name4:wrap12:piece lengthi16384e",
              1, "");
    check(try_info(info, n) != 0, "file-length-sum-wrap-rejected");

    /* BEP52 pure v2: piece length / file length that overflow the 32-bit piece bookkeeping */
    {
        static const struct { const char *flen, *plen; int ok; } cases[] = {
            {"100", "16384", 1},
            {"100", "4294967296", 0},          /* 2^32 truncates to a zero piece length */
            {"100", "2147483648", 0},          /* 2 GiB pieces */
            {"100", "17592186044416", 0},
            {"4611686018427387904", "16384", 0}, /* 2^62 bytes -> 2^48 pieces: piece count wraps uint32 */
            {"9223372036854775807", "16384", 0},
        };
        for (size_t k = 0; k < sizeof cases / sizeof cases[0]; k++) {
            ntx_torrent t;
            size_t o = 0;
            o += (size_t)snprintf((char *)info + o, sizeof info - o, "d9:file treed1:ad0:d6:lengthi%se11:pieces root32:",
                                  cases[k].flen);
            memset(info + o, 0x77, 32);
            o += 32;
            o += (size_t)snprintf((char *)info + o, sizeof info - o, "eee12:meta versioni2e4:name1:a12:piece lengthi%see",
                                  cases[k].plen);
            uint8_t ih[20] = {0};
            ntx_torrent_init_meta(&t, ih);
            ntx_sha256(info, o, t.info_hash_v2);
            memcpy(t.info_hash, t.info_hash_v2, 20);
            int rc = ntx_torrent_set_metainfo(&t, info, o, DIR, NULL);
            if (rc == 0) tt_free(&t);
            char nm[96];
            snprintf(nm, sizeof nm, "v2-len-%s-piece-%s-%s", cases[k].flen, cases[k].plen, cases[k].ok ? "accepted" : "rejected");
            check(cases[k].ok ? rc == 0 : rc != 0, nm);
            if (rc == 0) unlink(DIR "/a");
        }
    }

    rmdir(DIR);
    return g_fail;
}
