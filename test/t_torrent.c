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
#include <unistd.h>

#define PS 16384U
#define SIZE 100000ULL
#define NP 7U
#define STORE_PATH "downloads/test"

static int fail(const char *name) {
    fprintf(stderr, "FAIL %s\n", name);
    exit(1);
}

static uint32_t g_have_piece = 0xFFFFFFFFu;

static void on_have_cb(ntx_torrent *tt, uint32_t piece, void *ctx) {
    (void)tt;
    (void)ctx;
    g_have_piece = piece;
}

int main(void) {
    unlink(STORE_PATH);
    static uint8_t pat[PS];
    for (uint32_t i = 0; i < PS; i++) pat[i] = (uint8_t)(i * 7 + 3);
    uint8_t h0[20];
    ntx_sha1(pat, PS, h0);

    static uint8_t pieces[NP * 20];
    memcpy(pieces, h0, 20);
    for (unsigned i = 20; i < NP * 20; i++) pieces[i] = (uint8_t)(i * 5 + 1);

    static uint8_t info[512];
    int n = snprintf((char *)info, sizeof(info), "d12:piece lengthi%ue6:pieces%u:", PS, (unsigned)sizeof(pieces));
    memcpy(info + n, pieces, sizeof(pieces));
    n += (int)sizeof(pieces);
    n += snprintf((char *)info + n, sizeof(info) - n, "6:lengthi%llue4:name4:teste", (unsigned long long)SIZE);

    uint8_t info_hash[20];
    ntx_sha1(info, (size_t)n, info_hash);

    ntx_torrent t;
    ntx_torrent_init_meta(&t, info_hash);
    if (t.state != NTX_TTS_META || t.have_meta != 0) fail("init_meta");
    printf("PASS init_meta\n");

    if (ntx_torrent_set_metainfo(&t, info, (size_t)n, "downloads", NULL) != 0) fail("set_metainfo");
    if (t.state != NTX_TTS_DL || t.have_meta != 1) fail("metainfo_state");
    if (t.ps != PS || t.np != NP || t.size != SIZE) fail("metainfo_fields");
    if (strcmp(t.name, "test") != 0) fail("metainfo_name");
    printf("PASS set_metainfo\n");

    uint8_t wrong[20];
    memcpy(wrong, info_hash, 20);
    wrong[0] ^= 0xFF;
    ntx_torrent t2;
    ntx_torrent_init_meta(&t2, wrong);
    if (ntx_torrent_set_metainfo(&t2, info, (size_t)n, "downloads", NULL) != -1) fail("hash_mismatch");
    printf("PASS hash_mismatch\n");

    if (ntx_store_write(&t.store, 0, 0, pat, PS) != 0) fail("store_write");
    if (ntx_torrent_piece_complete(&t, 0) != 1) fail("piece_complete");
    if (t.have[0] != 1 || t.have_n != 1 || t.verified_B != PS) fail("piece_state");
    if (ntx_torrent_verified_bytes(&t) != PS) fail("verified_bytes");
    printf("PASS piece_complete\n");

    g_have_piece = 0xFFFFFFFFu;
    t.on_piece_have = on_have_cb;
    if (ntx_torrent_piece_complete(&t, 0) != 1) fail("piece_complete_reverify");
    if (g_have_piece != 0) fail("on_piece_have_cb");
    t.on_piece_have = NULL;
    printf("PASS on_piece_have_cb\n");

    static uint8_t bad[PS];
    memset(bad, 0xA5, sizeof(bad));
    if (ntx_store_write(&t.store, 1, 0, bad, PS) != 0) fail("store_write_bad");
    t.store.pmap[1] = 1;
    ntx_peer bad_peer;
    ntx_addr a;
    ntx_addr_set_v4(&a, 0x01020304);
    ntx_peer_init(&bad_peer, -1, &a, 6881, (int)NP);
    bad_peer.we_choke = 0;
    bad_peer.spd_d = 1234.0;
    uint64_t now = 1000000;
    if (ntx_torrent_piece_complete_from(&t, 1, &bad_peer, now) != 0) fail("piece_hash_fail");
    if (t.have[1] != 0 || t.store.pmap[1] != 0) fail("piece_cleared");
    if (bad_peer.we_choke != 1 || bad_peer.spd_d != 0.0) fail("peer_ban_flags");
    if (!ntx_torrent_peer_banned(&bad_peer, now)) fail("peer_banned_now");
    if (ntx_torrent_peer_banned(&bad_peer, now + NTX_TORRENT_PEER_BAN_MS)) fail("peer_banned_expired");
    ntx_peer_free(&bad_peer);
    printf("PASS piece_hash_fail\n");

    t.rarity[1] = 1;
    t.rarity[2] = 2;
    if (ntx_torrent_pick(&t) != 1) fail("pick_min_rarity");
    t.have[1] = 1;
    if (ntx_torrent_pick(&t) != 2) fail("pick_next");
    printf("PASS pick\n");

    ntx_torrent_on_peer_have(&t, 3);
    if (t.rarity[3] != 1) fail("on_peer_have");
    printf("PASS on_peer_have\n");

    t.rarity[1] = 2;
    t.rarity[2] = 1;
    ntx_peer p;
    ntx_addr a0;
    ntx_addr_clear(&a0);
    ntx_peer_init(&p, -1, &a0, 0, (int)NP);
    ntx_peer_set_phave(&p, 1, 1);
    ntx_peer_set_phave(&p, 2, 1);
    ntx_torrent_on_peer_lost(&t, &p);
    if (t.rarity[1] != 1 || t.rarity[2] != 0) fail("on_peer_lost");
    printf("PASS on_peer_lost\n");
    ntx_peer_free(&p);

    for (uint32_t i = 0; i < NP; i++) t.have[i] = 1;
    t.have_n = NP;
    if (ntx_torrent_done(&t) != 1) fail("done");
    printf("PASS done\n");

    ntx_store_close(&t.store);
    unlink(STORE_PATH);

    /* ---- ntx_torrent_verify_range (t2a-t2d) ---- */
    #define T2D "test/t2_store"
    #define T2F1 "test/t2_store/f1"
    #define T2F2 "test/t2_store/f2"
    static uint8_t t2buf[PS];
    uint8_t t2h[20];

    /* t2a: single-file, 5 pieces, 3 known-correct on disk */
    mkdir(T2D, 0755);
    unlink(T2D "/a");
    unlink(T2F1);
    unlink(T2F2);
    for (uint32_t i = 0; i < PS; i++) t2buf[i] = (uint8_t)(i * 3 + 1);
    ntx_sha1(t2buf, PS, t2h);
    uint8_t t2h3[20];
    ntx_sha1(t2buf, 848, t2h3);
    static uint8_t t2p[80];
    memcpy(t2p, t2h, 20);
    memcpy(t2p + 2 * 20, t2h, 20);
    memcpy(t2p + 3 * 20, t2h3, 20);
    for (unsigned i = 0; i < 20; i++)
        t2p[i + 20] = (uint8_t)(i * 11 + 7);
    static uint8_t t2info[512];
    int t2n = snprintf((char *)t2info, sizeof(t2info), "d12:piece lengthi%ue6:pieces80:", PS);
    memcpy(t2info + t2n, t2p, 80);
    t2n += 80;
    t2n += snprintf((char *)t2info + t2n, sizeof(t2info) - t2n, "6:lengthi50000e4:name1:ae");
    uint8_t t2ih[20];
    ntx_sha1(t2info, (size_t)t2n, t2ih);
    int t2fd = open(T2D "/a", O_WRONLY | O_CREAT, 0644);
    if (t2fd < 0 || ftruncate(t2fd, 50000) < 0) fail("t2a_setup");
    if (pwrite(t2fd, t2buf, PS, 0) != (ssize_t)PS) fail("t2a_setup");
    if (pwrite(t2fd, t2buf, PS, 2 * (off_t)PS) != (ssize_t)PS) fail("t2a_setup");
    if (pwrite(t2fd, t2buf, 848, 3 * (off_t)PS) != 848) fail("t2a_setup");
    close(t2fd);
    ntx_torrent tv;
    ntx_torrent_init_meta(&tv, t2ih);
    if (ntx_torrent_set_metainfo(&tv, t2info, (size_t)t2n, T2D, NULL) != 0) fail("t2a_meta");
    if (tv.np != 4) fail("t2a_np");
    if (ntx_torrent_verify_range(&tv, 0, 4) != 3) fail("t2a_new");
    if (tv.have_n != 3 || tv.verified_B != (2ULL * PS + 848)) fail("t2a_state");
    for (uint32_t i = 0; i < 4; i++)
        if (tv.store.pmap[i] != ((i == 0 || i == 2 || i == 3) ? 2 : 0)) fail("t2a_pmap");
    if (ntx_torrent_verify_range(&tv, 0, 4) != 0) fail("t2a_idem");
    if (tv.have_n != 3 || tv.verified_B != (2ULL * PS + 848)) fail("t2a_idem2");
    printf("PASS t2a\n");
    ntx_store_close(&tv.store);
    unlink(T2D "/a");

    /* t2b: one corrupted piece */
    t2fd = open(T2D "/a", O_WRONLY | O_CREAT, 0644);
    if (t2fd < 0 || ftruncate(t2fd, 50000) < 0) fail("t2b_setup");
    if (pwrite(t2fd, t2buf, PS, 0) != (ssize_t)PS) fail("t2b_setup");
    if (pwrite(t2fd, t2buf, PS, 2 * (off_t)PS) != (ssize_t)PS) fail("t2b_setup");
    if (pwrite(t2fd, t2buf, 848, 3 * (off_t)PS) != 848) fail("t2b_setup");
    close(t2fd);
    t2fd = open(T2D "/a", O_RDWR);
    uint8_t t2flip = 0;
    if (t2fd < 0 || pread(t2fd, &t2flip, 1, 2 * (off_t)PS + 100) != 1) fail("t2b_setup");
    t2flip ^= 0x01;
    if (pwrite(t2fd, &t2flip, 1, 2 * (off_t)PS + 100) != 1) fail("t2b_setup");
    close(t2fd);
    ntx_torrent_init_meta(&tv, t2ih);
    if (ntx_torrent_set_metainfo(&tv, t2info, (size_t)t2n, T2D, NULL) != 0) fail("t2b_meta");
    if (ntx_torrent_verify_range(&tv, 0, 4) != 2) fail("t2b_new");
    if (tv.have[2] != 0 || tv.store.pmap[2] != 0) fail("t2b_corrupt");
    if (tv.have_n != 2 || tv.verified_B != (PS + 848)) fail("t2b_others");
    printf("PASS t2b\n");
    ntx_store_close(&tv.store);
    unlink(T2D "/a");

    /* t2c: single-file with short last piece (boundary case) */
    static uint8_t t2p3[3 * 20];
    memcpy(t2p3, t2h, 20);
    for (unsigned i = 20; i < 3 * 20; i++) t2p3[i] = (uint8_t)(i * 5 + 2);
    static uint8_t t2m3[500];
    int t2m3n = snprintf((char *)t2m3, sizeof(t2m3),
                         "d12:piece lengthi%ue6:pieces60:", PS);
    memcpy(t2m3 + t2m3n, t2p3, sizeof(t2p3));
    t2m3n += (int)sizeof(t2p3);
    t2m3n += snprintf((char *)t2m3 + t2m3n, sizeof(t2m3) - (size_t)t2m3n,
                      "6:lengthi33000e4:name1:ce");
    uint8_t t2mh3[20];
    ntx_sha1(t2m3, (size_t)t2m3n, t2mh3);
    t2fd = open(T2D "/c", O_WRONLY | O_CREAT, 0644);
    if (t2fd < 0 || ftruncate(t2fd, 33000) < 0) fail("t2c_setup");
    if (pwrite(t2fd, t2buf, PS, 0) != (ssize_t)PS) fail("t2c_setup");
    close(t2fd);
    ntx_torrent t3;
    ntx_torrent_init_meta(&t3, t2mh3);
    if (ntx_torrent_set_metainfo(&t3, t2m3, (size_t)t2m3n, T2D, NULL) != 0) fail("t2c_meta");
    if (t3.np != 3 || t3.size != 33000ULL) fail("t2c_fields");
    if (ntx_torrent_verify_range(&t3, 0, 3) != 1) fail("t2c_new");
    if (t3.have[0] != 1) fail("t2c_have0");
    if (t3.have_n != 1 || t3.verified_B != PS) fail("t2c_state");
    for (uint32_t i = 1; i < 3; i++)
        if (t3.store.pmap[i] != 0 || t3.have[i] != 0) fail("t2c_rest");
    printf("PASS t2c\n");
    ntx_store_close(&t3.store);
    unlink(T2D "/c");
    unlink(T2F1);

    /* t2cm: multi-file, piece 1 (13616 B) spans the part boundary */
    static uint8_t t2A[20000];
    static uint8_t t2B[10000];
    static uint8_t t2P1[13616];
    uint8_t t2hm[40];
    for (unsigned i = 0; i < 20000; i++) t2A[i] = (uint8_t)(i * 5 + 2);
    for (unsigned i = 0; i < 10000; i++) t2B[i] = (uint8_t)(i * 7 + 4);
    ntx_sha1(t2A, 16384, t2hm);
    memcpy(t2P1, t2A + 16384, 3616);
    memcpy(t2P1 + 3616, t2B, 10000);
    ntx_sha1(t2P1, 13616, t2hm + 20);
    static uint8_t t2infoM[768];
    int t2nM = snprintf((char *)t2infoM, sizeof t2infoM,
                        "d5:filesld6:lengthi20000e4:pathl7:f1name1eed6:lengthi10000e4:pathl7:f2name1eee4:name1:t12:piece lengthi16384e6:pieces40:");
    memcpy(t2infoM + t2nM, t2hm, 40);
    t2nM += 40;
    t2nM += snprintf((char *)t2infoM + t2nM, sizeof t2infoM - t2nM, "e");
    uint8_t t2ihM[20];
    ntx_sha1(t2infoM, (size_t)t2nM, t2ihM);
    mkdir(T2D "/t", 0755);
    t2fd = open(T2D "/t/f1name1", O_WRONLY | O_CREAT, 0644);
    if (t2fd < 0 || ftruncate(t2fd, 20000) < 0) fail("t2cm_setup");
    if (pwrite(t2fd, t2A, 20000, 0) != 20000) fail("t2cm_setup");
    close(t2fd);
    t2fd = open(T2D "/t/f2name1", O_WRONLY | O_CREAT, 0644);
    if (t2fd < 0 || ftruncate(t2fd, 10000) < 0) fail("t2cm_setup");
    if (pwrite(t2fd, t2B, 10000, 0) != 10000) fail("t2cm_setup");
    close(t2fd);
    ntx_torrent tm;
    ntx_torrent_init_meta(&tm, t2ihM);
    if (ntx_torrent_set_metainfo(&tm, t2infoM, (size_t)t2nM, T2D, NULL) != 0) fail("t2cm_meta");
    if (tm.np != 2 || tm.size != 30000ULL) fail("t2cm_fields");
    if (ntx_torrent_verify_range(&tm, 0, 2) != 2) fail("t2cm_new");
    if (tm.have_n != 2 || tm.verified_B != 30000ULL) fail("t2cm_state");
    if (tm.store.pmap[0] != 2 || tm.store.pmap[1] != 2) fail("t2cm_pmap");
    printf("PASS t2cm\n");
    ntx_store_close(&tm.store);
    unlink(T2D "/t/f1name1");
    unlink(T2D "/t/f2name1");

    /* t2d: brand-new store, all zeros */
    ntx_torrent_init_meta(&tv, t2ih);
    if (ntx_torrent_set_metainfo(&tv, t2info, (size_t)t2n, T2D, NULL) != 0) fail("t2d_meta");
    if (ntx_torrent_verify_range(&tv, 0, tv.np) != 0) fail("t2d_new");
    if (tv.have_n != 0 || tv.verified_B != 0) fail("t2d_state");
    for (uint32_t i = 0; i < tv.np; i++)
        if (tv.store.pmap[i] != 0 || tv.have[i] != 0) fail("t2d_pmap");
    if (ntx_torrent_verify_range(&tv, 5, 5) != 0) fail("t2d_guard1");
    if (ntx_torrent_verify_range(&tv, 0, 99) != 0) fail("t2d_guard2");
    printf("PASS t2d\n");
    ntx_store_close(&tv.store);
    unlink(T2D "/a");
    #undef T2D
    #undef T2F1
    #undef T2F2
    return 0;
}
