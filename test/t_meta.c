#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/ui/ntx_diag.c"

/* split-out module sources, included directly */
#include "../src/proto/ntx_utmeta.c"

static int g_fail;

static void expect(const char *name, int ok) {
    if (ok)
        printf("PASS %s\n", name);
    else {
        printf("FAIL %s\n", name);
        g_fail = 1;
    }
}

static uint32_t meta_size_for_pieces(unsigned np) {
    if (np == 0) return 0;
    if (np == 1) return 512u;
    return (np - 1u) * NTX_UT_META_PIECE + 100u;
}

static void test_assemble(unsigned np) {
    uint32_t total = meta_size_for_pieces(np);
    uint8_t *src = calloc(total, 1);
    uint8_t *asm_buf = calloc(total, 1);
    if (!src || !asm_buf) {
        free(src);
        free(asm_buf);
        expect("assemble-alloc", 0);
        return;
    }
    for (uint32_t i = 0; i < total; i++) src[i] = (uint8_t)(i * 13u + 7u);

    uint8_t info_hash[20];
    ntx_sha1(src, total, info_hash);

    expect("npieces-count", ntx_ut_metadata_npieces(total) == np);

    uint32_t got_np = ntx_ut_metadata_npieces(total);
    for (uint32_t piece = 0; piece < got_np; piece++) {
        uint32_t off = piece * NTX_UT_META_PIECE;
        uint32_t dlen = total - off;
        if (dlen > NTX_UT_META_PIECE) dlen = NTX_UT_META_PIECE;

        uint8_t payload[17000];
        size_t pn = 0;
        if (ntx_ut_metadata_data_build(payload, &pn, piece, total, src + off, dlen) != 0) {
            expect("assemble-build", 0);
            free(src);
            free(asm_buf);
            return;
        }
        int mt;
        uint32_t pc, ts;
        const uint8_t *data;
        size_t rxlen;
        if (ntx_ut_metadata_parse(payload, pn, &mt, &pc, &ts, &data, &rxlen) != 0 || mt != NTX_UT_METADATA_DATA ||
            pc != piece || ts != total || rxlen != dlen) {
            expect("assemble-parse", 0);
            free(src);
            free(asm_buf);
            return;
        }
        if (ntx_ut_metadata_piece_write(asm_buf, total, piece, data, rxlen) != 0) {
            expect("assemble-write", 0);
            free(src);
            free(asm_buf);
            return;
        }
    }

    char tag[32];
    snprintf(tag, sizeof tag, "assemble-%u-match", np);
    expect(tag, memcmp(src, asm_buf, total) == 0);

    uint8_t got_hash[20];
    ntx_sha1(asm_buf, total, got_hash);
    snprintf(tag, sizeof tag, "assemble-%u-hash", np);
    expect(tag, memcmp(got_hash, info_hash, 20) == 0);

    uint8_t wrong[20];
    memcpy(wrong, info_hash, 20);
    wrong[0] ^= 0xFF;
    snprintf(tag, sizeof tag, "assemble-%u-bad-hash", np);
    expect(tag, memcmp(got_hash, wrong, 20) != 0);

    free(src);
    free(asm_buf);
}

static void test_piece_bounds(void) {
    uint8_t buf[32];
    expect("write-bad-piece", ntx_ut_metadata_piece_write(buf, 100, 99, (const uint8_t *)"x", 1) == -1);
    expect("write-zero-total", ntx_ut_metadata_piece_write(buf, 0, 0, (const uint8_t *)"x", 1) == -1);
    expect("npieces-zero", ntx_ut_metadata_npieces(0) == 0);
    expect("npieces-one", ntx_ut_metadata_npieces(1) == 1);
    expect("npieces-edge", ntx_ut_metadata_npieces(NTX_UT_META_PIECE) == 1);
    expect("npieces-edge2", ntx_ut_metadata_npieces(NTX_UT_META_PIECE + 1) == 2);
}

int main(void) {
    test_piece_bounds();
    test_assemble(1);
    test_assemble(2);
    test_assemble(10);
    return g_fail ? 1 : 0;
}
