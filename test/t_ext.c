#include <stdio.h>
#include <string.h>

#include "../src/proto/ntx_ext.c"
#include "../src/proto/ntx_bencode.c"
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

int main(void) {
    {
        uint8_t out[64];
        size_t total = ntx_ext_msg_build(out, sizeof out, 1, (const uint8_t *)"hello", 5);
        uint32_t len = ntx_wire_rd32(out);
        expect("framing-build", total == 11 && len == 7 && out[4] == 0x14 && out[5] == 1 &&
                                memcmp(out + 6, "hello", 5) == 0);
        {
            uint8_t ext_id = 0;
            const uint8_t *payload;
            size_t plen = 0;
            int rc = ntx_ext_msg_parse(out, total, &ext_id, &payload, &plen);
            expect("framing-parse", rc == 0 && ext_id == 1 && plen == 5 && memcmp(payload, "hello", 5) == 0);
        }
        {
            uint8_t short_buf[5] = {0, 0, 0, 6, 0x14};
            uint8_t eid;
            const uint8_t *pl2;
            size_t pln2;
            expect("framing-parse-short", ntx_ext_msg_parse(short_buf, 5, &eid, &pl2, &pln2) == -1);
        }
    }

    {
        const char *names[1] = {"ut_metadata"};
        uint8_t ids[1] = {1};
        uint8_t out[256];
        size_t outn = 0;
        ntx_ext_handshake_build(out, &outn, names, ids, 1, 0, 6881, "ntx/1.0");
        {
            ntx_be be;
            size_t consumed;
            int rc = ntx_be_parse(out, outn, &be, &consumed, 16, outn);
            const ntx_be *ms = (rc == 0 && be.t == NTX_BE_DICT) ? ntx_be_dict_get(&be, "metadata_size") : 0;
            expect("handshake-no-meta-size", rc == 0 && be.t == NTX_BE_DICT && !ms);
            ntx_be_free(&be);
        }
        {
            uint8_t pids[8];
            const char *pn[8];
            int pn_ext = 0;
            int pms = 99;
            int prc = ntx_ext_handshake_parse(out, outn, pids, 8, pn, &pn_ext, &pms);
            expect("handshake-parse-no-meta-size", prc == 0 && pn_ext == 1 && pms == 0);
            for (int i = 0; i < pn_ext; i++) free((void *)pn[i]);
        }
    }

    {
        const char *names[2] = {"ut_metadata", "ut_pex"};
        uint8_t ids[2] = {1, 2};
        uint8_t out[256];
        size_t outn = 0;
        ntx_ext_handshake_build(out, &outn, names, ids, 2, 100, 6881, "ntx/1.0");
        {
            ntx_be be;
            size_t consumed;
            int rc = ntx_be_parse(out, outn, &be, &consumed, 16, outn);
            int ok = (rc == 0 && be.t == NTX_BE_DICT);
            const ntx_be *m = ok ? ntx_be_dict_get(&be, "m") : 0;
            const ntx_be *ms = ok ? ntx_be_dict_get(&be, "metadata_size") : 0;
            ok = ok && m && m->t == NTX_BE_DICT;
            const ntx_be *um = (ok && m) ? ntx_be_dict_get(m, "ut_metadata") : 0;
            const ntx_be *up = (ok && m) ? ntx_be_dict_get(m, "ut_pex") : 0;
            ok = ok && um && um->t == NTX_BE_INT && um->i == 1 && up && up->t == NTX_BE_INT && up->i == 2;
            ok = ok && ms && ms->t == NTX_BE_INT && ms->i == 100;
            expect("handshake-build", ok);
            ntx_be_free(&be);
        }
        {
            uint8_t pids[8];
            const char *pn[8];
            int pn_ext = 0;
            int pms = 0;
            int prc = ntx_ext_handshake_parse(out, outn, pids, 8, pn, &pn_ext, &pms);
            expect("handshake-parse", prc == 0 && pn_ext == 2 && strcmp(pn[0], "ut_metadata") == 0 &&
                                    pids[0] == 1 && strcmp(pn[1], "ut_pex") == 0 && pids[1] == 2 && pms == 100);
            for (int i = 0; i < pn_ext; i++) free((void *)pn[i]);
        }
    }

    {
        uint8_t out[64];
        size_t outn = 0;
        int rc = ntx_ut_metadata_request_build(out, &outn, 3);
        {
            ntx_be be;
            size_t consumed;
            int prc = ntx_be_parse(out, outn, &be, &consumed, 16, outn);
            int ok = (rc == 0 && prc == 0 && be.t == NTX_BE_DICT);
            const ntx_be *mt = ok ? ntx_be_dict_get(&be, "msg_type") : 0;
            const ntx_be *pc = ok ? ntx_be_dict_get(&be, "piece") : 0;
            ok = ok && mt && mt->t == NTX_BE_INT && mt->i == 0 && pc && pc->t == NTX_BE_INT && pc->i == 3;
            expect("utmeta-request-build", ok);
            ntx_be_free(&be);
        }
        {
            int mt;
            uint32_t pc, ts;
            const uint8_t *data;
            size_t dlen;
            int prc2 = ntx_ut_metadata_parse(out, outn, &mt, &pc, &ts, &data, &dlen);
            expect("utmeta-request-parse", prc2 == 0 && mt == 0 && pc == 3);
        }
    }

    {
        uint8_t data[100];
        for (int i = 0; i < 100; i++) data[i] = (uint8_t)(i * 3 + 1);
        uint8_t out[512];
        size_t outn = 0;
        int rc = ntx_ut_metadata_data_build(out, &outn, 0, 100, data, 100);
        {
            ntx_be be;
            size_t consumed;
            int prc = ntx_be_parse(out, outn - 100, &be, &consumed, 16, outn - 100);
            int ok = (rc == 0 && outn == consumed + 100 && prc == 0 && be.t == NTX_BE_DICT);
            const ntx_be *mt = ok ? ntx_be_dict_get(&be, "msg_type") : 0;
            const ntx_be *pc = ok ? ntx_be_dict_get(&be, "piece") : 0;
            const ntx_be *ts = ok ? ntx_be_dict_get(&be, "total_size") : 0;
            ok = ok && mt && mt->t == NTX_BE_INT && mt->i == 1 && pc && pc->t == NTX_BE_INT && pc->i == 0 &&
                 ts && ts->t == NTX_BE_INT && ts->i == 100;
            ok = ok && consumed == outn - 100 && memcmp(out + consumed, data, 100) == 0;
            expect("utmeta-data-build", ok);
            ntx_be_free(&be);
        }
        {
            int mt;
            uint32_t pc, ts;
            const uint8_t *pdata;
            size_t pdlen;
            int prc2 = ntx_ut_metadata_parse(out, outn, &mt, &pc, &ts, &pdata, &pdlen);
            expect("utmeta-data-parse", prc2 == 0 && mt == 1 && pc == 0 && ts == 100 && pdlen == 100 &&
                                    memcmp(pdata, data, 100) == 0);
        }
    }

    {
        uint8_t out[64];
        size_t outn = 0;
        int rc = ntx_ut_metadata_reject_build(out, &outn, 5);
        {
            ntx_be be;
            size_t consumed;
            int prc = ntx_be_parse(out, outn, &be, &consumed, 16, outn);
            int ok = (rc == 0 && prc == 0 && be.t == NTX_BE_DICT);
            const ntx_be *mt = ok ? ntx_be_dict_get(&be, "msg_type") : 0;
            const ntx_be *pc = ok ? ntx_be_dict_get(&be, "piece") : 0;
            ok = ok && mt && mt->t == NTX_BE_INT && mt->i == 2 && pc && pc->t == NTX_BE_INT && pc->i == 5;
            expect("utmeta-reject-build", ok);
            ntx_be_free(&be);
        }
        {
            int mt;
            uint32_t pc, ts;
            const uint8_t *data;
            size_t dlen;
            int prc2 = ntx_ut_metadata_parse(out, outn, &mt, &pc, &ts, &data, &dlen);
            expect("utmeta-reject-parse", prc2 == 0 && mt == 2 && pc == 5);
        }
    }

    {
        static const uint8_t bep10_full[] =
            "d1:md11:ut_metadatai1ee1:pi6881e1:v4:nano13:metadata_sizei32768e"
            "6:yourip4:abcd4:ipv44:wxyz4:ipv616:0123456789abcdef4:reqqi250ee";
        uint8_t pids[8];
        const char *pn[8];
        int pn_ext = 0;
        int pms = 0;
        int prc = ntx_ext_handshake_parse(bep10_full, sizeof bep10_full - 1, pids, 8, pn, &pn_ext, &pms);
        expect("handshake-parse-bep10-full", prc == 0 && pn_ext == 1 && strcmp(pn[0], "ut_metadata") == 0 &&
                                                pids[0] == 1 && pms == 32768);
        for (int i = 0; i < pn_ext; i++) free((void *)pn[i]);
    }

    {
        uint8_t junk[3] = {0x01, 0x02, 0x03};
        int mt;
        uint32_t pc, ts;
        const uint8_t *data;
        size_t dlen;
        expect("utmeta-parse-nondict", ntx_ut_metadata_parse(junk, 3, &mt, &pc, &ts, &data, &dlen) == -1);
    }

    /* ---- hostile ut_metadata / extended-handshake values (security audit) ---- */
    {
        int mt = 0;
        uint32_t pc = 0, ts = 0;
        const uint8_t *data = NULL;
        size_t dlen = 0;
        static uint8_t big[20000];
        memset(big, 0xAB, sizeof big);
        uint8_t msg[20100];
        size_t n;
#define BUILD(hdr, dn)                                                                      \
    do {                                                                                    \
        n = strlen(hdr);                                                                    \
        memcpy(msg, hdr, n);                                                                \
        memcpy(msg + n, big, (dn));                                                         \
        n += (dn);                                                                          \
    } while (0)
        /* total_size is attacker-controlled and used to size a calloc: cap it */
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei2147483648ee", 16384);
        expect("utmeta-total-2GiB-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei4294967295ee", 16384);
        expect("utmeta-total-4GiB-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei-1ee", 16384);
        expect("utmeta-total-negative-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei16777217ee", 16384);
        expect("utmeta-total-over-16MiB-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei16777216ee", 16384);
        expect("utmeta-total-16MiB-ok", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) == 0 && ts == 16777216u);
        /* piece index must exist, and be non-negative */
        BUILD("d8:msg_typei1e5:piecei-1e10:total_sizei40000ee", 16384);
        expect("utmeta-piece-negative-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei3e10:total_sizei40000ee", 16384);
        expect("utmeta-piece-out-of-range-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        /* a DATA block is exactly 16 KiB, except the last one which is the remainder */
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei40000ee", 10);
        expect("utmeta-short-block-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei40000ee", 16385);
        expect("utmeta-long-block-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
        BUILD("d8:msg_typei1e5:piecei0e10:total_sizei40000ee", 16384);
        expect("utmeta-full-block-ok", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) == 0 && dlen == 16384);
        BUILD("d8:msg_typei1e5:piecei2e10:total_sizei40000ee", 7232);
        expect("utmeta-last-block-ok", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) == 0 && dlen == 7232);
        BUILD("d8:msg_typei1e5:piecei2e10:total_sizei40000ee", 7233);
        expect("utmeta-last-block-long-rejected", ntx_ut_metadata_parse(msg, n, &mt, &pc, &ts, &data, &dlen) != 0);
#undef BUILD
    }
    {
        const char *neg = "d1:md11:ut_metadatai1ee13:metadata_sizei-1ee";
        const char *huge = "d1:md11:ut_metadatai1ee13:metadata_sizei4294967296ee";
        const char *over = "d1:md11:ut_metadatai1ee13:metadata_sizei16777217ee";
        uint8_t ids[8];
        const char *nm[8];
        int ne, ms;
        int rc = ntx_ext_handshake_parse((const uint8_t *)neg, strlen(neg), ids, 8, nm, &ne, &ms);
        expect("exthello-negative-metadata-size-ignored", rc == 0 && ms == 0);
        for (int i = 0; i < ne; i++) free((void *)nm[i]);
        rc = ntx_ext_handshake_parse((const uint8_t *)huge, strlen(huge), ids, 8, nm, &ne, &ms);
        expect("exthello-huge-metadata-size-ignored", rc == 0 && ms == 0);
        for (int i = 0; i < ne; i++) free((void *)nm[i]);
        rc = ntx_ext_handshake_parse((const uint8_t *)over, strlen(over), ids, 8, nm, &ne, &ms);
        expect("exthello-over-cap-metadata-size-ignored", rc == 0 && ms == 0);
        for (int i = 0; i < ne; i++) free((void *)nm[i]);
    }

    return g_fail ? 1 : 0;
}
