#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "../src/net/ntx_utp_hdr.c"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

static uint8_t *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)(sz > 0 ? sz : 0) + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    buf[sz] = 0; /* NUL-terminated: callers parse the data as text */
    *n = (size_t)sz;
    return buf;
}

/* Decode a hex string (even length) into bytes. 0 on success. */
static int hexbytes(const char *hex, uint8_t *out, size_t cap, size_t *outn) {
    size_t len = strlen(hex);
    if (len % 2 != 0) return 0;
    size_t nb = len / 2;
    if (nb > cap) return 0;
    for (size_t i = 0; i < nb; i++) {
        int hi, lo;
        if (sscanf(hex + 2 * i, "%1x%1x", &hi, &lo) != 2) return 0;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *outn = nb;
    return 1;
}

/* ------------------------------------------------------------------ */
/* vectors.txt: hdr <name> <type> <ver> <ext> <conn> 0x<ts> 0x<tsdiff>
 *              0x<wnd> <seq> <ack> <packed_hex>                       */
static void test_hdr_vectors(void) {
    size_t n;
    char *data = (char *)read_file("test/vectors/utp/header/vectors.txt", &n);
    check(data != NULL, "hdr-vectors-read");
    if (!data) return;
    data[n] = 0;

    uint8_t buf[512];
    char name[64];
    int type, ver, ext, seq, ack;
    unsigned long conn, ts, tsdiff, wnd;
    char packed[512];

    const char *p = data;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char *line = malloc(len + 1);
        if (!line) break;
        memcpy(line, p, len);
        line[len] = 0;
        p = nl ? nl + 1 : line + len;

        int matched = sscanf(line, "hdr %63s %d %d %d %lx %lx %lx %lx %d %d %511s",
                             name, &type, &ver, &ext, &conn, &ts, &tsdiff, &wnd,
                             &seq, &ack, packed);
        if (matched != 11) { free(line); continue; }

        size_t pn = 0;
        int decoded = hexbytes(packed, buf, sizeof buf, &pn);
        char tname[128];

        ntx_utp_hdr h;
        int rc = decoded ? ntx_utp_hdr_parse(buf, pn, &h) : -1;
        int ok = rc == 0 &&
                 (int)h.type == type && (int)h.ver == ver &&
                 (int)h.extension == ext && (uint32_t)h.conn_id == conn &&
                 h.ts_us == ts && h.ts_diff_us == tsdiff && h.wnd_size == wnd &&
                 (int)h.seq_nr == seq && (int)h.ack_nr == ack;
        snprintf(tname, sizeof tname, "hdr-%s-parse", name);
        check(ok, tname);

        /* Write the line's fields and compare to the first 20 bytes of the
         * on-disk packed blob (golden roundtrip). */
        ntx_utp_hdr eh;
        eh.type = (uint8_t)type; eh.ver = (uint8_t)ver;
        eh.extension = (uint8_t)ext; eh.conn_id = (uint16_t)conn;
        eh.ts_us = (uint32_t)ts; eh.ts_diff_us = (uint32_t)tsdiff;
        eh.wnd_size = (uint32_t)wnd; eh.seq_nr = (uint16_t)seq;
        eh.ack_nr = (uint16_t)ack;
        uint8_t wb[32];
        int wrc = ntx_utp_hdr_write(wb, sizeof wb, &eh);
        int wok = wrc == 0 && pn >= NTX_UTP_HDR_LEN &&
                  memcmp(wb, buf, NTX_UTP_HDR_LEN) == 0;
        snprintf(tname, sizeof tname, "hdr-%s-write", name);
        check(wok, tname);
        free(line);
    }
    free(data);
}

/* Self-consistency: write then parse must be an identity (vector-independent). */
static void test_hdr_roundtrip(void) {
    ntx_utp_hdr h;
    h.type = NTX_UTP_ST_DATA; h.ver = NTX_UTP_VER; h.extension = 0;
    h.conn_id = 0x1234; h.ts_us = 1; h.ts_diff_us = 0;
    h.wnd_size = 0x00100000; h.seq_nr = 5; h.ack_nr = 4;
    uint8_t buf[32];
    int wr = ntx_utp_hdr_write(buf, sizeof buf, &h);
    ntx_utp_hdr back;
    int pr = ntx_utp_hdr_parse(buf, NTX_UTP_HDR_LEN, &back);
    check(wr == 0 && pr == 0 &&
          back.type == h.type && back.ver == h.ver &&
          back.extension == h.extension && back.conn_id == h.conn_id &&
          back.ts_us == h.ts_us && back.ts_diff_us == h.ts_diff_us &&
          back.wnd_size == h.wnd_size && back.seq_nr == h.seq_nr &&
          back.ack_nr == h.ack_nr,
          "hdr-roundtrip");
}

static void test_hdr_negatives(void) {
    ntx_utp_hdr h;
    uint8_t b[32];
    memset(b, 0xAB, sizeof b);

    check(ntx_utp_hdr_parse(b, 19, &h) == -1, "hdr-neg-short");

    /* ver = 2 (low nibble of byte 0) */
    uint8_t v2[20];
    memset(v2, 0, sizeof v2);
    v2[0] = (uint8_t)((NTX_UTP_ST_DATA << 4) | 2u);
    check(ntx_utp_hdr_parse(v2, 20, &h) == -1, "hdr-neg-ver2");

    /* type = 5 (high nibble of byte 0) */
    uint8_t t5[20];
    memset(t5, 0, sizeof t5);
    t5[0] = (uint8_t)((5u << 4) | NTX_UTP_VER);
    check(ntx_utp_hdr_parse(t5, 20, &h) == -1, "hdr-neg-type5");

    ntx_utp_hdr ok;
    ok.type = NTX_UTP_ST_DATA; ok.ver = NTX_UTP_VER; ok.extension = 0;
    ok.conn_id = 1; ok.ts_us = 0; ok.ts_diff_us = 0; ok.wnd_size = 0;
    ok.seq_nr = 0; ok.ack_nr = 0;
    uint8_t small[19];
    check(ntx_utp_hdr_write(small, 19, &ok) == -1, "hdr-neg-write-cap19");

    ntx_utp_hdr bad;
    bad = ok; bad.type = 5;
    check(ntx_utp_hdr_write(b, sizeof b, &bad) == -1, "hdr-neg-write-type5");
}

/* ------------------------------------------------------------------ */
/* sack.txt: sack <name> <ack_nr> <offsets_csv> <mask_hex>            */
static void test_sack_vectors(void) {
    size_t n;
    char *data = (char *)read_file("test/vectors/utp/header/sack.txt", &n);
    check(data != NULL, "sack-vectors-read");
    if (!data) return;
    data[n] = 0;

    uint8_t mask[512];
    uint16_t seqs[512];
    char name[64], offsets[256], maskhex[512];
    int ack_nr;

    const char *p = data;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char *line = malloc(len + 1);
        if (!line) break;
        memcpy(line, p, len);
        line[len] = 0;
        p = nl ? nl + 1 : line + len;

        if (sscanf(line, "sack %63s %d %255s %511s", name, &ack_nr, offsets,
                   maskhex) != 4) { free(line); continue; }

        /* Parse the comma-separated offsets (already in increasing order). */
        int offs[256];
        int noff = 0;
        char *save = offsets;
        char *tok;
        while ((tok = strtok_r(save, ",", &save)) != NULL && noff < 256)
            offs[noff++] = atoi(tok);

        size_t mn = 0;
        int decoded = hexbytes(maskhex, mask, sizeof mask, &mn);
        int n_acked = 0;
        int rc = decoded ? ntx_utp_parse_sack(mask, mn, (uint16_t)ack_nr, seqs,
                                              &n_acked, (int)sizeof seqs / 2)
                         : -1;
        int ok = rc == 0 && n_acked == noff;
        if (ok) {
            for (int i = 0; i < noff; i++) {
                uint32_t exp = (uint32_t)ack_nr + 2u + (uint32_t)offs[i];
                if (seqs[i] != (uint16_t)(exp & 0xFFFFu)) { ok = 0; break; }
            }
        }
        char tname[128];
        snprintf(tname, sizeof tname, "sack-%s", name);
        check(ok, tname);
        free(line);
    }
    free(data);
}

static void test_sack_negatives(void) {
    uint16_t seqs[8];
    int n_acked = 0;
    uint8_t m4[4] = {0xFF, 0xFF, 0xFF, 0xFF};

    check(ntx_utp_parse_sack(m4, 0, 10, seqs, &n_acked, 8) == -1, "sack-neg-n0");
    check(ntx_utp_parse_sack(m4, 6, 10, seqs, &n_acked, 8) == -1, "sack-neg-n6");
    uint8_t big[2049];
    memset(big, 0xFF, sizeof big);
    check(ntx_utp_parse_sack(big, 2049, 10, seqs, &n_acked, 8) == -1,
          "sack-neg-n2049");
    /* 32 bits set but cap = 3 */
    check(ntx_utp_parse_sack(m4, 4, 10, seqs, &n_acked, 3) == -1,
          "sack-neg-cap");
}

/* ------------------------------------------------------------------ */
/* ext.txt: ext <name> <chain_hex> <first> <payload_hex> <n_blocks>   */
static void test_ext_vectors(void) {
    size_t n;
    char *data = (char *)read_file("test/vectors/utp/header/ext.txt", &n);
    check(data != NULL, "ext-vectors-read");
    if (!data) return;
    data[n] = 0;

    uint8_t buf[512];
    char name[64];

    const char *p = data;
    while (*p) {
        const char *nl = strchr(p, '\n');
        size_t len = nl ? (size_t)(nl - p) : strlen(p);
        char *line = malloc(len + 1);
        if (!line) break;
        memcpy(line, p, len);
        line[len] = 0;
        p = nl ? nl + 1 : line + len;

        /* Skip the leading "ext " and the name token. */
        char *q = line;
        while (*q == ' ') q++;
        if (strncmp(q, "ext ", 4) != 0) { free(line); continue; }
        q += 4;
        while (*q == ' ') q++;
        char *name_end = q;
        while (*name_end && *name_end != ' ') name_end++;
        size_t nlen = (size_t)(name_end - q);
        if (nlen >= sizeof name) { free(line); continue; }
        memcpy(name, q, nlen);
        name[nlen] = 0;
        q = name_end;
        while (*q == ' ') q++;

        /* Remaining: <chain> <first> <payload> <blocks>. Empty chain/payload
         * collapse to double spaces, so tokenize and map by count. */
        char *tok[8];
        int nt = 0;
        char *save = q;
        char *t;
        while ((t = strtok_r(save, " ", &save)) != NULL && nt < 8)
            tok[nt++] = t;
        save = NULL;

        char chain[512] = "", payload[512] = "";
        int first = 0, blocks = 0;
        int mapped = 0;
        if (nt == 4) {
            strcpy(chain, tok[0]); first = atoi(tok[1]);
            strcpy(payload, tok[2]); blocks = atoi(tok[3]); mapped = 1;
        } else if (nt == 3) {
            /* chain present, payload empty */
            strcpy(chain, tok[0]); first = atoi(tok[1]);
            payload[0] = 0; blocks = atoi(tok[2]); mapped = 1;
        } else if (nt == 2) {
            /* chain and payload both empty */
            chain[0] = 0; first = atoi(tok[0]); payload[0] = 0;
            blocks = atoi(tok[1]); mapped = 1;
        }
        (void)blocks;

        size_t cn = 0;
        int decoded = mapped && hexbytes(chain, buf, sizeof buf, &cn);
        int got_first = 0;
        const uint8_t *got_payload = NULL;
        int rc = decoded ? ntx_utp_ext_skip(buf, cn, &got_first, &got_payload)
                         : -1;
        uint8_t pay[512];
        size_t pay_n = 0;
        int pay_dec = payload[0] == 0 ? 1 : hexbytes(payload, pay, sizeof pay,
                                                     &pay_n);
        int ok = rc == 0 && got_first == first && pay_dec &&
                 got_payload != NULL &&
                 (size_t)(got_payload - buf) + pay_n == cn &&
                 (pay_n == 0 || memcmp(got_payload, pay, pay_n) == 0);
        char tname[128];
        snprintf(tname, sizeof tname, "ext-%s", name);
        check(ok, tname);
        free(line);
    }
    free(data);
}

static void test_ext_negatives(void) {
    int first = -1;
    const uint8_t *payload = NULL;

    /* Truncated: type=1, len=4 but only 2 data bytes present (n=4). */
    uint8_t trunc[4] = {0x01, 0x04, 0xAA, 0xBB};
    check(ntx_utp_ext_skip(trunc, 4, &first, &payload) == -1, "ext-neg-trunc");

    /* Unterminated: a single SACK block, no (0,0) terminator. */
    uint8_t unterm[6] = {0x01, 0x04, 0x00, 0x00, 0x00, 0x0F};
    check(ntx_utp_ext_skip(unterm, 6, &first, &payload) == -1,
          "ext-neg-unterm");

    /* Terminator with len != 0. */
    uint8_t badterm[8] = {0x01, 0x04, 0x00, 0x00, 0x00, 0x0F, 0x00, 0x01};
    check(ntx_utp_ext_skip(badterm, 8, &first, &payload) == -1,
          "ext-neg-term-len");
}

int main(void) {
    test_hdr_vectors();
    test_hdr_roundtrip();
    test_hdr_negatives();
    test_sack_vectors();
    test_sack_negatives();
    test_ext_vectors();
    test_ext_negatives();
    return fails ? 1 : 0;
}
