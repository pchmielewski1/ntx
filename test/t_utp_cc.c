#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../src/net/ntx_utp_cc.c"
#include "../src/net/ntx_utp.h"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

static char *read_file(const char *path, size_t *n) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    char *buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz) { free(buf); return NULL; }
    buf[rd] = 0;
    *n = rd;
    return buf;
}

/* Find "KEY=" at start of line (skip # comments); parse long long value. */
static int kv(const char *buf, const char *key, long long *out) {
    size_t klen = strlen(key);
    const char *p = buf;
    while (p && *p) {
        if (*p != '#' && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            char *end;
            *out = strtoll(p + klen + 1, &end, 10);
            return 1;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return 0;
}

/* Find "KEY=" at start of line; copy the rest of the line (NUL-terminated). */
static int kvs(const char *buf, const char *key, char *out, size_t cap) {
    size_t klen = strlen(key);
    const char *p = buf;
    while (p && *p) {
        if (*p != '#' && strncmp(p, key, klen) == 0 && p[klen] == '=') {
            const char *q = p + klen + 1;
            size_t i = 0;
            while (*q && *q != '\n' && *q != '\r' && i + 1 < cap) out[i++] = *q++;
            out[i] = 0;
            return 1;
        }
        p = strchr(p, '\n');
        if (p) p++;
    }
    return 0;
}

int main(void) {
    /* ---- cc_constants.txt: frozen values + frozen header agreement ---- */
    size_t n;
    char *consts = read_file("test/vectors/utp/cc_constants.txt", &n);
    check(consts != NULL, "cc-const-file");
    if (consts) {
        long long v_target = 0, v_maxinc = 0, v_hist = 0, v_minpkt = 0;
        long long v_init = 0, v_min = 0, v_dup = 0;
        char loss[64] = "";
        check(kv(consts, "CCONTROL_TARGET_US", &v_target), "cc-const-key-target");
        check(kv(consts, "MAX_CWND_INCREASE_PACKETS_PER_RTT", &v_maxinc),
              "cc-const-key-maxinc");
        check(kv(consts, "CC_HISTORY", &v_hist), "cc-const-key-history");
        check(kv(consts, "MIN_PACKET_SIZE", &v_minpkt), "cc-const-key-minpkt");
        check(kv(consts, "INIT_TIMEOUT_MS", &v_init), "cc-const-key-init");
        check(kv(consts, "MIN_TIMEOUT_MS", &v_min), "cc-const-key-min");
        check(kv(consts, "DUP_ACK_LIMIT", &v_dup), "cc-const-key-dup");
        check(kvs(consts, "LOSS_FACTOR", loss, sizeof loss),
              "cc-const-key-loss");
        check(v_target == 100000, "cc-const-target-100ms");
        check(v_maxinc == 3, "cc-const-maxinc-3");
        check(v_hist == 120, "cc-const-history-120");
        check(v_minpkt == 150, "cc-const-minpkt-150");
        check(v_init == 1000, "cc-const-init-1000");
        check(v_min == 500, "cc-const-min-500");
        check(v_dup == 3, "cc-const-dup-3");
        check(strcmp(loss, "0.5") == 0, "cc-const-loss-0.5");
        /* frozen header macros must agree with the vector file */
        check((long long)NTX_UTP_TARGET_DELAY_US == v_target,
              "cc-macro-target");
        check((long long)NTX_UTP_MAX_CWND_INC_PER_RTT == v_maxinc,
              "cc-macro-maxinc");
        check((long long)NTX_UTP_CC_HISTORY == v_hist, "cc-macro-history");
        check((long long)NTX_UTP_MIN_PKT == v_minpkt, "cc-macro-minpkt");
        check((long long)NTX_UTP_INIT_TIMEOUT_MS == v_init, "cc-macro-init");
        check((long long)NTX_UTP_MIN_TIMEOUT_MS == v_min, "cc-macro-min");
        check((long long)NTX_UTP_DUP_ACK_LIMIT == v_dup, "cc-macro-dup");
        free(consts);
    }

    /* ---- cc.txt: replay the 7-step golden sequence, one fresh cc ---- */
    char *cc = read_file("test/vectors/utp/cc.txt", &n);
    check(cc != NULL, "cc-golden-file");
    if (cc) {
        ntx_utp_cc c;
        ntx_utp_cc_init(&c);
        const char *p = cc;
        int steps = 0;
        while (p && *p) {
            if (*p != '#' && *p != '\n') {
                unsigned long long ts, out;
                long long cin, cout;
                if (sscanf(p, "%llu %llu %lld %lld", &ts, &out, &cin, &cout) ==
                       4) {
                    steps++;
                    char name[32];
                    snprintf(name, sizeof name, "cc-step%d", steps);
                    int64_t got = ntx_utp_cc_update(&c, (uint32_t)ts,
                                                    (uint32_t)out, cin);
                    check(got == cout, name);
                }
            }
            p = strchr(p, '\n');
            if (p) p++;
        }
        check(steps == 7, "cc-golden-count");
        free(cc);
    }

    /* ---- unit behaviors ---- */
    ntx_utp_cc c;

    ntx_utp_cc_init(&c);
    check(ntx_utp_cc_update(&c, 0, 1400, 4096) == 4096, "cc-zero-ts-unchanged");

    ntx_utp_cc_init(&c);
    check(ntx_utp_cc_update(&c, 100000, 0, 4096) == 4096,
          "cc-first-sample-zero-outstanding");

    ntx_utp_cc_init(&c);
    check(ntx_utp_cc_update(&c, 100000, 1400, 0) == 0, "cc-zero-cwnd");

    /* shrink: base 100000, then ts_diff 250000 with outstanding == cwnd */
    ntx_utp_cc_init(&c);
    int64_t w = ntx_utp_cc_update(&c, 100000, 8192, 8192);
    int64_t w2 = ntx_utp_cc_update(&c, 250000, 8192, w);
    check(w2 < w, "cc-shrink-on-high-delay");

    /* extreme over-delay: gain must clamp the window to >= 0, no crash */
    ntx_utp_cc_init(&c);
    ntx_utp_cc_update(&c, 100000, 1, 1);
    int64_t w3 = ntx_utp_cc_update(&c, 4294967295u, 1, 1);
    check(w3 == 0, "cc-never-negative");

    /* ring persists: 120 samples of 200000 keep base 200000, so a 250000
     * sample yields a partial gain (scaled 1), not a full gain (3) as if
     * the ring had been cleared. */
    ntx_utp_cc_init(&c);
    for (int i = 0; i < NTX_UTP_CC_HISTORY; i++)
        ntx_utp_cc_update(&c, 200000, 0, 5000);
    int64_t w4 = ntx_utp_cc_update(&c, 250000, 5000, 5000);
    check(w4 == 5001, "cc-ring-persist");

    return fails ? 1 : 0;
}
