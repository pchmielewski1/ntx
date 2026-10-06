/* A5 golden replay: peer-wire (BT handshake + BEP3/BEP10) exchange fixture.
 *
 * Loads the frozen fixture from test/fixtures/pe/ (raw wire bytes +
 * .meta.json expectations) and replays it against the real wire code:
 *  - handshake checks mirror ntx_session_bt_hs.c (magic, info_hash, BEP10 bit),
 *  - message framing mirrors ntx_session_peer.c (4B length, keepalive len==0,
 *    BEP10 padded length 0x10000000|len),
 *  - each message payload is compared byte-for-byte with the real builders
 *    in ntx_btmsg.c (ntx_btmsg_build_*).
 * No network: fixture replay only. Deterministic.
 */
#include <stdio.h>
#include <string.h>

#include "util.h"
#include "golden_meta.h"

#include "../src/proto/ntx_btmsg.c"

static int g_fail;

static void expect(const char *name, int ok) {
    if (ok) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); g_fail = 1; }
}

static uint32_t rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static int hex_to(const char *hex, uint8_t *out, size_t n) {
    if (strlen(hex) != n * 2) return 0;
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1 || v > 255) return 0;
        out[i] = (uint8_t)v;
    }
    return 1;
}

/* MSB-first bit extraction — same expression as ntx_session_peer.c bitfield case */
static int bitfield_bit(const uint8_t *payload, size_t i) {
    return (payload[i / 8] >> (7 - i % 8)) & 1;
}

static int check_handshake(const uint8_t *raw, const gm *exp) {
    const gm *hs = gm_get(exp, "handshake");
    if (!hs || hs->t != GM_OBJ) return 0;
    const char *ihex = NULL, *pid = NULL;
    int bep10 = 0;
    if (gm_str(gm_get(hs, "info_hash"), &ihex) != 0) return 0;
    if (gm_str(gm_get(hs, "peer_id"), &pid) != 0) return 0;
    gm_bool(gm_get(hs, "bep10"), &bep10);

    if (raw[0] != 19) return 0;
    if (memcmp(raw + 1, "BitTorrent protocol", 19) != 0) return 0;
    if (bep10 && !(raw[25] & 0x10)) return 0;
    uint8_t ih[20];
    if (!hex_to(ihex, ih, 20)) return 0;
    if (memcmp(raw + 28, ih, 20) != 0) return 0;
    if (strlen(pid) != 20 || memcmp(raw + 48, pid, 20) != 0) return 0;
    return 1;
}

static int replay_pe(void) {
    size_t n, mn;
    uint8_t *raw = read_file("test/fixtures/pe/bt_exchange.bin", &n);
    uint8_t *meta = read_file("test/fixtures/pe/bt_exchange.meta.json", &mn);

    gm root;
    expect("pe:meta-parse", gm_parse((const char *)meta, mn, &root) == 0);
    if (g_fail) return 1;
    const gm *exp = gm_get(&root, "expected");
    expect("pe:meta-expected", exp != NULL && exp->t == GM_OBJ);
    if (!exp) return 1;

    expect("pe:handshake", check_handshake(raw, exp));
    if (g_fail) return 1;

    const gm *msgs = gm_get(exp, "messages");
    if (!msgs || msgs->t != GM_ARR) {
        printf("FAIL pe:messages\n");
        return 1;
    }

    size_t off = 68;
    int ok_all = 1;
    for (size_t mi = 0; mi < msgs->ne && ok_all; mi++) {
        const gm *m = msgs->el[mi];
        const char *type = NULL;
        if (!m || m->t != GM_OBJ || gm_str(gm_get(m, "type"), &type) != 0) {
            ok_all = 0;
            break;
        }
        if (off + 4 > n) { ok_all = 0; break; }
        uint32_t len = rd32(raw + off);
        char label[128];
        snprintf(label, sizeof label, "pe:msg%zu:%s", mi, type);

        if (len == 0) {
            int ok = strcmp(type, "keepalive") == 0 &&
                     raw[off] == 0 && raw[off + 1] == 0 && raw[off + 2] == 0 && raw[off + 3] == 0;
            expect(label, ok);
            off += 4;
            if (!ok) ok_all = 0;
            continue;
        }
        int padded = (len & 0x10000000u) != 0;
        uint32_t mlen = len & 0x0FFFFFFFu;
        if (mlen < 1 || off + 4 + mlen > n) { ok_all = 0; expect(label, 0); break; }
        uint8_t id = raw[off + 4];
        const uint8_t *pl = raw + off + 5;
        size_t plen = (size_t)mlen - 1;

        int mpad = 0;
        gm_bool(gm_get(m, "padded"), &mpad);
        if (padded != mpad) { ok_all = 0; expect(label, 0); break; }

        uint8_t built[64];
        size_t bn = 0;
        int ok = 0;
        if (strcmp(type, "interested") == 0) {
            bn = ntx_btmsg_build_interest(built, sizeof built, 1);
            ok = id == MSG_INTERESTED && plen == 0 &&
                 memcmp(raw + off, built, 5) == 0 && bn == 5;
        } else if (strcmp(type, "choke") == 0) {
            bn = ntx_btmsg_build_choke(built, sizeof built, 1);
            ok = id == MSG_CHOKE && plen == 0 &&
                 memcmp(raw + off, built, 5) == 0 && bn == 5;
        } else if (strcmp(type, "have") == 0) {
            int64_t idx = 0;
            if (gm_num(gm_get(m, "index"), &idx) != 0) { ok_all = 0; expect(label, 0); break; }
            bn = ntx_btmsg_build_have(built, sizeof built, (uint32_t)idx);
            ok = id == MSG_HAVE && plen == 4 &&
                 rd32(pl) == (uint32_t)idx &&
                 memcmp(raw + off + 4, built + 4, 5) == 0 && bn == 9;
        } else if (strcmp(type, "bitfield") == 0) {
            const gm *pieces = gm_get(m, "pieces");
            if (!pieces || pieces->t != GM_ARR) { ok_all = 0; expect(label, 0); break; }
            uint8_t bits[16];
            memset(bits, 0, sizeof bits);
            for (size_t pi = 0; pi < pieces->ne; pi++) {
                int64_t p;
                if (gm_num(pieces->el[pi], &p) != 0 || p < 0 || p / 8 >= (int)(sizeof bits)) {
                    ok_all = 0;
                    expect(label, 0);
                    break;
                }
                bits[p / 8] |= (uint8_t)(0x80 >> (p % 8));
            }
            bn = ntx_btmsg_build_bitfield(built, sizeof built, bits, plen);
            ok = id == MSG_BITFIELD && plen == (size_t)bn - 5 &&
                 memcmp(raw + off, built, 5 + plen) == 0;
            if (ok) {
                for (size_t i = 0; i < 8 * plen; i++) {
                    int want = 0;
                    for (size_t pi = 0; pi < pieces->ne; pi++) {
                        int64_t p = -1;
                        if (gm_num(pieces->el[pi], &p) == 0 && p == (int64_t)i) want = 1;
                    }
                    if (bitfield_bit(pl, i) != want) { ok = 0; break; }
                }
            }
        } else {
            ok_all = 0;
            expect(label, 0);
            break;
        }
        expect(label, ok);
        if (!ok) ok_all = 0;
        off += 4 + (size_t)mlen;
    }

    expect("pe:stream-exhausted", ok_all && off == n);

    gm_free(&root);
    free(raw);
    free(meta);
    return 0;
}

int main(void) {
    if (replay_pe()) return 1;
    return g_fail ? 1 : 0;
}
