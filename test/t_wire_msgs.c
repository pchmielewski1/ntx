#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

/* BEP6 optional wire ids (not in session enum — unit-level framing only) */
enum { MSG_SUGGEST = 13, MSG_REJECT = 16, MSG_ALLOWED_FAST = 17 };

static uint32_t wm_rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wm_wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t wm_build(uint8_t *out, size_t cap, uint8_t msg_id, const uint8_t *payload, size_t plen) {
    size_t total = 5 + plen;
    if (!out || cap < total) return 0;
    wm_wr32(out, (uint32_t)(1 + plen));
    out[4] = msg_id;
    if (plen && payload) memcpy(out + 5, payload, plen);
    return total;
}

static int wm_parse(const uint8_t *buf, size_t n, uint8_t *msg_id, const uint8_t **payload, size_t *plen) {
    if (!buf || n < 5) return -1;
    uint32_t len = wm_rd32(buf);
    if (len == 0 || len > n - 4) return -1;
    if (msg_id) *msg_id = buf[4];
    if (payload) *payload = buf + 5;
    if (plen) *plen = (size_t)len - 1;
    return 0;
}

static int wm_consume_one(uint8_t *buf, size_t *bl) {
    if (*bl < 4) return 0;
    uint32_t total_len = wm_rd32(buf);
    if (total_len == 0) {
        memmove(buf, buf + 4, *bl - 4);
        *bl -= 4;
        return 1;
    }
    if (*bl < 4 + (size_t)total_len) return 0;
    (void)buf[4]; /* unknown types ignored per BEP6 */
    memmove(buf, buf + 4 + total_len, *bl - 4 - (size_t)total_len);
    *bl -= 4 + (size_t)total_len;
    return 1;
}

int main(void) {
    {
        uint8_t payload[4];
        wm_wr32(payload, 42);
        uint8_t wire[16];
        size_t n = wm_build(wire, sizeof wire, (uint8_t)MSG_SUGGEST, payload, 4);
        assert(n == 9);
        assert(wm_rd32(wire) == 5);
        assert(wire[4] == MSG_SUGGEST);
        uint8_t mid = 0;
        const uint8_t *pl = 0;
        size_t plen = 0;
        assert(wm_parse(wire, n, &mid, &pl, &plen) == 0);
        assert(mid == MSG_SUGGEST && plen == 4 && wm_rd32(pl) == 42);
        printf("PASS msg_suggest\n");
    }

    {
        uint8_t payload[12];
        wm_wr32(payload, 3);
        wm_wr32(payload + 4, 16384);
        wm_wr32(payload + 8, 16384);
        uint8_t wire[32];
        size_t n = wm_build(wire, sizeof wire, (uint8_t)MSG_REJECT, payload, 12);
        assert(n == 17);
        assert(wm_rd32(wire) == 13);
        assert(wire[4] == MSG_REJECT);
        uint8_t mid = 0;
        const uint8_t *pl = 0;
        size_t plen = 0;
        assert(wm_parse(wire, n, &mid, &pl, &plen) == 0);
        assert(mid == MSG_REJECT && plen == 12);
        assert(wm_rd32(pl) == 3 && wm_rd32(pl + 4) == 16384 && wm_rd32(pl + 8) == 16384);
        printf("PASS msg_reject\n");
    }

    {
        uint8_t payload[4];
        wm_wr32(payload, 7);
        uint8_t wire[16];
        size_t n = wm_build(wire, sizeof wire, (uint8_t)MSG_ALLOWED_FAST, payload, 4);
        assert(n == 9);
        assert(wm_rd32(wire) == 5);
        assert(wire[4] == MSG_ALLOWED_FAST);
        uint8_t mid = 0;
        const uint8_t *pl = 0;
        size_t plen = 0;
        assert(wm_parse(wire, n, &mid, &pl, &plen) == 0);
        assert(mid == MSG_ALLOWED_FAST && plen == 4 && wm_rd32(pl) == 7);
        printf("PASS msg_allowed_fast\n");
    }

    {
        uint8_t buf[64];
        size_t bl = 0;
        uint8_t ka[4] = {0, 0, 0, 0};
        memcpy(buf + bl, ka, 4);
        bl += 4;
        uint8_t unknown_payload[2] = {0xAA, 0xBB};
        size_t ulen = wm_build(buf + bl, sizeof buf - bl, 99, unknown_payload, 2);
        assert(ulen == 7);
        bl += ulen;
        uint8_t suggest_payload[4];
        wm_wr32(suggest_payload, 1);
        size_t slen = wm_build(buf + bl, sizeof buf - bl, (uint8_t)MSG_SUGGEST, suggest_payload, 4);
        assert(slen == 9);
        bl += slen;

        int consumed = 0;
        while (wm_consume_one(buf, &bl)) consumed++;
        assert(consumed == 3);
        assert(bl == 0);
        printf("PASS msg_unknown_ignore\n");
    }

    return 0;
}
