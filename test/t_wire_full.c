#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

enum {
    MSG_CHOKE = 0, MSG_UNCHOKE = 1, MSG_INTERESTED = 2, MSG_NOT_INTERESTED = 3,
    MSG_HAVE = 4, MSG_BITFIELD = 5, MSG_REQUEST = 6, MSG_PIECE = 7, MSG_CANCEL = 8,
    MSG_HAVE_ALL = 14, MSG_HAVE_NONE = 15, MSG_EXT = 20
};

static uint32_t wf_rd32(const uint8_t *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void wf_wr32(uint8_t *p, uint32_t v) {
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}

static size_t wf_build(uint8_t *out, size_t cap, uint8_t id, const uint8_t *pl, size_t plen) {
    size_t n = 5 + plen;
    if (cap < n) return 0;
    wf_wr32(out, (uint32_t)(1 + plen));
    out[4] = id;
    if (plen && pl) memcpy(out + 5, pl, plen);
    return n;
}

static int wf_consume(uint8_t *buf, size_t *bl) {
    if (*bl < 4) return 0;
    uint32_t len = wf_rd32(buf);
    if (len == 0) {
        memmove(buf, buf + 4, *bl - 4);
        *bl -= 4;
        return 1;
    }
    if (*bl < 4 + len) return 0;
    memmove(buf, buf + 4 + len, *bl - 4 - len);
    *bl -= 4 + len;
    return 1;
}

int main(void) {
    uint8_t buf[512];
    size_t bl = 0;
    uint8_t ka[4] = {0, 0, 0, 0};
    memcpy(buf + bl, ka, 4);
    bl += 4;

    static const struct {
        uint8_t id;
        size_t plen;
    } msgs[] = {
        {MSG_CHOKE, 0}, {MSG_UNCHOKE, 0}, {MSG_INTERESTED, 0}, {MSG_NOT_INTERESTED, 0},
        {MSG_HAVE, 4}, {MSG_BITFIELD, 2}, {MSG_REQUEST, 12}, {MSG_PIECE, 16}, {MSG_CANCEL, 12},
        {MSG_HAVE_ALL, 0}, {MSG_HAVE_NONE, 0}, {MSG_EXT, 4}, {13, 4}, {16, 12}, {17, 4},
    };

    for (size_t i = 0; i < sizeof msgs / sizeof msgs[0]; i++) {
        uint8_t pl[32];
        memset(pl, 0, sizeof pl);
        if (msgs[i].plen >= 4) wf_wr32(pl, (uint32_t)i);
        if (msgs[i].plen >= 12) {
            wf_wr32(pl + 4, 0);
            wf_wr32(pl + 8, 16384);
        }
        if (msgs[i].plen >= 16) wf_wr32(pl + 12, 16384);
        size_t n = wf_build(buf + bl, sizeof buf - bl, msgs[i].id, pl, msgs[i].plen);
        assert(n > 0);
        bl += n;
    }

    int consumed = 0;
    while (wf_consume(buf, &bl)) consumed++;
    assert(consumed == (int)(sizeof msgs / sizeof msgs[0] + 1));
    assert(bl == 0);
    printf("PASS wire_full_table\n");
    return 0;
}
