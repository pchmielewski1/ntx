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
    /* BEP10 TX: use the peer's advertised ut_metadata ID (not our local ID). */
    uint8_t payload[64];
    size_t pn = 0;
    if (ntx_ut_metadata_request_build(payload, &pn, 0) != 0) return 1;

    uint8_t msg[128];
    uint8_t peer_meta_id = 2;
    size_t mn = ntx_ext_msg_build(msg, sizeof msg, peer_meta_id, payload, pn);
    expect("meta-tx-peer-id", mn > 0 && msg[4] == 0x14 && msg[5] == 2);

    /* Our local ID (1) must not be used when peer advertised metadata=2. */
    mn = ntx_ext_msg_build(msg, sizeof msg, NTX_EXT_LOCAL_METADATA, payload, pn);
    expect("meta-tx-local-differs", mn > 0 && msg[5] == 1);

    return g_fail ? 1 : 0;
}
