/* node-ID persistence — a 20 B file; restart → same ID; no file → random */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "../src/proto/ntx_bencode.c"
#include "../src/crypto/ntx_sha1.c"
#include "../src/crypto/ntx_rng.c"
#include "../src/net/ntx_sock.c"
#include "../src/net/ntx_addr.c"
#include "../src/net/ntx_netx.c"
#include "../src/net/ntx_proxy.c"
#include "../src/net/ntx_tunnel.c"
#include "../src/crypto/ntx_aes.c"
#include "../src/crypto/ntx_hmac.c"
#include "../src/crypto/ntx_sha256.c"
#include "../src/proto/ntx_dht_rt.c"
#include "../src/proto/ntx_dht_lookup.c"
#include "../src/proto/ntx_dht_tid.c"
#include "../src/proto/ntx_dht_token.c"
#include "../src/proto/ntx_dht_msg.c"
#include "../src/proto/ntx_dht.c"
#include "../src/proto/ntx_pex.c"
#include "../src/ui/ntx_diag.c"

static int fail(const char *m) {
    printf("FAIL %s\n", m);
    return 1;
}

static int test_dht_state_persist(void) {
    const char *path = "test/.dht_state_T25";
    unlink(path);
    ntx_dht_set_state_path(path);
    ntx_netx *netx = ntx_netx_init(NULL);
    if (!netx) return fail("netx");
    if (ntx_dht_start(netx) != 0) {
        ntx_netx_free(netx);
        return fail("dht_start");
    }
    uint8_t id1[20], id2[20], raw[24];
    if (ntx_dht_node_id_get(id1) != 0) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("node_id_get");
    }
    /* the file exists, 20 B, == id1 */
    FILE *f = fopen(path, "rb");
    if (!f) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("state-open");
    }
    if (fread(raw, 1, 20, f) != 20) {
        fclose(f);
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("state-read");
    }
    fclose(f);
    if (memcmp(raw, id1, 20) != 0) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("state-mismatch");
    }
    ntx_dht_stop();
    ntx_netx_free(netx);
    /* restart → same ID */
    netx = ntx_netx_init(NULL);
    if (!netx) return fail("netx2");
    if (ntx_dht_start(netx) != 0) {
        ntx_netx_free(netx);
        return fail("dht_start2");
    }
    if (ntx_dht_node_id_get(id2) != 0) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("node_id_get2");
    }
    if (memcmp(id1, id2, 20) != 0) {
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("restart-id-changed");
    }
    ntx_dht_stop();
    ntx_netx_free(netx);
    /* deleting the file → a new random ID */
    unlink(path);
    netx = ntx_netx_init(NULL);
    if (!netx) return fail("netx3");
    if (ntx_dht_start(netx) != 0) {
        ntx_netx_free(netx);
        return fail("dht_start3");
    }
    if (ntx_dht_node_id_get(id1) != 0) {   /* overwrites id1 with the new one */
        ntx_dht_stop();
        ntx_netx_free(netx);
        return fail("node_id_get3");
    }
    ntx_dht_stop();
    ntx_netx_free(netx);
    unlink(path);
    ntx_dht_set_state_path(NULL);
    printf("PASS dht_state_persist\n");
    return 0;
}

int main(void) {
    ntx_rng_init();
    if (test_dht_state_persist() != 0) return 1;
    return 0;
}
