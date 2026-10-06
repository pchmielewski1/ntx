/* No global state: view points into caller buffer during the call only; safe to repeat. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include <arpa/inet.h>

#include "../../src/proto/ntx_bencode.c"
#include "../../src/net/ntx_addr.c"
#include "../../src/proto/ntx_dht_rt.c"
#include "../../src/proto/ntx_dht_msg.c"

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t len) {
    ntx_dht_msg_view v;
    ntx_dht_node nodes[8];
    ntx_dht_cpeer vals[8];

    ntx_dht_msg_parse(data, len, &v);
    ntx_dht_msg_parse_nodes(data, len, nodes, 8, 0);
    ntx_dht_msg_parse_nodes6(data, len, nodes, 8, 0);
    ntx_dht_msg_parse_values(data, len, vals, 8);
    ntx_dht_msg_parse_values6(data, len, vals, 8);
    return 0;
}
