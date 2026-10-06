#ifndef NTX_CONFIG_H
#define NTX_CONFIG_H

#include <stdint.h>

#define NTX_VERSION "0.1.0" /* keep in sync with CHANGELOG.md */

typedef struct {
    const char *store_dir;
    uint16_t port_lo;
    uint16_t port_hi;
    int dht;
    int compat_peers; /* HYBRID: allow plaintext BitTorrent fallback (--compat-peers) */
    int utp; /* uTP (BEP29) for outbound peer connections (default off; --utp) */
    int verbose;
    int smooth;
    int socks5;
    int proxy;
    int tunnel;
    const char *proxy_host;
    uint16_t proxy_port;
    const char *tunnel_host;
    uint16_t tunnel_port;
    int max_peers;
    uint64_t down_limit;
    uint64_t up_limit;
    int allow_local_peers; /* dial loopback / link-local / multicast peers too (--allow-local-peers); default off */
    int https_tofu; /* HTTPS SPKI TOFU pinning (default on; --no-https-tofu) */
    const char *https_pin_file; /* optional SPKI pin file (--https-pin-file=PATH) */
} ntx_config;

#endif
