# Module map (`src/`)

Every file under `src/`, grouped by directory, with its responsibility. Layering and data flow are described in [architecture.md](architecture.md).

The build compiles every `src/**/*.c` into one binary (`make ntx`). Most unit tests `#include` the `.c` files they need instead of linking against the tree (see [testing.md](testing.md)); that is why a few modules use weak stubs for optional neighbours (for example the DoH stubs in `ntx_sock.c` and the uTP entry points in `ntx_netx.c`).

## `src/`

| File | Responsibility |
|------|----------------|
| `ntx_main.c` | Command-line parsing, `main` loop, signal handling, `--stats-json` output and the stdin control pump |

## `src/core/` — session, torrents, peers, storage

| File | Responsibility |
|------|----------------|
| `ntx_config.h` | `ntx_config` (command-line options as a struct) and `NTX_VERSION` |
| `ntx_time.h` | `ntx_mono_ms()`, the monotonic millisecond clock used everywhere |
| `ntx_session.h` | Public session API: init/free, add magnet / `.torrent`, pause/remove, snapshot, tracker pumps, quit |
| `ntx_session_internal.h` | `struct ntx_session`, the peer-phase and message-id enums, tuning constants and the declarations shared between the `ntx_session_*.c` files |
| `ntx_session.c` | Session lifecycle, 100 ms tick, torrent slots (add/remove/pause), peer slot allocation, outbound dial policy, accept path, metainfo-ready hook |
| `ntx_session_peer.c` | Per-peer socket I/O, outbound buffering, BitTorrent message parsing and dispatch, connection/handshake/idle timeouts, BEP52 hash exchange (serving requests, the request pump for pure-v2 piece layers, receiving `hashes`) |
| `ntx_session_pe.c` | Glue between a peer slot and the MSE/PE state machine, plaintext fallback, `have` map setup |
| `ntx_session_bt_hs.c` | BitTorrent handshake build/verify, promotion of a peer to the OK phase, per-peer polling of OK peers |
| `ntx_session_data.c` | Download and upload logic: request scheduling (rarest-first, endgame), block receive and piece verification queue, serving requests, rate limiting, choke/unchoke, seed-ratio, resume verification, BEP55 hole-punch handling |
| `ntx_session_meta.c` | `ut_metadata` (BEP9) state per torrent: request pump, piece assembly and info-hash check when fetching, serving the info dict to other peers |
| `ntx_session_pex.c` | `ut_pex` (BEP11) receive and periodic send |
| `ntx_session_trk.c` | Tracker scheduling: UDP (BEP15) and HTTP(S) announces, retries, dead-tracker accounting, `event=stopped` on exit, peer boosting |
| `ntx_session_stats.c` | Builds the `ntx_stats` snapshot (per-torrent and global) and the phase strings |
| `ntx_session_vlog.c` | Verbose per-peer / per-request log lines |
| `ntx_session_webseed.c` | HTTP(S) webseed (BEP19) block fetch for magnets with `ws=` / `as=` |
| `ntx_pieceblk.c` | Per-piece 16 KiB block bitmaps and in-flight request bookkeeping |
| `ntx_peer.h`, `ntx_peer.c` | `ntx_peer` state (choke/interest flags, remote bitfield, outstanding requests) and the adaptive request pipeline depth |
| `ntx_dial_bo.h` | Redial back-off table for outbound peer addresses (header-only, no I/O) |
| `ntx_pex_tx.h`, `ntx_pex_tx.c` | Per-torrent queue of outbound PEX added/dropped events |
| `ntx_torrent.h`, `ntx_torrent.c` | Torrent state (`ntx_torrent`), metainfo loading, piece completion and hash verification, rarity counters, piece pick, peer ban |
| `ntx_torrent_meta.c` | Metainfo version detection and info-hash computation (SHA-1 for v1, SHA-256 for v2) |
| `ntx_torrent_v2.h`, `ntx_torrent_v2.c` | BEP52 file-tree parsing into a flat file table |
| `ntx_torrent_v2_layers.c` | BEP52 `piece layers` validation and packing into the layout used for verification |
| `ntx_merkle.h`, `ntx_merkle.c` | BEP52 SHA-256 Merkle trees: piece/file roots and proof ingestion |
| `ntx_hash_msg.h`, `ntx_hash_msg.c` | Codec for the BEP52 hash-exchange messages (`hash request` 21, `hashes` 22, `hash reject` 23) |
| `ntx_store.h`, `ntx_store.c` | On-disk storage: single- and multi-file layout, piece map, piece read/write/verify, resume detection |

## `src/net/` — event loop, sockets, transports

| File | Responsibility |
|------|----------------|
| `ntx_netx.h`, `ntx_netx.c` | epoll event loop and timer heap; TCP/UDP listeners (v4 and v6); shared UDP socket demultiplexed between DHT and uTP; connection routing (tunnel → uTP / SOCKS5 → raw TCP) |
| `ntx_addr.h`, `ntx_addr.c` | `ntx_addr` (IPv4/IPv6), comparison, formatting, and the "special address" predicate used to refuse loopback/link-local/multicast peers |
| `ntx_sock.h`, `ntx_sock.c` | Socket helpers: create/bind/listen/connect for TCP and UDP (v4/v6), port-range bind, host resolution through DoH (no system resolver) |
| `ntx_proxy.h`, `ntx_proxy.c` | SOCKS5 client state machine (CONNECT and UDP ASSOCIATE) and `--proxy=` parsing |
| `ntx_tunnel.h`, `ntx_tunnel.c` | Client for the NTX1 tunnel: an authenticated, encrypted multiplexed connection that carries peer TCP connections as virtual fds |
| `ntx_tls.h`, `ntx_tls.c` | TLS client handshake driver (TLS 1.3 first, fresh-connection fallback to TLS 1.2), SPKI pin / TOFU check, application data I/O |
| `ntx_tls13.h`, `ntx_tls13.c` | Pure TLS 1.3 building blocks (RFC 8446): key schedule, record protection, handshake message builders and parsers |
| `ntx_tls_rec.c` | TLS 1.2 record layer and PRF |
| `ntx_utp.h`, `ntx_utp.c` | uTP (BEP29) glue: virtual fds, per-connection slots demultiplexed by peer address and connection id, UDP I/O (direct or through SOCKS5 UDP ASSOCIATE), timers |
| `ntx_utp_sm.c` | uTP connection state machine (handshake, windows, SACK, retransmit, close) |
| `ntx_utp_sm_int.h` | Test-only view of uTP state-machine internals |
| `ntx_utp_cc.c` | LEDBAT-style delay-based congestion control for uTP |
| `ntx_utp_hdr.c` | uTP 20-byte header, SACK and extension chain pack/parse |

## `src/proto/` — wire formats and protocol logic

| File | Responsibility |
|------|----------------|
| `ntx_bencode.h`, `ntx_bencode.c` | Strict bencode parser with depth/size limits, plus a small dict builder |
| `ntx_magnet.h`, `ntx_magnet.c` | Magnet URI parsing (`xt` btih/btmh, `dn`, `tr`, `ws`, `as`) |
| `ntx_wire.h` | Big-endian read/write helpers |
| `ntx_btmsg.h`, `ntx_btmsg.c` | Builders for the core BitTorrent messages (choke, interested, have, bitfield, request, piece, cancel, keep-alive) |
| `ntx_ext.h`, `ntx_ext.c` | BEP10 extension framing and extension handshake |
| `ntx_utmeta.h`, `ntx_utmeta.c` | `ut_metadata` (BEP9) message encode/decode |
| `ntx_pex.h`, `ntx_pex.c` | `ut_pex` (BEP11) payload parse and build, IPv4 and IPv6 |
| `ntx_holepunch.h`, `ntx_holepunch.c` | `ut_holepunch` (BEP55) payload codec and relay/target/race policy |
| `ntx_pe.h`, `ntx_pe.c` | MSE/PE handshake state machine |
| `ntx_pe_vc.c` | MSE/PE crypto layer: DH public values, `SKEY` obfuscation, RC4 key derivation, verification constant |
| `ntx_tracker.h`, `ntx_tracker.c` | UDP tracker (BEP15) packet build/parse, compact peer lists (v4 and v6), HTTP announce URL builder and response parser |
| `ntx_http.h`, `ntx_http.c` | Blocking HTTP/1.1 GET and Range GET (also dispatches `https://`), proxy-aware connect, tracker-reply dictionary parsing |
| `ntx_http_url.h`, `ntx_http_url.c` | `http://` / `https://` URL parser (rejects control bytes) |
| `ntx_https.h`, `ntx_https.c` | HTTPS transport: connect, TLS handshake with pin lookup, HTTP/1.1 response parsing including chunked bodies |
| `ntx_https_pin.h`, `ntx_https_pin.c` | SPKI pin pool, pin file loader, wildcard host matching, TOFU store |
| `ntx_https_pins.h` | Pin-pool entry types |
| `ntx_doh.h`, `ntx_doh.c` | DNS-over-HTTPS client (RFC 8484): A and AAAA lookups over pinned TLS with failover across a built-in resolver pool |
| `ntx_doh_pins.h` | The built-in DoH resolver addresses and their SPKI pins |
| `ntx_h2.h`, `ntx_h2.c` | Minimal HTTP/2 client used for a single DoH POST |
| `ntx_dht.h`, `ntx_dht.c` | DHT node (BEP5 with BEP32 IPv6): bootstrap, queries and responses, peer store, announce tokens, iterative `get_peers`, node-ID persistence |
| `ntx_dht_msg.h`, `ntx_dht_msg.c` | DHT KRPC message encode/parse and compact node/peer formats |
| `ntx_dht_rt.h`, `ntx_dht_rt.c` | Routing table (K = 8, 16 fixed buckets keyed by the top 4 XOR bits) |
| `ntx_dht_lookup.h`, `ntx_dht_lookup.c` | Iterative lookup state (candidate set, parallelism, termination) |
| `ntx_dht_tid.h`, `ntx_dht_tid.c` | Outstanding-transaction table |
| `ntx_dht_token.h`, `ntx_dht_token.c` | Announce token issue and verification |
| `ntx_dht_xor.h` | XOR distance and common-prefix helpers (header-only) |

## `src/crypto/` — primitives (no external library)

| File | Responsibility |
|------|----------------|
| `ntx_sha1.h`, `ntx_sha1.c` | SHA-1 |
| `ntx_sha256.h`, `ntx_sha256.c` | SHA-256 |
| `ntx_hmac.h`, `ntx_hmac.c` | HMAC-SHA1 and HMAC-SHA256 (one-shot and incremental) |
| `ntx_hkdf.h`, `ntx_hkdf.c` | HKDF-SHA256 (RFC 5869) |
| `ntx_aes.h`, `ntx_aes.c` | AES-128 with CTR and GCM |
| `ntx_rc4.h`, `ntx_rc4.c` | RC4 (MSE/PE only) |
| `ntx_rng.h`, `ntx_rng.c` | Random bytes from `/dev/urandom` through a refilled pool |
| `ntx_bignum.h`, `ntx_bignum.c` | Big-endian big integers and the Montgomery core (variable-time modexp for public values, constant-time ladder for secret exponents) |
| `ntx_dh.h`, `ntx_dh.c` | 768-bit Diffie-Hellman for MSE/PE |
| `ntx_x25519.h`, `ntx_x25519.c`, `ntx_x25519_fe.h`, `ntx_x25519_fe.c` | X25519 and its field arithmetic |
| `ntx_p256.h`, `ntx_p256.c` | P-256 ECDSA signature verification and SPKI parsing |
| `ntx_rsa_pkcs1.h`, `ntx_rsa_pkcs1.c` | RSA signature verification: PKCS#1 v1.5 and PSS, both with SHA-256 |
| `ntx_ct.h` | Constant-time helpers and a non-elidable `ntx_wipe` (header-only) |

## `src/ui/` — status line, JSON, diagnostics

| File | Responsibility |
|------|----------------|
| `ntx_stats.h`, `ntx_stats.c` | `ntx_stats` snapshot types and the JSON status emitter |
| `ntx_cli.h`, `ntx_cli.c` | Human-readable status line for the terminal |
| `ntx_ipc.h`, `ntx_ipc.c` | JSON control channel: line framer, command parser, string escaping, `hello` line |
| `ntx_ipc_dispatch.c` | Executes parsed control commands against the session |
| `ntx_diag.h`, `ntx_diag.c` | Mirror of diagnostic output into the `--verbose` / `--log=` file |

## Notes

- The DHT is a simplified BEP5 implementation: fixed 16-bucket routing table, K = 8, no dynamic bucket splitting.
- The TLS client supports only the suites needed for DoH and HTTPS trackers/webseeds: TLS 1.3 with `TLS_AES_128_GCM_SHA256`, and TLS 1.2 ECDHE with AES-128-GCM. There is no TLS server and peer connections never use TLS.
- Peer connections use MSE/PE, with a plaintext handshake fallback when `compat_peers` is set.
