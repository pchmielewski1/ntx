# Architecture

## Goals and constraints

`ntx` is a single BitTorrent client binary written in C11 + POSIX. It links only `libc` and `libm`: there is no OpenSSL, no vendored crypto library, no CMake. All cryptography (hashes, AES, X25519, P-256, RSA verification, DH), the TLS 1.3 / 1.2 client and the DNS-over-HTTPS (DoH) resolver live in `src/`. See [network.md](network.md) for the transport details and [module-map.md](module-map.md) for a file-by-file listing.

Size budget: the binary must stay below 1 MiB (1048576 bytes). `make size` enforces this; see [testing.md](testing.md).

The program is single-threaded. Almost all I/O is non-blocking and driven by one epoll loop, but a few operations block the loop for the duration of one request: DoH lookups, HTTP(S) tracker announces, HTTP(S) webseed range requests, and the final `event=stopped` announces on exit (bounded to about 3 seconds in total).

## Layers

```
src/ntx_main.c        command line, main loop, signals, JSON/CLI output
        |
src/core/             session  ->  torrent  ->  store      (+ peer state, tracker scheduling)
        |
src/proto/            wire formats: bencode, magnet, BEP3/6/9/10/11/52/55 messages, MSE/PE,
        |             trackers, DHT, DoH, HTTP(S)
src/net/              netx (epoll + timers), sockets, SOCKS5, NTX1 tunnel, TLS, uTP
        |
src/crypto/           hashes, AES, DH, X25519, P-256, RSA verify, RNG

src/ui/               status line, JSON status/control channel, diagnostics (used by main and core)
```

| Directory | Role |
|-----------|------|
| `src/ntx_main.c` | Option parsing, main loop, signal handling, output |
| `src/core/` | Session, torrent state, piece storage, peer state, tracker scheduling, per-peer protocol logic |
| `src/net/` | `ntx_netx` event loop, TCP/UDP sockets, SOCKS5, NTX1 tunnel, TLS 1.3 + 1.2, uTP |
| `src/proto/` | Protocol encoders/decoders and protocol clients (bencode, magnet, MSE/PE, trackers, DHT, DoH, HTTP/HTTPS, PEX, hole punching) |
| `src/crypto/` | Cryptographic primitives |
| `src/ui/` | Terminal status line, JSON status and control channel, diagnostics log |

### Session, torrent, store

- `ntx_session` (`src/core/ntx_session*.c`) is the single owner of runtime state: up to `NTX_SESSION_MAX_TTS` torrent slots (`tts[]`), up to `NTX_SESSION_MAX_PEERS` peer slots, tracker state, rate-limit buckets and statistics. Per-peer state is kept in parallel arrays indexed by peer slot (`peers[]`, `pe[]`, `peer_phase[]`, `peer_tts[]`, and so on). The `ntx_session_*.c` files all operate on the same `struct ntx_session` (`ntx_session_internal.h`).
- `ntx_torrent` (`ntx_torrent.c`) holds one torrent: metainfo, piece hashes, the `have` bitmap, per-piece rarity counters, and its `ntx_store`. A slot moves through `NTX_TTS_META` (magnet, metadata not yet known), `NTX_TTS_VERIFY` (re-checking existing files), `NTX_TTS_DL`, `NTX_TTS_DONE` (seeding), `NTX_TTS_PAUSED` and `NTX_TTS_DEAD` (free slot).
- `ntx_store` (`ntx_store.c`) maps pieces onto one file (single-file torrents) or several files (multi-file and BEP52 torrents) under `--store-dir`, and keeps a per-piece map: 0 = missing or failed verification, 1 = written but not verified, 2 = verified.
- `ntx_peer` (`ntx_peer.c`) is the small per-connection state record: choke/interest flags, the remote's bitfield, and the list of outstanding block requests.

## Data flow

```
magnet: URI  or  .torrent file
  -> parse (ntx_magnet / ntx_bencode)
  -> torrent slot:  magnet = META state (info dict still unknown), .torrent = metainfo loaded
  -> peer discovery
       trackers: UDP (BEP15) and HTTP(S); host names resolved through DoH (AAAA, then A)
       DHT (--dht, magnets): iterative get_peers over IPv4 and IPv6
       PEX (BEP11) and ut_holepunch (BEP55) from connected peers
  -> peer address filter (loopback / link-local / multicast refused unless --allow-local-peers)
  -> connect through ntx_netx_route_connect:
       NTX1 tunnel  |  uTP (--utp; over SOCKS5 UDP ASSOCIATE with --proxy)  |  SOCKS5 CONNECT  |  raw TCP
  -> per-peer phases:  PH_PE (MSE/PE handshake)  ->  PH_BTHS (68-byte BitTorrent handshake)  ->  PH_OK
       with a plaintext handshake fallback when `compat_peers` is set (the default in ntx_main.c)
  -> BEP10 extension handshake;  magnets: BEP9 ut_metadata fetch, hash-checked against the magnet xt
  -> store open:  existing files -> VERIFY (re-hash, resume)   otherwise -> DL
  -> DL: rarest-first piece selection, 16 KiB block requests, endgame duplicates for the last pieces
         block received -> piece complete -> hash check (SHA-1 for v1, SHA-256 Merkle for v2) -> HAVE broadcast
  -> DONE: seed; upload stops once uploaded bytes reach 3 x torrent size (ratio-done)
```

Details worth knowing:

- **Peer discovery per torrent type.** DHT lookups start when a magnet link is added (and the node announces the torrent when a download completes). A `.torrent` file contributes its `announce` / `announce-list` trackers. Magnet `tr=` values are the trackers for magnets.
- **MSE/PE.** An outbound connection always starts as the MSE/PE initiator; inbound connections start as the responder. If the remote answers with a plain BitTorrent handshake and `compat_peers` is set, the slot switches to plaintext. `compat_peers` defaults to on in `main()`; `--compat-peers` only sets it again.
- **uTP.** With `--utp`, outbound dials try uTP first. A uTP dial unanswered after `NTX_UTP_DIAL_MS` (1.5 s) is redone over TCP, and uTP-first is abandoned once `NTX_UTP_GIVEUP_MISSES` uTP dials have failed without a single uTP peer ever completing a handshake. Inbound uTP connections are accepted whenever the uTP listener exists.
- **Redial back-off.** An address whose outbound attempt failed is not dialled again for 30 s, doubling per failure up to 10 minutes (`ntx_dial_bo.h`). A peer that reached the OK phase clears its history. BEP55-triggered dials bypass the back-off.
- **Webseeds.** A webseed URL (BEP19) comes from the magnet's `ws=` (or `as=`) value only; `url-list` in a `.torrent` is not read. Every 5 s, for a downloading torrent that has no peer it can currently download from, the session fetches data over an HTTP(S) range request (`ntx_session_webseed_tick`).
- **BEP52.** v2 and hybrid torrents are supported. Pieces are aligned per file, so piece length comes from `ntx_torrent_piece_len()`, not from the store. Pure-v2 torrents obtained from a magnet fetch their piece layers from peers through the hash-exchange messages (21/22/23, `ntx_session_peer.c`) and verify them against the file roots before use.
- **Egress policy.** With `--proxy` or `--tunnel`, UDP trackers are not used, and `--dht` is rejected at startup, because both would send UDP from the local address. HTTP(S) trackers and webseeds go through the SOCKS5 proxy when `--proxy` is set (`ntx_http_set_proxy`); they never use the NTX1 tunnel. DoH queries go straight to the built-in resolver pool and do not use the proxy. If `--tunnel` is configured but the tunnel is not ready, peer dials fall through to the next route (uTP/proxy, then raw TCP) rather than failing.

## Main loop (`ntx_main.c`)

Each iteration of the loop in `main()`:

1. `ntx_session_trk_pump_udp(s)`: send queued UDP tracker connect/announce packets, within a time budget (`TRK_UDP_PUMP_BUDGET_MS`, 100 ms).
2. `ntx_session_trk_pump_http(s, 1)`: perform at most one due HTTP(S) tracker announce (blocking).
3. `ntx_netx_run_once(netx, 50)`: one epoll wait of up to 50 ms (shorter when a timer is due); runs socket callbacks, then due timers.
4. If the JSON control channel is open (`--stats-json` with stdin not a TTY): read and execute pending command lines (at most 64 lines per iteration), then continue; a `quit` command ends the loop.
5. At most every 100 ms: `ntx_session_stats_refresh`, take a snapshot, and print one status line (terminal) or one JSON object (`--stats-json`). The speed ring buffers rotate here, on every 10th refresh (about once per second), and only here.
6. If SIGINT/SIGTERM set the quit flag, call `ntx_session_quit` and leave the loop.

After the loop: final status line, `ntx_session_trk_stop_all` (best-effort `event=stopped`), then teardown. SIGPIPE is ignored.

### Session tick

`ntx_session_init` registers a 100 ms timer on the netx timer heap that re-arms itself. Each tick (`ntx_session_tick`) runs:

- every tick: handshake/connect timeouts and round-robin polling of OK peers, 16 per tick (`ntx_session_peer_hs_tick`), the data tick (request timeouts and refill, upload queue, up to 16 piece verifications, PEX, ut_metadata timeouts, keep-alives, periodic choke/unchoke), resume verification (about 2 MiB of hashing per tick per torrent), and the BEP52 hash-exchange tick;
- every 10th tick (about 1 s): statistics refresh (without rotating the speed rings) and tracker scheduling (stale UDP requests, due announces);
- every 50th tick (about 5 s): tracker "boost" when too few peers are connected; the webseed check also runs on this cadence;
- every 100th tick (about 10 s): `ntx_dht_tick()` when DHT is enabled.

### Event dispatch

`ntx_netx` keeps a table of file descriptors with read/write/close callbacks and a min-heap of timers. Peer sockets, the TCP listeners (IPv4 and IPv6), the shared UDP socket and the tracker UDP socket are all registered there. The shared UDP socket (bound to the same port as the TCP listener) is read by `ntx_netx` and demultiplexed by first byte: DHT packets go to `ntx_dht_input`, uTP packets to the uTP engine, everything else is dropped and counted. If binding that UDP port fails, the DHT falls back to its own socket and uTP is disabled. uTP and tunnel connections are exposed to the session as negative "virtual" file descriptors, so session code drives them like sockets.

## Session limits

| Constant | Value | Defined in |
|----------|-------|------------|
| `NTX_SESSION_MAX_TTS` | 16 torrent slots | `ntx_session.h` |
| `NTX_SESSION_MAX_PEERS` | 128 peer slots | `ntx_session.h` |
| `NTX_SESSION_MAX_TRK` | 32 trackers per torrent | `ntx_session.h` |
| `NTX_PEER_REQ_LEN` | 16384 (block size) | `ntx_peer.h` |
| `NTX_PEER_PIPE_MIN` / `NTX_PEER_MAX_REQ` | 32 / 128 requests in flight per peer (`NTX_PIPE_INFLIGHT` is an alias of the minimum); depth scales with measured throughput | `ntx_peer.h`, `ntx_session_internal.h` |
| `NTX_SEED_RATIO_NUM` | 3 (stop uploading at 3 x torrent size) | `ntx_session_internal.h` |
| `NTX_UNCHOKE_BEST` | 10 peers unchoked by speed, plus one optimistic unchoke | `ntx_session_internal.h` |
| `NTX_SEED_MAX_OK` / `NTX_SEED_MAX_HS` | 48 connected / 12 handshaking peers while seeding | `ntx_session_internal.h` |
| `NTX_PEER_MAX_PER_ADDR` | 8 connections per remote address | `ntx_session_internal.h` |
| `NTX_PEER_IDLE_TIMEOUT_S` | 300 s without data from an established peer | `ntx_session_internal.h` |
| `NTX_PEER_CONN_TIMEOUT_S` / `NTX_PEER_CONN_TIMEOUT_FAST_MS` | 5 s connect timeout; 2.5 s while fewer than `NTX_MIN_OK_PEERS` (3) peers work | `ntx_session_internal.h` |

`--max-peers` (default 128) lowers the peer-slot cap at run time.

## Build identity

`ntx_main.c` prints `ntx: build <NTX_BUILD_ID> compiled <date> <time>` on stderr at startup (`NTX_BUILD_ID` is `seed-ratio-v1` unless `NTX_IPC_BUILD_ID` is defined at compile time) and `--version` prints `NTX_VERSION` from `src/core/ntx_config.h`. The same build id appears in the JSON `hello` line.
