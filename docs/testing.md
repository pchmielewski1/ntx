# Testing

## How the test suite is built

Every file `test/t_*.c` is a standalone program with its own `main()`. The tests `#include` the `.c` files they need from `src/` directly, so each suite compiles with a single compiler command and links nothing else. A suite exits 0 on success and prints `PASS ...` lines; any failure exits non-zero.

`make test` compiles and runs every `test/t_*.c` in turn, using the Makefile's `CFLAGS` (`-O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections`). It stops at the first failure and prints `ALL PASS` at the end. All suites share one output file, `.test.tmp` in the repository root, so do not run two `make test` invocations in the same checkout at the same time.

Run tests from the repository root: suites read vectors and fixtures with paths such as `test/vectors/...`.

### Running a single suite

```sh
cc -O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -o /tmp/t_sha1 test/t_sha1.c -lm && /tmp/t_sha1
```

Replace `t_sha1` with any file name from the table below. (`test/t_*` binaries are gitignored, so compiling to `test/t_sha1` also works.)

## Makefile targets

| Target | What it does |
|--------|--------------|
| `make ntx` (also `make all`) | Builds the `./ntx` binary from every `src/**/*.c` with the hardening flags (`-fPIE`, `-fstack-protector-strong`, `_FORTIFY_SOURCE=2`, `-pie`, full RELRO, non-executable stack). |
| `make test` | Compiles and runs every `test/t_*.c` (see above). Needs no network, but several suites open loopback sockets, and a few fork helper processes. |
| `make test-cli` | Builds `ntx`, then runs `test/cli_errors.sh`: invalid command lines must fail fast with a message and a non-zero exit status. Needs no network. |
| `make test-net` | Builds `ntx`, then runs `test/net_loopback.sh`: starts `ntx` for 2 seconds with a dummy magnet link and checks that the listen port is inside `--port-lo`/`--port-hi` and the JSON status contains `port`. |
| `make test-ipc` | Alias for `make interop_ipc`. Builds `ntx`, then runs `test/interop/ipc/interop_ipc.sh`: end-to-end test of the JSON control channel (`--stats-json` with commands on stdin) using `python3` as the checker. |
| `make test-tls13` | Runs `test/tls13_interop.sh`: builds `test/tls_probe.c` (the real `ntx` TLS client) and talks to `openssl s_server` on loopback: ECDSA-P256 and RSA certificates, ALPN, SPKI pin match and mismatch, server-initiated KeyUpdate, fallback to TLS 1.2. Needs the `openssl` CLI; without it the script exits 77 and the target reports success (skipped). |
| `make test-live` | Compiles and runs only `test/t_tls_golden.c`, which replays the committed TLS 1.3 captures in `test/fixtures/tls/`. Despite the name it is offline and deterministic; the same suite also runs under `make test`. |
| `make test-interop` | Docker-based interop test against `transmission-daemon` (`test/interop/Dockerfile`, `test/interop/interop.sh`). Builds an image from a copy of `Makefile`, `src/` and `test/interop/`, compiles `ntx` inside the container, downloads a 1 MiB seeded file and checks handshake, MSE/PE, piece download and tracker announce. Needs Docker and network access for the image build. Scratch files go to `test/.scratch/`. |
| `make size` | Builds `ntx`, prints `size ntx` and `ls -l ntx`, and fails if the binary is 1 MiB (1048576 bytes) or larger. |
| `make static` | Builds a static binary with `musl-gcc` (needs musl installed). |
| `make probe` | Builds `./trk_http_probe` from `test/trk_http_probe.c`. It is a manual tool, not a test: it announces a fixed info hash to a few public HTTP trackers and prints `<url> rc=<status> np=<peers>` for each. It needs internet access, and exits 0 if at least one tracker returned peers. |
| `make clean` | Removes `ntx`, `trk_http_probe` and the temporary test binaries. |

There is no Make target for fuzzing; see [fuzzing.md](fuzzing.md).

## Continuous integration

`.github/workflows/ci.yml` runs on pushes to `main`/`master` and on pull requests.

- Job `build-test`, on `ubuntu-latest` (x86_64) and `ubuntu-24.04-arm` (aarch64): `make ntx`, `make size`, `make test`, `make test-cli`, `make test-net`, `make test-ipc`, `make test-tls13`.
- Job `sanitizers`, on `ubuntu-latest`: `make test` with `CFLAGS="-O1 -g -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=undefined -std=c11 -D_POSIX_C_SOURCE=200809L"` and `ASAN_OPTIONS=detect_leaks=0`. (Overriding `CFLAGS` drops `-Werror`.)

`make test-live`, `make test-interop`, the other interop scripts and `make probe` are not run in CI.

## Sanitizer sweep

`test/scripts/sweep.sh OUTDIR [extra cflags...]` compiles and runs every `test/t_*.c` in parallel (`JOBS`, default 8) and writes `OUTDIR/summary` with one line per suite (`OK`, `FAIL ... rc=N` or `CCFAIL`) followed by `DONE`, plus per-suite logs. Example:

```sh
test/scripts/sweep.sh /tmp/asan -O1 -g -fno-omit-frame-pointer \
    -fsanitize=address,undefined -fno-sanitize-recover=undefined \
    -Wno-format-truncation -Wno-restrict
```

The script compiles with `gcc`. Suites that open fixed ports or directories can collide when run in parallel, so re-run a failing suite on its own before treating the failure as real.

## Suites

All files are in `test/`.

### Cryptography

| Suite | What it tests |
|-------|---------------|
| `t_sha1.c` | SHA-1 known answers and streaming input |
| `t_sha256.c` | SHA-256 known answers and streaming input |
| `t_hmac.c` | HMAC-SHA1 known answers |
| `t_hmac_sha256.c` | HMAC-SHA256 known answers |
| `t_hkdf.c` | HKDF-SHA256: RFC 5869 case 1, empty salt, determinism |
| `t_mac_kat.c` | HMAC-SHA1/-SHA256 (one-shot and incremental), HKDF-Expand with long outputs, and the TLS 1.2 PRF, against vectors from `test/scripts/mac_vectors.py` |
| `t_aes.c` | AES-128 CTR known answers |
| `t_aes_gcm.c` | AES-128-GCM known answers, seal/open |
| `t_aes_kat.c` | AES-128-GCM/CTR against OpenSSL-made vectors; no plaintext released on a bad tag, in-place operation, every single-bit flip in ciphertext/AAD/tag rejected |
| `t_rc4.c` | RC4 and the MSE-style initialisation; zero-length or NULL key is rejected |
| `t_rng.c` | RNG initialisation, output, short `read()` handling, pool replacement after refill |
| `t_x25519.c` | X25519 with the RFC 7748 vectors; small-order and non-canonical points are rejected |
| `t_bignum.c` | Big-integer `mod`, `mulmod`, `modexp` and the Montgomery core against Python-generated vectors (odd/even moduli, leading zeros, 4096-bit modulus) |
| `t_dh_kat.c` | 768-bit DH (MSE/PE): known answers from Python `pow()`, key exchange, rejection of invalid peer keys, one-shot secret lifecycle |
| `t_p256_ecdsa.c` | ECDSA P-256 verification (good and bad hash), DER signature parsing, SPKI parsing, on-curve checks |
| `t_p256_kat.c` | ECDSA P-256 verification and SPKI parsing against OpenSSL-made vectors (tampered inputs, out-of-range `r`/`s`, off-curve and malformed keys) |
| `t_rsa_pkcs1.c` | RSASSA-PKCS1-v1_5/SHA-256 verification with one key from `test/vectors/rsa_pkcs1_sha256/` |
| `t_rsa_pkcs1_kat.c` | RSASSA-PKCS1-v1_5/SHA-256 against OpenSSL-made vectors (1024 to 4096-bit keys, tampered digests, degenerate keys) |
| `t_rsa_pss.c` | RSASSA-PSS (SHA-256, MGF1-SHA256, salt 32) verification, as used by TLS 1.3 `rsa_pss_rsae_sha256` |

### Encoding and protocol parsers

| Suite | What it tests |
|-------|---------------|
| `t_bencode.c` | Bencode parser on the vectors in `test/vectors/bencode/` |
| `t_magnet.c` | Magnet URI parsing: `xt` (hex and base32 `btih`, `btmh`), percent-decoding, tracker cap and de-duplication, `as`/`ws`, v1/v2/hybrid combinations |
| `t_http_url.c` | HTTP(S) URL parsing: path, default and explicit ports, IPv6 literals, bad input, query |
| `t_addr.c` | `ntx_addr`: construction, comparison, formatting, and the "special address" classifier |
| `t_ext.c` | BEP10 extension handshake and `ut_metadata` codec, including hostile values |
| `t_ext_tx_id.c` | Outgoing `ut_metadata` messages use the extension ID the peer advertised, not our own |
| `t_meta.c` | `ut_metadata` assembly and piece bounds |
| `t_pex.c` | BEP11 PEX: parse and build (IPv4 and IPv6), short records, dropped lists |
| `t_pex_tx.c` | Outbound PEX queue (`ntx_pex_tx`): connect/disconnect events, elision, de-duplication, caps, peek/commit |
| `t_wire_full.c` | Framing table for the core message ids (0 to 8, 14, 15, 20); self-contained, checks its own framing helpers |
| `t_wire_msgs.c` | Framing of the optional BEP6 ids (suggest, reject, allowed-fast); unit-level only |
| `t_wire_hs.c` | The 68-byte handshake built by the session: reserved bits (BEP10, Fast, DHT, BEP52) and info-hash matching |
| `t_hash_msg.c` | BEP52 hash request / hashes / hash reject codec against `test/vectors/bep52/hash_*` |
| `t_doh.c` | DNS wire parsing for DoH: A and AAAA answers, compressed names |
| `t_tracker.c` | UDP tracker (BEP15) packet build/parse and compact peers (IPv4 and IPv6) |
| `t_tracker_http.c` | HTTP tracker reply parsing and URL building; the HTTP connect path over IPv4 and IPv6 loopback and with a failing resolver |
| `t_http_chunked.c` | Chunked transfer decoding: the pure decoder, over a mock HTTPS stream, and over plain HTTP |
| `t_http_proxy_slow.c` | Plain HTTP GET through a SOCKS5 proxy stub that answers in slow pieces |
| `t_https_http.c` | `ntx_http_get_range` on `https://`: 200/206 responses, bad URL, SOCKS5 path, web-seed range, request-injection guard |
| `t_https_transport.c` | `ntx_https_connect`: handshake plus TOFU note, failure mapping, header and response reading (mock handshake) |
| `t_https_pin.c` | SPKI pins: host matching (exact and wildcard), pin file, lookup order, built-in pool, TOFU store and its events |
| `t_https_pin_tofu.c` | TOFU behaviour: first contact trusted, a different key for the same host rejected, LRU eviction when the table is full |

### Torrent, storage and piece logic

| Suite | What it tests |
|-------|---------------|
| `t_peer.c` | Per-peer state: init, bitfield and `have`, choke flags, request list, timeout |
| `t_peer_pipe_depth.c` | Request pipeline depth follows the peer's measured throughput |
| `t_store.c` | `ntx_store`: open/reopen, truncation and extension rules, partial writes, piece completion and verification, multi-file layout |
| `t_torrent.c` | Torrent init from metainfo, hash verification of existing data (`ntx_torrent_verify_range`), hash mismatch, multi-file pieces spanning a part boundary |
| `t_torrent_hostile.c` | Inconsistent metainfo is rejected before it sizes allocations: piece count versus size, absurd piece lengths, 64-bit wrap in multi-file sums |
| `t_merkle.c` | BEP52 Merkle trees: single-piece, multi-file, ingestion |
| `t_bep52_tree.c` | BEP52 file-tree parsing: fixtures, negative cases, file cap |
| `t_bep52_layers.c` | BEP52 piece layers: fixtures and negative cases |
| `t_bep52_meta.c` | v2/hybrid metainfo loading: pure v2, hybrid, wrong or missing layers, corrupted layers, invalid meta version |
| `t_bep52_verify.c` | Piece verification for v2/hybrid fixtures (SHA-256 Merkle), corrupted data, v1 regression |
| `t_bep52_endgame.c` | v2/hybrid fixtures: load, fill, verify, complete, including partial and wrongly ordered input |
| `t_bep52_hash.c` | Session-level info-hash selection for announce and handshake, and the gate on incoming metainfo (v1: SHA-1; v2: SHA-256 against `info_hash_v2`) |
| `t_bep52_stub.c` | Serving BEP52 hash requests: leaf base layer, proof omission, piece layer, reject cases, rate limit |
| `t_hash_exchange.c` | Requesting piece layers from peers: pending state, pump, `hashes` and `hash reject` handling, timeouts and rotation |

### Session (single-threaded protocol logic with socketpairs and fake peers)

| Suite | What it tests |
|-------|---------------|
| `t_session.c` | Session lifecycle: init/free, magnet add, `as=` web seed, snapshots, pause/resume per state, slot reuse, peer address validation, dual-stack listen, tracker announce state |
| `t_session_msgs.c` | Fast-extension messages are ignored where applicable, coalesced keep-alive plus piece, interest after bitfield |
| `t_session_bitfield.c` | A bitfield whose length is not exactly `ceil(pieces/8)` is rejected |
| `t_session_piece_guard.c` | Unsolicited, wrong-length, replayed or out-of-range `piece` messages and writes to verified pieces are refused |
| `t_session_req_timeout.c` | Per-request timeout and CANCEL with many requests in flight |
| `t_session_conn_timeout.c` | Connect timeout: 2.5 s while fewer than three peers work, 5 s otherwise |
| `t_session_idle_poll.c` | Reading through the OK-peer polling path refreshes the idle clock (no false 300 s idle drop) |
| `t_session_peer_limits.c` | Idle peer drop, per-address connection limit, request backpressure |
| `t_session_peer_filter.c` | Loopback, link-local, multicast and unspecified peer addresses are not dialled unless `--allow-local-peers` is set |
| `t_session_endgame.c` | Endgame completion: a piece verifies only when all its blocks arrived (block bitmap, not a high-water mark) |
| `t_session_endgame_dup.c` | Endgame duplicates: an idle peer re-requests the stalest outstanding blocks (at most two copies of a block, only blocks at least 1.5 s old); the first copy to arrive cancels the other; a late copy of a stored block is dropped |
| `t_session_upload.c` | Serving requests: direct and wire path, choked peers rejected, interest required |
| `t_session_shaping.c` | `--up-limit` / `--down-limit`: control messages are not dropped, limits below one block, reject (not cancel) for Fast peers, received blocks kept over the download limit |
| `t_session_resume.c` | Resume and verification: fresh store, resume of complete and partial data, already complete torrent, verification pump, magnet resume |
| `t_session_ext_tx.c` | `ut_metadata` request sent with the peer's advertised extension ID |
| `t_session_torrent_trackers.c` | Trackers from `announce` and `announce-list` of a `.torrent` are loaded (de-duplicated, capped) |
| `t_session_trk_http_peers.c` | HTTP tracker reply with IPv4 and IPv6 compact peers: every peer is used, nothing beyond the parsed arrays is read |
| `t_session_trk_pump.c` | Tracker pump: UDP trackers are sent within a time budget per loop pass, HTTP(S) trackers go after them |
| `t_session_verify_announce.c` | A torrent resumed from a paused verification announces `started`; a torrent that is complete on disk sends no announce |
| `t_session_trk_stop.c` | `event=stopped` announces: one torrent, all torrents, paused torrents skipped |
| `t_session_trk_udp.c` | UDP tracker replies: random transaction IDs, replies from the wrong address ignored, UDP trackers disabled behind a proxy or tunnel |
| `t_session_utp_fallback.c` | `--utp` dials that do not connect within `NTX_UTP_DIAL_MS` are redone over TCP; uTP is abandoned after repeated misses without success |
| `t_dial_backoff.c` | Redial back-off (`ntx_dial_bo`): table behaviour (30 s base, doubling, 10 min cap, replacement when full), blocked redial, expiry, a peer that reached OK is not penalised |
| `t_pex_flood.c` | PEX flood resistance: per-list caps, string size bound, truncation, session import limits, dropped entries not imported |
| `t_pex_outbound.c` | Outbound PEX through the session: added/dropped lists, elision, rate limit, drop cap |
| `t_holepunch.c` | BEP55 `ut_holepunch`: codec, relay and target policy, race handling, two-sided loopback punch |
| `t_ipc_ctrl.c` | JSON control channel: command parsing and dispatch, input framing, JSON string escaping, vectors in `test/vectors/ipc/` |
| `t_cli.c` | Status line and JSON output: line length budget, valid JSON structure, header fields, truncation flag, BEP52 and uTP tags |
| `t_cli_https.c` | Command-line parsing of `--no-https-tofu`, `--https-pin-file`, `--utp`, `--port-lo` (compiles `ntx_main.c` with `main` renamed) |

### Peer wire, DHT and golden replays

| Suite | What it tests |
|-------|---------------|
| `t_pe.c` | MSE/PE handshake between two instances over loopback, and wiping of handshake secrets afterwards |
| `t_pe_padding.c` | MSE/PE with padding split across reads, coalesced reads, and the leftover bytes handed to plaintext |
| `t_dht.c` | DHT engine on loopback UDP: `get_peers` encoding, dual-stack sockets, node injection, transaction IDs, iterative lookup, inbound queries and announces, rate limit, bootstrap |
| `t_dht_session.c` | Session with `--dht`: DHT starts, routing-table counters in stats, peers found by DHT reach the session (IPv4 and IPv6) |
| `t_dht_msg.c` | DHT message encode and parse (nodes, values, `want`) |
| `t_dht_rt.c` | Routing table: add, de-duplication, closest nodes, rejection of invalid entries |
| `t_dht_lookup.c` | Iterative lookup state: seeding, parallelism and cap, rounds, timeouts, closest set |
| `t_dht_tid.c` | Transaction-ID table: put/take for IPv4 and IPv6, mismatches, expiry |
| `t_dht_token.c` | Announce tokens: issue, verify, rotation, wrong address or secret |
| `t_dht_xor.c` | XOR distance, common-prefix length, comparison |
| `t_dht_state.c` | Node ID persistence in `ntx_dht_state` (restart keeps the ID; missing file gives a random ID) |
| `t_golden_announce.c` | Replays frozen HTTP tracker responses from `test/fixtures/announce/` through the real parser |
| `t_golden_dht.c` | Replays frozen DHT responses from `test/fixtures/dht/` through the real parser |
| `t_golden_pe.c` | Replays a frozen BitTorrent handshake/BEP10 exchange from `test/fixtures/pe/` against the wire code |

### Network layer (netx, sockets, proxy, tunnel, uTP, TLS)

| Suite | What it tests |
|-------|---------------|
| `t_sock_bind.c` | Port-range and specific bind (IPv4/IPv6), `connect_addr`, name resolution of literals |
| `t_proxy.c` | SOCKS5 client state machine and UDP encapsulation against a loopback proxy stub |
| `t_socks_udp.c` | SOCKS5 UDP ASSOCIATE framing against `test/vectors/socks/` and a loopback relay stub |
| `t_tunnel.c` | NTX1 tunnel OPEN request encoding for IPv4 and IPv6 |
| `t_netx_route.c` | Connect routing matrix: tunnel, then uTP/proxy, then raw TCP; tunnel configured but not ready falls through; proxy keeps TCP peers and HTTP(S); uTP over SOCKS5 UDP ASSOCIATE |
| `t_netx_shared.c` | Shared per-family UDP socket: when the listen port cannot be bound, DHT keeps working on its own socket and uTP is disabled |
| `t_utp_hdr.c` | uTP header, SACK and extension encode/parse against `test/vectors/utp/header/` |
| `t_utp_cc.c` | uTP congestion control: frozen constants and golden sequence from `test/vectors/utp/` |
| `t_utp_sm.c` | uTP state machine: open, data flow, SACK loss recovery, FIN, RESET, timeouts, zero window, RTT estimation |
| `t_utp_demux.c` | First-byte classifier that separates DHT and uTP datagrams, all 256 first bytes at lengths 1 and 2 |
| `t_utp_halfopen.c` | Unauthenticated SYNs only take capped half-open slots that are reaped after `NTX_UTP_HALFOPEN_MS` |
| `t_utp_net.c` | uTP on netx over real UDP loopback: listen, inbound and outbound connection, payload both ways, close |
| `t_utp_loopback.c` | End-to-end uTP byte stream through the public `ntx_netx_*` API (IPv4 and IPv6) |
| `t_utp_bt_handshake.c` | A BitTorrent handshake completes over uTP between two `ntx` sessions on loopback |
| `t_tls13.c` | TLS 1.3 building blocks (key schedule, `HKDF-Expand-Label`, Finished, records, ClientHello, ServerHello, certificate verify, KeyUpdate, full connection) against `test/vectors/tls13/kat.txt` and negative cases |
| `t_tls_golden.c` | Replays the TLS 1.3 captures in `test/fixtures/tls/` through the production handshake path (also run by `make test-live`) |
| `t_tls_pin.c` | TLS handshake against mock servers: ALPN, TLS 1.3 to 1.2 fallback, SPKI pin set and mismatch |
| `t_tls_rec_nonce.c` | The TLS 1.2 GCM record layer never reuses a (key, nonce) pair |

## Other test programs and scripts

| File | Purpose |
|------|---------|
| `test/cli_errors.sh` | `make test-cli` |
| `test/net_loopback.sh` | `make test-net` |
| `test/tls13_interop.sh`, `test/tls_probe.c` | `make test-tls13` |
| `test/interop/interop.sh`, `test/interop/Dockerfile`, `test/interop/tracker.py` | `make test-interop` (a minimal tracker runs next to `transmission-daemon` because its own announce endpoint is not usable) |
| `test/interop/ipc/interop_ipc.sh`, `assert_ipc.py` | `make test-ipc` |
| `test/interop/v2/` | BEP52 interop matrix, run by hand; see [`test/interop/v2/README.md`](../test/interop/v2/README.md) |
| `test/interop/utp/` | BEP29 uTP interop matrix (raw peer, relay and container engines), run by hand with `test/interop/utp/interop_utp.sh` |
| `test/run_magnet.sh`, `test/run_magnet_120.sh` | Manual smoke tests against a live swarm (internet and a magnet link or `.torrent` you may download). Not part of any Make target |
| `test/trk_http_probe.c` | `make probe` |
| `test/util.h`, `test/golden_meta.h` | Shared helpers for test programs (hex conversion; a minimal JSON reader for the `.meta.json` fixture sidecars) |
| `test/fuzz/` | libFuzzer harnesses; see [fuzzing.md](fuzzing.md) |
| `test/scripts/` | Reference vector generators and helper scripts; see [`test/scripts/README.md`](../test/scripts/README.md) |

Test data: `test/vectors/` holds known-answer vectors, mostly produced by the Python scripts in `test/scripts/` (independent of the C code); `test/fixtures/` holds frozen wire captures with `.meta.json` expectations. See [`test/fixtures/README.md`](../test/fixtures/README.md). Scratch output of scripts and fuzzing goes to `test/.scratch/`, which is gitignored.

## Size gate

The release binary must stay below 1 MiB (1048576 bytes). `make size` checks this and CI runs it on every push. `test/scripts/size_delta.sh [limit_kb]` is a local helper that prints the difference between the current `./ntx` and a size recorded in `test/.ntx-size-baseline`; that baseline file is not tracked in the repository, so the script only works if you create it yourself (a file containing the baseline size in bytes).
