# BitTorrent protocol

This document describes the BitTorrent wire protocol as `ntx` implements it today: which
messages and extensions are spoken, which limits and timeouts apply, and where the
implementation deliberately differs from the specifications. Transport details (sockets,
proxy, tunnel, DNS, TLS, uTP) are in [`network.md`](network.md); command-line options are in
[`cli.md`](cli.md).

The code is the source of truth. Sources: `src/proto/` (codecs and protocol helpers) and
`src/core/ntx_session_*.c` (session logic).

| Area | Specification | Status |
|------|---------------|--------|
| Peer wire | BEP 3 | implemented |
| Fast extension | BEP 6 | `have-all`, `have-none`, `reject` handled; `suggest` and `allowed-fast` ignored |
| Extension protocol | BEP 10 | implemented (`ut_metadata`, `ut_pex`, `ut_holepunch`) |
| Metadata exchange | BEP 9 | implemented, both directions |
| Peer exchange | BEP 11 | implemented; received `dropped` entries are ignored |
| Trackers | BEP 3, 12, 15, 23, 32 | HTTP(S) and UDP |
| Web seeds | BEP 19 | magnet `ws=` / `as=` only |
| DHT | BEP 5, 32 | iterative subset, only with `--dht` |
| uTP | BEP 29 | only with `--utp` (see `network.md`) |
| Padding files | BEP 47 | recognised when validating hybrid torrents |
| v2 / hybrid torrents | BEP 52 | implemented; TX side of the mid-connection upgrade is not |
| Holepunch | BEP 55 | acts as a connect target only (see `network.md`) |
| Encryption | MSE/PE | RC4 only; plaintext fallback by default |

## MSE / PE (Message Stream Encryption)

- Every peer connection starts in phase `PH_PE` (`ntx_pe.c`, `ntx_pe_vc.c`, `ntx_dh.c`):
  768-bit Diffie-Hellman, RC4 with the first 1024 bytes of keystream discarded in each
  direction, the verification constant (VC), and `crypto_provide` / `crypto_select`.
- Only the RC4 method (`crypto_provide` bit `0x02`) is offered and accepted. After a
  successful exchange the connection moves to `PH_BTHS` (the 68-byte BitTorrent handshake,
  usually carried inside the encrypted stream) and then to `PH_OK`. The whole wire
  (length, type, payload) stays RC4-encrypted from then on.
- **Plaintext fallback.** If the remote side begins with a plain `\x13BitTorrent protocol`
  handshake (inbound peers, or an outbound peer that answers our PE start in clear), the
  connection is handled as plaintext when `cfg.compat_peers` is set (`sp_plaintext_fallback`);
  otherwise it is dropped (`plaintext_strict`). The command-line client sets `compat_peers = 1`
  and the `--compat-peers` flag only repeats that default: there is no switch to turn the
  fallback off from the command line.
- MSE/PE obfuscates traffic. It does not authenticate the remote peer and is not strong
  confidentiality (see the limitations in the top-level `README.md`).

## BitTorrent handshake (68 bytes)

| Offset | Length | Field |
|--------|--------|-------|
| 0 | 1 | `pstrlen = 0x13` |
| 1 | 19 | `"BitTorrent protocol"` |
| 20 | 8 | reserved bits (below) |
| 28 | 20 | `info_hash` |
| 48 | 20 | `peer_id` |

Reserved bits we set (`sp_build_bt_handshake`):

| Byte | Bit | Meaning |
|------|-----|---------|
| 5 | `0x10` | extension protocol (BEP 10) |
| 7 | `0x04` | fast extension (BEP 6) |
| 7 | `0x01` | DHT (BEP 5), only with `--dht` |
| 7 | `0x10` | BEP 52 v2 support, only for v2 and hybrid torrents |

Incoming handshakes are accepted on magic string and info hash alone; the reserved bits are
not checked. See [BEP 52 reserved bit and hash selection](#bep-52-reserved-bit-and-hash-selection)
for how a v2 hash is matched.

## Peer messages

Message IDs handled by `sp_process_msgs`:

| ID | Message |
|----|---------|
| 0-8 | choke, unchoke, interested, not interested, have, bitfield, request, piece, cancel |
| 13 | suggest (BEP 6): ignored |
| 14 / 15 | have-all / have-none (BEP 6) |
| 16 | reject request (BEP 6) |
| 17 | allowed-fast (BEP 6): ignored |
| 20 | extended (BEP 10) |
| 21 / 22 / 23 | hash request / hashes / hash reject (BEP 52, see below) |

- A keep-alive is four zero bytes (`00 00 00 00`).
- `bitfield` must be exactly `ceil(pieces / 8)` bytes; any other length drops the peer
  (`bad_bitfield_len`). A bitfield that arrives before the metadata is known is kept and
  checked once the metadata is complete; if its length is wrong at that point it is ignored.
- `reject` (16) is sent only to peers that speak the fast extension, as the answer to a
  request we cannot or will not serve. A received `reject` frees the matching outstanding
  request and stops us from asking that peer for new blocks for 5 seconds.
- `cancel` removes a deferred request from the upload queue.
- Builders are in `ntx_btmsg.c`; the senders are the `ntx_session_peer_send_*` wrappers in
  `ntx_session_peer.c`.

## Extension protocol (BEP 10) and metadata exchange (BEP 9)

- Our extended handshake advertises `ut_metadata` = 1, `ut_pex` = 2 and, only when `--utp` is
  on, `ut_holepunch` = 3 (`ntx_ext.h`). It also carries our listen port, a version string
  (`ntx/<version>`) and, once we have it, `metadata_size`.
- **Sending** to a peer uses the IDs from *that peer's* extended handshake; **receiving**
  uses our own IDs (`NTX_EXT_LOCAL_*`), as BEP 10 specifies.
- Metadata is transferred in 16384-byte blocks, with up to 16 requests in flight
  (`NTX_META_INFLIGHT`). The metadata size is capped at 16 MiB. A metadata fetch that has
  not completed after 120 seconds (`NTX_META_TIMEOUT_S`) is restarted.
- Assembled metadata is only accepted if it hashes to the info hash: SHA-1 for v1, SHA-256
  for v2 and hybrid torrents (compared with `info_hash_v2`).

## Rate limits and the upload queue

`--down-limit` and `--up-limit` use a token bucket (`ntx_session_shape_ready` /
`ntx_session_shape_use`) that counts **block payload only**: outgoing `request` messages on the
download side and `piece` messages on the upload side. Control messages (have, choke,
keep-alive, extension messages, ...) are never delayed or dropped. Received blocks are never
discarded because of the download limit.

The burst size is one second of the limit. The bucket may go negative (a block larger than the
remaining budget creates a debt), so the long-run average equals the limit even for limits below
16 KiB, and an idle period repays the debt only at the limit rate.

An upload request that cannot be served immediately goes into a per-peer queue
(`NTX_UPQ_MAX` = 32 entries, served in order from the tick, duplicates by piece index and offset
ignored). When the queue is full the request is refused with `reject` (fast peers only). Upload
counters (`up_total`, share ratio) grow only when a block is actually sent.

## Session behaviour

- **Request pipeline:** blocks are 16384 bytes. A peer starts with 32 requests in flight
  (`NTX_PEER_PIPE_MIN`); the depth grows up to 128 (`NTX_PEER_MAX_REQ`) in proportion to the
  peer's measured throughput (about two seconds of data in flight, see
  `ntx_peer_pipe_depth`).
- **Request timeout:** 30 seconds (`NTX_PEER_REQ_TIMEOUT_S`); 12 seconds
  (`NTX_PEER_REQ_TIMEOUT_FAST_S`) while a partially downloaded piece exists.
- **Idle peers:** an established peer that sends nothing for 300 seconds is dropped.
- **Upload choking:** the 10 best peers (`NTX_UNCHOKE_BEST`) are unchoked, plus one
  optimistic unchoke that rotates every 30 seconds.
- **Bad data:** a peer that sent a piece that failed verification is banned for 60 seconds
  (`NTX_TORRENT_PEER_BAN_MS`).
- **Piece selection:** rarest first.
- **Seeding limit:** once a completed torrent has uploaded three times its size
  (`NTX_SEED_RATIO_NUM`), the session stops serving it: peers are choked, new requests are
  refused and the tracker is no longer announced to.

## Trackers

- The tracker list of a torrent is `announce` plus the flattened `announce-list` of the
  `.torrent` file (BEP 12; all tiers are announced to in parallel). Only `http://`,
  `https://` and `udp://` URLs shorter than 512 bytes are kept, duplicates are dropped, and
  at most `NTX_SESSION_MAX_TRK` (32) trackers are used. For magnet links the list comes from
  the `tr=` parameters (also at most 32, de-duplicated, then shuffled once with Fisher-Yates);
  `.torrent` trackers keep their file order.
- **HTTP(S):** the query carries the percent-encoded `info_hash` and `peer_id`, `compact=1`,
  `numwant`, `key` and, when applicable, `event`. Compact `peers` (6 bytes per peer) and
  `peers6` (18 bytes per peer, BEP 7/32) are imported independently. HTTPS uses the in-tree
  TLS client with SPKI pinning (see `network.md`).
- **UDP (BEP 15):** connect then announce; the connection id is refreshed after 60 seconds.
  The reply may carry an IPv6 tail after the IPv4 peers, which is used if the remaining length
  is a multiple of 18. UDP trackers are contacted over IPv4 only and are **skipped
  entirely** when `--proxy` or `--tunnel` is active, because UDP would bypass them.
- The announce interval from the tracker is clamped to 60-10800 seconds (default 1800 when
  the tracker gives none).
- A UDP announce with no reply after 8 seconds counts as one failure. After
  `NTX_TRK_MAX_FAIL` (3) consecutive failures a tracker is treated as dead and not contacted
  again.
- On `remove` and on exit the session sends `event=stopped` (HTTP synchronously, UDP as a
  fire-and-forget datagram when a connection id exists) to trackers with no recorded failures,
  within a total budget of 3 seconds. Replies to `stopped` are not processed.

## Magnet links (BEP 9)

`ntx_magnet.c` understands:

- `xt=urn:btih:<40 hex | 32 base32>` and `xt=urn:btmh:1220<64 hex>` (BEP 52 multihash,
  `0x12` = SHA-256, exactly `1220` followed by 64 hex digits). A repeated `xt` of the same
  type is rejected; a link may carry both a `btih` and a `btmh` (hybrid).
- `dn` (display name), `tr` (trackers, at most 32, de-duplicated), `ws` (web seed URL) and
  `as` (acceptable source). If there is no `ws`, `as` is used as the web seed.

## Connection set-up and download speed

These mechanisms decide how quickly a download starts and how well it uses a swarm in which
most advertised addresses are dead.

- **Peers per announce.** Both tracker protocols ask for `NTX_TRACKER_NUMWANT` (200) peers
  (HTTP `numwant`, UDP `num_want`), and the parsers accept that many addresses. In a large
  swarm the great majority of returned addresses do not answer, so the number of attempts
  matters more than the quality of any one reply.
- **Start without blocking.** `ntx_session_trk_announce` only queues UDP trackers.
  `ntx_session_trk_pump_udp` (called from the main loop and from the tick) resolves host
  names (one DoH lookup per new host; results are cached) and sends within a budget of
  `TRK_UDP_PUMP_BUDGET_MS` (100 ms) per loop iteration, so replies from the first trackers are
  handled before the rest are contacted. HTTP(S) trackers block the loop while they
  wait for the server, so they are deferred: when the torrent has live UDP trackers, each HTTP
  announce is delayed by `TRK_HTTP_AFTER_UDP_MS` (2.5 s, plus a random 0-150 ms), and
  `ntx_session_trk_pump_http` starts at most one per loop iteration.
- **Connect timeout.** An outbound connection that has not completed after
  `NTX_PEER_CONN_TIMEOUT_S` (5 s) is dropped. While fewer than `NTX_MIN_OK_PEERS` (3) peers
  are established the limit is `NTX_PEER_CONN_TIMEOUT_FAST_MS` (2.5 s), because a SYN that is
  unanswered for 2.5 s rarely gets through and the slot is better spent on another address.
  With `--utp`, the limit for a uTP dial is `NTX_UTP_DIAL_MS` (1.5 s); see below.
- **Redial back-off** (`ntx_dial_bo.h`). An outbound attempt that fails blocks the same
  `address:port` for 30 s (`NTX_DIAL_BO_BASE_MS`), doubling with every further failure up to
  10 min (`NTX_DIAL_BO_MAX_MS`). The table holds 512 entries (`NTX_DIAL_BO_N`). A connection
  that reaches the established state clears the entry. Dials caused by a BEP 55 `connect`
  message bypass the back-off, because the remote side is dialling us at the same time
  (`ntx_session_add_peer_dial_ex` with `force = 1`).
- **Pipelining.** See the request pipeline above: 32 requests in flight at first, growing
  with measured throughput.
- **Endgame.** When at most `NTX_ENDGAME_MAX_PIECES` (32) pieces are missing and every missing
  block is already requested from some peer, an otherwise idle peer also requests the oldest
  outstanding blocks of other peers (older than `NTX_ENDGAME_MIN_AGE_MS`, 1.5 s), so that at most
  two requests exist for the same block. The first copy to arrive sends `cancel` to the other
  peers; a late second copy is discarded without overwriting data or being counted twice
  (`piece_blk_have`).
- **`--utp`.** Outbound peers are dialled over uTP first. A uTP dial that has not connected
  after `NTX_UTP_DIAL_MS` (1.5 s) is repeated over TCP, and a uTP miss does not enter the
  redial back-off (only the TCP attempt can). After `NTX_UTP_GIVEUP_MISSES` (40) uTP misses in a
  session without a single uTP peer ever becoming established, new dials go straight to TCP.
  Details are in [`network.md`](network.md#utp-bep-29).

Tests for these paths: `t_session_trk_pump.c`, `t_session_conn_timeout.c`, `t_dial_backoff.c`,
`t_peer_pipe_depth.c`, `t_session_endgame_dup.c`, `t_session_utp_fallback.c`,
`t_session_trk_udp.c`, `t_session_trk_http_peers.c`.

## Peer exchange (BEP 11)

Sources: `ntx_pex.c` (codec), `ntx_pex_tx.c` (outbound event queue) and `ntx_session_pex.c`.

- **Outbound.** A peer that becomes established is queued as `added` (IPv4) or `added6`
  (IPv6); the disconnect of a peer that was advertised earlier is queued as `dropped` /
  `dropped6`. A connect followed by a disconnect before anything was advertised is cancelled.
  At most one message per minute is sent to each peer that supports `ut_pex`, with at most 50
  entries per list. The peer being sent to is removed from its own `added` list, and the
  queue holds at most 64 events per torrent (`NTX_PEX_TX_Q`).
- **Inbound.** Up to 32 `added` and 32 `added6` entries per message are handed to the dial
  path. `dropped` and `dropped6` are parsed but **ignored**: they describe the sender's
  connections, and honouring them would let a hostile peer evict good peers.

## BEP 55 holepunch (`ut_holepunch`)

`ut_holepunch` is advertised only with `--utp`. On receiving a `connect` message the session
dials the given endpoint over uTP. It never sends `rendezvous` messages and does not act as a
relay. Codec, relay and target policy, tie-break and counters are described in
[`network.md`](network.md#holepunch-bep-55).

## DHT (BEP 5, BEP 32)

Enabled only with `--dht`; cannot be combined with `--proxy` or `--tunnel` (a fatal error).
Sources: `ntx_dht.c`, `ntx_dht_msg.c`, `ntx_dht_rt.c`, `ntx_dht_lookup.c`, `ntx_dht_tid.c`,
`ntx_dht_token.c`.

- **Sockets.** IPv4 shares the listen-port UDP socket owned by `ntx_netx` (datagrams are
  classified by their first byte, see `network.md`); if that socket could not be bound the
  DHT opens its own. IPv6 uses a separate `AF_INET6` socket (`IPV6_V6ONLY`) on an ephemeral
  port.
- **Node id** (20 bytes) is stored in `<store_dir>/ntx_dht_state` and reused on the next start.
- **Routing.** Two tables, one per address family. Each has 16 buckets selected by the high
  nibble of the first byte of the XOR distance, `K = 8` nodes per bucket, a shared replacement
  list of 8, and nodes expire after 15 minutes. This is a fixed-granularity simplification of
  the Kademlia routing table.
- **Lookup.** An iterative `get_peers` with `alpha = 3`, a 2 s timeout per queried node and
  15 s overall; the IPv4 and IPv6 lookups run in parallel. Transactions use 2-byte ids in a
  table of 64 entries with a 15 s TTL; a reply must match id, source address and port
  (IPv4-mapped addresses are normalised).
- **Serving.** `ping`; `find_node` (the `K` closest nodes from the routing table of the
  requester's address family, as `nodes` or `nodes6`); `get_peers` (a token plus stored `values`
  / `values6` and closest nodes); and `announce_peer` (token verified, then stored). Peers are
  stored for up to 16 info hashes, 100 IPv4 and 100 IPv6 peers per hash, least recently used
  evicted. Tokens are the first 8 bytes of `SHA-1(secret || address || family || time bucket)`
  with a 600 s window.
- **Announce.** After a download completes the session runs `announce_peer` towards the (up to
  8) closest nodes of each family for which it holds a token. When the routing table is empty
  it first sends `get_peers` to the seed nodes to obtain tokens.
- **Bootstrap.** `router.bittorrent.com`, `router.utorrent.com` and `dht.transmissionbt.com`
  (port 6881), resolved through DoH, are sent `find_node` for our own id.
- **Rate limits.** At most 40 outgoing packets per second in total, and at most 10 incoming
  packets per second per source address (a window of 1 s, tracked for 16 addresses).
- **When it is used.** Peer lookup (`get_peers`) is started when a torrent is added as a
  **magnet link**; torrents added from a `.torrent` file do not start a DHT lookup. Only one
  lookup runs at a time. The session announces itself on completion of a download.
- Counters: `ntx_dht_stats` (rx, tx, dropped) and `dht_nodes4` / `dht_nodes6` in the stats.

## Web seeds (BEP 19)

`ntx_session_webseed.c` issues HTTP `Range` requests to the URL from the magnet `ws=` (or
`as=`) parameter. `http://` and `https://` URLs work (HTTPS uses the pinned TLS client). Web
seeds are used only when no established peer is currently able to send data, they are polled
about every 5 seconds, and each poll fetches one block (at most 16 KiB) synchronously. The
request offset is the byte offset in the torrent's piece space; the code does not append file
paths, so a multi-file layout is not mapped. The `url-list` key of `.torrent` files is not read.
Downloaded pieces go through the normal hash verification.

## BEP 52 (v2 and hybrid torrents)

Modules: `ntx_torrent.c` (v1 / v2 / hybrid dispatch, hash gate, piece layers),
`ntx_torrent_meta.c` (version and info hash), `ntx_torrent_v2.c` and `ntx_torrent_v2_layers.c`
(file tree and piece layers), `ntx_merkle.c` (SHA-256 merkle tree and proof verification),
`ntx_magnet.c` (`btmh`), `ntx_hash_msg.c` (codec for messages 21-23). The peer transport,
including uTP, is shared between v1 and v2.

### What the metainfo parser accepts

`ntx_torrent_set_metainfo(t, info, len, store_dir, piece_layers)` takes the raw `info`
dictionary and, optionally, the top-level `piece layers` dictionary (a sibling of `info` in a
`.torrent` file, otherwise `NULL`).

1. **Hash gate.** If `info_hash_v2` is non-zero, `SHA-256(info)` must equal it; otherwise
   `SHA-1(info)` must equal `info_hash`. A mismatch is rejected.
2. **`meta version`.** Missing: v1 path. `2`: v2 or hybrid. Greater than 2, not an integer or
   malformed bencode: rejected.
3. For v2 and hybrid:
   - `piece length` must be an integer, a power of two, at least 16384 and at most 64 MiB.
   - `file tree` must be a dictionary. It is walked by `ntx_torrent_v2_tree_walk` (at most 64
     files); the root cannot be a file, every non-empty file has a 32-byte `pieces root`.
     Path components are sanitised: `.` becomes `_`, `..` becomes `__`, an embedded `/`
     becomes `_`, and a NUL byte rejects the torrent.
   - A torrent is **hybrid** when it also has a v1 `pieces` string (non-empty, length a
     multiple of 20). The v1 file list without BEP 47 padding files (attribute `p`, or path
     `[".pad", <int>]`) must match the v2 file table one to one in order, name and length; the
     v1 piece count must equal the v2 total and the v1 total size must equal the end of the v2
     piece address space.
   - **`piece layers`** are optional. If supplied (a `.torrent` file), `ntx_torrent_v2_layers`
     requires an exact match: every file longer than one piece has an entry keyed by its
     `pieces root` whose value is `pieces * 32` bytes and folds to that root with
     `ntx_merkle_root_from_layer`; any other entry (unknown root, or a file that fits in one
     piece) rejects the torrent. If they are absent, see the BEP 9 flow below.
   - A hybrid torrent opens its store through the v1 path (SHA-1) and the v2 fields are
     attached afterwards (`t->hybrid = 1`). A pure v2 torrent opens the store from the v2 file
     table and has no flat SHA-1 hash array (`t->phash == NULL`).

### Piece verification

`ntx_torrent_piece_complete_from` and `ntx_torrent_verify_range` (per piece, resumable;
`verify_range` returns the number of newly verified pieces):

- **v1:** SHA-1 against the flat `pieces` array.
- **Hybrid:** SHA-1 is required. When piece layers are present, the SHA-256 merkle hash must
  also match; both must pass. Without layers the merkle cross-check is skipped.
- **Pure v2:** SHA-256 merkle only. A piece hash is the root of the subtree over its 16 KiB
  leaves (zero-padded to balance the tree, `ntx_merkle_verify_piece_layer`); for a file no
  longer than one piece the piece hash must equal the file's `pieces root`. The length of
  piece `j` of file `f` is `min(piece_length, file_length - j * piece_length)`; alignment gaps
  between files are not stored.

### Info hashes

The 20-byte `info_hash` used in announces and handshakes:

| Torrent | `info_hash` |
|---------|-------------|
| v1 | `SHA-1(info)` |
| pure v2 (magnet with only `btmh`, or a `.torrent` file) | first 20 bytes of `SHA-256(info)` |
| hybrid added through a magnet link with both `xt` | the `btih` value, i.e. the v1 `SHA-1(info)` |
| hybrid added from a `.torrent` file | `SHA-1(info)` (`meta version = 2` plus a v1 `pieces` string identifies it as hybrid) |

The full 32-byte `info_hash_v2` is what the metainfo hash gate checks, both in
`ntx_torrent_set_metainfo` and when metadata is assembled.

### Hash messages (21, 22, 23)

Normative source: BEP 52, "Hash request", "Hashes" and "Hash reject". Byte-level test vectors are
in `test/vectors/bep52/` (generated by `test/scripts/bep52_hash_msgs.py`; each `<name>.meta.json`
describes the fields). Code: the codec is `ntx_hash_msg.c`; serving, sending and correlation are
in `ntx_session_peer.c` (`sp_serve_hash_request`, `sp_hash_pump`, `sp_rx_hashes`,
`sp_rx_reject`, `ntx_session_hash_tick`); proof verification is `ntx_merkle_ingest_hashes` in
`ntx_merkle.c`. The session counters (`hash_req_tx`, `hash_req_rx_ok`, `hash_rej`,
`layers_pending`, `meta_version`, `hybrid`) are described in [`json-api.md`](json-api.md).

#### Framing

Like every peer message: a 4-byte big-endian length (`1 + payload`), the id, the payload.
The payload of 21 and 23 is exactly 48 bytes (`NTX_HASH_REQ_PAYLOAD`), a 53-byte frame.
Message 22 is the same 48-byte header, echoed from the request, followed by the hash blob
(a multiple of 32 bytes).

| Payload offset | Size | Field |
|----------------|------|-------|
| 0 | 32 | `pieces_root`: merkle root of the file (SHA-256, branching factor 2, 16 KiB leaves) |
| 32 | 4 | `base_layer`: layer relative to the leaves, 0 = leaf hashes |
| 36 | 4 | `index`: position of the first hash within the base layer |
| 40 | 4 | `length`: number of base hashes, a power of two, at least 2 |
| 44 | 4 | `proof_layers`: number of uncle layers counted upward from `base_layer + 1` |

The four integers are fixed-size 4-byte big-endian values, not bencode. The parser for 21 and 23
requires exactly 48 bytes; the parser for 22 requires at least 48 bytes and a remainder that is a
multiple of 32. The builder for 22 rejects a blob shorter than `length` hashes.

#### Omitted layers in message 22

Let `lg = log2(length)`. The wire carries the `length` base hashes plus one uncle per layer from
`base + lg` up to `base + proof_layers`, i.e. `max(0, proof_layers - lg + 1)` uncles. The
first `lg - 1` proof layers are omitted (they can be computed from the base span) but still
count towards `proof_layers`. When `proof_layers < lg` there are no uncles and the reply is just
the base span. Example from the vectors (`hashes_omitted_proof_layers`): `length = 4`
(`lg = 2`), `proof_layers = 3` gives one omitted layer and 4 + 2 = 6 hashes on the wire.

The receiver (`ntx_merkle_ingest_hashes`) is strict about counts: it needs
`proof_layers >= lg - 1` and exactly `length + (proof_layers - (lg - 1))` hashes. It folds the
span to a subtree root, climbs the uncles along the even-aligned path given by `index / length`
and compares the result with `pieces_root`. `base_layer` does not take part in verification
(the geometry follows from `index` and `length`), but a server must echo it faithfully because
reply correlation compares the whole header.

#### Serving requests (inbound 21 answered with 22 or 23)

- Every well-formed 21 is answered with 22 or 23; there is no silent drop. A request that
  violates the constraints (`length` not a power of two or less than 2, or `index % length != 0`;
  `ntx_hash_req_constraints_ok`) is answered with 23 echoing the request. A payload that is not
  48 bytes is discarded without a reply (it is not a request).
- Choking does not block serving, and sending a 21 is not gated by choking either.
- **Request budget.** If we already have `NTX_PEER_MAX_REQ` (128) block requests outstanding to
  that peer, the request is answered with 23. Each served request reads the whole file from the
  store and rebuilds its tree, so this limits CPU and memory amplification; the budget is shared
  with the piece-request path and there is no cache.
- **Root check.** `pieces_root` must be the root of a file of this torrent (the torrent must be
  v2 or hybrid with metadata). An unknown root gets 23, so a pure v1 torrent always answers 23.
- A file without a piece layer (no longer than one piece) gets 23, and so does a file that is not
  completely downloaded (the tree is rebuilt from the bytes in the store).
- **Index binding.** Besides the constraints above, the geometry must fit:
  `base_layer <= height`, `base_layer + lg <= height`, either no uncles or
  `base_layer + proof_layers <= height - 1`, and the span must lie inside the base layer:
  `index + length <= pieces >> base_layer`. Anything else gets 23. This closes an out-of-range
  `index` that `index % length` alone would not catch.
- `base_layer == 0` is not rejected when the file is complete; leaf hashes are served from the
  rebuilt tree.
- The reply echoes the request header unchanged. A build or allocation error gives 23.

#### Requesting hashes (outbound 21, correlation of 22 and 23)

The exchange runs while `ntx_torrent_layers_pending(t)` is true (pure v2, `meta_version == 2`,
not hybrid, no `piece_layer` yet, and at least one file longer than one piece) and the torrent is
not in `layers_stall`. It is driven by `ntx_session_hash_tick`, called from the handshake tick.

- **One request per file** covers the whole piece layer: `base_layer = log2(piece_length /
  16384)`, `index = 0`, `length = next_pow2(pieces)` (at least 2),
  `proof_layers = height - base_layer - 1`. Single-piece files and degenerate trees are skipped
  (they verify through the single-piece path).
- **Outstanding requests:** at most `NTX_HASH_OUT_MAX` (8) per torrent and one per file at a time.
  Peers are picked round-robin (`hash_rr`) and a peer that is at its request budget is skipped.
- **Attempts:** at most `NTX_HASH_TRIES_MAX` (6) per file. When they are used up and nothing is
  outstanding the torrent enters `layers_stall`, so the phase is bounded.
- **Timeout:** an outstanding request older than `NTX_HASH_TIMEOUT_MS` (8 s) is released, counted
  in `hash_rej`, and the next pump tries another peer.
- **No peers:** if no established peer exists for `NTX_HASH_STALL_MS` (60 s) the exchange stalls.
  When a new established peer appears, the stall and the attempt counters are cleared.
- **Correlation.** A 22 or 23 is trusted only if it matches an outstanding 21 that was sent to
  *the same peer*, on the full header (32-byte root and the four integers). Otherwise it is
  counted in `hash_ignore` and nothing is ingested. Binding to the source stops peer A from
  answering a request that was sent to peer B.
- **Ingesting 22.** The proof is checked with `ntx_merkle_ingest_hashes`. On failure the slot is
  dropped, `hash_rej` is incremented and another peer is tried. The span is clamped to
  `pieces * 32` bytes and must be complete. Verified spans go into a per-file scratch buffer
  (`hash_req_rx_ok` counts them). When every file has its layer, `ntx_torrent_apply_piece_layer`
  recomputes each slice with `ntx_merkle_root_from_layer` and compares it with the file's
  `pieces root` *before* the bytes are trusted; on a mismatch the scratch is discarded and the
  exchange restarts.
- **Handling 23.** A correlated reject releases the slot (the next peer is tried) and counts in
  `hash_rej`; an uncorrelated one counts in `hash_ignore`.
- `hash_rej` is a single counter for three causes: a 23 from a peer, an invalid or short 22, and
  a timed-out request.

#### Pure v2 over BEP 9

`ut_metadata` carries only the `info` dictionary; the top-level `piece layers` never arrives that
way. After assembly (the hash gate `SHA-256(info) == info_hash_v2` runs before parsing):

1. For a pure v2 torrent, `piece_layers = NULL` is accepted. The torrent leaves the metadata
   state (`have_meta = 1`) and metadata is not requested again. A layers dictionary that is
   *supplied* (the `.torrent` path) is still rejected if wrong or short.
2. `layers_pending` turns on the 21/22/23 exchange. A torrent whose files all fit in one piece
   never sets it; those pieces verify immediately.
3. Until layers exist, multi-piece files cannot be verified (`piece_layer == NULL` and
   `phash == NULL` fall through to a check that fails for files longer than one piece);
   single-piece files verify at once. A peer that sends data that cannot be verified *yet* is
   not banned: a ban requires `!layers_pending`.
4. When the layers arrive, `apply_piece_layer` validates every slice against its root,
   `layers_pending` clears, and verification proceeds normally.

#### BEP 52 reserved bit and hash selection

- **Sending.** `reserved[7] |= 0x10` when the torrent is hybrid or `meta_version == 2`. A v1
  torrent does not set it. The bit coexists with the fast (`0x04`) and DHT (`0x01`) bits, so a
  hybrid torrent with DHT sends `0x15` in that byte.
- **Receiving (mid-connection upgrade).** A handshake answered with
  `trunc20(SHA-256(info))` is accepted when the exact v1 match failed and the candidate torrent
  has `meta_version == 2` with a non-zero `info_hash_v2` (`sp_match_tts`). A pure v1 torrent can
  never match this way. Acceptance does not depend on the reserved bits.
- **Not implemented:** answering a v1 handshake with the v2 hash (the TX side of the upgrade) is
  optional in BEP 52 and `ntx` does not do it.
- **Hybrid swarms.** A hybrid torrent joins the swarm through its SHA-1 info hash, like v1.
  Pieces are verified in both formats as described above.

### Deviations and limits

- BEP 52 recommends that `length` of a hash request should not exceed 512; this is not
  enforced (`ntx_hash_req_constraints_ok` checks only the power of two and alignment). Server
  protection is the request budget and index binding, and the receiver counts hashes exactly.
- `meta_version` is `0` for v1 (the key is absent) and `2` for v2 and hybrid; `1` is not used.
- No third-party v2 client was available for interoperability tests; see the notes in
  [`testing.md`](testing.md) and `test/interop/v2/`.

Tests: `t_hash_msg.c`, `t_hash_exchange.c`, `t_merkle.c`, `t_bep52_meta.c`, `t_bep52_tree.c`,
`t_bep52_layers.c`, `t_bep52_verify.c`, `t_bep52_hash.c`, `t_bep52_endgame.c`.

## Transport, TLS, tunnel

HTTPS pinning and TLS, the NTX1 tunnel, SOCKS5 and uTP are described in
[`network.md`](network.md).
