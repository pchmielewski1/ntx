# Storage, resume and seeding

How `ntx` lays out files on disk, what it does with data that already exists, when it stops
seeding, and the limits that bound a session. Implementation: `src/core/ntx_store.c`,
`src/core/ntx_torrent.c`, `src/core/ntx_session*.c`; the constants live in
`src/core/ntx_session_internal.h`, `src/core/ntx_peer.h`, `src/core/ntx_torrent.h` and
`src/core/ntx_config.h`.

Protocol details are in [protocol.md](protocol.md); sockets, uTP, DHT and proxies are in
[network.md](network.md); the options are in [cli.md](cli.md).

## Directory and file layout

The store directory is `--store-dir=DIR`, default `downloads` (relative to the working directory).
Directories are created as needed (mode `0755`), files with mode `0644`.

| Torrent | Path on disk |
|---------|--------------|
| v1, single file | `<store>/<name>` |
| v1, multiple files | `<store>/<name>/<path…>` |
| Pure v2 | `<store>/<file-tree path>` (no torrent-name directory) |
| Hybrid (v1 + v2) | The v1 layout. The v2 file tree is cross-checked against it; a mismatch rejects the metainfo. |

Details:

- **Name sanitising (v1).** `/` in the torrent name becomes `_`; an empty name becomes `untitled`. In multi-file torrents a path component that is empty, `.` or `..`, or that contains `/` or a NUL byte, rejects the metainfo.
- **Single-entry multi-file torrents.** A v1 multi-file torrent with exactly one file is shown under that file's base name.
- **Pure v2.** Path components are sanitised (`.` becomes `_`, `..` becomes `__`, `/` becomes `_`). At most 64 files are supported (`NTX_TORRENT_MAX_FILES_V2`). The displayed name is the base name of the first file. The padding between files that v2 uses for alignment is not stored.
- **Piece length.** At most 64 MiB (`NTX_TORRENT_MAX_PIECE_LEN`). For v2 it must also be a power of two and at least 16 KiB.

Other files `ntx` may write into the store directory:

| File | When | Content |
|------|------|---------|
| `https_tofu.bin` | Unless `--no-https-tofu` | Pinned certificate keys for HTTPS trackers and DoH, at most 32 records (host, 32-byte pin, last-seen time); written atomically (temporary file, then rename). |
| `ntx_dht_state` | With `--dht` | The 20-byte DHT node id, so the id survives restarts. |
| `<name>-<8 hex>.torrent` | Per `--share` | The private hybrid metainfo of the shared file, mode `0600`. See [Sharing a file](#sharing-a-file). |

`ntx-verbose.log` (with `--verbose` / `--log`) is written to the working directory, not the store, and is truncated at start.

## File I/O

- Each file is opened read-write. A new file is created and extended to its full length with `ftruncate`, so it is sparse on file systems that support holes.
- An existing file that is **shorter** than the torrent says is extended. One that is **longer** is left as it is (nothing is ever truncated or deleted) and a diagnostic is printed.
- Data is read and written with `pread` / `pwrite` at the piece offset. `ntx` does not call `fsync`; durability is left to the operating system.
- Per-piece state (`pmap`): `0` = missing or failed verification, `1` = written, not yet verified, `2` = verified.
- A piece is accepted only after it verifies: SHA-1 against the `pieces` hash for v1, the Merkle root of 16 KiB block hashes for v2, both for hybrid torrents. A piece that fails is discarded and **the peer that supplied it is banned for 60 seconds** (`NTX_TORRENT_PEER_BAN_MS`).
- Progress (`pct`, `down`) counts verified bytes only. The transfer totals (`down_total`, `up_total`) count block payload bytes, not protocol overhead.
- Rate limiting (`--down-limit`, `--up-limit`, `--smooth`) is a token bucket with a one-second burst. It applies to block payload only.

## Resume and verification

When the metainfo becomes available (immediately for a `.torrent`, after the metadata download for a magnet link), the store is opened. If **any** file or part of the layout already existed, the torrent enters state `VERIFY` (phase `verify`); otherwise it goes straight to `DL`.

In `VERIFY`, `ntx` scans the files in order, 100 ms tick by tick, hashing up to 2 MiB per tick (at least one piece). The scan does not ban peers and does not send `have` messages. When the scan reaches the last piece:

- every piece valid: the torrent becomes `DONE` and is marked as already complete;
- otherwise: `DL`, with the valid pieces kept. Only the missing pieces are requested.

Verified pieces from the scan count immediately towards `pct` and `down`.

Behaviour of a torrent that was **already complete** when `ntx` started:

- It sends no `completed` announce.
- It sends no tracker announce at all: the `started` event is sent only when verification ends with missing pieces. Peers then find it through incoming connections, DHT and PEX, not through trackers. (The test `t3d` asserts that zero announces are sent.)

A magnet link whose data already exists on disk resumes in the same way, after its metadata has been fetched. If the metadata is not received within `NTX_META_TIMEOUT_S` (120 s), the request is repeated to the peers; `ntx` does not give up.

## Sharing a file

`--share=PATH` (design §5) is the one case where `ntx` serves data it did not download. The
storage side has three parts: a read-only store over a held descriptor, a metainfo built in
memory, and one `.torrent` file written to the store directory.

- **The file is never written to and never re-opened.** `ntx_session_share_add` opens it
  `O_RDONLY | O_CLOEXEC`, checks `S_ISREG` and `st_size > 0`, and keeps the descriptor for the
  whole life of the share. `ntx_store_open_ro_fd` builds the store on top of that
  caller-owned descriptor: no `open`, no `ftruncate`, no `mkdir`, and the descriptor is not
  closed by the store. Because the descriptor is held, renaming or unlinking the path does not
  disturb the share, and no other process can substitute a file under the same name.
- **Every piece is marked present by construction** (`have[i] = 1`, `pmap[i] = 2`) instead of
  being read back through the verification path — the author is the only source, so re-reading
  the file would only cost I/O. The hashes come from the streaming hasher
  (`ntx_share_hasher`), whose footprint is `O(piece length + pieces)` and never the file.
- **The `.torrent` is written atomically with mode `0600`** (design §5.4).
  The name is `<store-dir>/<stem>-<8 hex of ih>.torrent`, where `stem` is the longest
  whole-UTF-8-character prefix of the file name that still leaves room for the suffix inside
  `NAME_MAX`; the name **inside** the torrent is never cut. The bytes are checked first: the
  buffer's `SHA-1(info)` must equal the `ih` in the file name, because that hash is the access
  key of a private share and a file whose contents do not match its name must never reach disk.
  Then the target is examined — absent, or already exactly this hash, is fine (re-sharing keeps
  its link); any other content there is the `exists` error. The write goes to
  `<path>.tmp<pid><n>` opened `O_CREAT | O_TRUNC | O_EXCL`, `fchmod` to `0600` regardless of
  the umask, `fsync`, then `rename`. A planted symlink or a leftover from a killed run is
  therefore never followed. `ntx_share_write_torrent` is the only writer.
- **With `--share-from` nothing is written at all.** The `.torrent` on disk is read once
  (`ntx_session_share_add` → `share_from_read`), accepted or rejected before the first byte is
  hashed, and then never touched again — the name, piece length and both hash lists of the share
  are the ones that file carries. The comparison happens when hashing ends (`share_verify_cmp`):
  the streaming hasher's SHA-1 list and its BEP 52 layers must both equal what the `.torrent`
  claims, or the share fails with `changed`. Only the magnet is rebuilt, from the currently
  pinned tracker list, so a re-share follows key rotation without touching the link.
- **Change detection.** Once the metainfo is built, `fstat` of the held descriptor is compared
  once a second (`NTX_SHARE_FSTAT_MS`) against the saved `st_dev`, `st_ino`, `st_size`,
  `st_mtime` and `st_ctime`. Any difference fails the share with `changed`: peers are choked,
  a `stopped` announce is sent, and the slot stops serving (`ntx_session_share_serving` returns
  0, so block requests are refused). The descriptor and the store stay alive so the UI can
  still show what happened.
- **A read that fails while serving stops the share.** Serving reads the file through `pread` on
  the held descriptor. When one comes back short or with `EIO`, `data_serve` refuses the request
  (BEP 6 `reject_request`) and calls `ntx_session_share_io_failed`, which fails the share with
  `io`: `ntx_session_share_serving` returns `0` from then on, so no further request is served and
  the row shows `shr!`. An ordinary torrent gets only the one refusal — the hook is a no-op while
  `s->share[i]` is `NULL`, so nothing else about it changes.
- **Hashing budget.** The file is hashed inside the session tick, `pread` chunk by chunk
  against a real monotonic deadline, so one tick cannot hash a whole file and stall the loop.
  The phase is `hash` and `pct` is hashing progress.
- **Ratio exemption.** A share slot never hits the ratio stop: the ratio check returns "not
  reached" while `s->share[ti]` is set, so `--share` seeds until the file changes or the
  process is stopped, whatever `NTX_SEED_RATIO_NUM` does to an ordinary seed.

Nothing about a share is persisted: the `.torrent` file is the only artifact, and a restart
hashes the file again ([roadmap.md](roadmap.md)).

## Seeding and the share ratio

- A `DONE` torrent uploads to every peer that is interested in it: while seeding, all interested peers are unchoked.
- **Ratio stop.** The per-torrent counter `up` (bytes uploaded since the process started; it is **not** saved across restarts) is compared with the torrent size. At `up >= 3 × size` (`NTX_SEED_RATIO_NUM` = 3) the torrent enters phase `ratio-done`: all peers are choked, we send "not interested", a `stopped` announce is sent, and the torrent makes no more outbound connections, tracker announces or peer boosts and refuses requests. Existing connections stay open and the process keeps running until you stop it. There is no option to change the ratio.
- **Limited outbound dialling while seeding.** Once a torrent is `DONE`, `ntx` stops making outbound connections when `NTX_SEED_MAX_OK` (48) peers are connected, and keeps at most `NTX_SEED_MAX_HS` (12) handshakes in flight. This avoids hundreds of useless connections. Incoming connections are not affected.
- **Pause.** `pause` (JSON API) stops tracker announces, piece requests and uploads; connections stay open. `resume` returns to the previous state; a torrent paused during verification resumes straight into download if pieces are still missing (the rest of the scan is skipped). Pausing is not persisted.
- **Shutdown.** On exit or `remove`, `ntx` sends a best-effort `stopped` announce to the trackers, synchronously and bounded to 3 seconds in total (`NTX_TRK_STOP_BUDGET_MS`).

## Downloading

- **Request pipeline.** Blocks are 16 KiB (`NTX_PEER_REQ_LEN`). The number of requests in flight per peer adapts to its measured speed: about two seconds of throughput plus 16, between `NTX_PEER_PIPE_MIN` (32) and `NTX_PEER_MAX_REQ` (128).
- **Request timeout.** An unanswered request times out after `NTX_PEER_REQ_TIMEOUT_S` (30 s), or after 12 s when partially downloaded pieces exist. A block whose request is older than `NTX_PEER_REQ_STALE_MS` (8 s) no longer counts as in flight, so it may be requested from another peer.
- **Endgame.** When at most `NTX_ENDGAME_MAX_PIECES` (32) pieces are missing, an idle peer may re-request blocks that have been outstanding for at least `NTX_ENDGAME_MIN_AGE_MS` (1.5 s), with at most two copies of a block in flight. When the first copy arrives, the others are cancelled.
- **Peer discovery.** Peers come from trackers (the announce asks for `numwant=200` peers), DHT, PEX and incoming connections. A tracker is skipped after `NTX_TRK_MAX_FAIL` (3) consecutive failures.
- **Dialling.** Without `--utp`, outbound connections are TCP. With `--utp`, a peer is tried over uTP first and, if no answer arrives within `NTX_UTP_DIAL_MS` (1.5 s), over TCP. After `NTX_UTP_GIVEUP_MISSES` (40) uTP misses without any uTP success, uTP is no longer tried first. A TCP connection that is not established in `NTX_PEER_CONN_TIMEOUT_S` (5 s) is abandoned; the timeout is 2.5 s while fewer than `NTX_MIN_OK_PEERS` (3) peers are working.
- **Redial back-off.** An outbound address that failed is not dialled again for 30 s, and the delay doubles with each failure up to 600 s. A successful handshake clears the record. The table holds 512 addresses. A uTP miss does not count as a failure, and the TCP retry after it, as well as BEP 55 hole-punch dials, bypass the back-off.
- **Local addresses.** Unless `--allow-local-peers` is given, outbound dials to loopback, link-local, unspecified and multicast addresses are skipped (details in [cli.md](cli.md)).

## Limits

| Limit | Value | Constant |
|-------|-------|----------|
| Torrents per session | 16 | `NTX_SESSION_MAX_TTS` |
| Peer connections per session | 128 (the `--max-peers` option lowers the outbound part) | `NTX_SESSION_MAX_PEERS` |
| Trackers per session | 32 | `NTX_SESSION_MAX_TRK` |
| Pending UDP tracker requests | 64 | `NTX_TRK_PENDING` |
| Connections per remote address | 8 | `NTX_PEER_MAX_PER_ADDR` |
| Handshakes in flight (outbound) | 99 | `NTX_MAX_HS_CONNECTING` |
| Handshake timeout | 60 s | `NTX_PEER_HS_TIMEOUT_S` |
| Idle connection (no bytes received) | 300 s | `NTX_PEER_IDLE_TIMEOUT_S` |
| Files in a v2 / hybrid torrent | 64 | `NTX_TORRENT_MAX_FILES_V2` |
| Piece length | 64 MiB | `NTX_TORRENT_MAX_PIECE_LEN` |
| Peer ban after a failed piece | 60 s | `NTX_TORRENT_PEER_BAN_MS` |
| Tracker peers requested | 200 | `NTX_TRACKER_NUMWANT` |

These are compile-time limits. The same table sizes are reported as `max_tts` and `max_peers` in the JSON API `hello` line ([json-api.md](json-api.md)).
