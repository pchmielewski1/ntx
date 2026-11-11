# JSON control API (`--stats-json`)

With `--stats-json`, `ntx` becomes a machine-controlled process: it emits status and replies as
newline-delimited JSON (NDJSON) on **stdout** and accepts one JSON command per line on **stdin**.

This document is the specification of the interface. It is versioned together with the code;
the current version is **v1** (`"v":1` in every `hello` and `stats` line). Implementation:
`src/ui/ntx_ipc.c` (parser, framing), `src/ui/ntx_ipc_dispatch.c` (commands and replies),
`src/ui/ntx_stats.c` (stats emitter), `src/core/ntx_session_stats.c` (counters),
`src/ntx_main.c` (event-loop integration).

## Transport

- **stdout** carries only JSON documents, one per line: `hello`, `stats`, `ack`, `err`, `share`. Lines contain no spaces after `:` or `,`.
- **stderr** carries diagnostics in plain text (the build banner, TOFU notices, `--verbose` output). The status line of the normal CLI is not printed in this mode.
- **stdin** carries commands. The command channel is opened only when stdin is **not a terminal**; a terminal never becomes the protocol. stdin is switched to non-blocking mode.
- `--stats-json` may be used without a torrent argument; the session then starts empty and torrents are added with `add`.
- The process never waits for a command. In each event-loop iteration (the loop waits at most 50 ms for network events) it first reads and executes pending commands, then, about every 100 ms, emits a `stats` snapshot.
- Per iteration at most 64 command lines are executed; the rest stay queued in order and are handled in following iterations. A single read takes at most 1024 bytes and at most 64 reads are made per iteration.
- **EOF on stdin** closes the command channel only; the session keeps running and keeps emitting `stats`. A read error also closes the channel and keeps the session alive.
- The process ends on the `quit` command, on `SIGINT` or on `SIGTERM`, with exit status `0`. It then sends best-effort `stopped` announces to trackers (bounded to about 3 seconds in total).

### Request framing

- One request = one line terminated by `\n`. A `\r` before the `\n` is removed. Empty lines are ignored silently.
- A line may be at most **4096** bytes (without the newline). A longer line is discarded up to its newline, is never executed, and produces exactly one reply: `{"type":"err","cmd":"","ok":0,"code":"bad_json"}`.
- After a `quit`, any further lines in the same read are dropped, so the `quit` ack is always the last line on stdout.

## Messages from `ntx`

### `hello`

Emitted once, as the very first line, and again as the reply to the `hello` command.

```json
{"type":"hello","v":1,"protocol":"ntx-json","max_tts":16,"max_peers":128,"build":"seed-ratio-v1","caps":["ping","status","hello","add","pause","resume","remove","quit","share"]}
```

| Key | Meaning |
|-----|---------|
| `v` | Interface version. Incremented only for incompatible changes. |
| `protocol` | Always `"ntx-json"`. |
| `max_tts` | Number of torrent slots (16). Valid slot numbers are `0` to `max_tts - 1`. |
| `max_peers` | Size of the peer connection table (128). This is a compile-time limit, not the `--max-peers` option. |
| `build` | Build identifier (`NTX_IPC_BUILD_ID` in `src/ui/ntx_ipc.h`, overridable with `-D` at compile time). The value above is the default. |
| `caps` | Commands this binary implements. `"share"` is listed only while the built-in share tracker table is usable (at least `NTX_SHARE_MIN_TRACKERS` = 2 hosts with pins), and the share options are hidden from `--help` below that. The `share` command itself is always recognised; without the caps entry it is accepted and every attempt answers `no_trackers`. |

### `share`

Emitted once per `share` command, when the share reaches `ready` or fails. It is
asynchronous: the `ack` for the command is already out. Per event-loop tick the order is
always `ack` first, then `share`, then the `stats` snapshot.

```json
{"type":"share","i":0,"ok":1,"ih":"0123456789abcdef0123456789abcdef01234567","ih2":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123","name":"photo.jpg","magnet":"magnet:?xt=urn:btih:0123...&xt=urn:btmh:...&dn=photo.jpg&tr=https%3A%2F%2F...","torrent":"downloads/photo.jpg-01234567.torrent"}
{"type":"share","i":1,"ok":0,"code":"changed"}
```

| Key | Meaning |
|-----|---------|
| `type` | `"share"` |
| `i` | The torrent slot the share holds — the same `i` as in the `ack`. `remove` with this `i` releases the share. |
| `ok` | `1` ready (the file is hashed, the `.torrent` written and at least one share tracker answered), `0` failed. |
| `ih` | On success, the 40-hex wire info hash (SHA-1 of the `info` dictionary, the v1 half of the hybrid). |
| `ih2` | On success, the full 64-hex v2 info hash (SHA-256 of the same `info` dictionary). |
| `name` | Torrent name: the base name of `path`. Escaped like every string in this document. |
| `magnet` | The magnet link, with `xt=urn:btih:`, `xt=urn:btmh:`, `dn=` and one `tr=` per built-in share tracker. Write it to a file and `ntx` accepts it as input. |
| `torrent` | Path of the `.torrent` written for this share, inside `--store-dir` (mode `0600`). |
| `code` | On failure only; one of the share codes below. |

Exactly one `share` event exists per `share` command. If the torrent is `remove`d before
the event is emitted, the event is dropped with the slot.

### `stats`

Emitted about every 100 ms and immediately after a `status` command. Session fields come first,
then the `torrents` array. Example (one line, wrapped here for readability):

```json
{"type":"stats","v":1,"down_Bps":8500000,"up_Bps":131072,"total_peers":60,"conn_peers":55,
 "down_total":410000000,"up_total":12345678,"uptime_s":64,"port":6881,"dht":1,"enc":1,
 "doh":"Q9","doh_busy":0,"doh_ok":3,"doh_fail":0,"doh_mitm":0,
 "hash_req_tx":0,"hash_req_rx_ok":0,"hash_rej":0,
 "utp":1,"utp_conns":7,"utp_v6":0,"demux_dht":1200,"demux_utp":5400,"demux_drop":0,
 "punch_ok":1,"punch_fail":0,"port_map":2,"ext_port":49321,"n":1,"torrents":[{"i":0,"ih":"0112233445566778899aabbccddeef0011223344",
 "name":"ubuntu-24.04.iso","state":1,"phase":"dl","pct":21,"spd_d":8500000,"spd_u":131072,
 "eta_s":192,"done":215,"total":934,"partial":12,"peers":55,"trk_total":18,"trk_pend":0,
 "trk_udp_ok":9,"trk_dead":0,"peers_all":60,"peers_hs":5,"peers_ok":55,"peers_unchoked":12,
 "peers_interested":3,"meta_got":0,"meta_need":0,"verify_q":0,"meta_version":0,"hybrid":0,
 "layers_pending":0,"size":1950000000,"down":410000000,"up":12345678,
 "priv":0,"share":0,"enc_strict":0,"trk_pin_fail":0,"in_ok":0}]}
```

All values are non-negative integers unless a type is given. Byte totals, `uptime_s`, `demux_*`, `size`, `down` and `up` are unsigned 64-bit; the rest fit in 32 bits.

#### Session fields

| Key | Type | Meaning |
|-----|------|---------|
| `type` | string | `"stats"` |
| `v` | int | Interface version, `1`. |
| `down_Bps`, `up_Bps` | int | Block-payload rate in bytes per second, smoothed over the last five one-second samples (not wire bytes). |
| `total_peers` | int | Peer connections in use, in any phase (including incoming connections not yet matched to a torrent). |
| `conn_peers` | int | Connections that completed the BitTorrent handshake. |
| `down_total`, `up_total` | int | Block payload bytes stored / sent since the process started. |
| `uptime_s` | int | Seconds since the process started. |
| `port` | int | Listen port (TCP; UDP uses the same number when it could be bound). |
| `dht` | int | `1` if `--dht` was given. |
| `enc` | int | Always `1` (message-stream encryption is always offered). |
| `doh` | string | Short tag of the DNS-over-HTTPS provider used last (`!` after a failed lookup); empty before the first lookup. At most 7 bytes. |
| `doh_busy` | int | `1` while a DoH lookup is in flight. |
| `doh_ok`, `doh_fail`, `doh_mitm` | int | DoH lookups that succeeded / failed / were rejected by the SPKI pin check. Each saturates at 65535. |
| `hash_req_tx` | int | BEP 52 hash requests sent. |
| `hash_req_rx_ok` | int | Hash replies received, verified and accepted. |
| `hash_rej` | int | Hash requests that failed: rejected by the peer, bogus or short reply, or timeout. |
| `utp` | int | `1` if `--utp` was given. |
| `utp_conns` | int | Live uTP connections. |
| `utp_v6` | int | `1` if the IPv6 uTP socket is bound or a uTP connection over IPv6 exists. |
| `demux_dht`, `demux_utp`, `demux_drop` | int | Datagrams on the shared UDP socket routed to the DHT, to uTP, or matching neither. See [network.md](network.md). |
| `punch_ok`, `punch_fail` | int | BEP 55 holepunch dials started / refused before starting (duplicate, limits, no route). |
| `port_map` | int | NAT-PMP/PCP port-mapping state of the session: `0` `off`, `1` `pending` (a request is out, no answer yet), `2` `active` (the gateway mapped the port), `3` `none` (no gateway answered, or mapping is unsupported), `4` `cgnat` (the external address is in `100.64.0.0/10`, so inbound will not work). See [network.md](network.md#nat-pmp-and-pcp-port-mapping). |
| `ext_port` | int | The external port the gateway mapped. Non-zero only when `port_map` is `2`; `0` in every other state. |
| `n` | int | Number of objects actually present in `torrents`. |
| `torrents` | array | One object per live torrent (below). |
| `truncated` | int | Present, with value `1`, only when some torrents did not fit into the output buffer; absent otherwise. |

#### Torrent objects

Slots with state `DEAD` are not listed. `i` and `ih` come first in each object.

| Key | Meaning |
|-----|---------|
| `i` | Slot number `0`-`15`. Stable for the life of the torrent; this is the `i` used in commands. The array index is not the slot. |
| `ih` | 40 lowercase hex digits: the 20-byte info hash used on the wire and in tracker announces. SHA-1 of the `info` dictionary for v1 and hybrid torrents; the first 20 bytes of the SHA-256 for pure v2. The full 32-byte v2 hash is not exposed. |
| `name` | Torrent name, at most 47 bytes (empty until known; a magnet's `dn=` is used before the metadata arrives). |
| `state` | Numeric state, see below. |
| `phase` | Phase string, see below. |
| `pct` | Verified bytes / size × 100, capped at 100. Not wire bytes. |
| `spd_d`, `spd_u` | Download / upload rate of this torrent, bytes per second (same smoothing as the session rates). |
| `eta_s` | Seconds to completion at the current download rate; `0` if unknown or complete. |
| `done` | Verified pieces. |
| `total` | Pieces in the torrent (`0` until the metadata is known). |
| `partial` | Not yet verified pieces that have received some data. |
| `peers` | Same as `peers_ok`. |
| `trk_total` | Trackers known for this torrent. |
| `trk_pend` | UDP tracker requests in flight. |
| `trk_udp_ok` | UDP trackers whose connect handshake completed. |
| `trk_dead` | Trackers given up on after repeated failures. |
| `peers_all` | Connections assigned to this torrent. |
| `peers_hs` | Of those, still in the handshake. |
| `peers_ok` | Of those, past the handshake. |
| `peers_unchoked` | Peers that have unchoked us while we are interested. |
| `peers_interested` | Peers interested in our data. |
| `meta_got`, `meta_need` | Metadata pieces (16 KiB) received / total. `meta_need` is `0` until the metadata size is known. |
| `verify_q` | Pieces fully received and queued for hash verification. |
| `meta_version` | `0` = BitTorrent v1 metainfo, `2` = v2 or hybrid. (`1` is never used.) |
| `hybrid` | `1` if the metainfo carries both v1 and v2 data. |
| `layers_pending` | `1` for a pure-v2 torrent still waiting for its piece layers. |
| `size` | Payload size in bytes (`0` until the metadata is known). |
| `down` | Verified bytes (including data found valid on disk at start-up). |
| `up` | Bytes uploaded for this torrent since the process started. |
| `priv` | `1` when the metainfo is private (BEP 27: `private` present and non-zero in the `info` dictionary). |
| `share` | `0` not a share, `1` a live `share`, `2` a share that failed (for example the file changed on disk). |
| `enc_strict` | `1` when every peer connection of this torrent must complete message-stream encryption; a plaintext peer is dropped without fallback. Always `1` for a share. |
| `trk_pin_fail` | Number of this torrent's trackers whose SPKI pin check failed. A share with `trk_pin_fail == trk_total` means the built-in keys are out of date or a man-in-the-middle is present. |
| `in_ok` | Inbound peers that completed a handshake for this torrent. For a share it is the count of peers actually reached through the mapped port. |

#### `state` values

| `state` | Name | Meaning |
|---------|------|---------|
| `0` | `META` | Magnet link, metadata not yet available. |
| `1` | `DL` | Downloading. |
| `2` | `DONE` | Complete (seeding, or finished seeding). |
| `3` | `PAUSED` | Paused with `pause`. |
| `4` | `VERIFY` | Scanning existing files on disk. |
| `5` | `DEAD` | Free slot. Appears only in the `state` of a `remove` ack. |

#### `phase` values

`init`, `trk`, `trk-wait`, `connect`, `hs`, `meta-wait`, `meta`, `verify`, `hash`, `dl`, `wait`, `choked`, `stall`, `seed`, `ratio-done`, `pause` (at most 11 bytes). `hash` appears only while a `share` is hashing its file. Meanings: [cli.md](cli.md#phases).

#### Size and truncation

The line is built in a 24 KiB buffer. Torrent objects are added one by one; one that does not fit is left out together with all later ones, `n` stays equal to the number emitted and `"truncated":1` is appended. With at most 16 torrents the line is well below the buffer size, so this is a safety net. If even the header does not fit, the line is `{"type":"stats","v":1,"n":0,"torrents":[],"truncated":1}`.

#### String encoding

Strings (`name`, `doh`, `build`, echoed `cmd`) escape `"`, `\`, newline, carriage return and tab, and write other control characters as `\u00xx`. Bytes of `0x80` and above are written as they are and are not validated, so a torrent name that is not UTF-8 (or that was cut at 47 bytes inside a multi-byte character) yields output that is not valid UTF-8. Clients should decode leniently.

## Commands (stdin)

Each command is a single JSON object with a `cmd` string.

| `cmd` | Other keys | Effect and reply |
|-------|------------|------------------|
| `ping` | | Reply `ack`. Liveness check. |
| `status` | | An immediate `stats` line, outside the 100 ms cadence. No `ack`. |
| `hello` | | Reply: the `hello` line again. |
| `add` | `magnet` **or** `path` | Adds a torrent in the lowest free slot and replies `ack` with `i` and `ih`. `magnet`: same forms as on the command line (`urn:btih:` / `urn:btmh:`). `path`: a `.torrent` file (not a text file); it is read immediately and the data goes to the `--store-dir` given at start-up. The reply is sent before any network activity. `state` in the ack is `0` for a magnet, and `1` or `4` for a `.torrent` (`4` when data already exists on disk). `add` does not check whether the torrent is already loaded. |
| `pause` | `i` | Sets the torrent to `PAUSED` (a state, not a toggle: repeating it is fine). Tracker announces and piece requests stop; connections stay open. Not persisted across restarts. |
| `resume` | `i` | Restores the state held before the pause. On a torrent that is not paused it does nothing and still replies `ok`. A torrent that was paused during `VERIFY` resumes in `DL` if pieces are missing. |
| `remove` | `i` | Frees the slot: sends a best-effort `stopped` announce (synchronous, bounded to about 3 seconds), closes the torrent's connections and files. **Data on disk is kept.** |
| `share` | `path`, optional `torrent` | Shares one local file. `path`: the file to seed — it must exist, be a regular file and be non-empty; the base name becomes the torrent name. `torrent`: re-share under an existing `.torrent` (the `--share-from` equivalent) — accepted by the parser, **not implemented in this build**, answered `bad_arg`. The reply is the synchronous verdict only (open, `S_ISREG`, size, name, tracker table, free slot); hashing, the `.torrent` file and the announces happen later and are reported by the `share` event. The ack carries `i` and `state` but **no `ih`** — while hashing the hash is not known yet and is `40` zeros in the stats. |
| `quit` | | Reply `ack`, then the process exits with status `0`. The `ack` is the last line on stdout. |

Request syntax (everything else is rejected with `bad_json`):

- The line is one JSON object. Values are strings or integers only; `true`, `false`, `null`, arrays and nested objects are rejected, even under unknown keys.
- Known keys: `cmd`, `magnet`, `path`, `torrent` (strings); `seq`, `i` (integers). A known key with the wrong type is rejected. Unknown keys with a string or integer value are ignored. Duplicate keys: the last one wins. Keys of 16 bytes or more are ignored as unknown.
- Integers are optional `-` followed by decimal digits; no fraction, exponent or `+`; values outside the signed 64-bit range are rejected.
- String escapes: `\" \\ \/ \n \r \t \b \f` and `\uXXXX` for code points up to `U+007F`. Other characters are sent as raw UTF-8; `\u` escapes above `U+007F` are rejected.
- Spaces and tabs are allowed between tokens. `{}` and a missing `cmd` are `bad_json`.
- Limits: `cmd` at most 63 bytes (a longer one is answered as `unknown_cmd` with `"cmd":""`); `magnet` at most **2048** bytes after unescaping (longer: `io`) — the old 511-byte cap was relaxed for `add`, so a magnet with many `tr=` parameters fits; `path` and `torrent` at most 511 bytes each (longer: `io`).
- `seq` is an optional integer chosen by the client. It is copied unchanged into the `ack` or `err` for that request; without `seq` the reply has no `seq` key. For a malformed line, `seq` is echoed only if it was read before the error.
- `i` must be in `0`-`15` for `pause`, `resume` and `remove`; a missing, negative or larger value is `bad_i`.

## Replies

Every command except `status` and `hello` gets exactly one reply: an `ack` on success, an `err` on failure.
Keys appear in this order: `type`, `seq` (if sent), `cmd`, `i` (if applicable), `ih` (`add` only), `ok`, `state` or `code`.

```json
{"type":"ack","seq":1,"cmd":"add","i":0,"ih":"0123456789abcdef0123456789abcdef01234567","ok":1,"state":0}
{"type":"ack","seq":2,"cmd":"pause","i":0,"ok":1,"state":3}
{"type":"ack","seq":3,"cmd":"remove","i":0,"ok":1,"state":5}
{"type":"ack","seq":4,"cmd":"ping","ok":1}
{"type":"ack","seq":5,"cmd":"quit","ok":1}
{"type":"err","seq":6,"cmd":"pause","i":9,"ok":0,"code":"no_slot"}
{"type":"err","cmd":"pause","ok":0,"code":"bad_i"}
```

`err` replies carry `"ok":0` and a `code`. The echoed `cmd` is the command name; for an unknown command it is the string the client sent, and it is empty when none could be read. `i` is included when the request had a valid slot number, except for `bad_i`.

| `code` | Cause |
|--------|-------|
| `bad_json` | Not a valid request line (see syntax above), line too long, or no `cmd`. |
| `unknown_cmd` | `cmd` is not one of the commands above. |
| `bad_i` | `i` missing or outside `0`-`15`. |
| `no_slot` | The slot is free (never used, or removed). |
| `bad_arg` | `add` with both or neither of `magnet` / `path`, an empty value, or a magnet link without a valid `xt=`. Also `share` with no `path`, an empty `path`, or a `torrent` value (re-share under an existing link is not implemented in this build). |
| `io` | `add` with a `path` longer than 511 bytes, or a file that is missing, empty or not valid metainfo (or whose storage cannot be opened). Also `share` with a `path` or `torrent` longer than 511 bytes, or a `path` that cannot be opened, is not a regular file or is empty. |
| `full` | `add` while all 16 slots are in use. Also `share` while all 16 slots are in use. |
| `no_trackers` | `share` while the build has too few pinned HTTPS share trackers to announce on (`NTX_SHARE_MIN_TRACKERS`). `hello` then omits `"share"` from `caps`. |
| `not_ready` | Reserved for commands refused because of the torrent's state. The current build never sends it. |
| `internal` | A reply did not fit its buffer: `{"type":"err","cmd":"","ok":0,"code":"internal"}`. |

A command answered with `err` has had no effect.

### Share codes

The `code` of a failed `share` (in the `err` ack and in the `share` event) comes from one
table, `ntx_share_err_code()` in `src/core/ntx_share.c`:

| `code` | Cause |
|--------|-------|
| `"bad_arg"` | No `path`, an empty `path`, an unusable file name, or a `torrent` value (not implemented in this build). |
| `"io"` | The file cannot be opened, is not a regular file, is empty, or the hash / metainfo / store / `.torrent` write failed. |
| `"full"` | No free torrent slot (all 16 in use). |
| `"no_trackers"` | Too few pinned HTTPS share trackers in this build. |
| `"too_big"` | The file would need more than 32 768 pieces, so no piece length in the supported range fits the metainfo limits. |
| `"exists"` | `<store-dir>/<name>-<8 hex>.torrent` already exists on disk and its bytes do not hash to this info hash. |
| `"changed"` | The shared file changed after hashing: `st_dev`, `st_ino`, `st_size`, `st_mtime` or `st_ctime` differ from the values recorded at open (checked once per second). |

`"changed"` and `"exists"` can only arrive on the asynchronous `share` event; the
synchronous `err` ack only ever carries `"bad_arg"`, `"io"`, `"full"` or `"no_trackers"`.
The one-line English text for `stderr` (used by the CLI, not by JSON) is a separate table.

## Compatibility

- New keys and new commands may be added without changing `v`. Clients must look up values by key, ignore unknown keys and unknown `caps`, and must not depend on key order or on a key being absent.
- Key spellings are stable. The interoperability test greps the stream for `"pct":100` and `"peers_ok":`, so the compact formatting (no spaces) and these names are part of the contract.
- A change that breaks an existing client increments `v`.

## Security

Whoever can write to stdin controls the session and can make `ntx` read any file it can access (`add` with `path`). Whoever writes to stdin can share any readable file: `share` with `path` publishes that file's contents, its name and its size to the pinned share trackers and to any peer that gets the link, and the resulting magnet is handed back on stdout. Nothing checks a share against a policy — there is no allow-list of shareable directories. The model assumes a single owner process. Do not connect stdin to a network socket. `path` is only opened as a file; no shell or external program is ever invoked.

A share is private only in the sense that discovery is limited to the pinned HTTPS trackers
(no DHT, no PEX). Anyone who learns the info hash can download the file, so treat the magnet
link as a bearer credential, and treat `"changed"` / a failed share as a signal to stop rather
than as a way to revoke access.

## Example

```sh
printf '%s\n' \
  '{"cmd":"add","seq":1,"magnet":"magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567"}' \
  '{"cmd":"pause","seq":2,"i":0}' \
  '{"cmd":"quit","seq":3}' \
  | ntx --stats-json --store-dir=dl
```

stdout starts with the `hello` line, then contains the three acks for `seq` 1 to 3 (with `stats` lines in between, depending on timing), and ends with the `quit` ack; the exit status is `0`.

## Tests

- `test/t_ipc_ctrl.c` and the vectors in `test/vectors/ipc/`: parser, framing, dispatcher, per-iteration budget, stop-after-quit.
- `test/interop/ipc/interop_ipc.sh` with `assert_ipc.py` (`make test-ipc`): end-to-end run over a real pipe, including the EOF and `quit` behaviour.
- `test/net_loopback.sh` (`make test-net`): the `port` reported in the stats line lies in the requested `--port-lo`/`--port-hi` range.
