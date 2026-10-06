# BEP52 interop matrix

A manual harness that exercises `ntx`'s BEP52 (BitTorrent v2 and hybrid) support: v2 and hybrid torrents are seeded and leeched between two `ntx` instances over loopback, and, where Docker is available, against reference clients in a container. It is not part of `make test` or CI.

Run it from the repository root:

```sh
NTX_INTEROP_WATCHDOG=1 timeout -k 5 900 bash test/interop/v2/interop_v2.sh
cat test/.scratch/9/interop-v2/matrix.txt
```

(Without `NTX_INTEROP_WATCHDOG=1` the script re-executes itself under `timeout -k 5 900`.)

The script needs `python3` and an existing `./ntx` (run `make ntx` first); the container cells also need Docker and network access to build the image. Docker calls are wrapped in `timeout`, a stuck container is reported as a failed cell, and the script always exits 0, so read the matrix.

## Output

`matrix.txt` has one `cell|status|evidence` line per cell, numbered `c01`, `c02`, and so on in execution order. Status is one of:

- `RUN`: the behaviour was observed (in the `ntx` log, or as SHA-256-verified bytes on disk).
- `SKIP`: the cell could not be attempted (for example Docker is unavailable).
- `FAIL`: the cell was attempted and the expected behaviour was not observed. The evidence column holds the reason and the path of the log that shows it.

There is no `PASS` status: a cell only reports `RUN` when it saw the result itself. All scratch files go to `test/.scratch/9/interop-v2/` (gitignored).

## Cells

| Group | What it checks |
|-------|----------------|
| Fixtures | The fixtures `single_16k`, `multi_v2` and `hybrid_ok` are generated with `test/scripts/bep52_gen.py`, and the BEP52 hash-exchange vectors (messages 21/22/23) self-check |
| Seeding | An `ntx` seeder reaches the seeding state (100%, `phase seed`) for each fixture |
| Reserved bit | The BEP52 bit is on the wire: an MSE responder (`hs_capture.py`) takes the BitTorrent handshake from an outbound `ntx` dial and checks `m27 & 0x10` |
| `ut_metadata` | A request/response round trip against a local `ntx` seeder |
| Magnet leech | A magnet-only `ntx` leech over loopback: the info dict arrives only through BEP9, is checked against the magnet's `xt`, and the downloaded file is SHA-256-identical to the fixture |
| Reference image | The container image (transmission and qBittorrent-nox) builds |
| Reference clients | Seed, leech and metadata cells against the containerised engines. Each is preceded by a probe that asks the engine to load the fixture and quotes its verdict |

### Reference clients

The Dockerfile's own notes record what was observed when the harness was written (this documentation did not re-run the container cells):

- `transmission-daemon` (Debian bookworm) is a v1-only engine. It rejects every BEP52 fixture with `invalid or corrupt torrent file`, so the cells that need it to load a v2 or hybrid torrent are recorded as `FAIL` with that message.
- `qBittorrent-nox` (libtorrent) speaks BEP52, but the packaged binary never opens a listening socket when run head-less under Xvfb, so it cannot act as a loopback peer.

The cells that do not depend on a third-party BEP52 implementation (reserved bit, `ut_metadata`, magnet-only download for single-file v2, multi-file v2 and hybrid) run against `ntx` itself on loopback.

## Files

- `interop_v2.sh`: the matrix.
- `gen_torrents.py`: generates the `single_16k`, `multi_v2` and `hybrid_ok` fixtures for the matrix (it calls `test/scripts/bep52_gen.py`).
- `hs_capture.py`: an MSE responder. It completes the DH exchange and RC4 setup with `ntx`'s MSE/PE initiator and decrypts the handshake. The initiator's padding length is random and its reply is coalesced with the next message, so fixed offsets do not work; the capture searches for the padding length at which the keystream turns the stream into the 20-byte `19` + `BitTorrent protocol` magic. It prints `HS_OK ... m27=<hex> ...` or `HS_ERR <reason>`.
- `magnet_uri.py`: derives a magnet URI from a `.torrent`. The `btih` value is SHA-1 of the info dict for v1 and hybrid torrents and the truncated SHA-256 for pure v2 (BEP52); the `btmh` value is the `1220`-prefixed SHA-256 and is emitted only when the torrent has piece layers.
- `qbt-seed.sh`: in-container driver with the modes `probe`, `transmission-seed`, `transmission-leech` and `qbt-seed`.
- `Dockerfile`: `debian:bookworm` with transmission, qBittorrent-nox and Xvfb.

## Behaviour this harness depends on

- **Serving `ut_metadata`.** Any peer that holds the complete info dict serves it (BEP9), whether it loaded a `.torrent` or finished a magnet fetch: `ntx_session_data_send_metainfo` checks `have_meta`. Magnet-only peers can therefore get the metadata from a seeder that started from a `.torrent`; the requester checks the assembled dictionary against its own `xt`.
- **Piece length per file.** BEP52 aligns pieces per file, so the last piece of every file is short. Request selection uses `ntx_torrent_piece_len()`, which knows the torrent layout, and not `ntx_store_pl()`, which assumes one contiguous v1 stream. The multi-file v2 download cell depends on this.
