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
| Private share | `ntx --share` seeds a private (BEP 27) hybrid (BEP 52) single-file share and qBittorrent-nox (`Session\Encryption=1`) downloads it byte-identically, with the MSE proven from the seed's own handshake log. See [Private share](#private-share) |

### Reference clients

The Dockerfile's own notes record what was observed when the harness was written (this documentation did not re-run the container cells):

- `transmission-daemon` (Debian bookworm) is a v1-only engine. It rejects every BEP52 fixture with `invalid or corrupt torrent file`, so the cells that need it to load a v2 or hybrid torrent are recorded as `FAIL` with that message.
- `qBittorrent-nox` (libtorrent) speaks BEP52. The note above records what was observed when the harness was written: under Xvfb it never bound a socket. It does bind one head-less *without* Xvfb (the private-share cell below drives it through the WebAPI), but it still cannot stand in for the transmission probe above, which is what gates the cells that need the engine to load a fixture.

The cells that do not depend on a third-party BEP52 implementation (reserved bit, `ut_metadata`, magnet-only download for single-file v2, multi-file v2 and hybrid) run against `ntx` itself on loopback.

## Files

- `interop_v2.sh`: the matrix.
- `gen_torrents.py`: generates the `single_16k`, `multi_v2` and `hybrid_ok` fixtures for the matrix (it calls `test/scripts/bep52_gen.py`).
- `hs_capture.py`: an MSE responder. It completes the DH exchange and RC4 setup with `ntx`'s MSE/PE initiator and decrypts the handshake. The initiator's padding length is random and its reply is coalesced with the next message, so fixed offsets do not work; the capture searches for the padding length at which the keystream turns the stream into the 20-byte `19` + `BitTorrent protocol` magic. It prints `HS_OK ... m27=<hex> ...` or `HS_ERR <reason>`.
- `magnet_uri.py`: derives a magnet URI from a `.torrent`. The `btih` value is SHA-1 of the info dict for v1 and hybrid torrents and the truncated SHA-256 for pure v2 (BEP52); the `btmh` value is the `1220`-prefixed SHA-256 and is emitted only when the torrent has piece layers.
- `qbt-seed.sh`: in-container driver with the modes `probe`, `transmission-seed`, `transmission-leech`, `qbt-seed` and `qbt-share-leech`.
- `share_cert.py`: mints the share tracker's P-256 certificate and the SPKI pin table (`sharetest.inc`) for the seeder build, and with `--verify-torrent` asserts a metainfo is private, single-file and hybrid.
- `share_registry_tracker.py`: the qualified HTTPS share tracker of design §6.3, faked — pinned TLS, peers remembered per info_hash and answered `compact=1`, `/scrape` without `info_hash` → 400, `--blind <peer_id prefix>` to answer one peer with an EMPTY peer list (so the cell can force which side dials), and a JSON summary of what it saw, dumped atomically every 2 s and again on SIGTERM. `--self-check` verifies its byte-exact query decode.
- `Dockerfile`: `debian:bookworm` with transmission, qBittorrent-nox and Xvfb.

## Private share

The `ntx --share` cell is the only one that needs the pinned HTTPS share list,
because `--share` announces *only* to the compiled-in share trackers (design §6).
What it stands up, and why each piece has to be there:

- **Seeder build.** `make ntx-sharetest SHARETEST_INC=<generated>` — the recipe
  already exists in the `Makefile`; the cell passes its own `.inc`. The checked-in
  `scripts/pins/sharetest_trackers.inc` carries all-zero pins and fails closed, so
  it cannot stand in. The binary is built on the host and bind-mounted into the
  container, exactly like `src/` is copied into the docker context, so no `scripts/`
  is needed in the image.
- **Tracker endpoints.** Two rows on `127.0.0.2` / `127.0.0.3`, never `127.0.0.1`:
  that address has a hard-coded pin in `ntx_https_pin.c`'s built-in dev pool, which
  is consulted *before* the share table and would reject the harness certificate.
  Numeric literals also keep the announce path free of DNS/DoH. Two rows because
  `NTX_SHARE_MIN_TRACKERS` is 2.
- **Trust.** ntx pins; plain libtorrent does not. The certificate is installed as a
  system CA inside the container so qBittorrent can use the `.torrent` exactly as
  `--share` wrote it, with no rewritten announce.
- **qBittorrent, head-less.** `qbittorrent-nox` binds its peer socket within seconds
  without Xvfb, so the WebAPI (no auth needed with `LocalHostAuth=false` plus a
  loopback/bridge `AuthSubnetWhitelist`) is the control channel. Only the
  `[BitTorrent] Session\*` spellings are read by 4.5.2 — the `[Preferences]
  BitTorrent\*` ones read back as defaults. The two that matter and are easy to get
  wrong: `Session\Encryption=1`, the value the plan specifies, and
  `Session\DefaultSavePath` — 4.5.2 ignores the `save_path` field of
  `torrents/add`, so without it the download lands in the profile's default
  directory and the harness cannot read it back.
- **Why `1`, when qbt calls `2` "require".** `Session\Encryption` is *not*
  libtorrent's `peer_encryption_t` (0=plaintext / 1=allow / 2=require); qbt maps the
  value before it reaches libtorrent, and this image ships no WebUI strings to read
  the labels from. So the three values were measured A/B against this seed, one dial
  direction at a time (`--blind`, below), with `cmp` of the 1 MiB share as the verdict:

  | `Session\Encryption` | qbt dials (seed blinded) | seed dials (qbt blinded) |
  | --- | --- | --- |
  | `0` | `13 42 69 74 54..` plaintext BT handshake → `plaintext_strict_share` | full MSE, byte-identical |
  | `1` | opaque MSE DHKey offer, byte-identical | full MSE, byte-identical |
  | `2` | plaintext BT handshake → `plaintext_strict_share` | `FIN` after ntx's DHKey → `pe_fail st=RECV_DH inn=0` |

  i.e. qbt's own ordering is 0=allow, 1=require, 2=disabled — `1` is "require" and
  `2` is "plaintext only", the reverse of the names in libtorrent's enum. Every
  `2` cell therefore failed because the *client* had encryption off, which is why
  `1` is the value the plan uses and the value the cell sets. The "forced" property
  is still not taken from qbt's label: it is proven from the seed's log (below).
- **Peer discovery is real.** BEP 27 forbids DHT, PEX and LSD, so the only way qbt
  can learn the seeder's address is the tracker. The cell therefore asserts the
  announce arrived over https on both rows, that no scrape happened, and
  `dht_nodes=0` from `sync/maindata`.
- **Both MSE directions are proven, one per pass.** The seed and qbt announce
  `started` within milliseconds of each other, so unblinded they dial
  SIMULTANEOUSLY and only the winner of that race shows up in the seed's log — one
  run can therefore only ever observe one of ntx's two MSE roles. The cell runs the
  exchange twice and `share_registry_tracker.py --blind` forces the direction: the
  blinded peer still announces (so discovery stays real) but is answered an EMPTY
  peer list, so it can only ever be reached. `seed-dials` blinds `-qB4520-` and must
  show `pe_ok ... role=0` plus `peer_ok ... out=1 plain=0 via=pe_promote`;
  `qbt-dials` blinds `-NT0100-` and must show `role=1` / `out=0`. Each pass has its
  own source, store, tracker state and `cmp`.
- **Encryption is asserted positively.** In both passes the seeder's peer log must
  show the peer promoted through MSE (`via=pe_promote`) on a non-plaintext socket
  (`plain=0`), and must contain no `via=bths` peer at all — `via=bths` is the only
  route a plaintext handshake can take, so a byte-identical download cannot be
  earned unencrypted. A share is MSE-only in `ntx`: a plaintext handshake is dropped
  with `plaintext_strict_share` (`src/core/ntx_session_bt_hs.c`).
- **Environment failure vs wire failure.** `trk.state.json` is dumped atomically
  every 2 s, so a tracker killed by host OOM still reports what it saw, and liveness
  of the seed and tracker is sampled *before* the cell stops them. A missing seed or
  tracker, an `oom_kill` delta in `/proc/vmstat`, or a docker rc of 124/137 is
  reported as a cause in the FAIL reason. Those notes only ever add a cause — no
  wire assert is relaxed by them.
- **Bytes, not a hash echo.** `cmp` of the downloaded file against the source, plus
  `--verify-torrent` so the cell cannot pass on a metainfo that is not actually
  private, single-file and hybrid.

## Behaviour this harness depends on

- **Serving `ut_metadata`.** Any peer that holds the complete info dict serves it (BEP9), whether it loaded a `.torrent` or finished a magnet fetch: `ntx_session_data_send_metainfo` checks `have_meta`. Magnet-only peers can therefore get the metadata from a seeder that started from a `.torrent`; the requester checks the assembled dictionary against its own `xt`.
- **Piece length per file.** BEP52 aligns pieces per file, so the last piece of every file is short. Request selection uses `ntx_torrent_piece_len()`, which knows the torrent layout, and not `ntx_store_pl()`, which assumes one contiguous v1 stream. The multi-file v2 download cell depends on this.
