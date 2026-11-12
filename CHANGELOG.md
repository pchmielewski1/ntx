# Changelog

## Unreleased

### Features
- **`--share=PATH` — private sharing of one local file.** `ntx` hashes the file (streaming,
  inside the session tick), builds a hybrid v1 + v2 metainfo with `private = 1` and a random
  `ntx salt` in the info dictionary, writes it atomically to
  `<store-dir>/<name>-<8 hex>.torrent` with mode `0600`, announces on the built-in HTTPS share
  trackers and prints the magnet on stdout, so `ntx --share=f > link.txt` produces a file `ntx`
  itself accepts. The file is opened read-only and the descriptor is held for the whole share;
  an `fstat` once a second detects a change to `st_dev`/`st_ino`/`st_size`/`st_mtime`/`st_ctim`
  and stops the share (`shr!`, exit `1`). A share is exempt from the 3x ratio stop. The status
  line gains `prv`, `shr`/`shr!`, `enc!`, `pin!N`, `map:<port>`/`map-`/`map!cg`, `inN` and the
  `@hash` phase. `--share-from=FILE.torrent` re-shares a file under an existing link: the name,
  piece length and both hash lists come from the `.torrent` (which must be a private, single-file
  hybrid, at most 4 MiB), the file is hashed and compared against its SHA-1 `pieces` and BEP 52
  `piece layers`, and a mismatch ends the share as `changed`. The `.torrent` is never rewritten and
  the magnet is rebuilt from the currently pinned tracker list.
- **BEP 27 is honoured.** A non-zero integer under `private` in the info dictionary disables
  DHT `get_peers`/`announce_peer`, `ut_pex` and `ut_holepunch` for that torrent and restricts
  outbound dials to tracker-sourced addresses; a magnet whose info dictionary turns out to be
  private drops the outbound peers dialled before the flag was known. Inbound peers are
  unaffected. `--share` builds such a torrent.
- **Strict MSE/PE for share slots.** A peer that answers our PE start in plaintext, or that
  starts in plaintext toward a share slot, is dropped with no fallback.
- **Inbound plaintext hold (port-scan leak fixed).** `ntx` no longer answers an inbound
  connection that starts in plaintext until the remote side's full 68-byte handshake has
  arrived and its info hash matched a slot, so a scanner can no longer read the info hash of a
  live torrent out of the listener.
- **Pinned HTTPS share trackers.** A generated table of share trackers with their leaf SPKI
  hashes is compiled in; those hosts are fail-closed — their pin comes from the table only,
  never from TOFU or `--https-pin-file`, and a mismatching key is never retried in the session.
  Below `NTX_SHARE_MIN_TRACKERS` (2) usable hosts the feature is not in the release: the
  options disappear from `--help`, `--share` fails at start-up and `"share"` leaves the JSON
  `caps`. `make pins-check` is the release gate, `make pins-update` the only writer of the
  table, `make ntx-sharetest` the test build.
- **NAT-PMP / PCP port mapping** for shares (`--port-map` / `--no-port-map`): a PCP `MAP`
  (RFC 6887) to the default gateway on port 5351 with a NAT-PMP (RFC 6886) fallback after a
  version mismatch, replies accepted only from the gateway address, a 7200 s grant renewed at
  half its lifetime, lifetime-0 deletes on exit, CGNAT detection, and the granted external port
  carried in tracker announces and the BEP 10 `p` field. Refused together with `--proxy` or
  `--tunnel`.
- **JSON control API v1 additions:** the `share` command (`path`, optional `torrent`) with an
  `ack` carrying `i` and `state`, a separate asynchronous `share` event line carrying `ih`,
  `ih2`, `name`, `magnet` and `torrent` (or `ok:0` with a `code` from
  `bad_arg`/`io`/`full`/`no_trackers`/`too_big`/`exists`/`changed`), the new stats fields
  `priv`, `share`, `enc_strict`, `trk_pin_fail`, `in_ok`, `port_map` and `ext_port`, and the
  `magnet` limit of `add` relaxed from 511 to 2048 bytes.

### Packaging
- Release assets now include binary **RPM** (Fedora / RHEL / openSUSE) for x86_64 and aarch64,
  plus `ntx-<version>-packaging.tar.gz` with stamped **Gentoo** ebuild, Arch `PKGBUILD`, Alpine
  `APKBUILD`, Nix flake and source RPM `.spec`. Install matrix documented in README and release notes.

### Platforms
- OpenWrt **mipsel** (`mipsel_24kc`, MIPS32r2 soft-float, static musl): `make mips` /
  `make test-mipsel`; each GitHub Release ships `ntx-<version>-linux-mipsel` as a **manual**
  asset (Actions builds x86_64, aarch64 and riscv64). Crypto portability for 32-bit targets without
  `__uint128_t`.
- **riscv64** (RV64GC, lp64d, glibc 2.35+): `make riscv` / `make test-riscv` /
  `make test-riscv-shell`; cross-built and tested under `qemu-riscv64` in Actions, and every
  release ships `ntx-<version>-linux-riscv64` and `ntx_<version>_riscv64.deb` automatically.
  Source recipes (Alpine, Arch, Gentoo `~riscv`, Nix) accept riscv64.

## 0.1.0 - 2026-10-06

First public version. `ntx --version` prints the version of the release it was built for.

### Features
- BitTorrent v1, v2 and hybrid (BEP 52) downloading and seeding; magnet links, `.torrent` files,
  `ut_metadata`, PEX, Fast extension, MSE/PE encryption, DHT (IPv4 + IPv6), uTP with BEP 55
  holepunching, web seeds (magnet `ws=` / `as=`), HTTP/HTTPS/UDP trackers, SOCKS5 and the NTX1 tunnel.
- In-tree TLS 1.3 / 1.2 client with SPKI pinning (no OpenSSL), DoH-only name resolution.
- `--stats-json` NDJSON status and control channel; `--version`.

### Performance
- Faster start: tracker announces are queued and paced (replies are handled while the next tracker
  name is still being resolved), HTTP(S) trackers go after UDP ones, `numwant` 200, a 2.5 s connect
  timeout while few peers work, and a redial back-off for dead addresses.
- Faster transfer: adaptive request pipeline (32–128 blocks per peer) and an endgame mode that
  re-requests the last outstanding blocks from idle peers (the first copy cancels the others).
- Measured on one 627 MB swarm torrent: start to 100 % went from about 100–117 s to 50–60 s
  (a single torrent on one machine; results depend heavily on the swarm).

### Fixed before the first release
- `--utp` dialled every peer over uTP only, so peers without a uTP stack were never reached
  (`ut_metadata` never arrived, the download did not start). A uTP dial that is not answered within
  1.5 s is now retried over TCP, and the session stops trying uTP first if none ever works.
- A late or duplicate copy of an already stored block overwrote data and was counted twice.
- Trackers from a `.torrent` file (`announce` and `announce-list`) were not used at all.
- HTTP tracker replies carrying both `peers` and `peers6` imported garbage peers.
- Trackers never received `event=stopped` on `remove` or on exit; they now do (best effort, bounded to 3 s).
- A torrent paused during its initial verification and then resumed with pieces missing never sent its `started` announce.
- HTTP(S) requests through a SOCKS5 proxy only worked if the proxy answered within microseconds
  and then read from a non-blocking socket; they now wait for the proxy and the reply.
- `Transfer-Encoding: chunked` tracker, web seed and DoH replies were not understood.
- `--down-limit` threw away blocks that had already been received, and `--up-limit` dropped
  control messages; the limits are now a token bucket applied only to block payload, with a
  deferred upload queue, BEP6 `reject` and `cancel` handling. Upload counters only grow for
  blocks that were actually sent.
- Peers read through the polling path were dropped as idle after 300 s.
- A `bitfield` of the wrong length was half-applied instead of closing the connection.

### Security
See [SECURITY.md](SECURITY.md) for the pre-release audit (hostile metadata and wire input,
UDP tracker spoofing, uTP half-open flood, address filtering, TLS/crypto review, hardening flags).
