# Changelog

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
