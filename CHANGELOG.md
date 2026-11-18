# Changelog

## Unreleased

### Features
- **PCP port mapping works over IPv6.** The v6 default is now read from `/proc/net/ipv6_route`
  in the kernel's own layout (`dst dpl src spl nexthop metric refcnt use flags iface`, with
  `RTF_UP` and `RTF_GATEWAY` required, `RTF_REJECT` refused and a metric below `ffffffff`), and a
  `MAP` sequence of its own runs against that nexthop on port 5351: its own `AF_INET6`
  `IPV6_V6ONLY` socket, `connect()`ed — with `sin6_scope_id` from the route's interface for a
  link-local nexthop — its own nonce, grants, renewal clock, deferred retry and RFC 6887 §8.5
  Epoch check. The client address in the request is the socket's own address from `getsockname`;
  a host with nothing but a loopback, link-local or unique-local address skips the family instead
  of asking the router to open a port toward an address nothing outside can reach. TCP is mapped,
  and UDP with `--utp`, on the listen port. Because an announce carries one port and that decision
  stays IPv4's, a v6 grant is only kept while it forwards the listen port **unchanged** — anything
  else is a firewall opening the swarm can never be told about, so it is deleted with its own
  nonce and reported under `--verbose`. There is no NAT-PMP fallback after IPv6 (RFC 6886 is
  IPv4-only), so an `UNSUPP_VERSION` or an ICMP error there is simply a refusal, and none of it
  reaches the v4 sequence: the two families share rules and helpers, not state.
  `docs/network.md` [IPv6 (R15)](docs/network.md#ipv6-r15), `SECURITY.md`.
- **The IPv6 mapping is visible.** Stats gained `port_map6` (the same `0`–`4` scale) and
  `ext_port6`, and the status line a `map6:<port>` tag shown only while the v6 mapping is active.
  `port_map` is now the **aggregate** of the two families: `active` when either holds a mapping —
  a share reachable over v6 alone *is* reachable — otherwise the most informative refusal, in the
  order `cgnat` > `pending` > `none`, with `off` as the identity so a v4-only host reads exactly
  the value it read before. `ext_port` and `ext_port6` never borrow from each other, so
  `"ext_port":0,"ext_port6":6881` is a v6-only host and `map- map6:6881` its status line.
  `docs/json-api.md`, `docs/cli.md`.

### Fixed
- **`/proc/net/ipv6_route` was parsed against a line no kernel writes.** The reader expected
  another field order and only accepted a `::ffff:a.b.c.d` nexthop, which Linux never prints, so
  the v6 default of a dual-stack host was never found and PCP silently stayed IPv4-only — against
  design §8, which asks for both families. The parser follows the kernel format now and the test
  fixture is a real `cat /proc/net/ipv6_route`, including the `lo` blackhole line (`metric
  ffffffff`, `RTF_REJECT`) that a `dst`-and-`dpl`-only check would have accepted.
- **The MSE responder no longer answers with another slot's hash.** After `pe_verify_skey` it built
  its reply from the *first live* torrent slot, so in a session holding a share and any other torrent
  a peer that knew the second hash read the share's link out of the decrypted reply, and a share on a
  slot other than the first was often simply unreachable (the client gets a foreign hash and drops
  the connection). The reply is now built inside `PE_ST_RECV_HS` from the slot the SKEY matched and
  is refused — at the cost of zero bytes — unless the initiator's own handshake resolves to that
  same slot. A slot that is not serving is never matchable either: the all-zero hash of a share still
  hashing was accepted by the inbound plaintext matcher and offered as an MSE SKEY candidate, and
  since the zero hash is public knowledge anyone could pass MSE and land on a share whose bytes are
  not verified yet. One gate now covers the v1 loop, the BEP 52 v2 upgrade loop and the candidate
  list; plain torrent slots behave exactly as before. `docs/protocol.md`, `SECURITY.md`.
- **A share is published only over bytes it can still prove.** `--store-dir` is created at the end of
  the synchronous gate — parents `0755`, the leaf `0700` because it holds `.torrent` files, which are
  access keys, `chmod`ed so the umask cannot widen it, an existing final component refused unless it
  is a real directory — and writability is proven with one `O_CREAT | O_EXCL` probe rather than
  `access(W_OK)`, which is a lie for root. Before, a missing store dir was paid for with the whole
  hash and then answered `io` with "cannot read the file" for a *write* failure; it is an immediate
  `io` now, and the failure names the destination. The `st_dev`/`st_ino`/`st_size`/`st_mtime`/`st_ctim`
  snapshot is taken from the descriptor at open and re-checked before anything is built, written or
  announced, so a byte edited during hashing ends the share as `changed` with no `.torrent` and no
  magnet instead of publishing a link whose pieces fail forever, and a file that lost bytes under the
  hash (`pread` 0) is `changed`, not `io`. `docs/storage.md`, `docs/cli.md`, `docs/json-api.md`.
- **A failed share looks failed.** An error that followed its `ready` event was dropped on the floor
  (the slot's one event had already been spent), so the CLI kept seeding a dead share and a JSON
  consumer never saw `ok:0`; the two facts — a ready event and an error event — are separate now, each
  set only once the event is really queued, a full queue delays instead of dropping, and `ok:1` always
  precedes `ok:0` for an `i`. Both failure paths halt through one act: exactly one `stopped`, the
  slot's peers dropped through the normal teardown, the announce schedule cleared after the drops so a
  departing peer cannot re-arm it, and new handshakes naming the real hash refused. A failed share
  reports `phase: "fail"` with a zeroed hash in stats, keeps announcing nothing, and never sends a
  `stopped` for a swarm whose `started` was never answered. `docs/json-api.md`, `docs/cli.md`.
- **A dead HTTPS tracker costs 0.9 s, not 30.7 s.** Five unreachable share trackers (the size of the
  built-in pool) held the whole session loop for 153 s while TLS waited out its 15 s I/O timeout and
  the 1.2 fallback waited out another, with JSON, IPC, DHT and every peer waiting; each announce now
  carries a 900 ms budget that every blocking wait inside it clamps itself to, and the fetch dies as
  an ordinary connect failure — one strike, dead after the usual count, revived by the share's own
  revival. Measured: 964 ms worst iteration, 4.8 s for the five. `started_ok` is set by the reply to
  the request that carried `started` instead of by whatever event the slot happened to hold, so an
  answered `started` no longer leaves a share in `ANNOUNCING` forever (and owing no goodbye), a `none`
  reply buys no `READY` it did not earn, and a BEP 15 connect answer no longer marks a share ready
  before its `started` was sent. An announce response whose bencode ends in `\r`, `\n` or spaces is
  accepted now — the share-tracker survey lost three hosts to those two trailing bytes, not to TLS.
  A `.torrent` stays an exact document; the strict parser behind the share hash gates is deliberately
  not relaxed. `docs/network.md`.
- **Every share request gets an answer, and a bad one gets refused.** A queued share event whose JSON
  could not be built (an escape refusal, a line over the cap) vanished after being dequeued, leaving
  the consumer waiting forever for that `i`; it now emits the §11 failure shape for the same slot,
  `{"type":"share","i":<i>,"ok":0,"code":"io"}`. `\u0000` in a JSON string is `bad_json`: it used to
  decode, and every consumer downstream is `strlen`-based, so `{"cmd":"share","path":"a\u0000b"}`
  seeded the file `a` and replied `ok`. The generator and `add` share one magnet length
  (`NTX_MAGNET_MAX`, 2048 B, with a `_Static_assert` on the two buffers), so a link `ntx --share`
  prints is always one `ntx add` accepts. A magnet that cannot be written to stdout is reported and
  costs exit 1 instead of printing the `shared —` note over a link the operator never got (`/dev/full`,
  or a pipe whose reader is gone). `--share-from` given twice is exit 2, like `--share`. A
  `--share-from` `.torrent` must be one exact document — trailing garbage is `bad_arg`, never a share
  published under a prefix's link — and one name gate (valid UTF-8, no ASCII control bytes, no `/`)
  decides every name, including the one written into the metainfo. `docs/json-api.md`, `docs/cli.md`.
- **The status line keeps the tags that matter.** For a share slot the safety block (`prv`, `shr`/
  `shr!`, `enc!`, `pin!N`, `map`/`map!cg`, `inN`) is printed directly behind the name column and the
  counters give way first, so on an 80-column terminal a share that stopped serving, failed its pin
  check or will not take inbound no longer renders as a healthy line; a cut line really does end in
  ` ..` now, where the ellipsis had been written behind the terminating NUL. Names are cut on a UTF-8
  boundary and an ill-formed byte run becomes exactly one U+FFFD, so a share whose name held multi-byte
  text no longer emits stats lines (one per 100 ms) that a strict JSON parser rejects. A diagnostic no
  longer lands on top of the live status line — one CLI-owned hook closes it before any `ntx_diag`
  bytes. The two `exists` cases read differently: a different `.torrent` already at the destination
  versus this torrent already shared as `<name>`. Ctrl-C during hashing names the file instead of
  printing an empty row. `docs/cli.md`, `docs/json-api.md`.
- **The port mapper stops spinning and stops repeating itself.** A gateway that answers with ICMP
  port-unreachable left a pending `SO_ERROR` no callback read, so the level-triggered event never went
  away and the loop burned three million iterations a second; `SO_ERROR` is drained before each send
  and inside the error callback, the `send()` result is honoured, and an `ECONNREFUSED` steps PCP →
  NAT-PMP once per sequence. A §8.5 epoch restart costs one re-request from the tick, never one per
  round trip from the receive path, the check now runs both directions against the baseline and
  covers NAT-PMP's `Seconds Since Start of Epoch` too, and a `SUCCESS` grant with lifetime 0 is a
  refusal in both families. Retries are paced per their own RFC (PCP 3 s doubled to a 1024 s MRT with
  ±10 % jitter, NAT-PMP 250 ms doubled, nine sends), a gateway's stated result code is treated as the
  verdict it is — a definitive refusal ends the schedule, `NO_RESOURCES` and `NETWORK_FAILURE` get one
  deferred retry floored at 60 s — and a NAT-PMP renewal is never closer than 30 s to the last one.
  `--share` waits at most 4 s for the mapping and then announces on the listen port, re-announcing
  when the advertised port changes, where it used to print its magnet about two minutes late behind an
  unresponsive gateway. `docs/network.md`.
- **A mapping says what is true and is always torn down.** A renewal or a delete now carries the nonce
  the gateway actually granted, so a renewal renews instead of opening a second mapping and a delete
  names a request the gateway recognises. A renewal that fails drops the grant and backs off
  (5 min, doubling to 1 h), so the swarm stops being told to dial a port the gateway stopped
  forwarding — `ext_port` returns the listen port once the grant's own lifetime has passed. The CGNAT
  verdict sends the lifetime-0 deletes for held mappings *before* clearing the fields those deletes
  are built from, and the delete pump continues past a refused datagram instead of leaving the other
  family's mapping forwarding for the rest of its 7200 s. A NAT-PMP delete suggests port 0 as
  RFC 6886 §3.4 requires. A fresh UDP ask now suggests the TCP grant's port, and a gateway that
  forwards UDP elsewhere is reported under `--verbose`. A grant whose external port is 0, whose
  external address is all-zeros, or whose v4 address is not the IPv4-mapped form is refused as a
  refusal — not reported as `port_map: active` with the listen port behind it.
- **`--port-map` maps without a share, and reads the routing table honestly.** The flag used to be a
  no-op for a session that is not sharing — nothing was mapped and no `map` tag appeared — while both
  the CLI and the network docs promised the opposite; the mapping is requested at session bring-up
  when the user asked for it. On the v4 side the default route now requires `RTF_UP` and `RTF_GATEWAY`
  and refuses `RTF_REJECT` (the flags field is read as hex, as the kernel prints it), an equal metric
  keeps the first usable line rather than the last one walked, and a failed `getsockname` aborts the
  family instead of asking the gateway to forward to a zero or a stale client address. The IPv6 half of
  the driver is covered by its own entries above. `docs/network.md`, `docs/cli.md`.
- **A BEP 55 `connect` message cannot wipe a peer's dial penalty.** The holepunch dial cleared the
  back-off record of the endpoint named in the message and then dialled unforced, so any connected peer
  could reset a 30 s..10 min penalty on demand and every repeat message bought another attempt. The
  dial is now explicitly forced — a fresh connect message is evidence the endpoint is worth trying —
  while the failure history survives, re-arms on failure and keeps growing, and the address is tagged
  as peer-sourced so the BEP 27 gate and the stats see its real origin.

## 0.1.5 - 2026-11-13

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
- **A share works against qBittorrent.** The BEP 52 interop matrix has a cell where containerised
  qBittorrent-nox 4.5.2 downloads an `ntx --share` byte-identically, with a local pinned HTTPS
  tracker as the only address source — no DHT, PEX or holepunch, as BEP 27 demands — and never a
  `/scrape` without `info_hash`. It runs two passes that blind one dial side each, so the `ntx` MSE
  initiator and the responder are observed separately instead of strict encryption being taken on
  trust. Manual: `bash test/interop/v2/interop_v2.sh` (needs Docker and `python3`), verdict in
  `test/.scratch/9/interop-v2/matrix.txt`.

### Fixed
- **`--share` dialled nothing on a host with no usable IPv6 route.** The hostname resolver the
  HTTPS paths share preferred AAAA whenever the host published one and only tried A when the AAAA
  lookup itself failed, and every built-in share tracker publishes AAAA, so such a host got
  addresses it could not reach and announced to none of them. The family is now picked from
  `/proc/net/ipv6_route` — one cached read per process, where a `::/0` line counts only if it is
  `RTF_UP` with a usable metric — and the A record is used directly otherwise. Literal IPv4 and
  IPv6 addresses are unaffected.
- **Dial and teardown paths leaked memory.** A SOCKS5 dial left its ~632 B connect context behind
  on every path that drops the fd without a terminal proxy result — dial, connect and handshake
  timeouts, torrent `remove`, session teardown, a full peer table, `ntx_netx_free` with a dial in
  flight — so traffic through `--proxy` grew the heap without bound. A peer still attached at slot
  or session teardown never released the five arrays allocated per peer, and a torrent that finished
  hashing never released the `phash`, `have`, `rarity`, `info_raw` and `piece_layer` fields the
  metainfo validator hands to its caller; those are now freed through the new public
  `ntx_torrent_release()`.
- **The PCP/NAT-PMP address classifier misread IPv6 addresses.** It tested octets 10–11 only, so
  any global IPv6 address carrying `ff ff` there (a 6to4 or NAT64 prefix, a link-local) was read
  as an IPv4-mapped private or CGNAT address, and a ULA was read as public. The ten leading zero
  octets of an IPv4-mapped address are now required before the marker. That classifier decides
  both whether a mapping is requested at all and whether a granted external port is reported as
  `map!cg`.
- **A build without usable pinned share trackers no longer touches the caller's file.** Below
  `NTX_SHARE_MIN_TRACKERS` qualified hosts the tracker gate ran after the file had been opened and
  `fstat`ed and, for `--share-from`, after its `.torrent` had been parsed, so a share of an
  unreadable path answered `io` and a binary without the feature reported whether a path exists
  and is readable. The gate is now the first decision after argument validation, so every attempt
  answers `no_trackers` as `docs/json-api.md` promises, and the JSON path agrees with the earlier
  refusal the CLI already made.
- **Share-tracker keys rotated, and two hosts left the table.** The community HTTPS trackers
  rolled their Cloudflare edge keys; each verified new key is pinned beside the survey key of its
  host, so a binary accepts the old and the new certificate during the rollover. `tracker.nekomi.cn`
  and `004430.xyz` were dropped for answering a bare `/scrape` with the full peer list
  (~143 MB, a real `files` dictionary), which fails the no-full-scrape criterion of the survey.
  Five hosts remain, above `NTX_SHARE_MIN_TRACKERS`.

### Packaging
- Release assets now include binary **RPM** (Fedora / RHEL / openSUSE) for x86_64 and aarch64,
  plus `ntx-<version>-packaging.tar.gz` with stamped **Gentoo** ebuild, Arch `PKGBUILD`, Alpine
  `APKBUILD`, Nix flake and source RPM `.spec`. Install matrix documented in README and release notes.
- The release workflow gained two blocking gates before packaging: `make pins-check` (every
  built-in share-tracker key still verifies against the system CA store, no host answers a full
  `/scrape`, at least `NTX_SHARE_MIN_TRACKERS` hosts qualify) and a `strings` check that the test
  tracker table never reaches a published binary. New targets: `make test-share` runs the
  private-share end-to-end against `make ntx-sharetest`, and `make test-cli` additionally runs the
  offline gate for the pins tool (skipped when `python3` is absent).

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
