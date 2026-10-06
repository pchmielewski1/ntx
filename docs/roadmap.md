# Roadmap: ideas and known gaps

**Nothing on this page is implemented, scheduled or promised.** It is a list of things `ntx`
does not do today, with a note on what exists, what would be needed and what it would cost.
Some of these are deliberate non-goals. For what the program does today see
[`../README.md`](../README.md) and the documents linked from [`README.md`](README.md).

Contributions are welcome, but check first that the trade-off is acceptable: the project
values a small, readable code base that needs only `libc` + `libm`, and the release build
has to stay under the 1 MiB gate of `make size`.

## Platform

### Portability beyond Linux
- **Today:** the event loop is `epoll` (`src/net/ntx_netx.c`); everything else is plain POSIX
  (non-blocking sockets via `fcntl`, `pread`/`pwrite`, `clock_gettime`, `/dev/urandom`).
  CI builds and tests x86_64 and aarch64 Linux only. The `Makefile` assumes GNU Make and
  GNU `stat`.
- **Needed:** a small poll abstraction with a `kqueue` backend would cover macOS/BSD; a Windows
  port would additionally need a socket/file/time layer and a different build.
- **Trade-offs:** `kqueue` is a contained change. Windows touches almost every file and the
  maintenance cost is high for a client this small.

### Other CPU architectures
- **Today:** only x86_64 and aarch64 are built in CI. Nothing in the code is architecture
  specific, but other targets (e.g. riscv64) have not been tried.

## User interface

### Optional UI
- **Today:** a one-line status on stderr and the `--stats-json` NDJSON channel
  ([`json-api.md`](json-api.md)); no GUI, no config file.
- **Needed:** the cheapest option is an external front end that reads `--stats-json` and writes
  commands to stdin; it adds nothing to the binary. A built-in TUI or a local web page would add
  code to the event loop.
- **Trade-offs:** `ncurses` would end the "`libc` + `libm` only" property.

### Torrent management
- **Today:** `add`, `pause`, `resume` and `remove` work at run time over `--stats-json`.
  There is no download queue, the paused state is not persisted, and only one torrent can be
  given on the command line.
- **Needed:** a queue/scheduler and a small state file.
- **Trade-offs:** a state file means deciding on a format and a location; today `ntx` writes
  nothing except the downloaded data, the TOFU pin file and the optional verbose log.

## Download features

### Selective download, priorities, sequential mode
- **Today:** all files of a torrent are downloaded, pieces are picked rarest-first.
  BEP 47 padding files are recognised.
- **Needed:** a per-file "wanted" mask in the picker, the store and the progress accounting,
  plus a UI to set it (magnet `so=` from BEP 53 could carry it).
- **Trade-offs:** touches the piece picker, endgame mode and v2 file/merkle handling.

### Resume without re-hashing
- **Today:** on restart the existing data is re-scanned and every piece is re-verified; no
  resume file is kept.
- **Needed:** a persistent have-bitmap with file sizes/mtimes to validate it.
- **Trade-offs:** faster restart of large torrents versus a new on-disk format that can go
  stale.

### Torrent creation
- **Today:** not implemented (`ntx` only reads metainfo).
- **Needed:** hashing a directory into v1/v2/hybrid metainfo and a CLI for it.

### Private torrents (BEP 27)
- **Today:** the `private` flag in the info dictionary is not read. `ut_pex` is offered for every
  torrent, and DHT (when `--dht` is set) is used regardless of the flag. Do not use `ntx` for
  torrents from private trackers.
- **Needed:** parse the flag; disable PEX, DHT and (with LSD) local discovery for such torrents.

## Network

### NAT traversal and local discovery
- **Today:** none. There is no UPnP, NAT-PMP/PCP or Local Service Discovery (BEP 14). Inbound
  connections work only if the listen port is reachable. BEP 55 holepunching is supported
  only as a connect target over uTP (no relaying, no rendezvous requests) and does not replace
  port mapping.
- **Needed:** an SSDP/UPnP-IGD client or a NAT-PMP/PCP client for the router, and a multicast
  listener for LSD.
- **Trade-offs:** UPnP means SSDP, XML and SOAP over HTTP with little to share with the
  existing code. NAT-PMP/PCP is much smaller. Both add attack surface on the LAN side.

### Non-blocking tracker and DNS I/O
- **Today:** HTTP(S) tracker requests and DoH lookups are blocking calls inside the event loop
  (UDP trackers are not). A dead HTTP tracker can stall the loop for the length of its timeout.
  Announces are queued and paced to limit this, and HTTP(S) trackers go after UDP ones.
- **Needed:** run the HTTP and TLS clients as state machines on the event loop.
- **Trade-offs:** a sizeable rewrite of the TLS client driver for a gain that matters mainly
  with slow or dead trackers.

### HTTP redirects and tracker scrape
- **Today:** redirects from trackers and web seeds are not followed; scrape (BEP 48) is not
  implemented.

### Peer transport
- **Today:** uTP (BEP 29) is optional (`--utp`) and falls back to TCP. Known deviations from
  the BEP are listed at the top of `src/net/ntx_utp_sm.c`; for example, the outgoing
  `timestamp_difference_microseconds` is always 0. Interop against third-party uTP stacks is
  partial: the head-less seeder cells of the test matrix are skipped, not passed
  ([`testing.md`](testing.md)).
- **Needed:** more interop runs and congestion-control tuning on real, lossy links.

### Proxy and anonymity
- **Today:** `--proxy=socks5:…` carries peer TCP, HTTP(S) trackers and (via UDP ASSOCIATE) uTP.
  `--tunnel` speaks a custom framing protocol (NTX1) to a server you run yourself. `--dht` and
  UDP trackers are skipped in those modes, and `--dht` together with them is refused, because
  that traffic would bypass the proxy. A live Tor or VPN setup has not been tested.
- **Needed (SOCKS):** DNS through the proxy instead of DoH, and a way to carry DHT.
- **Trade-offs:** `ntx` will not embed Tor or WireGuard; use them as external programs.

### DNS and TLS trust
- **Today:** name resolution uses a compiled-in pool of DoH providers pinned by SPKI hash;
  there is no option to choose another resolver and no system DNS fallback. HTTPS trackers
  and web seeds are trusted via a pin file or trust-on-first-use (the built-in pin pool
  holds only a loopback test entry). There is no CA store, no TLS session resumption and no
  client certificates.
- **Needed:** a configurable resolver and pin set; optionally a CA bundle loader.
- **Trade-offs:** provider keys rotate, which currently requires a new release; a CA store
  would be a large dependency on data that `ntx` does not ship.

## Protocol extensions not implemented

Checked against the source tree; each is absent today.

- **BEP 14** LSD and **UPnP/NAT-PMP**: see above.
- **BEP 27** private torrents: see above.
- **BEP 48** tracker scrape.
- **BEP 53** magnet `so=` file selection, and magnet `x.pe` peer hints.
- **BEP 19** web seeds listed in a `.torrent` (`url-list`); only the magnet `ws=` / `as=`
  parameters are used.
- **DHT extensions:** BEP 33 (scrape), BEP 42 (node-ID restriction), BEP 44 (arbitrary data),
  BEP 51 (`sample_infohashes`). The DHT is an iterative BEP 5 / BEP 32 subset without sybil
  resistance beyond token checks.
- **Peer extensions:** `upload_only`, `lt_donthave`, a `yourip` consumer (the field is
  parsed and ignored), and BEP 16 super-seeding. BEP 6 `suggest` and `allowed_fast` messages
  are received but ignored.
- **BEP 52 handshake upgrade:** a v2 hash arriving in a handshake for a hybrid torrent is
  accepted, but `ntx` never initiates or answers the v1-to-v2 upgrade itself.
- **BEP 11 `dropped`:** received entries are ignored on purpose, so a hostile peer cannot
  evict good peers; outgoing `dropped` entries are sent.
