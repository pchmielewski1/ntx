# ntx

A BitTorrent client in one small C binary. **C11 + POSIX, `libc` + `libm` only**: no OpenSSL,
no vendored libraries, no build-system machinery. The cryptography (DH, RC4, AES-GCM, X25519,
P-256, RSA), the TLS 1.3 / 1.2 client and the DoH name resolver are implemented in-tree.
The release build is about **450 KiB** (`-O2`, aarch64, gcc 13; other targets and compilers
differ by some tens of KiB), and `make size` fails the build at 1 MiB (1048576 B).

It downloads `magnet:` links and `.torrent` files (single- and multi-file; BitTorrent v1, v2
and hybrid), verifies every piece, resumes from disk on restart, and seeds after completion
(until a 3x upload ratio). It is driven from the terminal: no GUI, no config file.

**Status:** a working client (magnet, metadata, download, seed), not a protocol sketch, and
not a drop-in replacement for qBittorrent or Transmission. Use it only with content you have
the right to download or share.

> **Security status:** all cryptography and the TLS stack are hand-written and have
> **not been independently audited**. [SECURITY.md](SECURITY.md) lists what was reviewed and
> fixed (a crypto review and a pre-release audit of the network-facing code) and what was not
> covered (notably: the fuzz harnesses were not run during that audit). Treat `ntx` as a
> project for reading, learning and experimenting; do not rely on it to protect anything you
> could not afford to lose.

## Why bother

`ntx` is about 25 kloc of C (sources and headers, comments included) that you can read end to
end: the wire protocol, the crypto, the event loop. If you want to know exactly what a
BitTorrent client does on the wire, or want a client whose DNS and TLS trust path (DoH and
SPKI pins instead of system DNS and a CA store) is small enough to audit yourself, start here.

- **One binary, one `cc` invocation.** `make` compiles all sources with a single compiler command.
- **No system DNS.** Hostnames resolve over DoH through a compiled-in, pinned failover pool
  (Quad9, OpenDNS, Control D, LibreDNS, UncensoredDNS, OpenBLD, DNSPod, in that order).
  A poisoned operator DNS is simply unused. DoH negotiates ALPN `h2` / `http/1.1` over the
  in-tree TLS client; a provider whose key does not match its pin is refused (details on
  stderr with `--verbose`). First contact with an unpinned HTTPS host is explicit TOFU, see below.
- **Peer encryption.** Outgoing connections start with Mainline MSE/PE (DH + RC4) and
  incoming ones accept it. A peer that speaks plaintext is still served: the fallback is
  always on (`--compat-peers` is accepted but is the default and cannot be turned off).
- **Your own TLS.** A from-scratch TLS 1.3 client (X25519, AES-128-GCM, ECDSA P-256 or
  RSA-PSS server signatures) with automatic fallback to TLS 1.2 (ECDHE-RSA / ECDHE-ECDSA)
  and certificate SPKI pinning; there is no system trust store (see
  [HTTPS](#https-trackers--webseed)).
- **Disk resume.** A restart re-scans existing data and re-verifies the pieces, so the
  bitfield and `left` are correct from the first announce; a finished torrent comes back as a
  seeder without noisy `started`/`completed` events.
- **Escape hatches.** SOCKS5 (peer TCP, HTTP(S), and UDP ASSOCIATE for uTP dials) and a custom
  TCP tunnel for outbound peer connections, rate limits, optional DHT.

## Requirements

- **Linux** (x86_64 or aarch64; the event loop uses `epoll`)
- A C11 compiler (`cc` / gcc / clang) and **GNU Make**
- Optional: `musl-gcc` for `make static`

No OpenSSL, no libcurl, no cmake: the binary links against `libc` and `libm` only.

## Quick start

```sh
make            # builds ./ntx
./ntx link.txt  # shows the CLI / status line (see note below)
```

`link.txt` is a **format demo** with a fictional infohash: it will not download real data
(the line stays at `META:trk-wait` / `META:meta-wait`). Pass your own `magnet:?…` URL or a
`.torrent` file instead. For a quick real test, the official torrent of a Linux distribution
is a good choice:

```sh
./ntx 'magnet:?xt=urn:btih:…'
./ntx --dht --stats-json some.torrent
```

Files land under `downloads/` by default (`--store-dir=` to change it). Stop with `Ctrl+C`;
a final status line is printed on exit.

Illustrative session (one line, refreshed in place on a TTY):

```
Example.Content.1080p META:trk-wait  trk02/18p01 pe00/00/00u00i00 dnsQ9  5s
Example.Content.1080p META:meta      trk08/18p00 pe43/00/08u02i00 m04/15 dnsQ9  18s
Example.Content.1080p  21% [====>     ]  382M/1.82G  v8.1M/s^0B/s  3:12  215/934 @dl …
Example.Content.1080p 100% [==========]  1.82G/1.82G  up9.8M ^45K/s r1.4 @seed …
```

While seeding, the live line shows cumulative upload (`up…`) and upload rate (`^…/s`), not
only the summary printed on `Ctrl+C`.

## CLI

```
usage: ntx [opts] <magnet|link.txt|.torrent>
  --store-dir=DIR      download directory (default: downloads/)
  --port-lo=N          listen port range start (default: 6881)
  --port-hi=N          listen port range end   (default: 6891)
  --max-peers=N        max concurrent peers            (default: 128)
  --proxy=socks5:HOST:PORT   SOCKS5 for peer TCP + HTTP (trackers/webseed)
  --tunnel=HOST:PORT   route peer TCP through an NTX1 tunnel (wins over proxy)
  --down-limit=B/s     download rate limit (0 = unlimited)
  --up-limit=B/s       upload rate limit   (0 = unlimited)
  --dht                enable DHT (default: off)
  --utp                enable uTP (BEP29) peer transport, IPv4 + IPv6 (default: off)
  --no-https-tofu      disable HTTPS TOFU pinning (default: on)
  --https-pin-file=PATH  load SPKI pins from PATH (host + 64-hex per line)
  --compat-peers       accept plaintext peers (always on; accepted for compatibility)
  --allow-local-peers  also dial/accept loopback, link-local and other special peer addresses
                       (default: off; see SECURITY.md)
  --smooth             rate caps 128 KiB/s down, 32 KiB/s up if no explicit limits
  --stats-json         NDJSON session stats on stdout instead of the status line
  --verbose, -v        verbose diagnostics to ntx-verbose.log
  --log=FILE           verbose log to FILE (also enables the log file)
  -h, --help           print the option summary to stdout and exit 0
  -V, --version        print the version and exit 0
```

This is the documented option list; `ntx --help` prints a shorter summary of the same options.
Details: [docs/cli.md](docs/cli.md).

The command line is validated strictly: an unknown option, a non-numeric or out-of-range
number, an unreadable `.torrent`, an invalid magnet link or a malformed `--proxy` /
`--tunnel` value is a hard error (message on stderr, exit status 1 or 2), never a silent
fallback, so a typo cannot quietly send traffic outside your proxy.

Listen binds the first free TCP port in `[--port-lo, --port-hi]` (an ephemeral port if the
whole range is busy). Status line tags: `trk` / `pe` / `dns…` / `@phase`. Progress counts
**verified bytes** (after the hash check), not raw wire traffic.

## Machine control (`--stats-json`)

With `--stats-json`, `ntx` speaks NDJSON on stdout (`hello`/`stats`/`ack`/`err`) and, when
stdin is not a TTY, accepts one JSON command per stdin line: `ping`, `status`, `hello`, `add`,
`pause`, `resume`, `remove`, `quit`. EOF on stdin closes the command channel while the session
keeps running. A torrent argument is optional in this mode (`add` can supply it). See
[docs/json-api.md](docs/json-api.md) for the full v1 contract.

## Features

- **Discovery:** UDP and HTTP(S) trackers (`announce` and `announce-list`, BEP 12), optional
  DHT, PEX (BEP 11), HTTP(S) Range web seeds from magnet `ws=` / `as=` (a `.torrent`
  `url-list` is not read).
- **HTTPS:** `https://` trackers and web seeds over the in-tree TLS client (TLS 1.3 with TLS 1.2
  fallback; ALPN `http/1.1`) with **SPKI pinning** (`SHA-256` of the leaf
  SubjectPublicKeyInfo), **TOFU on by default**, and no CA store.
- **Magnet:** BEP 9 `ut_metadata` (16 KiB blocks), SHA-1 checked against the info hash.
- **Wire:** BEP 3 / 6 / 10, rarest-first picker, an adaptive request pipeline of 32-128
  in-flight blocks per peer, an endgame mode for the last blocks, and a 60 s ban for peers
  that send a bad piece.
- **Rate limits:** `--down-limit` / `--up-limit` are token buckets applied to block payload.
- **Seeding:** after completion, upload until **3x** the torrent size.
- **BitTorrent v2 (BEP 52):** v2 and hybrid metainfo, `urn:btmh` magnets, merkle SHA-256 piece
  verification and hash exchange (messages 21/22/23) in both directions.
- **IPv6 (BEP 32):** dual listen (v4 + v6, same port when free), DoH AAAA-then-A hostname
  resolution, tracker `peers6` (HTTP + UDP), PEX `added6` / `dropped6`, outbound v6 via raw
  TCP, SOCKS5 or tunnel. The DHT is iterative and dual-stack (BEP 5 + BEP 32).
- **uTP (BEP 29):** UDP peer transport via `--utp` (20-byte header, SACK, delay-based
  congestion control) on the same port as the TCP listener, IPv4 and IPv6. One shared UDP
  owner demultiplexes DHT and uTP by first byte. BEP 55 holepunching works on the connect
  side only: `ntx` acts on `connect` messages and does not relay. SOCKS5 UDP ASSOCIATE
  (RFC 1928) is used for proxied dials. TCP is the default transport and the fallback.
- **Faster start and transfer:** tracker announces are queued and paced (UDP trackers first,
  HTTP(S) ones after), `numwant` is 200, connect attempts time out after 2.5 s while few peers
  work, and addresses that fail to connect are retried with a back-off. See
  [CHANGELOG.md](CHANGELOG.md) for the measurement.
- **Privacy:** DoH-only DNS, MSE/PE peers, proxy/tunnel for peer traffic, local-only diagnostics.

## HTTPS (trackers + webseed)

`https://` announce and web seed URLs use the in-tree TLS client (no OpenSSL, no CA store):
TLS 1.3 first (`TLS_AES_128_GCM_SHA256`, X25519, ECDSA-P256 / RSA-PSS), falling back to TLS 1.2
(ECDHE + AES-128-GCM). Trust is **SPKI pinning**, not a certificate chain: a connection is
accepted only if `SHA-256(SubjectPublicKeyInfo)` of the leaf matches a pin from
`--https-pin-file=PATH` or a pin remembered by trust-on-first-use (announced on stderr; on by
default, disable with `--no-https-tofu`). The built-in pin pool for HTTPS hosts contains only a
loopback test entry, so in practice an HTTPS tracker needs TOFU or a pin file. With TOFU off
and no matching pin, the connection is refused before any byte is sent. Responses may use
`Content-Length` or `Transfer-Encoding: chunked`; redirects are not followed. (The DoH
providers have their own compiled-in pins.)

The TLS stack has been checked against an independent Python reference, frozen server streams,
`openssl s_server` and live servers, but it has **not been externally audited**. Pin sources,
TLS 1.3 scope and the test matrix: the "TLS client" section of [docs/network.md](docs/network.md).

## Limitations

Some of these are deliberate non-goals; the rest are gaps listed in
[docs/roadmap.md](docs/roadmap.md) (nothing there is promised).

- Linux only (no Windows or macOS builds); only x86_64 and aarch64 are built and tested.
- No GUI and no config file. One torrent can be given on the command line; more can be added
  at run time through the `--stats-json` control channel.
- Not implemented: selective file download and priorities, sequential mode, torrent creation,
  NAT-PMP / UPnP port mapping, local peer discovery (LSD), download queueing, persistence of
  the paused state, tracker scrape, following HTTP redirects from trackers.
- **Private torrents (BEP 27):** the `private` flag is ignored; PEX is always offered and DHT
  is used when `--dht` is set. Do not use `ntx` with torrents from private trackers.
- PEX (BEP 11): `added` entries are used and `dropped` entries are sent, but received
  `dropped` entries are ignored (a hostile peer could otherwise evict good peers).
- **BitTorrent v2:** the optional mid-connection v1-to-v2 handshake upgrade is not
  implemented (a SHA-256 handshake hash arriving for a hybrid torrent is accepted, but `ntx`
  never initiates or answers the upgrade). No third-party v2 client was available for
  interop testing (details: [docs/testing.md](docs/testing.md)).
- **uTP (`--utp`):** outgoing dials try uTP first and are retried over TCP after 1.5 s without
  an answer (most peers have no uTP); if uTP never works in a session, `ntx` stops trying it
  first. `--utp` downloads from a public swarm were verified live. Not tested: a live Tor or
  VPN setup (only framing vectors), and head-less third-party uTP seeders (those interop
  cells are skipped, not passed; see [docs/network.md](docs/network.md)).
- Peer traffic is never TLS; the in-tree TLS client (SPKI-pinned, no CA store) is used only
  for DoH and HTTPS trackers / web seeds.
- The DHT is an iterative Mainline dual-stack subset (BEP 5 / BEP 32): enough for `--dht` peer
  discovery, not a full DHT router.
- `--tunnel` is a custom NTX1 framing protocol, not Tor, WireGuard or a generic VPN.
- HTTP(S) tracker requests and DoH lookups block the event loop while they run.

## Architecture

```
src/
├── ntx_main.c        entry point, CLI args, main loop, signals
├── core/             session, store/resume, piece engine, peers, trackers, stats
├── net/              epoll, sockets, SOCKS5, tunnel, TLS 1.3 / 1.2, uTP
├── proto/            bencode, magnet, trackers, BEP 9/10/11, DHT, MSE/PE, HTTP, DoH
├── crypto/           SHA-1/256, HMAC, AES, RC4, DH, X25519, P-256, RSA, RNG
└── ui/               status line, NDJSON, verbose log
```

74 C sources and 64 headers, no dependencies. See [docs/architecture.md](docs/architecture.md)
and [docs/module-map.md](docs/module-map.md).

## Testing

```sh
make test         # unit/integration suites, test/t_*.c (some bind loopback TCP/UDP sockets)
make test-cli     # command-line validation: bad input must fail fast, never be ignored
make test-interop # ntx vs. a reference client (transmission, in docker): wire/PE/tracker
make size         # binary size gate (< 1 MiB)
make test-net     # smoke: listen port in --port-lo/--port-hi + JSON
make test-ipc     # --stats-json command channel end to end
make test-tls13   # TLS 1.3 client vs. `openssl s_server` on loopback (needs the openssl CLI)
make probe        # optional tracker/DoH probe binary
make static       # musl static build (optional)
```

Suites cover crypto vectors (including independently generated ones), wire/MSE/PE,
magnet/tracker parsing, DoH/TLS/HTTPS, DHT, IPv6 bind, store resume, and session
endgame/upload simulations. They are a regression gate, not a protocol-conformance
certificate: conformance against a reference client is covered by `make test-interop`, and
the parsers have libFuzzer harnesses in `test/fuzz/` ([docs/fuzzing.md](docs/fuzzing.md)).
See [docs/testing.md](docs/testing.md) for the suite map.

## Platforms

| Architecture | Status |
|--------------|--------|
| Linux x86_64 | built and tested in CI (`make test` and the other targets above) |
| Linux aarch64 (ARM64) | built and tested in CI |

Flags: `-O2 -std=c11 -Wall -Wextra -Werror -D_POSIX_C_SOURCE=200809L -ffunction-sections`,
linked with `-Wl,--gc-sections`, plus hardening flags (stack protector, `_FORTIFY_SOURCE=2`,
PIE, full RELRO, non-executable stack).

## Privacy notes

### Protected

- **DNS resolution:** the pinned DoH pool only, no system DNS; the DoH channel is SPKI-pinned
  (a provider with a mismatching key is refused; details with `--verbose`).
- **Tracker and web seed fetches over HTTPS:** in-tree TLS 1.3 / 1.2 with SPKI pinning (no CA
  store).
- **Peer payload:** Mainline MSE/PE when negotiated; plaintext peers are still accepted.

### Not protected (visible to the network path)

- **Tracker announces:** BEP 3 UDP/HTTP announces are plaintext, so the info hash and your IP
  are visible to your ISP and anyone on the path.
- **PEX (BEP 11) and DHT (BEP 5):** plaintext by design.
- **`ut_metadata` content:** SHA-1-verified against the info hash, but not hidden.
- MSE/PE is obfuscation, not authentication or strong confidentiality.

**TOFU:** the first connection to an unpinned HTTPS host is trusted and remembered in
`<store>/https_tofu.bin` (default on; `--no-https-tofu` disables it). An attacker present on
that first connection is not detected.

Peer TCP can be forced through `--proxy` / `--tunnel`. `--verbose` writes a local log only;
there is no telemetry.

**Peer addresses.** By default, peers (from trackers, PEX, DHT or inbound) at loopback,
link-local (including the cloud metadata address 169.254.169.254), unspecified, multicast and
reserved addresses are refused, so a hostile tracker cannot point `ntx` at services on
localhost. Private LAN ranges (RFC 1918, IPv6 ULA) are **not** blocked, because LAN swarms
are legitimate; use a firewall if that matters to you. For local testing add
`--allow-local-peers`.

**Proxy and UDP.** `--dht` cannot be combined with `--proxy` / `--tunnel`: DHT is UDP and
would bypass them. For the same reason UDP trackers are skipped in those modes.

## Troubleshooting

| Symptom | Likely cause |
|---------|--------------|
| `dns!` / long `META:trk-wait` with `pe00` | DoH or trackers unreachable; check the network or try later |
| `META:connect` / many peers, `ok=0` | Firewall/NAT, or peers not accepting; try `--dht` (and `--utp`) |
| `@choked`, `u00` | Connected but not unchoked yet; wait, or raise `--max-peers` |
| Wire RX grows, piece count stuck | Normal until a full piece passes the hash check |

## Documentation

[docs/README.md](docs/README.md) is the index (architecture, CLI, JSON API, protocol, network,
storage, testing, fuzzing, module map, roadmap). Release notes: [CHANGELOG.md](CHANGELOG.md).
Security policy and review findings: [SECURITY.md](SECURITY.md).

## License

MIT, see [LICENSE](LICENSE).
