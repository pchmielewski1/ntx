# Command line and status line

This page describes the `ntx` command line, its exit codes and the one-line status display.
The code is the reference: `src/ntx_main.c` (option parser), `src/ui/ntx_cli.c` (status line),
`src/core/ntx_session_stats.c` (phases and counters). The machine-readable mode
(`--stats-json`) is specified in [json-api.md](json-api.md).

## Synopsis

```
ntx [options] <magnet | link.txt | file.torrent>
```

Exactly one torrent source is expected:

| Argument | Meaning |
|----------|---------|
| `magnet:?xt=urn:btih:...` | A magnet link (any argument starting with `magnet:`). `urn:btmh:` (BitTorrent v2) is accepted too. |
| `something.torrent` | A metainfo file (any argument ending in `.torrent`). |
| any other non-option argument | A text file whose **first line** is a magnet link (for example `link.txt`). |
| none | Only valid together with `--stats-json`; the torrent is then added later with the `add` command. |

Rules worth knowing:

- Options that take a value must be written `--option=value`. `--store-dir DIR` is not supported (`DIR` would be read as a text file and rejected).
- If both a magnet and a `.torrent` file are given, the magnet is used and the `.torrent` is ignored. If several arguments of the same kind are given, the last one wins. A second text file after a magnet is an error (`unexpected argument`).
- The command line is validated strictly: a typo is an error, never silently ignored.

## Options

Defaults are those of `ntx_main.c`. `ntx --help` prints the same list.

| Option | Default | Behaviour |
|--------|---------|-----------|
| `--store-dir=DIR` | `downloads` | Directory for downloaded data. Also holds `https_tofu.bin` and, with `--dht`, `ntx_dht_state`. Created on demand. Layout: [storage.md](storage.md). |
| `--port-lo=N` | `6881` | First port of the listen range (`0`-`65535`). |
| `--port-hi=N` | `6891` | Last port of the listen range (`0`-`65535`). |
| `--max-peers=N` | `128` | Cap on peer connections the session opens (outbound dials, counted over all torrents). `0` means the default. The practical ceiling is 128, the size of the connection table. Incoming connections are accepted while table slots are free (at most 8 per remote address). Range `0`-`2147483647`. |
| `--proxy=socks5:HOST:PORT` | off | Route peer TCP connections and HTTP(S) tracker / web seed requests through a SOCKS5 proxy. The `socks5:` prefix is optional (`--proxy=HOST:PORT` works). `HOST` cannot be an IPv6 literal; the port must be `1`-`65535`. With `--utp`, uTP datagrams use SOCKS5 UDP ASSOCIATE. UDP trackers are skipped in this mode. |
| `--tunnel=HOST:PORT` | off | Route peer TCP connections through an NTX1 tunnel (a custom framing protocol, see [network.md](network.md)). Takes priority over `--proxy` for peers. HTTP(S) trackers and web seeds use `--proxy` if given, otherwise connect directly. UDP trackers are skipped in this mode. |
| `--down-limit=B/s` | `0` | Download limit in bytes per second of block payload; `0` = unlimited. Values above 2^40 are treated as unlimited. |
| `--up-limit=B/s` | `0` | Upload limit, same rules. |
| `--smooth` | off | For each direction whose limit is still `0`: set 128 KiB/s down, 32 KiB/s up. Explicit limits win. |
| `--dht` | off | Enable the Mainline DHT (IPv4 + IPv6, shares the listen port over UDP). Cannot be combined with `--proxy` or `--tunnel`. |
| `--utp` | off | Enable uTP (BEP 29) on the shared UDP socket. Outbound dials go over uTP first; a dial still unanswered after `NTX_UTP_DIAL_MS` (1500 ms) is retried over TCP. After 40 such misses without a single working uTP peer the session stops trying uTP first. Incoming uTP connections are accepted. If the UDP port cannot be bound, uTP stays off. Not used when a tunnel is established. Details: [network.md](network.md). |
| `--compat-peers` | on | Allow plaintext BitTorrent when message-stream encryption (MSE/PE) fails. The flag is accepted for explicitness; it is already on by default and there is no option to turn it off. |
| `--allow-local-peers` | off | Also dial peer addresses that are normally refused: `0.0.0.0/8`, loopback, link-local (`169.254.0.0/16`, includes the cloud metadata address), multicast / reserved (`224.0.0.0` and above) and the IPv6 equivalents (`::`, `::1`, `fe80::/10`, `ff00::/8`, IPv4-mapped forms of the above). The filter applies to outbound dials, whatever the source of the address (tracker, PEX, DHT, holepunch). Private LAN ranges (RFC 1918, IPv6 ULA) are never blocked. |
| `--no-https-tofu` | TOFU on | Disable trust-on-first-use pinning for HTTPS hosts. Hosts without a built-in or file pin are then refused. |
| `--https-pin-file=PATH` | none | Extra SPKI pins. One pin per line: `host 64-hex-digits` (SHA-256 of the leaf SubjectPublicKeyInfo). `host` is exact or `*.suffix` (does not match the bare suffix). Lines starting with `#` are comments; at most 16 pins are read. A missing or unreadable file is silently ignored. |
| `--stats-json` | off | Print NDJSON on stdout instead of the status line and accept commands on stdin. See [json-api.md](json-api.md). |
| `--verbose`, `-v` | off | Detailed diagnostics. They go to stderr and are mirrored into `ntx-verbose.log` in the working directory (truncated at each start). |
| `--log=FILE` | none | Use `FILE` instead of `ntx-verbose.log` and open the log even without `--verbose`. Detailed messages still require `--verbose`; without it the file only receives the always-on messages and the status lines. |
| `-h`, `--help` | | Print usage to **stdout**, exit `0`. |
| `-V`, `--version` | | Print `ntx 0.1.0` (the `NTX_VERSION` constant) to stdout, exit `0`. Checked before anything else, wherever it appears. |

### Listen port

TCP is bound on the first free port in `[--port-lo, --port-hi]`. A reversed range is swapped; `--port-lo=0 --port-hi=0` asks the kernel for an ephemeral port; a lower bound of `0` with a non-zero upper bound starts at `1`. If the whole range is busy, an ephemeral port is used. An IPv6 listener is bound on the same port when free, otherwise on an ephemeral one. UDP (DHT, uTP) uses the exact TCP port; if that is busy, uTP is off and the DHT uses its own socket. The chosen port is reported as `port` in the JSON stats.

### Proxies, DNS and privacy

- `--proxy` and `--tunnel` never fail open at parse time: a malformed value is a fatal error (exit `2`), so `ntx` cannot start talking directly when you asked for a proxy.
- If a tunnel is configured but not established at connect time, peer connections fall through to the proxy or to a direct connection (see [network.md](network.md)).
- DNS-over-HTTPS lookups connect directly to the pinned resolver addresses; they are **not** routed through `--proxy` or `--tunnel`.
- Tor/VPN are external: point `--proxy` at a local SOCKS5 daemon (for example `socks5:127.0.0.1:9050`) or use an OS-level VPN. `ntx` does not embed Tor.

## Validation and exit codes

| Exit code | Meaning |
|-----------|---------|
| `0` | Normal end (`Ctrl+C`, `SIGTERM`, or the `quit` command), `--help`, `--version`. |
| `1` | The program started but could not continue: invalid magnet link, unreadable or invalid `.torrent`, or an initialisation failure (random source, sockets, memory). |
| `2` | Command-line error, or no torrent source without `--stats-json`. |

On exit `0` after a signal, `ntx` sends a best-effort `stopped` announce to trackers (bounded to about 3 seconds in total) and prints a final summary line (not in `--stats-json` mode).

Command-line errors (exit `2`) are reported on stderr, followed by `ntx: try '<argv0> --help'`:

| Situation | Message |
|-----------|---------|
| no arguments | usage text on stderr (no hint line) |
| unknown option, including typos | `ntx: unknown option '--dth'` |
| numeric value that is not plain decimal digits (empty, sign, space, hex, suffix such as `10k`), overflows, or exceeds its range | `ntx: invalid value for --port-lo: 'abc' (expected an integer 0..65535)` |
| malformed `--proxy` (other scheme, missing or zero port, text after the port) | `ntx: invalid --proxy value '...' (expected socks5:HOST:PORT)` |
| malformed `--tunnel` | `ntx: invalid --tunnel value '...' (expected HOST:PORT)` |
| `--dht` together with `--proxy` or `--tunnel` | `ntx: --dht cannot be combined with --proxy/--tunnel (DHT traffic is UDP and would bypass them)` |
| argument that is not a magnet, a `.torrent` name, or a readable file with a magnet on its first line | `ntx: '...' is not a magnet link, a .torrent file, or a readable file whose first line is a magnet link` |
| extra positional argument | `ntx: unexpected argument '...'` |

Start-up failures (exit `1`):

| Situation | Message |
|-----------|---------|
| magnet without a valid `xt=urn:btih:` / `urn:btmh:` | `ntx: invalid magnet link (needs xt=urn:btih:... or urn:btmh:...): ...` |
| `.torrent` missing, empty or not valid metainfo | `ntx: cannot load .torrent file (missing, empty or not valid metainfo): ...` |

The tests for these cases live in `test/cli_errors.sh` (`make test-cli`).

On every start except `--version`, `ntx` first prints one banner line to stderr: `ntx: build <id> compiled <date> <time>`.

## Status line

Without `--stats-json`, the status of the torrent is written to **stderr** about ten times per second (every 100 ms).

- On a terminal the line is redrawn in place (`\r` + clear line) and cut to the terminal width.
- When stderr is not a terminal, every refresh is a separate line ending in `\n` (about ten lines per second).
- A line is at most 176 characters (`CLI_MAX_LINE`).
- Progress is **verified bytes** (after the SHA-1 or merkle check), not bytes received from the wire.
- With `--verbose`, diagnostics share stderr with the status line.

Examples (real output of the formatter):

```
ubuntu-24.04.iso     META:trk-wait  trk02/18p01 pe00/00/00u00i00   5s
ubuntu-24.04.iso     META:meta      trk08/18p00 pe43/00/08u02i00 m04/15 dnsQ9  18s
ubuntu-24.04.iso      21% [==>       ]  391.0M/1.82G  v8.1M/s^0B/s   3:12  215/934  @dl   trk09/18p00 pe60/05/55u12i03 dnsQ9
ubuntu-24.04.iso     100% [==========]   1.82G/1.82G  up2.54G ^44K/s r1.4 @seed trk09/18p00 pe60/05/55u12i03 dnsQ9
ubuntu-24.04.iso     100% [==========]   1.82G/1.82G  up5.45G ^0B/s  r3.0 @ratio-done trk09/18p00 pe60/05/55u12i03 dnsQ9
```

Layout of the downloading line: name (first 20 bytes, padded), percentage, 10-cell bar, `verified/total` size, `v<down rate>` and `^<up rate>`, ETA (`--:--` when unknown), `pieces done/total`, `@phase`, then the diagnostic tags below. While waiting for metadata the line is `name META:<phase>` followed by the tags and the uptime in seconds. When the torrent is complete, the rate / ETA / piece-count fields are replaced by `up<total uploaded>`, `^<up rate>` and `r<ratio>` (uploaded / size).

On exit a summary line is printed to stderr (not with `--stats-json`):

```
ntx: complete — <name> (verified N/N, <size>, uploaded <bytes> r<ratio>, phase <phase>)
ntx: stopped — <name> (verified N/M, <have> of <size>, phase <phase>)
ntx: stopped — <name> (metadata not fetched, phase <phase>)
```

### Diagnostic tags

Tags are appended in this order. Counters are capped at 99.

| Tag | Meaning |
|-----|---------|
| `trkUU/TTpPP[dDD]` | `UU` UDP trackers with a completed handshake, `TT` trackers in total, `PP` UDP requests pending; `dDD` trackers given up on (shown only when non-zero). HTTP(S) trackers count in `TT` but never in `UU`. |
| `peAA/HH/OOuUUiII` | Connections to this torrent: `AA` all, `HH` still handshaking, `OO` handshake complete, `UU` peers that have unchoked us (and we are interested), `II` peers interested in us. |
| `mGG/NN` | Metadata pieces received / total (16 KiB each); shown only while the metadata is being fetched. |
| `v2`, `hl` | Metainfo is pure BitTorrent v2 (`v2`) or hybrid v1 + v2 (`hl`). |
| `Lpend` | Pure-v2 torrent still waiting for its piece layers (hash exchange). |
| `dnsXX` | Last DNS-over-HTTPS provider that answered: `Q9` Quad9, `OD` OpenDNS, `CD` Control D, `LD` LibreDNS, `UC` UncensoredDNS, `OB` OpenBLD, `DP` DNSPod. `dns..XX`: a lookup is in flight. `dns!`: every provider failed. `dns!XX`: the pin check failed for provider `XX` (possible man-in-the-middle). |
| `utpN` | `--utp` is on; `N` live uTP connections. Absent without `--utp`. |
| `punchO/F` | BEP 55 holepunch dials started / refused. Absent until the first one. |
| `@phase` | Current phase (next table). |

### Phases

| Phase | Meaning |
|-------|---------|
| `init` | Nothing known yet (metadata phase, no trackers). |
| `trk` | Metadata phase, tracker requests pending. |
| `trk-wait` | Trackers known, waiting for replies or peers. |
| `connect` | Defined for "connections open, none past the handshake"; the current logic reports `hs` first, so it does not appear in practice. |
| `hs` | Peers connected, handshakes in progress. |
| `meta-wait` | A peer is connected but the metadata size is not known yet. |
| `meta` | Downloading metadata (BEP 9). |
| `verify` | Scanning existing files on disk after a restart. |
| `dl` | Pieces are arriving. |
| `wait` | At least one peer has unchoked us, nothing has arrived yet. |
| `choked` | Peers connected but none lets us download. |
| `stall` | Downloading, but no peers and no trackers. |
| `seed` | Complete, uploading. |
| `ratio-done` | Upload ratio reached 3.0; uploading stopped (see [storage.md](storage.md)). |
| `pause` | Paused through the JSON `pause` command (visible in JSON mode only). |

The numeric torrent states (`state` in the JSON stats) are listed in [json-api.md](json-api.md).
