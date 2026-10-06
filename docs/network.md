# Network layer

This document describes how `ntx` moves bytes: the event loop and connection routing, SOCKS5
and the NTX1 tunnel, name resolution over DNS-over-HTTPS, the in-tree TLS client and its
trust model, the shared UDP socket, uTP (BEP 29) and BEP 55 holepunching. The BitTorrent
messages themselves are in [`protocol.md`](protocol.md); options are in [`cli.md`](cli.md).

The code is the source of truth. The modules are in `src/net/` (`ntx_netx.c`, `ntx_sock.c`,
`ntx_proxy.c`, `ntx_tunnel.c`, `ntx_utp*.c`, `ntx_tls*.c`) and `src/proto/` (`ntx_doh.c`,
`ntx_h2.c`, `ntx_https*.c`, `ntx_http.c`, `ntx_holepunch.c`).

## Event loop (`ntx_netx`)

- A single thread runs `epoll` plus a min-heap of timers. `ntx_netx_run_once(timeout_ms)` is
  one iteration.
- Outbound peer connections go through `ntx_netx_route_connect(addr, port, ...)`, which takes
  an `ntx_addr` (IPv4 or IPv6). `ntx_netx_route_connect_tcp` is the same routing without the
  uTP step, used for the TCP retry after a uTP miss.
- HTTP(S) tracker requests, web seeds and DoH lookups are synchronous and block the loop while
  they run (see the limitations in the top-level `README.md`).

## Outbound routing

`route_connect` tries these branches in order and uses the first that yields a connection:

1. **NTX1 tunnel**, if `--tunnel` is set and `ntx_tunnel_ready()` is true: the connection
   becomes a virtual fd inside the tunnel.
2. **uTP**, if `--utp` is on and the address family has a UDP socket (IPv4 and IPv6). With
   `--proxy` the datagrams go through SOCKS5 UDP ASSOCIATE (see below). Only a real uTP
   virtual fd ends this branch; if uTP is unavailable (no socket for that family, connection
   table full, SOCKS5 associate failed) routing continues.
3. **SOCKS5 CONNECT**, if `--proxy` is set.
4. **Raw TCP** (non-blocking).

So `--tunnel` wins over `--proxy` for peer connections.

**The tunnel fails open.** The order is conditional: if `--tunnel` is configured but
`ntx_tunnel_ready()` returns 0 (the tunnel server does not answer, or the handshake has not
finished), `route_connect` falls through to the next branches instead of returning an error.
That is a property of the routing, covered by `t_netx_route.c` (cell B), and it means a
tunnel outage does not cut connectivity. If you need peer traffic to never leave except
through the tunnel, a firewall rule is the reliable way to enforce that.

A failed SOCKS5 UDP ASSOCIATE for uTP falls through to SOCKS5 CONNECT, never to a direct
connection.

**IPv6 (BEP 32).** Raw: `ntx_sock_tcp6` with `ntx_sock_connect_addr`. SOCKS5: address type
`0x04` (16 bytes). Tunnel: `OPEN_V6` (`cmd = 3`, 16 bytes plus port).

## Listening and inbound connections

- TCP is bound on the first free port in `[--port-lo, --port-hi]` (default 6881-6891); if the
  whole range is busy, an ephemeral port is used (`ntx_sock_bind_range`).
- IPv6 listener: a second TCP socket (`ntx_sock_bind6`, `IPV6_V6ONLY = 1`) on the same port
  number if it is free, otherwise on an ephemeral port.
- UDP (DHT and uTP) uses exactly the TCP port number, see [Shared UDP socket](#shared-udp-socket-and-demultiplexing).
- Inbound peers go through the MSE/PE negotiation first. A plain BitTorrent handshake is
  accepted only through the compatibility fallback (`protocol.md`).

## SOCKS5 proxy

- `--proxy=socks5:HOST:PORT` is parsed by `ntx_proxy_parse_spec`. Only the "no authentication"
  method is offered. A malformed value is a fatal error at start-up.
- **Peer TCP** connections use SOCKS5 CONNECT (`route_connect_proxy`; address type 1 for IPv4,
  4 for IPv6). Target host names are resolved locally through DoH first.
- **HTTP(S)** (HTTP and HTTPS trackers, web seeds) use `ntx_http_set_proxy` with the same
  host and port: a blocking SOCKS5 CONNECT of at most 5 seconds. The target is resolved
  locally with `ntx_sock_resolve`.
- **uTP through the proxy** (`--proxy` plus `--utp`): `ntx_utp_route_connect_proxy` opens a
  TCP control connection and performs SOCKS5 UDP ASSOCIATE (RFC 1928, command `0x03`). The
  relay carries each uTP datagram in the RFC 1928 UDP header
  `RSV=0 | FRAG=0 | ATYP | DST.ADDR | DST.PORT | DATA` (`ntx_proxy_udp_encap` / `_decap`;
  fragmented datagrams are dropped). The local UDP socket used to talk to the proxy is
  `AF_INET`, but the destination in the frame can be IPv4 (`ATYP=1`) or IPv6 (`ATYP=4`).
  Tests: `t_socks_udp.c`, `t_proxy.c` and the G2/G2b cells of `t_netx_route.c`.
- **Not proxied:** DoH lookups connect directly to the resolver addresses on port 443; they do
  not use the proxy. UDP trackers and the DHT would bypass it too, so UDP trackers are skipped
  and `--dht` is a fatal error together with `--proxy` or `--tunnel`.

## NTX1 tunnel

`--tunnel=HOST:PORT` forwards peer TCP connections to a tunnel server that speaks `ntx`'s own
NTX1 framing (`ntx_tunnel.c`). It is not a standard protocol, and a compatible server is not
part of this repository.

- **Handshake:** each side sends 32 bytes: the ASCII tag `NTX1` followed by 28 random bytes.
  Both directions' AES-128-CTR keys, counters and the HMAC-SHA1 key are derived from these two
  hello messages.
- **Frames:** `[len (2 B)][payload][HMAC-SHA1 (20 B)]`. The payload is a 2-byte stream id plus
  data, encrypted with AES-128-CTR; the MAC covers the length and the ciphertext. A frame
  carries at most 16384 bytes, and at most 64 streams are open at a time.
- **Opening a stream:** `cmd = 1` (IPv4: 4 bytes plus port), `cmd = 3` `OPEN_V6` (16 bytes plus
  port, big endian), answered by `cmd = 2`.
- Streams appear to the rest of the program as virtual fds `-1 ... -64`.
- **Security note:** because the keys are derived only from values sent in the clear, an
  observer who sees the handshake can derive them. The tunnel hides nothing from an on-path
  attacker and does not authenticate the server. It is a routing mechanism, not a privacy
  guarantee; see [`../SECURITY.md`](../SECURITY.md).
- Only peer TCP uses the tunnel. HTTP(S) requests and DoH lookups do not.

## Name resolution: DoH only

- `ntx_sock_resolve(host)` returns an IP literal (dotted IPv4, IPv6, optionally `[::1]`)
  unchanged, otherwise asks DoH: first an `AAAA` query (`ntx_doh_lookup_aaaa`), then `A`
  (`ntx_doh_lookup_a`) if there is no `AAAA` answer.
- `ntx_sock_resolve4(host)` returns an IPv4 literal or the first DoH `A` record, and never an
  IPv6 address. UDP trackers use it.
- The source tree has no `getaddrinfo` or `gethostbyname`. If every DoH provider fails there
  is **no fallback to the system resolver**.
- Answers are cached: TTL clamped to 60-3600 s, failures for 300 s, 64 entries, `A` and `AAAA`
  kept separately.
- Consequence: the DoH operators see every host name looked up (tracker hosts, web seed hosts,
  DHT bootstrap hosts).

### The resolver pool (`ntx_doh_pins.h`)

The pool has 11 entries for 7 resolvers, tried in this order. The last one that worked is tried
first next time. Policy (from the header): Google and Cloudflare are deliberately not
included. A resolver that serves only TLS 1.3 is still possible now that the TLS client speaks
1.3, but it needs its own SPKI pin and has not been added.

| Tag | Resolver | Addresses |
|-----|----------|-----------|
| `Q9` | Quad9 | 9.9.9.9, 149.112.112.112 |
| `OD` | OpenDNS | 208.67.222.222, 208.67.220.220 |
| `CD` | Control D | 76.76.2.0 |
| `LD` | LibreDNS | 116.202.176.26 |
| `UC` | UncensoredDNS | 91.239.100.100, 89.233.43.71 |
| `OB` | OpenBLD | 45.144.49.133 |
| `DP` | DNSPod (`doh.pub`) | 120.53.53.53, 1.12.12.12 |

Transport: connect to the literal IP on port 443, TLS (1.3 first, fallback to 1.2) with ALPN
`h2` / `http/1.1` and the entry's SNI, verify the SPKI pin, then send an RFC 8484 `POST` of an
`application/dns-message` body, over HTTP/2 (`ntx_h2.c`) when negotiated, otherwise HTTP/1.1.
A pin failure moves on to the next entry. The status line shows the provider tag
(`dnsQ9`, `dns..Q9` while a lookup runs, `dns!` if all fail, `dns!UC` after a pin mismatch;
see [`cli.md`](cli.md)).

### Pin rotation (DoH pool)

Each pool entry is a pin *set*: `npins` keys out of `NTX_DOH_PIN_MAX` (8) slots. A connection is
accepted if the leaf SPKI matches **any** active key, and an all-zero slot never matches. A
single compiled-in pin would turn a provider's key rotation into a DoH outage for every
installed binary until a new release, so old and new keys are kept side by side. For
example UncensoredDNS carries 6 pins for its anycast backends (an RSA and an ECDSA leaf each).

To add a rotated key for a provider:

1. Fetch the new leaf:
   ```
   openssl s_client -connect HOST:443 -servername HOST </dev/null 2>/dev/null \
     | openssl x509 -outform DER > leaf.der
   ```
2. Compute the pin: `python3 test/scripts/pin_from_der.py leaf.der` (64 hex digits).
3. In `ntx_doh_pins.h` put the new pin in the first free slot (`pins[npins]`, then
   `npins++`).
4. Keep the old key in the set for at least one release, and remove it later (set the slot to
   zero, `npins--`).

Checks: `make probe` builds `trk_http_probe`, which resolves tracker hosts through the DoH
pool (a pin failure shows as an error on every host). Pin-set behaviour is covered by
`t_tls_pin.c` (match on key 0 and key 1, no match gives `NTX_TLS_PIN_FAIL`, an all-zero slot
never matches). [`../pins.txt`](../pins.txt) lists the same provider pins in the pin-file
format.

## TLS client

`ntx_tls.c`, `ntx_tls13.c` and `ntx_tls_rec.c` implement the client used for DoH and for HTTPS
trackers and web seeds. Peer traffic is never TLS.

`ntx_tls_handshake_ex` tries **TLS 1.3 first** and falls back to TLS 1.2. The build option
`-DNTX_TLS13_LIVE=0` produces a TLS 1.2-only client.

- **TLS 1.3 (RFC 8446).** Cipher suite `TLS_AES_128_GCM_SHA256` (`0x1301`), key share X25519,
  signature algorithms `ecdsa_secp256r1_sha256` (`0x0403`) and `rsa_pss_rsae_sha256`
  (`0x0804`). The ClientHello carries a `legacy_session_id` (middlebox compatibility, one
  change-cipher-spec after the ServerHello), `supported_versions` and ALPN. After the
  handshake it handles `KeyUpdate`, `NewSessionTicket` (ignored, no resumption) and
  `close_notify`.
  Not supported: PSK and resumption, 0-RTT, HelloRetryRequest (treated as a fallback trigger)
  and client certificates (a `CertificateRequest` fails the handshake).
- **Fallback to 1.2.** A ServerHello without `supported_versions`, a HelloRetryRequest, or an
  alert or EOF in the first flight closes the connection and reconnects to the same address
  with a TLS 1.2 handshake.
- **TLS 1.2.** Suites `0xC02F` (ECDHE-RSA-AES128-GCM-SHA256) and `0xC02B`
  (ECDHE-ECDSA-AES128-GCM-SHA256); the server key exchange must use X25519; signature
  algorithms ECDSA-P256-SHA256 and RSA-PKCS1-SHA256.
- **ALPN:** DoH offers `h2` and `http/1.1`; HTTPS trackers and web seeds offer `http/1.1`.

How the TLS 1.3 code is tested: key schedule and record vectors from an independent Python
reference (`test/scripts/tls13_ref.py`, `test/vectors/tls13/kat.txt`, `t_tls13.c`); recorded
server flights in `test/fixtures/tls/` replayed by `t_tls_golden.c` (12 scenarios, including
ECDSA and RSA-PSS, coalesced and fragmented messages, `KeyUpdate`, bad `Finished`,
`CertificateVerify` and record tags, and `CertificateRequest`); and `make test-tls13`, which
runs the real client against `openssl s_server` on loopback (ECDSA and RSA certificates,
pin match and mismatch, `KeyUpdate`, fallback to 1.2; it is skipped when the `openssl` CLI is
missing). Interoperability with public servers is not part of the automated tests.

### Trust model: SPKI pins, not CAs

The client has **no CA store** and does not validate certificate chains or host names. Trust is
decided by the SHA-256 hash of the leaf's SubjectPublicKeyInfo (the *pin*, 32 bytes), checked
before any application data is sent. The pin sources, in order (the first source that has a
pin for the host wins; sources are not combined):

1. The built-in pool: the DoH providers above plus one test entry for `127.0.0.1`. A host in
   the pool can use up to 4 pins (`NTX_HTTPS_PIN_MAX`) for HTTPS.
2. A pin file given with `--https-pin-file=PATH`: one `<host> <64 hex digits>` per line, `#`
   comments allowed. `host` is an exact name or `*.example.com` (matches sub-domains but not
   the apex). The community file [`../pins.txt`](../pins.txt) uses exact hosts only.
3. **TOFU** (trust on first use), on by default: the first connection to a host with no pin
   stores the leaf pin in `<store>/https_tofu.bin` (at most 32 hosts, least recently used
   evicted, file mode `0600`, written atomically). Every new pin is printed on stderr
   (`ntx: TOFU new pin: <host> (spki=...)`); an eviction goes to the diagnostic log.
   `--no-https-tofu` turns this off.

If no pin exists and TOFU is off, the connection is refused before any byte is sent. An
attacker present on the very first TOFU connection is not detected. A pin mismatch
(`NTX_TLS_PIN_FAIL`) aborts the session; for DoH the next pool entry is tried.

### HTTP(S) requests

`ntx_https.c` resolves the host, connects, checks the pin, runs TLS and then speaks HTTP/1.1.
The same code path is used by `ntx_http.c` for `https://` URLs (web seeds and HTTPS trackers).

- Connect and I/O timeouts are 5 seconds each for plain HTTP; the TLS handshake uses a 15
  second I/O timeout.
- Only status `200` and `206` are accepted; **redirects are not followed**. The body is read by
  `Content-Length` or `Transfer-Encoding: chunked` (malformed chunk framing is an error).

## Shared UDP socket and demultiplexing

`ntx_netx` owns one UDP socket per address family on the same port number as the TCP listener
(`udp4_fd`, and `udp6_fd` bound to `[::]` with `IPV6_V6ONLY = 1`), registered on the event loop with
one handler, `udp_demux_handler`. The two families are bound independently and fail soft: if
IPv6 is unavailable or the port is taken, IPv6 uTP is off and IPv4 is unaffected, and the
reverse.

Each datagram is classified by its first byte with the pure function `ntx_udp_classify`:

| First byte | Class |
|------------|-------|
| `d` (`0x64`), `l` (`0x6c`) or `i` (`0x69`) | DHT (bencode, BEP 5) |
| high nibble 0-4 **and** low nibble 1 | uTP (packet type 0-4, version 1) |
| anything else, including an empty datagram | dropped |

The sets cannot overlap: a bencode byte such as `0x64` would be uTP type 6, version 4. The
counters `demux_dht`, `demux_utp` and `demux_drop` add up to the number of datagrams
received; a uTP-shaped datagram with no uTP engine counts as dropped. Test vectors:
`test/vectors/utp/demux_classify.bin`; tests: `t_utp_demux.c`, `t_netx_shared.c`.

If the IPv4 UDP port cannot be bound, the shared owner is absent: uTP is off and the DHT opens its
own socket (the verbose log prints `shared udp :PORT busy`). The DHT's IPv6 socket is always its own,
bound to an ephemeral port.

An IPv4-mapped IPv6 address is normalised to IPv4 (`ntx_addr_from_sockaddr`), and because the
IPv6 sockets are `V6ONLY`, a v4 peer is only ever seen on `udp4_fd`.

## uTP (BEP 29)

An alternative peer transport over UDP. Code: `ntx_utp.h` (API), `ntx_utp_hdr.c` (header,
SACK and extensions), `ntx_utp_cc.c` (congestion control), `ntx_utp_sm.c` (connection state
machine) and `ntx_utp.c` (UDP glue, demultiplexing and virtual fds). Test vectors are in
`test/vectors/utp/` (generated by `test/scripts/utp_header.py`).

### Enabling it and the TCP fallback

- `--utp` (default **off**). Without it, outbound peer connections are TCP only. With it,
  outbound connections are tried over uTP first (IPv4 and IPv6) and inbound uTP connections
  are accepted on the shared UDP sockets.
- **TCP fallback.** Most peers in a public swarm have no uTP stack, so a uTP dial that has not
  connected within `NTX_UTP_DIAL_MS` (1.5 s) is retried over TCP
  (`ntx_netx_route_connect_tcp`; the drop path calls `ntx_session_add_peer_dial_tcp`). A uTP
  miss is not written to the redial back-off table (`ntx_dial_bo.h`), whereas a failed TCP
  attempt is. After `NTX_UTP_GIVEUP_MISSES` (40) uTP misses in a session without a single uTP
  peer ever becoming established (UDP filtered, or a swarm without uTP), the session stops
  trying uTP first and dials TCP directly. The fallback does not apply with `--tunnel`.
  Test: `t_session_utp_fallback.c`.

### Wire format

- 20-byte header, all fields big endian (`ntx_utp_hdr.c`); packet type in the high nibble,
  version 1 in the low nibble. Types `ST_DATA`, `ST_FIN`, `ST_STATE`, `ST_RESET`, `ST_SYN`
  are 0-4.
- Extension chain `(type, len, data)` ending with `(0, 0)`. The selective ACK (SACK) is
  extension type 1: the mask length is a multiple of 32 bits, the first bit stands for
  `ack_nr + 2` (`ack_nr + 1` is implicitly missing), and within a byte the least significant
  bit is the lower sequence number. The parser accepts masks up to 2048 bytes; the sender
  produces 16 bytes (128 packets).

### Congestion control, timeouts and loss

- **Congestion control** (`ntx_utp_cc.c`, BEP 29 section on congestion control): delay based,
  in the LEDBAT style. The target delay is 100 ms (`NTX_UTP_TARGET_DELAY_US`), the base delay is
  the minimum over a window of 120 samples, window growth is limited to 3 packets per RTT
  (`NTX_UTP_MAX_CWND_INC_PER_RTT`), and the arithmetic is Q16 fixed point.
- **Retransmission timer** (`ntx_utp_sm.c`): initial timeout 1000 ms, floor 500 ms
  (`timeout = max(rtt + 4 * rtt_var, 500)`), doubling on consecutive timeouts up to 8000 ms.
  `rtt_var` is updated only from packets that were sent once. On a timeout the packet size and
  the window are both set to 150 bytes (`NTX_UTP_MIN_PKT`) and a single probe packet is sent.
- **Loss:** three duplicate ACKs, or at least three ACKs beyond the oldest unacknowledged
  packet (also via SACK), halve the window and retransmit.
- **Connection setup:** the SYN carries `conn_id` equal to the initiator's receive id, and its
  send id is `conn_id + 1`. The acceptor answers with `ST_STATE`, which does not consume a
  sequence number. An in-order `ST_DATA` is acknowledged with a bare `ST_STATE` (no payload, no
  extensions) when there is nothing to piggyback on. Progress resets the timeout ladder.

### UDP glue (`ntx_utp.c`)

- The glue runs on the sockets owned by `ntx_netx` (see above), so TCP and UDP share one port
  number for both transports and both families. `ntx_netx` creates the uTP engine only when its
  shared IPv4 socket exists; IPv6 is added when the IPv6 socket exists. (`ntx_utp_listen` also
  has a standalone mode that binds its own sockets; the command-line client does not use it and
  only the tests do.)
- The send socket is chosen by the peer's address family. Without a socket for that family,
  `ntx_utp_route_connect` returns -1 and routing falls through to proxy or raw TCP.
- Connections are looked up by `(peer address, peer port, conn_id)` in a table of
  `NTX_UTP_MAX_CONNS` (64) slots with a 64 KiB receive buffer each (bytes that do not fit are
  dropped).
- **Half-open protection.** An inbound SYN costs a slot and is unauthenticated (UDP source
  addresses can be spoofed). Until the peer's first `ST_DATA` the slot is half-open: at most
  `NTX_UTP_MAX_HALFOPEN` (32) in total and `NTX_UTP_MAX_HALFOPEN_PER_SRC` (8) per source address,
  and each is reaped after `NTX_UTP_HALFOPEN_MS` (10 s). The accept callback fires on the first
  `ST_DATA`, which carries the BitTorrent (or MSE) handshake. Test: `t_utp_halfopen.c`.
- **Virtual fds.** A uTP connection is exposed as the negative number
  `-(NTX_UTP_VIRT_BASE + slot)` with `NTX_UTP_VIRT_BASE = 1000`, which cannot collide with the
  tunnel's `-1 ... -64`. `ntx_netx_read`, `_write` and `_peer_connected` dispatch on it before the
  tunnel; the session's read/write callbacks are attached to the glue slot, and the slot is
  released when the peer is freed.
- `ntx_netx.c` reaches `ntx_utp_*` and `ntx_dht_input` through weak symbols, so test programs
  that do not link those modules still build.

### Documented deviations

The header comment of `ntx_utp_sm.c` is the authoritative list. The main points:

- The acceptor's initial sequence number is derived deterministically from the SYN rather than
  random; the initial window is 4096 bytes and the initial data size 1200 bytes; at most 128
  packets are tracked in flight; the send queue is capped at 1 MiB.
- Out-of-order `ST_DATA` is kept in a reorder window of 128 packets (payload at most 1200 bytes)
  and delivered in order once the gap is filled; anything outside the window or when the
  buffer is full is dropped and recovered by the sender's loss path. The SACK mask is kept in step
  with the buffer, so SACK never acknowledges data that we do not hold.
- A FIN that arrives ahead of a gap is remembered and the close waits until the gap is
  filled and delivered.
- The outgoing `timestamp_difference` field is always 0 (one-way delay of the peer's packets is
  not echoed); the congestion controller uses the incoming value.
- An `ST_SYN` that repeats an already-accepted SYN is answered with `ST_STATE`; a SYN that
  collides with a live connection is treated as an error.
- Packet sizes after a timeout stay at the 150-byte floor until congestion control has raised
  the window back to the initial chunk size.

### IPv6

IPv6 uses the same machinery through the second shared socket: the IPv6 sibling binds the same
port number as the TCP listener, a v6 peer needs no second port, and v4 and v6 failures are
independent. Dialling a v6 peer without a v6 socket falls back to TCP. An address of an
unknown family is refused. With a proxy, the SOCKS5 UDP frame carries `ATYP = 4`. Tests use
the real `::1` loopback; if the host cannot bind it they print `SKIP` and assert nothing
(`t_utp_loopback.c`, `t_utp_net.c`, `t_netx_shared.c`, `t_netx_route.c`).

### Testing and interoperability

Unit and loopback tests: `t_utp_hdr.c`, `t_utp_cc.c`, `t_utp_sm.c`, `t_utp_loopback.c`,
`t_utp_net.c`, `t_utp_halfopen.c`, `t_utp_demux.c`, `t_utp_bt_handshake.c` (two `ntx --utp`
sessions reach the established state and exchange data) and `t_netx_route.c`.

`test/interop/utp/interop_utp.sh` is a manual interoperability harness, not part of CI. At the
wire level a raw BEP 29 peer written from the specification (`utp_probe.py`, not derived from
`ntx_utp*.c`) opens connections in both directions, pushes data and SACKs, and exercises loss
and reordering (with `tc netem` when the process has `CAP_NET_ADMIN`, otherwise through a
userspace relay `utp_relay.py`, labelled as such), FIN, RESET and a bytes-in equals bytes-out
accounting check. At the engine level it is designed to run a container with rtorrent and
qBittorrent-nox as seeders; that part is skipped when the engines do not start head-less or
Docker is unavailable, and skipped cells are reported as skipped. A download over `--utp`
against a public swarm has been performed by hand; no third-party uTP seeder is part of the
automated checks (see the limitations in the top-level `README.md`).

## Holepunch (BEP 55)

`ut_holepunch` is a BEP 10 extension (`NTX_EXT_LOCAL_HOLEPUNCH = 3`) that is **advertised only
when `--utp` is on**, because the `connect` message drives a uTP dial. `ntx_holepunch.c` is a pure
module (no I/O, no session) that holds the codec and the decision functions, so they are unit
tested without sockets. Test: `t_holepunch.c`.

### What the session does

- It **receives `connect`** from a relay peer and dials the given endpoint over uTP
  (`ntx_session_holepunch_on_rx` -> `ntx_session_add_peer_dial_ex` with back-off bypassed).
- It ignores a `connect` when uTP is off or when it already has a connection to that endpoint,
  and does not send an error to the relay in that case.
- It counts `error` and `rendezvous` messages and otherwise ignores them.
- It does **not** send `rendezvous` requests and does **not** act as a relay: the
  relay-side decision function below is implemented and tested, but nothing in the session
  calls it.
- When both peers dial each other and both connections succeed, the session keeps exactly one
  (see Race below).

### Payload (after the BEP 10 extended header)

```
msg_type  (1 B): 0x00 rendezvous | 0x01 connect | 0x02 error
addr_type (1 B): 0x00 IPv4 | 0x01 IPv6
addr      (4 B or 16 B)
port      (2 B, big endian)
err_code  (4 B, big endian; 0 in non-error messages)
```

Total payload: 12 bytes (IPv4) or 24 bytes (IPv6). Error codes: 1 `NoSuchPeer`, 2
`NotConnected`, 3 `NoSupport`, 4 `NoSelf`. `ntx_holepunch_build` and `_parse` reject a short
payload, an unknown `msg_type` or `addr_type`, an address length that does not match
`addr_type`, a non-zero `err_code` in a non-error message, and a zero or unknown code in an
error. `ntx_holepunch_build_error` echoes `addr_type`, `addr` and `port` of the rendezvous
exactly, as BEP 55 requires.

### Policy functions

| Relay input (`ntx_holepunch_relay_policy`) | Result |
|---|---|
| initiator did not advertise `ut_holepunch` | ignore |
| the two peers are already connected | ignore |
| the relay itself is the target | error `NoSelf` |
| the relay has no connection to the target | error `NoSuchPeer` |
| the target did not advertise `ut_holepunch` | error `NoSupport` |
| connected to the target and the target advertises it | `connect` to both |

`ntx_holepunch_target_policy`: a peer that receives a `connect` it does not want ignores it
and must not return an error to the relay; otherwise it dials.

**Race.** If both uTP dials succeed, `ntx_holepunch_race_winner(our_id, their_id)` decides
deterministically which one survives: the peer with the lexicographically lower `peer_id` keeps
the connection it dialled, the other keeps the one it accepted, which is the same physical
connection, so both sides agree. The check runs when a peer reaches the established state
(`sp_promote_peer_ok` -> `ntx_session_holepunch_resolve_race`) and drops the loser with the
reason `bep55-race`. Two connections in the same direction are not treated as a race.

### Counters

`hp_rx_connect`, `hp_rx_error`, `hp_rx_rendezvous`, `hp_dial_ok`, `hp_dial_fail` and
`hp_race_dropped` live in the session. The `punch_ok` / `punch_fail` pair in the JSON stats
([`json-api.md`](json-api.md)) is `hp_dial_ok` / `hp_dial_fail`: `punch_ok` means a dial was
**started** after a `connect`, not that the peer handshake succeeded; `punch_fail` means the
dial was refused before it started (duplicate, connection limits, allocation failure, no
route). Whether the peer actually came up is visible in the normal peer counts.

## Limitations

| Not available | Note |
|---------------|------|
| DNS over TLS (port 853) | not implemented |
| System DNS fallback | deliberately absent |
| TLS PSK/resumption, 0-RTT, client certificates | not implemented |
| Certificate chain and host name validation | not implemented; SPKI pins and TOFU are used instead |
| Redirects for HTTP(S) requests | not followed |
| UPnP, NAT-PMP, Local Service Discovery | not implemented; see [`roadmap.md`](roadmap.md) |
| BEP 55 relay role, sending `rendezvous` | not implemented |
