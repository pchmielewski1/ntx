# Golden wire fixtures

Frozen wire captures for replay tests. A replay test feeds the bytes of a `.bin` file through the real parser or handshake code and compares the result with the expectations in the matching `.meta.json`. Nothing here touches the network.

All fixtures are synthetic: they are built offline from the documented wire formats (see [`docs/protocol.md`](../../docs/protocol.md)), not captured from real peers, trackers or servers. Addresses are in the documentation ranges (`192.0.2.0/24` from RFC 5737 and `2001:db8::/48`); IDs, tokens, counters and ports are fixed constants.

## Layout

```
test/fixtures/announce/  <name>.bin + <name>.meta.json
test/fixtures/dht/       <name>.bin + <name>.meta.json
test/fixtures/pe/        <name>.bin + <name>.meta.json
test/fixtures/tls/       <name>.bin + <name>.meta.json
```

- `<name>.bin` is the raw byte stream: a bencoded tracker or DHT response, a peer-wire stream, or the bytes a TLS server sends.
- `<name>.meta.json` is a JSON sidecar with these keys:
  - `name`: fixture name, equal to the file base name.
  - `source`: where the bytes come from (the wire format, or the generator script for TLS).
  - `date`: freeze date, a fixed string.
  - `scrub_notes`: a statement that the fixture contains no real data.
  - `expected`: what the replay test must observe. The contents depend on the protocol (for example `interval`/`seeders`/`peers4` for announces, `id`/`nodes`/`values` for DHT, `handshake`/`messages` for peer wire, `outcome` and keys for TLS).
  - `client` (TLS only): the fixed client inputs (`sni`, `alpn`, `client_priv_hex`, `client_random_hex`) and the SHA-256 of the expected ClientHello (`ch_sha256_hex`).

## Fixtures

| Fixture | Content | Replay test |
|---------|---------|-------------|
| `announce/http_announce_list` | HTTP announce response: bencoded dictionary with a non-compact `peers` list and compact `peers6` (BEP32) | `test/t_golden_announce.c` |
| `announce/http_announce_compact` | HTTP announce response with a compact `peers` string | `test/t_golden_announce.c` |
| `dht/get_peers_response` | DHT `get_peers` response: `id`, `token`, `values`, `values6`, `nodes`, `nodes6` | `test/t_golden_dht.c` |
| `dht/find_node_response` | DHT `find_node` response: `id`, `nodes`, `nodes6` | `test/t_golden_dht.c` |
| `pe/bt_exchange` | 68-byte BitTorrent handshake (BEP10 bit set), then keep-alive, interested, bitfield, choke and further messages | `test/t_golden_pe.c` |
| `tls/tls13_*` | Server streams for the TLS 1.3 client. Success cases: `tls13_ecdsa_ok`, `tls13_ecdsa_coalesced`, `tls13_rsa_pss_ok`, `tls13_rsa_fragmented`, `tls13_no_alpn`. Failure cases: `tls13_bad_certverify`, `tls13_bad_finished`, `tls13_bad_record_tag`, `tls13_cert_context`, `tls13_certificate_request`, `tls13_pin_mismatch`, `tls13_unoffered_sigalg` | `test/t_tls_golden.c` (`make test-live` or `make test`) |

The `tls/` fixtures replay a recorded server stream over a socketpair into the production handshake code with fixed client keys. The test checks the outcome, protocol version, ALPN, the leaf SPKI pin, the application traffic secrets and application data, and that the client's own ClientHello hashes to the frozen value.

## Regenerating

```sh
python3 test/scripts/gen_fixtures_announce_dht_pe.py   # announce/, dht/, pe/ (deterministic)
python3 test/scripts/tls13_ref.py                      # tls/ and test/vectors/tls13/ (needs the `cryptography` package)
```

The first script is deterministic: re-running it produces identical files. `tls13_ref.py` deletes and rewrites every file in `tls/` and rewrites `test/vectors/tls13/kat.txt`; the certificates and keys in `test/vectors/tls13/` are its inputs. The output is not byte-for-byte reproducible because the CertificateVerify signatures are randomised. See [`test/scripts/README.md`](../scripts/README.md).

Tests read fixtures with paths relative to the repository root, so run them from there.
