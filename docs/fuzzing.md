# Fuzzing and the crypto freeze

## Fuzzing

There are four libFuzzer harnesses in `test/fuzz/`. They cover the parsers that handle bytes from the network. There is no `make` target for fuzzing; the only entry point is the runner script `test/fuzz/run_fuzz.sh`.

| Harness | Entry points exercised | Input |
|---------|------------------------|-------|
| `test/fuzz/fuzz_bencode.c` | `ntx_be_parse` (depth limit 32, size limit 1 MiB) and `ntx_be_free` | raw bencoded bytes |
| `test/fuzz/fuzz_tracker.c` | UDP tracker: `ntx_tracker_udp_connect_parse`, `ntx_tracker_udp_announce_parse_ex`, `ntx_tracker_peer_parse_compact`, `ntx_tracker_peer_parse_compact6`; HTTP: `ntx_tracker_http_parse_ex`; DNS wire: `ntx_doh_parse_response_a`, `ntx_doh_parse_response_aaaa` | UDP, HTTP or DNS response bytes |
| `test/fuzz/fuzz_dht.c` | `ntx_dht_msg_parse` (KRPC view), `ntx_dht_msg_parse_nodes`, `ntx_dht_msg_parse_nodes6`, `ntx_dht_msg_parse_values`, `ntx_dht_msg_parse_values6` | a DHT packet or a compact node/peer blob |
| `test/fuzz/fuzz_http.c` | `ntx_http_url_parse`, `http_parse_ipv4`, and, for input that is valid bencode, `http_parse_dict` / `http_parse_dict_ex` (tracker reply dictionary) | a URL string or a bencoded dictionary |

Not covered by any harness: magnet URIs, BitTorrent peer messages, BEP10/BEP9/BEP11/BEP52 payloads, MSE/PE, TLS records and handshake messages, uTP packets and the JSON control channel. Some of these have deterministic hostile-input tests in the unit suites (see [testing.md](testing.md)).

Notes:

- Every harness `#include`s the `.c` files it needs (the tracker and HTTP harnesses pull in the TLS and crypto sources too, because the parsers live next to them), like the unit tests do, so each builds with a single compiler command.
- The harnesses keep no state between calls: outputs are locals and the bencode tree is freed each iteration.
- `fuzz_tracker.c` does not include `src/net/ntx_sock.c`. That file defines weak DoH stubs that would collide with the real definitions from `ntx_doh.c` inside one translation unit, so the harness provides six link-only stubs for the socket functions instead (`ntx_sock_tcp4`, `ntx_sock_tcp6`, `ntx_sock_connect_addr`, `ntx_sock_resolve`, `ntx_sock_tcp_connect_host`, `ntx_sock_local_port`). The parsers under test never call them.

### Running

```sh
test/fuzz/run_fuzz.sh
```

The script, from the repository root:

1. Detects a toolchain: first `cc -ffuzz-target -fsanitize=address,undefined`, then `clang -fsanitize=fuzzer,address,undefined`. If neither works it prints a `TOOLCHAIN:` message, skips the fuzzing and exits 0. In practice you need `clang` with the libFuzzer runtime.
2. Creates the seed corpus under `test/fuzz/corpus/<name>/` (`bencode`, `tracker`, `dht`, `http`) by copying vectors from `test/vectors/bencode/` and `test/vectors/doh/` and generating the rest (UDP tracker replies, a DHT query and response, a URL, a tracker dictionary) with `python3`.
3. For each of the four targets, builds the harness with `-O1 -g -std=c11 -Wall -Wextra -D_POSIX_C_SOURCE=200809L` plus the sanitizer flags (no `-Werror`) and runs it for 60 seconds with `-corpus=test/fuzz/corpus/<name> -max_len=4096 -timeout=5`.
4. Prints `OK [name]: no crash, ...` or `CRASH [name]` with the artifact path and a hex dump of the first bytes. The script does not change its exit status on a crash, so read its output.

Build products, logs and crash artifacts go to `test/.scratch/` (a gitignored scratch directory): the binaries `fuzz_<name>`, the logs `fuzz_<name>.log`, and crash files `fuzz_<name>_crash-*`.

libFuzzer writes newly found interesting inputs into the corpus directory, so a run can add files to `test/fuzz/corpus/` in your working tree. Commit them only if you want them as permanent seeds.

For a longer session, run a built binary directly, for example:

```sh
timeout 3600 test/.scratch/fuzz_dht -corpus=test/fuzz/corpus/dht -max_len=4096 -timeout=5
```

## Crypto freeze

The project implements its cryptography itself, and none of it has been independently reviewed (see [`SECURITY.md`](../SECURITY.md)). To keep that risk visible, the following rule applies:

**Every change under `src/crypto/` is a review event.**

1. Have the change reviewed by someone other than its author before it is merged.
2. Start the commit message with `crypto:` (for example `crypto: constant-time tag comparison in GCM`), so such commits can be found with `git log --grep '^crypto:'`.
3. Back the change with a test: a known-answer vector produced by an independent implementation where possible (the generator scripts are in `test/scripts/`, see [`test/scripts/README.md`](../test/scripts/README.md)).

The rule is a project convention; no tooling enforces it.

Files covered, with the suites that exercise them (all suites are listed in [testing.md](testing.md)):

| File | Contents | Tests |
|------|----------|-------|
| `src/crypto/ntx_sha1.c` | SHA-1 | `t_sha1.c` |
| `src/crypto/ntx_sha256.c` | SHA-256 | `t_sha256.c` |
| `src/crypto/ntx_hmac.c` | HMAC-SHA1 / HMAC-SHA256 | `t_hmac.c`, `t_hmac_sha256.c`, `t_mac_kat.c` |
| `src/crypto/ntx_hkdf.c` | HKDF-SHA256 | `t_hkdf.c`, `t_mac_kat.c` |
| `src/crypto/ntx_aes.c` | AES-128, CTR, GCM | `t_aes.c`, `t_aes_gcm.c`, `t_aes_kat.c` |
| `src/crypto/ntx_rc4.c` | RC4 (MSE/PE) | `t_rc4.c` |
| `src/crypto/ntx_rng.c` | RNG (`/dev/urandom`) | `t_rng.c` |
| `src/crypto/ntx_x25519_fe.c`, `src/crypto/ntx_x25519.c` | X25519 | `t_x25519.c` |
| `src/crypto/ntx_bignum.c` | big integers, Montgomery core | `t_bignum.c` |
| `src/crypto/ntx_p256.c` | P-256 ECDSA verify, SPKI parsing | `t_p256_ecdsa.c`, `t_p256_kat.c` |
| `src/crypto/ntx_rsa_pkcs1.c` | RSA PKCS#1 v1.5 and PSS verify | `t_rsa_pkcs1.c`, `t_rsa_pkcs1_kat.c`, `t_rsa_pss.c` |
| `src/crypto/ntx_dh.c` | 768-bit DH (MSE/PE) | `t_dh_kat.c` |

The headers in `src/crypto/` (including the header-only `ntx_ct.h`) are covered by the same rule.
