# Security policy

## Status of this project

`ntx` is a **hobby / learning project**. It contains hand-written implementations of
SHA-1/256, HMAC, HKDF, AES-GCM, RC4, X25519, P-256 ECDSA, RSA PKCS#1 v1.5 / PSS verification,
768-bit DH (BitTorrent MSE/PE) and a TLS 1.3 / 1.2 client. None of this has been reviewed by an
independent cryptographer, and none of it has the years of scrutiny that OpenSSL,
BoringSSL or libsodium have. **Do not use `ntx` to protect anything you could not afford to
lose**, and do not copy its crypto into other projects.

What the project does to keep its own risk down: RFC/NIST test vectors for the primitives,
independent Python reference scripts for derived values (`test/scripts/`), libFuzzer
harnesses for the wire parsers (`docs/fuzzing.md`), a hardened build (PIE, RELRO, stack
protector, fortify), a sanitizer sweep of all suites, and a "crypto freeze" (every change under
`src/crypto/` is treated as a review event).

## Review items

Tracked in this document: a self-review of the crypto code raised eight items (R1-R8). All of
them have been **addressed in code and tests**; "addressed" means the specific weakness is
closed or its contract is enforced, not that the primitive has been independently audited.

| # | Item | Resolution | Where |
|---|------|------------|-------|
| R1 | ECDSA verify did not check that the public key lies on the curve | **fixed**: `ntx_p256_point_on_curve` (y² = x³ − 3x + b, coordinates < p) is part of verify; tests with off-curve and out-of-range points in `test/t_p256_ecdsa.c` | `src/crypto/ntx_p256.c` |
| R2 | Short `read()` from `/dev/urandom` treated as a full refill | **fixed**: the pool is refilled until all 256 bytes are fresh; `test/t_rng.c` | `src/crypto/ntx_rng.c` |
| R3 | DH: variable-time exponentiation with a secret exponent; prime provenance unverified | **fixed**: the shared Montgomery (CIOS) core's `ntx_mont_exp_ct` - square-and-always-multiply with masked selection, no secret-dependent branches or indexing in the C source; the 768-bit prime is the one from the MSE specification and is checked by `test/scripts/dh_kat.py` | `src/crypto/ntx_dh.c`, `ntx_bignum.c` |
| R4 | AES-GCM nonce uniqueness was left to the caller | **fixed**: contract documented in `ntx_aes.h`; the TLS 1.2 and TLS 1.3 record layers consume the sequence number before sending and refuse to wrap it (`test/t_tls_rec_nonce.c`, `test/t_tls13.c`) | `src/crypto/ntx_aes.h`, `src/net/ntx_tls_rec.c`, `src/net/ntx_tls13.c` |
| R5 | X25519 did not reject low-order points | **fixed**: `ntx_x25519` returns −1 for an all-zero shared secret (RFC 7748 §6.1 / RFC 8446 §7.4.2); both TLS key exchanges abort on it; vectors in `test/t_x25519.c` | `src/crypto/ntx_x25519.c` |
| R6 | `ntx_rc4_init` with key length 0 divided by zero | **fixed**: init returns an error and the stream refuses to produce output for an invalid key (`test/t_rc4.c`) | `src/crypto/ntx_rc4.c` |
| R7 | Timing hygiene of the old wide modular reduction (`bn_mod_wide`, since replaced by the Montgomery core), field adds and RSA padding comparison | **hardened**: PKCS#1 padding is compared in one pass without early exit, P-256 `fe_add` uses a masked conditional subtraction; `ntx_bn_modexp` is documented as **not** constant-time and is used with public values only (signatures, public moduli); secret exponents (DH) use `ntx_mont_exp_ct` | `src/crypto/ntx_bignum.[ch]`, `ntx_p256.c`, `ntx_rsa_pkcs1.c` |
| R8 | DH had no independent known-answer test | **fixed**: 89 vectors computed with Python big integers (`test/scripts/dh_kat.py` → `test/vectors/dh/kat.txt`, run by `test/t_dh_kat.c`) | `test/t_dh_kat.c` |

### Second review pass (primitives and TLS 1.2)

A line-by-line review of every primitive and the TLS 1.2 client found the following; each was
fixed test-first (the test failed on the old code, then passed), with vectors produced by
independent Python (`cryptography`, `hmac`, big-integer `pow`) under `test/vectors/`.

| Area | Finding | Fix |
|------|---------|-----|
| Bignum / RSA / P-256 | Verification used bit-serial long division: RSA-2048 verify 246 ms, P-256 verify 1.5 s | one Montgomery (CIOS) core for everything (RSA, P-256, DH): 0.26 ms and 23 ms. The slow division path is gone; an even or tiny modulus now fails closed (all-zero result). `ntx_bn_modexp` is still **not** constant-time (public values only); DH uses the constant-time `ntx_mont_exp_ct` |
| P-256 SPKI | Parser ignored the curve OID and accepted trailing bytes (P-384, secp256k1, wrong OIDs parsed as P-256) | exact AlgorithmIdentifier match and exact length |
| RSA verify | `e = 1` or even `n` makes the PKCS#1 encoding trivially "verify" (forgery with a hostile key) | `n` and `e` must be odd, `e ≥ 3`, in PKCS#1 and PSS |
| AES-GCM | Decrypted before authenticating; no in-place support; table-driven GHASH / MixColumns (data-dependent timing); 7.5 MB/s | verify-then-decrypt (nothing written on failure), in-place, constant-time GHASH and MixColumns, message limit 2^36−32 B, 128 MB/s. The S-box is still a table: **not cache-timing safe** |
| HKDF / TLS 1.2 PRF | `malloc` per call, arbitrary 100-byte and label limits that failed silently | incremental HMAC with a copyable keyed context, no allocation, RFC 5869 limit enforced, keys wiped |
| RNG | Served bytes stayed in the pool buffer | wiped after use |
| TLS 1.2 | No downgrade-sentinel check; server flight accepted in any order and duplicated; non-empty ServerHelloDone and trailing data accepted; Finished compared with `memcmp`; record version unchecked; `rsa_from_spki` ignored the key algorithm OID; secrets cleared with a `memset` the compiler may drop | `DOWNGRD` check (when 1.3 is enabled), strict SH→Cert→SKX→SHD order, constant-time Finished compare, record major version 3, rsaEncryption OID, `ntx_wipe` (`src/crypto/ntx_ct.h`) |
| X25519 | scalar and ladder state left on the stack | wiped |

DH no longer carries a private Montgomery copy: `ntx_dh.c` is down to the prime, key validation
and calls into the shared core (all 89 independent DH vectors still pass; DH key generation
0.19 -> 0.23 ms).

Deliberately **not** changed: P-256 field arithmetic (23 ms per verify is fine and the code
is vector-tested), RC4 (inherent to MSE/PE), TLS 1.2 Extended Master Secret (RFC 7627) and
strict-DER ECDSA signature parsing.

DH secret lifetime: `ntx_dh_compute_secret` is one-shot - it wipes the exponent
(`local_secret`) as soon as it has used it, and any further call (or a call after an invalid
peer key, which also wipes it) fails with -1 instead of silently computing 2^0. MSE/PE then
copies the shared secret out, scrubs the DH object (`ntx_dh_scrub`), and wipes its own copy
(`secret_buf`) when the handshake completes or fails; the derived RC4 keys are what remains.

Constant-time behaviour is a property of the C source as written; it has **not** been
measured on a binary (no dudect-style testing), and compilers are free to reintroduce branches.

RC4 is used only because BitTorrent MSE/PE mandates it; its known biases and timing
behaviour are inherent to the algorithm.

Other things to know:

- **TLS.** The client offers TLS 1.3 first (`TLS_AES_128_GCM_SHA256`, X25519, server
  signatures `ecdsa_secp256r1_sha256` or `rsa_pss_rsae_sha256`) and falls back to TLS 1.2
  (ECDHE + AES-128-GCM) on a fresh connection if the server does not speak 1.3. It does not
  implement PSK/resumption, 0-RTT, HelloRetryRequest or client certificates (session tickets
  are ignored). The handshake is checked against an independent Python reference, frozen
  server streams, `openssl s_server` (`test/tls13_interop.sh`) and live servers, but it has
  not been audited. Build with `-DNTX_TLS13_LIVE=0` for a TLS 1.2-only client. See
  [`docs/network.md`](docs/network.md).
- **No CA store.** Trust is SPKI pinning. With the default **TOFU** mode, the first
  connection to a host that has no pin is trusted and remembered — an attacker present on
  that first connection is not detected. Use `--no-https-tofu` with `--https-pin-file` for
  strict pinning.
- **Tracker announces, PEX and DHT are plaintext**; the info-hash and your IP address are
  visible to the network path. Peer-wire encryption (MSE/PE) is obfuscation, not
  authentication.

## Pre-release security audit (October 2026)

Besides the crypto reviews above, the whole program was reviewed from an attacker's point of view:
peers, trackers, DHT nodes, HTTP/HTTPS servers and `.torrent` / magnet metadata are all
untrusted input. Method: read every parser and every place a remote value becomes a size, an
index, a path, a host or a loop bound; try to break each assumption with a hostile input; fix
only what a test could first show failing (the test failed on the old code, then passed).
New suites are listed in [`docs/testing.md`](docs/testing.md). No file under `src/crypto/`
was changed in this pass.

| # | Finding | Impact before | Fix |
|---|---------|---------------|-----|
| F1 | `ut_metadata` (BEP 9): `metadata_size` unbounded or negative, DATA pieces not parsed strictly, leaked file-name buffers | a peer could make us allocate without limit, or feed a metadata blob of a different size | hard cap `NTX_UT_METADATA_MAX`, exact piece size and index checks, buffers freed (`src/proto/ntx_ext.c`, `ntx_utmeta.c`, `src/core/ntx_session_meta.c`) |
| F2 | `PIECE` handling trusted the peer: unrequested blocks, offsets/lengths outside the piece, duplicates, ignored `store_write` result | unsolicited data written into the store, bad accounting | a block is accepted only if it matches an outstanding request (`ntx_peer_request_match`); bounds, duplicate and write-failure checks (`ntx_session_peer.c`, `ntx_session_data.c`) |
| F3 | HTTP client: CR/LF and control characters in URLs and request lines, `user@host` confusion, unbounded numbers in `Content-Length` / chunk sizes / HTTP/2 `:status` | request splitting / header injection through a tracker or web-seed URL; integer wrap | URLs and request parts validated, userinfo rejected, numeric fields saturate instead of wrapping (`ntx_http_url.c`, `ntx_http.c`, `ntx_https.c`) |
| F4 | uTP: unlimited half-open connections (SYN flood) | memory and slot exhaustion by spoofed SYNs | `NTX_UTP_MAX_HALFOPEN` and a reaper after `NTX_UTP_HALFOPEN_MS` (`ntx_utp.c`) |
| F5 | No filter on peer addresses | a hostile tracker / PEX / DHT could make us connect to services on localhost or to the link-local cloud-metadata address (SSRF-like probing), and accept the same inbound | `ntx_addr_is_special` refuses unspecified, loopback, link-local, multicast and reserved addresses (also when IPv4-mapped) at the single chokepoint `ntx_session_add_peer_dial`; opt out with `--allow-local-peers`. **Private LAN ranges (RFC 1918, IPv6 ULA) are deliberately still allowed** - LAN swarms are legitimate - so a hostile tracker can still make `ntx` open TCP connections to hosts on your LAN (no data is sent beyond the BitTorrent handshake) |
| F6 | Peer resource limits: no per-address cap, no idle timeout, `REQUEST` / `HASH_REQUEST` floods | one host could fill all peer slots; unbounded upload queue | `NTX_PEER_MAX_PER_ADDR` = 8 inbound per address, `NTX_PEER_IDLE_TIMEOUT_S` = 300 s without any received byte, backpressure on requests |
| F7 | UDP tracker: sequential transaction id, reply accepted from any source | any host that can send us a datagram could forge tracker replies (inject peers) | random 32-bit TID, reply must come from the address the request went to (`ntx_session_trk.c`) |
| F8 | TOFU pin file written non-atomically; DHT token compared with `memcmp`; v1/v2 metainfo sizes not cross-checked (piece count vs `length`, sum overflow, v2 piece length) | torn pin file; timing side channel on the token; hostile `.torrent` could produce inconsistent sizes and out-of-range indexes | atomic write with mode 0600; constant-time compare (`ntx_ct_eq`); `ntx_torrent_*` / `ntx_store` check every size and sum (`NTX_TORRENT_MAX_PIECE_LEN` = 64 MiB), `test/t_torrent_hostile.c` |
| F9 | Anonymity: with `--proxy` / `--tunnel`, UDP trackers and DHT bypassed the proxy and leaked the real address; binary built without hardening | IP disclosure exactly when the user asked to hide it | UDP trackers are skipped in those modes and `--dht` together with them is a fatal error; the binary is built with stack protector, `_FORTIFY_SOURCE=2`, PIE, full RELRO and non-executable stack (`HARDEN_CFLAGS` / `HARDEN_LDFLAGS` in the `Makefile`) |
| F10 | `ntx_netx` fd table grow ignored a failed `realloc` (found with `gcc -fanalyzer`) | NULL dereference under memory exhaustion | the grow fails cleanly and the fd stays unregistered |

Behaviour changes you will notice: peers on non-global addresses are no longer used unless you
pass `--allow-local-peers` (needed for a LAN swarm and for local testing), and
`--dht` cannot be combined with `--proxy` / `--tunnel`.

Verification: the full suite (`make test`, `make test-cli`, `make test-net`, `make test-tls13`)
passes, as does a sweep of every `test/t_*.c` under AddressSanitizer + UndefinedBehaviorSanitizer
(`test/scripts/sweep.sh`). `gcc -fanalyzer` was run over the whole tree; apart from F10 its
reports were reviewed and are false positives or benign.

What this audit did **not** cover:

- **No fuzzing run.** The libFuzzer harnesses are documented in `docs/fuzzing.md`, but the audit
  machine had gcc only (libFuzzer needs clang), so the parsers were not fuzzed with coverage guidance in this pass.
  Fuzzing the bencode, metainfo, BEP 9/10/11, HTTP, DHT and uTP parsers is the most valuable next step.
- **No external review**, no penetration test, no Valgrind / MSan / TSan run. Concurrency is not
  a concern (single-threaded event loop), but that was not machine-checked.
- **DoH** answers are not matched against the query id / question beyond what the pinned TLS
  channel to the DoH provider already guarantees; a malicious or compromised DoH provider can
  still lie about addresses.
- **Plaintext protocols stay plaintext**; MSE/PE is obfuscation (see above).
- **DHT** is a minimal implementation: no routing-table poisoning defence beyond token checks and
  size limits, and no sybil resistance.
- **Local files.** Downloaded file names from metainfo are sanitised by the store layer, but a
  user who points `--store-dir` at a directory containing symlinks controls what happens there.
- **Control channel.** `--stats-json` reads commands from stdin only (no socket, no network);
  whoever controls the process's stdin already controls the process.
- **Test fixtures.** `test/vectors/tls13/key_p256.pem` and `key_rsa.pem` are throw-away private keys
  of the test servers used for the TLS golden streams. They protect nothing; secret scanners
  will flag them.

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting for this repository (*Security* tab,
then *Report a vulnerability*) rather than a public issue. Include the commit, how to
reproduce, and the impact you expect. This is a one-person hobby project: reports will be
answered as soon as possible, but there is no fixed response time and no bug bounty.

Reports about the items listed above are welcome too — a proof of concept or a test vector
for any of R1–R8 or F1–F10 is the most useful thing you can send; so is a crashing input from a
fuzzer (attach the input file).

## Supported versions

Only the latest commit on the default branch.
